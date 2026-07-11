"""Strict raw authorization bundle importer for P00 phase transitions.

The importer accepts no caller-authored aggregate summary or verdict.  It
binds a signed late-bound aggregate dataset to the identity-sealed 12-record
raw-chain evidence projection, reconstructs a phase-only Run A/Run B seal from
raw execution bytes, re-verifies OIDC MACHINE/proof statements, re-verifies
SSHSIG freeze/approval statements, and (only for final convergence) enforces
the two-principal/two-organization GO/NOGO threshold.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, NoReturn, Sequence
import weakref

from .chain_witness import (
    VerifiedChainHeadWitness,
    require_verified_chain_head_witness,
    verify_chain_head_witness,
)
from .control_context import (
    ControlContextError,
    VerifiedPhaseControlContext,
    criterion_documents,
    finalize_late_bound_dataset_context,
    require_verified_phase_control_context,
)
from .delegation import (
    EffectiveReviewerRoster,
    authorize_criterion_signer,
    build_effective_reviewer_roster,
)
from .digest import canonical_json_bytes, sha256_bytes
from .evidence_index import (
    EvidenceIndexError,
    VerifiedProtectedChainReplay,
    require_verified_protected_chain_replay,
)
from .execution_artifact import (
    ExecutionArtifactError,
    VerifiedPhaseExecutionArtifact,
    verify_phase_execution_artifact_bundle,
)
from .gate_runner import GateRunnerError, phase_criterion_result_projection
from .oidc_provenance import OidcProvenanceError, build_oidc_provenance_verifier
from .phase_evidence import (
    PhaseEvidenceError,
    VerifiedPhaseAggregateEvidence,
    require_verified_phase_aggregate_evidence,
)
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    PHASE_APPROVAL_NAMESPACE,
    PHASE_CRITERION_NAMESPACES,
    PHASE_FREEZE_NAMESPACE,
    PHASE_GO_NOGO_NAMESPACE,
    PHASE_PROOF_NAMESPACE,
    VerifiedPhaseCriterionResult,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedPhaseTransition,
    VerifiedSignerResult,
    _require_verified as _require_provenance_verified,
    authorize_phase_transition,
    verify_phase_go_nogo_authorization,
    verify_phase_state_context,
    verify_phase_transition_approval,
    verify_phase_transition_proof,
    verify_signed_phase_criterion_result,
    verify_signed_phase_protected_input_freeze,
)
from .serialized_bundle import SerializedBundleError, _policy_sshsig_verifier
from .sshsig import SshSigVerificationError, verify_sshsig
from .state_chain_v2 import require_verified_state_context_v2


BUNDLE_SCHEMA = "urn:agentapi-doctor:serialized-phase-authorization-bundle:v1alpha1"
BUNDLE_KIND = "SerializedProtectedPhaseAuthorizationBundle"
OP_PHASE_TRANSITION = "phase-transition"
MAX_BUNDLE_BYTES = 80 * 1024 * 1024
MAX_SIGNED_DOCUMENTS = 128
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


@dataclass
class PhaseBundleError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class VerifiedSerializedPhaseAuthorizationBundle:
    """Fresh phase authorization seals reconstructed from one raw artifact."""

    bundle_digest: str
    bundle_id: str
    operation: str
    source_commit: str
    prior_state_digest: str
    prior_chain_head_digest: str
    phase_context: VerifiedPhaseControlContext
    aggregate_evidence: VerifiedPhaseAggregateEvidence
    freeze: VerifiedPhaseProtectedInputFreeze
    criterion_result: VerifiedPhaseCriterionResult
    machine_execution: VerifiedPhaseExecutionArtifact
    event_input: VerifiedPhaseTransition
    chain_head_witness: VerifiedChainHeadWitness


_VERIFIED: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise PhaseBundleError(code, path, message)


def _translate(error: Exception) -> NoReturn:
    _fail(
        str(getattr(error, "code", "phase_authorization_failed")),
        str(getattr(error, "path", "phaseAuthorizationBundle")),
        str(getattr(error, "message", str(error))),
    )


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_source_commit", path, "expected lowercase 40-hex Git commit")
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("invalid_timestamp", path, "timezone-aware datetime required")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_timestamp", path, "second precision required")
    return normalized


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_bundle_schema", path, "field set differs from versioned schema")
    return value


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail("duplicate_bundle_key", "phaseAuthorizationBundle", key)
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail("invalid_bundle_json", "phaseAuthorizationBundle", value)


def _load(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BUNDLE_BYTES:
        _fail("invalid_bundle_size", "phaseAuthorizationBundle", "bounded bytes required")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except PhaseBundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("invalid_bundle_json", "phaseAuthorizationBundle", str(exc))
    if not isinstance(value, dict):
        _fail("invalid_bundle_schema", "phaseAuthorizationBundle", "object required")
    if canonical_json_bytes(value) != raw:
        _fail("noncanonical_bundle", "phaseAuthorizationBundle", "canonical JSON bytes required")
    return value


def _projection(value: VerifiedSerializedPhaseAuthorizationBundle) -> dict[str, Any]:
    transition = value.event_input
    return {
        "bundleDigest": value.bundle_digest,
        "bundleId": value.bundle_id,
        "operation": value.operation,
        "sourceCommit": value.source_commit,
        "priorStateDigest": value.prior_state_digest,
        "priorChainHeadDigest": value.prior_chain_head_digest,
        "phaseContextDigest": value.phase_context.context_digest,
        "aggregateEvidenceDigest": value.aggregate_evidence.evidence_digest,
        "freezeDigest": value.freeze.attestation_digest,
        "criterionResultDigest": value.criterion_result.attestation_digest,
        "executionBundleDigest": value.machine_execution.bundle_digest,
        "runPairDigest": value.machine_execution.run_pair_digest,
        "transition": {
            "fromState": transition.from_state,
            "toState": transition.to_state,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "goNoGoAuthorizationDigest": transition.go_nogo_authorization_digest,
            "criterionResultDigests": list(transition.criterion_result_digests),
        },
        "chainHeadWitnessDigest": value.chain_head_witness.attestation_digest,
    }


def _seal(
    value: VerifiedSerializedPhaseAuthorizationBundle,
) -> VerifiedSerializedPhaseAuthorizationBundle:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        present = _VERIFIED.get(identity)
        if present is not None and present[0] is reference:
            _VERIFIED.pop(identity, None)

    reference = weakref.ref(value, discard)
    _VERIFIED[identity] = (reference, document_digest(_projection(value)))
    return value


def require_verified_serialized_phase_bundle(
    value: Any, *, path: str = "phaseAuthorizationBundle"
) -> VerifiedSerializedPhaseAuthorizationBundle:
    entry = _VERIFIED.get(id(value))
    if (
        not isinstance(value, VerifiedSerializedPhaseAuthorizationBundle)
        or entry is None
        or entry[0]() is not value
        or entry[1] != document_digest(_projection(value))
    ):
        _fail("unverified_internal_result", path, "exact phase importer result required")
    try:
        require_verified_phase_control_context(value.phase_context)
        require_verified_phase_aggregate_evidence(value.aggregate_evidence)
        _require_provenance_verified(
            value.freeze, VerifiedPhaseProtectedInputFreeze, f"{path}.freeze"
        )
        _require_provenance_verified(
            value.criterion_result,
            VerifiedPhaseCriterionResult,
            f"{path}.criterionResult",
        )
        _require_provenance_verified(
            value.event_input, VerifiedPhaseTransition, f"{path}.eventInput"
        )
        require_verified_chain_head_witness(value.chain_head_witness, path=f"{path}.chainHeadWitness")
        projection = phase_criterion_result_projection(
            freeze=value.freeze,
            criterion_id=value.criterion_result.criterion.criterion_id,
            run_pair=value.machine_execution.run_pair,
        )
    except (
        ControlContextError,
        PhaseEvidenceError,
        ProtectedVerificationError,
        GateRunnerError,
    ) as exc:
        _translate(exc)
    if (
        projection["runPairDigest"] != value.machine_execution.run_pair_digest
        or value.criterion_result.run_pair_digest
        != value.machine_execution.run_pair_digest
        or value.criterion_result.evidence_digest
        != value.machine_execution.run_pair_digest
        or value.event_input.freeze_digest != value.freeze.attestation_digest
        or value.event_input.criterion_result_digests
        != (value.criterion_result.attestation_digest,)
    ):
        _fail("verified_bundle_projection_mismatch", path, "fresh seals differ")
    return value


def _current_fields(replay: VerifiedProtectedChainReplay) -> tuple[Any, Mapping[str, Any]]:
    chain = require_verified_protected_chain_replay(replay)
    try:
        current = require_verified_state_context_v2(chain.current)
    except ProtectedVerificationError as exc:
        _translate(exc)
    return current, current.state_core


def _aggregate_selection_binding(
    selections: Sequence[Any], evidence: VerifiedPhaseAggregateEvidence
) -> None:
    if len(selections) != 1 or not isinstance(selections[0], Mapping):
        _fail(
            "aggregate_dataset_selection_mismatch",
            "phaseAuthorizationBundle.lateBoundDatasetSelections",
            "exactly one signed aggregate dataset selection required",
        )
    body = selections[0].get("body")
    if not isinstance(body, Mapping):
        _fail("invalid_bundle_schema", "lateBoundDatasetSelections[0]", "body required")
    if (
        body.get("criterionIds") != ["P00-M-AGGREGATE"]
        or body.get("datasetManifest") != evidence.dataset_manifest
        or body.get("datasetDigest") != evidence.dataset_digest
    ):
        _fail(
            "aggregate_dataset_selection_mismatch",
            "phaseAuthorizationBundle.lateBoundDatasetSelections[0]",
            "signed selection does not carry the exact sealed 12-record dataset",
        )


def _operation(
    value: Any,
    *,
    context: VerifiedPhaseControlContext,
    evidence: VerifiedPhaseAggregateEvidence,
    from_state: str,
    to_state: str,
    state_digest: str,
    head_digest: str,
    workflow_commit: str,
) -> dict[str, Any]:
    operation = _exact(
        value,
        {
            "operationId",
            "type",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "workflowExecutionCommit",
            "phaseContextDigest",
            "aggregateEvidenceDigest",
            "aggregateContractApprovalDigest",
            "impactMapDigest",
            "unitContractDigests",
            "protectedInputsDigest",
            "criteriaDigest",
        },
        "phaseAuthorizationBundle.operation",
    )
    if (
        not isinstance(operation["operationId"], str)
        or ID_RE.fullmatch(operation["operationId"]) is None
    ):
        _fail("invalid_operation_id", "phaseAuthorizationBundle.operation.operationId", "invalid ID")
    subject = {
        "phase": context.subject.phase,
        "sourceCommit": context.subject.source_commit,
        "controlPlaneDigest": context.subject.control_plane_digest,
        "aggregateContractDigest": context.subject.aggregate_contract_digest,
    }
    exact = {
        "type": OP_PHASE_TRANSITION,
        "subject": subject,
        "fromState": from_state,
        "toState": to_state,
        "priorStateDigest": state_digest,
        "priorChainHeadDigest": head_digest,
        "workflowExecutionCommit": workflow_commit,
        "phaseContextDigest": context.context_digest,
        "aggregateEvidenceDigest": evidence.evidence_digest,
        "aggregateContractApprovalDigest": context.aggregate_contract_approval_digest,
        "impactMapDigest": context.impact_map_digest,
        "unitContractDigests": dict(context.unit_contract_digests),
        "protectedInputsDigest": document_digest(
            {"protectedInputs": dict(context.protected_inputs)}
        ),
        "criteriaDigest": document_digest(
            {"criteria": criterion_documents(context.criteria)}
        ),
    }
    if any(operation.get(key) != expected for key, expected in exact.items()):
        _fail("operation_binding_mismatch", "phaseAuthorizationBundle.operation", "trusted binding differs")
    return operation


def _go_signer_verifier(
    *,
    roster: EffectiveReviewerRoster,
    principal_name: str,
    role: str,
    source_commit: str,
    control_plane_digest: str,
    verification_time: datetime,
) -> Callable[[bytes, Mapping[str, Any], str], VerifiedSignerResult]:
    authorization = authorize_criterion_signer(
        roster,
        principal=principal_name,
        criterion_id="P00-H-GO-NOGO",
        required_role=role,
        required_capability="attest-human-result",
        at=verification_time,
    )
    principal = next(
        (item for item in roster.principals if item.identity == principal_name), None
    )
    if principal is None:
        _fail("signer_not_allowed", "goNoGo", "principal absent from roster")

    def verify(
        payload: bytes, signature: Mapping[str, Any], namespace: str
    ) -> VerifiedSignerResult:
        descriptor = _exact(
            signature,
            {"scheme", "namespace", "principal", "value"},
            "goNoGo.signature",
        )
        if (
            descriptor["scheme"] != "openssh-sshsig-v1"
            or namespace != PHASE_GO_NOGO_NAMESPACE
            or descriptor["namespace"] != namespace
            or descriptor["principal"] != principal_name
        ):
            _fail("signature_namespace_mismatch", "goNoGo.signature", "signer/domain differs")
        try:
            verify_sshsig(
                payload,
                armored_signature=descriptor["value"],
                public_key=principal.public_key,
                expected_namespace=PHASE_GO_NOGO_NAMESPACE,
            )
        except SshSigVerificationError as exc:
            _translate(exc)
        return VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=PHASE_GO_NOGO_NAMESPACE,
            principal=authorization.principal,
            role=authorization.role,
            organization=authorization.organization,
            statement_digest=sha256_bytes(payload),
            authority_digest=roster.authority_digest,
            source_commit=source_commit,
            control_plane_digest=control_plane_digest,
        )

    return verify


def _go_verifiers(
    statements: Sequence[Any],
    *,
    roster: EffectiveReviewerRoster,
    source_commit: str,
    control_plane_digest: str,
    verification_time: datetime,
) -> list[Callable[[bytes, Mapping[str, Any], str], VerifiedSignerResult]]:
    expected_roles = ["authorized-maintainer", "independent-external-reviewer"]
    if len(statements) != 2:
        _fail("go_nogo_threshold_not_met", "phaseAuthorizationBundle.goNoGo", "exactly two signatures required")
    result = []
    for index, (statement, expected_role) in enumerate(zip(statements, expected_roles)):
        body = statement.get("body") if isinstance(statement, Mapping) else None
        actor = body.get("actor") if isinstance(body, Mapping) else None
        if (
            not isinstance(actor, Mapping)
            or actor.get("role") != expected_role
            or not isinstance(actor.get("principal"), str)
        ):
            _fail("go_nogo_role_threshold_not_met", f"phaseAuthorizationBundle.goNoGo[{index}]", "deterministic required-role order differs")
        result.append(
            _go_signer_verifier(
                roster=roster,
                principal_name=actor["principal"],
                role=expected_role,
                source_commit=source_commit,
                control_plane_digest=control_plane_digest,
                verification_time=verification_time,
            )
        )
    return result


def verify_serialized_phase_authorization_bundle(
    raw_artifact: bytes,
    *,
    replay: VerifiedProtectedChainReplay,
    policy_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
    repo_root: Path,
    current_workflow_execution_commit: str,
    expected_to_state: str,
    control_context: VerifiedPhaseControlContext,
    aggregate_evidence: VerifiedPhaseAggregateEvidence,
    verification_time: datetime,
) -> VerifiedSerializedPhaseAuthorizationBundle:
    """Re-verify one canonical raw phase bundle into fresh transition seals."""

    try:
        chain = require_verified_protected_chain_replay(replay)
        base_context = require_verified_phase_control_context(control_context)
        evidence = require_verified_phase_aggregate_evidence(aggregate_evidence)
    except (EvidenceIndexError, ControlContextError, PhaseEvidenceError) as exc:
        _translate(exc)
    workflow_commit = _commit(
        current_workflow_execution_commit, "currentWorkflowExecutionCommit"
    )
    now = _utc(verification_time, "verificationTime")
    if (
        workflow_commit != chain.head_source_commit
        or base_context.subject.source_commit != workflow_commit
        or base_context.subject.control_plane_digest != chain.control_plane_digest
        or evidence.phase_context_digest != base_context.context_digest
        or evidence.source_machine_index_digest != chain.machine_evidence_index_digest
        or evidence.source_commit != workflow_commit
        or evidence.control_plane_digest != chain.control_plane_digest
        or evidence.aggregate_contract_digest
        != base_context.subject.aggregate_contract_digest
    ):
        _fail("phase_source_binding_mismatch", "phaseContext", "replay/context/evidence differs")
    current, state_core = _current_fields(chain)
    phase_state = state_core.get("phases", {}).get("P00")
    if not isinstance(phase_state, Mapping) or not isinstance(phase_state.get("status"), str):
        _fail("invalid_current_state", "current.phases.P00", "phase state unavailable")
    try:
        state_context = verify_phase_state_context(
            dict(state_core),
            expected_state_digest=chain.state_digest,
            expected_chain_head_digest=chain.head_digest,
            expected_control_plane_digest=chain.control_plane_digest,
            phase="P00",
            expected_status=phase_state["status"],
            expected_aggregate_contract_digest=(
                base_context.subject.aggregate_contract_digest
            ),
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    document = _load(raw_artifact)
    envelope = _exact(
        document,
        {
            "schemaVersion",
            "kind",
            "bundleId",
            "operation",
            "chainHeadWitness",
            "delegations",
            "revocations",
            "lateBoundDatasetSelections",
            "phaseProtectedInputFreeze",
            "phaseMachineExecutionArtifact",
            "phaseCriterionResult",
            "proof",
            "approval",
            "goNoGo",
            "bundleDigest",
        },
        "phaseAuthorizationBundle",
    )
    if envelope["schemaVersion"] != BUNDLE_SCHEMA or envelope["kind"] != BUNDLE_KIND:
        _fail("invalid_bundle_schema", "phaseAuthorizationBundle", "unsupported revision")
    if not isinstance(envelope["bundleId"], str) or ID_RE.fullmatch(envelope["bundleId"]) is None:
        _fail("invalid_bundle_id", "phaseAuthorizationBundle.bundleId", "invalid ID")
    bundle_digest = document_digest(envelope, omit_field="bundleDigest")
    if envelope["bundleDigest"] != bundle_digest:
        _fail("bundle_digest_mismatch", "phaseAuthorizationBundle.bundleDigest", "digest mismatch")
    lists = (
        envelope["delegations"],
        envelope["revocations"],
        envelope["lateBoundDatasetSelections"],
        envelope["goNoGo"],
    )
    if any(
        not isinstance(value, list) or len(value) > MAX_SIGNED_DOCUMENTS
        for value in lists
    ):
        _fail("invalid_bundle_schema", "phaseAuthorizationBundle", "bounded signed lists required")
    policy_digest = _digest(policy_result.get("digest"), "policyResult.digest")
    try:
        witness = verify_chain_head_witness(
            envelope["chainHeadWitness"],
            policy_result=policy_result,
            expected_prior_chain_head_digest=chain.head_digest,
            expected_prior_state_digest=chain.state_digest,
            expected_prior_event_count=chain.event_count,
            expected_prior_head_sequence=chain.head_sequence,
            expected_prior_source_commit=chain.head_source_commit,
            expected_control_plane_digest=chain.control_plane_digest,
            expected_trust_policy_digest=policy_digest,
            now=now,
        )
        roster = build_effective_reviewer_roster(
            policy_result=policy_result,
            delegations=envelope["delegations"],
            revocations=envelope["revocations"],
            expected_policy_digest=policy_digest,
            expected_control_plane_digest=chain.control_plane_digest,
            expected_source_commit=workflow_commit,
            expected_prior_chain_head_digest=chain.head_digest,
            now=now,
        )
        _aggregate_selection_binding(envelope["lateBoundDatasetSelections"], evidence)
        finalized = finalize_late_bound_dataset_context(
            base_context=base_context,
            raw_selections=envelope["lateBoundDatasetSelections"],
            roster=roster,
            verification_time=now,
        )
        context = require_verified_phase_control_context(finalized)
    except (ProtectedVerificationError, ControlContextError) as exc:
        _translate(exc)
    aggregate_criteria = [
        item
        for item in context.criteria
        if item.criterion_id == "P00-M-AGGREGATE" and item.kind == "MACHINE"
    ]
    if (
        context.late_bound_dataset_criteria
        or len(aggregate_criteria) != 1
        or aggregate_criteria[0].dataset_digest != evidence.dataset_digest
        or dict(context.dataset_selection_bindings).get("P00-M-AGGREGATE") is None
    ):
        _fail("aggregate_context_not_finalized", "phaseContext", "signed dataset binding differs")
    operation = _operation(
        envelope["operation"],
        context=context,
        evidence=evidence,
        from_state=state_context.status,
        to_state=expected_to_state,
        state_digest=chain.state_digest,
        head_digest=chain.head_digest,
        workflow_commit=workflow_commit,
    )
    freeze_signer = _policy_sshsig_verifier(
        policy_result=policy_result,
        expected_namespace=PHASE_FREEZE_NAMESPACE,
        required_role="independent-reviewer",
        required_capability="freeze-protected-input",
        expected_source_commit=workflow_commit,
        expected_control_plane_digest=chain.control_plane_digest,
        verification_time=now,
    )
    approval_signer = _policy_sshsig_verifier(
        policy_result=policy_result,
        expected_namespace=PHASE_APPROVAL_NAMESPACE,
        required_role="independent-reviewer",
        required_capability="approve-transition",
        expected_source_commit=workflow_commit,
        expected_control_plane_digest=chain.control_plane_digest,
        verification_time=now,
    )
    try:
        freeze = verify_signed_phase_protected_input_freeze(
            envelope["phaseProtectedInputFreeze"],
            expected_subject=context.subject,
            expected_aggregate_contract_approval_digest=(
                context.aggregate_contract_approval_digest
            ),
            expected_unit_contract_digests=dict(context.unit_contract_digests),
            expected_protected_inputs=dict(context.protected_inputs),
            expected_criteria=criterion_documents(context.criteria),
            expected_authority_digest=policy_digest,
            signer_verifier=freeze_signer,
        )
        raw_execution = envelope["phaseMachineExecutionArtifact"]
        if not isinstance(raw_execution, Mapping):
            _fail("invalid_bundle_schema", "phaseMachineExecutionArtifact", "object required")
        if raw_execution.get("evaluatorInput") != evidence.evaluator_input:
            _fail("aggregate_execution_input_mismatch", "phaseMachineExecutionArtifact.evaluatorInput", "caller substituted aggregate records")
        execution = verify_phase_execution_artifact_bundle(
            canonical_json_bytes(raw_execution),
            freeze=freeze,
            expected_criterion_id="P00-M-AGGREGATE",
        )
        raw_result = envelope["phaseCriterionResult"]
        result_body = raw_result.get("body") if isinstance(raw_result, Mapping) else None
        if (
            not isinstance(result_body, Mapping)
            or result_body.get("runPair") != dict(execution.run_pair)
            or result_body.get("runPairDigest") != execution.run_pair_digest
            or result_body.get("evidenceDigest") != execution.run_pair_digest
        ):
            _fail("phase_machine_execution_binding_mismatch", "phaseCriterionResult", "signed result differs from raw execution")
        machine_verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=policy_result,
            approved_jwks_snapshot=approved_jwks_snapshot,
            repo_root=repo_root,
            current_source_commit=workflow_commit,
            current_workflow_execution_commit=workflow_commit,
            expected_namespace=PHASE_CRITERION_NAMESPACES["MACHINE"],
        )
        result = verify_signed_phase_criterion_result(
            raw_result,
            freeze=freeze,
            expected_authority_digest=machine_verifier.authority_digest,
            signer_verifier=machine_verifier,
        )
        proof_verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=policy_result,
            approved_jwks_snapshot=approved_jwks_snapshot,
            repo_root=repo_root,
            current_source_commit=workflow_commit,
            current_workflow_execution_commit=workflow_commit,
            expected_namespace=PHASE_PROOF_NAMESPACE,
        )
        proof = verify_phase_transition_proof(
            envelope["proof"],
            freeze=freeze,
            criterion_results=[result],
            state_context=state_context,
            expected_to_state=expected_to_state,
            expected_authority_digest=proof_verifier.authority_digest,
            signer_verifier=proof_verifier,
        )
        approval = verify_phase_transition_approval(
            envelope["approval"],
            proof=proof,
            expected_authority_digest=policy_digest,
            signer_verifier=approval_signer,
            now=now,
        )
        if expected_to_state == "CONVERGED":
            go_statements = envelope["goNoGo"]
            go = verify_phase_go_nogo_authorization(
                go_statements,
                proof=proof,
                expected_authority_digest=roster.authority_digest,
                signer_verifiers=_go_verifiers(
                    go_statements,
                    roster=roster,
                    source_commit=workflow_commit,
                    control_plane_digest=chain.control_plane_digest,
                    verification_time=now,
                ),
                now=now,
            )
        else:
            if envelope["goNoGo"]:
                _fail("unexpected_go_nogo_authorization", "phaseAuthorizationBundle.goNoGo", "only final convergence consumes GO/NOGO")
            go = None
        transition = authorize_phase_transition(
            state_context=state_context,
            freeze=freeze,
            criterion_results=[result],
            proof=proof,
            approval=approval,
            go_nogo_authorization=go,
        )
    except (
        ExecutionArtifactError,
        GateRunnerError,
        OidcProvenanceError,
        ProtectedVerificationError,
        SerializedBundleError,
        SshSigVerificationError,
    ) as exc:
        _translate(exc)
    value = VerifiedSerializedPhaseAuthorizationBundle(
        bundle_digest=bundle_digest,
        bundle_id=envelope["bundleId"],
        operation=operation["type"],
        source_commit=workflow_commit,
        prior_state_digest=chain.state_digest,
        prior_chain_head_digest=chain.head_digest,
        phase_context=context,
        aggregate_evidence=evidence,
        freeze=freeze,
        criterion_result=result,
        machine_execution=execution,
        event_input=transition,
        chain_head_witness=witness,
    )
    return _seal(value)


__all__ = [
    "BUNDLE_KIND",
    "BUNDLE_SCHEMA",
    "OP_PHASE_TRANSITION",
    "PhaseBundleError",
    "VerifiedSerializedPhaseAuthorizationBundle",
    "require_verified_serialized_phase_bundle",
    "verify_serialized_phase_authorization_bundle",
]
