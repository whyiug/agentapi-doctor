"""OIDC-backed writers for protected provenance documents.

Every public builder consumes only identity-sealed verifier outputs.  Statement
bodies, identifiers, actors, authority bindings, result projections, and
digests are derived in this module; callers cannot inject a document body or a
claimed digest.  Each envelope is returned only after the corresponding normal
provenance verifier accepts the GitHub Actions OIDC signature.

Lifecycle generation consumes dedicated identity-sealed primary evidence.
Callers cannot provide blocker/invalidation digests.  Supersession approval is
verified as raw evidence, but the current state-chain revision cannot safely
replace its authoritative contract/control-plane subject and therefore fails
closed with a structured unsupported-revision result.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Callable, Mapping, NoReturn, Sequence

from .digest import canonical_json_bytes, sha256_bytes
from .gate_runner import (
    GateRunnerError,
    SealedPhaseRunPair,
    phase_criterion_result_projection,
)
from .lifecycle_evidence import (
    LifecycleEvidenceError,
    VerifiedBlockerResolution,
    VerifiedInvalidationEvidence,
    VerifiedSupersessionApproval,
    require_verified_blocker_resolution,
    require_verified_invalidation_evidence,
    require_verified_supersession_approval,
)
from .oidc_provenance import (
    OIDC_PROVENANCE_AUDIENCE_PREFIX,
    OIDC_SIGNATURE_SCHEME,
    OidcProvenanceError,
    OidcProvenanceVerifier,
    _require_verified as _require_oidc_verifier,
    create_signed_machine_criterion_result,
    github_actions_provenance_token_provider,
)
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    ACTIVATION_PROOF_KIND,
    ACTIVATION_PROOF_NAMESPACE,
    ACTIVATION_PROOF_SCHEMA,
    LIFECYCLE_PROOF_KIND,
    LIFECYCLE_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_SCHEMA,
    PHASE_CRITERION_KIND,
    PHASE_CRITERION_NAMESPACES,
    PHASE_CRITERION_SCHEMA,
    PHASE_PROOF_KIND,
    PHASE_PROOF_NAMESPACE,
    PHASE_PROOF_SCHEMA,
    PROOF_KIND,
    PROOF_NAMESPACE,
    PROOF_SCHEMA,
    CriterionBinding,
    PhaseSubject,
    PhaseUnitStateBinding,
    PrerequisiteStateBinding,
    SubjectBinding,
    VerifiedActivationProofResult,
    VerifiedCriterionResult,
    VerifiedLifecycleProofResult,
    VerifiedPhaseCriterionResult,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedPhaseStateContext,
    VerifiedPhaseTransitionProofResult,
    VerifiedProtectedInputFreeze,
    VerifiedTransitionProofResult,
    VerifiedWorkUnitStateContext,
    _require_verified as _require_provenance_verified,
    _required_criterion_kinds,
    _required_phase_criterion_ids,
    verify_activation_proof,
    verify_lifecycle_proof,
    verify_phase_transition_proof,
    verify_signed_phase_criterion_result,
    verify_verified_transition_proof,
)


TokenProvider = Callable[[str], str]
ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
MAX_TOKEN_BYTES = 32_768
IMPACT_MAP_PATH = "execution/impact-map.yaml"


@dataclass
class ProvenanceWriterError(ValueError):
    """Stable, token-free failure from a protected provenance writer."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise ProvenanceWriterError(code, path, message)


def _translate(
    error: ProtectedVerificationError | OidcProvenanceError | GateRunnerError,
) -> NoReturn:
    _fail(error.code, error.path, error.message)


def _format_utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("invalid_timestamp", "issuedAt", "timezone-aware datetime required")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_timestamp", "issuedAt", "second precision is required")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _stable_id(prefix: str, seed: Mapping[str, Any]) -> str:
    value = prefix + "-" + sha256_bytes(canonical_json_bytes(seed))[7:39]
    if ID_RE.fullmatch(value) is None:
        _fail("invalid_generated_id", "id", "internal identifier generation failed")
    return value


def _subject(subject: SubjectBinding) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "workUnit": subject.work_unit,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "contractDigest": subject.contract_digest,
    }


def _phase_subject(subject: PhaseSubject) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "aggregateContractDigest": subject.aggregate_contract_digest,
    }


def _criterion(criterion: CriterionBinding) -> dict[str, str]:
    return {
        "id": criterion.criterion_id,
        "kind": criterion.kind,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "evaluatorStatus": criterion.evaluator_status,
        "evidenceSchema": criterion.evidence_schema,
        "evidenceSchemaDigest": criterion.evidence_schema_digest,
        "datasetDigest": criterion.dataset_digest,
        "thresholdDigest": criterion.threshold_digest,
    }


def _prerequisite(value: PrerequisiteStateBinding) -> dict[str, str]:
    return {
        "phase": value.phase,
        "workUnit": value.work_unit,
        "status": value.status,
        "stateDigest": value.state_digest,
        "contractDigest": value.contract_digest,
        "sourceCommit": value.source_commit,
        "approvalDigest": value.approval_digest,
    }


def _phase_unit(value: PhaseUnitStateBinding) -> dict[str, Any]:
    return {
        "workUnit": value.work_unit,
        "status": value.status,
        "contractDigest": value.contract_digest,
        "sourceCommit": value.source_commit,
        "approvalDigest": value.approval_digest,
    }


def _actor(verifier: OidcProvenanceVerifier) -> dict[str, str]:
    return {
        "principal": verifier.principal,
        "role": verifier.role,
        "organization": verifier.organization,
    }


def _require_verifier(
    verifier: OidcProvenanceVerifier,
    *,
    namespace: str,
    source_commit: str,
    control_plane_digest: str,
    state_digest: str | None = None,
    chain_head_digest: str | None = None,
) -> None:
    try:
        _require_oidc_verifier(verifier)
    except OidcProvenanceError as exc:
        _translate(exc)
    if verifier.namespace != namespace:
        _fail(
            "provenance_namespace_mismatch",
            "oidcVerifier.namespace",
            "writer requires an authority sealed for this statement namespace",
        )
    if (
        verifier.source_commit != source_commit
        or verifier.workflow_execution_commit != source_commit
    ):
        _fail(
            "source_commit_mismatch",
            "oidcVerifier.sourceCommit",
            "statement source must equal the current protected workflow commit",
        )
    if verifier.control_plane_digest != control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "oidcVerifier.controlPlaneDigest",
            "statement and protected authority use different control planes",
        )
    if state_digest is not None and verifier.state_digest != state_digest:
        _fail(
            "state_digest_mismatch",
            "oidcVerifier.stateDigest",
            "proof authority targets another verified state",
        )
    if (
        chain_head_digest is not None
        and verifier.chain_head_digest != chain_head_digest
    ):
        _fail(
            "chain_head_digest_mismatch",
            "oidcVerifier.chainHeadDigest",
            "proof authority targets another verified chain head",
        )


def _impact_map_digest(verifier: OidcProvenanceVerifier) -> str:
    digest = dict(verifier.component_digests).get(IMPACT_MAP_PATH)
    if not isinstance(digest, str):
        _fail(
            "approved_impact_map_missing",
            "oidcVerifier.componentDigests",
            "sealed authority does not contain the approved impact-map blob",
        )
    return digest


def _sign(
    *,
    schema: str,
    kind: str,
    namespace: str,
    body: Mapping[str, Any],
    verifier: OidcProvenanceVerifier,
    token_provider: TokenProvider | None,
) -> dict[str, Any]:
    statement = {"schemaVersion": schema, "kind": kind, "body": dict(body)}
    payload = canonical_json_bytes(statement)
    audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + sha256_bytes(payload)
    provider = (
        github_actions_provenance_token_provider
        if token_provider is None
        else token_provider
    )
    try:
        token = provider(audience)
    except ProvenanceWriterError:
        raise
    except OidcProvenanceError as exc:
        _translate(exc)
    except Exception:
        _fail("token_provider_failed", "tokenProvider", "OIDC token provider failed")
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token.encode("ascii")) > MAX_TOKEN_BYTES
    ):
        _fail("invalid_oidc_token", "tokenProvider", "provider returned no bounded JWT")
    envelope = {
        **statement,
        "signature": {
            "scheme": OIDC_SIGNATURE_SCHEME,
            "namespace": namespace,
            "principal": verifier.principal,
            "value": token,
        },
    }
    envelope["attestationDigest"] = document_digest(envelope)
    return envelope


def _work_target(
    state: VerifiedWorkUnitStateContext, freeze: VerifiedProtectedInputFreeze
) -> str:
    kinds = {criterion.kind for criterion in freeze.criteria}
    if state.status == "ACTIVE":
        return "MACHINE_CONVERGED"
    if state.status == "MACHINE_CONVERGED":
        if kinds & {"EXTERNAL", "TIME"}:
            return "WAITING_EXTERNAL"
        if "HUMAN" in kinds:
            return "REVIEW_PENDING"
        return "CONVERGED"
    if state.status == "WAITING_EXTERNAL":
        return "REVIEW_PENDING" if "HUMAN" in kinds else "CONVERGED"
    if state.status == "REVIEW_PENDING":
        return "CONVERGED"
    _fail(
        "unsupported_work_unit_operation",
        "stateContext.status",
        "state is not at a convergence proof boundary",
    )


def _phase_target(
    state: VerifiedPhaseStateContext, freeze: VerifiedPhaseProtectedInputFreeze
) -> str:
    kinds = {criterion.kind for criterion in freeze.criteria}
    if state.status == "ACTIVE":
        return "MACHINE_CONVERGED"
    if state.status == "MACHINE_CONVERGED":
        if kinds & {"EXTERNAL", "TIME"}:
            return "WAITING_EXTERNAL"
        if "HUMAN" in kinds:
            return "REVIEW_PENDING"
        return "CONVERGED"
    if state.status == "WAITING_EXTERNAL":
        return "REVIEW_PENDING" if "HUMAN" in kinds else "CONVERGED"
    if state.status == "REVIEW_PENDING":
        return "CONVERGED"
    _fail(
        "unsupported_phase_operation",
        "phaseStateContext.status",
        "phase is not at an aggregate convergence proof boundary",
    )


def _require_work_inputs(
    *,
    freeze: VerifiedProtectedInputFreeze,
    results: Sequence[VerifiedCriterionResult],
    state: VerifiedWorkUnitStateContext,
) -> list[VerifiedCriterionResult]:
    try:
        _require_provenance_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
        _require_provenance_verified(
            state, VerifiedWorkUnitStateContext, "stateContext"
        )
        verified = list(results)
        for index, result in enumerate(verified):
            _require_provenance_verified(
                result, VerifiedCriterionResult, f"criterionResults[{index}]"
            )
    except ProtectedVerificationError as exc:
        _translate(exc)
    if (
        freeze.subject.phase != state.phase
        or freeze.subject.work_unit != state.work_unit
        or freeze.subject.control_plane_digest != state.control_plane_digest
        or freeze.subject.contract_digest != state.contract_digest
    ):
        _fail(
            "state_subject_mismatch", "stateContext", "freeze belongs to another unit"
        )
    ids = [result.criterion.criterion_id for result in verified]
    if len(ids) != len(set(ids)):
        _fail("duplicate_criterion_result", "criterionResults", "duplicate result")
    if any(
        result.freeze_digest != freeze.attestation_digest
        or result.subject != freeze.subject
        or not result.criterion_satisfied
        for result in verified
    ):
        _fail(
            "criterion_result_replay",
            "criterionResults",
            "every result must be sealed, satisfied, and bound to the exact freeze",
        )
    return sorted(verified, key=lambda item: item.criterion.criterion_id)


def create_signed_work_unit_transition_proof(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_results: Sequence[VerifiedCriterionResult],
    state_context: VerifiedWorkUnitStateContext,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedTransitionProofResult]:
    """Create the unique next convergence proof for one sealed work unit."""

    results = _require_work_inputs(
        freeze=freeze, results=criterion_results, state=state_context
    )
    target = _work_target(state_context, freeze)
    try:
        required_kinds = _required_criterion_kinds(state_context.status, target, freeze)
    except ProtectedVerificationError as exc:
        _translate(exc)
    required_ids = {
        criterion.criterion_id
        for criterion in freeze.criteria
        if criterion.kind in required_kinds
    }
    if target == "MACHINE_CONVERGED" and not required_ids:
        _fail(
            "missing_machine_criterion",
            "freeze.criteria",
            "MACHINE_CONVERGED requires at least one frozen MACHINE criterion",
        )
    if {result.criterion.criterion_id for result in results} != required_ids:
        _fail(
            "incomplete_criterion_set",
            "criterionResults",
            "sealed results are not the exact set required for the next transition",
        )
    _require_verifier(
        verifier,
        namespace=PROOF_NAMESPACE,
        source_commit=freeze.subject.source_commit,
        control_plane_digest=freeze.subject.control_plane_digest,
        state_digest=state_context.state_digest,
        chain_head_digest=state_context.chain_head_digest,
    )
    projection = [
        {
            "criterionId": result.criterion.criterion_id,
            "kind": result.criterion.kind,
            "resultDigest": result.attestation_digest,
            "evidenceDigest": result.evidence_digest,
        }
        for result in results
    ]
    proof_id = _stable_id(
        "proof",
        {
            "freezeDigest": freeze.attestation_digest,
            "stateDigest": state_context.state_digest,
            "chainHeadDigest": state_context.chain_head_digest,
            "toState": target,
            "criterionResults": projection,
        },
    )
    body = {
        "proofId": proof_id,
        "freezeDigest": freeze.attestation_digest,
        "subject": _subject(freeze.subject),
        "fromState": state_context.status,
        "toState": target,
        "priorStateDigest": state_context.state_digest,
        "priorChainHeadDigest": state_context.chain_head_digest,
        "criterionResults": projection,
        "issuedAt": _format_utc(issued_at),
        "actor": _actor(verifier),
        "authorityDigest": verifier.authority_digest,
    }
    envelope = _sign(
        schema=PROOF_SCHEMA,
        kind=PROOF_KIND,
        namespace=PROOF_NAMESPACE,
        body=body,
        verifier=verifier,
        token_provider=token_provider,
    )
    try:
        result = verify_verified_transition_proof(
            envelope,
            freeze=freeze,
            criterion_results=results,
            state_context=state_context,
            expected_to_state=target,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _translate(exc)
    return envelope, result


def create_signed_activation_proof(
    *,
    freeze: VerifiedProtectedInputFreeze,
    state_context: VerifiedWorkUnitStateContext,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedActivationProofResult]:
    """Create a READY -> ACTIVE proof from sealed contract and state inputs."""

    _require_work_inputs(freeze=freeze, results=(), state=state_context)
    if state_context.status != "READY":
        _fail("invalid_activation_state", "stateContext", "activation requires READY")
    _require_verifier(
        verifier,
        namespace=ACTIVATION_PROOF_NAMESPACE,
        source_commit=freeze.subject.source_commit,
        control_plane_digest=freeze.subject.control_plane_digest,
        state_digest=state_context.state_digest,
        chain_head_digest=state_context.chain_head_digest,
    )
    impact_map_digest = _impact_map_digest(verifier)
    prerequisites = [_prerequisite(item) for item in state_context.prerequisites]
    proof_id = _stable_id(
        "activation",
        {
            "subject": _subject(freeze.subject),
            "stateDigest": state_context.state_digest,
            "chainHeadDigest": state_context.chain_head_digest,
            "contractApprovalDigest": freeze.contract_approval_digest,
            "impactMapDigest": impact_map_digest,
            "prerequisites": prerequisites,
        },
    )
    body = {
        "proofId": proof_id,
        "subject": _subject(freeze.subject),
        "fromState": "READY",
        "toState": "ACTIVE",
        "priorStateDigest": state_context.state_digest,
        "priorChainHeadDigest": state_context.chain_head_digest,
        "contractApprovalDigest": freeze.contract_approval_digest,
        "impactMapDigest": impact_map_digest,
        "prerequisites": prerequisites,
        "issuedAt": _format_utc(issued_at),
        "actor": _actor(verifier),
        "authorityDigest": verifier.authority_digest,
    }
    envelope = _sign(
        schema=ACTIVATION_PROOF_SCHEMA,
        kind=ACTIVATION_PROOF_KIND,
        namespace=ACTIVATION_PROOF_NAMESPACE,
        body=body,
        verifier=verifier,
        token_provider=token_provider,
    )
    try:
        result = verify_activation_proof(
            envelope,
            state_context=state_context,
            expected_subject=freeze.subject,
            expected_contract_approval_digest=freeze.contract_approval_digest,
            expected_impact_map_digest=impact_map_digest,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _translate(exc)
    return envelope, result


def create_signed_lifecycle_proof(
    *,
    freeze: VerifiedProtectedInputFreeze,
    state_context: VerifiedWorkUnitStateContext,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    lifecycle_evidence: (
        VerifiedBlockerResolution
        | VerifiedInvalidationEvidence
        | VerifiedSupersessionApproval
        | None
    ) = None,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedLifecycleProofResult]:
    """Create a lifecycle proof from readiness or one exact sealed evidence object."""

    _require_work_inputs(freeze=freeze, results=(), state=state_context)
    transition_type: str
    to_state: str
    reason_code: str
    reason: str
    blocker_resolution_digest: str | None = None
    invalidation_kind: str | None = None
    invalidation_digest: str | None = None
    primary_evidence_digest: str | None = None
    if state_context.status in {"NOT_STARTED", "REJECTED"}:
        if lifecycle_evidence is not None:
            _fail(
                "unexpected_lifecycle_evidence",
                "lifecycleEvidence",
                "READINESS does not consume blocker, invalidation, or supersession evidence",
            )
        transition_type = "READINESS"
        to_state = "READY"
        reason_code = (
            "approved-prerequisites-ready"
            if state_context.status == "NOT_STARTED"
            else "approved-replacement-contract-ready"
        )
        reason = (
            "Protected workflow verified prerequisites and the approved contract freeze."
            if state_context.status == "NOT_STARTED"
            else "Protected workflow verified the approved replacement contract freeze."
        )
    elif isinstance(lifecycle_evidence, VerifiedBlockerResolution):
        try:
            resolution = require_verified_blocker_resolution(lifecycle_evidence)
        except LifecycleEvidenceError as exc:
            _fail(exc.code, exc.path, exc.message)
        if (
            state_context.status != "BLOCKED"
            or resolution.subject != freeze.subject
            or resolution.from_state != state_context.status
            or resolution.to_state != "ACTIVE"
            or resolution.prior_state_digest != state_context.state_digest
            or resolution.prior_chain_head_digest != state_context.chain_head_digest
        ):
            _fail(
                "lifecycle_evidence_replay",
                "lifecycleEvidence",
                "BlockerResolution differs from exact freeze/state/head/transition",
            )
        transition_type = "RESUME"
        to_state = "ACTIVE"
        reason_code = resolution.reason_code
        reason = resolution.reason
        blocker_resolution_digest = resolution.attestation_digest
        primary_evidence_digest = resolution.attestation_digest
    elif isinstance(lifecycle_evidence, VerifiedInvalidationEvidence):
        try:
            require_verified_invalidation_evidence(lifecycle_evidence)
        except LifecycleEvidenceError as exc:
            _fail(exc.code, exc.path, exc.message)
        _fail(
            "unsupported_invalidation_batch_semantics",
            "lifecycleEvidence",
            "state-chain v1 cannot atomically invalidate every affected work unit and phase",
        )
    elif isinstance(lifecycle_evidence, VerifiedSupersessionApproval):
        try:
            require_verified_supersession_approval(lifecycle_evidence)
        except LifecycleEvidenceError as exc:
            _fail(exc.code, exc.path, exc.message)
        _fail(
            "unsupported_control_plane_revision",
            "lifecycleEvidence.replacementSubject",
            "state-chain v1 cannot atomically replace the authoritative contract/control-plane subject",
        )
    elif lifecycle_evidence is not None:
        _fail(
            "unverified_lifecycle_evidence",
            "lifecycleEvidence",
            "unsupported or reconstructed lifecycle evidence object",
        )
    else:
        _fail(
            "unsupported_lifecycle_operation",
            "stateContext.status",
            "this state requires exact sealed RESUME, INVALIDATION, or SUPERSESSION evidence",
        )
    _require_verifier(
        verifier,
        namespace=LIFECYCLE_PROOF_NAMESPACE,
        source_commit=freeze.subject.source_commit,
        control_plane_digest=freeze.subject.control_plane_digest,
        state_digest=state_context.state_digest,
        chain_head_digest=state_context.chain_head_digest,
    )
    impact_map_digest = _impact_map_digest(verifier)
    if (
        isinstance(lifecycle_evidence, VerifiedInvalidationEvidence)
        and lifecycle_evidence.impact_map_digest != impact_map_digest
    ):
        _fail(
            "impact_map_digest_mismatch",
            "lifecycleEvidence.impactMapDigest",
            "sealed invalidation and lifecycle proof authority use different impact maps",
        )
    prerequisites = [_prerequisite(item) for item in state_context.prerequisites]
    proof_id = _stable_id(
        "lifecycle",
        {
            "subject": _subject(freeze.subject),
            "fromState": state_context.status,
            "toState": to_state,
            "stateDigest": state_context.state_digest,
            "chainHeadDigest": state_context.chain_head_digest,
            "contractApprovalDigest": freeze.contract_approval_digest,
            "impactMapDigest": impact_map_digest,
            "prerequisites": prerequisites,
            "primaryEvidenceDigest": primary_evidence_digest,
        },
    )
    body = {
        "proofId": proof_id,
        "transitionType": transition_type,
        "subject": _subject(freeze.subject),
        "fromState": state_context.status,
        "toState": to_state,
        "priorStateDigest": state_context.state_digest,
        "priorChainHeadDigest": state_context.chain_head_digest,
        "contractApprovalDigest": freeze.contract_approval_digest,
        "impactMapDigest": impact_map_digest,
        "prerequisites": prerequisites,
        "reasonCode": reason_code,
        "reason": reason,
        "blockerResolutionDigest": blocker_resolution_digest,
        "invalidationKind": invalidation_kind,
        "invalidationDigest": invalidation_digest,
        "issuedAt": _format_utc(issued_at),
        "actor": _actor(verifier),
        "authorityDigest": verifier.authority_digest,
    }
    envelope = _sign(
        schema=LIFECYCLE_PROOF_SCHEMA,
        kind=LIFECYCLE_PROOF_KIND,
        namespace=LIFECYCLE_PROOF_NAMESPACE,
        body=body,
        verifier=verifier,
        token_provider=token_provider,
    )
    try:
        result = verify_lifecycle_proof(
            envelope,
            state_context=state_context,
            expected_subject=freeze.subject,
            expected_to_state=to_state,
            expected_contract_approval_digest=freeze.contract_approval_digest,
            expected_impact_map_digest=impact_map_digest,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _translate(exc)
    return envelope, result


create_signed_readiness_proof = create_signed_lifecycle_proof


def create_signed_phase_machine_criterion_result(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedPhaseRunPair,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedPhaseCriterionResult]:
    """Create one phase MACHINE result from an exact sealed aggregate pair."""

    namespace = PHASE_CRITERION_NAMESPACES["MACHINE"]
    try:
        _require_provenance_verified(
            freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze"
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    _require_verifier(
        verifier,
        namespace=namespace,
        source_commit=freeze.subject.source_commit,
        control_plane_digest=freeze.subject.control_plane_digest,
    )
    try:
        projection = phase_criterion_result_projection(
            freeze=freeze, criterion_id=criterion_id, run_pair=run_pair
        )
    except GateRunnerError as exc:
        _translate(exc)
    matches = [
        criterion
        for criterion in freeze.criteria
        if criterion.criterion_id == criterion_id and criterion.kind == "MACHINE"
    ]
    if len(matches) != 1:
        _fail(
            "invalid_machine_criterion",
            "criterionId",
            "exact MACHINE criterion required",
        )
    criterion = matches[0]
    pair_document = json.loads(canonical_json_bytes(projection["runPair"]))
    pair_digest = document_digest(pair_document)
    if pair_digest != projection["evidenceDigest"]:
        _fail("run_pair_digest_mismatch", "runPair", "sealed phase pair digest drift")
    result_id = _stable_id(
        "phase-result",
        {
            "freezeDigest": freeze.attestation_digest,
            "criterionId": criterion.criterion_id,
            "runPairDigest": pair_digest,
        },
    )
    body = {
        "resultId": result_id,
        "freezeDigest": freeze.attestation_digest,
        "subject": _phase_subject(freeze.subject),
        "criterion": _criterion(criterion),
        "outcome": projection["outcome"],
        "evidenceDigest": pair_digest,
        "runPair": pair_document,
        "runPairDigest": pair_digest,
        "humanReview": None,
        "issuedAt": _format_utc(issued_at),
        "actor": _actor(verifier),
        "authorityDigest": verifier.authority_digest,
    }
    envelope = _sign(
        schema=PHASE_CRITERION_SCHEMA,
        kind=PHASE_CRITERION_KIND,
        namespace=namespace,
        body=body,
        verifier=verifier,
        token_provider=token_provider,
    )
    try:
        result = verify_signed_phase_criterion_result(
            envelope,
            freeze=freeze,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _translate(exc)
    return envelope, result


def _require_phase_inputs(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    results: Sequence[VerifiedPhaseCriterionResult],
    state: VerifiedPhaseStateContext,
) -> list[VerifiedPhaseCriterionResult]:
    try:
        _require_provenance_verified(
            freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze"
        )
        _require_provenance_verified(
            state, VerifiedPhaseStateContext, "phaseStateContext"
        )
        verified = list(results)
        for index, result in enumerate(verified):
            _require_provenance_verified(
                result,
                VerifiedPhaseCriterionResult,
                f"phaseCriterionResults[{index}]",
            )
    except ProtectedVerificationError as exc:
        _translate(exc)
    if (
        freeze.subject.phase != state.phase
        or freeze.subject.control_plane_digest != state.control_plane_digest
        or freeze.subject.aggregate_contract_digest != state.aggregate_contract_digest
    ):
        _fail(
            "state_subject_mismatch",
            "phaseStateContext",
            "freeze belongs to another phase",
        )
    ids = [result.criterion.criterion_id for result in verified]
    if len(ids) != len(set(ids)):
        _fail("duplicate_criterion_result", "phaseCriterionResults", "duplicate result")
    if any(
        result.freeze_digest != freeze.attestation_digest
        or result.subject != freeze.subject
        or not result.criterion_satisfied
        for result in verified
    ):
        _fail(
            "criterion_result_replay",
            "phaseCriterionResults",
            "every result must be sealed, satisfied, and bound to the aggregate freeze",
        )
    return sorted(verified, key=lambda item: item.criterion.criterion_id)


def create_signed_phase_transition_proof(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_results: Sequence[VerifiedPhaseCriterionResult],
    state_context: VerifiedPhaseStateContext,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedPhaseTransitionProofResult]:
    """Create the unique next aggregate proof from sealed phase evidence."""

    results = _require_phase_inputs(
        freeze=freeze, results=criterion_results, state=state_context
    )
    target = _phase_target(state_context, freeze)
    try:
        required_ids, deferred = _required_phase_criterion_ids(
            state_context.status, target, freeze
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    if target == "MACHINE_CONVERGED" and not required_ids:
        _fail(
            "missing_machine_criterion",
            "phaseFreeze.criteria",
            "MACHINE_CONVERGED requires at least one aggregate MACHINE criterion",
        )
    if {result.criterion.criterion_id for result in results} != required_ids:
        _fail(
            "incomplete_criterion_set",
            "phaseCriterionResults",
            "sealed results are not the exact set required for the next aggregate transition",
        )
    _require_verifier(
        verifier,
        namespace=PHASE_PROOF_NAMESPACE,
        source_commit=freeze.subject.source_commit,
        control_plane_digest=freeze.subject.control_plane_digest,
        state_digest=state_context.state_digest,
        chain_head_digest=state_context.chain_head_digest,
    )
    unit_states = [_phase_unit(unit) for unit in state_context.units]
    result_projection = [
        {
            "criterionId": result.criterion.criterion_id,
            "kind": result.criterion.kind,
            "resultDigest": result.attestation_digest,
            "evidenceDigest": result.evidence_digest,
        }
        for result in results
    ]
    proof_id = _stable_id(
        "phase-proof",
        {
            "freezeDigest": freeze.attestation_digest,
            "stateDigest": state_context.state_digest,
            "chainHeadDigest": state_context.chain_head_digest,
            "toState": target,
            "unitStates": unit_states,
            "criterionResults": result_projection,
            "deferredGoNoGoCriterionId": deferred,
        },
    )
    body = {
        "proofId": proof_id,
        "freezeDigest": freeze.attestation_digest,
        "subject": _phase_subject(freeze.subject),
        "fromState": state_context.status,
        "toState": target,
        "priorStateDigest": state_context.state_digest,
        "priorChainHeadDigest": state_context.chain_head_digest,
        "unitStates": unit_states,
        "criterionResults": result_projection,
        "deferredGoNoGoCriterionId": deferred,
        "issuedAt": _format_utc(issued_at),
        "actor": _actor(verifier),
        "authorityDigest": verifier.authority_digest,
    }
    envelope = _sign(
        schema=PHASE_PROOF_SCHEMA,
        kind=PHASE_PROOF_KIND,
        namespace=PHASE_PROOF_NAMESPACE,
        body=body,
        verifier=verifier,
        token_provider=token_provider,
    )
    try:
        result = verify_phase_transition_proof(
            envelope,
            freeze=freeze,
            criterion_results=results,
            state_context=state_context,
            expected_to_state=target,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _translate(exc)
    return envelope, result


__all__ = [
    "ProvenanceWriterError",
    "create_signed_activation_proof",
    "create_signed_lifecycle_proof",
    "create_signed_machine_criterion_result",
    "create_signed_phase_machine_criterion_result",
    "create_signed_phase_transition_proof",
    "create_signed_readiness_proof",
    "create_signed_work_unit_transition_proof",
]
