"""Replay R3 post-Genesis StateTransition and EvidenceAttachment events.

The replay boundary is deliberately narrow.  Genesis is delegated to the R3
protected verifier.  Every later event is independently verified against the
pinned GitHub Actions OIDC claims and is paired, by position, with one
identity-sealed provenance result.  No caller-controlled digest registry is
accepted.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence
import weakref

from .digest import canonical_json_bytes, sha256_bytes
from .oidc import (
    OidcVerificationError,
    validate_jwks_snapshot,
    verify_github_actions_oidc_token,
)
from .protected import (
    ALLOWED_TRANSITIONS,
    ProtectedVerificationError,
    _exact_keys,
    _parse_utc,
    _require_commit,
    _require_nonempty,
    _require_sha256,
    _state_core_digest,
    _validate_state_invariants,
    document_digest,
)
from .protected_v2 import (
    OIDC_AUDIENCE_PREFIX,
    OIDC_SIGNATURE_SCHEME,
    STATE_EVENT_KIND,
    STATE_EVENT_NAMESPACE,
    STATE_EVENT_SCHEMA,
    STATE_VIEW_SCHEMA,
    _expected_oidc_claims,
    _verify_workflow_blob,
    verify_genesis_event_v2,
)
from .provenance import (
    VerifiedCriterionResult,
    VerifiedProtectedInputFreeze,
    VerifiedTransitionApprovalResult,
    VerifiedTransitionProofResult,
    VerifiedLifecycleTransition,
    VerifiedPhaseTransition,
    VerifiedWorkUnitTransition,
    _require_verified as _require_provenance_verified,
)


EVENT_ID_RE = re.compile(r"^evt-([0-9]{8})$")
PENDING_STATUSES = {
    "MACHINE_CONVERGED",
    "BLOCKED",
    "WAITING_EXTERNAL",
    "REVIEW_PENDING",
}
EXECUTED_VERIFIER_PATHS = (
    "tools/phasegate/__init__.py",
    "tools/phasegate/chain_artifact.py",
    "tools/phasegate/chain_witness.py",
    "tools/phasegate/community_facts.py",
    "tools/phasegate/control_context.py",
    "tools/phasegate/delegation.py",
    "tools/phasegate/digest.py",
    "tools/phasegate/evidence_index.py",
    "tools/phasegate/execution_artifact.py",
    "tools/phasegate/external_facts.py",
    "tools/phasegate/gate_runner.py",
    "tools/phasegate/lifecycle_bundle.py",
    "tools/phasegate/lifecycle_evidence.py",
    "tools/phasegate/main.py",
    "tools/phasegate/oidc.py",
    "tools/phasegate/oidc_provenance.py",
    "tools/phasegate/p00_evaluators.py",
    "tools/phasegate/phase_bundle.py",
    "tools/phasegate/phase_evidence.py",
    "tools/phasegate/post_event_writer.py",
    "tools/phasegate/protected.py",
    "tools/phasegate/protected_v2.py",
    "tools/phasegate/provenance.py",
    "tools/phasegate/provenance_writer.py",
    "tools/phasegate/run_executor.py",
    "tools/phasegate/serialized_bundle.py",
    "tools/phasegate/sshsig.py",
    "tools/phasegate/state_chain_v2.py",
    "tools/phasegate/state_writer.py",
    "tools/phasegate/validation.py",
    "tools/phasegate/workflow_orchestrator.py",
)


@dataclass(frozen=True)
class VerifiedGenesisAnchorV2:
    state_core: Mapping[str, Any]
    state_digest: str
    chain_head_digest: str
    head_sequence: int
    event_count: int
    timestamp: datetime
    head_source_commit: str
    attachments: tuple[Mapping[str, Any], ...]
    control_plane_digest: str
    trust_policy_digest: str
    jwks_snapshot_digest: str
    workflow_execution_commit: str
    workflow_run_id: str
    workflow_check_run_id: str
    approved_component_digests: tuple[tuple[str, str], ...]
    state_signer_digest: str
    bootstrap_approval_digest: str
    bootstrap_request_digest: str


@dataclass(frozen=True)
class VerifiedEvidenceAttachmentV2:
    subject_phase: str
    subject_work_unit: str
    source_commit: str
    control_plane_digest: str
    contract_digest: str
    freeze_digest: str
    criterion_result_digests: tuple[str, ...]
    proof_digest: str | None
    approval_digest: str | None
    attachment_digest: str


@dataclass(frozen=True)
class VerifiedStateChainV2:
    state_core: Mapping[str, Any]
    state_digest: str
    attachments: tuple[Mapping[str, Any], ...]
    event_count: int
    head_sequence: int
    head_digest: str
    head_timestamp: datetime
    head_source_commit: str
    workflow_runs: tuple[tuple[str, str], ...]
    control_plane_digest: str
    trust_policy_digest: str
    jwks_snapshot_digest: str
    workflow_execution_commit: str
    approved_component_digests: tuple[tuple[str, str], ...]
    state_signer_digest: str
    bootstrap_approval_digest: str
    bootstrap_request_digest: str
    chain_snapshot_digest: str


@dataclass(frozen=True)
class VerifiedProjectedStateTransitionV2:
    payload: Mapping[str, Any]
    resulting_state_core: Mapping[str, Any]
    resulting_state_digest: str
    projection_digest: str


@dataclass(frozen=True)
class VerifiedProjectedEvidenceAttachmentV2:
    payload: Mapping[str, Any]
    resulting_state_digest: str
    projection_digest: str


_VERIFIED_OBJECTS: dict[int, weakref.ReferenceType[Any]] = {}


def _fail(code: str, path: str, message: str) -> None:
    raise ProtectedVerificationError(code, path, message)


def _mark_verified(value: Any) -> Any:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if _VERIFIED_OBJECTS.get(identity) is reference:
            _VERIFIED_OBJECTS.pop(identity, None)

    _VERIFIED_OBJECTS[identity] = weakref.ref(value, discard)
    return value


def _require_verified(value: Any, expected_type: type, path: str) -> None:
    reference = _VERIFIED_OBJECTS.get(id(value))
    if (
        not isinstance(value, expected_type)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact identity-sealed result returned by this verifier",
        )


def _state_core_from_view(view: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "planVersion",
        "controlPlaneDigest",
        "activePhase",
        "activeWorkUnit",
        "pendingWorkUnit",
        "phases",
    }
    if not fields.issubset(view):
        _fail("invalid_genesis_view", "genesisView", "state core fields are missing")
    return {name: deepcopy(view[name]) for name in fields}


def _chain_snapshot_digest(
    *,
    state_core: Mapping[str, Any],
    attachments: Sequence[Mapping[str, Any]],
    event_count: int,
    head_sequence: int,
    head_digest: str,
    head_timestamp: datetime,
    head_source_commit: str,
    workflow_runs: Sequence[tuple[str, str]],
    control_plane_digest: str,
    trust_policy_digest: str,
    jwks_snapshot_digest: str,
    workflow_execution_commit: str,
    approved_component_digests: Sequence[tuple[str, str]],
    state_signer_digest: str,
    bootstrap_approval_digest: str,
    bootstrap_request_digest: str,
) -> str:
    return document_digest(
        {
            "stateCore": state_core,
            "attachments": list(attachments),
            "eventCount": event_count,
            "headSequence": head_sequence,
            "headDigest": head_digest,
            "headTimestamp": head_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "headSourceCommit": head_source_commit,
            "workflowRuns": [list(item) for item in workflow_runs],
            "controlPlaneDigest": control_plane_digest,
            "trustPolicyDigest": trust_policy_digest,
            "jwksSnapshotDigest": jwks_snapshot_digest,
            "workflowExecutionCommit": workflow_execution_commit,
            "approvedComponentDigests": dict(approved_component_digests),
            "stateSignerDigest": state_signer_digest,
            "bootstrapApprovalDigest": bootstrap_approval_digest,
            "bootstrapRequestDigest": bootstrap_request_digest,
        }
    )


def verify_genesis_anchor_v2(
    *,
    event: Any,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    jwks_snapshot: Any,
    expected_control_plane_digest: str,
    expected_chain_head_digest: str,
    contract_digests: Mapping[str, str],
    repo_root: Path,
) -> VerifiedGenesisAnchorV2:
    """Verify R3 Genesis and seal the state/chain anchor for later replay."""

    result = verify_genesis_event_v2(
        event=event,
        policy_result=policy_result,
        approval_result=approval_result,
        jwks_snapshot=jwks_snapshot,
        expected_control_plane_digest=expected_control_plane_digest,
        expected_chain_head_digest=expected_chain_head_digest,
        contract_digests=contract_digests,
        repo_root=repo_root,
    )
    if not isinstance(result, dict) or result.get("schemaVersion") != STATE_VIEW_SCHEMA:
        _fail("invalid_genesis_view", "genesisView", "R3 verifier returned no state view")
    core = _state_core_from_view(result)
    state_digest = _state_core_digest(core)
    if result.get("stateDigest") != state_digest:
        _fail("state_digest_mismatch", "genesisView.stateDigest", "Genesis state drift")
    chain = _exact_keys(
        result.get("chain"),
        {"eventCount", "headSequence", "headDigest"},
        "genesisView.chain",
    )
    if chain != {
        "eventCount": 1,
        "headSequence": 0,
        "headDigest": expected_chain_head_digest,
    }:
        _fail("invalid_genesis_view", "genesisView.chain", "invalid Genesis chain anchor")
    attachments = result.get("attachments")
    if attachments != []:
        _fail("invalid_genesis_view", "genesisView.attachments", "Genesis cannot attach evidence")
    body = event.get("body") if isinstance(event, dict) else None
    timestamp = _parse_utc(
        body.get("timestamp") if isinstance(body, dict) else None,
        "genesisEvent.body.timestamp",
    )
    head_source_commit = _require_commit(
        body.get("sourceCommit") if isinstance(body, dict) else None,
        "genesisEvent.body.sourceCommit",
    )
    _validate_state_invariants(core)
    policy_digest = _require_sha256(policy_result.get("digest"), "policyResult.digest")
    jwks_digest = _require_sha256(
        approval_result.get("jwksSnapshotDigest"),
        "approvalResult.jwksSnapshotDigest",
    )
    workflow_commit = _require_commit(
        approval_result.get("workflowExecutionCommit"),
        "approvalResult.workflowExecutionCommit",
    )
    if (
        approval_result.get("status") != "verified"
        or approval_result.get("decision") != "APPROVE"
        or approval_result.get("controlPlaneDigest") != expected_control_plane_digest
        or approval_result.get("trustPolicyDigest") != policy_digest
    ):
        _fail(
            "genesis_trust_binding_mismatch",
            "approvalResult",
            "Genesis requires the exact verified APPROVE bootstrap decision",
        )
    bootstrap_approval_digest = _require_sha256(
        approval_result.get("approvalDigest"), "approvalResult.approvalDigest"
    )
    bootstrap_request_digest = _require_sha256(
        approval_result.get("requestDigest"), "approvalResult.requestDigest"
    )
    components = approval_result.get("componentDigests")
    if not isinstance(components, Mapping):
        _fail(
            "invalid_component_digests",
            "approvalResult.componentDigests",
            "approved component digest mapping is required",
        )
    if any(not isinstance(component_path, str) or not component_path for component_path in components):
        _fail("invalid_component_digests", "approvalResult.componentDigests", "invalid path")
    approved_components: list[tuple[str, str]] = []
    for component_path in sorted(components):
        approved_components.append(
            (
                component_path,
                _require_sha256(
                    components[component_path],
                    f"approvalResult.componentDigests.{component_path}",
                ),
            )
        )
    provenance = result.get("provenance")
    if not isinstance(provenance, dict):
        _fail("invalid_genesis_view", "genesisView.provenance", "provenance missing")
    workflow_run_id = provenance.get("workflowRunId")
    workflow_check_run_id = provenance.get("workflowCheckRunId")
    if (
        not isinstance(workflow_run_id, str)
        or not workflow_run_id.isdigit()
        or not isinstance(workflow_check_run_id, str)
        or not workflow_check_run_id.isdigit()
    ):
        _fail("invalid_genesis_view", "genesisView.provenance", "workflow run identity missing")
    return _mark_verified(
        VerifiedGenesisAnchorV2(
            state_core=core,
            state_digest=state_digest,
            chain_head_digest=expected_chain_head_digest,
            head_sequence=0,
            event_count=1,
            timestamp=timestamp,
            head_source_commit=head_source_commit,
            attachments=(),
            control_plane_digest=expected_control_plane_digest,
            trust_policy_digest=policy_digest,
            jwks_snapshot_digest=jwks_digest,
            workflow_execution_commit=workflow_commit,
            workflow_run_id=workflow_run_id,
            workflow_check_run_id=workflow_check_run_id,
            approved_component_digests=tuple(approved_components),
            state_signer_digest=document_digest(policy_result.get("stateSigner")),
            bootstrap_approval_digest=bootstrap_approval_digest,
            bootstrap_request_digest=bootstrap_request_digest,
        )
    )


def authorize_evidence_attachment_v2(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_results: Sequence[VerifiedCriterionResult] = (),
    proof: VerifiedTransitionProofResult | None = None,
    approval: VerifiedTransitionApprovalResult | None = None,
) -> VerifiedEvidenceAttachmentV2:
    """Seal an exact provenance bundle for a non-state-changing attachment."""

    _require_provenance_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
    results = list(criterion_results)
    for index, result in enumerate(results):
        _require_provenance_verified(
            result, VerifiedCriterionResult, f"criterionResults[{index}]"
        )
    result_ids = [item.criterion.criterion_id for item in results]
    if result_ids != sorted(set(result_ids)):
        _fail(
            "invalid_criterion_set",
            "criterionResults",
            "criterion results must be sorted and unique",
        )
    if any(
        item.freeze_digest != freeze.attestation_digest
        or item.subject != freeze.subject
        for item in results
    ):
        _fail(
            "criterion_result_replay",
            "criterionResults",
            "criterion result belongs to another freeze/unit/commit",
        )
    projection = tuple(item.attestation_digest for item in results)
    if proof is not None:
        _require_provenance_verified(proof, VerifiedTransitionProofResult, "proof")
        actual_proof_projection = tuple(
            (
                item.criterion.criterion_id,
                item.criterion.kind,
                item.attestation_digest,
                item.evidence_digest,
            )
            for item in results
        )
        if (
            proof.freeze_digest != freeze.attestation_digest
            or proof.subject != freeze.subject
            or actual_proof_projection != proof.criterion_results
        ):
            _fail(
                "proof_attachment_mismatch",
                "proof",
                "proof does not bind the exact attached freeze/result set",
            )
    elif approval is not None:
        _fail("approval_without_proof", "approval", "approval attachment requires proof")
    if approval is not None:
        _require_provenance_verified(
            approval, VerifiedTransitionApprovalResult, "approval"
        )
        if (
            proof is None
            or not approval.authorized
            or approval.proof_digest != proof.attestation_digest
            or approval.subject != proof.subject
        ):
            _fail(
                "approval_attachment_mismatch",
                "approval",
                "approval does not authorize the exact attached proof",
            )
    value = {
        "phase": freeze.subject.phase,
        "workUnit": freeze.subject.work_unit,
        "sourceCommit": freeze.subject.source_commit,
        "controlPlaneDigest": freeze.subject.control_plane_digest,
        "contractDigest": freeze.subject.contract_digest,
        "freezeDigest": freeze.attestation_digest,
        "criterionResultDigests": list(projection),
        "proofDigest": proof.attestation_digest if proof is not None else None,
        "approvalDigest": approval.attestation_digest if approval is not None else None,
    }
    return _mark_verified(
        VerifiedEvidenceAttachmentV2(
            subject_phase=freeze.subject.phase,
            subject_work_unit=freeze.subject.work_unit,
            source_commit=freeze.subject.source_commit,
            control_plane_digest=freeze.subject.control_plane_digest,
            contract_digest=freeze.subject.contract_digest,
            freeze_digest=freeze.attestation_digest,
            criterion_result_digests=projection,
            proof_digest=value["proofDigest"],
            approval_digest=value["approvalDigest"],
            attachment_digest=document_digest(value),
        )
    )


def _signed_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def _verify_descendant_commit(
    repo_root: Path, *, ancestor: str, descendant: str, path: str
) -> None:
    _require_commit(ancestor, f"{path}.ancestor")
    _require_commit(descendant, f"{path}.descendant")
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("git_lineage_verifier_unavailable", path, str(exc))
    if completed.returncode != 0:
        _fail(
            "source_commit_not_descendant",
            path,
            "post-event source must descend from the sealed prior head source",
        )


def _verify_oidc_event(
    event: Any,
    *,
    sequence: int,
    previous_digest: str,
    previous_timestamp: datetime,
    previous_source_commit: str,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    jwks_snapshot: Any,
    repo_root: Path,
    approved_component_digests: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any], str, datetime, Mapping[str, Any]]:
    path = f"events[{sequence}]"
    envelope = _exact_keys(
        event,
        {"schemaVersion", "kind", "body", "signature", "eventDigest"},
        path,
    )
    if envelope["schemaVersion"] != STATE_EVENT_SCHEMA or envelope["kind"] != STATE_EVENT_KIND:
        _fail("invalid_event_schema", path, "unsupported StateEvent envelope")
    event_digest = document_digest(envelope, omit_field="eventDigest")
    if envelope["eventDigest"] != event_digest:
        _fail("event_digest_mismatch", path, "event digest does not cover envelope")
    body = _exact_keys(
        envelope["body"],
        {
            "eventType",
            "eventId",
            "sequence",
            "previousDigest",
            "timestamp",
            "actor",
            "sourceCommit",
            "controlPlaneDigest",
            "trustPolicyDigest",
            "reasonCode",
            "reason",
            "writer",
            "payload",
        },
        f"{path}.body",
    )
    if not isinstance(body["payload"], dict):
        _fail("invalid_schema", f"{path}.body.payload", "payload must be an object")
    match = EVENT_ID_RE.fullmatch(body["eventId"]) if isinstance(body["eventId"], str) else None
    if (
        body["sequence"] != sequence
        or match is None
        or int(match.group(1)) != sequence
        or body["previousDigest"] != previous_digest
    ):
        _fail("event_chain_discontinuity", f"{path}.body", "sequence/previous digest mismatch")
    if body["eventType"] not in {"StateTransition", "EvidenceAttachment"}:
        _fail("invalid_event_type", f"{path}.body.eventType", "unsupported post-Genesis event")
    timestamp = _parse_utc(body["timestamp"], f"{path}.body.timestamp")
    if timestamp <= previous_timestamp:
        _fail("nonmonotonic_event_time", f"{path}.body.timestamp", "event time must increase")
    _require_commit(body["sourceCommit"], f"{path}.body.sourceCommit")
    _verify_descendant_commit(
        repo_root,
        ancestor=previous_source_commit,
        descendant=body["sourceCommit"],
        path=f"{path}.body.sourceCommit",
    )
    if body["controlPlaneDigest"] != policy_result.get("document", {}).get(
        "controlPlaneDigest"
    ):
        _fail("control_plane_digest_mismatch", f"{path}.body", "event control plane differs")
    if body["trustPolicyDigest"] != policy_result.get("digest"):
        _fail("trust_policy_digest_mismatch", f"{path}.body", "event policy differs")
    _require_nonempty(body["reasonCode"], f"{path}.body.reasonCode", maximum=256)
    _require_nonempty(body["reason"], f"{path}.body.reason")
    signer = policy_result.get("stateSigner")
    actor = _exact_keys(
        body["actor"], {"principal", "role", "organization"}, f"{path}.body.actor"
    )
    if not isinstance(signer, dict) or actor != {
        "principal": signer.get("identity"),
        "role": signer.get("role"),
        "organization": signer.get("organization"),
    }:
        _fail("actor_principal_mismatch", f"{path}.body.actor", "OIDC actor mismatch")
    workflow_commit = _require_commit(
        body["sourceCommit"], f"{path}.body.sourceCommit"
    )
    expected_claims = _expected_oidc_claims(
        policy_result, workflow_execution_commit=workflow_commit
    )
    writer = _exact_keys(
        body["writer"],
        {
            "jwksSnapshotDigest",
            "claimsPolicyDigest",
            "workflowPath",
            "workflowExecutionCommit",
        },
        f"{path}.body.writer",
    )
    if (
        writer["jwksSnapshotDigest"] != approval_result.get("jwksSnapshotDigest")
        or writer["workflowPath"] != signer.get("workflowPath")
        or writer["workflowExecutionCommit"] != body["sourceCommit"]
        or writer["claimsPolicyDigest"]
        != sha256_bytes(canonical_json_bytes(expected_claims))
    ):
        _fail("writer_binding_mismatch", f"{path}.body.writer", "writer trust binding differs")
    signature = _exact_keys(
        envelope["signature"],
        {"scheme", "namespace", "statementDigest", "jwt"},
        f"{path}.signature",
    )
    statement_digest = sha256_bytes(_signed_payload(envelope))
    if (
        signature["scheme"] != OIDC_SIGNATURE_SCHEME
        or signature["namespace"] != STATE_EVENT_NAMESPACE
        or signature["statementDigest"] != statement_digest
    ):
        _fail("signature_binding_mismatch", f"{path}.signature", "OIDC statement mismatch")
    expected_snapshot_digest = approval_result.get("jwksSnapshotDigest")
    try:
        snapshot_result = validate_jwks_snapshot(
            jwks_snapshot, expected_snapshot_digest=expected_snapshot_digest
        )
        claims = verify_github_actions_oidc_token(
            signature["jwt"],
            approved_jwks=jwks_snapshot["keys"],
            expected_audience=OIDC_AUDIENCE_PREFIX + statement_digest,
            expected_claims=expected_claims,
            statement_timestamp=timestamp,
        )
    except OidcVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if (
        snapshot_result["digest"] != policy_result.get("jwks", {}).get("digest")
        or claims["run_attempt"] != "1"
    ):
        _fail("oidc_policy_mismatch", f"{path}.signature", "OIDC trust policy differs")
    for ref_claim in ("head_ref", "base_ref"):
        if claims.get(ref_claim) not in {None, ""}:
            _fail(
                "oidc_pull_request_ref_forbidden",
                f"{path}.signature.{ref_claim}",
                "protected-main events require absent or empty PR refs",
            )
    executed_paths = (signer["workflowPath"], *EXECUTED_VERIFIER_PATHS)
    for executed_path in executed_paths:
        expected_digest = approved_component_digests.get(executed_path)
        if expected_digest is None:
            _fail(
                "workflow_source_digest_mismatch",
                executed_path,
                "approved executed-component digest is missing",
            )
        _verify_workflow_blob(
            repo_root=repo_root,
            workflow_commit=workflow_commit,
            workflow_path=executed_path,
            expected_digest=expected_digest,
        )
    return envelope, body, event_digest, timestamp, claims


def _apply_transition(
    core: dict[str, Any],
    body: Mapping[str, Any],
    transition: VerifiedWorkUnitTransition,
    *,
    verify_resulting_digest: bool = True,
) -> str:
    _require_provenance_verified(
        transition, VerifiedWorkUnitTransition, "verifiedEventInput"
    )
    payload = _exact_keys(
        body["payload"],
        {
            "transitionType",
            "phase",
            "workUnit",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractDigest",
            "proofDigest",
            "approvalDigest",
            "evidenceDigest",
            "criterionResultDigests",
            "chainHeadWitnessDigest",
            "resultingStateDigest",
        },
        "event.body.payload",
    )
    exact = {
        "transitionType": transition.transition_type,
        "phase": transition.subject.phase,
        "workUnit": transition.subject.work_unit,
        "fromState": transition.from_state,
        "toState": transition.to_state,
        "priorStateDigest": transition.prior_state_digest,
        "priorChainHeadDigest": transition.prior_chain_head_digest,
        "contractDigest": transition.subject.contract_digest,
        "proofDigest": transition.proof_digest,
        "approvalDigest": transition.approval_digest,
        "evidenceDigest": transition.evidence_digest,
        "criterionResultDigests": list(transition.criterion_result_digests),
    }
    if any(payload[key] != value for key, value in exact.items()):
        _fail("transition_binding_mismatch", "event.body.payload", "sealed transition differs")
    _require_sha256(payload["chainHeadWitnessDigest"], "event.body.payload.chainHeadWitnessDigest")
    if (
        body["sourceCommit"] != transition.subject.source_commit
        or body["controlPlaneDigest"] != transition.subject.control_plane_digest
    ):
        _fail("transition_binding_mismatch", "event.body", "source/control binding differs")
    if transition.transition_type not in {"ACTIVATION", "CONVERGENCE"}:
        _fail("transition_kind_mismatch", "event.body.payload", "unknown transition type")
    if transition.to_state not in ALLOWED_TRANSITIONS.get(transition.from_state, ()):
        _fail("illegal_state_transition", "event.body.payload", "transition is not allowed")
    if transition.transition_type == "ACTIVATION" and (
        transition.from_state != "READY" or transition.to_state != "ACTIVE"
    ):
        _fail("transition_kind_mismatch", "event.body.payload", "activation kind replay")
    if transition.transition_type == "CONVERGENCE" and transition.to_state == "ACTIVE":
        _fail("transition_kind_mismatch", "event.body.payload", "convergence kind replay")
    phases = core.get("phases")
    phase = phases.get(transition.subject.phase) if isinstance(phases, dict) else None
    units = phase.get("workUnits") if isinstance(phase, dict) else None
    unit = units.get(transition.subject.work_unit) if isinstance(units, dict) else None
    if not isinstance(unit, dict):
        _fail("unknown_work_unit", "event.body.payload", "transition target is absent")
    if (
        core.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or phase.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or unit.get("contractDigest") != transition.subject.contract_digest
        or unit.get("status") != transition.from_state
    ):
        _fail("transition_state_mismatch", "event.body.payload", "current state differs")
    if _state_core_digest(core) != transition.prior_state_digest:
        _fail("state_digest_mismatch", "event.body.payload", "prior state digest differs")
    if core.get("activeWorkUnit") == transition.subject.work_unit:
        core["activeWorkUnit"] = None
    if core.get("pendingWorkUnit") == transition.subject.work_unit:
        core["pendingWorkUnit"] = None
    unit["status"] = transition.to_state
    unit["sourceCommit"] = transition.subject.source_commit
    unit["approvalDigest"] = transition.approval_digest
    if transition.to_state == "ACTIVE":
        if core.get("activeWorkUnit") is not None:
            _fail("multiple_active_pointers", "state", "another unit is ACTIVE")
        core["activePhase"] = transition.subject.phase
        core["activeWorkUnit"] = transition.subject.work_unit
    elif transition.to_state in PENDING_STATUSES:
        if core.get("pendingWorkUnit") is not None:
            _fail("multiple_pending_work_units", "state", "another unit is pending")
        core["pendingWorkUnit"] = transition.subject.work_unit
    _validate_state_invariants(core)
    resulting = _state_core_digest(core)
    if verify_resulting_digest and payload["resultingStateDigest"] != resulting:
        _fail("state_digest_mismatch", "event.body.payload.resultingStateDigest", "result differs")
    return resulting


def _apply_lifecycle_transition(
    core: dict[str, Any],
    body: Mapping[str, Any],
    transition: VerifiedLifecycleTransition,
    *,
    verify_resulting_digest: bool = True,
) -> str:
    _require_provenance_verified(
        transition, VerifiedLifecycleTransition, "verifiedEventInput"
    )
    payload = _exact_keys(
        body["payload"],
        {
            "transitionType",
            "phase",
            "workUnit",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractDigest",
            "contractApprovalDigest",
            "impactMapDigest",
            "prerequisites",
            "blockerResolutionDigest",
            "invalidationKind",
            "invalidationDigest",
            "proofDigest",
            "approvalDigest",
            "chainHeadWitnessDigest",
            "resultingStateDigest",
        },
        "event.body.payload",
    )
    prerequisites = [
        {
            "phase": item.phase,
            "workUnit": item.work_unit,
            "status": item.status,
            "stateDigest": item.state_digest,
            "contractDigest": item.contract_digest,
            "sourceCommit": item.source_commit,
            "approvalDigest": item.approval_digest,
        }
        for item in transition.prerequisites
    ]
    exact = {
        "transitionType": transition.transition_type,
        "phase": transition.subject.phase,
        "workUnit": transition.subject.work_unit,
        "fromState": transition.from_state,
        "toState": transition.to_state,
        "priorStateDigest": transition.prior_state_digest,
        "priorChainHeadDigest": transition.prior_chain_head_digest,
        "contractDigest": transition.subject.contract_digest,
        "contractApprovalDigest": transition.contract_approval_digest,
        "impactMapDigest": transition.impact_map_digest,
        "prerequisites": prerequisites,
        "blockerResolutionDigest": transition.blocker_resolution_digest,
        "invalidationKind": transition.invalidation_kind,
        "invalidationDigest": transition.invalidation_digest,
        "proofDigest": transition.proof_digest,
        "approvalDigest": transition.approval_digest,
    }
    if any(payload[key] != value for key, value in exact.items()):
        _fail("transition_binding_mismatch", "event.body.payload", "sealed lifecycle transition differs")
    _require_sha256(payload["chainHeadWitnessDigest"], "event.body.payload.chainHeadWitnessDigest")
    if (
        body["sourceCommit"] != transition.subject.source_commit
        or body["controlPlaneDigest"] != transition.subject.control_plane_digest
        or body["reasonCode"] != transition.reason_code
        or body["reason"] != transition.reason
    ):
        _fail("transition_binding_mismatch", "event.body", "source/control/reason binding differs")
    if transition.to_state not in ALLOWED_TRANSITIONS.get(transition.from_state, ()):
        _fail("illegal_state_transition", "event.body.payload", "transition is not allowed")
    expected_type = (
        "READINESS"
        if transition.from_state in {"NOT_STARTED", "REJECTED"} and transition.to_state == "READY"
        else "RESUME"
        if (transition.from_state, transition.to_state) == ("BLOCKED", "ACTIVE")
        else "SUPERSESSION"
        if transition.to_state == "SUPERSEDED"
        else "INVALIDATION"
        if transition.to_state in {"BLOCKED", "REJECTED"}
        else None
    )
    if expected_type != transition.transition_type:
        _fail("transition_kind_mismatch", "event.body.payload", "lifecycle kind replay")
    phases = core.get("phases")
    phase = phases.get(transition.subject.phase) if isinstance(phases, dict) else None
    units = phase.get("workUnits") if isinstance(phase, dict) else None
    unit = units.get(transition.subject.work_unit) if isinstance(units, dict) else None
    if not isinstance(unit, dict):
        _fail("unknown_work_unit", "event.body.payload", "transition target is absent")
    if (
        core.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or phase.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or unit.get("contractDigest") != transition.subject.contract_digest
        or unit.get("status") != transition.from_state
        or _state_core_digest(core) != transition.prior_state_digest
    ):
        _fail("transition_state_mismatch", "event.body.payload", "current lifecycle state differs")
    if core.get("activeWorkUnit") == transition.subject.work_unit:
        core["activeWorkUnit"] = None
    if core.get("pendingWorkUnit") == transition.subject.work_unit:
        core["pendingWorkUnit"] = None
    unit["status"] = transition.to_state
    unit["sourceCommit"] = transition.subject.source_commit
    unit["approvalDigest"] = transition.approval_digest
    if transition.to_state == "ACTIVE":
        if phase.get("status") != "ACTIVE" or core.get("activeWorkUnit") is not None:
            _fail("multiple_active_pointers", "state", "cannot resume while another unit/phase is active")
        core["activePhase"] = transition.subject.phase
        core["activeWorkUnit"] = transition.subject.work_unit
    elif transition.to_state in PENDING_STATUSES:
        if core.get("pendingWorkUnit") is not None:
            _fail("multiple_pending_work_units", "state", "another unit is pending")
        core["pendingWorkUnit"] = transition.subject.work_unit
    _validate_state_invariants(core)
    resulting = _state_core_digest(core)
    if verify_resulting_digest and payload["resultingStateDigest"] != resulting:
        _fail("state_digest_mismatch", "event.body.payload.resultingStateDigest", "result differs")
    return resulting


def _apply_phase_transition(
    core: dict[str, Any],
    body: Mapping[str, Any],
    transition: VerifiedPhaseTransition,
    *,
    verify_resulting_digest: bool = True,
) -> str:
    _require_provenance_verified(
        transition, VerifiedPhaseTransition, "verifiedEventInput"
    )
    payload = _exact_keys(
        body["payload"],
        {
            "transitionType",
            "phase",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "aggregateContractDigest",
            "freezeDigest",
            "proofDigest",
            "approvalDigest",
            "goNoGoAuthorizationDigest",
            "evidenceDigest",
            "criterionResultDigests",
            "unitStates",
            "chainHeadWitnessDigest",
            "resultingStateDigest",
        },
        "event.body.payload",
    )
    unit_states = [
        {
            "workUnit": unit.work_unit,
            "status": unit.status,
            "contractDigest": unit.contract_digest,
            "sourceCommit": unit.source_commit,
            "approvalDigest": unit.approval_digest,
        }
        for unit in transition.unit_states
    ]
    exact = {
        "transitionType": "PHASE_AGGREGATE",
        "phase": transition.subject.phase,
        "fromState": transition.from_state,
        "toState": transition.to_state,
        "priorStateDigest": transition.prior_state_digest,
        "priorChainHeadDigest": transition.prior_chain_head_digest,
        "aggregateContractDigest": transition.subject.aggregate_contract_digest,
        "freezeDigest": transition.freeze_digest,
        "proofDigest": transition.proof_digest,
        "approvalDigest": transition.approval_digest,
        "goNoGoAuthorizationDigest": transition.go_nogo_authorization_digest,
        "evidenceDigest": transition.evidence_digest,
        "criterionResultDigests": list(transition.criterion_result_digests),
        "unitStates": unit_states,
    }
    if any(payload[key] != value for key, value in exact.items()):
        _fail("transition_binding_mismatch", "event.body.payload", "sealed phase transition differs")
    _require_sha256(payload["chainHeadWitnessDigest"], "event.body.payload.chainHeadWitnessDigest")
    if "workUnit" in payload:
        _fail("phase_is_not_work_unit", "event.body.payload", "aggregate cannot use a work-unit subject")
    if (
        body["sourceCommit"] != transition.subject.source_commit
        or body["controlPlaneDigest"] != transition.subject.control_plane_digest
    ):
        _fail("transition_binding_mismatch", "event.body", "source/control binding differs")
    if transition.to_state not in ALLOWED_TRANSITIONS.get(transition.from_state, ()):
        _fail("illegal_state_transition", "event.body.payload", "phase transition is not allowed")
    if transition.transition_type != "PHASE_AGGREGATE" or transition.to_state == "ACTIVE":
        _fail("transition_kind_mismatch", "event.body.payload", "phase aggregate kind replay")
    phases = core.get("phases")
    phase = phases.get(transition.subject.phase) if isinstance(phases, dict) else None
    units = phase.get("workUnits") if isinstance(phase, dict) else None
    if not isinstance(phase, dict) or not isinstance(units, dict):
        _fail("unknown_phase", "event.body.payload", "phase target is absent")
    observed_units = [
        {
            "workUnit": unit_id,
            "status": unit.get("status"),
            "contractDigest": unit.get("contractDigest"),
            "sourceCommit": unit.get("sourceCommit"),
            "approvalDigest": unit.get("approvalDigest"),
        }
        for unit_id, unit in sorted(units.items())
        if isinstance(unit, dict)
    ]
    if (
        core.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or phase.get("controlPlaneDigest") != transition.subject.control_plane_digest
        or phase.get("aggregateContractDigest") != transition.subject.aggregate_contract_digest
        or phase.get("status") != transition.from_state
        or _state_core_digest(core) != transition.prior_state_digest
        or observed_units != unit_states
        or any(unit.get("status") != "CONVERGED" for unit in units.values())
    ):
        _fail("transition_state_mismatch", "event.body.payload", "current aggregate state differs")
    if core.get("activeWorkUnit") is not None or core.get("pendingWorkUnit") is not None:
        _fail("phase_aggregate_pointer_conflict", "state", "aggregate is not a pending work unit")
    phase["status"] = transition.to_state
    phase["sourceCommit"] = transition.subject.source_commit
    phase["approvalDigest"] = transition.approval_digest
    if core.get("activePhase") == transition.subject.phase:
        core["activePhase"] = None
    _validate_state_invariants(core)
    resulting = _state_core_digest(core)
    if verify_resulting_digest and payload["resultingStateDigest"] != resulting:
        _fail("state_digest_mismatch", "event.body.payload.resultingStateDigest", "result differs")
    return resulting


def project_state_transition_payload_v2(
    *,
    state_core: Mapping[str, Any],
    current_chain_head_digest: str,
    chain_head_witness_digest: str,
    transition: VerifiedWorkUnitTransition
    | VerifiedLifecycleTransition
    | VerifiedPhaseTransition,
) -> VerifiedProjectedStateTransitionV2:
    """Project one sealed transition through the same mutation code as replay.

    Protected writers use this helper instead of reimplementing pointer rules.
    The result is itself identity-sealed and digest-protected; callers should
    pass it through :func:`verify_projected_state_transition_v2` immediately
    before serializing an event.
    """

    _require_sha256(current_chain_head_digest, "currentChainHeadDigest")
    _require_sha256(chain_head_witness_digest, "chainHeadWitnessDigest")
    if not isinstance(state_core, Mapping):
        _fail("invalid_state", "state", "state core mapping required")
    if isinstance(transition, VerifiedLifecycleTransition):
        _require_provenance_verified(
            transition, VerifiedLifecycleTransition, "verifiedEventInput"
        )
    elif isinstance(transition, VerifiedPhaseTransition):
        _require_provenance_verified(
            transition, VerifiedPhaseTransition, "verifiedEventInput"
        )
    elif isinstance(transition, VerifiedWorkUnitTransition):
        _require_provenance_verified(
            transition, VerifiedWorkUnitTransition, "verifiedEventInput"
        )
    else:
        _fail("event_input_kind_mismatch", "verifiedEventInput", "sealed transition required")
    if transition.prior_chain_head_digest != current_chain_head_digest:
        _fail("transition_chain_replay", "verifiedEventInput", "transition targets another head")
    if _state_core_digest(state_core) != transition.prior_state_digest:
        _fail("state_digest_mismatch", "state", "transition targets another state")
    placeholder = "sha256:" + "0" * 64
    if isinstance(transition, VerifiedLifecycleTransition):
        payload: dict[str, Any] = {
            "transitionType": transition.transition_type,
            "phase": transition.subject.phase,
            "workUnit": transition.subject.work_unit,
            "fromState": transition.from_state,
            "toState": transition.to_state,
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": transition.prior_chain_head_digest,
            "contractDigest": transition.subject.contract_digest,
            "contractApprovalDigest": transition.contract_approval_digest,
            "impactMapDigest": transition.impact_map_digest,
            "prerequisites": [
                {
                    "phase": item.phase,
                    "workUnit": item.work_unit,
                    "status": item.status,
                    "stateDigest": item.state_digest,
                    "contractDigest": item.contract_digest,
                    "sourceCommit": item.source_commit,
                    "approvalDigest": item.approval_digest,
                }
                for item in transition.prerequisites
            ],
            "blockerResolutionDigest": transition.blocker_resolution_digest,
            "invalidationKind": transition.invalidation_kind,
            "invalidationDigest": transition.invalidation_digest,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "chainHeadWitnessDigest": chain_head_witness_digest,
            "resultingStateDigest": placeholder,
        }
        body = {
            "sourceCommit": transition.subject.source_commit,
            "controlPlaneDigest": transition.subject.control_plane_digest,
            "reasonCode": transition.reason_code,
            "reason": transition.reason,
            "payload": payload,
        }
        projected_core = deepcopy(dict(state_core))
        resulting_digest = _apply_lifecycle_transition(
            projected_core,
            body,
            transition,
            verify_resulting_digest=False,
        )
    elif isinstance(transition, VerifiedPhaseTransition):
        payload = {
            "transitionType": transition.transition_type,
            "phase": transition.subject.phase,
            "fromState": transition.from_state,
            "toState": transition.to_state,
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": transition.prior_chain_head_digest,
            "aggregateContractDigest": transition.subject.aggregate_contract_digest,
            "freezeDigest": transition.freeze_digest,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "goNoGoAuthorizationDigest": transition.go_nogo_authorization_digest,
            "evidenceDigest": transition.evidence_digest,
            "criterionResultDigests": list(transition.criterion_result_digests),
            "unitStates": [
                {
                    "workUnit": unit.work_unit,
                    "status": unit.status,
                    "contractDigest": unit.contract_digest,
                    "sourceCommit": unit.source_commit,
                    "approvalDigest": unit.approval_digest,
                }
                for unit in transition.unit_states
            ],
            "chainHeadWitnessDigest": chain_head_witness_digest,
            "resultingStateDigest": placeholder,
        }
        body = {
            "sourceCommit": transition.subject.source_commit,
            "controlPlaneDigest": transition.subject.control_plane_digest,
            "payload": payload,
        }
        projected_core = deepcopy(dict(state_core))
        resulting_digest = _apply_phase_transition(
            projected_core,
            body,
            transition,
            verify_resulting_digest=False,
        )
    else:
        payload = {
            "transitionType": transition.transition_type,
            "phase": transition.subject.phase,
            "workUnit": transition.subject.work_unit,
            "fromState": transition.from_state,
            "toState": transition.to_state,
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": transition.prior_chain_head_digest,
            "contractDigest": transition.subject.contract_digest,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "evidenceDigest": transition.evidence_digest,
            "criterionResultDigests": list(transition.criterion_result_digests),
            "chainHeadWitnessDigest": chain_head_witness_digest,
            "resultingStateDigest": placeholder,
        }
        body = {
            "sourceCommit": transition.subject.source_commit,
            "controlPlaneDigest": transition.subject.control_plane_digest,
            "payload": payload,
        }
        projected_core = deepcopy(dict(state_core))
        resulting_digest = _apply_transition(
            projected_core,
            body,
            transition,
            verify_resulting_digest=False,
        )
    payload["resultingStateDigest"] = resulting_digest
    projection_document = {
        "payload": payload,
        "resultingStateCore": projected_core,
        "resultingStateDigest": resulting_digest,
    }
    return _mark_verified(
        VerifiedProjectedStateTransitionV2(
            payload=deepcopy(payload),
            resulting_state_core=deepcopy(projected_core),
            resulting_state_digest=resulting_digest,
            projection_digest=document_digest(projection_document),
        )
    )


def verify_projected_state_transition_v2(
    projection: VerifiedProjectedStateTransitionV2,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Consume a projection only if its seal and nested mappings are intact."""

    _require_verified(
        projection, VerifiedProjectedStateTransitionV2, "projectedTransition"
    )
    document = {
        "payload": projection.payload,
        "resultingStateCore": projection.resulting_state_core,
        "resultingStateDigest": projection.resulting_state_digest,
    }
    if (
        document_digest(document) != projection.projection_digest
        or _state_core_digest(projection.resulting_state_core)
        != projection.resulting_state_digest
        or projection.payload.get("resultingStateDigest")
        != projection.resulting_state_digest
    ):
        _fail("projected_transition_mutated", "projectedTransition", "projection changed after verification")
    return deepcopy(dict(projection.payload)), deepcopy(dict(projection.resulting_state_core))


# Narrow writer-facing alias requested by the protected event pipeline.
project_event_payload_v2 = project_state_transition_payload_v2


def project_evidence_attachment_payload_v2(
    *,
    state_core: Mapping[str, Any],
    current_chain_head_digest: str,
    chain_head_witness_digest: str,
    attachment: VerifiedEvidenceAttachmentV2,
) -> VerifiedProjectedEvidenceAttachmentV2:
    """Project a sealed non-mutating evidence attachment for a writer."""

    _require_verified(attachment, VerifiedEvidenceAttachmentV2, "verifiedEventInput")
    _require_sha256(current_chain_head_digest, "currentChainHeadDigest")
    _require_sha256(chain_head_witness_digest, "chainHeadWitnessDigest")
    if not isinstance(state_core, Mapping):
        _fail("invalid_state", "state", "state core mapping required")
    state_digest = _state_core_digest(state_core)
    payload = {
        "phase": attachment.subject_phase,
        "workUnit": attachment.subject_work_unit,
        "priorStateDigest": state_digest,
        "priorChainHeadDigest": current_chain_head_digest,
        "contractDigest": attachment.contract_digest,
        "evidenceSourceCommit": attachment.source_commit,
        "freezeDigest": attachment.freeze_digest,
        "criterionResultDigests": list(attachment.criterion_result_digests),
        "proofDigest": attachment.proof_digest,
        "approvalDigest": attachment.approval_digest,
        "attachmentDigest": attachment.attachment_digest,
        "chainHeadWitnessDigest": chain_head_witness_digest,
        "resultingStateDigest": state_digest,
    }
    body = {
        "controlPlaneDigest": attachment.control_plane_digest,
        "payload": payload,
    }
    _apply_attachment(
        state_core,
        body,
        attachment,
        event_digest="sha256:" + "0" * 64,
    )
    projection_document = {
        "payload": payload,
        "resultingStateDigest": state_digest,
    }
    return _mark_verified(
        VerifiedProjectedEvidenceAttachmentV2(
            payload=deepcopy(payload),
            resulting_state_digest=state_digest,
            projection_digest=document_digest(projection_document),
        )
    )


def verify_projected_evidence_attachment_v2(
    projection: VerifiedProjectedEvidenceAttachmentV2,
) -> dict[str, Any]:
    """Consume an attachment projection only if seal and payload are intact."""

    _require_verified(
        projection,
        VerifiedProjectedEvidenceAttachmentV2,
        "projectedAttachment",
    )
    document = {
        "payload": projection.payload,
        "resultingStateDigest": projection.resulting_state_digest,
    }
    if (
        document_digest(document) != projection.projection_digest
        or projection.payload.get("priorStateDigest")
        != projection.resulting_state_digest
        or projection.payload.get("resultingStateDigest")
        != projection.resulting_state_digest
    ):
        _fail("projected_attachment_mutated", "projectedAttachment", "projection changed after verification")
    return deepcopy(dict(projection.payload))


def _apply_attachment(
    core: Mapping[str, Any],
    body: Mapping[str, Any],
    attachment: VerifiedEvidenceAttachmentV2,
    *,
    event_digest: str,
) -> dict[str, Any]:
    _require_verified(attachment, VerifiedEvidenceAttachmentV2, "verifiedEventInput")
    payload = _exact_keys(
        body["payload"],
        {
            "phase",
            "workUnit",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractDigest",
            "evidenceSourceCommit",
            "freezeDigest",
            "criterionResultDigests",
            "proofDigest",
            "approvalDigest",
            "attachmentDigest",
            "chainHeadWitnessDigest",
            "resultingStateDigest",
        },
        "event.body.payload",
    )
    exact = {
        "phase": attachment.subject_phase,
        "workUnit": attachment.subject_work_unit,
        "contractDigest": attachment.contract_digest,
        "evidenceSourceCommit": attachment.source_commit,
        "freezeDigest": attachment.freeze_digest,
        "criterionResultDigests": list(attachment.criterion_result_digests),
        "proofDigest": attachment.proof_digest,
        "approvalDigest": attachment.approval_digest,
        "attachmentDigest": attachment.attachment_digest,
    }
    if any(payload[key] != value for key, value in exact.items()):
        _fail("attachment_binding_mismatch", "event.body.payload", "sealed attachment differs")
    _require_sha256(payload["chainHeadWitnessDigest"], "event.body.payload.chainHeadWitnessDigest")
    state_digest = _state_core_digest(core)
    phases = core.get("phases")
    phase = phases.get(attachment.subject_phase) if isinstance(phases, dict) else None
    units = phase.get("workUnits") if isinstance(phase, dict) else None
    unit = units.get(attachment.subject_work_unit) if isinstance(units, dict) else None
    if (
        payload["priorStateDigest"] != state_digest
        or payload["resultingStateDigest"] != state_digest
        or body["controlPlaneDigest"] != attachment.control_plane_digest
        or core.get("controlPlaneDigest") != attachment.control_plane_digest
        or not isinstance(unit, dict)
        or unit.get("contractDigest") != attachment.contract_digest
        or unit.get("sourceCommit") != attachment.source_commit
    ):
        _fail("attachment_state_mutation", "event.body", "attachment changed or crossed state")
    return {
        "eventDigest": event_digest,
        "attachmentDigest": attachment.attachment_digest,
        "phase": attachment.subject_phase,
        "workUnit": attachment.subject_work_unit,
        "sourceCommit": attachment.source_commit,
        "controlPlaneDigest": attachment.control_plane_digest,
        "freezeDigest": attachment.freeze_digest,
        "criterionResultDigests": list(attachment.criterion_result_digests),
        "proofDigest": attachment.proof_digest,
        "approvalDigest": attachment.approval_digest,
    }


def replay_post_genesis_chain_v2(
    *,
    genesis: VerifiedGenesisAnchorV2,
    events: Sequence[Any],
    verified_event_inputs: Sequence[
        VerifiedWorkUnitTransition
        | VerifiedLifecycleTransition
        | VerifiedPhaseTransition
        | VerifiedEvidenceAttachmentV2
    ],
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    jwks_snapshot: Any,
    expected_chain_head_digest: str,
    repo_root: Path,
    approved_component_digests: Mapping[str, str],
) -> VerifiedStateChainV2:
    """Replay a strict, externally head-pinned R3 post-Genesis event suffix."""

    _require_verified(genesis, VerifiedGenesisAnchorV2, "genesis")
    _require_sha256(expected_chain_head_digest, "external.expectedChainHeadDigest")
    if _state_core_digest(genesis.state_core) != genesis.state_digest:
        _fail("state_digest_mismatch", "genesis.stateCore", "sealed Genesis state was mutated")
    if (
        policy_result.get("digest") != genesis.trust_policy_digest
        or policy_result.get("document", {}).get("controlPlaneDigest")
        != genesis.control_plane_digest
        or policy_result.get("jwks", {}).get("digest")
        != genesis.jwks_snapshot_digest
        or document_digest(policy_result.get("stateSigner"))
        != genesis.state_signer_digest
        or approval_result.get("jwksSnapshotDigest")
        != genesis.jwks_snapshot_digest
        or approval_result.get("workflowExecutionCommit")
        != genesis.workflow_execution_commit
        or approval_result.get("status") != "verified"
        or approval_result.get("decision") != "APPROVE"
        or approval_result.get("approvalDigest")
        != genesis.bootstrap_approval_digest
        or approval_result.get("requestDigest") != genesis.bootstrap_request_digest
        or approval_result.get("controlPlaneDigest") != genesis.control_plane_digest
        or approval_result.get("trustPolicyDigest") != genesis.trust_policy_digest
    ):
        _fail(
            "genesis_trust_binding_mismatch",
            "genesis",
            "post-Genesis verifier trust differs from the sealed Genesis anchor",
        )
    if not isinstance(approved_component_digests, Mapping):
        _fail(
            "invalid_component_digests",
            "approvedComponentDigests",
            "approved component digest mapping is required",
        )
    if any(
        not isinstance(component_path, str) or not component_path
        for component_path in approved_component_digests
    ):
        _fail("invalid_component_digests", "approvedComponentDigests", "invalid path")
    normalized_components = tuple(
        sorted((path, digest) for path, digest in approved_component_digests.items())
    )
    approval_components = approval_result.get("componentDigests")
    if not isinstance(approval_components, Mapping):
        _fail("genesis_trust_binding_mismatch", "approvalResult.componentDigests", "component pins missing")
    normalized_approval_components = tuple(sorted(approval_components.items()))
    if (
        normalized_components != genesis.approved_component_digests
        or normalized_approval_components != genesis.approved_component_digests
    ):
        _fail(
            "genesis_trust_binding_mismatch",
            "approvedComponentDigests",
            "post-Genesis component pins differ from Genesis approval",
        )
    for component_path, component_digest in normalized_components:
        _require_sha256(component_digest, f"approvedComponentDigests.{component_path}")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        _fail("invalid_event_sequence", "events", "events must be an ordered sequence")
    inputs = list(verified_event_inputs)
    if len(events) != len(inputs):
        _fail("event_input_count_mismatch", "verifiedEventInputs", "one sealed input per event is required")
    core = deepcopy(dict(genesis.state_core))
    attachments = [deepcopy(dict(item)) for item in genesis.attachments]
    head = genesis.chain_head_digest
    timestamp = genesis.timestamp
    source_commit = genesis.head_source_commit
    sequence = genesis.head_sequence
    workflow_runs: list[tuple[str, str]] = [
        (genesis.workflow_run_id, genesis.workflow_check_run_id)
    ]
    seen_runs: set[tuple[str, str]] = {
        (genesis.workflow_run_id, genesis.workflow_check_run_id)
    }
    for offset, (event, verified_input) in enumerate(zip(events, inputs), start=1):
        sequence = genesis.head_sequence + offset
        envelope, body, event_digest, timestamp, claims = _verify_oidc_event(
            event,
            sequence=sequence,
            previous_digest=head,
            previous_timestamp=timestamp,
            previous_source_commit=source_commit,
            policy_result=policy_result,
            approval_result=approval_result,
            jwks_snapshot=jwks_snapshot,
            repo_root=repo_root,
            approved_component_digests=approved_component_digests,
        )
        run_identity = (claims["run_id"], claims["check_run_id"])
        if run_identity in seen_runs:
            _fail("oidc_run_replay", f"events[{sequence}].signature", "workflow run reused")
        seen_runs.add(run_identity)
        workflow_runs.append(run_identity)
        if body["eventType"] == "StateTransition":
            if not isinstance(
                verified_input,
                (
                    VerifiedWorkUnitTransition,
                    VerifiedLifecycleTransition,
                    VerifiedPhaseTransition,
                ),
            ):
                _fail("event_input_kind_mismatch", f"events[{sequence}]", "transition input required")
            if verified_input.prior_chain_head_digest != head:
                _fail("transition_chain_replay", f"events[{sequence}]", "transition targets another head")
            if isinstance(verified_input, VerifiedLifecycleTransition):
                _apply_lifecycle_transition(core, body, verified_input)
            elif isinstance(verified_input, VerifiedPhaseTransition):
                _apply_phase_transition(core, body, verified_input)
            else:
                _apply_transition(core, body, verified_input)
        else:
            if not isinstance(verified_input, VerifiedEvidenceAttachmentV2):
                _fail("event_input_kind_mismatch", f"events[{sequence}]", "attachment input required")
            if body["payload"].get("priorChainHeadDigest") != head:
                _fail("attachment_chain_replay", f"events[{sequence}]", "attachment targets another head")
            attachments.append(
                _apply_attachment(
                    core, body, verified_input, event_digest=event_digest
                )
            )
        head = event_digest
        source_commit = body["sourceCommit"]
        del envelope
    if head != expected_chain_head_digest:
        _fail(
            "chain_head_digest_mismatch",
            "external.expectedChainHeadDigest",
            "event suffix is truncated, extended, or bound to another head",
        )
    attachments_tuple = tuple(attachments)
    workflow_runs_tuple = tuple(workflow_runs)
    state_digest = _state_core_digest(core)
    event_count = genesis.event_count + len(events)
    snapshot_digest = _chain_snapshot_digest(
        state_core=core,
        attachments=attachments_tuple,
        event_count=event_count,
        head_sequence=sequence,
        head_digest=head,
        head_timestamp=timestamp,
        head_source_commit=source_commit,
        workflow_runs=workflow_runs_tuple,
        control_plane_digest=genesis.control_plane_digest,
        trust_policy_digest=genesis.trust_policy_digest,
        jwks_snapshot_digest=genesis.jwks_snapshot_digest,
        workflow_execution_commit=genesis.workflow_execution_commit,
        approved_component_digests=genesis.approved_component_digests,
        state_signer_digest=genesis.state_signer_digest,
        bootstrap_approval_digest=genesis.bootstrap_approval_digest,
        bootstrap_request_digest=genesis.bootstrap_request_digest,
    )
    return _mark_verified(
        VerifiedStateChainV2(
            state_core=deepcopy(core),
            state_digest=state_digest,
            attachments=attachments_tuple,
            event_count=event_count,
            head_sequence=sequence,
            head_digest=head,
            head_timestamp=timestamp,
            head_source_commit=source_commit,
            workflow_runs=workflow_runs_tuple,
            control_plane_digest=genesis.control_plane_digest,
            trust_policy_digest=genesis.trust_policy_digest,
            jwks_snapshot_digest=genesis.jwks_snapshot_digest,
            workflow_execution_commit=genesis.workflow_execution_commit,
            approved_component_digests=genesis.approved_component_digests,
            state_signer_digest=genesis.state_signer_digest,
            bootstrap_approval_digest=genesis.bootstrap_approval_digest,
            bootstrap_request_digest=genesis.bootstrap_request_digest,
            chain_snapshot_digest=snapshot_digest,
        )
    )


def require_verified_state_context_v2(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> VerifiedGenesisAnchorV2 | VerifiedStateChainV2:
    """Fail before token issuance unless the exact sealed current head is intact."""

    if isinstance(current, VerifiedGenesisAnchorV2):
        _require_verified(current, VerifiedGenesisAnchorV2, "current")
        if (
            _state_core_digest(current.state_core) != current.state_digest
            or current.state_core.get("controlPlaneDigest")
            != current.control_plane_digest
            or current.attachments != ()
            or current.event_count != 1
            or current.head_sequence != 0
        ):
            _fail("current_state_mutated", "current", "Genesis anchor state changed")
        for path, value in (
            ("chainHeadDigest", current.chain_head_digest),
            ("controlPlaneDigest", current.control_plane_digest),
            ("trustPolicyDigest", current.trust_policy_digest),
            ("jwksSnapshotDigest", current.jwks_snapshot_digest),
            ("stateSignerDigest", current.state_signer_digest),
            ("bootstrapApprovalDigest", current.bootstrap_approval_digest),
            ("bootstrapRequestDigest", current.bootstrap_request_digest),
        ):
            _require_sha256(value, f"current.{path}")
        _require_commit(current.head_source_commit, "current.headSourceCommit")
        _require_commit(current.workflow_execution_commit, "current.workflowExecutionCommit")
        if len(set(current.approved_component_digests)) != len(current.approved_component_digests):
            _fail("current_trust_mutated", "current.approvedComponentDigests", "duplicate component pin")
        return current
    if isinstance(current, VerifiedStateChainV2):
        _require_verified(current, VerifiedStateChainV2, "current")
        if (
            _state_core_digest(current.state_core) != current.state_digest
            or current.state_core.get("controlPlaneDigest")
            != current.control_plane_digest
            or current.event_count != current.head_sequence + 1
            or len(set(current.workflow_runs)) != len(current.workflow_runs)
        ):
            _fail("current_state_mutated", "current", "current chain state changed")
        observed_snapshot = _chain_snapshot_digest(
            state_core=current.state_core,
            attachments=current.attachments,
            event_count=current.event_count,
            head_sequence=current.head_sequence,
            head_digest=current.head_digest,
            head_timestamp=current.head_timestamp,
            head_source_commit=current.head_source_commit,
            workflow_runs=current.workflow_runs,
            control_plane_digest=current.control_plane_digest,
            trust_policy_digest=current.trust_policy_digest,
            jwks_snapshot_digest=current.jwks_snapshot_digest,
            workflow_execution_commit=current.workflow_execution_commit,
            approved_component_digests=current.approved_component_digests,
            state_signer_digest=current.state_signer_digest,
            bootstrap_approval_digest=current.bootstrap_approval_digest,
            bootstrap_request_digest=current.bootstrap_request_digest,
        )
        if observed_snapshot != current.chain_snapshot_digest:
            _fail("current_state_mutated", "current", "sealed chain snapshot changed")
        return current
    _fail("unverified_internal_result", "current", "sealed Genesis or chain context required")


def verify_next_event_v2(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    event: Any,
    verified_event_input: VerifiedWorkUnitTransition
    | VerifiedLifecycleTransition
    | VerifiedPhaseTransition
    | VerifiedEvidenceAttachmentV2,
    expected_chain_head_witness_digest: str,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    jwks_snapshot: Any,
    repo_root: Path,
    approved_component_digests: Mapping[str, str],
) -> VerifiedStateChainV2:
    """Incrementally verify exactly one append against a sealed current head."""

    require_verified_state_context_v2(current)
    witness_digest = _require_sha256(
        expected_chain_head_witness_digest,
        "external.expectedChainHeadWitnessDigest",
    )
    if isinstance(current, VerifiedGenesisAnchorV2):
        core = deepcopy(dict(current.state_core))
        attachments = [deepcopy(dict(item)) for item in current.attachments]
        head = current.chain_head_digest
        timestamp = current.timestamp
        source_commit = current.head_source_commit
        sequence = current.head_sequence
        event_count = current.event_count
        workflow_runs = [
            (current.workflow_run_id, current.workflow_check_run_id)
        ]
        control_plane_digest = current.control_plane_digest
        trust_policy_digest = current.trust_policy_digest
        jwks_snapshot_digest = current.jwks_snapshot_digest
        workflow_execution_commit = current.workflow_execution_commit
        component_pins = current.approved_component_digests
        state_signer_digest = current.state_signer_digest
        bootstrap_approval_digest = current.bootstrap_approval_digest
        bootstrap_request_digest = current.bootstrap_request_digest
    else:
        core = deepcopy(dict(current.state_core))
        attachments = [deepcopy(dict(item)) for item in current.attachments]
        head = current.head_digest
        timestamp = current.head_timestamp
        source_commit = current.head_source_commit
        sequence = current.head_sequence
        event_count = current.event_count
        workflow_runs = list(current.workflow_runs)
        control_plane_digest = current.control_plane_digest
        trust_policy_digest = current.trust_policy_digest
        jwks_snapshot_digest = current.jwks_snapshot_digest
        workflow_execution_commit = current.workflow_execution_commit
        component_pins = current.approved_component_digests
        state_signer_digest = current.state_signer_digest
        bootstrap_approval_digest = current.bootstrap_approval_digest
        bootstrap_request_digest = current.bootstrap_request_digest
    approval_components = approval_result.get("componentDigests")
    supplied_components = (
        tuple(sorted(approved_component_digests.items()))
        if isinstance(approved_component_digests, Mapping)
        else ()
    )
    if (
        policy_result.get("digest") != trust_policy_digest
        or policy_result.get("document", {}).get("controlPlaneDigest")
        != control_plane_digest
        or policy_result.get("jwks", {}).get("digest") != jwks_snapshot_digest
        or document_digest(policy_result.get("stateSigner")) != state_signer_digest
        or approval_result.get("status") != "verified"
        or approval_result.get("decision") != "APPROVE"
        or approval_result.get("approvalDigest") != bootstrap_approval_digest
        or approval_result.get("requestDigest") != bootstrap_request_digest
        or approval_result.get("controlPlaneDigest") != control_plane_digest
        or approval_result.get("trustPolicyDigest") != trust_policy_digest
        or approval_result.get("jwksSnapshotDigest") != jwks_snapshot_digest
        or approval_result.get("workflowExecutionCommit")
        != workflow_execution_commit
        or not isinstance(approval_components, Mapping)
        or tuple(sorted(approval_components.items())) != component_pins
        or supplied_components != component_pins
    ):
        _fail("genesis_trust_binding_mismatch", "current", "incremental trust differs from Genesis")
    sequence += 1
    envelope, body, event_digest, next_timestamp, claims = _verify_oidc_event(
        event,
        sequence=sequence,
        previous_digest=head,
        previous_timestamp=timestamp,
        previous_source_commit=source_commit,
        policy_result=policy_result,
        approval_result=approval_result,
        jwks_snapshot=jwks_snapshot,
        repo_root=repo_root,
        approved_component_digests=approved_component_digests,
    )
    if body["payload"].get("chainHeadWitnessDigest") != witness_digest:
        _fail("chain_head_witness_mismatch", "event.body.payload.chainHeadWitnessDigest", "event binds another witness")
    run_identity = (claims["run_id"], claims["check_run_id"])
    if run_identity in set(workflow_runs):
        _fail("oidc_run_replay", f"events[{sequence}].signature", "workflow run reused")
    workflow_runs.append(run_identity)
    if body["eventType"] == "StateTransition":
        if isinstance(verified_event_input, VerifiedLifecycleTransition):
            if verified_event_input.prior_chain_head_digest != head:
                _fail("transition_chain_replay", f"events[{sequence}]", "transition targets another head")
            _apply_lifecycle_transition(core, body, verified_event_input)
        elif isinstance(verified_event_input, VerifiedPhaseTransition):
            if verified_event_input.prior_chain_head_digest != head:
                _fail("transition_chain_replay", f"events[{sequence}]", "transition targets another head")
            _apply_phase_transition(core, body, verified_event_input)
        elif isinstance(verified_event_input, VerifiedWorkUnitTransition):
            if verified_event_input.prior_chain_head_digest != head:
                _fail("transition_chain_replay", f"events[{sequence}]", "transition targets another head")
            _apply_transition(core, body, verified_event_input)
        else:
            _fail("event_input_kind_mismatch", f"events[{sequence}]", "transition input required")
    else:
        if not isinstance(verified_event_input, VerifiedEvidenceAttachmentV2):
            _fail("event_input_kind_mismatch", f"events[{sequence}]", "attachment input required")
        if body["payload"].get("priorChainHeadDigest") != head:
            _fail("attachment_chain_replay", f"events[{sequence}]", "attachment targets another head")
        attachments.append(
            _apply_attachment(
                core, body, verified_event_input, event_digest=event_digest
            )
        )
    del envelope
    event_count += 1
    attachments_tuple = tuple(attachments)
    workflow_runs_tuple = tuple(workflow_runs)
    state_digest = _state_core_digest(core)
    next_source_commit = body["sourceCommit"]
    snapshot_digest = _chain_snapshot_digest(
        state_core=core,
        attachments=attachments_tuple,
        event_count=event_count,
        head_sequence=sequence,
        head_digest=event_digest,
        head_timestamp=next_timestamp,
        head_source_commit=next_source_commit,
        workflow_runs=workflow_runs_tuple,
        control_plane_digest=control_plane_digest,
        trust_policy_digest=trust_policy_digest,
        jwks_snapshot_digest=jwks_snapshot_digest,
        workflow_execution_commit=workflow_execution_commit,
        approved_component_digests=component_pins,
        state_signer_digest=state_signer_digest,
        bootstrap_approval_digest=bootstrap_approval_digest,
        bootstrap_request_digest=bootstrap_request_digest,
    )
    return _mark_verified(
        VerifiedStateChainV2(
            state_core=deepcopy(core),
            state_digest=state_digest,
            attachments=attachments_tuple,
            event_count=event_count,
            head_sequence=sequence,
            head_digest=event_digest,
            head_timestamp=next_timestamp,
            head_source_commit=next_source_commit,
            workflow_runs=workflow_runs_tuple,
            control_plane_digest=control_plane_digest,
            trust_policy_digest=trust_policy_digest,
            jwks_snapshot_digest=jwks_snapshot_digest,
            workflow_execution_commit=workflow_execution_commit,
            approved_component_digests=component_pins,
            state_signer_digest=state_signer_digest,
            bootstrap_approval_digest=bootstrap_approval_digest,
            bootstrap_request_digest=bootstrap_request_digest,
            chain_snapshot_digest=snapshot_digest,
        )
    )
