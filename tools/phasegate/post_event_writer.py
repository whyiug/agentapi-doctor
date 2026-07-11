"""Protected construction of one post-Genesis StateEvent.

This module is intentionally a very small authority boundary.  It accepts an
identity-sealed current chain, one identity-sealed transition or evidence
attachment, and the exact identity-sealed maintainer observation of that chain
head.  The state-chain verifier owns all payload projection and state mutation
semantics; this writer only supplies deterministic envelope metadata, obtains a
digest-bound GitHub Actions OIDC token, and asks the incremental verifier to
consume its result before returning it.

There is no repository write path here.  The only network-capable operation is
the default GitHub Actions OIDC token provider, which callers can replace with
an offline provider in tests.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Callable, Mapping, NoReturn

from .chain_witness import (
    VerifiedChainHeadWitness,
    require_verified_chain_head_witness,
)
from .digest import canonical_json_bytes, sha256_bytes
from .oidc import OidcVerificationError, validate_jwks_snapshot
from .protected import ProtectedVerificationError, document_digest
from .protected_v2 import (
    OIDC_AUDIENCE_PREFIX,
    OIDC_SIGNATURE_SCHEME,
    STATE_EVENT_KIND,
    STATE_EVENT_NAMESPACE,
    STATE_EVENT_SCHEMA,
    _expected_oidc_claims,
)
from .provenance import (
    VerifiedLifecycleTransition,
    VerifiedPhaseTransition,
    VerifiedWorkUnitTransition,
)
from .state_chain_v2 import (
    VerifiedEvidenceAttachmentV2,
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    project_event_payload_v2,
    project_evidence_attachment_payload_v2,
    require_verified_state_context_v2,
    verify_next_event_v2,
    verify_projected_evidence_attachment_v2,
    verify_projected_state_transition_v2,
)
from .state_writer import StateWriterError, github_actions_token_provider


TokenProvider = Callable[[str], str]
VerifiedEventInput = (
    VerifiedWorkUnitTransition
    | VerifiedLifecycleTransition
    | VerifiedPhaseTransition
    | VerifiedEvidenceAttachmentV2
)

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_TOKEN_BYTES = 32_768


@dataclass
class PostEventWriterError(ValueError):
    """Stable, secret-free failure from the protected post-event writer."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise PostEventWriterError(code, path, message)


def _translate(
    error: ProtectedVerificationError | StateWriterError | OidcVerificationError,
) -> NoReturn:
    _fail(error.code, error.path, error.message)


def _require_commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        _fail("invalid_source_commit", path, "expected a lowercase 40-hex Git SHA-1")
    return value


def _require_digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _timestamp(value: datetime | str) -> tuple[datetime, str]:
    if isinstance(value, str):
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            _fail(
                "invalid_timestamp",
                "statementTimestamp",
                "expected second-precision RFC3339 UTC timestamp",
            )
        return parsed, value
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(
            "invalid_timestamp",
            "statementTimestamp",
            "timestamp must be timezone-aware",
        )
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail(
            "invalid_timestamp",
            "statementTimestamp",
            "timestamp must have second precision",
        )
    return normalized, normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _current_fields(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> tuple[Mapping[str, Any], str, str, int, int, datetime, str, str]:
    """Return only values already authenticated by the sealed chain context."""

    try:
        sealed = require_verified_state_context_v2(current)
    except ProtectedVerificationError as exc:
        _translate(exc)
    state_core = sealed.state_core
    control_plane_digest = state_core.get("controlPlaneDigest")
    _require_digest(control_plane_digest, "current.stateCore.controlPlaneDigest")
    if isinstance(sealed, VerifiedGenesisAnchorV2):
        return (
            state_core,
            sealed.state_digest,
            sealed.chain_head_digest,
            sealed.event_count,
            sealed.head_sequence,
            sealed.timestamp,
            sealed.head_source_commit,
            sealed.trust_policy_digest,
        )
    return (
        state_core,
        sealed.state_digest,
        sealed.head_digest,
        sealed.event_count,
        sealed.head_sequence,
        sealed.head_timestamp,
        sealed.head_source_commit,
        sealed.trust_policy_digest,
    )


def _event_kind_and_reason(
    verified_input: VerifiedEventInput,
) -> tuple[str, str, str]:
    if isinstance(verified_input, VerifiedLifecycleTransition):
        return "StateTransition", verified_input.reason_code, verified_input.reason
    if isinstance(verified_input, VerifiedPhaseTransition):
        return (
            "StateTransition",
            "authorized-phase-aggregate-transition",
            "Protected workflow applied the sealed phase aggregate authorization.",
        )
    if isinstance(verified_input, VerifiedWorkUnitTransition):
        if verified_input.transition_type == "ACTIVATION":
            return (
                "StateTransition",
                "authorized-work-unit-activation",
                "Protected workflow applied the sealed work-unit activation authorization.",
            )
        return (
            "StateTransition",
            "authorized-work-unit-transition",
            "Protected workflow applied the sealed work-unit convergence authorization.",
        )
    if isinstance(verified_input, VerifiedEvidenceAttachmentV2):
        return (
            "EvidenceAttachment",
            "verified-evidence-attachment",
            "Protected workflow attached the sealed evidence bundle without changing state.",
        )
    _fail(
        "event_input_kind_mismatch",
        "verifiedEventInput",
        "an identity-sealed transition or evidence attachment is required",
    )


def _project_payload(
    *,
    state_core: Mapping[str, Any],
    current_head_digest: str,
    verified_input: VerifiedEventInput,
    witness_digest: str,
) -> dict[str, Any]:
    try:
        if isinstance(verified_input, VerifiedEvidenceAttachmentV2):
            projection = project_evidence_attachment_payload_v2(
                state_core=state_core,
                current_chain_head_digest=current_head_digest,
                attachment=verified_input,
                chain_head_witness_digest=witness_digest,
            )
            return verify_projected_evidence_attachment_v2(projection)
        projection = project_event_payload_v2(
            state_core=state_core,
            current_chain_head_digest=current_head_digest,
            transition=verified_input,
            chain_head_witness_digest=witness_digest,
        )
        payload, _resulting_core = verify_projected_state_transition_v2(projection)
        return payload
    except ProtectedVerificationError as exc:
        _translate(exc)


def _validate_witness(
    *,
    witness: VerifiedChainHeadWitness,
    state_digest: str,
    head_digest: str,
    event_count: int,
    head_sequence: int,
    head_source_commit: str,
    control_plane_digest: str,
    trust_policy_digest: str,
    event_timestamp: datetime,
) -> VerifiedChainHeadWitness:
    try:
        sealed = require_verified_chain_head_witness(witness)
    except ProtectedVerificationError as exc:
        _translate(exc)
    exact = {
        "prior_chain_head_digest": head_digest,
        "prior_state_digest": state_digest,
        "prior_event_count": event_count,
        "prior_head_sequence": head_sequence,
        "prior_source_commit": head_source_commit,
        "control_plane_digest": control_plane_digest,
        "trust_policy_digest": trust_policy_digest,
    }
    if any(getattr(sealed, name) != value for name, value in exact.items()):
        _fail(
            "chain_witness_binding_mismatch",
            "chainHeadWitness",
            "witness is stale or belongs to another state, head, source, policy, or control plane",
        )
    if event_count != head_sequence + 1:
        _fail(
            "invalid_chain_position",
            "current",
            "event count must equal head sequence plus one",
        )
    if not sealed.witnessed_at <= event_timestamp < sealed.valid_until:
        _fail(
            "chain_witness_outside_event_time",
            "statementTimestamp",
            "event timestamp is outside the sealed witness validity interval",
        )
    return sealed


def _validate_bootstrap_trust(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, str], str]:
    """Check every Genesis trust pin before requesting a new OIDC token."""

    document = policy_result.get("document")
    signer = policy_result.get("stateSigner")
    jwks_policy = policy_result.get("jwks")
    if (
        not isinstance(document, Mapping)
        or not isinstance(signer, Mapping)
        or not isinstance(jwks_policy, Mapping)
        or policy_result.get("digest") != current.trust_policy_digest
        or document_digest(document) != current.trust_policy_digest
        or document.get("controlPlaneDigest") != current.control_plane_digest
        or document_digest(signer) != current.state_signer_digest
        or jwks_policy.get("digest") != current.jwks_snapshot_digest
    ):
        _fail(
            "genesis_trust_binding_mismatch",
            "policyResult",
            "policy differs from the sealed Genesis trust context",
        )
    component_digests = approval_result.get("componentDigests")
    if not isinstance(component_digests, Mapping) or any(
        not isinstance(path, str) or not isinstance(digest, str)
        for path, digest in component_digests.items()
    ):
        _fail(
            "invalid_component_digests",
            "approvalResult.componentDigests",
            "approved component digest mapping is required",
        )
    approval_components = tuple(sorted(component_digests.items()))
    phases = current.state_core.get("phases")
    p00 = phases.get("P00") if isinstance(phases, Mapping) else None
    bootstrap_candidate_source_commit = (
        p00.get("baseCommit") if isinstance(p00, Mapping) else None
    )
    _require_commit(
        bootstrap_candidate_source_commit,
        "current.stateCore.phases.P00.baseCommit",
    )
    if (
        approval_result.get("status") != "verified"
        or approval_result.get("decision") != "APPROVE"
        or approval_result.get("approvalDigest") != current.bootstrap_approval_digest
        or approval_result.get("requestDigest") != current.bootstrap_request_digest
        or approval_result.get("controlPlaneDigest") != current.control_plane_digest
        or approval_result.get("trustPolicyDigest") != current.trust_policy_digest
        or approval_result.get("jwksSnapshotDigest") != current.jwks_snapshot_digest
        or approval_result.get("workflowExecutionCommit")
        != current.workflow_execution_commit
        or approval_result.get("candidateSourceCommit")
        != bootstrap_candidate_source_commit
        or approval_components != current.approved_component_digests
    ):
        _fail(
            "genesis_trust_binding_mismatch",
            "approvalResult",
            "approval differs from the sealed Genesis trust context",
        )
    try:
        snapshot = validate_jwks_snapshot(
            approved_jwks_snapshot,
            expected_snapshot_digest=current.jwks_snapshot_digest,
        )
    except OidcVerificationError as exc:
        _translate(exc)
    if snapshot["digest"] != current.jwks_snapshot_digest:
        _fail(
            "oidc_jwks_snapshot_digest_mismatch",
            "approvedJwksSnapshot",
            "JWK snapshot differs from the sealed Genesis trust context",
        )
    return signer, component_digests, current.jwks_snapshot_digest


def create_post_genesis_event(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    verified_event_input: VerifiedEventInput,
    chain_head_witness: VerifiedChainHeadWitness,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
    repo_root: Path,
    workflow_execution_commit: str,
    statement_timestamp: datetime | str,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedStateChainV2]:
    """Build and self-verify exactly one event after a sealed chain head.

    Payload, state, chain position, actor, reason (except the already-sealed
    lifecycle reason), and signing claims are all derived here.  The caller can
    select only a sealed operation and the current protected-main commit.
    """

    workflow_commit = _require_commit(
        workflow_execution_commit, "workflowExecutionCommit"
    )
    timestamp, timestamp_text = _timestamp(statement_timestamp)
    (
        state_core,
        state_digest,
        head_digest,
        event_count,
        head_sequence,
        head_timestamp,
        head_source_commit,
        trust_policy_digest,
    ) = _current_fields(current)
    control_plane_digest = _require_digest(
        state_core.get("controlPlaneDigest"), "current.stateCore.controlPlaneDigest"
    )
    head_source_commit = _require_commit(head_source_commit, "current.headSourceCommit")
    if timestamp <= head_timestamp:
        _fail(
            "nonmonotonic_event_time",
            "statementTimestamp",
            "event time must be later than the current chain head",
        )
    witness = _validate_witness(
        witness=chain_head_witness,
        state_digest=state_digest,
        head_digest=head_digest,
        event_count=event_count,
        head_sequence=head_sequence,
        head_source_commit=head_source_commit,
        control_plane_digest=control_plane_digest,
        trust_policy_digest=trust_policy_digest,
        event_timestamp=timestamp,
    )
    if not isinstance(policy_result, Mapping) or not isinstance(
        approval_result, Mapping
    ):
        _fail("invalid_trust_context", "trust", "verified trust mappings required")
    signer, component_digests, jwks_digest = _validate_bootstrap_trust(
        current=current,
        policy_result=policy_result,
        approval_result=approval_result,
        approved_jwks_snapshot=approved_jwks_snapshot,
    )
    actor = {
        "principal": signer.get("identity"),
        "role": signer.get("role"),
        "organization": signer.get("organization"),
    }
    if any(not isinstance(value, str) or not value for value in actor.values()):
        _fail(
            "invalid_oidc_signer_policy",
            "policyResult.stateSigner",
            "protected workflow actor is incomplete",
        )
    event_type, reason_code, reason = _event_kind_and_reason(verified_event_input)
    if event_type == "StateTransition":
        subject = verified_event_input.subject
        if subject.source_commit != workflow_commit:
            _fail(
                "workflow_execution_commit_mismatch",
                "workflowExecutionCommit",
                "a transition must execute at its sealed subject source commit",
            )
    payload = _project_payload(
        state_core=state_core,
        current_head_digest=head_digest,
        verified_input=verified_event_input,
        witness_digest=witness.attestation_digest,
    )
    claims = _expected_oidc_claims(
        policy_result, workflow_execution_commit=workflow_commit
    )
    claims_policy_digest = sha256_bytes(canonical_json_bytes(claims))
    sequence = head_sequence + 1
    body = {
        "eventType": event_type,
        "eventId": f"evt-{sequence:08d}",
        "sequence": sequence,
        "previousDigest": head_digest,
        "timestamp": timestamp_text,
        "actor": actor,
        "sourceCommit": workflow_commit,
        "controlPlaneDigest": control_plane_digest,
        "trustPolicyDigest": trust_policy_digest,
        "reasonCode": reason_code,
        "reason": reason,
        "writer": {
            "jwksSnapshotDigest": jwks_digest,
            "claimsPolicyDigest": claims_policy_digest,
            "workflowPath": signer.get("workflowPath"),
            "workflowExecutionCommit": workflow_commit,
        },
        "payload": payload,
    }
    statement = {
        "schemaVersion": STATE_EVENT_SCHEMA,
        "kind": STATE_EVENT_KIND,
        "body": body,
    }
    statement_digest = sha256_bytes(canonical_json_bytes(statement))
    audience = OIDC_AUDIENCE_PREFIX + statement_digest
    provider = (
        github_actions_token_provider if token_provider is None else token_provider
    )
    try:
        token = provider(audience)
    except (PostEventWriterError,):
        raise
    except StateWriterError as exc:
        _translate(exc)
    except Exception:
        _fail(
            "token_provider_failed",
            "tokenProvider",
            "injected OIDC token provider failed",
        )
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
            "namespace": STATE_EVENT_NAMESPACE,
            "statementDigest": statement_digest,
            "jwt": token,
        },
    }
    envelope["eventDigest"] = document_digest(envelope)
    try:
        verified_chain = verify_next_event_v2(
            current=current,
            event=envelope,
            verified_event_input=verified_event_input,
            expected_chain_head_witness_digest=witness.attestation_digest,
            policy_result=policy_result,
            approval_result=approval_result,
            jwks_snapshot=approved_jwks_snapshot,
            repo_root=Path(repo_root),
            approved_component_digests=component_digests,
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    return deepcopy(envelope), verified_chain


build_post_genesis_event = create_post_genesis_event


__all__ = [
    "PostEventWriterError",
    "build_post_genesis_event",
    "create_post_genesis_event",
]
