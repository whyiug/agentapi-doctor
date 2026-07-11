"""Canonical raw authorization importer for supported lifecycle operations.

Process-local lifecycle evidence and provenance seals are intentionally not
serializable.  This module imports one canonical JSON artifact containing the
raw primary evidence, protected lifecycle proof, and independent approval;
freshly verifies every signature and state binding; and returns new exact
process-local seals.

Only RESUME is writable in state-chain revision v1.  IMPACT/CONTROL
invalidation and SUPERSESSION are recognized but fail before a transition can
be projected: v1 has no atomic representation for cross-unit/phase
invalidation or control-plane replacement.  No digest copied from the bundle
is accepted as authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping, NoReturn
import weakref

from .chain_witness import (
    VerifiedChainHeadWitness,
    require_verified_chain_head_witness,
    verify_chain_head_witness,
)
from .digest import canonical_json_bytes, sha256_bytes
from .lifecycle_evidence import (
    OIDC_SCHEME,
    SSHSIG_SCHEME,
    LifecycleEvidenceError,
    VerifiedBlockerResolution,
    VerifiedInvalidationEvidence,
    compute_invalidation_projection,
    require_verified_blocker_resolution,
    require_verified_invalidation_evidence,
    verify_blocker_resolution,
)
from .oidc_provenance import OidcProvenanceError
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    SignerVerifier,
    SubjectBinding,
    VerifiedLifecycleApprovalResult,
    VerifiedLifecycleProofResult,
    VerifiedLifecycleTransition,
    VerifiedWorkUnitStateContext,
    _require_verified as _require_provenance_verified,
    authorize_lifecycle_transition,
    verify_lifecycle_approval,
    verify_lifecycle_proof,
)
from .sshsig import SshSigVerificationError


BUNDLE_SCHEMA = "urn:agentapi-doctor:lifecycle-authorization-bundle:v1alpha1"
BUNDLE_KIND = "RawLifecycleAuthorizationBundle"
MAX_BUNDLE_BYTES = 16 * 1024 * 1024

OP_RESUME = "work-unit-resume"
OP_INVALIDATION = "work-unit-impact-invalidation"
OP_CONTROL_INVALIDATION = "work-unit-control-invalidation"
OP_SUPERSESSION = "work-unit-supersession"
RECOGNIZED_OPERATIONS = frozenset(
    {OP_RESUME, OP_INVALIDATION, OP_CONTROL_INVALIDATION, OP_SUPERSESSION}
)
SUPPORTED_OPERATIONS = frozenset({OP_RESUME})

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

PrimaryEvidence = VerifiedBlockerResolution | VerifiedInvalidationEvidence


@dataclass
class LifecycleBundleError(ValueError):
    """Stable, secret-free raw lifecycle import failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class VerifiedLifecycleAuthorizationBundle:
    bundle_digest: str
    bundle_id: str
    operation: str
    source_commit: str
    base_commit: str
    prior_state_digest: str
    prior_chain_head_digest: str
    primary_evidence: PrimaryEvidence
    proof: VerifiedLifecycleProofResult
    approval: VerifiedLifecycleApprovalResult
    event_input: VerifiedLifecycleTransition
    chain_head_witness: VerifiedChainHeadWitness


_VERIFIED: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise LifecycleBundleError(code, path, message)


def _translate(error: Exception) -> NoReturn:
    _fail(
        str(getattr(error, "code", "lifecycle_authorization_failed")),
        str(getattr(error, "path", "lifecycleAuthorizationBundle")),
        str(getattr(error, "message", str(error))),
    )


def _mark_verified(
    value: VerifiedLifecycleAuthorizationBundle,
) -> VerifiedLifecycleAuthorizationBundle:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _VERIFIED.get(identity)
        if current is not None and current[0] is reference:
            _VERIFIED.pop(identity, None)

    reference = weakref.ref(value, discard)
    _VERIFIED[identity] = (reference, _bundle_projection_digest(value))
    return value


def _bundle_projection_digest(
    value: VerifiedLifecycleAuthorizationBundle,
) -> str:
    primary = value.primary_evidence
    proof = value.proof
    approval = value.approval
    event = value.event_input
    witness = value.chain_head_witness
    projection = {
        "bundleDigest": value.bundle_digest,
        "bundleId": value.bundle_id,
        "operation": value.operation,
        "sourceCommit": value.source_commit,
        "baseCommit": value.base_commit,
        "priorStateDigest": value.prior_state_digest,
        "priorChainHeadDigest": value.prior_chain_head_digest,
        "primary": {
            "type": type(primary).__name__,
            "attestationDigest": primary.attestation_digest,
            "statementDigest": primary.statement_digest,
            "subject": _subject_document(primary.subject),
            "fromState": primary.from_state,
            "toState": primary.to_state,
            "priorStateDigest": primary.prior_state_digest,
            "priorChainHeadDigest": primary.prior_chain_head_digest,
            "invalidationKind": getattr(primary, "invalidation_kind", None),
            "authorityMode": getattr(primary, "authority_mode", None),
        },
        "proof": {
            "attestationDigest": proof.attestation_digest,
            "statementDigest": proof.statement_digest,
            "subject": _subject_document(proof.subject),
            "fromState": proof.from_state,
            "toState": proof.to_state,
            "transitionType": proof.transition_type,
            "blockerResolutionDigest": proof.blocker_resolution_digest,
            "invalidationKind": proof.invalidation_kind,
            "invalidationDigest": proof.invalidation_digest,
        },
        "approval": {
            "attestationDigest": approval.attestation_digest,
            "statementDigest": approval.statement_digest,
            "proofDigest": approval.proof_digest,
            "decision": approval.decision,
            "authorized": approval.authorized,
        },
        "event": {
            "transitionType": event.transition_type,
            "subject": _subject_document(event.subject),
            "fromState": event.from_state,
            "toState": event.to_state,
            "priorStateDigest": event.prior_state_digest,
            "priorChainHeadDigest": event.prior_chain_head_digest,
            "blockerResolutionDigest": event.blocker_resolution_digest,
            "invalidationKind": event.invalidation_kind,
            "invalidationDigest": event.invalidation_digest,
            "proofDigest": event.proof_digest,
            "approvalDigest": event.approval_digest,
        },
        "chainHeadWitness": {
            "attestationDigest": witness.attestation_digest,
            "witnessId": witness.witness_id,
            "priorChainHeadDigest": witness.prior_chain_head_digest,
            "priorStateDigest": witness.prior_state_digest,
            "priorEventCount": witness.prior_event_count,
            "priorHeadSequence": witness.prior_head_sequence,
            "priorSourceCommit": witness.prior_source_commit,
            "controlPlaneDigest": witness.control_plane_digest,
            "trustPolicyDigest": witness.trust_policy_digest,
            "witnessedAt": witness.witnessed_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "validUntil": witness.valid_until.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "principal": witness.principal,
            "organization": witness.organization,
        },
    }
    return sha256_bytes(canonical_json_bytes(projection))


def require_verified_lifecycle_bundle(
    value: Any, *, path: str = "lifecycleAuthorizationBundle"
) -> VerifiedLifecycleAuthorizationBundle:
    """Reject copied, reconstructed, or partially substituted bundle results."""

    record = _VERIFIED.get(id(value))
    if (
        not isinstance(value, VerifiedLifecycleAuthorizationBundle)
        or record is None
        or record[0]() is not value
    ):
        _fail(
            "unverified_lifecycle_bundle",
            path,
            "expected the exact result returned by the lifecycle bundle importer",
        )
    try:
        observed_projection_digest = _bundle_projection_digest(value)
    except (AttributeError, TypeError, ValueError):
        _fail(
            "mutated_lifecycle_bundle",
            path,
            "verified bundle projection is no longer structurally valid",
        )
    if observed_projection_digest != record[1]:
        _fail(
            "mutated_lifecycle_bundle",
            path,
            "verified bundle projection changed after import",
        )
    try:
        if value.operation == OP_RESUME:
            primary = require_verified_blocker_resolution(value.primary_evidence)
        elif value.operation == OP_INVALIDATION:
            primary = require_verified_invalidation_evidence(value.primary_evidence)
        else:
            _fail(
                "verified_bundle_projection_mismatch",
                path,
                "unsupported operation escaped the importer",
            )
        _require_provenance_verified(
            value.proof, VerifiedLifecycleProofResult, f"{path}.proof"
        )
        _require_provenance_verified(
            value.approval, VerifiedLifecycleApprovalResult, f"{path}.approval"
        )
        _require_provenance_verified(
            value.event_input, VerifiedLifecycleTransition, f"{path}.eventInput"
        )
        witness = require_verified_chain_head_witness(
            value.chain_head_witness, path=f"{path}.chainHeadWitness"
        )
    except (
        LifecycleEvidenceError,
        OidcProvenanceError,
        ProtectedVerificationError,
        SshSigVerificationError,
    ) as exc:
        _translate(exc)
    if (
        value.source_commit != primary.subject.source_commit
        or value.prior_state_digest != primary.prior_state_digest
        or value.prior_chain_head_digest != primary.prior_chain_head_digest
        or value.proof.subject != primary.subject
        or value.event_input.proof_digest != value.proof.attestation_digest
        or value.event_input.approval_digest != value.approval.attestation_digest
        or witness.prior_state_digest != value.prior_state_digest
        or witness.prior_chain_head_digest != value.prior_chain_head_digest
    ):
        _fail(
            "verified_bundle_projection_mismatch",
            path,
            "fresh evidence/proof/approval/transition projection differs",
        )
    return value


def lifecycle_primary_evidence_for_writer(
    bundle: Any,
) -> PrimaryEvidence:
    """Return the exact inner seal for ``create_signed_lifecycle_proof``."""

    return require_verified_lifecycle_bundle(bundle).primary_evidence


def lifecycle_transition_for_state_writer(
    bundle: Any,
) -> VerifiedLifecycleTransition:
    """Return the exact authorized transition seal for a state writer."""

    return require_verified_lifecycle_bundle(bundle).event_input


def lifecycle_chain_head_witness_for_state_writer(
    bundle: Any,
) -> VerifiedChainHeadWitness:
    """Return the freshly verified witness required by the post-event writer."""

    return require_verified_lifecycle_bundle(bundle).chain_head_witness


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail(
                "duplicate_lifecycle_bundle_key",
                "lifecycleAuthorizationBundle",
                f"duplicate key: {key}",
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(
        "invalid_lifecycle_bundle_json",
        "lifecycleAuthorizationBundle",
        f"non-finite number: {value}",
    )


def _load(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BUNDLE_BYTES:
        _fail(
            "invalid_lifecycle_bundle_size",
            "lifecycleAuthorizationBundle",
            f"canonical bundle must be 1..{MAX_BUNDLE_BYTES} bytes",
        )
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except LifecycleBundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail(
            "invalid_lifecycle_bundle_json",
            "lifecycleAuthorizationBundle",
            str(exc),
        )
    if not isinstance(value, dict):
        _fail(
            "invalid_lifecycle_bundle_schema",
            "lifecycleAuthorizationBundle",
            "top-level object required",
        )
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        _fail(
            "invalid_lifecycle_bundle_json",
            "lifecycleAuthorizationBundle",
            str(exc),
        )
    if raw != canonical:
        _fail(
            "noncanonical_lifecycle_bundle",
            "lifecycleAuthorizationBundle",
            "bytes must be exact canonical JSON without trailing data",
        )
    return value


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(
            "invalid_lifecycle_bundle_schema",
            path,
            "field set differs from the versioned schema",
        )
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_lifecycle_bundle_digest", path, "lowercase SHA-256 required")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_lifecycle_bundle_commit", path, "full lowercase Git commit required")
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(
            "invalid_lifecycle_bundle_timestamp",
            "verificationTime",
            "timezone-aware datetime required",
        )
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail(
            "invalid_lifecycle_bundle_timestamp",
            "verificationTime",
            "second precision required",
        )
    return normalized


def _subject_document(subject: SubjectBinding) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "workUnit": subject.work_unit,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "contractDigest": subject.contract_digest,
    }


def _probe_control_drift(
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    base_commit: str,
    head_commit: str,
    approved_component_digests: Mapping[str, str],
    expected_impact_map_digest: str,
) -> None:
    base_subject = replace(expected_subject, source_commit=base_commit)
    try:
        projection = compute_invalidation_projection(
            repo_root=repo_root,
            state_context=state_context,
            expected_subject=base_subject,
            base_commit=base_commit,
            head_commit=head_commit,
            approved_component_digests=approved_component_digests,
            expected_impact_map_digest=expected_impact_map_digest,
        )
    except LifecycleEvidenceError as exc:
        if exc.code == "invalidation_authority_source_mismatch":
            # A standard IMPACT projection correctly requires candidate head.
            return
        _translate(exc)
    if projection.invalidation_kind == "CONTROL":
        _fail(
            "unsupported_control_plane_revision",
            "lifecycleAuthorizationBundle.primaryEvidence",
            "state-chain v1 has no verified old-authority to new-authority bridge for CONTROL drift",
        )
    _fail(
        "invalid_invalidation_authority",
        "lifecycleAuthorizationBundle.primaryEvidence",
        "unexpected invalidation authority projection",
    )


def verify_lifecycle_authorization_bundle(
    raw_artifact: bytes,
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    expected_operation: str,
    expected_contract_approval_digest: str,
    expected_impact_map_digest: str,
    approved_component_digests: Mapping[str, str],
    policy_result: Mapping[str, Any],
    expected_prior_event_count: int,
    expected_prior_head_sequence: int,
    expected_prior_source_commit: str,
    expected_trust_policy_digest: str,
    expected_human_authority_digest: str,
    expected_invalidation_authority_digest: str,
    expected_proof_authority_digest: str,
    blocker_signer_verifier: SignerVerifier | None,
    invalidation_signer_verifier: SignerVerifier | None,
    proof_signer_verifier: SignerVerifier,
    approval_signer_verifier: SignerVerifier,
    verification_time: datetime,
) -> VerifiedLifecycleAuthorizationBundle:
    """Freshly verify a canonical RESUME authorization.

    Invalidation evidence remains independently verifiable, but state-chain v1
    cannot atomically invalidate every affected work unit and its phase.  All
    invalidation bundle operations therefore fail closed before an event input
    can be produced.
    """

    if expected_operation not in RECOGNIZED_OPERATIONS:
        _fail(
            "unsupported_lifecycle_operation",
            "expectedOperation",
            "operation is not a recognized lifecycle bundle type",
        )
    if not isinstance(policy_result, Mapping):
        _fail(
            "invalid_trust_policy",
            "policyResult",
            "verified chain-witness policy mapping required",
        )
    try:
        _require_provenance_verified(
            state_context, VerifiedWorkUnitStateContext, "stateContext"
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    now = _utc(verification_time)
    contract_approval = _digest(
        expected_contract_approval_digest, "expectedContractApprovalDigest"
    )
    impact_map = _digest(expected_impact_map_digest, "expectedImpactMapDigest")
    for value, path in (
        (expected_subject.control_plane_digest, "expectedSubject.controlPlaneDigest"),
        (expected_subject.contract_digest, "expectedSubject.contractDigest"),
        (expected_trust_policy_digest, "expectedTrustPolicyDigest"),
        (expected_human_authority_digest, "expectedHumanAuthorityDigest"),
        (
            expected_invalidation_authority_digest,
            "expectedInvalidationAuthorityDigest",
        ),
        (expected_proof_authority_digest, "expectedProofAuthorityDigest"),
    ):
        _digest(value, path)
    if (
        expected_subject.phase != state_context.phase
        or expected_subject.work_unit != state_context.work_unit
        or expected_subject.control_plane_digest != state_context.control_plane_digest
        or expected_subject.contract_digest != state_context.contract_digest
    ):
        _fail(
            "lifecycle_bundle_subject_mismatch",
            "expectedSubject",
            "subject differs from exact verified current state",
        )
    if state_context.recorded_source_commit is None:
        _fail(
            "lifecycle_bundle_base_missing",
            "stateContext.recordedSourceCommit",
            "lifecycle operation requires the source recorded in current state",
        )
    base_commit = _commit(
        state_context.recorded_source_commit, "stateContext.recordedSourceCommit"
    )
    head_commit = _commit(expected_subject.source_commit, "expectedSubject.sourceCommit")
    prior_source_commit = _commit(
        expected_prior_source_commit, "expectedPriorSourceCommit"
    )
    if (
        isinstance(expected_prior_event_count, bool)
        or not isinstance(expected_prior_event_count, int)
        or expected_prior_event_count < 0
        or isinstance(expected_prior_head_sequence, bool)
        or not isinstance(expected_prior_head_sequence, int)
        or expected_prior_head_sequence < 0
    ):
        _fail(
            "invalid_chain_position",
            "expectedChainPosition",
            "non-negative event count and head sequence required",
        )

    document = _load(raw_artifact)
    envelope = _exact(
        document,
        {
            "schemaVersion",
            "kind",
            "bundleId",
            "operation",
            "chainHeadWitness",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "baseCommit",
            "headCommit",
            "contractApprovalDigest",
            "impactMapDigest",
            "primaryEvidence",
            "proof",
            "approval",
            "bundleDigest",
        },
        "lifecycleAuthorizationBundle",
    )
    if envelope["schemaVersion"] != BUNDLE_SCHEMA or envelope["kind"] != BUNDLE_KIND:
        _fail(
            "invalid_lifecycle_bundle_schema",
            "lifecycleAuthorizationBundle",
            "unsupported lifecycle bundle revision",
        )
    bundle_id = envelope["bundleId"]
    if not isinstance(bundle_id, str) or ID_RE.fullmatch(bundle_id) is None:
        _fail(
            "invalid_lifecycle_bundle_id",
            "lifecycleAuthorizationBundle.bundleId",
            "invalid bounded bundle identifier",
        )
    bundle_digest = document_digest(envelope, omit_field="bundleDigest")
    if envelope["bundleDigest"] != bundle_digest:
        _fail(
            "lifecycle_bundle_digest_mismatch",
            "lifecycleAuthorizationBundle.bundleDigest",
            "bundle digest does not cover exact raw documents",
        )
    if envelope["operation"] != expected_operation:
        _fail(
            "lifecycle_operation_replay",
            "lifecycleAuthorizationBundle.operation",
            "bundle targets another lifecycle operation",
        )
    try:
        chain_head_witness = verify_chain_head_witness(
            envelope["chainHeadWitness"],
            policy_result=policy_result,
            expected_prior_chain_head_digest=state_context.chain_head_digest,
            expected_prior_state_digest=state_context.state_digest,
            expected_prior_event_count=expected_prior_event_count,
            expected_prior_head_sequence=expected_prior_head_sequence,
            expected_prior_source_commit=prior_source_commit,
            expected_control_plane_digest=state_context.control_plane_digest,
            expected_trust_policy_digest=expected_trust_policy_digest,
            now=now,
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    if expected_operation in {OP_INVALIDATION, OP_CONTROL_INVALIDATION}:
        _fail(
            "unsupported_invalidation_batch_semantics",
            "lifecycleAuthorizationBundle.operation",
            "state-chain v1 cannot atomically invalidate every affected work unit and phase",
        )
    if expected_operation == OP_SUPERSESSION:
        _fail(
            "unsupported_control_plane_revision",
            "lifecycleAuthorizationBundle.operation",
            "state-chain v1 cannot authorize this control-plane revision operation",
        )
    if expected_operation not in SUPPORTED_OPERATIONS:
        _fail(
            "unsupported_lifecycle_operation",
            "lifecycleAuthorizationBundle.operation",
            "operation is not implemented",
        )
    if (
        envelope["subject"] != _subject_document(expected_subject)
        or envelope["fromState"] != state_context.status
        or envelope["priorStateDigest"] != state_context.state_digest
        or envelope["priorChainHeadDigest"] != state_context.chain_head_digest
        or envelope["baseCommit"] != base_commit
        or envelope["headCommit"] != head_commit
        or envelope["contractApprovalDigest"] != contract_approval
        or envelope["impactMapDigest"] != impact_map
    ):
        _fail(
            "lifecycle_bundle_replay",
            "lifecycleAuthorizationBundle",
            "outer state/head/subject/control pins differ from trusted current inputs",
        )

    try:
        if expected_operation == OP_RESUME:
            if state_context.status != "BLOCKED" or envelope["toState"] != "ACTIVE":
                _fail(
                    "invalid_resume_bundle_transition",
                    "lifecycleAuthorizationBundle",
                    "RESUME must bind exact BLOCKED->ACTIVE",
                )
            if blocker_signer_verifier is None:
                _fail(
                    "missing_lifecycle_signer_verifier",
                    "blockerSignerVerifier",
                    "RESUME requires an SSHSIG verifier",
                )
            primary: PrimaryEvidence = verify_blocker_resolution(
                envelope["primaryEvidence"],
                repo_root=repo_root,
                state_context=state_context,
                expected_subject=expected_subject,
                expected_authority_digest=expected_human_authority_digest,
                signer_verifier=blocker_signer_verifier,
                verification_time=now,
            )
            expected_to_state = "ACTIVE"
        else:  # pragma: no cover - SUPPORTED_OPERATIONS is RESUME-only.
            _fail(
                "unsupported_invalidation_batch_semantics",
                "lifecycleAuthorizationBundle.operation",
                "state-chain v1 cannot authorize invalidation event inputs",
            )
        proof = verify_lifecycle_proof(
            envelope["proof"],
            state_context=state_context,
            expected_subject=expected_subject,
            expected_to_state=expected_to_state,
            expected_contract_approval_digest=contract_approval,
            expected_impact_map_digest=impact_map,
            expected_authority_digest=expected_proof_authority_digest,
            signer_verifier=proof_signer_verifier,
        )
        if proof.signer.scheme != OIDC_SCHEME:
            _fail(
                "lifecycle_proof_identity_mismatch",
                "lifecycleAuthorizationBundle.proof.signature.scheme",
                "protected lifecycle proof requires GitHub Actions OIDC",
            )
        if isinstance(primary, VerifiedBlockerResolution):
            projection_matches = (
                proof.transition_type == "RESUME"
                and proof.blocker_resolution_digest == primary.attestation_digest
                and proof.invalidation_kind is None
                and proof.invalidation_digest is None
            )
        else:
            projection_matches = (
                proof.transition_type == "INVALIDATION"
                and proof.blocker_resolution_digest is None
                and proof.invalidation_kind == primary.invalidation_kind
                and proof.invalidation_digest == primary.attestation_digest
            )
        if (
            not projection_matches
            or proof.reason_code != primary.reason_code
            or proof.reason != primary.reason
        ):
            _fail(
                "primary_evidence_projection_mismatch",
                "lifecycleAuthorizationBundle.proof",
                "proof does not consume the exact freshly verified primary evidence",
            )
        approval = verify_lifecycle_approval(
            envelope["approval"],
            proof=proof,
            expected_authority_digest=expected_human_authority_digest,
            signer_verifier=approval_signer_verifier,
            now=now,
        )
        if approval.signer.scheme != SSHSIG_SCHEME:
            _fail(
                "lifecycle_approval_identity_mismatch",
                "lifecycleAuthorizationBundle.approval.signature.scheme",
                "independent lifecycle approval requires SSHSIG",
            )
        event_input = authorize_lifecycle_transition(
            state_context=state_context,
            proof=proof,
            approval=approval,
        )
    except LifecycleBundleError:
        raise
    except (
        LifecycleEvidenceError,
        OidcProvenanceError,
        ProtectedVerificationError,
        SshSigVerificationError,
    ) as exc:
        _translate(exc)

    return _mark_verified(
        VerifiedLifecycleAuthorizationBundle(
            bundle_digest=bundle_digest,
            bundle_id=bundle_id,
            operation=expected_operation,
            source_commit=expected_subject.source_commit,
            base_commit=base_commit,
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            primary_evidence=primary,
            proof=proof,
            approval=approval,
            event_input=event_input,
            chain_head_witness=chain_head_witness,
        )
    )


__all__ = [
    "BUNDLE_KIND",
    "BUNDLE_SCHEMA",
    "LifecycleBundleError",
    "MAX_BUNDLE_BYTES",
    "OP_CONTROL_INVALIDATION",
    "OP_INVALIDATION",
    "OP_RESUME",
    "OP_SUPERSESSION",
    "VerifiedLifecycleAuthorizationBundle",
    "lifecycle_chain_head_witness_for_state_writer",
    "lifecycle_primary_evidence_for_writer",
    "lifecycle_transition_for_state_writer",
    "require_verified_lifecycle_bundle",
    "verify_lifecycle_authorization_bundle",
]
