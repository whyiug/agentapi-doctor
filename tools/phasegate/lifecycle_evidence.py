"""Identity-sealed raw evidence for protected lifecycle transitions.

Lifecycle proofs are projections, not primary evidence.  This module verifies
the three primary evidence families which cannot safely be represented by a
caller-provided digest:

* an independently SSHSIG-approved blocker resolution for ``BLOCKED->ACTIVE``;
* a protected-workflow OIDC invalidation derived from two exact local Git
  commits, the approved component map, and the approved impact map; and
* an independently SSHSIG-approved explicit Plan/RFC supersession decision.

The returned frozen dataclasses are identity sealed.  Reconstructing one from
its fields does not recreate the seal and therefore cannot authorize a writer.
CONTROL invalidation uses a dedicated authority still executing the approved
base revision; standard approved-head authority is accepted only for IMPACT.
The current state-chain revision cannot bridge CONTROL authority revisions or
safely swap a supersession's authoritative subject.  The provenance writer
therefore reports structured unsupported-control-plane-revision failures for
both instead of pretending those transitions are production-writable.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping, NoReturn, Sequence
import weakref

from .digest import (
    canonical_json_bytes,
    normalize_control_plane_references,
    sha256_bytes,
)
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    SignerVerifier,
    SubjectBinding,
    VerifiedSignerResult,
    VerifiedWorkUnitStateContext,
    _require_verified as _require_provenance_verified,
    _resolve_signer,
    _validate_envelope,
    _validate_expected_subject,
    _validate_subject,
)


BLOCKER_RESOLUTION_SCHEMA = (
    "urn:agentapi-doctor:blocker-resolution:v1alpha1"
)
BLOCKER_RESOLUTION_KIND = "BlockerResolution"
BLOCKER_RESOLUTION_NAMESPACE = (
    "agentapi-doctor/lifecycle-evidence/blocker-resolution/v1"
)

INVALIDATION_SCHEMA = "urn:agentapi-doctor:lifecycle-invalidation:v1alpha1"
INVALIDATION_KIND = "LifecycleInvalidation"
INVALIDATION_NAMESPACE = "agentapi-doctor/lifecycle-evidence/invalidation/v1"

SUPERSESSION_SCHEMA = "urn:agentapi-doctor:supersession-approval:v1alpha1"
SUPERSESSION_KIND = "SupersessionApproval"
SUPERSESSION_NAMESPACE = (
    "agentapi-doctor/lifecycle-evidence/supersession-approval/v1"
)

SSHSIG_SCHEME = "openssh-sshsig-v1"
OIDC_SCHEME = "github-actions-oidc-jwt-rs256-v1"
CONTROL_INPUT_MANIFEST = "execution/control-plane-inputs.yaml"
IMPACT_MAP_PATH = "execution/impact-map.yaml"

MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_COMPONENT_BYTES = 8 * 1024 * 1024
MAX_CHANGED_PATHS = 4096
MAX_COMPONENTS = 4096
MAX_ARTIFACTS = 128
MAX_ASSERTIONS = 128
MAX_HUMAN_APPROVAL_LIFETIME = timedelta(days=30)
MAX_INVALIDATION_AGE = timedelta(hours=24)

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC_PATH_RE = re.compile(r"^rfcs/[0-9]{4}-[A-Za-z0-9._-]+\.md$")
JSON_COMPONENT_KINDS = frozenset(
    {"json", "json-yaml", "manifest", "contract", "catalog", "gate"}
)
TEXT_COMPONENT_KINDS = frozenset({"text", "markdown", "python", "workflow"})

INVALIDATION_TARGETS = {
    "ACTIVE": "BLOCKED",
    "READY": "REJECTED",
    "MACHINE_CONVERGED": "REJECTED",
    "WAITING_EXTERNAL": "REJECTED",
    "REVIEW_PENDING": "REJECTED",
    "CONVERGED": "REJECTED",
}


class LifecycleEvidenceError(ProtectedVerificationError):
    """Stable, secret-free lifecycle evidence verification failure."""


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise LifecycleEvidenceError(code, path, message)


@dataclass(frozen=True)
class ResolutionArtifact:
    path: str
    digest: str
    validator: str
    assertions: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedBlockerResolution:
    attestation_digest: str
    statement_digest: str
    resolution_id: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    artifacts: tuple[ResolutionArtifact, ...]
    reason_code: str
    reason: str
    requester_principal: str
    requester_organization: str
    issued_at: datetime
    valid_until: datetime
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class InvalidationComputation:
    """Mechanically derived, unsigned invalidation projection."""

    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    base_commit: str
    head_commit: str
    impact_map_digest: str
    approved_component_map_digest: str
    changed_paths: tuple[str, ...]
    matched_mappings: tuple[str, ...]
    affected_units: tuple[str, ...]
    invalidation_kind: str
    authority_mode: str
    control_drift_detected: bool
    changed_components: tuple[str, ...]
    invalid_components: tuple[str, ...]
    approved_control_plane_digest: str
    head_control_plane_digest: str | None
    reason_code: str
    reason: str


@dataclass(frozen=True)
class VerifiedInvalidationEvidence:
    attestation_digest: str
    statement_digest: str
    invalidation_id: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    base_commit: str
    head_commit: str
    impact_map_digest: str
    approved_component_map_digest: str
    changed_paths: tuple[str, ...]
    matched_mappings: tuple[str, ...]
    affected_units: tuple[str, ...]
    invalidation_kind: str
    authority_mode: str
    control_drift_detected: bool
    changed_components: tuple[str, ...]
    invalid_components: tuple[str, ...]
    approved_control_plane_digest: str
    head_control_plane_digest: str | None
    reason_code: str
    reason: str
    issued_at: datetime
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class SupersessionDecision:
    kind: str
    decision_id: str
    path: str
    digest: str


@dataclass(frozen=True)
class VerifiedSupersessionApproval:
    attestation_digest: str
    statement_digest: str
    approval_id: str
    subject: SubjectBinding
    replacement_subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    decision: SupersessionDecision
    reason_code: str
    reason: str
    requester_principal: str
    requester_organization: str
    issued_at: datetime
    valid_until: datetime
    signer: VerifiedSignerResult


_VERIFIED_OBJECTS: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _mark_verified(value: Any) -> Any:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _VERIFIED_OBJECTS.get(identity)
        if current is not None and current[0] is reference:
            _VERIFIED_OBJECTS.pop(identity, None)

    reference = weakref.ref(value, discard)
    _VERIFIED_OBJECTS[identity] = (reference, _sealed_projection_digest(value))
    return value


def _sealed_projection(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if is_dataclass(value):
        return {
            field.name: _sealed_projection(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_sealed_projection(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _sealed_projection(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    _fail(
        "invalid_lifecycle_seal_projection",
        "lifecycleEvidence",
        "verified result contains an unsupported projection value",
    )


def _sealed_projection_digest(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(_sealed_projection(value)))


def _require_verified(value: Any, expected_type: type, path: str) -> None:
    record = _VERIFIED_OBJECTS.get(id(value))
    if (
        not isinstance(value, expected_type)
        or record is None
        or record[0]() is not value
    ):
        _fail(
            "unverified_lifecycle_evidence",
            path,
            "writer inputs must be exact objects returned by lifecycle evidence verification",
        )
    if _sealed_projection_digest(value) != record[1]:
        _fail(
            "mutated_lifecycle_evidence",
            path,
            "verified lifecycle evidence changed after verification",
        )


def require_verified_blocker_resolution(value: Any) -> VerifiedBlockerResolution:
    _require_verified(value, VerifiedBlockerResolution, "blockerResolution")
    return value


def require_verified_invalidation_evidence(
    value: Any,
) -> VerifiedInvalidationEvidence:
    _require_verified(value, VerifiedInvalidationEvidence, "invalidationEvidence")
    return value


def require_verified_supersession_approval(
    value: Any,
) -> VerifiedSupersessionApproval:
    _require_verified(value, VerifiedSupersessionApproval, "supersessionApproval")
    return value


def _exact(value: Any, fields: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(
            "invalid_lifecycle_evidence_schema",
            path,
            "field set differs from the versioned lifecycle evidence schema",
        )
    return value


def _text(
    value: Any,
    path: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
) -> str:
    if (
        not isinstance(value, str)
        or len(value.strip()) < minimum
        or len(value) > maximum
        or "\x00" in value
    ):
        _fail("invalid_lifecycle_evidence", path, "invalid bounded non-empty string")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        _fail("invalid_lifecycle_evidence", path, "invalid bounded identifier")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_lifecycle_evidence_digest", path, "invalid SHA-256 digest")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_lifecycle_commit", path, "full lowercase Git commit required")
    return value


def _repo_path(value: Any, path: str, *, pattern: bool = False) -> str:
    raw = _text(value, path, maximum=1024)
    parts = raw.split("/")
    if (
        raw.startswith("/")
        or "\\" in raw
        or any(part in {"", ".", ".."} for part in parts)
        or (not pattern and any(character in raw for character in "*?["))
    ):
        _fail("unsafe_lifecycle_path", path, "safe repository-relative path required")
    return raw


def _timestamp(value: Any, path: str) -> datetime:
    raw = _text(value, path, maximum=64)
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _fail(
            "invalid_lifecycle_timestamp",
            path,
            "second-precision RFC3339 UTC timestamp required",
        )
    return parsed


def _verification_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(
            "invalid_lifecycle_timestamp",
            "verificationTime",
            "timezone-aware verification time required",
        )
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail(
            "invalid_lifecycle_timestamp",
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


def _state_subject(
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    *,
    expected_statuses: set[str],
    require_recorded_source: bool,
) -> None:
    try:
        _require_provenance_verified(
            state_context, VerifiedWorkUnitStateContext, "stateContext"
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if state_context.status not in expected_statuses:
        _fail(
            "invalid_lifecycle_evidence_state",
            "stateContext.status",
            "lifecycle evidence is not valid for the current state",
        )
    if (
        expected_subject.phase != state_context.phase
        or expected_subject.work_unit != state_context.work_unit
        or expected_subject.control_plane_digest != state_context.control_plane_digest
        or expected_subject.contract_digest != state_context.contract_digest
    ):
        _fail(
            "lifecycle_evidence_subject_mismatch",
            "subject",
            "phase/work-unit/control-plane/contract differs from exact verified state",
        )
    if require_recorded_source and (
        state_context.recorded_source_commit is None
        or expected_subject.source_commit != state_context.recorded_source_commit
    ):
        _fail(
            "lifecycle_evidence_source_mismatch",
            "subject.sourceCommit",
            "subject source differs from the exact source recorded in state",
        )


def _coi(value: Any, path: str) -> tuple[str, str]:
    body = _exact(
        value,
        {
            "independent",
            "requesterPrincipal",
            "requesterOrganization",
            "declaration",
        },
        path,
    )
    if body["independent"] is not True:
        _fail("conflict_of_interest", f"{path}.independent", "independence required")
    principal = _text(body["requesterPrincipal"], f"{path}.requesterPrincipal", maximum=256)
    organization = _text(
        body["requesterOrganization"], f"{path}.requesterOrganization", maximum=256
    )
    _text(body["declaration"], f"{path}.declaration", minimum=8, maximum=2048)
    return principal, organization


def _validate_human_window(
    issued_at: datetime, valid_until: datetime, verification_time: datetime, path: str
) -> None:
    if valid_until <= issued_at:
        _fail("invalid_approval_window", path, "validUntil must follow issuedAt")
    if valid_until - issued_at > MAX_HUMAN_APPROVAL_LIFETIME:
        _fail("invalid_approval_window", path, "approval validity exceeds 30 days")
    if verification_time < issued_at or verification_time >= valid_until:
        _fail("expired_lifecycle_approval", path, "approval is not valid now")


def _resolve_exact_signer(
    *,
    payload: bytes,
    statement_digest: str,
    signature: Mapping[str, Any],
    namespace: str,
    body: Mapping[str, Any],
    subject: SubjectBinding,
    expected_role: str,
    expected_scheme: str,
    expected_authority_digest: str,
    signer_verifier: SignerVerifier,
) -> VerifiedSignerResult:
    if not callable(signer_verifier):
        _fail(
            "signer_verification_required",
            "signature",
            "a cryptographic signer verifier callback is required",
        )
    try:
        signer = _resolve_signer(
            payload=payload,
            statement_digest=statement_digest,
            signature=signature,
            namespace=namespace,
            body=body,
            subject=subject,
            expected_role=expected_role,
            expected_authority_digest=expected_authority_digest,
            verified_signer_result=None,
            signer_verifier=signer_verifier,
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if signer.scheme != expected_scheme:
        _fail(
            "lifecycle_signature_scheme_mismatch",
            "signature.scheme",
            "lifecycle evidence uses the wrong identity proof scheme",
        )
    return signer


def _resolution_artifacts(value: Any) -> tuple[ResolutionArtifact, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARTIFACTS:
        _fail(
            "empty_blocker_resolution_manifest",
            "blockerResolution.body.resolutionArtifacts",
            "BlockerResolution requires a non-empty bounded artifact manifest",
        )
    result: list[ResolutionArtifact] = []
    for index, candidate in enumerate(value):
        path = f"blockerResolution.body.resolutionArtifacts[{index}]"
        body = _exact(candidate, {"path", "digest", "validator", "assertions"}, path)
        artifact_path = _repo_path(body["path"], f"{path}.path")
        validator = _text(body["validator"], f"{path}.validator", maximum=512)
        if "://" not in validator:
            _fail(
                "invalid_resolution_validator",
                f"{path}.validator",
                "validator must be a named URI, not a file-existence claim",
            )
        assertions_raw = body["assertions"]
        if (
            not isinstance(assertions_raw, list)
            or not 1 <= len(assertions_raw) <= MAX_ASSERTIONS
        ):
            _fail(
                "empty_resolution_assertions",
                f"{path}.assertions",
                "each artifact requires at least one semantic assertion",
            )
        assertions = tuple(
            _identifier(item, f"{path}.assertions[{position}]")
            for position, item in enumerate(assertions_raw)
        )
        if list(assertions) != sorted(set(assertions)):
            _fail(
                "invalid_resolution_assertions",
                f"{path}.assertions",
                "assertions must be sorted and unique",
            )
        result.append(
            ResolutionArtifact(
                path=artifact_path,
                digest=_digest(body["digest"], f"{path}.digest"),
                validator=validator,
                assertions=assertions,
            )
        )
    paths = [item.path for item in result]
    if paths != sorted(set(paths), key=lambda item: item.encode("utf-8")):
        _fail(
            "invalid_blocker_resolution_manifest",
            "blockerResolution.body.resolutionArtifacts",
            "artifact paths must be UTF-8 sorted and unique",
        )
    return tuple(result)


def verify_blocker_resolution(
    statement: Any,
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    expected_authority_digest: str,
    signer_verifier: SignerVerifier,
    verification_time: datetime,
) -> VerifiedBlockerResolution:
    """Verify an independent exact-state SSHSIG ``BlockerResolution``."""

    _state_subject(
        state_context,
        expected_subject,
        expected_statuses={"BLOCKED"},
        require_recorded_source=False,
    )
    if state_context.recorded_source_commit is None:
        _fail(
            "blocker_source_missing",
            "stateContext.recordedSourceCommit",
            "BLOCKED state must retain the source commit which entered the blocker",
        )
    root = _repository_root(repo_root)
    blocked_source = _verify_commit(
        root, state_context.recorded_source_commit, "stateContext.recordedSourceCommit"
    )
    resolution_source = _verify_commit(
        root, expected_subject.source_commit, "subject.sourceCommit"
    )
    _require_commit_ancestry(
        root,
        blocked_source,
        resolution_source,
        path="blockerResolution.commitRange",
        strict=False,
    )
    now = _verification_time(verification_time)
    try:
        envelope, raw_body, signature, digest, payload, statement_digest = (
            _validate_envelope(
                statement,
                schema=BLOCKER_RESOLUTION_SCHEMA,
                kind=BLOCKER_RESOLUTION_KIND,
                namespace=BLOCKER_RESOLUTION_NAMESPACE,
                path="blockerResolution",
            )
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    body = _exact(
        raw_body,
        {
            "resolutionId",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "artifactDigestAlgorithm",
            "resolutionArtifacts",
            "reasonCode",
            "reason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "blockerResolution.body",
    )
    try:
        subject = _validate_subject(body["subject"], "blockerResolution.body.subject")
        _validate_expected_subject(
            subject, expected_subject, "blockerResolution.body.subject"
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if body["fromState"] != "BLOCKED" or body["toState"] != "ACTIVE":
        _fail(
            "invalid_blocker_resolution_transition",
            "blockerResolution.body",
            "BlockerResolution must bind BLOCKED->ACTIVE",
        )
    if (
        body["priorStateDigest"] != state_context.state_digest
        or body["priorChainHeadDigest"] != state_context.chain_head_digest
    ):
        _fail(
            "blocker_resolution_replay",
            "blockerResolution.body",
            "resolution targets another state or chain head",
        )
    _digest(body["priorStateDigest"], "blockerResolution.body.priorStateDigest")
    _digest(
        body["priorChainHeadDigest"],
        "blockerResolution.body.priorChainHeadDigest",
    )
    if body["artifactDigestAlgorithm"] != "git-blob-content-sha256-v1":
        _fail(
            "invalid_resolution_digest_algorithm",
            "blockerResolution.body.artifactDigestAlgorithm",
            "exact Git blob content SHA-256 is required",
        )
    artifacts = _resolution_artifacts(body["resolutionArtifacts"])
    for artifact in artifacts:
        observed = sha256_bytes(
            _git_blob(root, resolution_source, artifact.path)
        )
        if observed != artifact.digest:
            _fail(
                "resolution_artifact_digest_mismatch",
                artifact.path,
                "resolution artifact differs from the exact current Git commit",
            )
    reason_code = _identifier(body["reasonCode"], "blockerResolution.body.reasonCode")
    reason = _text(body["reason"], "blockerResolution.body.reason", minimum=8)
    requester_principal, requester_organization = _coi(
        body["conflictOfInterest"], "blockerResolution.body.conflictOfInterest"
    )
    issued_at = _timestamp(body["issuedAt"], "blockerResolution.body.issuedAt")
    valid_until = _timestamp(
        body["validUntil"], "blockerResolution.body.validUntil"
    )
    _validate_human_window(issued_at, valid_until, now, "blockerResolution.body")
    signer = _resolve_exact_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=BLOCKER_RESOLUTION_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_scheme=SSHSIG_SCHEME,
        expected_authority_digest=expected_authority_digest,
        signer_verifier=signer_verifier,
    )
    if (
        signer.principal == requester_principal
        or signer.organization == requester_organization
    ):
        _fail(
            "conflict_of_interest",
            "blockerResolution.body.conflictOfInterest",
            "reviewer must differ from requester principal and organization",
        )
    del envelope
    return _mark_verified(
        VerifiedBlockerResolution(
            attestation_digest=digest,
            statement_digest=statement_digest,
            resolution_id=_identifier(
                body["resolutionId"], "blockerResolution.body.resolutionId"
            ),
            subject=subject,
            from_state="BLOCKED",
            to_state="ACTIVE",
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            artifacts=artifacts,
            reason_code=reason_code,
            reason=reason,
            requester_principal=requester_principal,
            requester_organization=requester_organization,
            issued_at=issued_at,
            valid_until=valid_until,
            signer=signer,
        )
    )


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    path: str,
    maximum: int = MAX_GIT_OUTPUT_BYTES,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> bytes:
    git = shutil.which("git", path="/usr/bin:/bin")
    if git is None:
        _fail("git_verifier_unavailable", path, "fixed Git executable unavailable")
    try:
        completed = subprocess.run(
            [git, "-c", "core.pager=cat", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=30,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("git_verifier_unavailable", path, "bounded local Git operation failed")
    if completed.returncode not in allowed_returncodes:
        _fail("invalid_lifecycle_git_range", path, "local Git operation rejected range")
    if len(completed.stdout) > maximum or len(completed.stderr) > 65536:
        _fail("git_output_too_large", path, "bounded local Git output exceeded")
    return completed.stdout


def _repository_root(value: Path) -> Path:
    if not isinstance(value, Path):
        _fail("invalid_repository", "repoRoot", "repoRoot must be a Path")
    try:
        root = value.resolve(strict=True)
    except OSError:
        _fail("invalid_repository", "repoRoot", "repository path is unavailable")
    observed_raw = _git(root, ["rev-parse", "--show-toplevel"], path="repoRoot", maximum=4096)
    try:
        observed = Path(observed_raw.decode("utf-8", "strict").strip()).resolve(
            strict=True
        )
    except (OSError, UnicodeDecodeError):
        _fail("invalid_repository", "repoRoot", "Git top-level is invalid")
    if observed != root:
        _fail("invalid_repository", "repoRoot", "path must be the Git top-level")
    return root


def _verify_commit(root: Path, commit: str, path: str) -> str:
    expected = _commit(commit, path)
    observed = _git(
        root,
        ["rev-parse", "--verify", f"{expected}^{{commit}}"],
        path=path,
        maximum=128,
    ).decode("ascii", "strict").strip()
    if observed != expected:
        _fail("invalid_lifecycle_commit", path, "commit does not resolve exactly")
    return expected


def _require_commit_ancestry(
    root: Path,
    base_commit: str,
    head_commit: str,
    *,
    path: str,
    strict: bool,
) -> None:
    merge_base = _git(
        root,
        ["merge-base", base_commit, head_commit],
        path=path,
        maximum=128,
    ).decode("ascii", "strict").strip()
    if merge_base != base_commit or (strict and base_commit == head_commit):
        qualifier = "strict " if strict else ""
        _fail(
            "invalid_lifecycle_git_range",
            path,
            f"base must be a {qualifier}ancestor of head",
        )


def _git_blob(root: Path, commit: str, component_path: str) -> bytes:
    safe = _repo_path(component_path, "approvedComponentDigests")
    listing = _git(
        root,
        ["ls-tree", "-z", commit, "--", safe],
        path=safe,
        maximum=8192,
    )
    entries = listing.rstrip(b"\x00").split(b"\x00") if listing else []
    if len(entries) != 1:
        _fail("approved_component_unavailable", safe, "one exact Git blob required")
    metadata, separator, raw_path = entries[0].partition(b"\t")
    fields = metadata.split(b" ")
    try:
        observed_path = raw_path.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("unsafe_lifecycle_path", safe, "component path is not UTF-8")
    if (
        not separator
        or observed_path != safe
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        _fail("unsafe_component_type", safe, "regular Git blob required")
    size_raw = _git(
        root,
        ["cat-file", "-s", f"{commit}:{safe}"],
        path=safe,
        maximum=128,
    )
    try:
        size = int(size_raw.strip())
    except ValueError:
        _fail("approved_component_unavailable", safe, "invalid Git blob size")
    if not 0 <= size <= MAX_COMPONENT_BYTES:
        _fail("approved_component_too_large", safe, "Git blob exceeds bound")
    blob = _git(
        root,
        ["show", f"{commit}:{safe}"],
        path=safe,
        maximum=MAX_COMPONENT_BYTES,
    )
    if len(blob) != size:
        _fail("approved_component_unavailable", safe, "Git blob size drift")
    return blob


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_lifecycle_json_key", key, "duplicate JSON key")
        result[key] = value
    return result


def _strict_json(raw: bytes, path: str) -> Any:
    if len(raw) > MAX_COMPONENT_BYTES or b"\x00" in raw:
        _fail("invalid_lifecycle_json", path, "invalid bounded JSON input")
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_json_pairs,
            parse_constant=lambda _value: _fail(
                "invalid_lifecycle_json", path, "non-finite JSON number"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("invalid_lifecycle_json", path, "strict JSON-compatible YAML required")


def _component_digest(raw: bytes, kind: str, path: str) -> str:
    if kind in JSON_COMPONENT_KINDS:
        return sha256_bytes(
            canonical_json_bytes(
                normalize_control_plane_references(_strict_json(raw, path))
            )
        )
    if kind in TEXT_COMPONENT_KINDS:
        if b"\x00" in raw:
            _fail("binary_control_component", path, "text component contains NUL")
        return sha256_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    _fail("unsupported_component_kind", path, f"unsupported component kind {kind!r}")


def _component_map(value: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= MAX_COMPONENTS:
        _fail(
            "invalid_component_map",
            "approvedComponentDigests",
            "non-empty bounded approved component map required",
        )
    items: list[tuple[str, str]] = []
    for raw_path, raw_digest in value.items():
        path = _repo_path(raw_path, "approvedComponentDigests")
        items.append((path, _digest(raw_digest, f"approvedComponentDigests.{path}")))
    normalized = tuple(sorted(items, key=lambda item: item[0].encode("utf-8")))
    if len({path for path, _digest_value in normalized}) != len(normalized):
        _fail("invalid_component_map", "approvedComponentDigests", "duplicate path")
    return normalized


def _manifest_entries(raw: bytes) -> dict[str, str]:
    value = _strict_json(raw, CONTROL_INPUT_MANIFEST)
    if not isinstance(value, Mapping):
        _fail("invalid_component_manifest", CONTROL_INPUT_MANIFEST, "object required")
    inputs = value.get("inputs")
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= MAX_COMPONENTS:
        _fail(
            "invalid_component_manifest",
            f"{CONTROL_INPUT_MANIFEST}.inputs",
            "non-empty bounded inputs required",
        )
    kinds: dict[str, str] = {}
    order: list[str] = []
    for index, candidate in enumerate(inputs):
        path = f"{CONTROL_INPUT_MANIFEST}.inputs[{index}]"
        body = _exact(candidate, {"path", "kind", "required"}, path)
        if body["required"] is not True:
            _fail("invalid_component_manifest", f"{path}.required", "required=true")
        component_path = _repo_path(body["path"], f"{path}.path")
        kind = _text(body["kind"], f"{path}.kind", maximum=64)
        if component_path in kinds:
            _fail("invalid_component_manifest", path, "duplicate component path")
        kinds[component_path] = kind
        order.append(component_path)
    if order != sorted(order, key=lambda item: item.encode("utf-8")):
        _fail("invalid_component_manifest", f"{CONTROL_INPUT_MANIFEST}.inputs", "paths not sorted")
    if CONTROL_INPUT_MANIFEST not in kinds:
        _fail(
            "component_manifest_missing",
            f"{CONTROL_INPUT_MANIFEST}.inputs",
            "control-plane input manifest must cover its own exact blob",
        )
    return kinds


def _manifest_kinds(raw: bytes, expected_paths: tuple[str, ...]) -> dict[str, str]:
    kinds = _manifest_entries(raw)
    if tuple(kinds) != expected_paths:
        _fail(
            "component_map_manifest_mismatch",
            "approvedComponentDigests",
            "approved component map differs from the pinned manifest",
        )
    return kinds


def _control_plane_at_commit(
    root: Path, commit: str
) -> tuple[str, dict[str, str], dict[str, str]]:
    manifest_raw = _git_blob(root, commit, CONTROL_INPUT_MANIFEST)
    kinds = _manifest_entries(manifest_raw)
    components = {
        path: _component_digest(_git_blob(root, commit, path), kind, path)
        for path, kind in kinds.items()
    }
    return _aggregate_components(components), components, kinds


def _approved_components_at_base(
    root: Path,
    base_commit: str,
    approved: tuple[tuple[str, str], ...],
) -> tuple[dict[str, str], dict[str, str]]:
    approved_map = dict(approved)
    if CONTROL_INPUT_MANIFEST not in approved_map:
        _fail(
            "component_manifest_missing",
            "approvedComponentDigests",
            "approved component map must contain its own input manifest",
        )
    manifest_raw = _git_blob(root, base_commit, CONTROL_INPUT_MANIFEST)
    kinds = _manifest_kinds(manifest_raw, tuple(path for path, _digest_value in approved))
    observed: dict[str, str] = {}
    for path, expected_digest in approved:
        actual = _component_digest(_git_blob(root, base_commit, path), kinds[path], path)
        if actual != expected_digest:
            _fail(
                "approved_component_digest_mismatch",
                path,
                "base commit does not match the approved component map",
            )
        observed[path] = actual
    return kinds, observed


def _head_components(
    root: Path,
    head_commit: str,
    approved: tuple[tuple[str, str], ...],
    kinds: Mapping[str, str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    result: dict[str, str] = {}
    invalid: list[str] = []
    for path, _expected in approved:
        try:
            result[path] = _component_digest(
                _git_blob(root, head_commit, path), kinds[path], path
            )
        except LifecycleEvidenceError as exc:
            if exc.code not in {
                "approved_component_unavailable",
                "unsafe_component_type",
                "approved_component_too_large",
                "invalid_lifecycle_json",
                "duplicate_lifecycle_json_key",
                "binary_control_component",
            }:
                raise
            invalid.append(path)
    return result, tuple(invalid)


def _aggregate_components(components: Mapping[str, str]) -> str:
    records = [
        {"path": path, "digest": digest}
        for path, digest in sorted(
            components.items(), key=lambda item: item[0].encode("utf-8")
        )
    ]
    return sha256_bytes(canonical_json_bytes(records))


def _changed_paths(root: Path, base_commit: str, head_commit: str) -> tuple[str, ...]:
    _require_commit_ancestry(
        root, base_commit, head_commit, path="commitRange", strict=True
    )
    raw = _git(
        root,
        ["diff", "--name-only", "-z", "--no-renames", base_commit, head_commit, "--"],
        path="commitRange",
    )
    entries = raw.rstrip(b"\x00").split(b"\x00") if raw else []
    if not entries or len(entries) > MAX_CHANGED_PATHS:
        _fail(
            "invalid_changed_path_set",
            "commitRange",
            "strict commit range must contain a non-empty bounded path set",
        )
    paths: list[str] = []
    for index, encoded in enumerate(entries):
        try:
            candidate = encoded.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _fail("unsafe_lifecycle_path", f"changedPaths[{index}]", "path is not UTF-8")
        paths.append(_repo_path(candidate, f"changedPaths[{index}]"))
    normalized = tuple(sorted(set(paths), key=lambda item: item.encode("utf-8")))
    if len(normalized) != len(paths):
        _fail("invalid_changed_path_set", "commitRange", "duplicate changed path")
    return normalized


def _impact_projection(
    raw: bytes,
    *,
    expected_control_plane_digest: str,
    expected_status: str,
    changed_paths: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    value = _strict_json(raw, IMPACT_MAP_PATH)
    body = _exact(
        value,
        {
            "schemaVersion",
            "kind",
            "mapStatus",
            "controlPlaneDigest",
            "defaultImpact",
            "stateEffects",
            "mappings",
            "spellingOnlyPolicy",
        },
        IMPACT_MAP_PATH,
    )
    if (
        body["schemaVersion"] != "urn:agentapi-doctor:impact-map:v1"
        or body["kind"] != "ImpactMapCandidate"
        or body["controlPlaneDigest"] != expected_control_plane_digest
    ):
        _fail("invalid_impact_map", IMPACT_MAP_PATH, "approved impact-map binding differs")
    if body["defaultImpact"] != "manual-review-required":
        _fail("invalid_impact_map", f"{IMPACT_MAP_PATH}.defaultImpact", "unsafe default")
    state_effects = body["stateEffects"]
    if not isinstance(state_effects, Mapping) or state_effects.get(expected_status) != INVALIDATION_TARGETS[expected_status]:
        _fail(
            "invalid_impact_state_effect",
            f"{IMPACT_MAP_PATH}.stateEffects",
            "impact map weakens the normative state transition",
        )
    mappings = body["mappings"]
    if not isinstance(mappings, list) or not mappings:
        _fail("invalid_impact_map", f"{IMPACT_MAP_PATH}.mappings", "mappings required")
    matched: set[str] = set()
    affected: set[str] = set()
    covered: set[str] = set()
    seen_ids: set[str] = set()
    for index, candidate in enumerate(mappings):
        path = f"{IMPACT_MAP_PATH}.mappings[{index}]"
        mapping = _exact(candidate, {"id", "paths", "affected", "reason"}, path)
        mapping_id = _identifier(mapping["id"], f"{path}.id")
        if mapping_id in seen_ids:
            _fail("invalid_impact_map", f"{path}.id", "duplicate mapping ID")
        seen_ids.add(mapping_id)
        patterns_raw = mapping["paths"]
        affected_raw = mapping["affected"]
        if not isinstance(patterns_raw, list) or not patterns_raw:
            _fail("invalid_impact_map", f"{path}.paths", "path patterns required")
        if not isinstance(affected_raw, list) or not affected_raw:
            _fail("invalid_impact_map", f"{path}.affected", "affected units required")
        patterns = tuple(
            _repo_path(item, f"{path}.paths[{position}]", pattern=True)
            for position, item in enumerate(patterns_raw)
        )
        targets = tuple(
            _identifier(item, f"{path}.affected[{position}]")
            for position, item in enumerate(affected_raw)
        )
        _text(mapping["reason"], f"{path}.reason", minimum=8)
        matching = {
            changed
            for changed in changed_paths
            if any(fnmatchcase(changed, pattern) for pattern in patterns)
        }
        if matching:
            matched.add(mapping_id)
            covered.update(matching)
            affected.update(targets)
    uncovered = sorted(set(changed_paths) - covered)
    if uncovered:
        _fail(
            "unmapped_impact_requires_review",
            "changedPaths",
            "approved impact map requires human review for at least one changed path",
        )
    return (
        tuple(sorted(matched)),
        tuple(sorted(affected)),
        INVALIDATION_TARGETS[expected_status],
    )


def compute_invalidation_projection(
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    base_commit: str,
    head_commit: str,
    approved_component_digests: Mapping[str, str],
    expected_impact_map_digest: str,
) -> InvalidationComputation:
    """Derive invalidation solely from approved inputs and exact Git commits."""

    _state_subject(
        state_context,
        expected_subject,
        expected_statuses=set(INVALIDATION_TARGETS),
        require_recorded_source=False,
    )
    if state_context.status == "NOT_STARTED":
        _fail(
            "ambiguous_invalidation_target",
            "stateContext.status",
            "NOT_STARTED requires an explicit supersession or replacement approval",
        )
    root = _repository_root(repo_root)
    base = _verify_commit(root, base_commit, "baseCommit")
    head = _verify_commit(root, head_commit, "headCommit")
    if state_context.recorded_source_commit != base:
        _fail(
            "invalidation_base_mismatch",
            "baseCommit",
            "base commit differs from the source recorded in exact current state",
        )
    changed_paths = _changed_paths(root, base, head)
    approved = _component_map(approved_component_digests)
    approved_map = dict(approved)
    impact_digest = _digest(expected_impact_map_digest, "expectedImpactMapDigest")
    if approved_map.get(IMPACT_MAP_PATH) != impact_digest:
        _fail(
            "impact_map_digest_mismatch",
            "expectedImpactMapDigest",
            "impact-map pin differs from the approved component map",
        )
    kinds, base_components = _approved_components_at_base(root, base, approved)
    approved_aggregate = _aggregate_components(base_components)
    if approved_aggregate != state_context.control_plane_digest:
        _fail(
            "approved_control_plane_digest_mismatch",
            "approvedComponentDigests",
            "approved component map does not aggregate to exact current control plane",
        )
    impact_raw = _git_blob(root, base, IMPACT_MAP_PATH)
    if _component_digest(impact_raw, kinds[IMPACT_MAP_PATH], IMPACT_MAP_PATH) != impact_digest:
        _fail("impact_map_digest_mismatch", IMPACT_MAP_PATH, "base impact-map digest differs")
    matched, affected, to_state = _impact_projection(
        impact_raw,
        expected_control_plane_digest=state_context.control_plane_digest,
        expected_status=state_context.status,
        changed_paths=changed_paths,
    )
    if state_context.work_unit not in affected:
        _fail(
            "invalidation_target_not_affected",
            "affectedUnits",
            "approved impact map does not affect the requested work unit",
        )
    head_components, invalid_components = _head_components(root, head, approved, kinds)
    changed_components = tuple(
        path
        for path, expected_digest in approved
        if path in invalid_components or head_components.get(path) != expected_digest
    )
    head_aggregate = (
        None if invalid_components else _aggregate_components(head_components)
    )
    control_drift = bool(changed_components) or head_aggregate != approved_aggregate
    kind = "CONTROL" if control_drift else "IMPACT"
    authority_mode = (
        "APPROVED_BASE_REVISION_CHECK"
        if control_drift
        else "STANDARD_APPROVED_HEAD"
    )
    required_authority_source = base if control_drift else head
    if expected_subject.source_commit != required_authority_source:
        _fail(
            "invalidation_authority_source_mismatch",
            "subject.sourceCommit",
            (
                "CONTROL invalidation requires a dedicated authority executing the "
                "approved base revision"
                if control_drift
                else "IMPACT invalidation requires the standard authority at candidate head"
            ),
        )
    reason_code = (
        "approved-control-plane-drift"
        if control_drift
        else "approved-impact-map-change"
    )
    reason = (
        f"Protected workflow derived {len(changed_paths)} changed path(s), "
        f"{len(affected)} affected target(s), and {kind} invalidation from exact Git commits."
    )
    return InvalidationComputation(
        subject=expected_subject,
        from_state=state_context.status,
        to_state=to_state,
        prior_state_digest=state_context.state_digest,
        prior_chain_head_digest=state_context.chain_head_digest,
        base_commit=base,
        head_commit=head,
        impact_map_digest=impact_digest,
        approved_component_map_digest=approved_aggregate,
        changed_paths=changed_paths,
        matched_mappings=matched,
        affected_units=affected,
        invalidation_kind=kind,
        authority_mode=authority_mode,
        control_drift_detected=control_drift,
        changed_components=changed_components,
        invalid_components=invalid_components,
        approved_control_plane_digest=approved_aggregate,
        head_control_plane_digest=head_aggregate,
        reason_code=reason_code,
        reason=reason,
    )


def invalidation_body(
    computation: InvalidationComputation,
    *,
    invalidation_id: str,
    issued_at: datetime,
    actor: Mapping[str, str],
    authority_digest: str,
) -> dict[str, Any]:
    """Render the exact unsigned body a protected workflow must OIDC-sign."""

    if not isinstance(computation, InvalidationComputation):
        _fail("invalid_invalidation_computation", "computation", "typed computation required")
    issued = _verification_time(issued_at).strftime("%Y-%m-%dT%H:%M:%SZ")
    actor_body = _exact(actor, {"principal", "role", "organization"}, "actor")
    return {
        "invalidationId": _identifier(invalidation_id, "invalidationId"),
        "subject": _subject_document(computation.subject),
        "fromState": computation.from_state,
        "toState": computation.to_state,
        "priorStateDigest": computation.prior_state_digest,
        "priorChainHeadDigest": computation.prior_chain_head_digest,
        "baseCommit": computation.base_commit,
        "headCommit": computation.head_commit,
        "impactMapDigest": computation.impact_map_digest,
        "approvedComponentMapDigest": computation.approved_component_map_digest,
        "changedPaths": list(computation.changed_paths),
        "matchedMappings": list(computation.matched_mappings),
        "affectedUnits": list(computation.affected_units),
        "invalidationKind": computation.invalidation_kind,
        "authorityMode": computation.authority_mode,
        "controlDrift": {
            "detected": computation.control_drift_detected,
            "changedComponents": list(computation.changed_components),
            "invalidComponents": list(computation.invalid_components),
            "approvedControlPlaneDigest": computation.approved_control_plane_digest,
            "headControlPlaneDigest": computation.head_control_plane_digest,
        },
        "reasonCode": computation.reason_code,
        "reason": computation.reason,
        "issuedAt": issued,
        "actor": dict(actor_body),
        "authorityDigest": _digest(authority_digest, "authorityDigest"),
    }


def verify_invalidation_evidence(
    statement: Any,
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    base_commit: str,
    head_commit: str,
    approved_component_digests: Mapping[str, str],
    expected_impact_map_digest: str,
    expected_authority_digest: str,
    signer_verifier: SignerVerifier,
    verification_time: datetime,
) -> VerifiedInvalidationEvidence:
    """Recompute and verify one protected OIDC invalidation statement."""

    computation = compute_invalidation_projection(
        repo_root=repo_root,
        state_context=state_context,
        expected_subject=expected_subject,
        base_commit=base_commit,
        head_commit=head_commit,
        approved_component_digests=approved_component_digests,
        expected_impact_map_digest=expected_impact_map_digest,
    )
    now = _verification_time(verification_time)
    try:
        envelope, raw_body, signature, digest, payload, statement_digest = (
            _validate_envelope(
                statement,
                schema=INVALIDATION_SCHEMA,
                kind=INVALIDATION_KIND,
                namespace=INVALIDATION_NAMESPACE,
                path="invalidationEvidence",
            )
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    body = _exact(
        raw_body,
        {
            "invalidationId",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "baseCommit",
            "headCommit",
            "impactMapDigest",
            "approvedComponentMapDigest",
            "changedPaths",
            "matchedMappings",
            "affectedUnits",
            "invalidationKind",
            "authorityMode",
            "controlDrift",
            "reasonCode",
            "reason",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "invalidationEvidence.body",
    )
    expected_body = invalidation_body(
        computation,
        invalidation_id=_identifier(
            body["invalidationId"], "invalidationEvidence.body.invalidationId"
        ),
        issued_at=_timestamp(body["issuedAt"], "invalidationEvidence.body.issuedAt"),
        actor=_exact(body["actor"], {"principal", "role", "organization"}, "invalidationEvidence.body.actor"),
        authority_digest=expected_authority_digest,
    )
    if body != expected_body:
        _fail(
            "invalidation_projection_mismatch",
            "invalidationEvidence.body",
            "signed invalidation differs from mechanical Git/impact/control projection",
        )
    issued_at = _timestamp(body["issuedAt"], "invalidationEvidence.body.issuedAt")
    if issued_at > now or now - issued_at > MAX_INVALIDATION_AGE:
        _fail(
            "stale_invalidation_evidence",
            "invalidationEvidence.body.issuedAt",
            "protected invalidation is future-dated or older than 24 hours",
        )
    signer = _resolve_exact_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=INVALIDATION_NAMESPACE,
        body=body,
        subject=expected_subject,
        expected_role="protected-workflow",
        expected_scheme=OIDC_SCHEME,
        expected_authority_digest=expected_authority_digest,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedInvalidationEvidence(
            attestation_digest=digest,
            statement_digest=statement_digest,
            invalidation_id=body["invalidationId"],
            subject=computation.subject,
            from_state=computation.from_state,
            to_state=computation.to_state,
            prior_state_digest=computation.prior_state_digest,
            prior_chain_head_digest=computation.prior_chain_head_digest,
            base_commit=computation.base_commit,
            head_commit=computation.head_commit,
            impact_map_digest=computation.impact_map_digest,
            approved_component_map_digest=computation.approved_component_map_digest,
            changed_paths=computation.changed_paths,
            matched_mappings=computation.matched_mappings,
            affected_units=computation.affected_units,
            invalidation_kind=computation.invalidation_kind,
            authority_mode=computation.authority_mode,
            control_drift_detected=computation.control_drift_detected,
            changed_components=computation.changed_components,
            invalid_components=computation.invalid_components,
            approved_control_plane_digest=computation.approved_control_plane_digest,
            head_control_plane_digest=computation.head_control_plane_digest,
            reason_code=computation.reason_code,
            reason=computation.reason,
            issued_at=issued_at,
            signer=signer,
        )
    )


def _decision(value: Any) -> SupersessionDecision:
    body = _exact(value, {"kind", "decisionId", "path", "digest"}, "supersessionApproval.body.decision")
    kind = body["kind"]
    if kind not in {"PLAN", "RFC"}:
        _fail("invalid_supersession_decision", "supersessionApproval.body.decision.kind", "PLAN or RFC required")
    path = _repo_path(body["path"], "supersessionApproval.body.decision.path")
    if (kind == "PLAN" and path != "agentapi-doctor-Plan.md") or (
        kind == "RFC" and RFC_PATH_RE.fullmatch(path) is None
    ):
        _fail(
            "invalid_supersession_decision",
            "supersessionApproval.body.decision.path",
            "decision path does not match its declared Plan/RFC kind",
        )
    return SupersessionDecision(
        kind=kind,
        decision_id=_identifier(body["decisionId"], "supersessionApproval.body.decision.decisionId"),
        path=path,
        digest=_digest(body["digest"], "supersessionApproval.body.decision.digest"),
    )


def verify_supersession_approval(
    statement: Any,
    *,
    repo_root: Path,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    expected_authority_digest: str,
    signer_verifier: SignerVerifier,
    verification_time: datetime,
) -> VerifiedSupersessionApproval:
    """Verify explicit independent SSHSIG approval of a Plan/RFC replacement."""

    _state_subject(
        state_context,
        expected_subject,
        expected_statuses={"ACTIVE", "BLOCKED"},
        require_recorded_source=True,
    )
    root = _repository_root(repo_root)
    old_commit = _verify_commit(root, expected_subject.source_commit, "subject.sourceCommit")
    now = _verification_time(verification_time)
    try:
        envelope, raw_body, signature, digest, payload, statement_digest = (
            _validate_envelope(
                statement,
                schema=SUPERSESSION_SCHEMA,
                kind=SUPERSESSION_KIND,
                namespace=SUPERSESSION_NAMESPACE,
                path="supersessionApproval",
            )
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    body = _exact(
        raw_body,
        {
            "approvalId",
            "subject",
            "replacementSubject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "decision",
            "reasonCode",
            "reason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "supersessionApproval.body",
    )
    try:
        subject = _validate_subject(body["subject"], "supersessionApproval.body.subject")
        _validate_expected_subject(subject, expected_subject, "supersessionApproval.body.subject")
        replacement = _validate_subject(
            body["replacementSubject"], "supersessionApproval.body.replacementSubject"
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if (
        replacement.phase != subject.phase
        or replacement.work_unit != subject.work_unit
        or replacement == subject
    ):
        _fail(
            "invalid_supersession_replacement",
            "supersessionApproval.body.replacementSubject",
            "replacement must be a distinct revision of the same work unit",
        )
    replacement_commit = _verify_commit(
        root,
        replacement.source_commit,
        "supersessionApproval.body.replacementSubject.sourceCommit",
    )
    _require_commit_ancestry(
        root,
        old_commit,
        replacement_commit,
        path="supersessionApproval.commitRange",
        strict=True,
    )
    if body["fromState"] != state_context.status or body["toState"] != "SUPERSEDED":
        _fail(
            "invalid_supersession_transition",
            "supersessionApproval.body",
            "approval must bind exact current state to SUPERSEDED",
        )
    if (
        body["priorStateDigest"] != state_context.state_digest
        or body["priorChainHeadDigest"] != state_context.chain_head_digest
    ):
        _fail(
            "supersession_replay",
            "supersessionApproval.body",
            "approval targets another state or chain head",
        )
    _digest(body["priorStateDigest"], "supersessionApproval.body.priorStateDigest")
    _digest(body["priorChainHeadDigest"], "supersessionApproval.body.priorChainHeadDigest")
    decision = _decision(body["decision"])
    replacement_control, replacement_components, _replacement_kinds = (
        _control_plane_at_commit(root, replacement_commit)
    )
    if replacement_control != replacement.control_plane_digest:
        _fail(
            "replacement_control_plane_digest_mismatch",
            "supersessionApproval.body.replacementSubject.controlPlaneDigest",
            "replacement commit does not match its complete control-plane digest",
        )
    contract_path = f"execution/work-units/{replacement.work_unit}.yaml"
    if replacement_components.get(contract_path) != replacement.contract_digest:
        _fail(
            "replacement_contract_digest_mismatch",
            "supersessionApproval.body.replacementSubject.contractDigest",
            "replacement contract is not the exact pinned Git component",
        )
    if replacement_components.get(decision.path) != decision.digest:
        _fail(
            "supersession_decision_digest_mismatch",
            "supersessionApproval.body.decision.digest",
            "Plan/RFC decision is not the exact pinned replacement Git component",
        )
    if body["reasonCode"] != "plan-rfc-explicit-supersession":
        _fail(
            "invalid_supersession_reason",
            "supersessionApproval.body.reasonCode",
            "explicit Plan/RFC supersession reason code required",
        )
    reason = _text(body["reason"], "supersessionApproval.body.reason", minimum=8)
    requester_principal, requester_organization = _coi(
        body["conflictOfInterest"], "supersessionApproval.body.conflictOfInterest"
    )
    issued_at = _timestamp(body["issuedAt"], "supersessionApproval.body.issuedAt")
    valid_until = _timestamp(body["validUntil"], "supersessionApproval.body.validUntil")
    _validate_human_window(issued_at, valid_until, now, "supersessionApproval.body")
    signer = _resolve_exact_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=SUPERSESSION_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_scheme=SSHSIG_SCHEME,
        expected_authority_digest=expected_authority_digest,
        signer_verifier=signer_verifier,
    )
    if signer.principal == requester_principal or signer.organization == requester_organization:
        _fail(
            "conflict_of_interest",
            "supersessionApproval.body.conflictOfInterest",
            "reviewer must differ from requester principal and organization",
        )
    del envelope
    return _mark_verified(
        VerifiedSupersessionApproval(
            attestation_digest=digest,
            statement_digest=statement_digest,
            approval_id=_identifier(body["approvalId"], "supersessionApproval.body.approvalId"),
            subject=subject,
            replacement_subject=replacement,
            from_state=state_context.status,
            to_state="SUPERSEDED",
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            decision=decision,
            reason_code="plan-rfc-explicit-supersession",
            reason=reason,
            requester_principal=requester_principal,
            requester_organization=requester_organization,
            issued_at=issued_at,
            valid_until=valid_until,
            signer=signer,
        )
    )


def evidence_document_digest(statement: Mapping[str, Any]) -> str:
    """Return the exact outer evidence digest (for artifact naming only)."""

    return document_digest(statement, omit_field="attestationDigest")
