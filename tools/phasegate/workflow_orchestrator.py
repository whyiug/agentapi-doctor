"""Protected R3 raw-chain replay and append orchestration.

The lower-level protected verifiers deliberately return identity-sealed,
process-local objects.  This module is the workflow entry boundary that starts
with transport bytes on every invocation.  It re-reads the approved bootstrap
request and trust material from an externally pinned Git commit, re-verifies
the raw bootstrap approval and Genesis event, imports every raw authorization
bundle into fresh seals, and incrementally replays the corresponding OIDC
StateEvent.

Only an exact bootstrap request commit and an exact chain-head digest are
accepted as external trust pins.  Caller-authored control-plane digests,
component maps, contracts, protected-input registries, criteria, and state
views are intentionally not accepted by this API.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping, NoReturn

from .chain_artifact import (
    ChainArtifactError,
    ParsedChainArtifact,
    encode_chain_artifact,
    parse_chain_artifact,
)
from .control_context import (
    ControlContextError,
    derive_phase_control_context,
    derive_work_unit_control_context,
)
from .evidence_index import (
    EvidenceIndexError,
    VerifiedMachineEvidenceRecord,
    VerifiedProtectedChainReplay,
    machine_index_digest,
    require_verified_protected_chain_replay as _require_evidence_replay,
    seal_verified_protected_chain_replay,
    state_view,
    verified_machine_evidence_index as _verified_evidence_index,
)
from .oidc import OidcVerificationError, jwks_snapshot_digest
from .oidc_provenance import (
    OidcProvenanceError,
    build_oidc_provenance_verifier,
)
from .phase_bundle import (
    OP_PHASE_TRANSITION,
    PhaseBundleError,
    VerifiedSerializedPhaseAuthorizationBundle,
    require_verified_serialized_phase_bundle,
    verify_serialized_phase_authorization_bundle,
)
from .phase_evidence import (
    PhaseEvidenceError,
    build_p00_phase_aggregate_evidence,
)
from .post_event_writer import PostEventWriterError, create_post_genesis_event
from .protected import ProtectedVerificationError, document_digest
from .protected_v2 import (
    validate_trust_policy_v2,
    verify_control_plane_approval_v2,
)
from .provenance import (
    ACTIVATION_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_NAMESPACE,
    MACHINE_CRITERION_NAMESPACE,
    PHASE_PROOF_NAMESPACE,
)
from .serialized_bundle import (
    OP_ACTIVATION,
    OP_ATTACHMENT,
    OP_CONVERGENCE,
    OP_READINESS,
    SerializedBundleError,
    VerifiedSerializedAuthorizationBundle,
    require_verified_serialized_bundle,
    verify_serialized_authorization_bundle,
)
from .state_chain_v2 import (
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    require_verified_state_context_v2,
    verify_genesis_anchor_v2,
    verify_next_event_v2,
)


REQUEST_PATH = "execution/approval-requests/P00.B00-R3.yaml"
POLICY_PATH = "execution/protected-verifier/trust-policy.yaml"
JWKS_PATH = "execution/protected-verifier/github-actions-oidc-jwks.json"

MAX_GIT_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_GIT_ERROR_BYTES = 4096
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
WORK_UNIT_RE = re.compile(r"^P00\.W(?:0[1-9]|[1-9][0-9])$")

TokenProvider = Callable[[str], str]


@dataclass
class WorkflowOrchestratorError(ValueError):
    """Stable, secret-free protected workflow failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class _BootstrapTrust:
    request: Mapping[str, Any]
    policy: Mapping[str, Any]
    jwks: Mapping[str, Any]
    policy_result: Mapping[str, Any]
    approval_result: Mapping[str, Any]
    candidate_source_commit: str
    control_plane_digest: str
    request_digest: str
    policy_digest: str
    jwks_digest: str


@dataclass(frozen=True)
class _ReplayDetails:
    parsed: ParsedChainArtifact
    replay: VerifiedProtectedChainReplay
    trust: _BootstrapTrust


@dataclass(frozen=True)
class _EventIntent:
    operation: str
    phase: str
    work_unit: str | None
    to_state: str
    workflow_commit: str
    verification_time: datetime


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise WorkflowOrchestratorError(code, path, message)


def _translate(error: Exception) -> NoReturn:
    raise WorkflowOrchestratorError(
        str(getattr(error, "code", "protected_workflow_failed")),
        str(getattr(error, "path", "protectedWorkflow")),
        str(getattr(error, "message", str(error))),
    ) from None


def require_verified_protected_chain_replay(
    value: Any, *, path: str = "chainReplay"
) -> VerifiedProtectedChainReplay:
    """Compatibility wrapper with the orchestrator's stable error type."""

    try:
        return _require_evidence_replay(value, path=path)
    except EvidenceIndexError as exc:
        _translate(exc)


def verified_machine_evidence_index(
    replay: Any,
) -> tuple[VerifiedMachineEvidenceRecord, ...]:
    """Return the identity-sealed index through the orchestration API."""

    try:
        return _verified_evidence_index(replay)
    except EvidenceIndexError as exc:
        _translate(exc)


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_git_commit", path, "expected lowercase 40-hex Git SHA-1")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("invalid_timestamp", path, "UTC timestamp with Z suffix required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("invalid_timestamp", path, "invalid RFC 3339 timestamp")
    normalized = parsed.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_timestamp", path, "second precision required")
    return normalized


def _repo_root(value: Path) -> Path:
    try:
        root = Path(value).resolve(strict=True)
    except (OSError, TypeError):
        _fail("invalid_repository", "repoRoot", "repository is unavailable")
    if not root.is_dir():
        _fail("invalid_repository", "repoRoot", "repository root must be a directory")
    top = _git(root, ["rev-parse", "--show-toplevel"], path="repoRoot", maximum=4096)
    try:
        observed = Path(top.decode("utf-8", "strict").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("invalid_repository", "repoRoot", "Git top-level is invalid")
    if observed != root:
        _fail("invalid_repository", "repoRoot", "path is not the Git top-level")
    return root


def _git(
    root: Path,
    arguments: list[str],
    *,
    path: str,
    maximum: int = MAX_GIT_DOCUMENT_BYTES,
) -> bytes:
    executable = Path("/usr/bin/git")
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        _fail("git_verifier_unavailable", str(executable), "fixed Git is unavailable")
    environment = {
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    try:
        result = subprocess.run(
            [str(executable), "-c", "core.pager=cat", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("git_verifier_unavailable", path, "fixed Git verification failed")
    if result.returncode != 0:
        _fail("git_object_unavailable", path, "required Git object is unavailable")
    if len(result.stdout) > maximum or len(result.stderr) > MAX_GIT_ERROR_BYTES:
        _fail("git_output_too_large", path, "bounded Git output exceeded")
    return result.stdout


def _verify_ancestor(root: Path, *, ancestor: str, descendant: str, path: str) -> None:
    ancestor = _commit(ancestor, f"{path}.ancestor")
    descendant = _commit(descendant, f"{path}.descendant")
    executable = Path("/usr/bin/git")
    environment = {
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    try:
        result = subprocess.run(
            [
                str(executable),
                "-c",
                "core.pager=cat",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ],
            check=False,
            capture_output=True,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("git_verifier_unavailable", path, "Git ancestry verification failed")
    if result.returncode != 0:
        _fail(
            "workflow_commit_not_approved_descendant",
            path,
            "workflow commit is not a descendant of the approved request commit",
        )
    if len(result.stdout) > 4096 or len(result.stderr) > MAX_GIT_ERROR_BYTES:
        _fail("git_output_too_large", path, "bounded ancestry output exceeded")


def _pairs(path: str) -> Callable[[list[tuple[str, Any]]], dict[str, Any]]:
    def load(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_json_key", path, f"duplicate key: {key}")
            result[key] = value
        return result

    return load


def _strict_json(raw: bytes, path: str) -> dict[str, Any]:
    def constant(value: str) -> NoReturn:
        _fail("invalid_json", path, f"non-finite number: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs(path),
            parse_constant=constant,
        )
    except WorkflowOrchestratorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("invalid_json", path, str(exc))
    if not isinstance(value, dict):
        _fail("invalid_json", path, "top-level JSON object required")
    return value


def _git_json(root: Path, commit: str, relative: str) -> dict[str, Any]:
    commit = _commit(commit, "gitCommit")
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        _fail("unsafe_git_path", "gitPath", "safe repository-relative path required")
    listing = _git(
        root,
        ["ls-tree", "-z", commit, "--", relative],
        path=relative,
        maximum=8192,
    )
    entries = listing.rstrip(b"\x00").split(b"\x00") if listing else []
    if len(entries) != 1:
        _fail("git_object_unavailable", relative, "one exact Git blob required")
    metadata, separator, raw_path = entries[0].partition(b"\t")
    fields = metadata.split(b" ")
    try:
        observed_path = raw_path.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("unsafe_git_path", relative, "Git path is not UTF-8")
    if (
        not separator
        or observed_path != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        _fail("unsafe_git_object", relative, "regular Git blob required")
    size_raw = _git(
        root,
        ["cat-file", "-s", f"{commit}:{relative}"],
        path=relative,
        maximum=128,
    )
    try:
        size = int(size_raw.strip())
    except ValueError:
        _fail("git_object_unavailable", relative, "invalid Git blob size")
    if not 0 <= size <= MAX_GIT_DOCUMENT_BYTES:
        _fail("git_output_too_large", relative, "Git blob exceeds bound")
    raw = _git(
        root,
        ["show", f"{commit}:{relative}"],
        path=relative,
    )
    if len(raw) != size:
        _fail("git_object_unavailable", relative, "Git blob size changed")
    return _strict_json(raw, relative)


def _bootstrap_trust(
    *,
    parsed: ParsedChainArtifact,
    repo_root: Path,
    bootstrap_request_commit: str,
) -> _BootstrapTrust:
    request_commit = _commit(bootstrap_request_commit, "bootstrapRequestCommit")
    request = _git_json(repo_root, request_commit, REQUEST_PATH)
    candidate = request.get("candidate")
    if not isinstance(candidate, dict):
        _fail("invalid_bootstrap_request", REQUEST_PATH, "candidate object required")
    candidate_commit = _commit(
        candidate.get("candidateSourceCommit"), f"{REQUEST_PATH}.candidate.candidateSourceCommit"
    )
    control_digest = _digest(
        candidate.get("controlPlaneDigest"), f"{REQUEST_PATH}.candidate.controlPlaneDigest"
    )
    _verify_ancestor(
        repo_root,
        ancestor=candidate_commit,
        descendant=request_commit,
        path="bootstrapRequestCommit",
    )
    policy = _git_json(repo_root, request_commit, POLICY_PATH)
    jwks = _git_json(repo_root, request_commit, JWKS_PATH)
    request_digest = document_digest(request)
    policy_digest = document_digest(policy)
    try:
        snapshot_digest = jwks_snapshot_digest(jwks)
    except OidcVerificationError as exc:
        _translate(exc)
    genesis_body = parsed.genesis_event.get("body")
    if not isinstance(genesis_body, Mapping):
        _fail("invalid_genesis", "chainArtifact.genesisEvent.body", "object required")
    consumed_at = _timestamp(
        genesis_body.get("timestamp"), "chainArtifact.genesisEvent.body.timestamp"
    )
    try:
        approval_result = verify_control_plane_approval_v2(
            request=request,
            approval=parsed.bootstrap_approval,
            policy=policy,
            jwks_snapshot=jwks,
            expected_policy_digest=policy_digest,
            expected_jwks_snapshot_digest=snapshot_digest,
            expected_control_plane_digest=control_digest,
            expected_candidate_source_commit=candidate_commit,
            expected_request_digest=request_digest,
            expected_workflow_execution_commit=request_commit,
            consumption_time=consumed_at,
        )
        policy_result = validate_trust_policy_v2(
            policy,
            jwks_snapshot=jwks,
            expected_policy_digest=policy_digest,
            expected_jwks_snapshot_digest=snapshot_digest,
            expected_control_plane_digest=control_digest,
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    return _BootstrapTrust(
        request=deepcopy(request),
        policy=deepcopy(policy),
        jwks=deepcopy(jwks),
        policy_result=policy_result,
        approval_result=approval_result,
        candidate_source_commit=candidate_commit,
        control_plane_digest=control_digest,
        request_digest=request_digest,
        policy_digest=policy_digest,
        jwks_digest=snapshot_digest,
    )


def _event_intent(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    event: Mapping[str, Any],
) -> _EventIntent:
    """Derive candidates that must later match both bundle and signed event."""

    body = event.get("body")
    if not isinstance(body, Mapping):
        _fail("invalid_post_genesis_event", "event.body", "object required")
    payload = body.get("payload")
    if not isinstance(payload, Mapping):
        _fail("invalid_post_genesis_event", "event.body.payload", "object required")
    workflow_commit = _commit(body.get("sourceCommit"), "event.body.sourceCommit")
    timestamp = _timestamp(body.get("timestamp"), "event.body.timestamp")
    event_type = body.get("eventType")
    phase = payload.get("phase")
    if phase != "P00":
        _fail("unsupported_phase", "event.body.payload.phase", "exact P00 required")
    if event_type == "EvidenceAttachment":
        work_unit = payload.get("workUnit")
        if not isinstance(work_unit, str) or WORK_UNIT_RE.fullmatch(work_unit) is None:
            _fail("unsupported_work_unit", "event.body.payload.workUnit", "P00.Wnn required")
        operation = OP_ATTACHMENT
        unit = (
            current.state_core.get("phases", {})
            .get("P00", {})
            .get("workUnits", {})
            .get(work_unit)
        )
        if not isinstance(unit, Mapping) or not isinstance(unit.get("status"), str):
            _fail("unknown_work_unit", "event.body.payload.workUnit", work_unit)
        to_state = unit["status"]
    elif event_type == "StateTransition":
        transition_type = payload.get("transitionType")
        to_state = payload.get("toState")
        if not isinstance(to_state, str):
            _fail("invalid_post_genesis_event", "event.body.payload.toState", "string required")
        if transition_type == "PHASE_AGGREGATE":
            if "workUnit" in payload:
                _fail(
                    "phase_is_not_work_unit",
                    "event.body.payload.workUnit",
                    "phase aggregate payload must omit workUnit",
                )
            operation = OP_PHASE_TRANSITION
            work_unit = None
        elif transition_type == "CONVERGENCE":
            operation = OP_CONVERGENCE
            work_unit = payload.get("workUnit")
        elif transition_type == "READINESS":
            operation = OP_READINESS
            work_unit = payload.get("workUnit")
        elif transition_type == "ACTIVATION":
            operation = OP_ACTIVATION
            work_unit = payload.get("workUnit")
        else:
            _fail(
                "unsupported_lifecycle_operation",
                "event.body.payload.transitionType",
                "resume, invalidation, and supersession are not supported by this revision",
            )
        if operation != OP_PHASE_TRANSITION and (
            not isinstance(work_unit, str)
            or WORK_UNIT_RE.fullmatch(work_unit) is None
        ):
            _fail(
                "unsupported_work_unit",
                "event.body.payload.workUnit",
                "P00.Wnn required",
            )
    else:
        _fail("invalid_post_genesis_event", "event.body.eventType", "unsupported event kind")
    return _EventIntent(
        operation=operation,
        phase="P00",
        work_unit=work_unit,
        to_state=to_state,
        workflow_commit=workflow_commit,
        verification_time=timestamp,
    )


def _namespace(operation: str) -> str:
    if operation in {OP_CONVERGENCE, OP_ATTACHMENT}:
        return MACHINE_CRITERION_NAMESPACE
    if operation == OP_READINESS:
        return LIFECYCLE_PROOF_NAMESPACE
    if operation == OP_ACTIVATION:
        return ACTIVATION_PROOF_NAMESPACE
    if operation == OP_PHASE_TRANSITION:
        return PHASE_PROOF_NAMESPACE
    _fail("unsupported_operation", "operation", operation)


def _verify_bundle_and_event(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    event: Mapping[str, Any],
    raw_bundle: bytes,
    trust: _BootstrapTrust,
    repo_root: Path,
    bootstrap_request_commit: str,
    phase_replay: VerifiedProtectedChainReplay,
) -> tuple[
    VerifiedStateChainV2,
    VerifiedSerializedAuthorizationBundle | VerifiedSerializedPhaseAuthorizationBundle,
]:
    intent = _event_intent(current, event)
    _verify_ancestor(
        repo_root,
        ancestor=bootstrap_request_commit,
        descendant=intent.workflow_commit,
        path="event.body.sourceCommit",
    )
    try:
        authority = build_oidc_provenance_verifier(
            current=current,
            policy_result=trust.policy_result,
            approved_jwks_snapshot=trust.jwks,
            repo_root=repo_root,
            current_source_commit=intent.workflow_commit,
            current_workflow_execution_commit=intent.workflow_commit,
            expected_namespace=_namespace(intent.operation),
        )
        if intent.operation == OP_PHASE_TRANSITION:
            context = derive_phase_control_context(
                current=current,
                oidc_authority=authority,
                repo_root=repo_root,
                phase=intent.phase,
            )
            work_contexts = tuple(
                derive_work_unit_control_context(
                    current=current,
                    oidc_authority=authority,
                    repo_root=repo_root,
                    work_unit=f"P00.W0{index}",
                )
                for index in range(1, 6)
            )
            evidence = build_p00_phase_aggregate_evidence(
                phase_replay,
                phase_context=context,
                work_unit_contexts=work_contexts,
            )
            imported = require_verified_serialized_phase_bundle(
                verify_serialized_phase_authorization_bundle(
                    raw_bundle,
                    replay=phase_replay,
                    policy_result=trust.policy_result,
                    approved_jwks_snapshot=trust.jwks,
                    repo_root=repo_root,
                    current_workflow_execution_commit=intent.workflow_commit,
                    expected_to_state=intent.to_state,
                    control_context=context,
                    aggregate_evidence=evidence,
                    verification_time=intent.verification_time,
                )
            )
        else:
            assert intent.work_unit is not None
            context = derive_work_unit_control_context(
                current=current,
                oidc_authority=authority,
                repo_root=repo_root,
                work_unit=intent.work_unit,
            )
            imported = require_verified_serialized_bundle(
                verify_serialized_authorization_bundle(
                    raw_bundle,
                    current=current,
                    policy_result=trust.policy_result,
                    approved_jwks_snapshot=trust.jwks,
                    repo_root=repo_root,
                    current_workflow_execution_commit=intent.workflow_commit,
                    expected_operation=intent.operation,
                    expected_to_state=intent.to_state,
                    control_context=context,
                    verification_time=intent.verification_time,
                )
            )
        next_current = verify_next_event_v2(
            current=current,
            event=event,
            verified_event_input=imported.event_input,
            expected_chain_head_witness_digest=imported.chain_head_witness.attestation_digest,
            policy_result=trust.policy_result,
            approval_result=trust.approval_result,
            jwks_snapshot=trust.jwks,
            repo_root=repo_root,
            approved_component_digests=dict(context.component_digests),
        )
        return next_current, imported
    except (
        ControlContextError,
        OidcProvenanceError,
        PhaseBundleError,
        PhaseEvidenceError,
        ProtectedVerificationError,
        SerializedBundleError,
    ) as exc:
        _translate(exc)


def _replay_snapshot(
    *,
    parsed: ParsedChainArtifact,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    trust: _BootstrapTrust,
    request_commit: str,
    machine_index: tuple[VerifiedMachineEvidenceRecord, ...],
) -> VerifiedProtectedChainReplay:
    sealed = require_verified_state_context_v2(current)
    head_digest = (
        sealed.chain_head_digest
        if isinstance(sealed, VerifiedGenesisAnchorV2)
        else sealed.head_digest
    )
    return seal_verified_protected_chain_replay(
        VerifiedProtectedChainReplay(
            artifact_digest=parsed.artifact_digest,
            bootstrap_request_commit=request_commit,
            candidate_source_commit=trust.candidate_source_commit,
            control_plane_digest=trust.control_plane_digest,
            trust_policy_digest=trust.policy_digest,
            jwks_snapshot_digest=trust.jwks_digest,
            event_count=sealed.event_count,
            head_sequence=sealed.head_sequence,
            head_digest=head_digest,
            head_source_commit=sealed.head_source_commit,
            state_digest=sealed.state_digest,
            machine_evidence_index_digest=machine_index_digest(machine_index),
            machine_evidence_index=machine_index,
            state_view=state_view(sealed),
            current=sealed,
        )
    )


def _replay_details(
    raw_chain: bytes,
    *,
    repo_root: Path,
    expected_bootstrap_request_commit: str,
    expected_chain_head_digest: str,
) -> _ReplayDetails:
    expected_head = _digest(expected_chain_head_digest, "expectedChainHeadDigest")
    request_commit = _commit(
        expected_bootstrap_request_commit, "expectedBootstrapRequestCommit"
    )
    root = _repo_root(repo_root)
    try:
        parsed = parse_chain_artifact(raw_chain)
    except ChainArtifactError as exc:
        _translate(exc)
    if parsed.head_digest != expected_head:
        _fail(
            "chain_head_digest_mismatch",
            "expectedChainHeadDigest",
            "raw artifact is truncated, extended, reordered, or from another chain",
        )
    trust = _bootstrap_trust(
        parsed=parsed,
        repo_root=root,
        bootstrap_request_commit=request_commit,
    )
    try:
        current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2 = verify_genesis_anchor_v2(
            event=parsed.genesis_event,
            policy_result=trust.policy_result,
            approval_result=trust.approval_result,
            jwks_snapshot=trust.jwks,
            expected_control_plane_digest=trust.control_plane_digest,
            expected_chain_head_digest=parsed.genesis_event["eventDigest"],
            contract_digests=trust.approval_result["componentDigests"],
            repo_root=root,
        )
        # Deriving the initial W01 context forces full manifest/component-map
        # recomputation before an otherwise-empty post-Genesis suffix can pass.
        bootstrap_authority = build_oidc_provenance_verifier(
            current=current,
            policy_result=trust.policy_result,
            approved_jwks_snapshot=trust.jwks,
            repo_root=root,
            current_source_commit=request_commit,
            current_workflow_execution_commit=request_commit,
            expected_namespace=MACHINE_CRITERION_NAMESPACE,
        )
        derive_work_unit_control_context(
            current=current,
            oidc_authority=bootstrap_authority,
            repo_root=root,
            work_unit="P00.W01",
        )
    except (ControlContextError, OidcProvenanceError, ProtectedVerificationError) as exc:
        _translate(exc)
    machine_records: list[VerifiedMachineEvidenceRecord] = []
    for entry in parsed.entries:
        phase_replay = _replay_snapshot(
            parsed=parsed,
            current=current,
            trust=trust,
            request_commit=request_commit,
            machine_index=tuple(machine_records),
        )
        current, imported = _verify_bundle_and_event(
            current=current,
            event=entry.event,
            raw_bundle=entry.authorization_bundle,
            trust=trust,
            repo_root=root,
            bootstrap_request_commit=request_commit,
            phase_replay=phase_replay,
        )
        body = entry.event.get("body")
        sequence = body.get("sequence") if isinstance(body, Mapping) else None
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            _fail("invalid_event_sequence", "event.body.sequence", "integer required")
        if not isinstance(imported, VerifiedSerializedAuthorizationBundle):
            # Phase aggregate MACHINE evidence is deliberately not a child
            # work-unit record and therefore cannot feed its own future input.
            continue
        for result in imported.criterion_results:
            if result.criterion.kind != "MACHINE":
                continue
            projections = [
                projection
                for projection in imported.machine_execution_results
                if projection.criterion_id == result.criterion.criterion_id
            ]
            if (
                len(projections) != 1
                or not result.signature_verified
                or not result.criterion_satisfied
                or result.outcome != "PASS"
                or result.run_pair_digest is None
                or imported.freeze is None
            ):
                _fail(
                    "invalid_machine_evidence_index",
                    "authorizationBundle.criterionResults",
                    "only satisfied raw-recomputed MACHINE evidence can be indexed",
                )
            projection = projections[0]
            if (
                projection.run_pair_digest != result.run_pair_digest
                or projection.verifier_authority_digest
                != result.signer.authority_digest
            ):
                _fail(
                    "invalid_machine_evidence_index",
                    "authorizationBundle.machineExecutionResults",
                    "sealed execution projection differs from verified result",
                )
            machine_records.append(
                VerifiedMachineEvidenceRecord(
                    event_sequence=sequence,
                    event_digest=_digest(entry.event.get("eventDigest"), "event.eventDigest"),
                    bundle_digest=imported.bundle_digest,
                    operation=imported.operation,
                    phase=result.subject.phase,
                    work_unit=result.subject.work_unit,
                    source_commit=result.subject.source_commit,
                    control_plane_digest=result.subject.control_plane_digest,
                    contract_digest=result.subject.contract_digest,
                    criterion_id=result.criterion.criterion_id,
                    evaluator=result.criterion.evaluator,
                    evaluator_digest=result.criterion.evaluator_digest,
                    verifier_digest=_digest(
                        projection.verifier_authority_digest,
                        "machineExecutionResult.verifierAuthorityDigest",
                    ),
                    evaluator_dataset_freeze_digest=_digest(
                        projection.evaluator_dataset_freeze_digest,
                        "machineExecutionResult.evaluatorDatasetFreezeDigest",
                    ),
                    dataset_catalog_path=projection.dataset_catalog_path,
                    dataset_slot_digest=_digest(
                        projection.dataset_slot_digest,
                        "machineExecutionResult.datasetSlotDigest",
                    ),
                    dataset_selection_digest=(
                        _digest(
                            projection.dataset_selection_digest,
                            "machineExecutionResult.datasetSelectionDigest",
                        )
                        if projection.dataset_selection_digest is not None
                        else None
                    ),
                    dataset_digest=result.criterion.dataset_digest,
                    freeze_digest=imported.freeze.attestation_digest,
                    result_digest=result.attestation_digest,
                    evidence_digest=result.evidence_digest,
                    verification_pair_id=projection.verification_pair_id,
                    run_pair_digest=projection.run_pair_digest,
                    execution_bundle_digest=projection.execution_bundle_digest,
                    outcome=result.outcome,
                )
            )
    sealed = require_verified_state_context_v2(current)
    head_digest = (
        sealed.chain_head_digest
        if isinstance(sealed, VerifiedGenesisAnchorV2)
        else sealed.head_digest
    )
    if head_digest != expected_head or sealed.event_count != parsed.event_count:
        _fail("chain_replay_mismatch", "chainArtifact", "replay does not match transport head/count")
    replay = _replay_snapshot(
        parsed=parsed,
        current=sealed,
        trust=trust,
        request_commit=request_commit,
        machine_index=tuple(machine_records),
    )
    return _ReplayDetails(parsed=parsed, replay=replay, trust=trust)


def replay_protected_chain(
    raw_chain: bytes,
    *,
    repo_root: Path,
    expected_bootstrap_request_commit: str,
    expected_chain_head_digest: str,
) -> VerifiedProtectedChainReplay:
    """Re-verify and replay one canonical raw protected chain from Genesis."""

    return _replay_details(
        raw_chain,
        repo_root=repo_root,
        expected_bootstrap_request_commit=expected_bootstrap_request_commit,
        expected_chain_head_digest=expected_chain_head_digest,
    ).replay


def append_post_genesis(
    raw_chain: bytes,
    raw_authorization_bundle: bytes,
    *,
    repo_root: Path,
    expected_bootstrap_request_commit: str,
    expected_current_chain_head_digest: str,
    expected_operation: str,
    expected_to_state: str,
    expected_work_unit: str | None,
    expected_phase: str = "P00",
    current_workflow_execution_commit: str,
    statement_timestamp: datetime | str,
    token_provider: TokenProvider,
) -> tuple[bytes, Mapping[str, Any]]:
    """Append one raw-authorized event, then replay the updated artifact fresh."""

    if expected_operation not in {
        OP_CONVERGENCE,
        OP_ATTACHMENT,
        OP_READINESS,
        OP_ACTIVATION,
        OP_PHASE_TRANSITION,
    }:
        _fail("unsupported_operation", "expectedOperation", "operation is not implemented")
    if not isinstance(expected_to_state, str) or not expected_to_state:
        _fail("invalid_expected_state", "expectedToState", "non-empty state required")
    if expected_phase != "P00":
        _fail("unsupported_phase", "expectedPhase", "exact P00 required")
    if expected_operation == OP_PHASE_TRANSITION:
        if expected_work_unit is not None:
            _fail(
                "phase_is_not_work_unit",
                "expectedWorkUnit",
                "phase aggregate append must omit a work unit",
            )
    elif (
        not isinstance(expected_work_unit, str)
        or WORK_UNIT_RE.fullmatch(expected_work_unit) is None
    ):
        _fail("unsupported_work_unit", "expectedWorkUnit", "P00.Wnn required")
    workflow_commit = _commit(
        current_workflow_execution_commit, "currentWorkflowExecutionCommit"
    )
    if not callable(token_provider):
        _fail("invalid_token_provider", "tokenProvider", "callable required")
    if isinstance(statement_timestamp, datetime):
        if statement_timestamp.tzinfo is None or statement_timestamp.microsecond:
            _fail("invalid_timestamp", "statementTimestamp", "aware second-precision timestamp required")
        verification_time = statement_timestamp.astimezone(timezone.utc)
    else:
        verification_time = _timestamp(statement_timestamp, "statementTimestamp")
    details = _replay_details(
        raw_chain,
        repo_root=repo_root,
        expected_bootstrap_request_commit=expected_bootstrap_request_commit,
        expected_chain_head_digest=expected_current_chain_head_digest,
    )
    current = details.replay.current
    _verify_ancestor(
        Path(repo_root).resolve(strict=True),
        ancestor=details.replay.bootstrap_request_commit,
        descendant=workflow_commit,
        path="currentWorkflowExecutionCommit",
    )
    try:
        authority = build_oidc_provenance_verifier(
            current=current,
            policy_result=details.trust.policy_result,
            approved_jwks_snapshot=details.trust.jwks,
            repo_root=repo_root,
            current_source_commit=workflow_commit,
            current_workflow_execution_commit=workflow_commit,
            expected_namespace=_namespace(expected_operation),
        )
        if expected_operation == OP_PHASE_TRANSITION:
            context = derive_phase_control_context(
                current=current,
                oidc_authority=authority,
                repo_root=repo_root,
                phase=expected_phase,
            )
            work_contexts = tuple(
                derive_work_unit_control_context(
                    current=current,
                    oidc_authority=authority,
                    repo_root=repo_root,
                    work_unit=f"P00.W0{index}",
                )
                for index in range(1, 6)
            )
            evidence = build_p00_phase_aggregate_evidence(
                details.replay,
                phase_context=context,
                work_unit_contexts=work_contexts,
            )
            imported = verify_serialized_phase_authorization_bundle(
                raw_authorization_bundle,
                replay=details.replay,
                policy_result=details.trust.policy_result,
                approved_jwks_snapshot=details.trust.jwks,
                repo_root=repo_root,
                current_workflow_execution_commit=workflow_commit,
                expected_to_state=expected_to_state,
                control_context=context,
                aggregate_evidence=evidence,
                verification_time=verification_time,
            )
        else:
            assert expected_work_unit is not None
            context = derive_work_unit_control_context(
                current=current,
                oidc_authority=authority,
                repo_root=repo_root,
                work_unit=expected_work_unit,
            )
            imported = verify_serialized_authorization_bundle(
                raw_authorization_bundle,
                current=current,
                policy_result=details.trust.policy_result,
                approved_jwks_snapshot=details.trust.jwks,
                repo_root=repo_root,
                current_workflow_execution_commit=workflow_commit,
                expected_operation=expected_operation,
                expected_to_state=expected_to_state,
                control_context=context,
                verification_time=verification_time,
            )
        event, next_current = create_post_genesis_event(
            current=current,
            verified_event_input=imported.event_input,
            chain_head_witness=imported.chain_head_witness,
            policy_result=details.trust.policy_result,
            approval_result=details.trust.approval_result,
            approved_jwks_snapshot=details.trust.jwks,
            repo_root=repo_root,
            workflow_execution_commit=workflow_commit,
            statement_timestamp=verification_time,
            token_provider=token_provider,
        )
    except (
        ControlContextError,
        OidcProvenanceError,
        PhaseBundleError,
        PhaseEvidenceError,
        PostEventWriterError,
        ProtectedVerificationError,
        SerializedBundleError,
    ) as exc:
        _translate(exc)
    existing_entries = [
        (entry.event, _strict_json(entry.authorization_bundle, "authorizationBundle"))
        for entry in details.parsed.entries
    ]
    bundle_document = _strict_json(raw_authorization_bundle, "authorizationBundle")
    updated = encode_chain_artifact(
        bootstrap_approval=details.parsed.bootstrap_approval,
        genesis_event=details.parsed.genesis_event,
        entries=(*existing_entries, (event, bundle_document)),
    )
    next_head = event["eventDigest"]
    # post_event_writer already verifies the new raw OIDC event incrementally;
    # the transport encoder self-parses the canonical artifact.  A later
    # workflow invocation still starts with replay_protected_chain, so no
    # process-local seal crosses the artifact boundary.
    parsed_updated = parse_chain_artifact(updated)
    if (
        parsed_updated.head_digest != next_head
        or parsed_updated.event_count != details.replay.event_count + 1
        or next_current.head_digest != next_head
        or next_current.event_count != parsed_updated.event_count
    ):
        _fail("post_append_replay_mismatch", "chainArtifact", "writer and transport heads differ")
    return updated, state_view(next_current)


__all__ = [
    "JWKS_PATH",
    "POLICY_PATH",
    "REQUEST_PATH",
    "VerifiedMachineEvidenceRecord",
    "VerifiedProtectedChainReplay",
    "WorkflowOrchestratorError",
    "append_post_genesis",
    "replay_protected_chain",
    "require_verified_protected_chain_replay",
    "verified_machine_evidence_index",
]
