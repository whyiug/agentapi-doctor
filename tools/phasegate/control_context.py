"""Derive protected P00 freeze inputs from approved repository authority.

This module is the only bridge between the immutable control-plane component
map sealed into Genesis/OIDC authority and the provenance freeze verifier.  It
does not accept caller-authored digest registries or criterion bindings.  Every
digest is recomputed from an exact Git tree, the approved JSON-compatible
manifests, and one identity-sealed observation of the executor binaries.

P00 datasets are deliberately catalog-bound here.  A catalog whose gate
declares ``late_bound_requires_signed_freeze`` is represented first by the
digest of that approved dataset *slot*.  The raw signed-selection importer in
this module must replace that slot with a recomputed record-set digest before
those MACHINE criteria can converge.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, NoReturn, Sequence
import weakref

from .digest import (
    CONTROL_PLANE_PLACEHOLDER,
    canonical_json_bytes,
    normalize_control_plane_references,
    sha256_bytes,
)
from .execution_artifact import (
    TOOL_SCHEMA,
    canonical_toolchain_manifest,
    toolchain_digest,
)
from .delegation import (
    EffectiveReviewerRoster,
    authorize_criterion_signer,
    _require_verified as _require_roster_verified,
)
from .oidc_provenance import (
    OidcProvenanceError,
    OidcProvenanceVerifier,
    _require_verified as _require_oidc_verified,
)
from .protected import ProtectedVerificationError, document_digest
from .provenance import CriterionBinding, PhaseSubject, SubjectBinding
from .state_chain_v2 import (
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    require_verified_state_context_v2,
)
from .sshsig import SshSigVerificationError, verify_sshsig


MANIFEST_PATH = "execution/control-plane-inputs.yaml"
WORKFLOW_CONTRACT_PATH = "execution/protected-verifier/workflow-contract.yaml"
EVALUATOR_CATALOG_PATH = "execution/evaluators/catalog.yaml"
EVIDENCE_SCHEMA_CATALOG_PATH = "execution/evidence-schemas/catalog.yaml"
METRIC_CATALOG_PATH = "execution/metrics/definitions.yaml"
ACCEPTANCE_CATALOG_PATH = "execution/catalogs/p00/acceptance.yaml"
IMPACT_MAP_PATH = "execution/impact-map.yaml"
PLAN_PATH = "agentapi-doctor-Plan.md"

SUPPORT_LOCK_SCHEMA = "urn:agentapi-doctor:p00-executor-support-lock:v1alpha1"
DEPENDENCY_SET_SCHEMA = "urn:agentapi-doctor:p00-executor-dependency-set:v1alpha1"
PREFLIGHT_SCHEMA = "urn:agentapi-doctor:p00-executor-preflight:v1alpha1"
CONTEXT_SCHEMA = "urn:agentapi-doctor:p00-control-context:v1alpha1"
DATASET_SELECTION_SCHEMA = (
    "urn:agentapi-doctor:p00-dataset-freeze-selection:v1alpha1"
)
DATASET_SELECTION_KIND = "P00DatasetFreezeSelection"
DATASET_SELECTION_NAMESPACE = "agentapi-doctor/p00-dataset-freeze-selection/v1"
DATASET_REVIEWER_ROLE = "independent-dataset-reviewer"
DATASET_REVIEWER_CAPABILITY = "freeze-protected-input"

MAX_COMPONENTS = 512
MAX_COMPONENT_BYTES = 4 * 1024 * 1024
MAX_COMPONENT_TOTAL_BYTES = 64 * 1024 * 1024

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
WORK_UNIT_RE = re.compile(r"^P00\.W(0[1-9]|[1-9][0-9])$")

JSON_COMPONENT_KINDS = {
    "json",
    "json-yaml",
    "manifest",
    "contract",
    "catalog",
    "gate",
}
TEXT_COMPONENT_KINDS = {"text"}

EXPECTED_EVALUATOR_STATUS = {
    "MACHINE": "implemented",
    "EXTERNAL": "external-only",
    "TIME": "time-only",
    "HUMAN": "human-only",
}


@dataclass
class ControlContextError(ValueError):
    """Stable fail-closed context derivation error."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class VerifiedExecutorPreflight:
    """Identity-sealed observation used by the real fixed executor."""

    preflight_digest: str
    source_commit: str
    support_lock_digest: str
    dependency_set_digest: str
    toolchain_digest: str
    tool_facts: tuple[tuple[str, str | tuple[str, ...]], ...]


@dataclass(frozen=True)
class VerifiedWorkUnitControlContext:
    """Exact protected inputs and criteria for one P00 work unit."""

    context_digest: str
    subject: SubjectBinding
    contract_approval_digest: str
    impact_map_digest: str
    protected_inputs: tuple[tuple[str, str], ...]
    criteria: tuple[CriterionBinding, ...]
    prerequisite_units: tuple[str, ...]
    component_digests: tuple[tuple[str, str], ...]
    component_set_digest: str
    gate_path: str
    contract_path: str
    late_bound_dataset_criteria: tuple[str, ...]
    dataset_catalog_bindings: tuple[tuple[str, str, str], ...]
    dataset_selection_digests: tuple[str, ...]
    dataset_selection_bindings: tuple[tuple[str, str], ...]
    executor_preflight: VerifiedExecutorPreflight


@dataclass(frozen=True)
class VerifiedPhaseControlContext:
    """Exact protected inputs and criteria for the P00 aggregate."""

    context_digest: str
    subject: PhaseSubject
    aggregate_contract_approval_digest: str
    impact_map_digest: str
    unit_contract_digests: tuple[tuple[str, str], ...]
    protected_inputs: tuple[tuple[str, str], ...]
    criteria: tuple[CriterionBinding, ...]
    component_digests: tuple[tuple[str, str], ...]
    component_set_digest: str
    gate_path: str
    contract_path: str
    late_bound_dataset_criteria: tuple[str, ...]
    dataset_catalog_bindings: tuple[tuple[str, str, str], ...]
    dataset_selection_digests: tuple[str, ...]
    dataset_selection_bindings: tuple[tuple[str, str], ...]
    executor_preflight: VerifiedExecutorPreflight


@dataclass(frozen=True)
class _ApprovedRepository:
    root: Path
    commit: str
    control_plane_digest: str
    components: tuple[tuple[str, str], ...]
    kinds: tuple[tuple[str, str], ...]
    blobs: tuple[tuple[str, bytes], ...]


_VERIFIED_PREFLIGHTS: dict[int, weakref.ReferenceType[Any]] = {}
_VERIFIED_CONTEXTS: dict[int, weakref.ReferenceType[Any]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise ControlContextError(code, path, message)


def _mark(
    registry: dict[int, weakref.ReferenceType[Any]], value: Any
) -> Any:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if registry.get(identity) is reference:
            registry.pop(identity, None)

    registry[identity] = weakref.ref(value, discard)
    return value


def _require_seal(
    registry: dict[int, weakref.ReferenceType[Any]],
    value: Any,
    expected_type: type,
    path: str,
) -> None:
    reference = registry.get(id(value))
    if (
        not isinstance(value, expected_type)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact identity-sealed verifier result",
        )


def require_verified_executor_preflight(
    value: Any, *, path: str = "executorPreflight"
) -> VerifiedExecutorPreflight:
    _require_seal(_VERIFIED_PREFLIGHTS, value, VerifiedExecutorPreflight, path)
    assert isinstance(value, VerifiedExecutorPreflight)
    return value


def require_verified_work_unit_control_context(
    value: Any, *, path: str = "controlContext"
) -> VerifiedWorkUnitControlContext:
    _require_seal(_VERIFIED_CONTEXTS, value, VerifiedWorkUnitControlContext, path)
    assert isinstance(value, VerifiedWorkUnitControlContext)
    require_verified_executor_preflight(value.executor_preflight)
    return value


def require_verified_phase_control_context(
    value: Any, *, path: str = "controlContext"
) -> VerifiedPhaseControlContext:
    _require_seal(_VERIFIED_CONTEXTS, value, VerifiedPhaseControlContext, path)
    assert isinstance(value, VerifiedPhaseControlContext)
    require_verified_executor_preflight(value.executor_preflight)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_source_commit", path, "expected lowercase 40-hex Git SHA-1")
    return value


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_control_schema", path, "field set differs from approved revision")
    return value


def _strict_json(raw: bytes, path: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_control_key", path, f"duplicate key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> NoReturn:
        _fail("invalid_control_json", path, f"non-finite number: {value}")

    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except ControlContextError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("invalid_control_json", path, str(exc))


def _git_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    path: str,
    maximum: int = MAX_COMPONENT_BYTES + 4096,
) -> bytes:
    git = Path("/usr/bin/git")
    if git.is_symlink() or not git.is_file() or not os.access(git, os.X_OK):
        _fail("git_verifier_unavailable", str(git), "fixed Git is unavailable")
    try:
        result = subprocess.run(
            [str(git), "-c", "core.pager=cat", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=20,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("git_verifier_unavailable", path, "fixed Git verification failed")
    if result.returncode != 0:
        _fail("approved_component_unavailable", path, "Git object is unavailable")
    if len(result.stdout) > maximum or len(result.stderr) > 4096:
        _fail("approved_component_too_large", path, "Git output exceeds bound")
    return result.stdout


def _repository_root(repo_root: Path) -> Path:
    try:
        root = Path(repo_root).resolve(strict=True)
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


def _git_blob(root: Path, commit: str, component_path: str) -> bytes:
    if (
        not isinstance(component_path, str)
        or not component_path
        or "\\" in component_path
        or component_path.startswith("/")
        or any(part in {"", ".", ".."} for part in component_path.split("/"))
    ):
        _fail("unsafe_component_path", "componentMap", "unsafe repository path")
    listing = _git(
        root,
        ["ls-tree", "-z", commit, "--", component_path],
        path=component_path,
        maximum=8192,
    )
    entries = listing.rstrip(b"\x00").split(b"\x00") if listing else []
    if len(entries) != 1:
        _fail("approved_component_unavailable", component_path, "one Git blob required")
    metadata, separator, raw_path = entries[0].partition(b"\t")
    fields = metadata.split(b" ")
    try:
        observed_path = raw_path.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("unsafe_component_path", component_path, "path is not UTF-8")
    if (
        not separator
        or observed_path != component_path
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        _fail("unsafe_component_type", component_path, "regular Git blob required")
    size_raw = _git(
        root,
        ["cat-file", "-s", f"{commit}:{component_path}"],
        path=component_path,
        maximum=128,
    )
    try:
        size = int(size_raw.strip())
    except ValueError:
        _fail("approved_component_unavailable", component_path, "invalid blob size")
    if not 0 <= size <= MAX_COMPONENT_BYTES:
        _fail("approved_component_too_large", component_path, "blob exceeds bound")
    blob = _git(
        root,
        ["show", f"{commit}:{component_path}"],
        path=component_path,
        maximum=MAX_COMPONENT_BYTES,
    )
    if len(blob) != size:
        _fail("approved_component_unavailable", component_path, "blob size drift")
    return blob


def _component_digest(raw: bytes, kind: str, path: str) -> str:
    if kind in JSON_COMPONENT_KINDS:
        value = _strict_json(raw, path)
        return sha256_bytes(
            canonical_json_bytes(normalize_control_plane_references(value))
        )
    if kind in TEXT_COMPONENT_KINDS:
        if b"\x00" in raw:
            _fail("binary_control_component", path, "text component contains NUL")
        return sha256_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    _fail("unsupported_component_kind", path, f"unsupported kind: {kind}")


def _manifest_entries(raw: bytes) -> list[dict[str, Any]]:
    manifest = _exact(
        _strict_json(raw, MANIFEST_PATH),
        {
            "schemaVersion",
            "kind",
            "manifestStatus",
            "digestAlgorithm",
            "canonicalization",
            "controlPlaneDigestPlaceholder",
            "normalization",
            "inputs",
            "excluded",
        },
        MANIFEST_PATH,
    )
    if (
        manifest["schemaVersion"] != "urn:agentapi-doctor:control-plane-inputs:v1"
        or manifest["kind"] != "ControlPlaneInputManifestCandidate"
        or manifest["digestAlgorithm"] != "sha256"
        or manifest["canonicalization"] != "bootstrap-canonical-json-v1"
        or manifest["controlPlaneDigestPlaceholder"] != CONTROL_PLANE_PLACEHOLDER
    ):
        _fail("unsupported_control_manifest", MANIFEST_PATH, "manifest semantics drift")
    inputs = manifest["inputs"]
    if not isinstance(inputs, list) or not 0 < len(inputs) <= MAX_COMPONENTS:
        _fail("invalid_control_manifest", f"{MANIFEST_PATH}.inputs", "bounded list required")
    result: list[dict[str, Any]] = []
    for index, value in enumerate(inputs):
        entry = _exact(value, {"path", "kind", "required"}, f"{MANIFEST_PATH}.inputs[{index}]")
        if (
            not isinstance(entry["path"], str)
            or not isinstance(entry["kind"], str)
            or entry["required"] is not True
        ):
            _fail("invalid_control_manifest", f"{MANIFEST_PATH}.inputs[{index}]", "path/kind/required drift")
        result.append(dict(entry))
    paths = [entry["path"] for entry in result]
    if paths != sorted(paths, key=lambda value: value.encode("utf-8")) or len(set(paths)) != len(paths):
        _fail("invalid_control_manifest", f"{MANIFEST_PATH}.inputs", "paths must be sorted and unique")
    return result


def _approved_repository(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    authority: OidcProvenanceVerifier,
    repo_root: Path,
) -> tuple[_ApprovedRepository, VerifiedGenesisAnchorV2 | VerifiedStateChainV2]:
    try:
        sealed = require_verified_state_context_v2(current)
        _require_oidc_verified(authority)
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    except OidcProvenanceError as exc:
        _fail(exc.code, exc.path, exc.message)
    head_digest = (
        sealed.chain_head_digest
        if isinstance(sealed, VerifiedGenesisAnchorV2)
        else sealed.head_digest
    )
    expected_component_set_digest = sha256_bytes(
        canonical_json_bytes(
            {"componentDigests": dict(authority.component_digests)}
        )
    )
    if (
        authority.control_plane_digest != sealed.control_plane_digest
        or authority.policy_digest != sealed.trust_policy_digest
        or authority.jwks_snapshot_digest != sealed.jwks_snapshot_digest
        or authority.approval_digest != sealed.bootstrap_approval_digest
        or authority.bootstrap_request_digest != sealed.bootstrap_request_digest
        or authority.state_digest != sealed.state_digest
        or authority.chain_head_digest != head_digest
        or authority.component_digests != sealed.approved_component_digests
        or authority.component_set_digest != expected_component_set_digest
        or authority.source_commit != authority.workflow_execution_commit
    ):
        _fail("authority_state_mismatch", "oidcAuthority", "OIDC authority differs from replayed state")
    root = _repository_root(repo_root)
    commit = _commit(authority.workflow_execution_commit, "oidcAuthority.workflowExecutionCommit")
    approved = dict(authority.component_digests)
    if len(approved) != len(authority.component_digests):
        _fail("component_map_mismatch", "oidcAuthority.componentDigests", "duplicate component path")
    manifest_raw = _git_blob(root, commit, MANIFEST_PATH)
    entries = _manifest_entries(manifest_raw)
    declared = {entry["path"]: entry["kind"] for entry in entries}
    if set(declared) != set(approved):
        _fail(
            "component_map_mismatch",
            "oidcAuthority.componentDigests",
            "approved map must exactly equal the declared manifest path set",
        )
    blobs: dict[str, bytes] = {}
    recomputed: list[tuple[str, str]] = []
    total = 0
    for entry in entries:
        path = entry["path"]
        raw = manifest_raw if path == MANIFEST_PATH else _git_blob(root, commit, path)
        total += len(raw)
        if total > MAX_COMPONENT_TOTAL_BYTES:
            _fail("component_set_too_large", "componentMap", "component set exceeds bound")
        digest = _component_digest(raw, entry["kind"], path)
        if approved[path] != digest:
            _fail("approved_component_digest_mismatch", path, "approved component differs from exact Git blob")
        blobs[path] = raw
        recomputed.append((path, digest))
    aggregate = sha256_bytes(
        canonical_json_bytes(
            [{"path": path, "digest": digest} for path, digest in recomputed]
        )
    )
    if aggregate != sealed.control_plane_digest or aggregate != authority.control_plane_digest:
        _fail("control_plane_digest_mismatch", "componentMap", "full component aggregate differs from sealed authority")
    return (
        _ApprovedRepository(
            root=root,
            commit=commit,
            control_plane_digest=aggregate,
            components=tuple(recomputed),
            kinds=tuple(sorted(declared.items())),
            blobs=tuple(sorted(blobs.items())),
        ),
        sealed,
    )


def _document(repository: _ApprovedRepository, path: str) -> dict[str, Any]:
    blobs = dict(repository.blobs)
    if path not in blobs:
        _fail("unapproved_control_path", path, "path is absent from approved map")
    value = _strict_json(blobs[path], path)
    if not isinstance(value, dict):
        _fail("invalid_control_schema", path, "object required")
    return value


def _component(repository: _ApprovedRepository, path: str) -> str:
    components = dict(repository.components)
    if path not in components:
        _fail("unapproved_control_path", path, "path is absent from approved map")
    return components[path]


def _aggregate_paths(repository: _ApprovedRepository, paths: Sequence[str], path: str) -> str:
    if (
        isinstance(paths, (str, bytes))
        or not paths
        or any(not isinstance(item, str) or not item for item in paths)
        or len(set(paths)) != len(paths)
    ):
        _fail("invalid_control_path_set", path, "unique non-empty paths required")
    ordered = sorted(paths, key=lambda value: value.encode("utf-8"))
    records = [
        {"path": item, "digest": _component(repository, item)} for item in ordered
    ]
    return sha256_bytes(canonical_json_bytes(records))


def _support_and_dependency_documents(
    repository: _ApprovedRepository,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = _document(repository, WORKFLOW_CONTRACT_PATH)
    runtime = contract.get("runtime")
    workflows = contract.get("workflows")
    action_pins = contract.get("actionPins")
    network = contract.get("networkPolicy")
    if (
        not isinstance(runtime, dict)
        or not isinstance(workflows, dict)
        or not isinstance(action_pins, list)
        or not isinstance(network, dict)
    ):
        _fail("invalid_runtime_manifest", WORKFLOW_CONTRACT_PATH, "runtime/dependency projections are missing")
    required_runtime = {
        "runner",
        "pythonDependencies",
        "candidateDependencyInstall",
        "runAttempt",
        "timeoutMinutes",
        "toolchainRecordedInArtifact",
    }
    if set(runtime) != required_runtime:
        _fail("invalid_runtime_manifest", f"{WORKFLOW_CONTRACT_PATH}.runtime", "runtime field set drift")
    if (
        runtime["pythonDependencies"] != "stdlib only"
        or runtime["candidateDependencyInstall"] != "forbidden"
        or runtime["toolchainRecordedInArtifact"] is not True
        or network.get("dependencyInstall") != "forbidden"
    ):
        _fail("unsafe_runtime_manifest", WORKFLOW_CONTRACT_PATH, "P00 dependency-free execution semantics drift")
    pins: list[dict[str, str]] = []
    for index, raw_pin in enumerate(action_pins):
        pin = _exact(raw_pin, {"repository", "version", "commit"}, f"{WORKFLOW_CONTRACT_PATH}.actionPins[{index}]")
        if not all(isinstance(pin[name], str) and pin[name] for name in pin):
            _fail("invalid_runtime_manifest", f"{WORKFLOW_CONTRACT_PATH}.actionPins[{index}]", "action pin is invalid")
        _commit(pin["commit"], f"{WORKFLOW_CONTRACT_PATH}.actionPins[{index}].commit")
        pins.append(dict(pin))
    repositories = [pin["repository"] for pin in pins]
    if len(set(repositories)) != len(repositories):
        _fail("invalid_runtime_manifest", f"{WORKFLOW_CONTRACT_PATH}.actionPins", "action repositories must be unique")
    pins.sort(key=lambda value: value["repository"].encode("utf-8"))
    cross_platform = workflows.get("crossPlatform")
    state_writer = workflows.get("stateWriter")
    if not all(isinstance(value, str) and value for value in (cross_platform, state_writer)):
        _fail("invalid_runtime_manifest", f"{WORKFLOW_CONTRACT_PATH}.workflows", "workflow paths are missing")
    support = {
        "schemaVersion": SUPPORT_LOCK_SCHEMA,
        "sourceManifest": WORKFLOW_CONTRACT_PATH,
        "sourceManifestDigest": _component(repository, WORKFLOW_CONTRACT_PATH),
        "phase": "P00",
        "protectedRunner": runtime["runner"],
        "crossPlatformWorkflow": cross_platform,
        "crossPlatformWorkflowDigest": _component(repository, cross_platform),
        "stateWriterWorkflow": state_writer,
        "stateWriterWorkflowDigest": _component(repository, state_writer),
    }
    dependencies = {
        "schemaVersion": DEPENDENCY_SET_SCHEMA,
        "sourceManifest": WORKFLOW_CONTRACT_PATH,
        "sourceManifestDigest": _component(repository, WORKFLOW_CONTRACT_PATH),
        "pythonDependencies": runtime["pythonDependencies"],
        "candidateDependencyInstall": runtime["candidateDependencyInstall"],
        "workflowDependencyInstall": network["dependencyInstall"],
        "actionPins": pins,
    }
    return support, dependencies


def _file_digest(path: Path, field: str) -> str:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        _fail("executor_preflight_unavailable", field, "fixed executable is unavailable")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        _fail("executor_preflight_unavailable", field, "regular executable required")
    try:
        with resolved.open("rb") as handle:
            chunks = iter(lambda: handle.read(1024 * 1024), b"")
            import hashlib

            digest = hashlib.sha256()
            for chunk in chunks:
                digest.update(chunk)
    except OSError:
        _fail("executor_preflight_unavailable", field, "cannot read executable")
    return "sha256:" + digest.hexdigest()


def verify_executor_preflight(
    *,
    source_commit: str,
    support_lock_document: Mapping[str, Any],
    dependency_set_document: Mapping[str, Any],
) -> VerifiedExecutorPreflight:
    """Observe the exact fixed executor tools and seal manifest-derived inputs.

    Callers can supply documents, not digests.  A control-context factory still
    compares both resulting digests with its own approved Git projections, so a
    seal over substitute documents cannot cross that boundary.
    """

    commit = _commit(source_commit, "sourceCommit")
    try:
        support = json.loads(canonical_json_bytes(support_lock_document))
        dependencies = json.loads(canonical_json_bytes(dependency_set_document))
    except Exception as exc:
        _fail("invalid_preflight_manifest", "executorPreflight", str(exc))
    if not isinstance(support, dict) or support.get("schemaVersion") != SUPPORT_LOCK_SCHEMA:
        _fail("invalid_preflight_manifest", "supportLock", "unsupported support lock")
    if not isinstance(dependencies, dict) or dependencies.get("schemaVersion") != DEPENDENCY_SET_SCHEMA:
        _fail("invalid_preflight_manifest", "dependencySet", "unsupported dependency set")
    tool_facts = canonical_toolchain_manifest(
        {
            "schemaVersion": TOOL_SCHEMA,
            "gitDigest": _file_digest(Path("/usr/bin/git"), "tools.git"),
            "pythonDigest": _file_digest(Path(sys.executable), "tools.python"),
            "unshareDigest": _file_digest(Path("/usr/bin/unshare"), "tools.unshare"),
            "unshareArguments": ["--user", "--map-root-user", "--net", "--"],
        }
    )
    support_digest = document_digest(support)
    dependency_digest = document_digest(dependencies)
    tools_digest = toolchain_digest(tool_facts)
    preflight_document = {
        "schemaVersion": PREFLIGHT_SCHEMA,
        "sourceCommit": commit,
        "supportLockDigest": support_digest,
        "dependencySetDigest": dependency_digest,
        "toolchainDigest": tools_digest,
        "toolFacts": tool_facts,
    }
    return _mark(
        _VERIFIED_PREFLIGHTS,
        VerifiedExecutorPreflight(
            preflight_digest=document_digest(preflight_document),
            source_commit=commit,
            support_lock_digest=support_digest,
            dependency_set_digest=dependency_digest,
            toolchain_digest=tools_digest,
            tool_facts=tuple(
                sorted(
                    (
                        key,
                        tuple(value) if key == "unshareArguments" else value,
                    )
                    for key, value in tool_facts.items()
                )
            ),
        ),
    )


def _executor_preflight(repository: _ApprovedRepository) -> VerifiedExecutorPreflight:
    support, dependencies = _support_and_dependency_documents(repository)
    return verify_executor_preflight(
        source_commit=repository.commit,
        support_lock_document=support,
        dependency_set_document=dependencies,
    )


def _indexed(records: Any, path: str) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list) or not records:
        _fail("invalid_catalog", path, "non-empty record list required")
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(records):
        if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            _fail("invalid_catalog", f"{path}[{index}]", "record ID required")
        if value["id"] in result:
            _fail("duplicate_catalog_id", f"{path}[{index}].id", value["id"])
        result[value["id"]] = value
    return result


def _implementation_digest(
    repository: _ApprovedRepository, evaluator: Mapping[str, Any], path: str
) -> str:
    implementation_paths = evaluator.get("implementationPaths")
    if not isinstance(implementation_paths, list) or not implementation_paths:
        return document_digest({"evaluator": evaluator})
    if (
        any(not isinstance(item, str) or not item for item in implementation_paths)
        or len(set(implementation_paths)) != len(implementation_paths)
    ):
        _fail("invalid_evaluator_catalog", path, "implementation paths must be unique")
    ordered = sorted(implementation_paths, key=lambda value: value.encode("utf-8"))
    digests = [_component(repository, item) for item in ordered]
    if len(digests) == 1:
        return digests[0]
    return _aggregate_paths(repository, ordered, f"{path}.implementationPaths")


def _criteria(
    repository: _ApprovedRepository,
    *,
    owner: str,
    contract_criteria: Any,
    gate_criteria: Any,
    gate_protected_inputs: Sequence[str],
    gate_dataset_policy: Any,
) -> tuple[
    tuple[CriterionBinding, ...],
    tuple[str, ...],
    tuple[tuple[str, str, str], ...],
]:
    if not isinstance(contract_criteria, list) or not contract_criteria:
        _fail("invalid_contract", "contract.convergence", "criteria required")
    if gate_criteria != contract_criteria:
        _fail("contract_gate_criteria_mismatch", "gate.criteria", "gate criteria differ from contract")
    evaluator_catalog = _document(repository, EVALUATOR_CATALOG_PATH)
    schema_catalog = _document(repository, EVIDENCE_SCHEMA_CATALOG_PATH)
    metric_catalog = _document(repository, METRIC_CATALOG_PATH)
    acceptance_catalog = _document(repository, ACCEPTANCE_CATALOG_PATH)
    for path, document in (
        (EVALUATOR_CATALOG_PATH, evaluator_catalog),
        (EVIDENCE_SCHEMA_CATALOG_PATH, schema_catalog),
        (METRIC_CATALOG_PATH, metric_catalog),
        (ACCEPTANCE_CATALOG_PATH, acceptance_catalog),
    ):
        if document.get("controlPlaneDigest") != repository.control_plane_digest:
            _fail("embedded_control_plane_mismatch", path, "catalog embeds another control plane")
    evaluators = _indexed(evaluator_catalog.get("evaluators"), f"{EVALUATOR_CATALOG_PATH}.evaluators")
    schemas = _indexed(schema_catalog.get("schemas"), f"{EVIDENCE_SCHEMA_CATALOG_PATH}.schemas")
    metrics = _indexed(metric_catalog.get("metrics"), f"{METRIC_CATALOG_PATH}.metrics")
    acceptance = _indexed(acceptance_catalog.get("criteria"), f"{ACCEPTANCE_CATALOG_PATH}.criteria")
    protected_catalogs = [
        item
        for item in gate_protected_inputs
        if item.startswith("execution/catalogs/p00/") and item != ACCEPTANCE_CATALOG_PATH
    ]
    if len(protected_catalogs) != 1:
        _fail("ambiguous_dataset_catalog", "gate.protectedInputs", "one subject dataset catalog required")
    default_dataset_path = protected_catalogs[0]
    default_dataset_digest = _component(repository, default_dataset_path)
    default_dataset = _document(repository, default_dataset_path)
    if (
        default_dataset.get("controlPlaneDigest") != repository.control_plane_digest
        or default_dataset.get("protected") is not True
    ):
        _fail(
            "dataset_catalog_not_protected",
            default_dataset_path,
            "dataset catalog must be explicitly protected by this control plane",
        )
    result: list[CriterionBinding] = []
    late_bound: list[str] = []
    dataset_bindings: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(contract_criteria):
        if not isinstance(raw, dict):
            _fail("invalid_criterion", f"contract.convergence[{index}]", "object required")
        required = {"id", "kind", "evaluator", "threshold", "evidenceSchema"}
        allowed = required | {"metric"}
        if not required.issubset(raw) or not set(raw).issubset(allowed):
            _fail("invalid_criterion", f"contract.convergence[{index}]", "criterion field set drift")
        criterion_id = raw["id"]
        kind = raw["kind"]
        evaluator_id = raw["evaluator"]
        schema_id = raw["evidenceSchema"]
        if (
            not all(isinstance(value, str) and value for value in (criterion_id, kind, evaluator_id, schema_id, raw["threshold"]))
            or criterion_id in seen
            or kind not in EXPECTED_EVALUATOR_STATUS
        ):
            _fail("invalid_criterion", f"contract.convergence[{index}]", "criterion identity is invalid")
        seen.add(criterion_id)
        evaluator = evaluators.get(evaluator_id)
        schema = schemas.get(schema_id)
        accepted = acceptance.get(criterion_id)
        if evaluator is None or schema is None or accepted is None:
            _fail("missing_criterion_catalog_entry", criterion_id, "evaluator/schema/acceptance entry missing")
        status = EXPECTED_EVALUATOR_STATUS[kind]
        if (
            evaluator.get("kind") != kind
            or evaluator.get("status") != status
            or schema.get("kind") != kind
            or schema.get("status") != status
            or accepted
            != {
                "id": criterion_id,
                "owner": owner,
                "kind": kind,
                "evaluator": evaluator_id,
                "evaluatorStatus": status,
            }
        ):
            _fail("criterion_catalog_mismatch", criterion_id, "catalog binding differs from gate")
        implementation_digest = _implementation_digest(
            repository, evaluator, f"{EVALUATOR_CATALOG_PATH}#{evaluator_id}"
        )
        metric_id = raw.get("metric")
        if metric_id is None:
            evaluator_digest = implementation_digest
            dataset_digest = default_dataset_digest
            threshold_digest = document_digest(
                {
                    "criterionId": criterion_id,
                    "kind": kind,
                    "evaluator": evaluator_id,
                    "threshold": raw["threshold"],
                }
            )
        else:
            if not isinstance(metric_id, str) or not metric_id:
                _fail("invalid_metric_reference", criterion_id, "metric ID required")
            metric = metrics.get(metric_id)
            expected_ref = f"{METRIC_CATALOG_PATH}#{metric_id}.threshold"
            if (
                metric is None
                or raw["threshold"] != expected_ref
                or metric.get("evaluator") != evaluator_id
                or metric.get("evaluatorDigest") != implementation_digest
                or metric.get("datasetCatalog") != default_dataset_path
            ):
                _fail("metric_binding_mismatch", criterion_id, "metric/evaluator/dataset/threshold binding differs")
            declared_dataset = metric.get("datasetDigest")
            if declared_dataset is None:
                policy = gate_dataset_policy
                if (
                    not isinstance(policy, dict)
                    or policy.get("status") != "late_bound_requires_signed_freeze"
                    or policy.get("digest") is not None
                    or metric.get("datasetStatus") != "late_bound_requires_signed_freeze"
                ):
                    _fail("unapproved_late_bound_dataset", criterion_id, "late-bound policy is incomplete")
                dataset_digest = default_dataset_digest
                late_bound.append(criterion_id)
            else:
                dataset_digest = _sha(declared_dataset, f"{METRIC_CATALOG_PATH}#{metric_id}.datasetDigest")
            evaluator_digest = implementation_digest
            threshold_digest = document_digest(
                {
                    "criterionId": criterion_id,
                    "thresholdReference": raw["threshold"],
                    "metricDefinition": metric,
                }
            )
        if (
            isinstance(gate_dataset_policy, dict)
            and gate_dataset_policy.get("status") == "late_bound_requires_signed_freeze"
            and criterion_id not in late_bound
            and kind == "MACHINE"
        ):
            late_bound.append(criterion_id)
        result.append(
            CriterionBinding(
                criterion_id=criterion_id,
                kind=kind,
                evaluator=evaluator_id,
                evaluator_digest=evaluator_digest,
                evidence_schema=schema_id,
                evidence_schema_digest=document_digest(schema),
                dataset_digest=dataset_digest,
                threshold_digest=threshold_digest,
                evaluator_status=status,
            )
        )
        dataset_bindings.append(
            (criterion_id, default_dataset_path, dataset_digest)
        )
    result.sort(key=lambda item: item.criterion_id)
    dataset_bindings.sort(key=lambda item: item[0])
    return (
        tuple(result),
        tuple(sorted(set(late_bound))),
        tuple(dataset_bindings),
    )


def criterion_documents(criteria: Sequence[CriterionBinding]) -> list[dict[str, str]]:
    """Return the exact provenance projection for derived bindings."""

    return [
        {
            "id": item.criterion_id,
            "kind": item.kind,
            "evaluator": item.evaluator,
            "evaluatorDigest": item.evaluator_digest,
            "evaluatorStatus": item.evaluator_status,
            "evidenceSchema": item.evidence_schema,
            "evidenceSchemaDigest": item.evidence_schema_digest,
            "datasetDigest": item.dataset_digest,
            "thresholdDigest": item.threshold_digest,
        }
        for item in criteria
    ]


def _protected_inputs(
    repository: _ApprovedRepository,
    *,
    gate_protected_inputs: Sequence[str],
    preflight: VerifiedExecutorPreflight,
) -> tuple[tuple[str, str], ...]:
    checked = require_verified_executor_preflight(preflight)
    support, dependencies = _support_and_dependency_documents(repository)
    if (
        checked.source_commit != repository.commit
        or checked.support_lock_digest != document_digest(support)
        or checked.dependency_set_digest != document_digest(dependencies)
        or checked.toolchain_digest
        != toolchain_digest(
            {
                key: list(value) if key == "unshareArguments" else value
                for key, value in checked.tool_facts
            }
        )
    ):
        _fail("executor_preflight_mismatch", "executorPreflight", "preflight differs from approved manifests/tools")
    tool_paths = sorted(
        path for path, _digest in repository.components if path.startswith("tools/phasegate/")
    )
    values = {
        "planDigest": _component(repository, PLAN_PATH),
        "supportLockDigest": checked.support_lock_digest,
        "toolchainDigest": checked.toolchain_digest,
        "dependencySetDigest": checked.dependency_set_digest,
        "gateRunnerDigest": _aggregate_paths(repository, tool_paths, "gateRunnerComponents"),
        "evaluatorSetDigest": _component(repository, EVALUATOR_CATALOG_PATH),
        "metricDefinitionsDigest": _component(repository, METRIC_CATALOG_PATH),
        "protectedAcceptanceDigest": _aggregate_paths(
            repository,
            list(gate_protected_inputs),
            "gate.protectedInputs",
        ),
    }
    return tuple(sorted(values.items()))


def _state_approval_digest(
    sealed: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> str:
    return _sha(sealed.bootstrap_approval_digest, "current.bootstrapApprovalDigest")


def _context_document(
    *,
    subject: Mapping[str, str],
    approval_digest: str,
    impact_map_digest: str,
    protected_inputs: Sequence[tuple[str, str]],
    criteria: Sequence[CriterionBinding],
    prerequisites: Sequence[str],
    component_set_digest: str,
    preflight_digest: str,
    dataset_selection_digests: Sequence[str] = (),
    dataset_selection_bindings: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    return {
        "schemaVersion": CONTEXT_SCHEMA,
        "subject": dict(subject),
        "contractApprovalDigest": approval_digest,
        "impactMapDigest": impact_map_digest,
        "protectedInputs": dict(protected_inputs),
        "criteria": criterion_documents(criteria),
        "prerequisiteUnits": list(prerequisites),
        "componentSetDigest": component_set_digest,
        "executorPreflightDigest": preflight_digest,
        "datasetSelectionDigests": list(dataset_selection_digests),
        "datasetSelectionBindings": dict(dataset_selection_bindings),
    }


def _selection_time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("invalid_dataset_selection_time", path, "UTC timestamp required")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        _fail("invalid_dataset_selection_time", path, "invalid timestamp")
    normalized = parsed.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_dataset_selection_time", path, "second precision required")
    return normalized


def _selection_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def finalize_late_bound_dataset_context(
    *,
    base_context: VerifiedWorkUnitControlContext | VerifiedPhaseControlContext,
    raw_selections: Sequence[Mapping[str, Any]],
    roster: EffectiveReviewerRoster,
    verification_time: datetime,
) -> VerifiedWorkUnitControlContext | VerifiedPhaseControlContext:
    """Verify raw reviewer-signed datasets and replace only late-bound digests.

    The signed object carries the complete canonical records, not merely a
    digest.  One selection covers all late-bound MACHINE criteria sharing an
    approved dataset catalog.  This prevents denominator forks inside a work
    unit or aggregate gate while preserving the Plan's independently reviewed
    late binding.
    """

    if isinstance(base_context, VerifiedWorkUnitControlContext):
        context: VerifiedWorkUnitControlContext | VerifiedPhaseControlContext = (
            require_verified_work_unit_control_context(base_context)
        )
        subject_document = {
            "phase": context.subject.phase,
            "workUnit": context.subject.work_unit,
            "sourceCommit": context.subject.source_commit,
            "controlPlaneDigest": context.subject.control_plane_digest,
            "contractDigest": context.subject.contract_digest,
        }
        approval_digest = context.contract_approval_digest
        prerequisites = context.prerequisite_units
    elif isinstance(base_context, VerifiedPhaseControlContext):
        context = require_verified_phase_control_context(base_context)
        subject_document = {
            "phase": context.subject.phase,
            "sourceCommit": context.subject.source_commit,
            "controlPlaneDigest": context.subject.control_plane_digest,
            "aggregateContractDigest": context.subject.aggregate_contract_digest,
        }
        approval_digest = context.aggregate_contract_approval_digest
        prerequisites = ()
    else:
        _fail(
            "unverified_internal_result",
            "controlContext",
            "expected an identity-sealed work-unit or phase control context",
        )
    try:
        _require_roster_verified(roster, EffectiveReviewerRoster, "roster")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if (
        roster.source_commit != context.subject.source_commit
        or roster.control_plane_digest != context.subject.control_plane_digest
    ):
        _fail("dataset_roster_binding_mismatch", "roster", "roster belongs to another source/control plane")
    if not isinstance(verification_time, datetime) or verification_time.tzinfo is None:
        _fail("invalid_dataset_selection_time", "verificationTime", "timezone-aware datetime required")
    now = verification_time.astimezone(timezone.utc)
    late_ids = set(context.late_bound_dataset_criteria)
    if not late_ids:
        if raw_selections:
            _fail("unexpected_dataset_selection", "datasetSelections", "context has no late-bound criteria")
        return context
    if isinstance(raw_selections, (str, bytes)) or not isinstance(raw_selections, Sequence):
        _fail("invalid_dataset_selection_set", "datasetSelections", "selection list required")
    groups: dict[tuple[str, str], list[str]] = {}
    for criterion_id, catalog_path, slot_digest in context.dataset_catalog_bindings:
        if criterion_id in late_ids:
            groups.setdefault((catalog_path, slot_digest), []).append(criterion_id)
    for ids in groups.values():
        ids.sort()
    if set().union(*(set(ids) for ids in groups.values())) != late_ids:
        _fail("dataset_binding_incomplete", "controlContext", "late-bound catalog mapping is incomplete")
    if len(raw_selections) != len(groups):
        _fail("dataset_selection_set_mismatch", "datasetSelections", "one selection per approved catalog is required")
    expected_group_order = sorted(groups, key=lambda item: groups[item][0])
    actual_group_order: list[tuple[str, str]] = []
    replacements: dict[str, str] = {}
    selection_digests: list[str] = []
    selection_bindings: list[tuple[str, str]] = []
    for index, raw in enumerate(raw_selections):
        path = f"datasetSelections[{index}]"
        envelope = _exact(
            raw,
            {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
            path,
        )
        if (
            envelope["schemaVersion"] != DATASET_SELECTION_SCHEMA
            or envelope["kind"] != DATASET_SELECTION_KIND
        ):
            _fail("unsupported_dataset_selection", path, "schema or kind differs")
        attestation_digest = document_digest(
            envelope, omit_field="attestationDigest"
        )
        if envelope["attestationDigest"] != attestation_digest:
            _fail(
                "attestation_digest_mismatch",
                f"{path}.attestationDigest",
                "selection envelope changed",
            )
        body = _exact(
            envelope["body"],
            {
                "selectionId",
                "baseContextDigest",
                "subject",
                "criterionIds",
                "datasetCatalog",
                "datasetManifest",
                "datasetArtifactDigest",
                "recordIds",
                "datasetDigest",
                "issuedAt",
                "validUntil",
                "actor",
                "conflictOfInterest",
                "authorityDigest",
            },
            f"{path}.body",
        )
        if (
            not isinstance(body["selectionId"], str)
            or not body["selectionId"]
            or len(body["selectionId"]) > 256
            or body["baseContextDigest"] != context.context_digest
            or body["subject"] != subject_document
            or body["authorityDigest"] != roster.authority_digest
        ):
            _fail("dataset_selection_binding_mismatch", f"{path}.body", "context/subject/authority differs")
        criterion_ids = body["criterionIds"]
        if (
            not isinstance(criterion_ids, list)
            or not criterion_ids
            or criterion_ids != sorted(set(criterion_ids))
            or any(not isinstance(item, str) or not item for item in criterion_ids)
        ):
            _fail("invalid_dataset_selection_set", f"{path}.body.criterionIds", "sorted unique IDs required")
        catalog = _exact(
            body["datasetCatalog"], {"path", "slotDigest"}, f"{path}.body.datasetCatalog"
        )
        if not isinstance(catalog["path"], str) or not catalog["path"]:
            _fail(
                "dataset_selection_scope_mismatch",
                f"{path}.body.datasetCatalog.path",
                "approved catalog path required",
            )
        _sha(
            catalog["slotDigest"],
            f"{path}.body.datasetCatalog.slotDigest",
        )
        group = (catalog["path"], catalog["slotDigest"])
        if group not in groups or criterion_ids != groups[group]:
            _fail("dataset_selection_scope_mismatch", f"{path}.body", "selection must cover the exact shared catalog group")
        actual_group_order.append(group)
        manifest = _exact(
            body["datasetManifest"],
            {"schemaVersion", "datasetId", "records"},
            f"{path}.body.datasetManifest",
        )
        if (
            manifest["schemaVersion"]
            != "urn:agentapi-doctor:p00-dataset-records:v1alpha1"
            or not isinstance(manifest["datasetId"], str)
            or not manifest["datasetId"]
            or not isinstance(manifest["records"], list)
            or not manifest["records"]
            or len(manifest["records"]) > 100_000
        ):
            _fail("invalid_dataset_manifest", f"{path}.body.datasetManifest", "bounded non-empty dataset required")
        records: list[Mapping[str, Any]] = []
        ids: list[str] = []
        for record_index, record in enumerate(manifest["records"]):
            if not isinstance(record, Mapping):
                _fail("invalid_dataset_manifest", f"{path}.body.datasetManifest.records[{record_index}]", "object required")
            record_id = record.get("id")
            if not isinstance(record_id, str) or not record_id:
                _fail("invalid_dataset_manifest", f"{path}.body.datasetManifest.records[{record_index}].id", "record ID required")
            ids.append(record_id)
            records.append(record)
        if ids != sorted(set(ids)) or body["recordIds"] != ids:
            _fail("dataset_record_set_mismatch", f"{path}.body.recordIds", "records and sorted IDs differ")
        dataset_digest = sha256_bytes(canonical_json_bytes(records))
        artifact_digest = document_digest(manifest)
        if (
            body["datasetDigest"] != dataset_digest
            or body["datasetArtifactDigest"] != artifact_digest
        ):
            _fail("dataset_artifact_digest_mismatch", f"{path}.body", "raw records do not match declared digests")
        issued_at = _selection_time(body["issuedAt"], f"{path}.body.issuedAt")
        valid_until = _selection_time(body["validUntil"], f"{path}.body.validUntil")
        if issued_at >= valid_until or not issued_at <= now < valid_until:
            _fail("dataset_selection_outside_validity", f"{path}.body", "selection is not currently valid")
        actor = _exact(
            body["actor"], {"principal", "role", "organization"}, f"{path}.body.actor"
        )
        conflict = _exact(
            body["conflictOfInterest"],
            {"independent", "statement"},
            f"{path}.body.conflictOfInterest",
        )
        if (
            conflict["independent"] is not True
            or not isinstance(conflict["statement"], str)
            or not conflict["statement"].strip()
            or len(conflict["statement"]) > 2048
        ):
            _fail(
                "dataset_reviewer_conflict",
                f"{path}.body.conflictOfInterest",
                "signed independent-review statement is required",
            )
        signature = _exact(
            envelope["signature"],
            {"scheme", "namespace", "principal", "value"},
            f"{path}.signature",
        )
        if (
            actor.get("role") != DATASET_REVIEWER_ROLE
            or signature.get("scheme") != "openssh-sshsig-v1"
            or signature.get("namespace") != DATASET_SELECTION_NAMESPACE
            or signature.get("principal") != actor.get("principal")
            or not isinstance(signature.get("value"), str)
            or not signature["value"]
            or len(signature["value"]) > 16_384
        ):
            _fail("dataset_selection_signer_mismatch", path, "dedicated reviewer signature required")
        authorizations = []
        try:
            for criterion_id in criterion_ids:
                authorizations.append(
                    authorize_criterion_signer(
                        roster,
                        principal=actor["principal"],
                        criterion_id=criterion_id,
                        required_role=DATASET_REVIEWER_ROLE,
                        required_capability=DATASET_REVIEWER_CAPABILITY,
                        at=now,
                    )
                )
        except ProtectedVerificationError as exc:
            _fail(exc.code, exc.path, exc.message)
        if any(
            authorization.organization != actor.get("organization")
            or authorization.role != actor.get("role")
            for authorization in authorizations
        ):
            _fail("dataset_selection_signer_mismatch", f"{path}.body.actor", "actor differs from roster grant")
        principal = next(
            (item for item in roster.principals if item.identity == actor["principal"]),
            None,
        )
        if principal is None:
            _fail("signer_not_allowed", f"{path}.body.actor", "reviewer is absent from roster")
        try:
            verify_sshsig(
                _selection_payload(envelope),
                armored_signature=signature["value"],
                public_key=principal.public_key,
                expected_namespace=DATASET_SELECTION_NAMESPACE,
            )
        except (SshSigVerificationError, KeyError, TypeError) as exc:
            if isinstance(exc, SshSigVerificationError):
                _fail(exc.code, exc.path, exc.message)
            _fail("invalid_dataset_selection_signature", f"{path}.signature", "signature is invalid")
        selection_digests.append(attestation_digest)
        for criterion_id in criterion_ids:
            replacements[criterion_id] = dataset_digest
            selection_bindings.append((criterion_id, attestation_digest))
    if actual_group_order != expected_group_order:
        _fail("dataset_selection_set_mismatch", "datasetSelections", "selection groups must be deterministically ordered")
    if set(replacements) != late_ids:
        _fail("dataset_selection_set_mismatch", "datasetSelections", "late-bound criteria are not exactly covered")
    finalized_criteria = tuple(
        replace(item, dataset_digest=replacements.get(item.criterion_id, item.dataset_digest))
        for item in context.criteria
    )
    context_document = _context_document(
        subject=subject_document,
        approval_digest=approval_digest,
        impact_map_digest=context.impact_map_digest,
        protected_inputs=context.protected_inputs,
        criteria=finalized_criteria,
        prerequisites=prerequisites,
        component_set_digest=context.component_set_digest,
        preflight_digest=context.executor_preflight.preflight_digest,
        dataset_selection_digests=selection_digests,
        dataset_selection_bindings=selection_bindings,
    )
    return _mark(
        _VERIFIED_CONTEXTS,
        replace(
            context,
            context_digest=document_digest(context_document),
            criteria=finalized_criteria,
            late_bound_dataset_criteria=(),
            dataset_selection_digests=tuple(selection_digests),
            dataset_selection_bindings=tuple(sorted(selection_bindings)),
        ),
    )


def derive_work_unit_control_context(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    oidc_authority: OidcProvenanceVerifier,
    repo_root: Path,
    work_unit: str,
) -> VerifiedWorkUnitControlContext:
    """Mechanically derive one work-unit context without caller digest maps."""

    match = WORK_UNIT_RE.fullmatch(work_unit) if isinstance(work_unit, str) else None
    if match is None:
        _fail("unsupported_work_unit", "workUnit", "exact P00.Wnn ID required")
    repository, sealed = _approved_repository(
        current=current, authority=oidc_authority, repo_root=repo_root
    )
    contract_path = f"execution/work-units/{work_unit}.yaml"
    gate_path = f"execution/gates/p00/{work_unit}.yaml"
    contract = _document(repository, contract_path)
    gate = _document(repository, gate_path)
    if (
        contract.get("id") != work_unit
        or contract.get("phase") != "P00"
        or contract.get("kind") != "WorkUnitContractCandidate"
        or contract.get("controlPlaneDigest") != repository.control_plane_digest
        or gate.get("workUnit") != work_unit
        or gate.get("phase") != "P00"
        or gate.get("contract") != contract_path
        or gate.get("controlPlaneDigest") != repository.control_plane_digest
    ):
        _fail("contract_gate_binding_mismatch", work_unit, "contract/gate identity differs")
    protected_paths = gate.get("protectedInputs")
    if not isinstance(protected_paths, list):
        _fail("invalid_gate", f"{gate_path}.protectedInputs", "path list required")
    criteria, late_bound, dataset_bindings = _criteria(
        repository,
        owner=work_unit,
        contract_criteria=contract.get("convergence"),
        gate_criteria=gate.get("criteria"),
        gate_protected_inputs=protected_paths,
        gate_dataset_policy=gate.get("datasetPolicy"),
    )
    preflight = _executor_preflight(repository)
    protected = _protected_inputs(
        repository, gate_protected_inputs=protected_paths, preflight=preflight
    )
    components = repository.components
    component_set_digest = sha256_bytes(
        canonical_json_bytes({"componentDigests": dict(components)})
    )
    contract_digest = _component(repository, contract_path)
    subject = SubjectBinding(
        phase="P00",
        work_unit=work_unit,
        source_commit=repository.commit,
        control_plane_digest=repository.control_plane_digest,
        contract_digest=contract_digest,
    )
    state_units = sealed.state_core.get("phases", {}).get("P00", {}).get("workUnits", {})
    unit_state = state_units.get(work_unit) if isinstance(state_units, dict) else None
    if not isinstance(unit_state, dict) or unit_state.get("contractDigest") != contract_digest:
        _fail("state_contract_mismatch", work_unit, "replayed state contract differs from approved component")
    # Replay owns the current state-transition approval.  It legitimately
    # changes after every lifecycle/convergence event and is not the immutable
    # P00 contract approval.  Validate its shape only; B00's sealed approval
    # remains the contract approval because it covered the full P00 map.
    current_transition_approval = unit_state.get("approvalDigest")
    if current_transition_approval is not None:
        _sha(current_transition_approval, f"current.state.{work_unit}.approvalDigest")
    number = int(match.group(1))
    prerequisites = tuple(
        sorted(
            unit
            for unit in state_units
            if isinstance(unit, str)
            and WORK_UNIT_RE.fullmatch(unit)
            and int(unit.rsplit("W", 1)[1]) < number
        )
    )
    approval_digest = _state_approval_digest(sealed)
    impact_digest = _component(repository, IMPACT_MAP_PATH)
    context_document = _context_document(
        subject={
            "phase": subject.phase,
            "workUnit": subject.work_unit,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "contractDigest": subject.contract_digest,
        },
        approval_digest=approval_digest,
        impact_map_digest=impact_digest,
        protected_inputs=protected,
        criteria=criteria,
        prerequisites=prerequisites,
        component_set_digest=component_set_digest,
        preflight_digest=preflight.preflight_digest,
    )
    return _mark(
        _VERIFIED_CONTEXTS,
        VerifiedWorkUnitControlContext(
            context_digest=document_digest(context_document),
            subject=subject,
            contract_approval_digest=approval_digest,
            impact_map_digest=impact_digest,
            protected_inputs=protected,
            criteria=criteria,
            prerequisite_units=prerequisites,
            component_digests=components,
            component_set_digest=component_set_digest,
            gate_path=gate_path,
            contract_path=contract_path,
            late_bound_dataset_criteria=late_bound,
            dataset_catalog_bindings=dataset_bindings,
            dataset_selection_digests=(),
            dataset_selection_bindings=(),
            executor_preflight=preflight,
        ),
    )


def derive_phase_control_context(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    oidc_authority: OidcProvenanceVerifier,
    repo_root: Path,
    phase: str,
) -> VerifiedPhaseControlContext:
    """Mechanically derive the P00 aggregate context (not bundle support)."""

    if phase != "P00":
        _fail("unsupported_phase", "phase", "only P00 aggregate is implemented")
    repository, sealed = _approved_repository(
        current=current, authority=oidc_authority, repo_root=repo_root
    )
    contract_path = "execution/phases/P00.yaml"
    gate_path = "execution/gates/p00/aggregate.yaml"
    contract = _document(repository, contract_path)
    gate = _document(repository, gate_path)
    if (
        contract.get("id") != "P00"
        or contract.get("kind") != "PhaseAggregateContractCandidate"
        or contract.get("controlPlaneDigest") != repository.control_plane_digest
        or gate.get("workUnit") is not None
        or gate.get("phase") != "P00"
        or gate.get("contract") != contract_path
        or gate.get("controlPlaneDigest") != repository.control_plane_digest
    ):
        _fail("contract_gate_binding_mismatch", "P00", "aggregate contract/gate identity differs")
    protected_paths = gate.get("protectedInputs")
    if not isinstance(protected_paths, list):
        _fail("invalid_gate", f"{gate_path}.protectedInputs", "path list required")
    criteria, late_bound, dataset_bindings = _criteria(
        repository,
        owner="P00",
        contract_criteria=contract.get("convergence"),
        gate_criteria=gate.get("criteria"),
        gate_protected_inputs=protected_paths,
        gate_dataset_policy=gate.get("datasetPolicy"),
    )
    preflight = _executor_preflight(repository)
    protected = _protected_inputs(
        repository, gate_protected_inputs=protected_paths, preflight=preflight
    )
    component_set_digest = sha256_bytes(
        canonical_json_bytes({"componentDigests": dict(repository.components)})
    )
    aggregate_digest = _component(repository, contract_path)
    phase_state = sealed.state_core.get("phases", {}).get("P00")
    if not isinstance(phase_state, dict) or phase_state.get("aggregateContractDigest") != aggregate_digest:
        _fail("state_contract_mismatch", "P00", "replayed aggregate contract differs")
    unit_contracts = tuple(
        (unit, _component(repository, f"execution/work-units/{unit}.yaml"))
        for unit in contract.get("workUnits", [])
    )
    subject = PhaseSubject(
        phase="P00",
        source_commit=repository.commit,
        control_plane_digest=repository.control_plane_digest,
        aggregate_contract_digest=aggregate_digest,
    )
    approval_digest = _state_approval_digest(sealed)
    impact_digest = _component(repository, IMPACT_MAP_PATH)
    context_document = _context_document(
        subject={
            "phase": subject.phase,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "aggregateContractDigest": subject.aggregate_contract_digest,
        },
        approval_digest=approval_digest,
        impact_map_digest=impact_digest,
        protected_inputs=protected,
        criteria=criteria,
        prerequisites=(),
        component_set_digest=component_set_digest,
        preflight_digest=preflight.preflight_digest,
    )
    return _mark(
        _VERIFIED_CONTEXTS,
        VerifiedPhaseControlContext(
            context_digest=document_digest(context_document),
            subject=subject,
            aggregate_contract_approval_digest=approval_digest,
            impact_map_digest=impact_digest,
            unit_contract_digests=unit_contracts,
            protected_inputs=protected,
            criteria=criteria,
            component_digests=repository.components,
            component_set_digest=component_set_digest,
            gate_path=gate_path,
            contract_path=contract_path,
            late_bound_dataset_criteria=late_bound,
            dataset_catalog_bindings=dataset_bindings,
            dataset_selection_digests=(),
            dataset_selection_bindings=(),
            executor_preflight=preflight,
        ),
    )


__all__ = [
    "CONTEXT_SCHEMA",
    "ControlContextError",
    "DEPENDENCY_SET_SCHEMA",
    "DATASET_REVIEWER_CAPABILITY",
    "DATASET_REVIEWER_ROLE",
    "DATASET_SELECTION_KIND",
    "DATASET_SELECTION_NAMESPACE",
    "DATASET_SELECTION_SCHEMA",
    "PREFLIGHT_SCHEMA",
    "SUPPORT_LOCK_SCHEMA",
    "VerifiedExecutorPreflight",
    "VerifiedPhaseControlContext",
    "VerifiedWorkUnitControlContext",
    "criterion_documents",
    "derive_phase_control_context",
    "derive_work_unit_control_context",
    "finalize_late_bound_dataset_context",
    "require_verified_executor_preflight",
    "require_verified_phase_control_context",
    "require_verified_work_unit_control_context",
    "verify_executor_preflight",
]
