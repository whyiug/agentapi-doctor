"""Deterministic digests for the pre-Genesis control-plane candidate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


CONTROL_PLANE_PLACEHOLDER = "sha256:__CONTROL_PLANE_DIGEST__"


class DigestError(ValueError):
    """Raised when a declared digest input is unsafe or invalid."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the bootstrap canonical JSON representation.

    P00 deliberately calls this ``bootstrap-canonical-json-v1`` rather than
    claiming full RFC 8785 conformance.  P01 owns the production canonicalizer.
    """

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DigestError(f"value is not canonical JSON: {exc}") from exc
    return encoded.encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def load_json_yaml(path: Path) -> Any:
    """Load JSON-compatible YAML without adding a bootstrap dependency."""

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DigestError(f"cannot read {path}: {exc}") from exc

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DigestError(f"{path} contains duplicate object key {key!r}")
            result[key] = value
        return result

    def reject_non_finite(token: str) -> Any:
        raise DigestError(f"{path} contains non-finite number {token}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except json.JSONDecodeError as exc:
        raise DigestError(
            f"{path} must be JSON-compatible YAML: line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc


def normalize_control_plane_references(value: Any) -> Any:
    """Remove the aggregate digest's intentional self-reference.

    Contracts carry the final aggregate digest.  Their component projection
    replaces only that field with a fixed token before hashing.  The approval
    request is not an input, so no other field is normalized.
    """

    if isinstance(value, dict):
        return {
            key: (
                CONTROL_PLANE_PLACEHOLDER
                if key == "controlPlaneDigest"
                else normalize_control_plane_references(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_control_plane_references(item) for item in value]
    return value


def _safe_repo_path(root: Path, declared: str) -> Path:
    if not declared or "\\" in declared:
        raise DigestError(f"invalid repository-relative path: {declared!r}")
    relative = Path(declared)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise DigestError(f"unsafe repository-relative path: {declared!r}")
    resolved_root = root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise DigestError(f"path escapes repository root: {declared!r}") from exc
    return resolved


def _component_digest(path: Path, kind: str) -> str:
    if kind in {"json", "json-yaml", "manifest", "contract", "catalog", "gate"}:
        value = normalize_control_plane_references(load_json_yaml(path))
        return sha256_bytes(canonical_json_bytes(value))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DigestError(f"cannot read {path}: {exc}") from exc
    # Text-like bootstrap inputs use normalized line endings.  Binary inputs
    # are intentionally unsupported until a later, approved control plane.
    if b"\x00" in raw:
        raise DigestError(f"binary control-plane input is not allowed: {path}")
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return sha256_bytes(normalized)


def read_input_manifest(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = root / "execution/control-plane-inputs.yaml"
    manifest = load_json_yaml(manifest_path)
    if not isinstance(manifest, dict):
        raise DigestError("control-plane-inputs must be an object")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise DigestError("control-plane-inputs.inputs must be a non-empty array")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(inputs):
        if not isinstance(entry, dict):
            raise DigestError(f"inputs[{index}] must be an object")
        path = entry.get("path")
        kind = entry.get("kind")
        required = entry.get("required")
        if (
            not isinstance(path, str)
            or not isinstance(kind, str)
            or required is not True
        ):
            raise DigestError(
                f"inputs[{index}] requires string path/kind and required=true"
            )
        if path in seen:
            raise DigestError(f"duplicate control-plane input: {path}")
        seen.add(path)
        normalized.append({"path": path, "kind": kind, "required": True})
    if any(path.startswith("execution/approval-requests/") for path in seen):
        raise DigestError(
            "approval requests must not be self-referential digest inputs"
        )
    return manifest, normalized


def compute_control_plane_digest(
    root: Path, inputs: Iterable[dict[str, Any]] | None = None
) -> tuple[str, list[dict[str, str]]]:
    """Compute aggregate and per-component digests for declared inputs."""

    root = root.resolve()
    if inputs is None:
        _, declared_inputs = read_input_manifest(root)
    else:
        declared_inputs = list(inputs)
    components: list[dict[str, str]] = []
    for entry in declared_inputs:
        declared = entry["path"]
        declared_path = root / Path(declared)
        if declared_path.is_symlink():
            raise DigestError(f"symlink control-plane input is not allowed: {declared}")
        path = _safe_repo_path(root, declared)
        if not path.is_file():
            raise DigestError(f"required control-plane input is missing: {declared}")
        digest = _component_digest(path, entry["kind"])
        components.append({"path": declared, "digest": digest})
    components.sort(key=lambda item: item["path"].encode("utf-8"))
    aggregate = sha256_bytes(canonical_json_bytes(components))
    return aggregate, components


def aggregate_selected_components(
    components: Iterable[dict[str, str]], prefixes: Iterable[str]
) -> str:
    selected = [
        item
        for item in components
        if any(item["path"].startswith(prefix) for prefix in prefixes)
    ]
    selected.sort(key=lambda item: item["path"].encode("utf-8"))
    if not selected:
        raise DigestError(f"no components match prefixes: {list(prefixes)!r}")
    return sha256_bytes(canonical_json_bytes(selected))


def approval_digest_groups(components: list[dict[str, str]]) -> dict[str, str]:
    """Return the named digest groups required by the B00 review request."""

    by_path = {item["path"]: item["digest"] for item in components}
    required_paths = {
        "agentapi-doctor-Plan.md",
        "AGENTS.md",
        "execution/phases/P00.yaml",
        "execution/evaluators/catalog.yaml",
        "execution/evidence-schemas/catalog.yaml",
        "execution/metrics/definitions.yaml",
        "execution/impact-map.yaml",
        "execution/product-stage-map.yaml",
        "test/bootstrap/test_phasegate.py",
        "test/bootstrap/test_protected_verifier.py",
        "execution/protected-verifier/trust-policy.yaml",
        "execution/protected-verifier/workflow-contract.yaml",
        ".github/workflows/p00-protected-verifier-candidate.yml",
        ".github/workflows/p00-protected-control-plane.yml",
        ".github/workflows/p00-protected-state-writer.yml",
        ".github/workflows/p00-bootstrap-cross-platform.yml",
    }
    missing = sorted(required_paths - by_path.keys())
    if missing:
        raise DigestError(f"cannot build approval digest groups; missing {missing}")
    return {
        "planDigest": by_path["agentapi-doctor-Plan.md"],
        "agentInstructionsDigest": by_path["AGENTS.md"],
        "aggregateContractDigest": by_path["execution/phases/P00.yaml"],
        "gateRunnerDigest": aggregate_selected_components(
            components, ["tools/phasegate/"]
        ),
        "workUnitContractSetDigest": aggregate_selected_components(
            components, ["execution/work-units/"]
        ),
        "gateDefinitionSetDigest": aggregate_selected_components(
            components, ["execution/gates/p00/"]
        ),
        "evaluatorCatalogDigest": by_path["execution/evaluators/catalog.yaml"],
        "evidenceSchemaCatalogDigest": by_path[
            "execution/evidence-schemas/catalog.yaml"
        ],
        "metricDefinitionsDigest": by_path["execution/metrics/definitions.yaml"],
        "protectedCatalogSetDigest": aggregate_selected_components(
            components, ["execution/catalogs/p00/"]
        ),
        "impactMapDigest": by_path["execution/impact-map.yaml"],
        "productStageMapDigest": by_path["execution/product-stage-map.yaml"],
        "antiPlaceholderTestDigest": by_path["test/bootstrap/test_phasegate.py"],
        "protectedVerifierTestDigest": by_path[
            "test/bootstrap/test_protected_verifier.py"
        ],
        "protectedVerifierPolicySetDigest": aggregate_selected_components(
            components, ["execution/protected-verifier/"]
        ),
        "protectedWorkflowDigest": by_path[
            ".github/workflows/p00-protected-verifier-candidate.yml"
        ],
        "protectedControlPlaneWorkflowDigest": by_path[
            ".github/workflows/p00-protected-control-plane.yml"
        ],
        "protectedStateWriterWorkflowDigest": by_path[
            ".github/workflows/p00-protected-state-writer.yml"
        ],
        "crossPlatformWorkflowDigest": by_path[
            ".github/workflows/p00-bootstrap-cross-platform.yml"
        ],
    }
