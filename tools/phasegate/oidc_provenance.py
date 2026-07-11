"""GitHub Actions OIDC provenance for protected workflow statements.

The verifier is configured once from an externally pinned trust policy, JWK
snapshot, source commit, namespace, and exact approved component digest map.
Its authority digest is embedded in the signed statement; the OIDC audience
then binds the canonical statement digest.  This creates one closed chain from
the real GitHub workflow identity to actor, source, control plane, and executed
component approval semantics.

The MACHINE result writer is deliberately in-memory.  It consumes only a
provenance-sealed freeze and the public sealed gate-runner projection, obtains
one token through an injected provider (or the restricted Actions endpoint),
and returns only after the normal provenance verifier accepts its own output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping
from urllib import parse, request
import weakref

from .digest import canonical_json_bytes, sha256_bytes
from .gate_runner import (
    GateRunnerError,
    SealedRunPair,
    criterion_result_projection,
)
from .oidc import (
    OidcVerificationError,
    validate_jwks_snapshot,
    verify_github_actions_oidc_token,
)
from .protected import (
    ProtectedVerificationError,
    _exact_keys,
    _parse_utc,
    _require_commit,
    _require_sha256,
    document_digest,
)
from .protected_v2 import OIDC_PROVENANCE_AUDIENCE_PREFIX
from .provenance import (
    CRITERION_KIND,
    CRITERION_SCHEMA,
    MACHINE_CRITERION_NAMESPACE,
    VerifiedCriterionResult,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    verify_signed_criterion_result,
)
from .state_chain_v2 import (
    EXECUTED_VERIFIER_PATHS,
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    require_verified_state_context_v2,
)


OIDC_SIGNATURE_SCHEME = "github-actions-oidc-jwt-rs256-v1"
AUTHORITY_SCHEMA = "urn:agentapi-doctor:oidc-provenance-authority:v1alpha1"
AUTHORITY_KIND = "ProtectedWorkflowOidcAuthority"
MAX_OIDC_RESPONSE_BYTES = 65_536
MAX_STATEMENT_BYTES = 4 * 1024 * 1024
MAX_COMPONENT_BYTES = 4 * 1024 * 1024
RESULT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

TokenProvider = Callable[[str], str]


@dataclass
class OidcProvenanceError(ValueError):
    """Stable, secret-free OIDC provenance failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class OidcProvenanceVerifier:
    """Identity-sealed callback implementing provenance ``SignerVerifier``."""

    namespace: str
    principal: str
    role: str
    organization: str
    policy_digest: str
    jwks_snapshot_digest: str
    control_plane_digest: str
    source_commit: str
    workflow_execution_commit: str
    approval_digest: str
    bootstrap_request_digest: str
    chain_head_digest: str
    state_digest: str
    component_set_digest: str
    component_digests: tuple[tuple[str, str], ...]
    expected_claims: tuple[tuple[str, str], ...]
    authority_digest: str
    approved_jwks_json: str = field(repr=False)

    def __call__(
        self, payload: bytes, signature: Mapping[str, Any], namespace: str
    ) -> VerifiedSignerResult:
        return _verify_signature(self, payload, signature, namespace)


_VERIFIED_AUTHORITIES: dict[
    int, weakref.ReferenceType[OidcProvenanceVerifier]
] = {}


def _fail(code: str, path: str, message: str) -> None:
    raise OidcProvenanceError(code, path, message)


def _mark_verified(value: OidcProvenanceVerifier) -> OidcProvenanceVerifier:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[OidcProvenanceVerifier]) -> None:
        if _VERIFIED_AUTHORITIES.get(identity) is reference:
            _VERIFIED_AUTHORITIES.pop(identity, None)

    _VERIFIED_AUTHORITIES[identity] = weakref.ref(value, discard)
    return value


def _require_verified(value: Any, path: str = "oidcVerifier") -> None:
    reference = _VERIFIED_AUTHORITIES.get(id(value))
    if (
        not isinstance(value, OidcProvenanceVerifier)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_oidc_authority",
            path,
            "expected the exact verifier returned by the protected factory",
        )


def _strict_json_bytes(
    payload: bytes, path: str, *, require_canonical: bool = True
) -> Any:
    if not isinstance(payload, bytes) or len(payload) > MAX_STATEMENT_BYTES:
        _fail("invalid_statement", path, "statement must be bounded bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_statement", path, "statement is not UTF-8")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("duplicate_statement_key", path, "duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_token: str) -> Any:
        _fail("invalid_statement", path, "non-finite JSON number is forbidden")

    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError:
        _fail("invalid_statement", path, "statement is not strict JSON")
    if require_canonical:
        try:
            canonical = canonical_json_bytes(value)
        except Exception:
            _fail("invalid_statement", path, "statement is not canonical JSON data")
        if canonical != payload:
            _fail(
                "noncanonical_statement",
                path,
                "callback requires canonical payload bytes",
            )
    return value


def _snapshot_json(value: Any, path: str) -> Any:
    try:
        return json.loads(canonical_json_bytes(value).decode("utf-8"))
    except Exception:
        _fail("invalid_canonical_input", path, "value is not canonical JSON data")


def _format_utc(value: datetime, path: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("invalid_timestamp", path, "timezone-aware datetime required")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_timestamp", path, "timestamp must have second precision")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _component_map(value: Any, required_paths: list[str]) -> tuple[tuple[str, str], ...]:
    if (
        not isinstance(value, Mapping)
        or not value
        or len(value) > 512
        or not set(required_paths).issubset(value)
        or any(
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in path.split("/")
            for path in value
        )
    ):
        _fail(
            "component_approval_mismatch",
            "current.approvedComponentDigests",
            "sealed pins must contain every policy-required executed component",
        )
    result = []
    for path in sorted(value):
        digest = value[path]
        try:
            _require_sha256(digest, f"current.approvedComponentDigests.{path}")
        except ProtectedVerificationError as exc:
            _fail(exc.code, exc.path, exc.message)
        result.append((path, digest))
    return tuple(result)


def _verify_component_blob(
    *, repo_root: Path, commit: str, path: str, expected_digest: str
) -> None:
    git = Path("/usr/bin/git")
    if not git.is_file() or git.is_symlink() or not os.access(git, os.X_OK):
        _fail("git_verifier_unavailable", str(git), "fixed Git executable unavailable")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
    }
    try:
        tree = subprocess.run(
            [
                str(git),
                "-c",
                "core.pager=cat",
                "-C",
                str(repo_root),
                "ls-tree",
                "-z",
                commit,
                "--",
                path,
            ],
            check=False,
            capture_output=True,
            timeout=20,
            env=environment,
        )
        size = subprocess.run(
            [
                str(git),
                "-c",
                "core.pager=cat",
                "-C",
                str(repo_root),
                "cat-file",
                "-s",
                f"{commit}:{path}",
            ],
            check=False,
            capture_output=True,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(
            "git_verifier_unavailable",
            "workflowCommit",
            "fixed Git blob verification failed",
        )
    entries = tree.stdout.rstrip(b"\x00").split(b"\x00") if tree.stdout else []
    if tree.returncode != 0 or len(entries) != 1:
        _fail(
            "approved_component_unavailable",
            path,
            "cannot resolve exact approved component at workflow commit",
        )
    try:
        component_size = int(size.stdout.strip())
    except ValueError:
        _fail("approved_component_unavailable", path, "invalid Git blob size")
    if (
        size.returncode != 0
        or component_size < 0
        or component_size > MAX_COMPONENT_BYTES
    ):
        _fail(
            "approved_component_too_large",
            path,
            "approved executable component exceeds the bounded verifier limit",
        )
    metadata, separator, observed_path = entries[0].partition(b"\t")
    fields = metadata.split(b" ")
    try:
        observed_path_text = observed_path.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("unsafe_approved_component", path, "component path is not UTF-8")
    if (
        not separator
        or observed_path_text != path
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        _fail(
            "unsafe_approved_component",
            path,
            "approved component must be one exact regular Git blob",
        )
    try:
        blob = subprocess.run(
            [
                str(git),
                "-c",
                "core.pager=cat",
                "-C",
                str(repo_root),
                "show",
                f"{commit}:{path}",
            ],
            check=False,
            capture_output=True,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(
            "git_verifier_unavailable",
            "workflowCommit",
            "fixed Git blob verification failed",
        )
    if blob.returncode != 0:
        _fail(
            "approved_component_unavailable",
            path,
            "cannot read exact approved component at workflow commit",
        )
    if sha256_bytes(blob.stdout) != expected_digest:
        _fail(
            "approved_component_digest_mismatch",
            path,
            "executed workflow component differs from approved digest",
        )


def _verify_descendant_commit(
    repo_root: Path, *, ancestor: str, descendant: str
) -> None:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(
            "git_lineage_verifier_unavailable",
            "currentSourceCommit",
            "fixed Git lineage verification failed",
        )
    if completed.returncode != 0:
        _fail(
            "source_commit_not_descendant",
            "currentSourceCommit",
            "current protected-main commit must descend from the sealed chain head",
        )


def _sealed_context(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> tuple[VerifiedGenesisAnchorV2 | VerifiedStateChainV2, str]:
    try:
        sealed = require_verified_state_context_v2(current)
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    head_digest = (
        sealed.chain_head_digest
        if isinstance(sealed, VerifiedGenesisAnchorV2)
        else sealed.head_digest
    )
    return sealed, head_digest


def _policy_context(
    policy_result: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_control_plane_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        _require_sha256(expected_policy_digest, "external.expectedPolicyDigest")
        _require_sha256(
            expected_control_plane_digest, "external.expectedControlPlaneDigest"
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if not isinstance(policy_result, Mapping):
        _fail("invalid_policy_result", "policyResult", "validated policy is required")
    document = policy_result.get("document")
    if not isinstance(document, dict):
        _fail("invalid_policy_result", "policyResult.document", "policy is missing")
    if (
        policy_result.get("digest") != expected_policy_digest
        or document_digest(document) != expected_policy_digest
    ):
        _fail(
            "trust_policy_digest_mismatch",
            "policyResult",
            "validated policy differs from external pin",
        )
    if document.get("controlPlaneDigest") != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "policyResult.document.controlPlaneDigest",
            "policy differs from control-plane pin",
        )
    machine_policy = policy_result.get("machineProvenance")
    document_policy = document.get("signatureSchemes", {}).get(
        "machineProvenance"
    )
    if not isinstance(machine_policy, dict) or machine_policy != document_policy:
        _fail(
            "invalid_policy_result",
            "policyResult.machineProvenance",
            "validated machine provenance projection is missing",
        )
    signer = policy_result.get("stateSigner")
    if (
        not isinstance(signer, dict)
        or machine_policy.get("signerPolicyRef") != "githubActionsStateSigner"
    ):
        _fail(
            "invalid_machine_provenance_policy",
            "policyResult.machineProvenance",
            "protected signer policy is missing",
        )
    return machine_policy, signer


def build_oidc_provenance_verifier(
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    policy_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
    repo_root: Path,
    current_source_commit: str,
    current_workflow_execution_commit: str,
    expected_namespace: str,
) -> OidcProvenanceVerifier:
    """Build one sealed, namespace-specific protected-workflow callback."""

    sealed, current_chain_head_digest = _sealed_context(current)
    expected_policy_digest = sealed.trust_policy_digest
    expected_jwks_snapshot_digest = sealed.jwks_snapshot_digest
    expected_control_plane_digest = sealed.control_plane_digest
    machine_policy, signer = _policy_context(
        policy_result,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
    )
    try:
        source_commit = _require_commit(
            current_source_commit, "currentSourceCommit"
        )
        workflow_commit = _require_commit(
            current_workflow_execution_commit,
            "currentWorkflowExecutionCommit",
        )
        _require_sha256(
            expected_jwks_snapshot_digest,
            "external.expectedJwksSnapshotDigest",
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if source_commit != workflow_commit:
        _fail(
            "source_workflow_commit_mismatch",
            "currentWorkflowExecutionCommit",
            "statement source and protected workflow commit must be identical",
        )
    allowed_namespaces = machine_policy.get("allowedNamespaces")
    if (
        not isinstance(expected_namespace, str)
        or not isinstance(allowed_namespaces, list)
        or expected_namespace not in allowed_namespaces
    ):
        _fail(
            "provenance_namespace_not_allowed",
            "external.expectedNamespace",
            "namespace is outside protected machine provenance policy",
        )
    if machine_policy.get("audiencePrefix") != OIDC_PROVENANCE_AUDIENCE_PREFIX:
        _fail(
            "invalid_machine_provenance_policy",
            "policyResult.machineProvenance.audiencePrefix",
            "audience prefix drift",
        )
    required_paths = machine_policy.get("requiredComponentPaths")
    workflow_path = signer.get("workflowPath")
    if not isinstance(workflow_path, str) or not workflow_path:
        _fail(
            "invalid_oidc_signer_policy",
            "policyResult.stateSigner.workflowPath",
            "protected workflow path is missing",
        )
    expected_required_paths = sorted(
        (workflow_path, *EXECUTED_VERIFIER_PATHS)
    )
    if (
        not isinstance(required_paths, list)
        or required_paths != expected_required_paths
    ):
        _fail(
            "invalid_machine_provenance_policy",
            "policyResult.machineProvenance.requiredComponentPaths",
            "component policy differs from the StateEvent executed path set",
        )
    components = _component_map(
        dict(sealed.approved_component_digests), required_paths
    )
    try:
        repository = Path(repo_root).resolve(strict=True)
    except (OSError, TypeError):
        _fail("invalid_repository", "repoRoot", "repository root is unavailable")
    if not repository.is_dir():
        _fail("invalid_repository", "repoRoot", "repository root must be a directory")
    _verify_descendant_commit(
        repository,
        ancestor=sealed.head_source_commit,
        descendant=source_commit,
    )
    approved_component_map = dict(components)
    executed_components = tuple(
        (path, approved_component_map[path]) for path in required_paths
    )
    for component_path, component_digest in executed_components:
        _verify_component_blob(
            repo_root=repository,
            commit=workflow_commit,
            path=component_path,
            expected_digest=component_digest,
        )
    component_document = {path: digest for path, digest in components}
    component_set_digest = sha256_bytes(
        canonical_json_bytes({"componentDigests": component_document})
    )
    try:
        snapshot_result = validate_jwks_snapshot(
            approved_jwks_snapshot,
            expected_snapshot_digest=expected_jwks_snapshot_digest,
        )
    except OidcVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    policy_jwks = policy_result.get("jwks")
    if (
        not isinstance(policy_jwks, dict)
        or policy_jwks.get("digest") != snapshot_result["digest"]
    ):
        _fail(
            "oidc_jwks_snapshot_digest_mismatch",
            "policyResult.jwks",
            "snapshot differs from validated trust policy",
        )
    if document_digest(signer) != sealed.state_signer_digest:
        _fail(
            "state_signer_digest_mismatch",
            "policyResult.stateSigner",
            "OIDC signer differs from the sealed Genesis authority",
        )
    actor_ids = signer.get("allowedActorIds")
    if actor_ids != ["6668626"]:
        _fail(
            "invalid_oidc_signer_policy",
            "policyResult.stateSigner.allowedActorIds",
            "exact protected actor ID is required",
        )
    expected_claims = {
        "repository": signer.get("repository"),
        "repository_id": signer.get("repositoryId"),
        "repository_owner": signer.get("repositoryOwner"),
        "repository_owner_id": signer.get("repositoryOwnerId"),
        "repository_visibility": signer.get("repositoryVisibility"),
        "event_name": signer.get("eventName"),
        "ref": signer.get("ref"),
        "ref_type": signer.get("refType"),
        "ref_protected": signer.get("refProtected"),
        "runner_environment": signer.get("runnerEnvironment"),
        "actor_id": actor_ids[0],
        "workflow_ref": signer.get("workflowRef"),
        "workflow_sha": workflow_commit,
        "sha": workflow_commit,
    }
    if any(not isinstance(value, str) for value in expected_claims.values()):
        _fail(
            "invalid_oidc_signer_policy",
            "policyResult.stateSigner",
            "all protected claim pins must be strings",
        )
    if (
        expected_claims["repository_visibility"] != "public"
        or expected_claims["ref"] != "refs/heads/main"
        or expected_claims["ref_type"] != "branch"
        or expected_claims["ref_protected"] != "true"
        or expected_claims["event_name"] != "workflow_dispatch"
        or expected_claims["runner_environment"] != "github-hosted"
        or machine_policy.get("runAttempt") != "1"
        or machine_policy.get("shaMustEqualWorkflowSha") is not True
        or machine_policy.get("headAndBaseRefMustBeAbsent") is not True
    ):
        _fail(
            "invalid_machine_provenance_policy",
            "policyResult.machineProvenance",
            "public protected-main claim policy drift",
        )
    actor = {
        "principal": signer.get("identity"),
        "role": signer.get("role"),
        "organization": signer.get("organization"),
    }
    if actor["role"] != "protected-workflow" or any(
        not isinstance(value, str) or not value for value in actor.values()
    ):
        _fail(
            "invalid_oidc_signer_policy",
            "policyResult.stateSigner",
            "protected workflow actor policy is invalid",
        )
    authority_document = {
        "schemaVersion": AUTHORITY_SCHEMA,
        "kind": AUTHORITY_KIND,
        "namespace": expected_namespace,
        "actor": actor,
        "policyDigest": expected_policy_digest,
        "jwksSnapshotDigest": expected_jwks_snapshot_digest,
        "controlPlaneDigest": expected_control_plane_digest,
        "sourceCommit": source_commit,
        "workflowExecutionCommit": workflow_commit,
        "bootstrapWorkflowExecutionCommit": sealed.workflow_execution_commit,
        "approvalDigest": sealed.bootstrap_approval_digest,
        "bootstrapRequestDigest": sealed.bootstrap_request_digest,
        "chainHeadDigest": current_chain_head_digest,
        "stateDigest": sealed.state_digest,
        "componentSetDigest": component_set_digest,
        "componentDigests": component_document,
        "executedComponentDigests": dict(executed_components),
        "expectedClaimsDigest": sha256_bytes(
            canonical_json_bytes(expected_claims)
        ),
        "audiencePrefix": OIDC_PROVENANCE_AUDIENCE_PREFIX,
    }
    authority_digest = sha256_bytes(canonical_json_bytes(authority_document))
    keys_json = canonical_json_bytes(
        _snapshot_json(approved_jwks_snapshot["keys"], "jwks.keys")
    ).decode("utf-8")
    return _mark_verified(
        OidcProvenanceVerifier(
            namespace=expected_namespace,
            principal=actor["principal"],
            role=actor["role"],
            organization=actor["organization"],
            policy_digest=expected_policy_digest,
            jwks_snapshot_digest=expected_jwks_snapshot_digest,
            control_plane_digest=expected_control_plane_digest,
            source_commit=source_commit,
            workflow_execution_commit=workflow_commit,
            approval_digest=sealed.bootstrap_approval_digest,
            bootstrap_request_digest=sealed.bootstrap_request_digest,
            chain_head_digest=current_chain_head_digest,
            state_digest=sealed.state_digest,
            component_set_digest=component_set_digest,
            component_digests=components,
            expected_claims=tuple(sorted(expected_claims.items())),
            authority_digest=authority_digest,
            approved_jwks_json=keys_json,
        )
    )


make_oidc_provenance_signer_verifier = build_oidc_provenance_verifier


def _statement_bindings(
    verifier: OidcProvenanceVerifier, payload: bytes
) -> datetime:
    statement = _strict_json_bytes(payload, "payload")
    if not isinstance(statement, dict):
        _fail("invalid_statement", "payload", "statement must be an object")
    body = statement.get("body")
    if not isinstance(body, dict):
        _fail("invalid_statement", "payload.body", "body must be an object")
    actor = body.get("actor")
    expected_actor = {
        "principal": verifier.principal,
        "role": verifier.role,
        "organization": verifier.organization,
    }
    if actor != expected_actor:
        _fail(
            "actor_principal_mismatch",
            "payload.body.actor",
            "statement actor differs from protected workflow identity",
        )
    if body.get("authorityDigest") != verifier.authority_digest:
        _fail(
            "authority_digest_mismatch",
            "payload.body.authorityDigest",
            "statement authority differs from sealed OIDC verifier",
        )
    subject = body.get("subject")
    if not isinstance(subject, dict):
        _fail("invalid_statement", "payload.body.subject", "subject is required")
    if subject.get("sourceCommit") != verifier.source_commit:
        _fail(
            "source_commit_mismatch",
            "payload.body.subject.sourceCommit",
            "statement source differs from protected workflow commit",
        )
    if subject.get("controlPlaneDigest") != verifier.control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "payload.body.subject.controlPlaneDigest",
            "statement control plane differs from authority",
        )
    try:
        return _parse_utc(body.get("issuedAt"), "payload.body.issuedAt")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)


def _verify_signature(
    verifier: OidcProvenanceVerifier,
    payload: bytes,
    signature: Mapping[str, Any],
    namespace: str,
) -> VerifiedSignerResult:
    _require_verified(verifier)
    descriptor = _exact_keys(
        signature,
        {"scheme", "namespace", "principal", "value"},
        "signature",
    )
    if descriptor["scheme"] != OIDC_SIGNATURE_SCHEME:
        _fail(
            "unsupported_signature_scheme",
            "signature.scheme",
            "protected workflow provenance requires GitHub OIDC RS256",
        )
    if (
        namespace != verifier.namespace
        or descriptor["namespace"] != verifier.namespace
    ):
        _fail(
            "signature_namespace_mismatch",
            "signature.namespace",
            "OIDC token cannot be replayed across provenance domains",
        )
    if descriptor["principal"] != verifier.principal:
        _fail(
            "actor_principal_mismatch",
            "signature.principal",
            "signature principal differs from protected workflow identity",
        )
    token = descriptor["value"]
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token) > 32_768
    ):
        _fail("invalid_oidc_token", "signature.value", "JWT must be bounded ASCII")
    statement_timestamp = _statement_bindings(verifier, payload)
    statement_digest = sha256_bytes(payload)
    expected_audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + statement_digest
    try:
        claims = verify_github_actions_oidc_token(
            token,
            approved_jwks=json.loads(verifier.approved_jwks_json),
            expected_audience=expected_audience,
            expected_claims=dict(verifier.expected_claims),
            statement_timestamp=statement_timestamp,
        )
    except OidcVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    for claim in ("head_ref", "base_ref"):
        if claim in claims:
            _fail(
                "oidc_pull_request_claim_forbidden",
                f"jwt.claims.{claim}",
                "protected-main provenance requires the PR ref claim to be absent",
            )
    return VerifiedSignerResult(
        scheme=OIDC_SIGNATURE_SCHEME,
        namespace=verifier.namespace,
        principal=verifier.principal,
        role=verifier.role,
        organization=verifier.organization,
        statement_digest=statement_digest,
        authority_digest=verifier.authority_digest,
        source_commit=verifier.source_commit,
        control_plane_digest=verifier.control_plane_digest,
    )


def github_actions_provenance_token_provider(
    audience: str,
    *,
    environ: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> str:
    """Acquire one token only from the fixed GitHub Actions OIDC boundary."""

    environment = os.environ if environ is None else environ
    if environment.get("GITHUB_ACTIONS") != "true":
        _fail(
            "not_github_actions",
            "environment.GITHUB_ACTIONS",
            "default token acquisition is restricted to GitHub Actions",
        )
    endpoint = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not endpoint or not bearer:
        _fail(
            "missing_oidc_environment",
            "environment",
            "GitHub Actions OIDC request variables are unavailable",
        )
    if (
        not isinstance(audience, str)
        or not audience.startswith(OIDC_PROVENANCE_AUDIENCE_PREFIX + "sha256:")
    ):
        _fail("invalid_audience", "audience", "provenance audience prefix mismatch")
    parsed = parse.urlsplit(endpoint)
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        _fail("unsafe_oidc_endpoint", "environment", "invalid endpoint port")
    if (
        parsed.scheme != "https"
        or not hostname.endswith(".actions.githubusercontent.com")
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path
    ):
        _fail(
            "unsafe_oidc_endpoint",
            "environment.ACTIONS_ID_TOKEN_REQUEST_URL",
            "OIDC endpoint must be an HTTPS GitHub Actions host",
        )
    query = parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(name == "audience" for name, _ in query):
        _fail(
            "unsafe_oidc_endpoint",
            "environment.ACTIONS_ID_TOKEN_REQUEST_URL",
            "OIDC request URL must not preselect an audience",
        )
    query.append(("audience", audience))
    target = parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parse.urlencode(query), "")
    )
    oidc_request = request.Request(
        target,
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        method="GET",
    )
    opener = request.urlopen if urlopen is None else urlopen
    try:
        with opener(oidc_request, timeout=10) as response:
            payload = response.read(MAX_OIDC_RESPONSE_BYTES + 1)
    except Exception:
        _fail(
            "oidc_request_failed",
            "tokenProvider",
            "GitHub Actions OIDC token request failed",
        )
    if len(payload) > MAX_OIDC_RESPONSE_BYTES:
        _fail("oidc_response_too_large", "tokenProvider", "response is too large")
    document = _strict_json_bytes(
        payload, "tokenProvider", require_canonical=False
    )
    if not isinstance(document, dict) or set(document) != {"value"}:
        _fail("invalid_oidc_response", "tokenProvider", "response field set invalid")
    token = document["value"]
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token) > 32_768
    ):
        _fail("invalid_oidc_response", "tokenProvider", "OIDC JWT is invalid")
    return token


def _criterion_document(criterion: Any) -> dict[str, str]:
    return {
        "id": criterion.criterion_id,
        "kind": criterion.kind,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "evaluatorStatus": "implemented",
        "evidenceSchema": criterion.evidence_schema,
        "evidenceSchemaDigest": criterion.evidence_schema_digest,
        "datasetDigest": criterion.dataset_digest,
        "thresholdDigest": criterion.threshold_digest,
    }


def create_signed_machine_criterion_result(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedRunPair,
    verifier: OidcProvenanceVerifier,
    issued_at: datetime,
    result_id: str | None = None,
    token_provider: TokenProvider | None = None,
) -> tuple[dict[str, Any], VerifiedCriterionResult]:
    """Create and self-verify one OIDC-backed MACHINE criterion result."""

    _require_verified(verifier)
    if verifier.namespace != MACHINE_CRITERION_NAMESPACE:
        _fail(
            "provenance_namespace_not_allowed",
            "oidcVerifier.namespace",
            "MACHINE writer requires the machine criterion namespace",
        )
    try:
        projection = criterion_result_projection(
            freeze=freeze,
            criterion_id=criterion_id,
            run_pair=run_pair,
        )
    except GateRunnerError as exc:
        _fail(exc.code, exc.path, exc.message)
    if (
        freeze.subject.source_commit != verifier.source_commit
        or freeze.subject.control_plane_digest != verifier.control_plane_digest
    ):
        _fail(
            "freeze_authority_mismatch",
            "freeze.subject",
            "sealed freeze source/control differs from OIDC authority",
        )
    matches = [
        criterion
        for criterion in freeze.criteria
        if criterion.criterion_id == criterion_id
    ]
    if len(matches) != 1 or matches[0].kind != "MACHINE":
        _fail("invalid_machine_criterion", "criterionId", "exact MACHINE criterion required")
    criterion = matches[0]
    timestamp = _format_utc(issued_at, "issuedAt")
    pair_document = _snapshot_json(projection["runPair"], "runPair")
    pair_digest = document_digest(pair_document)
    if (
        pair_digest != projection["runPairDigest"]
        or pair_digest != projection["evidenceDigest"]
    ):
        _fail(
            "run_pair_digest_mismatch",
            "runPair",
            "detached runPair differs from the sealed projection",
        )
    if result_id is None:
        result_id = (
            "machine-"
            + criterion_id.lower()
            + "-"
            + pair_digest.removeprefix("sha256:")[:24]
        )
    if not isinstance(result_id, str) or not RESULT_ID_RE.fullmatch(result_id):
        _fail("invalid_result_id", "resultId", "invalid bounded result ID")
    body = {
        "resultId": result_id,
        "freezeDigest": freeze.attestation_digest,
        "subject": {
            "phase": freeze.subject.phase,
            "workUnit": freeze.subject.work_unit,
            "sourceCommit": freeze.subject.source_commit,
            "controlPlaneDigest": freeze.subject.control_plane_digest,
            "contractDigest": freeze.subject.contract_digest,
        },
        "criterion": _criterion_document(criterion),
        "outcome": projection["outcome"],
        "evidenceDigest": pair_digest,
        "runPair": pair_document,
        "runPairDigest": pair_digest,
        "humanReview": None,
        "issuedAt": timestamp,
        "actor": {
            "principal": verifier.principal,
            "role": verifier.role,
            "organization": verifier.organization,
        },
        "authorityDigest": verifier.authority_digest,
    }
    statement = {
        "schemaVersion": CRITERION_SCHEMA,
        "kind": CRITERION_KIND,
        "body": body,
    }
    payload = canonical_json_bytes(statement)
    audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + sha256_bytes(payload)
    provider = (
        github_actions_provenance_token_provider
        if token_provider is None
        else token_provider
    )
    try:
        token = provider(audience)
    except OidcProvenanceError:
        raise
    except Exception:
        _fail("token_provider_failed", "tokenProvider", "OIDC token provider failed")
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token) > 32_768
    ):
        _fail("invalid_oidc_token", "tokenProvider", "provider returned no JWT")
    envelope = {
        **statement,
        "signature": {
            "scheme": OIDC_SIGNATURE_SCHEME,
            "namespace": MACHINE_CRITERION_NAMESPACE,
            "principal": verifier.principal,
            "value": token,
        },
    }
    envelope["attestationDigest"] = document_digest(envelope)
    try:
        result = verify_signed_criterion_result(
            envelope,
            freeze=freeze,
            expected_authority_digest=verifier.authority_digest,
            signer_verifier=verifier,
        )
    except (ProtectedVerificationError, OidcProvenanceError) as exc:
        _fail(exc.code, exc.path, exc.message)
    return envelope, result


__all__ = [
    "OIDC_PROVENANCE_AUDIENCE_PREFIX",
    "OIDC_SIGNATURE_SCHEME",
    "OidcProvenanceError",
    "OidcProvenanceVerifier",
    "build_oidc_provenance_verifier",
    "create_signed_machine_criterion_result",
    "github_actions_provenance_token_provider",
    "make_oidc_provenance_signer_verifier",
]
