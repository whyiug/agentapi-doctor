"""Read-only verification for protected approvals and signed execution state.

This module deliberately contains no signing or state-event creation API.  A
protected workflow may call it with externally pinned trust, subject, and chain
digests.  Repository-controlled policy alone is never treated as a trust root.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

from .digest import DigestError, canonical_json_bytes, load_json_yaml, sha256_bytes


POLICY_SCHEMA = "urn:agentapi-doctor:protected-verifier-policy:v1alpha1"
POLICY_KIND = "ProtectedVerifierTrustPolicy"
APPROVAL_SCHEMA = "urn:agentapi-doctor:control-plane-approval:v1alpha1"
APPROVAL_KIND = "ControlPlaneApprovalAttestation"
STATE_EVENT_SCHEMA = "urn:agentapi-doctor:state-event:v1alpha1"
STATE_EVENT_KIND = "SignedStateEvent"
STATE_VIEW_SCHEMA = "urn:agentapi-doctor:execution:v1alpha1"

APPROVAL_NAMESPACE = "agentapi-doctor/control-plane-approval/v1"
STATE_EVENT_NAMESPACE = "agentapi-doctor/state-event/v1"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EVENT_ID_RE = re.compile(r"^evt-([0-9]{8})$")
EVENT_FILE_RE = re.compile(r"^([0-9]{8})\.json$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}$")
RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "NOT_STARTED": ("READY", "REJECTED", "SUPERSEDED"),
    "READY": ("ACTIVE", "REJECTED", "SUPERSEDED"),
    "ACTIVE": ("MACHINE_CONVERGED", "BLOCKED", "REJECTED", "SUPERSEDED"),
    "BLOCKED": ("ACTIVE", "REJECTED", "SUPERSEDED"),
    "MACHINE_CONVERGED": (
        "CONVERGED",
        "WAITING_EXTERNAL",
        "REVIEW_PENDING",
        "REJECTED",
    ),
    "WAITING_EXTERNAL": ("CONVERGED", "REVIEW_PENDING", "REJECTED"),
    "REVIEW_PENDING": ("CONVERGED", "REJECTED"),
    "CONVERGED": ("REJECTED",),
    "REJECTED": ("READY",),
    "SUPERSEDED": (),
}

REQUIRED_EXTERNAL_PINS = (
    "trustPolicyDigest",
    "controlPlaneDigest",
    "candidateSourceCommit",
    "requestDigest",
    "chainHeadDigest",
    "sshKeygenDigest",
)

CAPABILITIES = {"approve-control-plane", "sign-state-event"}
PREVIOUS_REQUEST_DIGEST = (
    "sha256:54c8a29baafb06c13d3d3eb35183bd95aab44ea63f638c53c997da5d60ddb8de"
)
PREVIOUS_CONTROL_PLANE_DIGEST = (
    "sha256:b37b85c688c099899421740d4a82ff4405aba1daed195cdb5c58b0b0889eca77"
)
PREVIOUS_CANDIDATE_COMMIT = "1e2409c24231b83c09a93ee18764cce9ee1a4efc"
PENDING_STATUSES = {
    "MACHINE_CONVERGED",
    "BLOCKED",
    "WAITING_EXTERNAL",
    "REVIEW_PENDING",
}


@dataclass
class ProtectedVerificationError(ValueError):
    """A stable, fail-closed verifier error suitable for CLI JSON output."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> None:
    raise ProtectedVerificationError(code, path, message)


def _exact_keys(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("invalid_schema", path, "must be an object")
    actual = set(value)
    if actual != expected:
        _fail(
            "invalid_schema",
            path,
            f"field set mismatch; missing={sorted(expected - actual)}, extra={sorted(actual - expected)}",
        )
    return value


def _require_sha256(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _require_commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        _fail("invalid_source_commit", path, "expected a lowercase 40-hex Git SHA-1")
    return value


def _require_nonempty(value: Any, path: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _fail(
            "invalid_schema",
            path,
            f"must be a non-empty string up to {maximum} characters",
        )
    if "\x00" in value:
        _fail("invalid_schema", path, "NUL is forbidden")
    return value


def _parse_utc(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC_RE.fullmatch(value):
        _fail(
            "invalid_timestamp", path, "expected second-precision RFC3339 UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        _fail("invalid_timestamp", path, str(exc))
    return parsed


def _now_utc(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        _fail("invalid_timestamp", "now", "verification time must be timezone-aware")
    return current.astimezone(timezone.utc)


def document_digest(value: Any, *, omit_field: str | None = None) -> str:
    """Digest a strict canonical JSON value, optionally omitting one top-level field."""

    projected = deepcopy(value)
    if omit_field is not None:
        if not isinstance(projected, dict) or omit_field not in projected:
            _fail("invalid_schema", omit_field, "digest field is missing")
        del projected[omit_field]
    try:
        return sha256_bytes(canonical_json_bytes(projected))
    except DigestError as exc:
        _fail("invalid_schema", "document", str(exc))


def _reject_symlink_components(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            _fail(
                "unsafe_input_path",
                label,
                f"symlink path component is forbidden: {cursor}",
            )
    return absolute


def load_strict_document(path: Path, *, label: str) -> Any:
    """Load one regular, non-symlink, strict JSON-compatible YAML document."""

    path = _reject_symlink_components(path, label)
    try:
        metadata = path.stat()
    except OSError as exc:
        _fail("missing_input", label, str(exc))
    if not stat.S_ISREG(metadata.st_mode):
        _fail("unsafe_input_path", label, "input must be a regular file")
    try:
        return load_json_yaml(path)
    except DigestError as exc:
        _fail("invalid_json_document", label, str(exc))


def _ssh_public_key_fingerprint(public_key: str, path: str) -> str:
    fields = public_key.split(" ")
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        _fail(
            "unsupported_public_key",
            path,
            "only comment-free ssh-ed25519 keys are allowed",
        )
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        _fail("invalid_public_key", path, f"invalid SSH public-key base64: {exc}")
    if len(blob) < 4:
        _fail("invalid_public_key", path, "truncated SSH public-key blob")
    algorithm_length = int.from_bytes(blob[:4], "big")
    algorithm_end = 4 + algorithm_length
    if blob[4:algorithm_end] != b"ssh-ed25519" or len(blob) < algorithm_end + 4:
        _fail("invalid_public_key", path, "SSH key blob algorithm mismatch")
    key_length = int.from_bytes(blob[algorithm_end : algorithm_end + 4], "big")
    key = blob[algorithm_end + 4 :]
    if key_length != 32 or len(key) != 32:
        _fail("invalid_public_key", path, "Ed25519 public key must be 32 bytes")
    encoded = (
        base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    )
    return f"SHA256:{encoded}"


def _validate_principal(entry: Any, index: int) -> dict[str, Any]:
    path = f"policy.principals[{index}]"
    principal = _exact_keys(
        entry,
        {
            "identity",
            "organization",
            "role",
            "publicKey",
            "fingerprint",
            "capabilities",
            "validFrom",
            "validUntil",
        },
        path,
    )
    identity = principal["identity"]
    if not isinstance(identity, str) or not PRINCIPAL_RE.fullmatch(identity):
        _fail(
            "invalid_principal",
            f"{path}.identity",
            "principal must be exact ASCII without wildcards",
        )
    organization = _require_nonempty(
        principal["organization"], f"{path}.organization", maximum=256
    )
    role = _require_nonempty(principal["role"], f"{path}.role", maximum=128)
    if not role.isascii() or not organization.isascii():
        _fail(
            "invalid_principal", path, "role and organization must be unambiguous ASCII"
        )
    public_key = _require_nonempty(
        principal["publicKey"], f"{path}.publicKey", maximum=1024
    )
    fingerprint = _ssh_public_key_fingerprint(public_key, f"{path}.publicKey")
    if principal["fingerprint"] != fingerprint:
        _fail(
            "public_key_fingerprint_mismatch",
            f"{path}.fingerprint",
            "fingerprint does not match public key",
        )
    capabilities = principal["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(item, str) for item in capabilities)
        or capabilities != sorted(set(capabilities))
        or not set(capabilities).issubset(CAPABILITIES)
    ):
        _fail(
            "invalid_capabilities",
            f"{path}.capabilities",
            "capabilities must be a sorted unique supported list",
        )
    valid_from = _parse_utc(principal["validFrom"], f"{path}.validFrom")
    valid_until = _parse_utc(principal["validUntil"], f"{path}.validUntil")
    if valid_from >= valid_until:
        _fail("invalid_principal_validity", path, "validFrom must precede validUntil")
    return principal


def validate_trust_policy(
    policy: Any,
    *,
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    require_configured: bool = True,
) -> dict[str, Any]:
    """Validate policy semantics and its externally supplied digest pin."""

    _require_sha256(expected_policy_digest, "external.expectedPolicyDigest")
    _require_sha256(
        expected_control_plane_digest, "external.expectedControlPlaneDigest"
    )
    actual_policy_digest = document_digest(policy)
    if actual_policy_digest != expected_policy_digest:
        _fail(
            "trust_policy_digest_mismatch",
            "policy",
            "policy does not match the external digest pin",
        )
    document = _exact_keys(
        policy,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "revision",
            "policyStatus",
            "controlPlaneDigest",
            "signatureScheme",
            "thresholds",
            "separationOfDuties",
            "principals",
            "revokedFingerprints",
            "requiredExternalPins",
            "allowedTransitions",
        },
        "policy",
    )
    if document["schemaVersion"] != POLICY_SCHEMA or document["kind"] != POLICY_KIND:
        _fail("invalid_policy_schema", "policy", "schemaVersion or kind mismatch")
    if document["policyId"] != "P00-protected-verifier" or document["revision"] != 1:
        _fail(
            "invalid_policy_identity", "policy", "unexpected policy identity/revision"
        )
    if document["policyStatus"] not in {"pending_trust_roots", "configured"}:
        _fail(
            "invalid_policy_status", "policy.policyStatus", "unsupported policy status"
        )
    if document["controlPlaneDigest"] != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "policy.controlPlaneDigest",
            "policy subject differs from external pin",
        )

    scheme = _exact_keys(
        document["signatureScheme"],
        {"type", "allowedKeyTypes", "approvalNamespace", "stateEventNamespace"},
        "policy.signatureScheme",
    )
    if (
        scheme["type"] != "openssh-sshsig-v1"
        or scheme["allowedKeyTypes"] != ["ssh-ed25519"]
        or scheme["approvalNamespace"] != APPROVAL_NAMESPACE
        or scheme["stateEventNamespace"] != STATE_EVENT_NAMESPACE
    ):
        _fail(
            "invalid_signature_policy",
            "policy.signatureScheme",
            "signature-domain policy drift",
        )
    thresholds = _exact_keys(
        document["thresholds"],
        {"controlPlaneApproval", "stateEvent"},
        "policy.thresholds",
    )
    if thresholds != {"controlPlaneApproval": 1, "stateEvent": 1}:
        _fail(
            "unsupported_signature_threshold",
            "policy.thresholds",
            "v1alpha1 supports exact threshold one",
        )
    separation = _exact_keys(
        document["separationOfDuties"],
        {
            "distinctPrincipals",
            "distinctKeys",
            "distinctOrganizations",
            "approvalRole",
            "stateEventRole",
        },
        "policy.separationOfDuties",
    )
    if separation != {
        "distinctPrincipals": True,
        "distinctKeys": True,
        "distinctOrganizations": True,
        "approvalRole": "independent-reviewer",
        "stateEventRole": "protected-workflow",
    }:
        _fail(
            "separation_of_duties_drift",
            "policy.separationOfDuties",
            "approval and state-event authorities must remain separate",
        )
    if document["requiredExternalPins"] != list(REQUIRED_EXTERNAL_PINS):
        _fail(
            "external_pin_policy_drift",
            "policy.requiredExternalPins",
            "required external pin set drift",
        )
    expected_transitions = {
        key: list(value) for key, value in ALLOWED_TRANSITIONS.items()
    }
    if document["allowedTransitions"] != expected_transitions:
        _fail(
            "transition_policy_drift",
            "policy.allowedTransitions",
            "Plan section 29.2 transition set drift",
        )

    revoked = document["revokedFingerprints"]
    if (
        not isinstance(revoked, list)
        or any(not isinstance(item, str) for item in revoked)
        or revoked != sorted(set(revoked))
    ):
        _fail(
            "invalid_revocation_list",
            "policy.revokedFingerprints",
            "must be a sorted unique string list",
        )
    principals = document["principals"]
    if not isinstance(principals, list):
        _fail("invalid_principal_roster", "policy.principals", "must be an array")
    validated = [
        _validate_principal(item, index) for index, item in enumerate(principals)
    ]
    identities = [item["identity"] for item in validated]
    fingerprints = [item["fingerprint"] for item in validated]
    if len(set(identities)) != len(identities) or len(set(fingerprints)) != len(
        fingerprints
    ):
        _fail(
            "ambiguous_signer",
            "policy.principals",
            "principal identities and keys must be unique",
        )
    if any(item in revoked for item in fingerprints):
        _fail(
            "revoked_active_principal", "policy", "active roster contains a revoked key"
        )
    approval_principals = [
        item for item in validated if "approve-control-plane" in item["capabilities"]
    ]
    state_principals = [
        item for item in validated if "sign-state-event" in item["capabilities"]
    ]
    if any(len(item["capabilities"]) != 1 for item in validated):
        _fail(
            "separation_of_duties_violation",
            "policy.principals",
            "one principal or key cannot hold both protected capabilities",
        )
    if any(item["role"] != separation["approvalRole"] for item in approval_principals):
        _fail(
            "role_not_authorized",
            "policy.principals",
            "approval capability must use the independent reviewer role",
        )
    if any(item["role"] != separation["stateEventRole"] for item in state_principals):
        _fail(
            "role_not_authorized",
            "policy.principals",
            "state-event capability must use the protected workflow role",
        )
    if {item["organization"] for item in approval_principals} & {
        item["organization"] for item in state_principals
    }:
        _fail(
            "separation_of_duties_violation",
            "policy.principals",
            "approval and state-event organizations must be distinct",
        )
    if document["policyStatus"] == "pending_trust_roots":
        if principals or revoked:
            _fail(
                "invalid_pending_policy",
                "policy",
                "pending policy must not carry trust roots",
            )
        if require_configured:
            _fail(
                "trust_policy_not_configured",
                "policy",
                "no independently pinned signer roster exists",
            )
    elif require_configured:
        capabilities = {cap for item in validated for cap in item["capabilities"]}
        if not CAPABILITIES.issubset(capabilities):
            _fail(
                "incomplete_trust_roster",
                "policy.principals",
                "approval and state-event signers are both required",
            )
    return {
        "document": document,
        "digest": actual_policy_digest,
        "principals": {item["identity"]: item for item in validated},
        "revoked": set(revoked),
    }


def _principal_for(
    policy_result: Mapping[str, Any],
    identity: Any,
    capability: str,
    *,
    at: datetime,
) -> dict[str, Any]:
    if not isinstance(identity, str) or not PRINCIPAL_RE.fullmatch(identity):
        _fail("invalid_principal", "signature.principal", "invalid exact principal")
    principal = policy_result["principals"].get(identity)
    if principal is None:
        _fail(
            "signer_not_allowed",
            "signature.principal",
            "principal is absent from the pinned roster",
        )
    if principal["fingerprint"] in policy_result["revoked"]:
        _fail("signer_revoked", "signature.principal", "signing key is revoked")
    if capability not in principal["capabilities"]:
        _fail(
            "role_not_authorized",
            "signature.principal",
            f"principal lacks {capability} capability",
        )
    valid_from = _parse_utc(principal["validFrom"], "policy.principal.validFrom")
    valid_until = _parse_utc(principal["validUntil"], "policy.principal.validUntil")
    if not valid_from <= at < valid_until:
        _fail(
            "signer_outside_validity",
            "signature.principal",
            "signer is outside policy validity",
        )
    return principal


def _signature_value(
    signature: Any, expected_namespace: str, path: str
) -> tuple[str, str]:
    value = _exact_keys(signature, {"scheme", "namespace", "principal", "value"}, path)
    if value["scheme"] != "openssh-sshsig-v1":
        _fail(
            "unsupported_signature_scheme",
            f"{path}.scheme",
            "only OpenSSH SSHSIG v1 is supported",
        )
    if value["namespace"] != expected_namespace:
        _fail(
            "signature_namespace_mismatch",
            f"{path}.namespace",
            "signature namespace is not valid for this statement",
        )
    principal = value["principal"]
    if not isinstance(principal, str) or not PRINCIPAL_RE.fullmatch(principal):
        _fail("invalid_principal", f"{path}.principal", "invalid exact principal")
    armored = value["value"]
    if not isinstance(armored, str) or len(armored) > 16384 or "\x00" in armored:
        _fail("malformed_signature", f"{path}.value", "invalid SSH signature armor")
    if not (
        armored.startswith("-----BEGIN SSH SIGNATURE-----\n")
        and armored.rstrip().endswith("-----END SSH SIGNATURE-----")
        and armored.count("-----BEGIN SSH SIGNATURE-----") == 1
        and armored.count("-----END SSH SIGNATURE-----") == 1
    ):
        _fail("malformed_signature", f"{path}.value", "invalid SSH signature armor")
    return principal, armored


def trusted_ssh_keygen_digest() -> tuple[Path, str]:
    """Return the fixed system ssh-keygen path and its raw SHA-256 digest."""

    candidate = Path("/usr/bin/ssh-keygen")
    try:
        metadata = candidate.stat()
    except OSError as exc:
        _fail("signature_verifier_unavailable", str(candidate), str(exc))
    if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail(
            "signature_verifier_unavailable",
            str(candidate),
            "trusted ssh-keygen must be a regular non-symlink system executable",
        )
    if not os.access(candidate, os.X_OK):
        _fail(
            "signature_verifier_unavailable",
            str(candidate),
            "trusted ssh-keygen is not executable",
        )
    hasher = hashlib.sha256()
    try:
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError as exc:
        _fail("signature_verifier_unavailable", str(candidate), str(exc))
    return candidate, f"sha256:{hasher.hexdigest()}"


def _verify_sshsig(
    *,
    payload: bytes,
    signature: Mapping[str, Any],
    principal: Mapping[str, Any],
    namespace: str,
    expected_ssh_keygen_digest: str,
) -> None:
    _require_sha256(expected_ssh_keygen_digest, "external.expectedSshKeygenDigest")
    executable, observed_digest = trusted_ssh_keygen_digest()
    if observed_digest != expected_ssh_keygen_digest:
        _fail(
            "ssh_keygen_digest_mismatch",
            str(executable),
            "system ssh-keygen differs from the external toolchain pin",
        )
    _, armored = _signature_value(signature, namespace, "signature")
    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-verify-") as directory:
        temporary = Path(directory)
        allowed = temporary / "allowed_signers"
        signature_path = temporary / "statement.sig"
        allowed.write_text(
            f'{principal["identity"]} namespaces="{namespace}" {principal["publicKey"]}\n',
            encoding="utf-8",
        )
        signature_path.write_text(armored.rstrip() + "\n", encoding="utf-8")
        allowed.chmod(0o600)
        signature_path.chmod(0o600)
        try:
            completed = subprocess.run(
                [
                    str(executable),
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    principal["identity"],
                    "-n",
                    namespace,
                    "-s",
                    str(signature_path),
                ],
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _fail("signature_verifier_unavailable", "ssh-keygen", str(exc))
    if completed.returncode != 0:
        _fail(
            "signature_invalid",
            "signature",
            "OpenSSH rejected the canonical signed statement",
        )


def _signed_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def verify_control_plane_approval(
    *,
    request: Any,
    approval: Any,
    policy: Any,
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_candidate_source_commit: str,
    expected_request_digest: str,
    expected_ssh_keygen_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify one independently signed bootstrap decision without creating state."""

    _require_sha256(expected_request_digest, "external.expectedRequestDigest")
    _require_commit(
        expected_candidate_source_commit, "external.expectedCandidateSourceCommit"
    )
    actual_request_digest = document_digest(request)
    if actual_request_digest != expected_request_digest:
        _fail(
            "request_digest_mismatch",
            "request",
            "request does not match the external digest pin",
        )
    request_document = _exact_keys(
        request,
        {
            "schemaVersion",
            "kind",
            "requestId",
            "revision",
            "previousRequest",
            "requestStatus",
            "candidate",
            "componentDigests",
            "digestGroups",
            "antiPlaceholderTests",
            "protectedVerifierTests",
            "diff",
            "decisionsRequested",
            "limitations",
            "nextAuthorizedAction",
        },
        "request",
    )
    if (
        request_document["schemaVersion"]
        != "urn:agentapi-doctor:bootstrap-request:v1alpha2"
        or request_document["kind"] != "BootstrapControlPlaneReviewRequest"
        or request_document["requestId"] != "P00.B00-R2"
        or request_document["revision"] != 2
        or request_document["requestStatus"] != "pending_review"
    ):
        _fail("invalid_request", "request", "unsupported bootstrap request")
    if request_document["previousRequest"] != {
        "requestId": "P00.B00",
        "revision": 1,
        "requestDigest": PREVIOUS_REQUEST_DIGEST,
        "controlPlaneDigest": PREVIOUS_CONTROL_PLANE_DIGEST,
        "candidateSourceCommit": PREVIOUS_CANDIDATE_COMMIT,
    }:
        _fail(
            "request_revision_chain_mismatch",
            "request.previousRequest",
            "request does not preserve the reviewed P00.B00 predecessor",
        )
    candidate = _exact_keys(
        request_document["candidate"],
        {
            "baseCommit",
            "candidateSourceCommit",
            "gitObjectFormat",
            "canonicalPlanPath",
            "controlPlaneDigest",
        },
        "request.candidate",
    )
    if (
        candidate["baseCommit"] != PREVIOUS_CANDIDATE_COMMIT
        or candidate["gitObjectFormat"] != "sha1"
        or candidate["canonicalPlanPath"] != "agentapi-doctor-Plan.md"
    ):
        _fail(
            "request_candidate_binding_drift",
            "request.candidate",
            "request base, Git object format, or canonical plan path drifted",
        )
    if candidate["candidateSourceCommit"] != expected_candidate_source_commit:
        _fail(
            "candidate_commit_unbound",
            "request.candidate.candidateSourceCommit",
            "request does not bind the externally selected candidate",
        )
    if candidate["controlPlaneDigest"] != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "request.candidate.controlPlaneDigest",
            "request subject differs from external pin",
        )

    policy_result = validate_trust_policy(
        policy,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
        require_configured=True,
    )
    envelope = _exact_keys(
        approval,
        {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
        "approval",
    )
    if (
        envelope["schemaVersion"] != APPROVAL_SCHEMA
        or envelope["kind"] != APPROVAL_KIND
    ):
        _fail("invalid_approval_schema", "approval", "schemaVersion or kind mismatch")
    actual_attestation_digest = document_digest(
        envelope, omit_field="attestationDigest"
    )
    if envelope["attestationDigest"] != actual_attestation_digest:
        _fail(
            "approval_digest_mismatch",
            "approval.attestationDigest",
            "attestation digest does not cover the signed envelope",
        )
    body = _exact_keys(
        envelope["body"],
        {
            "attestationId",
            "requestId",
            "requestRevision",
            "requestDigest",
            "decision",
            "candidateSourceCommit",
            "controlPlaneDigest",
            "digestGroups",
            "reviewedDecisionIds",
            "scope",
            "reason",
            "validFrom",
            "validUntil",
            "constraints",
            "conflictOfInterest",
            "reviewer",
            "trustPolicyDigest",
            "sshKeygenDigest",
        },
        "approval.body",
    )
    _require_nonempty(body["attestationId"], "approval.body.attestationId", maximum=256)
    if (
        body["requestId"] != request_document["requestId"]
        or body["requestRevision"] != request_document["revision"]
    ):
        _fail(
            "request_identity_mismatch",
            "approval.body",
            "approval references another request",
        )
    if body["requestDigest"] != actual_request_digest:
        _fail(
            "request_digest_mismatch",
            "approval.body.requestDigest",
            "approval does not bind the full request",
        )
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail(
            "invalid_approval_decision",
            "approval.body.decision",
            "decision must be APPROVE or REJECT",
        )
    if body["candidateSourceCommit"] != expected_candidate_source_commit:
        _fail(
            "source_commit_mismatch",
            "approval.body.candidateSourceCommit",
            "approval subject differs from external pin",
        )
    if body["controlPlaneDigest"] != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "approval.body.controlPlaneDigest",
            "approval subject differs from external pin",
        )
    if body["digestGroups"] != request_document["digestGroups"]:
        _fail(
            "approval_digest_group_mismatch",
            "approval.body.digestGroups",
            "approval did not bind every reviewed digest group",
        )
    decision_ids = (
        [
            item.get("id")
            for item in request_document["decisionsRequested"]
            if isinstance(item, dict)
        ]
        if isinstance(request_document["decisionsRequested"], list)
        else []
    )
    if body["reviewedDecisionIds"] != decision_ids or len(set(decision_ids)) != len(
        decision_ids
    ):
        _fail(
            "incomplete_review_decisions",
            "approval.body.reviewedDecisionIds",
            "reviewed decisions must exactly match request order",
        )
    if body["scope"] != {"phase": "P00", "bootstrapId": "P00.B00"}:
        _fail(
            "invalid_approval_scope",
            "approval.body.scope",
            "approval scope must be the P00 bootstrap",
        )
    _require_nonempty(body["reason"], "approval.body.reason")
    if body["constraints"] != []:
        _fail(
            "unsupported_approval_constraints",
            "approval.body.constraints",
            "v1alpha1 cannot silently weaken approval",
        )
    conflict = _exact_keys(
        body["conflictOfInterest"],
        {"independent", "statement"},
        "approval.body.conflictOfInterest",
    )
    if conflict["independent"] is not True:
        _fail(
            "reviewer_not_independent",
            "approval.body.conflictOfInterest",
            "independence must be affirmatively declared",
        )
    _require_nonempty(
        conflict["statement"], "approval.body.conflictOfInterest.statement"
    )
    reviewer = _exact_keys(
        body["reviewer"],
        {"principal", "role", "organization"},
        "approval.body.reviewer",
    )
    if body["trustPolicyDigest"] != policy_result["digest"]:
        _fail(
            "trust_policy_digest_mismatch",
            "approval.body.trustPolicyDigest",
            "approval binds another policy",
        )
    if body["sshKeygenDigest"] != expected_ssh_keygen_digest:
        _fail(
            "ssh_keygen_digest_mismatch",
            "approval.body.sshKeygenDigest",
            "approval does not bind the externally pinned verifier toolchain",
        )
    valid_from = _parse_utc(body["validFrom"], "approval.body.validFrom")
    valid_until = _parse_utc(body["validUntil"], "approval.body.validUntil")
    verification_time = _now_utc(now)
    if valid_from >= valid_until or not valid_from <= verification_time < valid_until:
        _fail(
            "approval_outside_validity",
            "approval.body",
            "approval is not valid at verification time",
        )
    signature_principal, _ = _signature_value(
        envelope["signature"], APPROVAL_NAMESPACE, "approval.signature"
    )
    if signature_principal != reviewer["principal"]:
        _fail(
            "actor_principal_mismatch", "approval", "reviewer and SSH principal differ"
        )
    trusted = _principal_for(
        policy_result,
        signature_principal,
        "approve-control-plane",
        at=verification_time,
    )
    if (
        reviewer["role"] != trusted["role"]
        or reviewer["organization"] != trusted["organization"]
    ):
        _fail(
            "role_not_authorized",
            "approval.body.reviewer",
            "reviewer role/organization is not policy-authorized",
        )
    _verify_sshsig(
        payload=_signed_payload(envelope),
        signature=envelope["signature"],
        principal=trusted,
        namespace=APPROVAL_NAMESPACE,
        expected_ssh_keygen_digest=expected_ssh_keygen_digest,
    )
    return {
        "status": "verified",
        "decision": body["decision"],
        "approvalDigest": actual_attestation_digest,
        "requestDigest": actual_request_digest,
        "controlPlaneDigest": expected_control_plane_digest,
        "candidateSourceCommit": expected_candidate_source_commit,
        "reviewer": deepcopy(reviewer),
        "trustPolicyDigest": policy_result["digest"],
        "sshKeygenDigest": expected_ssh_keygen_digest,
    }


def _safe_repo_file(root: Path, declared: Any, path: str) -> Path:
    if not isinstance(declared, str) or not declared or "\\" in declared:
        _fail(
            "unsafe_evidence_path",
            path,
            "path must be a portable repository-relative path",
        )
    relative = Path(declared)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        _fail("unsafe_evidence_path", path, "unsafe repository-relative path")
    candidate = root / relative
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            _fail("unsafe_evidence_path", path, "symlink path components are forbidden")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        _fail("unsafe_evidence_path", path, str(exc))
    if not resolved.is_file():
        _fail("unsafe_evidence_path", path, "evidence pointer must be a regular file")
    return resolved


def _state_core_digest(core: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(core))


def _validate_state_invariants(core: Mapping[str, Any]) -> None:
    phases = core.get("phases")
    if not isinstance(phases, dict) or not phases:
        _fail("invalid_state", "state.phases", "state must contain phases")
    active_phases = [
        phase_id
        for phase_id, phase in phases.items()
        if isinstance(phase, dict) and phase.get("status") == "ACTIVE"
    ]
    active_units: list[tuple[str, str]] = []
    pending_units: list[tuple[str, str]] = []
    for phase_id, phase in phases.items():
        if (
            not isinstance(phase, dict)
            or phase.get("status") not in ALLOWED_TRANSITIONS
        ):
            _fail(
                "invalid_state",
                f"state.phases.{phase_id}.status",
                "phase status is not recognized",
            )
        units = phase.get("workUnits") if isinstance(phase, dict) else None
        if not isinstance(units, dict):
            _fail(
                "invalid_state",
                f"state.phases.{phase_id}.workUnits",
                "must be an object",
            )
        unit_statuses: list[str] = []
        for unit_id, unit in units.items():
            if (
                not isinstance(unit, dict)
                or unit.get("status") not in ALLOWED_TRANSITIONS
            ):
                _fail(
                    "invalid_state",
                    f"state.phases.{phase_id}.workUnits.{unit_id}.status",
                    "work-unit status is not recognized",
                )
            unit_statuses.append(unit["status"])
            if unit.get("status") == "ACTIVE":
                active_units.append((phase_id, unit_id))
            if unit.get("status") in PENDING_STATUSES:
                pending_units.append((phase_id, unit_id))
        if phase["status"] in {
            "MACHINE_CONVERGED",
            "WAITING_EXTERNAL",
            "REVIEW_PENDING",
            "CONVERGED",
        } and any(status != "CONVERGED" for status in unit_statuses):
            _fail(
                "phase_unit_convergence_mismatch",
                f"state.phases.{phase_id}",
                "a converged-or-later phase requires every work unit to remain CONVERGED",
            )
    if len(active_phases) > 1 or len(active_units) > 1:
        _fail(
            "multiple_active_pointers",
            "state",
            "at most one phase and one work unit may be ACTIVE",
        )
    expected_phase = active_phases[0] if active_phases else None
    expected_unit = active_units[0][1] if active_units else None
    if core.get("activePhase") != expected_phase:
        _fail(
            "active_phase_pointer_mismatch",
            "state.activePhase",
            "pointer does not match ACTIVE phase",
        )
    if core.get("activeWorkUnit") != expected_unit:
        _fail(
            "active_work_unit_pointer_mismatch",
            "state.activeWorkUnit",
            "pointer does not match ACTIVE work unit",
        )
    if active_units and active_units[0][0] != expected_phase:
        _fail(
            "active_unit_phase_mismatch",
            "state",
            "ACTIVE unit must belong to ACTIVE phase",
        )
    if len(pending_units) > 1:
        _fail(
            "multiple_pending_work_units",
            "state",
            "the singular pendingWorkUnit pointer cannot represent multiple pending units",
        )
    expected_pending = pending_units[0][1] if pending_units else None
    if core.get("pendingWorkUnit") != expected_pending:
        _fail(
            "pending_work_unit_pointer_mismatch",
            "state.pendingWorkUnit",
            "pointer does not match the sole pending-status work unit",
        )
    if expected_pending is not None and expected_pending == expected_unit:
        _fail(
            "active_pending_conflict",
            "state",
            "one unit cannot be active and pending",
        )


def _initial_state_from_genesis(
    body: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    approval_result: Mapping[str, Any],
    contract_digests: Mapping[str, str],
) -> dict[str, Any]:
    expected_units = [f"P00.W0{index}" for index in range(1, 6)]
    if payload["planVersion"] != "1.0":
        _fail(
            "invalid_genesis",
            "event.body.payload.planVersion",
            "unexpected plan version",
        )
    if (
        payload["requestId"] != "P00.B00-R2"
        or payload["requestDigest"] != approval_result["requestDigest"]
        or payload["approvalDigest"] != approval_result["approvalDigest"]
    ):
        _fail(
            "approval_digest_mismatch",
            "event.body.payload",
            "Genesis does not bind the verified approval/request",
        )
    if (
        payload["activePhase"] != "P00"
        or payload["activeWorkUnit"] != "P00.W01"
        or payload["pendingWorkUnit"] is not None
    ):
        _fail(
            "invalid_genesis",
            "event.body.payload",
            "Genesis must atomically activate P00/P00.W01",
        )
    if payload["aggregateContractDigest"] != contract_digests.get(
        "execution/phases/P00.yaml"
    ):
        _fail(
            "contract_digest_mismatch",
            "event.body.payload.aggregateContractDigest",
            "aggregate contract mismatch",
        )
    unit_digests = payload["workUnitContractDigests"]
    expected_unit_digests = {
        unit: contract_digests.get(f"execution/work-units/{unit}.yaml")
        for unit in expected_units
    }
    if unit_digests != expected_unit_digests or any(
        value is None for value in expected_unit_digests.values()
    ):
        _fail(
            "contract_digest_mismatch",
            "event.body.payload.workUnitContractDigests",
            "work-unit contract set mismatch",
        )
    work_units: dict[str, Any] = {}
    for unit in expected_units:
        work_units[unit] = {
            "status": "ACTIVE" if unit == "P00.W01" else "NOT_STARTED",
            "contractDigest": expected_unit_digests[unit],
            "approvalDigest": approval_result["approvalDigest"]
            if unit == "P00.W01"
            else None,
            "sourceCommit": body["sourceCommit"] if unit == "P00.W01" else None,
        }
    core: dict[str, Any] = {
        "planVersion": "1.0",
        "controlPlaneDigest": body["controlPlaneDigest"],
        "activePhase": "P00",
        "activeWorkUnit": "P00.W01",
        "pendingWorkUnit": None,
        "phases": {
            "P00": {
                "status": "ACTIVE",
                "aggregateContractDigest": payload["aggregateContractDigest"],
                "controlPlaneDigest": body["controlPlaneDigest"],
                "baseCommit": body["sourceCommit"],
                "startedAt": body["timestamp"],
                "workUnits": work_units,
            }
        },
    }
    _validate_state_invariants(core)
    if payload["resultingStateDigest"] != _state_core_digest(core):
        _fail(
            "state_digest_mismatch",
            "event.body.payload.resultingStateDigest",
            "Genesis state digest mismatch",
        )
    return core


def _apply_transition(
    core: dict[str, Any],
    body: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    contract_digests: Mapping[str, str],
) -> None:
    if payload["priorStateDigest"] != _state_core_digest(core):
        _fail(
            "state_digest_mismatch",
            "event.body.payload.priorStateDigest",
            "transition prior state mismatch",
        )
    phase_id = payload["phase"]
    phase = core["phases"].get(phase_id)
    if phase is None:
        _fail("unknown_state_target", "event.body.payload.phase", "unknown phase")
    scope = payload["scope"]
    if scope == "phase":
        if payload["workUnit"] is not None:
            _fail(
                "invalid_state_transition",
                "event.body.payload.workUnit",
                "phase transition cannot name a work unit",
            )
        target = phase
        expected_contract = contract_digests.get(f"execution/phases/{phase_id}.yaml")
    elif scope == "workUnit":
        unit_id = payload["workUnit"]
        if not isinstance(unit_id, str) or unit_id not in phase["workUnits"]:
            _fail(
                "unknown_state_target",
                "event.body.payload.workUnit",
                "unknown work unit",
            )
        target = phase["workUnits"][unit_id]
        expected_contract = contract_digests.get(f"execution/work-units/{unit_id}.yaml")
    else:
        _fail(
            "invalid_state_transition",
            "event.body.payload.scope",
            "scope must be phase or workUnit",
        )
    if payload["contractDigest"] != expected_contract:
        _fail(
            "contract_digest_mismatch",
            "event.body.payload.contractDigest",
            "target contract mismatch",
        )
    from_status = payload["fromStatus"]
    to_status = payload["toStatus"]
    if target.get("status") != from_status:
        _fail(
            "transition_from_mismatch",
            "event.body.payload.fromStatus",
            "replayed state differs from event fromStatus",
        )
    if to_status not in ALLOWED_TRANSITIONS.get(from_status, ()):
        _fail(
            "invalid_state_transition",
            "event.body.payload",
            f"transition {from_status}->{to_status} is forbidden",
        )
    evidence_digest = payload["evidenceDigest"]
    approval_digest = payload["approvalDigest"]
    if evidence_digest is not None:
        _require_sha256(evidence_digest, "event.body.payload.evidenceDigest")
        _fail(
            "unverified_transition_evidence",
            "event.body.payload.evidenceDigest",
            "this candidate has no approved evidence verifier result type",
        )
    if approval_digest is not None:
        _require_sha256(approval_digest, "event.body.payload.approvalDigest")
        _fail(
            "unverified_transition_approval",
            "event.body.payload.approvalDigest",
            "this candidate has no approved transition-approval result type",
        )
    if to_status == "MACHINE_CONVERGED" and evidence_digest is None:
        _fail(
            "missing_transition_evidence",
            "event.body.payload.evidenceDigest",
            "machine convergence requires evidence",
        )
    if to_status in {"ACTIVE", "CONVERGED", "READY"} and approval_digest is None:
        _fail(
            "missing_transition_approval",
            "event.body.payload.approvalDigest",
            "activation/convergence/reopen requires approval",
        )
    if (
        from_status == "CONVERGED"
        and to_status == "REJECTED"
        and body["reasonCode"]
        not in {"control-plane-invalidation", "impact-invalidation"}
    ):
        _fail(
            "invalid_state_transition_reason",
            "event.body.reasonCode",
            "converged state may reopen only for a declared invalidation",
        )
    if scope == "workUnit" and to_status in {"READY", "ACTIVE"}:
        unit_id = payload["workUnit"]
        match = re.fullmatch(r"P00\.W0([1-5])", str(unit_id))
        if match is None:
            _fail(
                "unknown_state_target",
                "event.body.payload.workUnit",
                "P00 verifier supports only W01-W05",
            )
        predecessor_states = [
            phase["workUnits"][f"P00.W0{index}"]["status"]
            for index in range(1, int(match.group(1)))
        ]
        if any(status != "CONVERGED" for status in predecessor_states):
            _fail(
                "prerequisite_not_satisfied",
                "event.body.payload.workUnit",
                "all earlier P00 work units must be CONVERGED before readiness/activation",
            )
    if scope == "phase" and to_status in {
        "MACHINE_CONVERGED",
        "WAITING_EXTERNAL",
        "REVIEW_PENDING",
        "CONVERGED",
    }:
        if any(
            unit.get("status") != "CONVERGED" for unit in phase["workUnits"].values()
        ):
            _fail(
                "phase_aggregate_incomplete",
                "event.body.payload.phase",
                "phase cannot converge while a work unit is not CONVERGED",
            )
    target["status"] = to_status
    target["sourceCommit"] = body["sourceCommit"]
    if approval_digest is not None:
        target["approvalDigest"] = approval_digest
    if scope == "phase":
        if to_status == "ACTIVE":
            core["activePhase"] = phase_id
        elif core["activePhase"] == phase_id:
            core["activePhase"] = None
        if (
            core["activePhase"] is None
            and to_status != "ACTIVE"
            and core["activeWorkUnit"] is not None
        ):
            _fail(
                "active_unit_phase_mismatch",
                "state",
                "phase cannot leave ACTIVE while a unit remains ACTIVE",
            )
    else:
        unit_id = payload["workUnit"]
        if to_status == "ACTIVE":
            if phase["status"] != "ACTIVE":
                _fail(
                    "active_unit_phase_mismatch",
                    "state",
                    "unit activation requires ACTIVE phase",
                )
            core["activeWorkUnit"] = unit_id
            core["pendingWorkUnit"] = None
        else:
            if core["activeWorkUnit"] == unit_id:
                core["activeWorkUnit"] = None
                core["pendingWorkUnit"] = (
                    unit_id if to_status in PENDING_STATUSES else None
                )
            elif core["pendingWorkUnit"] == unit_id:
                core["pendingWorkUnit"] = (
                    unit_id if to_status in PENDING_STATUSES else None
                )
    _validate_state_invariants(core)
    if payload["resultingStateDigest"] != _state_core_digest(core):
        _fail(
            "state_digest_mismatch",
            "event.body.payload.resultingStateDigest",
            "transition resulting state mismatch",
        )


def _apply_attachment(
    core: Mapping[str, Any],
    body: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    if payload["stateDigest"] != _state_core_digest(core):
        _fail(
            "state_digest_mismatch",
            "event.body.payload.stateDigest",
            "attachment cannot change or target another state",
        )
    phase = core["phases"].get(payload["phase"])
    if phase is None or payload["workUnit"] not in phase["workUnits"]:
        _fail(
            "unknown_state_target",
            "event.body.payload",
            "attachment targets an unknown unit",
        )
    unit = phase["workUnits"][payload["workUnit"]]
    if body["sourceCommit"] != unit.get("sourceCommit"):
        _fail(
            "source_commit_mismatch",
            "event.body.sourceCommit",
            "attachment source differs from target unit",
        )
    for key in ("evidenceDigest", "evidenceIndexDigest"):
        _require_sha256(payload[key], f"event.body.payload.{key}")
    pointer = payload["evidenceIndexPointer"]
    if not isinstance(pointer, str) or not pointer.startswith(
        "execution/gates/p00/evidence/"
    ):
        _fail(
            "unsafe_evidence_path",
            "event.body.payload.evidenceIndexPointer",
            "pointer must be under P00 evidence output",
        )
    evidence_path = _safe_repo_file(
        repo_root, pointer, "event.body.payload.evidenceIndexPointer"
    )
    raw_digest = sha256_bytes(evidence_path.read_bytes())
    if raw_digest != payload["evidenceIndexDigest"]:
        _fail(
            "evidence_index_digest_mismatch",
            pointer,
            "evidence index bytes do not match event",
        )
    index = load_strict_document(evidence_path, label=pointer)
    expected_index = {
        "schemaVersion",
        "phase",
        "workUnit",
        "sourceCommit",
        "controlPlaneDigest",
        "evidenceKind",
        "evidenceSchema",
        "evidenceDigest",
        "evidencePointer",
        "verificationPairId",
    }
    index_document = _exact_keys(index, expected_index, pointer)
    if index_document["schemaVersion"] != "urn:agentapi-doctor:evidence-index:v1alpha1":
        _fail(
            "invalid_evidence_index_schema",
            f"{pointer}#schemaVersion",
            "unsupported evidence index schema",
        )
    for field in (
        "phase",
        "workUnit",
        "sourceCommit",
        "controlPlaneDigest",
        "evidenceKind",
        "evidenceSchema",
        "evidenceDigest",
        "verificationPairId",
    ):
        expected = (
            body[field]
            if field in {"sourceCommit", "controlPlaneDigest"}
            else payload[field]
        )
        if index_document[field] != expected:
            _fail(
                "evidence_binding_mismatch",
                f"{pointer}#{field}",
                "evidence index binding mismatch",
            )
    evidence_pointer = index_document["evidencePointer"]
    if (
        not isinstance(evidence_pointer, str)
        or not evidence_pointer.startswith("execution/gates/p00/evidence/")
        or evidence_pointer == pointer
    ):
        _fail(
            "unsafe_evidence_path",
            f"{pointer}#evidencePointer",
            "evidence object must be a distinct file under P00 evidence output",
        )
    evidence_object = _safe_repo_file(
        repo_root, evidence_pointer, f"{pointer}#evidencePointer"
    )
    if sha256_bytes(evidence_object.read_bytes()) != payload["evidenceDigest"]:
        _fail(
            "evidence_digest_mismatch",
            evidence_pointer,
            "evidence object bytes do not match the attachment digest",
        )

    catalog_pointer = "execution/evidence-schemas/catalog.yaml"
    catalog_path = _safe_repo_file(repo_root, catalog_pointer, catalog_pointer)
    catalog = load_strict_document(catalog_path, label=catalog_pointer)
    if (
        not isinstance(catalog, dict)
        or catalog.get("controlPlaneDigest") != body["controlPlaneDigest"]
    ):
        _fail(
            "evidence_schema_catalog_mismatch",
            catalog_pointer,
            "evidence schema catalog is absent or bound to another control plane",
        )
    schemas = catalog.get("schemas")
    schema = (
        next(
            (
                item
                for item in schemas
                if isinstance(item, dict)
                and item.get("id") == payload["evidenceSchema"]
            ),
            None,
        )
        if isinstance(schemas, list)
        else None
    )
    if schema is None:
        _fail(
            "unknown_evidence_schema",
            "event.body.payload.evidenceSchema",
            "attachment references a schema outside the approved catalog",
        )
    if schema.get("status") == "planned":
        _fail(
            "unimplemented_evidence_schema",
            "event.body.payload.evidenceSchema",
            "planned evidence schema cannot support a verified attachment",
        )
    return {
        "eventId": body["eventId"],
        "phase": payload["phase"],
        "workUnit": payload["workUnit"],
        "evidenceKind": payload["evidenceKind"],
        "evidenceDigest": payload["evidenceDigest"],
        "evidenceIndexPointer": pointer,
    }


def load_event_directory(directory: Path) -> list[dict[str, Any]]:
    """Load an exact, contiguous 00000000.json event sequence."""

    directory = _reject_symlink_components(directory, str(directory))
    if not directory.is_dir():
        _fail("missing_event_chain", str(directory), "event directory is missing")
    entries = list(directory.iterdir())
    if any(item.is_symlink() or not item.is_file() for item in entries):
        _fail(
            "unsafe_event_file",
            str(directory),
            "events must be regular non-symlink files",
        )
    unexpected = sorted(
        item.name for item in entries if not EVENT_FILE_RE.fullmatch(item.name)
    )
    if unexpected:
        _fail(
            "unexpected_event_file", str(directory), f"unexpected files: {unexpected}"
        )
    ordered = sorted(entries, key=lambda item: item.name)
    if not ordered:
        _fail(
            "missing_event_chain",
            str(directory),
            "at least one Genesis event is required",
        )
    documents: list[dict[str, Any]] = []
    for sequence, path in enumerate(ordered):
        expected_name = f"{sequence:08d}.json"
        if path.name != expected_name:
            _fail("event_order_mismatch", str(path), f"expected {expected_name}")
        document = load_strict_document(path, label=str(path))
        if not isinstance(document, dict):
            _fail("invalid_event_schema", str(path), "event must be an object")
        documents.append(document)
    return documents


def _verify_prior_prefix(
    current: Sequence[Mapping[str, Any]], prior: Sequence[Mapping[str, Any]]
) -> None:
    if len(current) < len(prior):
        _fail(
            "event_chain_truncated",
            "events",
            "current chain is shorter than protected prior chain",
        )
    for index, prior_event in enumerate(prior):
        if current[index] != prior_event:
            _fail(
                "event_history_rewritten",
                f"events[{index}]",
                "protected prior event was modified",
            )


def replay_state_events(
    *,
    events: Sequence[Any],
    policy: Any,
    approval_result: Mapping[str, Any],
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_chain_head_digest: str,
    expected_ssh_keygen_digest: str,
    contract_digests: Mapping[str, str],
    repo_root: Path,
    prior_events: Sequence[Any] = (),
) -> dict[str, Any]:
    """Verify, anchor, and replay a signed linear StateEvent chain."""

    _require_sha256(expected_chain_head_digest, "external.expectedChainHeadDigest")
    _require_sha256(expected_ssh_keygen_digest, "external.expectedSshKeygenDigest")
    if approval_result.get("decision") != "APPROVE":
        _fail(
            "approval_not_valid_for_genesis",
            "approval",
            "Genesis requires a verified APPROVE decision",
        )
    if approval_result.get("sshKeygenDigest") != expected_ssh_keygen_digest:
        _fail(
            "ssh_keygen_digest_mismatch",
            "approval",
            "state replay toolchain differs from the verified approval",
        )
    policy_result = validate_trust_policy(
        policy,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
        require_configured=True,
    )
    if not events:
        _fail("missing_event_chain", "events", "Genesis is required")
    _verify_prior_prefix(events, prior_events)
    seen_ids: set[str] = set()
    previous_digest: str | None = None
    previous_time: datetime | None = None
    core: dict[str, Any] | None = None
    attachments: list[dict[str, Any]] = []
    for sequence, event in enumerate(events):
        path = f"events[{sequence}]"
        envelope = _exact_keys(
            event,
            {"schemaVersion", "kind", "body", "signature", "eventDigest"},
            path,
        )
        if (
            envelope["schemaVersion"] != STATE_EVENT_SCHEMA
            or envelope["kind"] != STATE_EVENT_KIND
        ):
            _fail(
                "invalid_event_schema", path, "schemaVersion or envelope kind mismatch"
            )
        actual_digest = document_digest(envelope, omit_field="eventDigest")
        if envelope["eventDigest"] != actual_digest:
            _fail(
                "event_digest_mismatch",
                f"{path}.eventDigest",
                "event digest does not cover signed envelope",
            )
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
                "payload",
            },
            f"{path}.body",
        )
        if (
            body["sequence"] != sequence
            or body["eventId"] != f"evt-{sequence:08d}"
            or not EVENT_ID_RE.fullmatch(str(body["eventId"]))
        ):
            _fail(
                "event_order_mismatch",
                f"{path}.body",
                "sequence/eventId is not contiguous",
            )
        if body["eventId"] in seen_ids:
            _fail("duplicate_event", f"{path}.body.eventId", "event ID is duplicated")
        seen_ids.add(body["eventId"])
        if body["previousDigest"] != previous_digest:
            _fail(
                "event_chain_broken",
                f"{path}.body.previousDigest",
                "event does not reference prior signed envelope",
            )
        _require_commit(body["sourceCommit"], f"{path}.body.sourceCommit")
        if body["controlPlaneDigest"] != expected_control_plane_digest:
            _fail(
                "control_plane_digest_mismatch",
                f"{path}.body.controlPlaneDigest",
                "state event uses another control plane",
            )
        if body["trustPolicyDigest"] != policy_result["digest"]:
            _fail(
                "trust_policy_digest_mismatch",
                f"{path}.body.trustPolicyDigest",
                "state event uses another trust policy",
            )
        timestamp = _parse_utc(body["timestamp"], f"{path}.body.timestamp")
        if previous_time is not None and timestamp < previous_time:
            _fail(
                "event_time_regression",
                f"{path}.body.timestamp",
                "event timestamps must be monotonic",
            )
        previous_time = timestamp
        actor = _exact_keys(
            body["actor"],
            {"principal", "role", "organization"},
            f"{path}.body.actor",
        )
        signature_principal, _ = _signature_value(
            envelope["signature"], STATE_EVENT_NAMESPACE, f"{path}.signature"
        )
        if signature_principal != actor["principal"]:
            _fail(
                "actor_principal_mismatch", path, "event actor and SSH principal differ"
            )
        trusted = _principal_for(
            policy_result,
            signature_principal,
            "sign-state-event",
            at=timestamp,
        )
        if (
            actor["role"] != trusted["role"]
            or actor["organization"] != trusted["organization"]
        ):
            _fail(
                "role_not_authorized",
                f"{path}.body.actor",
                "actor role/organization is not policy-authorized",
            )
        _require_nonempty(body["reasonCode"], f"{path}.body.reasonCode", maximum=128)
        _require_nonempty(body["reason"], f"{path}.body.reason")
        _verify_sshsig(
            payload=_signed_payload(envelope),
            signature=envelope["signature"],
            principal=trusted,
            namespace=STATE_EVENT_NAMESPACE,
            expected_ssh_keygen_digest=expected_ssh_keygen_digest,
        )
        event_type = body["eventType"]
        if sequence == 0:
            if event_type != "Genesis" or body["previousDigest"] is not None:
                _fail("invalid_genesis", path, "first event must be the only Genesis")
            payload = _exact_keys(
                body["payload"],
                {
                    "requestId",
                    "requestDigest",
                    "approvalDigest",
                    "planVersion",
                    "activePhase",
                    "activeWorkUnit",
                    "pendingWorkUnit",
                    "aggregateContractDigest",
                    "workUnitContractDigests",
                    "resultingStateDigest",
                },
                f"{path}.body.payload",
            )
            if body["sourceCommit"] != approval_result["candidateSourceCommit"]:
                _fail(
                    "source_commit_mismatch",
                    f"{path}.body.sourceCommit",
                    "Genesis differs from approved candidate",
                )
            core = _initial_state_from_genesis(
                body,
                payload,
                approval_result=approval_result,
                contract_digests=contract_digests,
            )
        elif event_type == "Genesis":
            _fail(
                "invalid_genesis", path, "Genesis may appear only once at sequence zero"
            )
        elif event_type == "StateTransition":
            payload = _exact_keys(
                body["payload"],
                {
                    "scope",
                    "phase",
                    "workUnit",
                    "fromStatus",
                    "toStatus",
                    "contractDigest",
                    "evidenceDigest",
                    "approvalDigest",
                    "priorStateDigest",
                    "resultingStateDigest",
                },
                f"{path}.body.payload",
            )
            assert core is not None
            _apply_transition(
                core,
                body,
                payload,
                contract_digests=contract_digests,
            )
        elif event_type == "EvidenceAttachment":
            payload = _exact_keys(
                body["payload"],
                {
                    "phase",
                    "workUnit",
                    "evidenceKind",
                    "evidenceSchema",
                    "evidenceDigest",
                    "evidenceIndexPointer",
                    "evidenceIndexDigest",
                    "verificationPairId",
                    "stateDigest",
                },
                f"{path}.body.payload",
            )
            assert core is not None
            attachments.append(
                _apply_attachment(core, body, payload, repo_root=repo_root)
            )
        else:
            _fail("unknown_event_kind", f"{path}.body.eventType", str(event_type))
        previous_digest = actual_digest
        previous_time = timestamp
    if previous_digest != expected_chain_head_digest:
        _fail(
            "chain_head_digest_mismatch",
            "events",
            "chain head differs from external anchor",
        )
    assert core is not None
    _validate_state_invariants(core)
    return {
        "schemaVersion": STATE_VIEW_SCHEMA,
        **deepcopy(core),
        "stateDigest": _state_core_digest(core),
        "attachments": attachments,
        "chain": {
            "eventCount": len(events),
            "headSequence": len(events) - 1,
            "headDigest": previous_digest,
        },
    }


def canonical_state_view_bytes(view: Mapping[str, Any]) -> bytes:
    """Return the only serialized representation accepted for a derived view."""

    return canonical_json_bytes(view) + b"\n"


def compare_state_view(path: Path, expected: Mapping[str, Any]) -> None:
    """Reject a missing, symlinked, or hand-edited derived phase-state view."""

    if path.is_symlink() or not path.is_file():
        _fail(
            "phase_state_view_missing",
            str(path),
            "derived view must be a regular non-symlink file",
        )
    try:
        actual = path.read_bytes()
    except OSError as exc:
        _fail("phase_state_view_missing", str(path), str(exc))
    if actual != canonical_state_view_bytes(expected):
        _fail(
            "phase_state_view_drift",
            str(path),
            "phase-state view is not the exact replay result",
        )
