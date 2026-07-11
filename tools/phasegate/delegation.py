"""Chain-bound SSHSIG reviewer delegation for P00 protected evidence.

The policy's static SSH principal is the only delegation root.  A delegation
may add only the narrowly enumerated P00 reviewer roles and criteria; it never
inherits control-plane approval, StateEvent signing, or delegation authority.

The effective roster and every verified input are identity-sealed objects.  A
caller cannot construct a look-alike frozen dataclass and pass it to the
criterion authorization or provenance adapter APIs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import re
from typing import Any, Callable, Mapping, Sequence
import weakref

from .digest import canonical_json_bytes, sha256_bytes
from .protected import (
    ProtectedVerificationError,
    _exact_keys,
    _parse_utc,
    _require_commit,
    _require_nonempty,
    _require_sha256,
    _ssh_public_key_fingerprint,
    document_digest,
)
from .protected_v2 import PRINCIPAL_RE, REVIEWER_DELEGATION_NAMESPACE
from .provenance import (
    EXTERNAL_CRITERION_NAMESPACE,
    HUMAN_CRITERION_NAMESPACE,
    VerifiedSignerResult,
)
from .sshsig import SshSigVerificationError, verify_sshsig


DELEGATION_SCHEMA = "urn:agentapi-doctor:reviewer-delegation:v1alpha1"
DELEGATION_KIND = "ReviewerDelegation"
REVOCATION_SCHEMA = (
    "urn:agentapi-doctor:reviewer-delegation-revocation:v1alpha1"
)
REVOCATION_KIND = "ReviewerDelegationRevocation"
ROSTER_SCHEMA = "urn:agentapi-doctor:effective-reviewer-roster:v1alpha1"
ROSTER_KIND = "EffectiveReviewerRoster"

SIGNATURE_SCHEME = "openssh-sshsig-v1"
DOCUMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_DOCUMENTS = 128


@dataclass(frozen=True)
class EffectiveReviewerRoleGrant:
    """One exact role/capability/criterion authorization projection."""

    role: str
    capabilities: tuple[str, ...]
    criteria: tuple[str, ...]


@dataclass(frozen=True)
class EffectiveReviewerPrincipal:
    """Immutable reviewer identity in the effective roster."""

    identity: str
    organization: str
    roles: tuple[str, ...]
    public_key: str
    fingerprint: str
    capabilities: tuple[str, ...]
    criterion_allowlist: tuple[str, ...]
    role_grants: tuple[EffectiveReviewerRoleGrant, ...]
    valid_from: str
    valid_until: str
    origin: str
    delegation_digest: str | None


@dataclass(frozen=True)
class VerifiedReviewerDelegation:
    """A root-signed delegation bound to exact control and chain inputs."""

    attestation_digest: str
    statement_digest: str
    delegation_id: str
    policy_digest: str
    control_plane_digest: str
    source_commit: str
    prior_chain_head_digest: str
    delegator_identity: str
    issued_at: str
    reason: str
    delegate: EffectiveReviewerPrincipal


@dataclass(frozen=True)
class VerifiedReviewerRevocation:
    """A root-signed revocation of one exact verified delegation."""

    attestation_digest: str
    statement_digest: str
    revocation_id: str
    delegation_digest: str
    policy_digest: str
    control_plane_digest: str
    source_commit: str
    prior_chain_head_digest: str
    delegator_identity: str
    delegate_identity: str
    delegate_fingerprint: str
    issued_at: str
    reason: str


@dataclass(frozen=True)
class EffectiveReviewerRoster:
    """Identity-sealed static and unrevoked delegated reviewer roster."""

    policy_digest: str
    control_plane_digest: str
    source_commit: str
    prior_chain_head_digest: str
    delegation_digests: tuple[str, ...]
    revocation_digests: tuple[str, ...]
    principals: tuple[EffectiveReviewerPrincipal, ...]
    authority_digest: str


@dataclass(frozen=True)
class CriterionScopedAuthorization:
    """One signer's authorization, not a criterion threshold decision.

    In particular, this object never claims that P00-H-GO-NOGO's two-principal
    and two-organization threshold has been met.
    """

    criterion_id: str
    principal: str
    organization: str
    role: str
    capability: str
    authority_digest: str
    delegation_digest: str | None


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
            "input must be the exact object returned by this verifier",
        )


def _now_utc(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        _fail("invalid_timestamp", "now", "verification time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_identity(value: Any, path: str) -> str:
    if not isinstance(value, str) or not PRINCIPAL_RE.fullmatch(value):
        _fail("invalid_principal", path, "invalid exact reviewer identity")
    return value


def _validate_document_id(value: Any, path: str) -> str:
    if not isinstance(value, str) or not DOCUMENT_ID_RE.fullmatch(value):
        _fail("invalid_document_id", path, "invalid bounded delegation document ID")
    return value


def _sorted_unique_strings(
    value: Any,
    path: str,
    *,
    allowed: set[str] | None = None,
    nonempty: bool = True,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or any(
            not isinstance(item, str)
            or not item
            or not item.isascii()
            or len(item) > 256
            for item in value
        )
    ):
        _fail("invalid_sorted_set", path, "must be a sorted unique ASCII string list")
    if value != sorted(set(value)):
        _fail("invalid_sorted_set", path, "must be a sorted unique ASCII string list")
    if allowed is not None and not set(value).issubset(allowed):
        _fail("delegation_scope_exceeded", path, "contains a value outside policy scope")
    return tuple(value)


def _signed_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def _validate_signature_descriptor(value: Any, path: str) -> dict[str, str]:
    signature = _exact_keys(
        value, {"scheme", "namespace", "principal", "value"}, path
    )
    if signature["scheme"] != SIGNATURE_SCHEME:
        _fail("unsupported_signature_scheme", f"{path}.scheme", "expected SSHSIG v1")
    if signature["namespace"] != REVIEWER_DELEGATION_NAMESPACE:
        _fail(
            "signature_namespace_mismatch",
            f"{path}.namespace",
            "delegation signatures use one exact non-replayable namespace",
        )
    _validate_identity(signature["principal"], f"{path}.principal")
    armored = signature["value"]
    if (
        not isinstance(armored, str)
        or not armored
        or len(armored) > 16_384
        or "\x00" in armored
    ):
        _fail("malformed_signature", f"{path}.value", "invalid bounded SSHSIG armor")
    return signature


def _validate_envelope(
    value: Any, *, schema: str, kind: str, path: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], str, bytes, str]:
    envelope = _exact_keys(
        value,
        {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
        path,
    )
    if envelope["schemaVersion"] != schema or envelope["kind"] != kind:
        _fail("invalid_statement_schema", path, "schemaVersion or kind mismatch")
    if not isinstance(envelope["body"], dict):
        _fail("invalid_schema", f"{path}.body", "must be an object")
    signature = _validate_signature_descriptor(
        envelope["signature"], f"{path}.signature"
    )
    attestation_digest = document_digest(envelope, omit_field="attestationDigest")
    if envelope["attestationDigest"] != attestation_digest:
        _fail(
            "attestation_digest_mismatch",
            f"{path}.attestationDigest",
            "digest does not cover the exact signed envelope",
        )
    payload = _signed_payload(envelope)
    return (
        envelope,
        envelope["body"],
        signature,
        attestation_digest,
        payload,
        sha256_bytes(payload),
    )


def _validate_policy_context(
    policy_result: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_control_plane_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    _require_sha256(expected_policy_digest, "external.expectedPolicyDigest")
    _require_sha256(
        expected_control_plane_digest, "external.expectedControlPlaneDigest"
    )
    if not isinstance(policy_result, Mapping):
        _fail("invalid_policy_result", "policyResult", "must be a validated policy")
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
            "validated policy differs from the external pin",
        )
    if document.get("controlPlaneDigest") != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "policyResult.document.controlPlaneDigest",
            "policy control plane differs from the external pin",
        )
    policy = document.get("reviewerDelegation")
    if not isinstance(policy, dict) or policy_result.get("reviewerDelegation") != policy:
        _fail(
            "invalid_policy_result",
            "policyResult.reviewerDelegation",
            "validated delegation policy projection is missing or inconsistent",
        )
    if policy.get("namespace") != REVIEWER_DELEGATION_NAMESPACE:
        _fail(
            "reviewer_delegation_policy_drift",
            "policyResult.reviewerDelegation.namespace",
            "unexpected delegation namespace",
        )
    principals = policy_result.get("principals")
    if not isinstance(principals, dict):
        _fail("invalid_policy_result", "policyResult.principals", "roster is missing")
    expected_principals = {
        entry.get("identity"): entry
        for entry in document.get("sshPrincipals", [])
        if isinstance(entry, dict)
    }
    if principals != expected_principals:
        _fail(
            "invalid_policy_result",
            "policyResult.principals",
            "principal projection differs from the policy document",
        )
    roots = policy_result.get("delegationRoots")
    if not isinstance(roots, dict) or len(roots) != 1:
        _fail(
            "invalid_delegation_root",
            "policyResult.delegationRoots",
            "exactly one validated delegation root is required",
        )
    root_capability = policy.get("rootCapability")
    expected_roots = {
        identity: principal
        for identity, principal in principals.items()
        if root_capability in principal.get("capabilities", [])
    }
    if roots != expected_roots:
        _fail(
            "invalid_policy_result",
            "policyResult.delegationRoots",
            "delegation root projection differs from policy principals",
        )
    return document, policy, roots


def _validate_binding(
    body: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_source_commit: str,
    expected_prior_chain_head_digest: str,
    path: str,
) -> None:
    _require_commit(expected_source_commit, "external.expectedSourceCommit")
    _require_sha256(
        expected_prior_chain_head_digest,
        "external.expectedPriorChainHeadDigest",
    )
    expected = {
        "policyDigest": expected_policy_digest,
        "controlPlaneDigest": expected_control_plane_digest,
        "sourceCommit": expected_source_commit,
        "priorChainHeadDigest": expected_prior_chain_head_digest,
    }
    observed = {name: body.get(name) for name in expected}
    if observed != expected:
        code = "delegation_binding_mismatch"
        if observed["priorChainHeadDigest"] != expected_prior_chain_head_digest:
            code = "prior_chain_head_mismatch"
        _fail(code, path, "policy/control/source/prior-chain binding differs")


def _validate_delegator(
    value: Any,
    *,
    signature_principal: str,
    roots: Mapping[str, dict[str, Any]],
    issued_at: datetime,
    revoked_fingerprints: set[str],
    path: str,
) -> dict[str, Any]:
    actor = _exact_keys(value, {"identity", "organization", "fingerprint"}, path)
    identity = _validate_identity(actor["identity"], f"{path}.identity")
    if identity != signature_principal:
        _fail("actor_principal_mismatch", path, "delegator and signature differ")
    root = roots.get(identity)
    if root is None:
        _fail("delegator_not_authorized", path, "signer is not a delegation root")
    if actor != {
        "identity": root["identity"],
        "organization": root["organization"],
        "fingerprint": root["fingerprint"],
    }:
        _fail("delegator_identity_mismatch", path, "delegator metadata differs")
    if root["fingerprint"] in revoked_fingerprints:
        _fail("delegator_revoked", path, "delegation root is revoked")
    if "delegate-reviewer" not in root["capabilities"]:
        _fail("delegator_not_authorized", path, "delegate-reviewer is missing")
    valid_from = _parse_utc(root["validFrom"], f"{path}.root.validFrom")
    valid_until = _parse_utc(root["validUntil"], f"{path}.root.validUntil")
    if not valid_from <= issued_at < valid_until:
        _fail(
            "delegator_outside_validity",
            path,
            "delegation root was not valid when the document was issued",
        )
    return root


def _verify_root_signature(
    *, payload: bytes, signature: Mapping[str, Any], root: Mapping[str, Any]
) -> None:
    try:
        verify_sshsig(
            payload,
            armored_signature=signature["value"],
            public_key=root["publicKey"],
            expected_namespace=REVIEWER_DELEGATION_NAMESPACE,
        )
    except SshSigVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)


def _delegate_principal(
    value: Any,
    *,
    delegation_policy: Mapping[str, Any],
    static_principals: Mapping[str, Any],
    root: Mapping[str, Any],
    issued_at: datetime,
    path: str,
) -> EffectiveReviewerPrincipal:
    delegate = _exact_keys(
        value,
        {
            "identity",
            "organization",
            "roles",
            "publicKey",
            "fingerprint",
            "capabilities",
            "criterionAllowlist",
            "validFrom",
            "validUntil",
        },
        path,
    )
    identity = _validate_identity(delegate["identity"], f"{path}.identity")
    organization = _require_nonempty(
        delegate["organization"], f"{path}.organization", maximum=256
    )
    roles = _sorted_unique_strings(
        delegate["roles"],
        f"{path}.roles",
        allowed=set(delegation_policy["allowedRoles"]),
    )
    capabilities = _sorted_unique_strings(
        delegate["capabilities"],
        f"{path}.capabilities",
        allowed=set(delegation_policy["allowedCapabilities"]),
    )
    role_policy = delegation_policy["roleGrants"]
    expected_capabilities = tuple(
        sorted(
            {
                capability
                for role in roles
                for capability in role_policy[role]["capabilities"]
            }
        )
    )
    if capabilities != expected_capabilities:
        _fail(
            "delegation_capability_mismatch",
            f"{path}.capabilities",
            "capabilities must exactly equal the union granted to selected roles",
        )
    allowed_criteria = {
        criterion
        for role in roles
        for criterion in role_policy[role]["criteria"]
    }
    criteria = _sorted_unique_strings(
        delegate["criterionAllowlist"],
        f"{path}.criterionAllowlist",
        allowed=allowed_criteria,
    )
    role_grants = tuple(
        EffectiveReviewerRoleGrant(
            role=role,
            capabilities=tuple(role_policy[role]["capabilities"]),
            criteria=tuple(
                criterion
                for criterion in role_policy[role]["criteria"]
                if criterion in criteria
            ),
        )
        for role in roles
    )
    if any(not grant.criteria for grant in role_grants):
        _fail(
            "empty_delegated_role",
            f"{path}.criterionAllowlist",
            "each delegated role must authorize at least one selected criterion",
        )
    public_key = delegate["publicKey"]
    if not isinstance(public_key, str):
        _fail(
            "unsupported_public_key",
            f"{path}.publicKey",
            "only comment-free ssh-ed25519 keys are allowed",
        )
    fingerprint = _ssh_public_key_fingerprint(public_key, f"{path}.publicKey")
    if delegate["fingerprint"] != fingerprint:
        _fail(
            "public_key_fingerprint_mismatch",
            f"{path}.fingerprint",
            "fingerprint does not match the delegated Ed25519 key",
        )
    if identity in static_principals:
        _fail("self_delegation", f"{path}.identity", "static identity cannot be delegated")
    static_fingerprints = {
        principal["fingerprint"] for principal in static_principals.values()
    }
    if fingerprint in static_fingerprints:
        _fail(
            "self_delegation",
            f"{path}.fingerprint",
            "a static key cannot be reused under a delegated identity",
        )
    valid_from = _parse_utc(delegate["validFrom"], f"{path}.validFrom")
    valid_until = _parse_utc(delegate["validUntil"], f"{path}.validUntil")
    if valid_from >= valid_until:
        _fail("invalid_delegation_validity", path, "validFrom must precede validUntil")
    if issued_at > valid_from:
        _fail(
            "retroactive_delegation",
            f"{path}.validFrom",
            "delegation validity cannot begin before issuance",
        )
    root_valid_from = _parse_utc(root["validFrom"], f"{path}.root.validFrom")
    root_valid_until = _parse_utc(root["validUntil"], f"{path}.root.validUntil")
    if valid_from < root_valid_from or valid_until > root_valid_until:
        _fail(
            "delegation_exceeds_root_validity",
            path,
            "delegate validity must remain inside delegation-root validity",
        )
    if (valid_until - valid_from).total_seconds() > delegation_policy[
        "maxValiditySeconds"
    ]:
        _fail(
            "delegation_validity_too_long",
            path,
            "delegation exceeds the policy maximum validity",
        )
    return EffectiveReviewerPrincipal(
        identity=identity,
        organization=organization,
        roles=roles,
        public_key=public_key,
        fingerprint=fingerprint,
        capabilities=capabilities,
        criterion_allowlist=criteria,
        role_grants=role_grants,
        valid_from=delegate["validFrom"],
        valid_until=delegate["validUntil"],
        origin="delegation",
        delegation_digest=None,
    )


def verify_reviewer_delegation(
    statement: Any,
    *,
    policy_result: Mapping[str, Any],
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_source_commit: str,
    expected_prior_chain_head_digest: str,
    now: datetime | None = None,
) -> VerifiedReviewerDelegation:
    """Verify one exact root-signed reviewer delegation."""

    document, delegation_policy, roots = _validate_policy_context(
        policy_result,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
    )
    _, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=DELEGATION_SCHEMA,
        kind=DELEGATION_KIND,
        path="delegation",
    )
    body = _exact_keys(
        body,
        {
            "delegationId",
            "policyDigest",
            "controlPlaneDigest",
            "sourceCommit",
            "priorChainHeadDigest",
            "delegator",
            "delegate",
            "issuedAt",
            "reason",
        },
        "delegation.body",
    )
    delegation_id = _validate_document_id(
        body["delegationId"], "delegation.body.delegationId"
    )
    _validate_binding(
        body,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
        expected_source_commit=expected_source_commit,
        expected_prior_chain_head_digest=expected_prior_chain_head_digest,
        path="delegation.body",
    )
    issued_at = _parse_utc(body["issuedAt"], "delegation.body.issuedAt")
    if issued_at > _now_utc(now):
        _fail("future_delegation", "delegation.body.issuedAt", "issuance is in future")
    reason = _require_nonempty(body["reason"], "delegation.body.reason")
    revoked = policy_result.get("revokedFingerprints")
    if not isinstance(revoked, set):
        _fail(
            "invalid_policy_result",
            "policyResult.revokedFingerprints",
            "validated revocation set is missing",
        )
    root = _validate_delegator(
        body["delegator"],
        signature_principal=signature["principal"],
        roots=roots,
        issued_at=issued_at,
        revoked_fingerprints=revoked,
        path="delegation.body.delegator",
    )
    delegate = _delegate_principal(
        body["delegate"],
        delegation_policy=delegation_policy,
        static_principals=policy_result["principals"],
        root=root,
        issued_at=issued_at,
        path="delegation.body.delegate",
    )
    _verify_root_signature(payload=payload, signature=signature, root=root)
    delegate = replace(delegate, delegation_digest=digest)
    return _mark_verified(
        VerifiedReviewerDelegation(
            attestation_digest=digest,
            statement_digest=statement_digest,
            delegation_id=delegation_id,
            policy_digest=expected_policy_digest,
            control_plane_digest=expected_control_plane_digest,
            source_commit=expected_source_commit,
            prior_chain_head_digest=expected_prior_chain_head_digest,
            delegator_identity=root["identity"],
            issued_at=body["issuedAt"],
            reason=reason,
            delegate=delegate,
        )
    )


def verify_reviewer_revocation(
    statement: Any,
    *,
    delegation: VerifiedReviewerDelegation,
    policy_result: Mapping[str, Any],
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_source_commit: str,
    expected_prior_chain_head_digest: str,
    now: datetime | None = None,
) -> VerifiedReviewerRevocation:
    """Verify one exact root-signed delegation revocation."""

    _require_verified(delegation, VerifiedReviewerDelegation, "delegation")
    expected_delegation_binding = (
        expected_policy_digest,
        expected_control_plane_digest,
        expected_source_commit,
        expected_prior_chain_head_digest,
    )
    if (
        delegation.policy_digest,
        delegation.control_plane_digest,
        delegation.source_commit,
        delegation.prior_chain_head_digest,
    ) != expected_delegation_binding:
        _fail(
            "delegation_binding_mismatch",
            "delegation",
            "revocation target belongs to another policy/control/source/chain",
        )
    _, _, roots = _validate_policy_context(
        policy_result,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
    )
    _, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=REVOCATION_SCHEMA,
        kind=REVOCATION_KIND,
        path="revocation",
    )
    body = _exact_keys(
        body,
        {
            "revocationId",
            "delegationDigest",
            "policyDigest",
            "controlPlaneDigest",
            "sourceCommit",
            "priorChainHeadDigest",
            "delegator",
            "delegateIdentity",
            "delegateFingerprint",
            "issuedAt",
            "reason",
        },
        "revocation.body",
    )
    revocation_id = _validate_document_id(
        body["revocationId"], "revocation.body.revocationId"
    )
    _validate_binding(
        body,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
        expected_source_commit=expected_source_commit,
        expected_prior_chain_head_digest=expected_prior_chain_head_digest,
        path="revocation.body",
    )
    expected_target = {
        "delegationDigest": delegation.attestation_digest,
        "delegateIdentity": delegation.delegate.identity,
        "delegateFingerprint": delegation.delegate.fingerprint,
    }
    if {name: body.get(name) for name in expected_target} != expected_target:
        _fail(
            "revocation_target_mismatch",
            "revocation.body",
            "revocation does not identify the exact verified delegation",
        )
    issued_at = _parse_utc(body["issuedAt"], "revocation.body.issuedAt")
    if issued_at < _parse_utc(delegation.issued_at, "delegation.issuedAt"):
        _fail(
            "revocation_before_delegation",
            "revocation.body.issuedAt",
            "revocation cannot precede delegation issuance",
        )
    if issued_at > _now_utc(now):
        _fail("future_revocation", "revocation.body.issuedAt", "issuance is in future")
    reason = _require_nonempty(body["reason"], "revocation.body.reason")
    revoked = policy_result.get("revokedFingerprints")
    if not isinstance(revoked, set):
        _fail(
            "invalid_policy_result",
            "policyResult.revokedFingerprints",
            "validated revocation set is missing",
        )
    root = _validate_delegator(
        body["delegator"],
        signature_principal=signature["principal"],
        roots=roots,
        issued_at=issued_at,
        revoked_fingerprints=revoked,
        path="revocation.body.delegator",
    )
    _verify_root_signature(payload=payload, signature=signature, root=root)
    return _mark_verified(
        VerifiedReviewerRevocation(
            attestation_digest=digest,
            statement_digest=statement_digest,
            revocation_id=revocation_id,
            delegation_digest=delegation.attestation_digest,
            policy_digest=expected_policy_digest,
            control_plane_digest=expected_control_plane_digest,
            source_commit=expected_source_commit,
            prior_chain_head_digest=expected_prior_chain_head_digest,
            delegator_identity=root["identity"],
            delegate_identity=delegation.delegate.identity,
            delegate_fingerprint=delegation.delegate.fingerprint,
            issued_at=body["issuedAt"],
            reason=reason,
        )
    )


def _static_principal(
    principal: Mapping[str, Any], human_grants: Mapping[str, Any]
) -> EffectiveReviewerPrincipal:
    grants = []
    all_criteria: set[str] = set()
    for role in principal["roles"]:
        criteria = tuple(
            sorted(
                criterion
                for criterion, grant in human_grants.items()
                if role in grant["roles"]
            )
        )
        capabilities = (
            ("attest-human-result",)
            if criteria and "attest-human-result" in principal["capabilities"]
            else ()
        )
        all_criteria.update(criteria)
        grants.append(
            EffectiveReviewerRoleGrant(
                role=role,
                capabilities=capabilities,
                criteria=criteria,
            )
        )
    return EffectiveReviewerPrincipal(
        identity=principal["identity"],
        organization=principal["organization"],
        roles=tuple(principal["roles"]),
        public_key=principal["publicKey"],
        fingerprint=principal["fingerprint"],
        capabilities=tuple(principal["capabilities"]),
        criterion_allowlist=tuple(sorted(all_criteria)),
        role_grants=tuple(grants),
        valid_from=principal["validFrom"],
        valid_until=principal["validUntil"],
        origin="policy",
        delegation_digest=None,
    )


def _principal_projection(principal: EffectiveReviewerPrincipal) -> dict[str, Any]:
    return {
        "identity": principal.identity,
        "organization": principal.organization,
        "roles": list(principal.roles),
        "publicKey": principal.public_key,
        "fingerprint": principal.fingerprint,
        "capabilities": list(principal.capabilities),
        "criterionAllowlist": list(principal.criterion_allowlist),
        "roleGrants": [
            {
                "role": grant.role,
                "capabilities": list(grant.capabilities),
                "criteria": list(grant.criteria),
            }
            for grant in principal.role_grants
        ],
        "validFrom": principal.valid_from,
        "validUntil": principal.valid_until,
        "origin": principal.origin,
        "delegationDigest": principal.delegation_digest,
    }


def build_effective_reviewer_roster(
    *,
    policy_result: Mapping[str, Any],
    delegations: Sequence[Any] = (),
    revocations: Sequence[Any] = (),
    expected_policy_digest: str,
    expected_control_plane_digest: str,
    expected_source_commit: str,
    expected_prior_chain_head_digest: str,
    now: datetime | None = None,
) -> EffectiveReviewerRoster:
    """Verify documents and build one identity-sealed effective roster.

    Delegations and revocations in one roster are deliberately bound to the
    same externally pinned prior chain head.  A caller must rebuild the roster
    for a different chain head instead of replaying authorization across forks.
    """

    document, _, _ = _validate_policy_context(
        policy_result,
        expected_policy_digest=expected_policy_digest,
        expected_control_plane_digest=expected_control_plane_digest,
    )
    _require_commit(expected_source_commit, "external.expectedSourceCommit")
    _require_sha256(
        expected_prior_chain_head_digest,
        "external.expectedPriorChainHeadDigest",
    )
    if (
        isinstance(delegations, (str, bytes))
        or not isinstance(delegations, Sequence)
        or len(delegations) > MAX_DOCUMENTS
        or isinstance(revocations, (str, bytes))
        or not isinstance(revocations, Sequence)
        or len(revocations) > MAX_DOCUMENTS
    ):
        _fail(
            "invalid_delegation_set",
            "delegations",
            f"delegation and revocation lists are bounded to {MAX_DOCUMENTS}",
        )
    verification_time = _now_utc(now)
    verified_delegations = tuple(
        verify_reviewer_delegation(
            value,
            policy_result=policy_result,
            expected_policy_digest=expected_policy_digest,
            expected_control_plane_digest=expected_control_plane_digest,
            expected_source_commit=expected_source_commit,
            expected_prior_chain_head_digest=expected_prior_chain_head_digest,
            now=verification_time,
        )
        for value in delegations
    )
    delegation_ids = [value.delegation_id for value in verified_delegations]
    delegation_digests = [
        value.attestation_digest for value in verified_delegations
    ]
    if (
        len(set(delegation_ids)) != len(delegation_ids)
        or len(set(delegation_digests)) != len(delegation_digests)
    ):
        _fail(
            "duplicate_delegation",
            "delegations",
            "delegation IDs and attestation digests must be unique",
        )
    fingerprint_identities: dict[str, set[str]] = {}
    for value in verified_delegations:
        fingerprint_identities.setdefault(value.delegate.fingerprint, set()).add(
            value.delegate.identity
        )
    if any(len(identities) != 1 for identities in fingerprint_identities.values()):
        _fail(
            "key_identity_alias",
            "delegations",
            "one SSH key may not represent multiple delegated identities",
        )
    by_digest = {
        value.attestation_digest: value for value in verified_delegations
    }
    verified_revocations = []
    for index, value in enumerate(revocations):
        target = (
            value.get("body", {}).get("delegationDigest")
            if isinstance(value, dict) and isinstance(value.get("body"), dict)
            else None
        )
        delegation = by_digest.get(target)
        if delegation is None:
            _fail(
                "unknown_delegation",
                f"revocations[{index}].body.delegationDigest",
                "revocation target is not in the verified delegation set",
            )
        verified_revocations.append(
            verify_reviewer_revocation(
                value,
                delegation=delegation,
                policy_result=policy_result,
                expected_policy_digest=expected_policy_digest,
                expected_control_plane_digest=expected_control_plane_digest,
                expected_source_commit=expected_source_commit,
                expected_prior_chain_head_digest=expected_prior_chain_head_digest,
                now=verification_time,
            )
        )
    revocation_ids = [value.revocation_id for value in verified_revocations]
    revoked_delegations = [
        value.delegation_digest for value in verified_revocations
    ]
    if (
        len(set(revocation_ids)) != len(revocation_ids)
        or len(set(revoked_delegations)) != len(revoked_delegations)
    ):
        _fail(
            "duplicate_revocation",
            "revocations",
            "each revocation ID and delegation target must be unique",
        )
    principals = [
        _static_principal(principal, document["humanCriterionRoleGrants"])
        for principal in policy_result["principals"].values()
    ]
    revoked_set = set(revoked_delegations)
    principals.extend(
        value.delegate
        for value in verified_delegations
        if value.attestation_digest not in revoked_set
    )
    identities = [value.identity for value in principals]
    fingerprints = [value.fingerprint for value in principals]
    if len(set(identities)) != len(identities):
        _fail(
            "ambiguous_signer",
            "delegations",
            "effective reviewer identities must be unique",
        )
    if len(set(fingerprints)) != len(fingerprints):
        _fail(
            "ambiguous_signer",
            "delegations",
            "effective reviewer SSH keys must be unique",
        )
    principals_tuple = tuple(sorted(principals, key=lambda value: value.identity))
    delegation_digests_tuple = tuple(sorted(delegation_digests))
    revocation_digests_tuple = tuple(
        sorted(value.attestation_digest for value in verified_revocations)
    )
    roster_document = {
        "schemaVersion": ROSTER_SCHEMA,
        "kind": ROSTER_KIND,
        "policyDigest": expected_policy_digest,
        "controlPlaneDigest": expected_control_plane_digest,
        "sourceCommit": expected_source_commit,
        "priorChainHeadDigest": expected_prior_chain_head_digest,
        "delegationDigests": list(delegation_digests_tuple),
        "revocationDigests": list(revocation_digests_tuple),
        "principals": [
            _principal_projection(principal) for principal in principals_tuple
        ],
    }
    return _mark_verified(
        EffectiveReviewerRoster(
            policy_digest=expected_policy_digest,
            control_plane_digest=expected_control_plane_digest,
            source_commit=expected_source_commit,
            prior_chain_head_digest=expected_prior_chain_head_digest,
            delegation_digests=delegation_digests_tuple,
            revocation_digests=revocation_digests_tuple,
            principals=principals_tuple,
            authority_digest=sha256_bytes(canonical_json_bytes(roster_document)),
        )
    )


def authorize_criterion_signer(
    roster: EffectiveReviewerRoster,
    *,
    principal: str,
    criterion_id: str,
    required_role: str,
    required_capability: str,
    at: datetime | None = None,
) -> CriterionScopedAuthorization:
    """Authorize one identity for one criterion without claiming its threshold."""

    _require_verified(roster, EffectiveReviewerRoster, "roster")
    _validate_identity(principal, "principal")
    _require_nonempty(criterion_id, "criterionId", maximum=256)
    _require_nonempty(required_role, "requiredRole", maximum=256)
    _require_nonempty(required_capability, "requiredCapability", maximum=256)
    selected = next(
        (value for value in roster.principals if value.identity == principal), None
    )
    if selected is None:
        _fail("signer_not_allowed", "principal", "identity is not in effective roster")
    role_grant = next(
        (grant for grant in selected.role_grants if grant.role == required_role),
        None,
    )
    if role_grant is None:
        _fail("role_not_authorized", "requiredRole", "role is not granted")
    if required_capability not in role_grant.capabilities:
        _fail(
            "capability_not_authorized",
            "requiredCapability",
            "capability is not granted for the selected role",
        )
    if criterion_id not in role_grant.criteria:
        _fail(
            "criterion_not_authorized",
            "criterionId",
            "criterion is outside the selected role's allowlist",
        )
    verification_time = _now_utc(at)
    valid_from = _parse_utc(selected.valid_from, "principal.validFrom")
    valid_until = _parse_utc(selected.valid_until, "principal.validUntil")
    if not valid_from <= verification_time < valid_until:
        _fail(
            "signer_outside_validity",
            "principal",
            "reviewer is outside the exact delegated validity interval",
        )
    return _mark_verified(
        CriterionScopedAuthorization(
            criterion_id=criterion_id,
            principal=selected.identity,
            organization=selected.organization,
            role=required_role,
            capability=required_capability,
            authority_digest=roster.authority_digest,
            delegation_digest=selected.delegation_digest,
        )
    )


def make_provenance_signer_verifier(
    roster: EffectiveReviewerRoster,
    *,
    criterion_id: str,
    required_role: str,
    required_capability: str,
    expected_namespace: str,
    expected_source_commit: str,
    expected_control_plane_digest: str,
    verification_time: datetime,
) -> Callable[[bytes, Mapping[str, Any], str], VerifiedSignerResult]:
    """Build a criterion-scoped SSHSIG adapter for provenance.

    The adapter returns the signer's real delegated role.  It intentionally
    does not map rights, technical, or external reviewers to the generic
    ``independent-reviewer`` role.  Existing provenance code must become
    criterion-role aware before it can consume those HUMAN results.

    P00-H-GO-NOGO is rejected here because a single-signer callback cannot
    establish its two-principal and two-organization threshold.  Its future
    multisignature verifier should consume :func:`authorize_criterion_signer`
    results instead.
    """

    _require_verified(roster, EffectiveReviewerRoster, "roster")
    _require_commit(expected_source_commit, "external.expectedSourceCommit")
    _require_sha256(
        expected_control_plane_digest, "external.expectedControlPlaneDigest"
    )
    if expected_source_commit != roster.source_commit:
        _fail("source_commit_mismatch", "roster", "source differs from roster")
    if expected_control_plane_digest != roster.control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "roster",
            "control plane differs from roster",
        )
    if criterion_id == "P00-H-GO-NOGO":
        _fail(
            "multisignature_verifier_required",
            "criterionId",
            "P00 go/no-go requires two principals and two organizations",
        )
    if criterion_id.startswith("P00-H-"):
        required_namespace = HUMAN_CRITERION_NAMESPACE
    elif criterion_id.startswith("P00-X-"):
        required_namespace = EXTERNAL_CRITERION_NAMESPACE
    else:
        _fail("unsupported_criterion", "criterionId", "unsupported P00 criterion")
    if expected_namespace != required_namespace:
        _fail(
            "signature_namespace_mismatch",
            "expectedNamespace",
            "criterion kind and provenance namespace differ",
        )
    fixed_time = _now_utc(verification_time)

    def verify(
        payload: bytes, signature: Mapping[str, Any], namespace: str
    ) -> VerifiedSignerResult:
        if not isinstance(payload, bytes):
            _fail("invalid_signature_payload", "payload", "payload must be bytes")
        descriptor = _exact_keys(
            signature,
            {"scheme", "namespace", "principal", "value"},
            "signature",
        )
        if descriptor["scheme"] != SIGNATURE_SCHEME:
            _fail(
                "unsupported_signature_scheme",
                "signature.scheme",
                "delegated reviewers must use SSHSIG v1",
            )
        if namespace != expected_namespace or descriptor["namespace"] != namespace:
            _fail(
                "signature_namespace_mismatch",
                "signature.namespace",
                "signature cannot be replayed across criterion domains",
            )
        principal = _validate_identity(
            descriptor["principal"], "signature.principal"
        )
        authorization = authorize_criterion_signer(
            roster,
            principal=principal,
            criterion_id=criterion_id,
            required_role=required_role,
            required_capability=required_capability,
            at=fixed_time,
        )
        selected = next(
            value for value in roster.principals if value.identity == principal
        )
        try:
            verify_sshsig(
                payload,
                armored_signature=descriptor["value"],
                public_key=selected.public_key,
                expected_namespace=expected_namespace,
            )
        except SshSigVerificationError as exc:
            _fail(exc.code, exc.path, exc.message)
        return VerifiedSignerResult(
            scheme=SIGNATURE_SCHEME,
            namespace=expected_namespace,
            principal=authorization.principal,
            role=authorization.role,
            organization=authorization.organization,
            statement_digest=sha256_bytes(payload),
            authority_digest=authorization.authority_digest,
            source_commit=expected_source_commit,
            control_plane_digest=expected_control_plane_digest,
        )

    return verify
