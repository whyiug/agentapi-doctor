"""Portable SSHSIG verification for an externally pinned state-chain head.

A chain witness does not create or mutate state.  It records the exact head a
human maintainer observed before a protected workflow appends the next event.
The resulting identity-sealed object is intended to be consumed in-process by
the event writer; a caller-supplied dictionary with the same fields is not an
authorization result.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping
import weakref

from .protected import (
    ProtectedVerificationError,
    _exact_keys,
    _parse_utc,
    _require_commit,
    _require_nonempty,
    _require_sha256,
    document_digest,
)
from .protected_v2 import (
    _now_utc,
    _principal_for,
    _signed_payload,
    _validate_signature_descriptor,
    _verify_human_sshsig,
)


CHAIN_WITNESS_SCHEMA = "urn:agentapi-doctor:chain-head-witness:v1alpha1"
CHAIN_WITNESS_KIND = "ChainHeadWitness"
CHAIN_WITNESS_NAMESPACE = "agentapi-doctor/chain-head-witness/v1"


@dataclass(frozen=True)
class VerifiedChainHeadWitness:
    attestation_digest: str
    witness_id: str
    prior_chain_head_digest: str
    prior_state_digest: str
    prior_event_count: int
    prior_head_sequence: int
    prior_source_commit: str
    control_plane_digest: str
    trust_policy_digest: str
    witnessed_at: datetime
    valid_until: datetime
    principal: str
    organization: str


_VERIFIED: dict[int, weakref.ReferenceType[Any]] = {}


def _fail(code: str, path: str, message: str) -> None:
    raise ProtectedVerificationError(code, path, message)


def _mark_verified(value: VerifiedChainHeadWitness) -> VerifiedChainHeadWitness:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if _VERIFIED.get(identity) is reference:
            _VERIFIED.pop(identity, None)

    _VERIFIED[identity] = weakref.ref(value, discard)
    return value


def require_verified_chain_head_witness(
    value: Any, *, path: str = "chainHeadWitness"
) -> VerifiedChainHeadWitness:
    reference = _VERIFIED.get(id(value))
    if (
        not isinstance(value, VerifiedChainHeadWitness)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact identity-sealed chain witness returned by this verifier",
        )
    return value


def _bounded_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("invalid_chain_position", path, "must be a non-negative integer")
    if value > 2**53 - 1:
        _fail("invalid_chain_position", path, "integer exceeds portable JSON range")
    return value


def verify_chain_head_witness(
    statement: Any,
    *,
    policy_result: Mapping[str, Any],
    expected_prior_chain_head_digest: str,
    expected_prior_state_digest: str,
    expected_prior_event_count: int,
    expected_prior_head_sequence: int,
    expected_prior_source_commit: str,
    expected_control_plane_digest: str,
    expected_trust_policy_digest: str,
    now: datetime | None = None,
) -> VerifiedChainHeadWitness:
    """Verify one exact, currently valid maintainer chain-head observation."""

    for value, path in (
        (expected_prior_chain_head_digest, "external.expectedPriorChainHeadDigest"),
        (expected_prior_state_digest, "external.expectedPriorStateDigest"),
        (expected_control_plane_digest, "external.expectedControlPlaneDigest"),
        (expected_trust_policy_digest, "external.expectedTrustPolicyDigest"),
    ):
        _require_sha256(value, path)
    _require_commit(
        expected_prior_source_commit, "external.expectedPriorSourceCommit"
    )
    expected_event_count = _bounded_integer(
        expected_prior_event_count, "external.expectedPriorEventCount"
    )
    expected_sequence = _bounded_integer(
        expected_prior_head_sequence, "external.expectedPriorHeadSequence"
    )
    if expected_event_count != expected_sequence + 1:
        _fail(
            "invalid_chain_position",
            "external",
            "event count must equal head sequence plus one",
        )
    envelope = _exact_keys(
        statement,
        {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
        "chainHeadWitness",
    )
    if (
        envelope["schemaVersion"] != CHAIN_WITNESS_SCHEMA
        or envelope["kind"] != CHAIN_WITNESS_KIND
    ):
        _fail(
            "invalid_chain_witness_schema",
            "chainHeadWitness",
            "unsupported chain witness envelope",
        )
    digest = document_digest(envelope, omit_field="attestationDigest")
    if envelope["attestationDigest"] != digest:
        _fail(
            "chain_witness_digest_mismatch",
            "chainHeadWitness.attestationDigest",
            "witness digest mismatch",
        )
    body = _exact_keys(
        envelope["body"],
        {
            "witnessId",
            "priorChainHeadDigest",
            "priorStateDigest",
            "priorEventCount",
            "priorHeadSequence",
            "priorSourceCommit",
            "controlPlaneDigest",
            "trustPolicyDigest",
            "witnessedAt",
            "validUntil",
            "reason",
            "actor",
        },
        "chainHeadWitness.body",
    )
    witness_id = _require_nonempty(
        body["witnessId"], "chainHeadWitness.body.witnessId", maximum=256
    )
    exact = {
        "priorChainHeadDigest": expected_prior_chain_head_digest,
        "priorStateDigest": expected_prior_state_digest,
        "priorEventCount": expected_event_count,
        "priorHeadSequence": expected_sequence,
        "priorSourceCommit": expected_prior_source_commit,
        "controlPlaneDigest": expected_control_plane_digest,
        "trustPolicyDigest": expected_trust_policy_digest,
    }
    if any(body[key] != value for key, value in exact.items()):
        _fail(
            "chain_witness_binding_mismatch",
            "chainHeadWitness.body",
            "witness is for another state, head, source, policy, or control plane",
        )
    _require_nonempty(body["reason"], "chainHeadWitness.body.reason")
    witnessed_at = _parse_utc(
        body["witnessedAt"], "chainHeadWitness.body.witnessedAt"
    )
    valid_until = _parse_utc(
        body["validUntil"], "chainHeadWitness.body.validUntil"
    )
    verification_time = _now_utc(now)
    if witnessed_at >= valid_until or not witnessed_at <= verification_time < valid_until:
        _fail(
            "chain_witness_outside_validity",
            "chainHeadWitness.body",
            "chain witness is not currently valid",
        )
    if (valid_until - witnessed_at).total_seconds() > 86400:
        _fail(
            "chain_witness_validity_too_long",
            "chainHeadWitness.body.validUntil",
            "chain witness validity may not exceed 24 hours",
        )
    actor = _exact_keys(
        body["actor"],
        {"principal", "role", "organization"},
        "chainHeadWitness.body.actor",
    )
    signature_principal, _ = _validate_signature_descriptor(
        envelope["signature"],
        expected_namespace=CHAIN_WITNESS_NAMESPACE,
        path="chainHeadWitness.signature",
    )
    if signature_principal != actor["principal"]:
        _fail(
            "actor_principal_mismatch",
            "chainHeadWitness",
            "actor and signature principal differ",
        )
    if policy_result.get("digest") != expected_trust_policy_digest:
        _fail(
            "trust_policy_digest_mismatch",
            "policyResult",
            "verified policy differs from the external pin",
        )
    trusted = _principal_for(
        policy_result,
        identity=signature_principal,
        capability="witness-chain-head",
        role=actor["role"],
        at=verification_time,
    )
    if actor["organization"] != trusted["organization"]:
        _fail(
            "role_not_authorized",
            "chainHeadWitness.body.actor",
            "actor organization differs from policy",
        )
    _verify_human_sshsig(
        payload=_signed_payload(envelope),
        signature=envelope["signature"],
        principal=trusted,
        namespace=CHAIN_WITNESS_NAMESPACE,
    )
    return _mark_verified(
        VerifiedChainHeadWitness(
            attestation_digest=digest,
            witness_id=witness_id,
            prior_chain_head_digest=expected_prior_chain_head_digest,
            prior_state_digest=expected_prior_state_digest,
            prior_event_count=expected_event_count,
            prior_head_sequence=expected_sequence,
            prior_source_commit=expected_prior_source_commit,
            control_plane_digest=expected_control_plane_digest,
            trust_policy_digest=expected_trust_policy_digest,
            witnessed_at=witnessed_at,
            valid_until=valid_until,
            principal=actor["principal"],
            organization=actor["organization"],
        )
    )
