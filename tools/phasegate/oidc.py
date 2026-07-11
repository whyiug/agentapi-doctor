"""Narrow, dependency-free verification for GitHub Actions OIDC JWTs.

This module is intentionally an offline verifier.  It never discovers or
downloads keys.  Callers must supply a separately approved JWK snapshot and an
exact set of expected claims.  The token proves provenance for one canonical
statement; it does not, by itself, prove branch protection or authorization.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping


OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RS256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
MAX_TOKEN_BYTES = 32768
MAX_TOKEN_LIFETIME_SECONDS = 600
MAX_EVENT_TO_ISSUE_SKEW_SECONDS = 120


@dataclass
class OidcVerificationError(ValueError):
    """Stable fail-closed error returned by the protected verifier."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> None:
    raise OidcVerificationError(code, path, message)


def _strict_json(payload: bytes, path: str) -> Any:
    if len(payload) > MAX_TOKEN_BYTES:
        _fail("oidc_document_too_large", path, "decoded JWT JSON is too large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail("invalid_oidc_json", path, f"JWT JSON is not UTF-8: {exc}")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("duplicate_oidc_json_key", path, f"duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(token: str) -> Any:
        _fail("invalid_oidc_json", path, f"non-finite number {token}")

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        _fail(
            "invalid_oidc_json",
            path,
            f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
        )


def _base64url_decode(value: str, path: str, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or (not value and not allow_empty):
        _fail("invalid_base64url", path, "base64url value is empty")
    if value and ("=" in value or not BASE64URL_RE.fullmatch(value)):
        _fail(
            "invalid_base64url",
            path,
            "base64url must be unpadded and use only the URL-safe alphabet",
        )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        _fail("invalid_base64url", path, str(exc))
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        _fail("noncanonical_base64url", path, "base64url encoding is not canonical")
    return decoded


def _integer_claim(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("invalid_oidc_time", f"jwt.claims.{name}", "must be an integer")
    return value


def _validate_jwk(entry: Any, index: int) -> dict[str, Any]:
    path = f"jwks.keys[{index}]"
    if not isinstance(entry, dict):
        _fail("invalid_oidc_jwk", path, "JWK must be an object")
    expected = {"kid", "kty", "use", "alg", "n", "e"}
    if set(entry) != expected:
        _fail("invalid_oidc_jwk", path, "JWK field set must be exact")
    kid = entry["kid"]
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        _fail("invalid_oidc_jwk", f"{path}.kid", "invalid exact key ID")
    if entry["kty"] != "RSA" or entry["use"] != "sig" or entry["alg"] != "RS256":
        _fail(
            "invalid_oidc_jwk",
            path,
            "only RSA signing keys restricted to RS256 are accepted",
        )
    modulus_bytes = _base64url_decode(entry["n"], f"{path}.n")
    exponent_bytes = _base64url_decode(entry["e"], f"{path}.e")
    if not modulus_bytes or modulus_bytes[0] == 0:
        _fail("invalid_oidc_jwk", f"{path}.n", "RSA modulus is not minimally encoded")
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if modulus.bit_length() < 2048 or modulus.bit_length() > 4096:
        _fail("invalid_oidc_jwk", f"{path}.n", "RSA modulus must be 2048-4096 bits")
    if exponent != 65537:
        _fail("invalid_oidc_jwk", f"{path}.e", "RSA exponent must be 65537")
    return {**entry, "modulus": modulus, "exponent": exponent}


def validate_jwks(keys: Any) -> dict[str, dict[str, Any]]:
    """Validate a normalized, already approved JWK list."""

    if not isinstance(keys, list) or not keys:
        _fail("invalid_oidc_jwks", "jwks.keys", "at least one approved JWK is required")
    validated = [_validate_jwk(entry, index) for index, entry in enumerate(keys)]
    kids = [entry["kid"] for entry in validated]
    if len(set(kids)) != len(kids):
        _fail("duplicate_oidc_kid", "jwks.keys", "JWK key IDs must be unique")
    if kids != sorted(kids):
        _fail("invalid_oidc_jwks", "jwks.keys", "JWK keys must be sorted by kid")
    return {entry["kid"]: entry for entry in validated}


def jwks_snapshot_digest(snapshot: Any) -> str:
    """Return the canonical digest used as an external snapshot pin."""

    try:
        payload = json.dumps(
            snapshot,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail("invalid_oidc_jwks_snapshot", "jwks", str(exc))
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_jwks_snapshot(
    snapshot: Any, *, expected_snapshot_digest: str
) -> dict[str, Any]:
    """Validate the exact offline GitHub JWK snapshot and its external pin."""

    if not isinstance(expected_snapshot_digest, str) or not SHA256_RE.fullmatch(
        expected_snapshot_digest
    ):
        _fail(
            "invalid_oidc_policy",
            "expectedJwksSnapshotDigest",
            "expected lowercase sha256:<64 hex>",
        )
    if jwks_snapshot_digest(snapshot) != expected_snapshot_digest:
        _fail(
            "oidc_jwks_snapshot_digest_mismatch",
            "jwks",
            "snapshot differs from its external approval pin",
        )
    if not isinstance(snapshot, dict):
        _fail("invalid_oidc_jwks_snapshot", "jwks", "snapshot must be an object")
    expected_fields = {
        "schemaVersion",
        "kind",
        "snapshotStatus",
        "issuer",
        "discoveryUrl",
        "jwksUrl",
        "retrievedAt",
        "sourceRawDigest",
        "algorithms",
        "historicalVerificationPolicy",
        "keys",
    }
    if set(snapshot) != expected_fields:
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks",
            "snapshot field set must be exact",
        )
    if (
        snapshot["schemaVersion"]
        != "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1"
        or snapshot["kind"] != "GitHubActionsOidcJwksSnapshotCandidate"
        or snapshot["snapshotStatus"] != "candidate-unapproved"
    ):
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks",
            "unsupported snapshot schema, kind, or review status",
        )
    if (
        snapshot["issuer"] != OIDC_ISSUER
        or snapshot["discoveryUrl"]
        != OIDC_ISSUER + "/.well-known/openid-configuration"
        or snapshot["jwksUrl"] != OIDC_ISSUER + "/.well-known/jwks"
        or snapshot["algorithms"] != ["RS256"]
    ):
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks",
            "issuer discovery or algorithm policy drift",
        )
    retrieved = snapshot["retrievedAt"]
    if not isinstance(retrieved, str) or not RFC3339_UTC_RE.fullmatch(retrieved):
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks.retrievedAt",
            "expected second-precision RFC3339 UTC",
        )
    try:
        datetime.strptime(retrieved, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        _fail("invalid_oidc_jwks_snapshot", "jwks.retrievedAt", str(exc))
    raw_digest = snapshot["sourceRawDigest"]
    if not isinstance(raw_digest, str) or not SHA256_RE.fullmatch(raw_digest):
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks.sourceRawDigest",
            "source response digest is invalid",
        )
    if snapshot["historicalVerificationPolicy"] != {
        "networkDuringReplay": "forbidden",
        "unknownKid": "block-for-independently-approved-rotation",
        "tokenValidity": "the StateEvent timestamp must precede token issuance by at most 120 seconds and token lifetime must not exceed 600 seconds",
        "revocation": "a later policy revision may explicitly revoke a key; repository-local online refresh never grants trust",
    }:
        _fail(
            "invalid_oidc_jwks_snapshot",
            "jwks.historicalVerificationPolicy",
            "historical verification policy drift",
        )
    return {
        "digest": expected_snapshot_digest,
        "keys": validate_jwks(snapshot["keys"]),
        "document": snapshot,
    }


def _verify_rs256(
    signing_input: bytes,
    signature: bytes,
    *,
    modulus: int,
    exponent: int,
) -> None:
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width:
        _fail("invalid_oidc_signature", "jwt.signature", "RSA signature width mismatch")
    encoded_integer = int.from_bytes(signature, "big")
    if encoded_integer >= modulus:
        _fail("invalid_oidc_signature", "jwt.signature", "RSA signature is out of range")
    encoded = pow(encoded_integer, exponent, modulus).to_bytes(width, "big")
    digest = hashlib.sha256(signing_input).digest()
    trailer = RS256_DIGEST_INFO + digest
    padding_length = width - len(trailer) - 3
    if padding_length < 8:
        _fail("invalid_oidc_signature", "jwt.signature", "RSA key is too short")
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + trailer
    if not hmac.compare_digest(encoded, expected):
        _fail(
            "invalid_oidc_signature",
            "jwt.signature",
            "RS256 PKCS#1 v1.5 verification failed",
        )


def _epoch(value: datetime, path: str) -> int:
    if value.tzinfo is None:
        _fail("invalid_oidc_time", path, "timestamp must be timezone-aware")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_oidc_time", path, "timestamp must have second precision")
    return int(normalized.timestamp())


def verify_github_actions_oidc_token(
    token: str,
    *,
    approved_jwks: Any,
    expected_audience: str,
    expected_claims: Mapping[str, str],
    statement_timestamp: datetime,
) -> dict[str, Any]:
    """Verify one digest-bound GitHub Actions token entirely offline.

    Token expiry is checked against the signed statement timestamp and issue
    time, rather than the later replay time.  This preserves historical
    verification without treating the short-lived bearer token as currently
    valid authentication.
    """

    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_BYTES:
        _fail("invalid_oidc_token", "jwt", "JWT must be bounded ASCII")
    segments = token.split(".")
    if len(segments) != 3:
        _fail("invalid_oidc_token", "jwt", "JWT must contain exactly three segments")
    header_raw = _base64url_decode(segments[0], "jwt.header")
    claims_raw = _base64url_decode(segments[1], "jwt.claims")
    signature = _base64url_decode(segments[2], "jwt.signature")
    header = _strict_json(header_raw, "jwt.header")
    claims = _strict_json(claims_raw, "jwt.claims")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        _fail("invalid_oidc_json", "jwt", "header and claims must be objects")
    required_header = {"alg", "kid", "typ"}
    allowed_header = required_header | {"x5t", "x5t#S256"}
    if not required_header.issubset(header) or not set(header).issubset(allowed_header):
        _fail(
            "invalid_oidc_header",
            "jwt.header",
            "header fields are missing or contain a key-selection override",
        )
    if header["alg"] != "RS256" or header["typ"] != "JWT":
        _fail("unsupported_oidc_algorithm", "jwt.header", "only RS256 JWT is accepted")
    kid = header["kid"]
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        _fail("invalid_oidc_header", "jwt.header.kid", "invalid exact key ID")
    jwks = validate_jwks(approved_jwks)
    key = jwks.get(kid)
    if key is None:
        _fail("unknown_oidc_kid", "jwt.header.kid", "key ID is absent from approved snapshot")
    signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
    _verify_rs256(
        signing_input,
        signature,
        modulus=key["modulus"],
        exponent=key["exponent"],
    )

    if claims.get("iss") != OIDC_ISSUER:
        _fail("oidc_claim_mismatch", "jwt.claims.iss", "issuer mismatch")
    if not isinstance(expected_audience, str) or not expected_audience:
        _fail("invalid_oidc_policy", "expectedAudience", "audience pin is required")
    if claims.get("aud") != expected_audience:
        _fail(
            "oidc_audience_mismatch",
            "jwt.claims.aud",
            "audience must exactly bind the canonical statement digest",
        )
    for name, expected in expected_claims.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            _fail("invalid_oidc_policy", "expectedClaims", "claim pins must be strings")
        if claims.get(name) != expected:
            _fail("oidc_claim_mismatch", f"jwt.claims.{name}", "claim differs from policy")

    for required in ("jti", "run_id", "run_number", "run_attempt", "check_run_id"):
        value = claims.get(required)
        if not isinstance(value, str) or not value or len(value) > 256:
            _fail("missing_oidc_claim", f"jwt.claims.{required}", "required claim missing")
    if claims["run_attempt"] != "1":
        _fail("oidc_rerun_forbidden", "jwt.claims.run_attempt", "rerun tokens are forbidden")
    for name in ("run_id", "run_number", "run_attempt", "check_run_id"):
        if not claims[name].isascii() or not claims[name].isdigit():
            _fail("invalid_oidc_claim", f"jwt.claims.{name}", "must be decimal ASCII")
    for name in ("workflow_sha", "sha"):
        value = claims.get(name)
        if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
            _fail("invalid_oidc_claim", f"jwt.claims.{name}", "must be a full Git SHA-1")

    issued_at = _integer_claim(claims, "iat")
    not_before = _integer_claim(claims, "nbf")
    expires_at = _integer_claim(claims, "exp")
    if not_before > issued_at or issued_at >= expires_at:
        _fail("invalid_oidc_time", "jwt.claims", "nbf/iat/exp order is invalid")
    if issued_at - not_before > 60:
        _fail("invalid_oidc_time", "jwt.claims.nbf", "not-before skew is excessive")
    if expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS:
        _fail("invalid_oidc_time", "jwt.claims.exp", "token lifetime is excessive")
    event_epoch = _epoch(statement_timestamp, "statementTimestamp")
    if event_epoch > issued_at or issued_at - event_epoch > MAX_EVENT_TO_ISSUE_SKEW_SECONDS:
        _fail(
            "oidc_statement_time_mismatch",
            "statementTimestamp",
            "statement must be created shortly before token issuance",
        )
    if not not_before <= issued_at < expires_at:
        _fail("invalid_oidc_time", "jwt.claims", "token issue instant is outside validity")
    return dict(claims)
