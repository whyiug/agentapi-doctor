"""Dependency-free verification for the narrow OpenSSH SSHSIG profile.

The implementation accepts only comment-free Ed25519 public keys, SSHSIG
version 1, an empty reserved field, SHA-256/SHA-512 message prehashing, and an
Ed25519 SSH signature.  It follows OpenSSH ``PROTOCOL.sshsig`` and RFC 8032.
Signing is deliberately out of scope.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import re
from typing import Any


MAGIC = b"SSHSIG"
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"
SSH_ED25519 = b"ssh-ed25519"
MAX_ARMOR_BYTES = 16384
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._@:+-]{0,255}$")

# RFC 8032 / Ed25519 constants.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
SQRT_M1 = pow(2, (Q - 1) // 4, Q)
IDENTITY = (0, 1)


@dataclass
class SshSigVerificationError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> None:
    raise SshSigVerificationError(code, path, message)


def _ssh_string(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        _fail("sshsig_value_too_large", "sshsig", "SSH string is too large")
    return len(value).to_bytes(4, "big") + value


class _Reader:
    def __init__(self, payload: bytes, path: str) -> None:
        self.payload = payload
        self.offset = 0
        self.path = path

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.payload):
            _fail("malformed_sshsig", self.path, "truncated SSH wire value")
        result = self.payload[self.offset : self.offset + count]
        self.offset += count
        return result

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def string(self, *, maximum: int = 16384) -> bytes:
        length = self.u32()
        if length > maximum:
            _fail("malformed_sshsig", self.path, "SSH string exceeds limit")
        return self.take(length)

    def finish(self) -> None:
        if self.offset != len(self.payload):
            _fail("malformed_sshsig", self.path, "trailing SSH wire bytes")


def _decode_armor(armored: Any) -> bytes:
    if (
        not isinstance(armored, str)
        or not armored.isascii()
        or len(armored.encode("ascii")) > MAX_ARMOR_BYTES
        or "\r" in armored
        or "\x00" in armored
    ):
        _fail("malformed_sshsig_armor", "signature.value", "invalid bounded ASCII armor")
    lines = armored.rstrip("\n").split("\n")
    if (
        len(lines) < 3
        or lines[0] != ARMOR_BEGIN
        or lines[-1] != ARMOR_END
        or any(not line or len(line) > 76 for line in lines[1:-1])
    ):
        _fail("malformed_sshsig_armor", "signature.value", "invalid SSHSIG armor framing")
    encoded = "".join(lines[1:-1])
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        _fail("malformed_sshsig_armor", "signature.value", str(exc))
    if base64.b64encode(decoded).decode("ascii") != encoded:
        _fail("malformed_sshsig_armor", "signature.value", "noncanonical base64 armor")
    return decoded


def _parse_public_key(public_key: Any) -> tuple[bytes, bytes]:
    if not isinstance(public_key, str) or len(public_key) > 1024:
        _fail("invalid_sshsig_public_key", "publicKey", "invalid public key")
    fields = public_key.split(" ")
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        _fail(
            "invalid_sshsig_public_key",
            "publicKey",
            "only comment-free ssh-ed25519 keys are accepted",
        )
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        _fail("invalid_sshsig_public_key", "publicKey", str(exc))
    if base64.b64encode(blob).decode("ascii") != fields[1]:
        _fail("invalid_sshsig_public_key", "publicKey", "noncanonical key base64")
    reader = _Reader(blob, "publicKey")
    algorithm = reader.string(maximum=64)
    raw_key = reader.string(maximum=64)
    reader.finish()
    if algorithm != SSH_ED25519 or len(raw_key) != 32:
        _fail("invalid_sshsig_public_key", "publicKey", "invalid Ed25519 key blob")
    _decode_point(raw_key, "publicKey")
    return blob, raw_key


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = x * SQRT_M1 % Q
    if (x * x - xx) % Q != 0:
        _fail("invalid_ed25519_point", "signature", "point is not on Ed25519")
    return x


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2 % Q
    x3 = (x1 * y2 + y1 * x2) * pow(1 + product, Q - 2, Q) % Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q) % Q
    return x3, y3


def _scalar_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    if scalar < 0:
        _fail("invalid_ed25519_scalar", "signature", "negative scalar")
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


BASE_Y = 4 * pow(5, Q - 2, Q) % Q
BASE_X = _recover_x(BASE_Y)
if BASE_X & 1:
    BASE_X = Q - BASE_X
BASE = (BASE_X, BASE_Y)


def _decode_point(encoded: bytes, path: str) -> tuple[int, int]:
    if len(encoded) != 32:
        _fail("invalid_ed25519_point", path, "Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= Q:
        _fail("invalid_ed25519_point", path, "noncanonical Ed25519 y coordinate")
    x = _recover_x(y)
    if (x & 1) != sign:
        x = Q - x
    if x == 0 and sign:
        _fail("invalid_ed25519_point", path, "noncanonical Ed25519 sign bit")
    point = (x, y)
    if _scalar_multiply(point, L) != IDENTITY:
        _fail("invalid_ed25519_point", path, "point is outside the prime-order subgroup")
    if point == IDENTITY or _scalar_multiply(point, 8) == IDENTITY:
        _fail("invalid_ed25519_point", path, "small-order Ed25519 point is forbidden")
    return point


def _verify_ed25519(message: bytes, signature: bytes, public_key: bytes) -> None:
    if len(signature) != 64:
        _fail("invalid_ed25519_signature", "signature", "Ed25519 signature must be 64 bytes")
    encoded_r = signature[:32]
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        _fail("invalid_ed25519_signature", "signature", "Ed25519 scalar is noncanonical")
    point_a = _decode_point(public_key, "publicKey")
    point_r = _decode_point(encoded_r, "signature.R")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % L
    if _scalar_multiply(BASE, scalar) != _add(
        point_r, _scalar_multiply(point_a, challenge)
    ):
        _fail("invalid_ed25519_signature", "signature", "Ed25519 verification failed")


def verify_sshsig(
    payload: bytes,
    *,
    armored_signature: Any,
    public_key: Any,
    expected_namespace: str,
) -> dict[str, str]:
    """Verify an OpenSSH SSHSIG using the approved Ed25519 public key."""

    if not isinstance(payload, bytes):
        _fail("invalid_sshsig_payload", "payload", "payload must be bytes")
    if (
        not isinstance(expected_namespace, str)
        or not NAMESPACE_RE.fullmatch(expected_namespace)
    ):
        _fail("invalid_sshsig_namespace", "expectedNamespace", "invalid exact namespace")
    approved_blob, raw_public_key = _parse_public_key(public_key)
    blob = _decode_armor(armored_signature)
    reader = _Reader(blob, "signature.value")
    if reader.take(6) != MAGIC or reader.u32() != 1:
        _fail("malformed_sshsig", "signature.value", "magic or version mismatch")
    embedded_key = reader.string(maximum=1024)
    namespace_raw = reader.string(maximum=256)
    reserved = reader.string(maximum=1024)
    hash_algorithm = reader.string(maximum=32)
    signature_blob = reader.string(maximum=1024)
    reader.finish()
    if embedded_key != approved_blob:
        _fail("sshsig_key_mismatch", "signature.value", "embedded key is not approved")
    try:
        namespace = namespace_raw.decode("ascii")
        hash_name = hash_algorithm.decode("ascii")
    except UnicodeDecodeError as exc:
        _fail("malformed_sshsig", "signature.value", str(exc))
    if namespace != expected_namespace:
        _fail("sshsig_namespace_mismatch", "signature.namespace", "namespace mismatch")
    if reserved != b"":
        _fail("unsupported_sshsig_reserved", "signature.value", "reserved field must be empty")
    if hash_name not in {"sha256", "sha512"}:
        _fail("unsupported_sshsig_hash", "signature.value", "unsupported message hash")
    signature_reader = _Reader(signature_blob, "signature.value.signature")
    algorithm = signature_reader.string(maximum=64)
    raw_signature = signature_reader.string(maximum=128)
    signature_reader.finish()
    if algorithm != SSH_ED25519:
        _fail("unsupported_sshsig_algorithm", "signature.value", "signature is not Ed25519")
    message_digest = hashlib.new(hash_name, payload).digest()
    signed = (
        MAGIC
        + _ssh_string(namespace_raw)
        + _ssh_string(b"")
        + _ssh_string(hash_algorithm)
        + _ssh_string(message_digest)
    )
    _verify_ed25519(signed, raw_signature, raw_public_key)
    return {"namespace": namespace, "hashAlgorithm": hash_name}
