"""Strict transport container for a raw R3 state chain and its authorizations.

This module deliberately grants no authority.  It preserves the exact raw
bootstrap approval, StateEvent envelopes, and post-Genesis authorization
bundles across process and GitHub Actions artifact boundaries.  Cryptographic
verification and state replay remain the responsibility of the protected
verifiers; this parser only prevents ambiguous, truncated, reordered, or
non-canonical transport input from reaching them.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, NoReturn, Sequence

from .digest import DigestError, canonical_json_bytes
from .protected import document_digest


CHAIN_ARTIFACT_SCHEMA = "urn:agentapi-doctor:state-chain-artifact:v1alpha1"
CHAIN_ARTIFACT_KIND = "RawStateChainArtifact"
MAX_CHAIN_ARTIFACT_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EVENT_ID_RE = re.compile(r"^evt-([0-9]{8})$")


@dataclass
class ChainArtifactError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class ParsedChainEntry:
    event: Mapping[str, Any]
    authorization_bundle: bytes


@dataclass(frozen=True)
class ParsedChainArtifact:
    bootstrap_approval: Mapping[str, Any]
    genesis_event: Mapping[str, Any]
    entries: tuple[ParsedChainEntry, ...]
    event_count: int
    head_digest: str
    artifact_digest: str

    @property
    def events(self) -> tuple[Mapping[str, Any], ...]:
        return (self.genesis_event, *(entry.event for entry in self.entries))


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise ChainArtifactError(code, path, message)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            _fail("duplicate_key", "chainArtifact", key)
        value[key] = item
    return value


def _reject_constant(value: str) -> NoReturn:
    _fail("noncanonical_json", "chainArtifact", f"non-finite number {value}")


def _load(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CHAIN_ARTIFACT_BYTES:
        _fail(
            "invalid_artifact_bytes",
            "chainArtifact",
            "non-empty bounded bytes are required",
        )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        _fail("invalid_artifact_json", "chainArtifact", str(exc))
    except json.JSONDecodeError as exc:
        _fail(
            "invalid_artifact_json",
            "chainArtifact",
            f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
        )
    if not isinstance(value, dict):
        _fail("invalid_artifact_schema", "chainArtifact", "object required")
    try:
        canonical = canonical_json_bytes(value)
    except DigestError as exc:
        _fail("noncanonical_json", "chainArtifact", str(exc))
    if canonical != raw:
        _fail(
            "noncanonical_json",
            "chainArtifact",
            "exact bootstrap canonical JSON bytes are required",
        )
    return value


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_artifact_schema", path, "field set mismatch")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "lowercase sha256:<64 hex> required")
    return value


def _event_links(
    event: Any,
    *,
    path: str,
    expected_sequence: int,
    expected_previous: str | None,
) -> tuple[dict[str, Any], str]:
    envelope = _exact(
        event,
        {"schemaVersion", "kind", "body", "signature", "eventDigest"},
        path,
    )
    event_digest = _digest(envelope["eventDigest"], f"{path}.eventDigest")
    if document_digest(envelope, omit_field="eventDigest") != event_digest:
        _fail("event_digest_mismatch", f"{path}.eventDigest", "event bytes changed")
    body = envelope["body"]
    if not isinstance(body, dict):
        _fail("invalid_artifact_schema", f"{path}.body", "object required")
    sequence = body.get("sequence")
    event_id = body.get("eventId")
    previous = body.get("previousDigest")
    event_type = body.get("eventType")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence != expected_sequence
        or not isinstance(event_id, str)
        or EVENT_ID_RE.fullmatch(event_id) is None
        or event_id != f"evt-{expected_sequence:08d}"
    ):
        _fail("invalid_event_sequence", path, "event ID/sequence is not contiguous")
    if previous != expected_previous:
        _fail(
            "event_chain_mismatch", f"{path}.body.previousDigest", "chain link differs"
        )
    if expected_sequence == 0:
        if event_type != "Genesis":
            _fail("invalid_genesis", f"{path}.body.eventType", "Genesis required")
    elif event_type not in {"StateTransition", "EvidenceAttachment"}:
        _fail(
            "invalid_post_genesis_event",
            f"{path}.body.eventType",
            "StateTransition or EvidenceAttachment required",
        )
    return deepcopy(envelope), event_digest


def parse_chain_artifact(raw: bytes) -> ParsedChainArtifact:
    """Parse a canonical raw chain container without granting trust to it."""

    document = _exact(
        _load(raw),
        {
            "schemaVersion",
            "kind",
            "bootstrapApproval",
            "genesisEvent",
            "entries",
            "eventCount",
            "headDigest",
            "artifactDigest",
        },
        "chainArtifact",
    )
    if (
        document["schemaVersion"] != CHAIN_ARTIFACT_SCHEMA
        or document["kind"] != CHAIN_ARTIFACT_KIND
    ):
        _fail("unsupported_artifact_schema", "chainArtifact", "unsupported revision")
    artifact_digest = _digest(
        document["artifactDigest"], "chainArtifact.artifactDigest"
    )
    if document_digest(document, omit_field="artifactDigest") != artifact_digest:
        _fail(
            "artifact_digest_mismatch",
            "chainArtifact.artifactDigest",
            "artifact bytes changed",
        )
    approval = document["bootstrapApproval"]
    if not isinstance(approval, dict):
        _fail(
            "invalid_bootstrap_approval",
            "chainArtifact.bootstrapApproval",
            "raw approval envelope object required",
        )
    genesis, head = _event_links(
        document["genesisEvent"],
        path="chainArtifact.genesisEvent",
        expected_sequence=0,
        expected_previous=None,
    )
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list):
        _fail("invalid_artifact_schema", "chainArtifact.entries", "array required")
    entries: list[ParsedChainEntry] = []
    for index, raw_entry in enumerate(raw_entries, start=1):
        entry_path = f"chainArtifact.entries[{index - 1}]"
        entry = _exact(raw_entry, {"event", "authorizationBundle"}, entry_path)
        event, event_digest = _event_links(
            entry["event"],
            path=f"{entry_path}.event",
            expected_sequence=index,
            expected_previous=head,
        )
        bundle = entry["authorizationBundle"]
        if not isinstance(bundle, dict):
            _fail(
                "invalid_authorization_bundle",
                f"{entry_path}.authorizationBundle",
                "raw authorization bundle object required",
            )
        try:
            bundle_bytes = canonical_json_bytes(bundle)
        except DigestError as exc:
            _fail("invalid_authorization_bundle", entry_path, str(exc))
        entries.append(
            ParsedChainEntry(
                event=event,
                authorization_bundle=bundle_bytes,
            )
        )
        head = event_digest
    event_count = document["eventCount"]
    if (
        isinstance(event_count, bool)
        or not isinstance(event_count, int)
        or event_count != len(entries) + 1
    ):
        _fail(
            "event_count_mismatch",
            "chainArtifact.eventCount",
            "event count does not match the exact chain",
        )
    if _digest(document["headDigest"], "chainArtifact.headDigest") != head:
        _fail(
            "chain_head_mismatch",
            "chainArtifact.headDigest",
            "declared head is truncated, extended, or reordered",
        )
    return ParsedChainArtifact(
        bootstrap_approval=deepcopy(approval),
        genesis_event=genesis,
        entries=tuple(entries),
        event_count=event_count,
        head_digest=head,
        artifact_digest=artifact_digest,
    )


def encode_chain_artifact(
    *,
    bootstrap_approval: Mapping[str, Any],
    genesis_event: Mapping[str, Any],
    entries: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> bytes:
    """Encode transport bytes, then self-parse them; this does not verify trust."""

    if not isinstance(bootstrap_approval, Mapping) or not isinstance(
        genesis_event, Mapping
    ):
        _fail("invalid_artifact_input", "chainArtifact", "mapping inputs required")
    if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
        _fail("invalid_artifact_input", "chainArtifact.entries", "sequence required")
    raw_entries: list[dict[str, Any]] = []
    for index, item in enumerate(entries):
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], Mapping)
            or not isinstance(item[1], Mapping)
        ):
            _fail(
                "invalid_artifact_input",
                f"chainArtifact.entries[{index}]",
                "(event, authorization bundle) mappings required",
            )
        raw_entries.append(
            {
                "event": deepcopy(dict(item[0])),
                "authorizationBundle": deepcopy(dict(item[1])),
            }
        )
    event_documents = [dict(genesis_event), *(item["event"] for item in raw_entries)]
    head = event_documents[-1].get("eventDigest")
    body: dict[str, Any] = {
        "schemaVersion": CHAIN_ARTIFACT_SCHEMA,
        "kind": CHAIN_ARTIFACT_KIND,
        "bootstrapApproval": deepcopy(dict(bootstrap_approval)),
        "genesisEvent": deepcopy(dict(genesis_event)),
        "entries": raw_entries,
        "eventCount": len(event_documents),
        "headDigest": head,
    }
    body["artifactDigest"] = document_digest(body)
    encoded = canonical_json_bytes(body)
    parse_chain_artifact(encoded)
    return encoded


__all__ = [
    "CHAIN_ARTIFACT_KIND",
    "CHAIN_ARTIFACT_SCHEMA",
    "ChainArtifactError",
    "ParsedChainArtifact",
    "ParsedChainEntry",
    "encode_chain_artifact",
    "parse_chain_artifact",
]
