from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.chain_artifact import (  # noqa: E402
    ChainArtifactError,
    encode_chain_artifact,
    parse_chain_artifact,
)
from tools.phasegate.digest import canonical_json_bytes  # noqa: E402
from tools.phasegate.protected import document_digest  # noqa: E402


def event(sequence: int, previous: str | None, event_type: str) -> dict:
    value = {
        "schemaVersion": "urn:agentapi-doctor:state-event:v1",
        "kind": "StateEvent",
        "body": {
            "eventType": event_type,
            "eventId": f"evt-{sequence:08d}",
            "sequence": sequence,
            "previousDigest": previous,
            "payload": {},
        },
        "signature": {"scheme": "test-only-raw-transport"},
    }
    value["eventDigest"] = document_digest(value)
    return value


class ChainArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.approval = {"schemaVersion": "test-approval", "value": "raw"}
        self.genesis = event(0, None, "Genesis")
        self.first = event(1, self.genesis["eventDigest"], "StateTransition")
        self.second = event(2, self.first["eventDigest"], "EvidenceAttachment")
        self.bundle_a = {
            "schemaVersion": "raw-auth-a",
            "bundleDigest": "not-trusted-here",
        }
        self.bundle_b = {
            "schemaVersion": "raw-auth-b",
            "bundleDigest": "not-trusted-here",
        }
        self.raw = encode_chain_artifact(
            bootstrap_approval=self.approval,
            genesis_event=self.genesis,
            entries=((self.first, self.bundle_a), (self.second, self.bundle_b)),
        )

    def _document(self) -> dict:
        return json.loads(self.raw)

    @staticmethod
    def _canonical(document: dict) -> bytes:
        document["artifactDigest"] = document_digest(
            document, omit_field="artifactDigest"
        )
        return canonical_json_bytes(document)

    def test_roundtrip_preserves_raw_chain_and_authorization_bytes(self) -> None:
        parsed = parse_chain_artifact(self.raw)
        self.assertEqual(parsed.event_count, 3)
        self.assertEqual(parsed.head_digest, self.second["eventDigest"])
        self.assertEqual(parsed.bootstrap_approval, self.approval)
        self.assertEqual(parsed.events, (self.genesis, self.first, self.second))
        self.assertEqual(
            parsed.entries[0].authorization_bundle, canonical_json_bytes(self.bundle_a)
        )
        self.assertEqual(
            parsed.entries[1].authorization_bundle, canonical_json_bytes(self.bundle_b)
        )

    def test_noncanonical_and_duplicate_input_fail_before_transport(self) -> None:
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(json.dumps(self._document(), sort_keys=True).encode())
        self.assertEqual(caught.exception.code, "noncanonical_json")
        duplicate = self.raw.replace(
            b'{"artifactDigest":',
            b'{"artifactDigest":"sha256:' + b"0" * 64 + b'","artifactDigest":',
            1,
        )
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(duplicate)
        self.assertEqual(caught.exception.code, "duplicate_key")

    def test_truncated_or_forged_head_and_count_are_rejected(self) -> None:
        for field, value, code in (
            ("headDigest", self.first["eventDigest"], "chain_head_mismatch"),
            ("eventCount", 2, "event_count_mismatch"),
        ):
            with self.subTest(field=field):
                document = self._document()
                document[field] = value
                with self.assertRaises(ChainArtifactError) as caught:
                    parse_chain_artifact(self._canonical(document))
                self.assertEqual(caught.exception.code, code)

    def test_reordered_or_relinked_events_are_rejected(self) -> None:
        document = self._document()
        document["entries"].reverse()
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(self._canonical(document))
        self.assertIn(
            caught.exception.code, {"invalid_event_sequence", "event_chain_mismatch"}
        )
        document = self._document()
        document["entries"][1]["event"]["body"]["previousDigest"] = self.genesis[
            "eventDigest"
        ]
        document["entries"][1]["event"]["eventDigest"] = document_digest(
            document["entries"][1]["event"], omit_field="eventDigest"
        )
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(self._canonical(document))
        self.assertEqual(caught.exception.code, "event_chain_mismatch")

    def test_event_tamper_is_rejected_even_if_outer_digest_is_recomputed(self) -> None:
        document = self._document()
        document["entries"][0]["event"]["body"]["payload"] = {"forged": True}
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(self._canonical(document))
        self.assertEqual(caught.exception.code, "event_digest_mismatch")

    def test_extra_or_missing_fields_are_rejected(self) -> None:
        document = self._document()
        document["surprise"] = True
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(self._canonical(document))
        self.assertEqual(caught.exception.code, "invalid_artifact_schema")
        document = self._document()
        del document["entries"][0]["authorizationBundle"]
        with self.assertRaises(ChainArtifactError) as caught:
            parse_chain_artifact(self._canonical(document))
        self.assertEqual(caught.exception.code, "invalid_artifact_schema")

    def test_encode_does_not_mutate_callers(self) -> None:
        approval = deepcopy(self.approval)
        genesis = deepcopy(self.genesis)
        first = deepcopy(self.first)
        bundle = deepcopy(self.bundle_a)
        encode_chain_artifact(
            bootstrap_approval=approval,
            genesis_event=genesis,
            entries=((first, bundle),),
        )
        self.assertEqual(approval, self.approval)
        self.assertEqual(genesis, self.genesis)
        self.assertEqual(first, self.first)
        self.assertEqual(bundle, self.bundle_a)


if __name__ == "__main__":
    unittest.main()
