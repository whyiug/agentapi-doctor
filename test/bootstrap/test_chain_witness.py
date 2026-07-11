from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.chain_witness import (
    CHAIN_WITNESS_KIND,
    CHAIN_WITNESS_NAMESPACE,
    CHAIN_WITNESS_SCHEMA,
    VerifiedChainHeadWitness,
    require_verified_chain_head_witness,
    verify_chain_head_witness,
)
from tools.phasegate.digest import canonical_json_bytes
from tools.phasegate.protected import (
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
)


def d(character: str) -> str:
    return "sha256:" + character * 64


class ChainHeadWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="chain-witness-test-")
        cls.key = Path(cls.temporary.name) / "id_ed25519"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "",
                "-f",
                str(cls.key),
            ],
            check=True,
            timeout=30,
        )
        cls.public_key = (cls.key.with_suffix(".pub")).read_text(
            encoding="utf-8"
        ).strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.now = datetime(2026, 7, 11, 12, 5, tzinfo=timezone.utc)
        self.policy = {
            "digest": d("a"),
            "principals": {
                "maintainer@test": {
                    "identity": "maintainer@test",
                    "organization": "test-org",
                    "roles": ["authorized-maintainer"],
                    "publicKey": self.public_key,
                    "fingerprint": _ssh_public_key_fingerprint(
                        self.public_key, "test.publicKey"
                    ),
                    "capabilities": ["witness-chain-head"],
                    "validFrom": "2026-07-11T00:00:00Z",
                    "validUntil": "2026-07-12T00:00:00Z",
                }
            },
            "revokedFingerprints": set(),
        }
        self.body = {
            "witnessId": "wit-00000001",
            "priorChainHeadDigest": d("b"),
            "priorStateDigest": d("c"),
            "priorEventCount": 1,
            "priorHeadSequence": 0,
            "priorSourceCommit": "d" * 40,
            "controlPlaneDigest": d("e"),
            "trustPolicyDigest": d("a"),
            "witnessedAt": "2026-07-11T12:00:00Z",
            "validUntil": "2026-07-11T13:00:00Z",
            "reason": "Observed exact imported chain head before append.",
            "actor": {
                "principal": "maintainer@test",
                "role": "authorized-maintainer",
                "organization": "test-org",
            },
        }

    def _statement(self, body: dict | None = None) -> dict:
        envelope = {
            "schemaVersion": CHAIN_WITNESS_SCHEMA,
            "kind": CHAIN_WITNESS_KIND,
            "body": deepcopy(body or self.body),
        }
        payload = canonical_json_bytes(envelope)
        message = Path(self.temporary.name) / "message.json"
        signature = Path(self.temporary.name) / "message.json.sig"
        message.write_bytes(payload)
        signature.unlink(missing_ok=True)
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(self.key),
                "-n",
                CHAIN_WITNESS_NAMESPACE,
                str(message),
            ],
            check=True,
            timeout=30,
        )
        envelope["signature"] = {
            "scheme": "openssh-sshsig-v1",
            "namespace": CHAIN_WITNESS_NAMESPACE,
            "principal": "maintainer@test",
            "value": signature.read_text(encoding="ascii"),
        }
        envelope["attestationDigest"] = None
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    def _verify(self, statement: dict, **overrides):
        arguments = {
            "policy_result": self.policy,
            "expected_prior_chain_head_digest": d("b"),
            "expected_prior_state_digest": d("c"),
            "expected_prior_event_count": 1,
            "expected_prior_head_sequence": 0,
            "expected_prior_source_commit": "d" * 40,
            "expected_control_plane_digest": d("e"),
            "expected_trust_policy_digest": d("a"),
            "now": self.now,
        }
        arguments.update(overrides)
        return verify_chain_head_witness(statement, **arguments)

    def assert_code(self, code: str, statement: dict, **overrides) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            self._verify(statement, **overrides)
        self.assertEqual(caught.exception.code, code)

    def test_valid_witness_is_identity_sealed(self) -> None:
        verified = self._verify(self._statement())
        self.assertEqual(verified.prior_chain_head_digest, d("b"))
        self.assertIs(require_verified_chain_head_witness(verified), verified)
        forged = VerifiedChainHeadWitness(**verified.__dict__)
        with self.assertRaises(ProtectedVerificationError):
            require_verified_chain_head_witness(forged)
        with self.assertRaises(ProtectedVerificationError):
            require_verified_chain_head_witness(deepcopy(verified))

    def test_head_state_source_and_position_replay_are_rejected(self) -> None:
        statement = self._statement()
        cases = {
            "chain_witness_binding_mismatch": {
                "expected_prior_chain_head_digest": d("f")
            },
            "invalid_chain_position": {"expected_prior_event_count": 2},
        }
        for code, overrides in cases.items():
            with self.subTest(code=code):
                self.assert_code(code, statement, **overrides)

    def test_payload_tamper_and_signature_replay_are_rejected(self) -> None:
        statement = self._statement()
        tampered = deepcopy(statement)
        tampered["body"]["reason"] = "Changed after signing."
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        self.assert_code("invalid_ed25519_signature", tampered)
        namespace = deepcopy(statement)
        namespace["signature"]["namespace"] = "agentapi-doctor/other/v1"
        namespace["attestationDigest"] = document_digest(
            namespace, omit_field="attestationDigest"
        )
        self.assert_code("signature_namespace_mismatch", namespace)

    def test_expired_or_overlong_witness_is_rejected(self) -> None:
        expired = deepcopy(self.body)
        expired["validUntil"] = "2026-07-11T12:01:00Z"
        self.assert_code("chain_witness_outside_validity", self._statement(expired))
        overlong = deepcopy(self.body)
        overlong["validUntil"] = "2026-07-12T12:00:01Z"
        self.assert_code("chain_witness_validity_too_long", self._statement(overlong))

    def test_wrong_role_organization_or_revocation_is_rejected(self) -> None:
        statement = self._statement()
        wrong_role = deepcopy(self.body)
        wrong_role["actor"]["role"] = "independent-reviewer"
        self.assert_code("role_not_authorized", self._statement(wrong_role))
        revoked_policy = deepcopy(self.policy)
        revoked_policy["revokedFingerprints"] = {
            self.policy["principals"]["maintainer@test"]["fingerprint"]
        }
        self.assert_code(
            "signer_revoked", statement, policy_result=revoked_policy
        )


if __name__ == "__main__":
    unittest.main()
