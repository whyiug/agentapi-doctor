"""Reference and adversarial tests for the pure-Python SSHSIG verifier."""

from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.sshsig import SshSigVerificationError, verify_sshsig


class SshSigVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="phasegate-sshsig-test-")
        root = Path(cls.temporary.name)
        cls.key = root / "reviewer"
        cls.other_key = root / "other"
        for key in (cls.key, cls.other_key):
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        cls.public_key = " ".join(
            cls.key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
        )
        cls.other_public_key = " ".join(
            cls.other_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )
        cls.namespace = "agentapi-doctor/control-plane-approval/v1"
        cls.payload = b'{"candidate":"test-only"}'
        cls.signature = cls._sign(cls.payload)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _sign(cls, payload: bytes, *, hash_algorithm: str = "sha512") -> str:
        completed = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(cls.key),
                "-n",
                cls.namespace,
                "-O",
                f"hashalg={hash_algorithm}",
            ],
            input=payload,
            check=True,
            capture_output=True,
            timeout=10,
        )
        return completed.stdout.decode("ascii")

    def _verify(self, **overrides: object) -> dict[str, str]:
        return verify_sshsig(
            overrides.get("payload", self.payload),
            armored_signature=overrides.get("signature", self.signature),
            public_key=overrides.get("public_key", self.public_key),
            expected_namespace=overrides.get("namespace", self.namespace),
        )

    def _assert_error(self, code: str, **overrides: object) -> None:
        with self.assertRaises(SshSigVerificationError) as caught:
            self._verify(**overrides)
        self.assertEqual(caught.exception.code, code)

    def test_reference_openssh_sha512_signature_verifies(self) -> None:
        self.assertEqual(self._verify()["hashAlgorithm"], "sha512")

    def test_reference_openssh_sha256_signature_verifies(self) -> None:
        signature = self._sign(self.payload, hash_algorithm="sha256")
        self.assertEqual(
            self._verify(signature=signature)["hashAlgorithm"], "sha256"
        )

    def test_payload_or_namespace_replay_is_rejected(self) -> None:
        self._assert_error(
            "invalid_ed25519_signature", payload=self.payload + b"\n"
        )
        self._assert_error(
            "sshsig_namespace_mismatch",
            namespace="agentapi-doctor/state-event/v1",
        )

    def test_embedded_key_must_equal_approved_key(self) -> None:
        self._assert_error(
            "sshsig_key_mismatch", public_key=self.other_public_key
        )

    def test_key_comments_and_non_ed25519_keys_are_rejected(self) -> None:
        self._assert_error(
            "invalid_sshsig_public_key",
            public_key=self.public_key + " reviewer@example.invalid",
        )
        self._assert_error(
            "invalid_sshsig_public_key",
            public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7",
        )

    def test_signature_mutation_and_trailing_armor_are_rejected(self) -> None:
        lines = self.signature.rstrip("\n").split("\n")
        raw = bytearray(base64.b64decode("".join(lines[1:-1])))
        raw[-1] ^= 1
        encoded = base64.b64encode(bytes(raw)).decode("ascii")
        mutated_lines = [encoded[index : index + 76] for index in range(0, len(encoded), 76)]
        mutated = lines[0] + "\n" + "\n".join(mutated_lines) + "\n" + lines[-1] + "\n"
        self._assert_error("invalid_ed25519_signature", signature=mutated)
        self._assert_error(
            "malformed_sshsig_armor", signature=self.signature + "trailing\n"
        )

    def test_noncanonical_armor_and_invalid_namespace_policy_fail(self) -> None:
        lines = self.signature.rstrip("\n").split("\n")
        malformed = lines[0] + "\n" + lines[1] + "=\n" + "\n".join(lines[2:])
        self._assert_error("malformed_sshsig_armor", signature=malformed)
        self._assert_error("invalid_sshsig_namespace", namespace="../bad")


if __name__ == "__main__":
    unittest.main()
