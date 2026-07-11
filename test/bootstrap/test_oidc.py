"""Adversarial tests for the offline GitHub Actions OIDC verifier."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.oidc import (
    OidcVerificationError,
    jwks_snapshot_digest,
    validate_jwks_snapshot,
    verify_github_actions_oidc_token,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


class GitHubActionsOidcVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="phasegate-oidc-test-")
        cls.private_key = Path(cls.temporary.name) / "test-only-rsa.pem"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(cls.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        modulus_output = subprocess.run(
            [
                "/usr/bin/openssl",
                "rsa",
                "-in",
                str(cls.private_key),
                "-noout",
                "-modulus",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        modulus = bytes.fromhex(modulus_output.removeprefix("Modulus="))
        cls.jwk = {
            "kid": "test-github-oidc-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.timestamp = datetime(2026, 7, 11, 0, 0, 0, tzinfo=timezone.utc)
        self.audience = (
            "urn:agentapi-doctor:state-event:v1:sha256:"
            + "a" * 64
        )
        self.expected_claims = {
            "repository": "whyiug/agentapi-doctor",
            "repository_id": "1296831403",
            "repository_owner": "whyiug",
            "repository_owner_id": "6668626",
            "repository_visibility": "private",
            "event_name": "push",
            "ref": "refs/heads/agent/p00-bootstrap-candidate",
            "ref_type": "branch",
            "ref_protected": "false",
            "runner_environment": "github-hosted",
            "actor_id": "6668626",
            "workflow_sha": "a" * 40,
            "sha": "a" * 40,
        }
        self.claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": self.audience,
            **self.expected_claims,
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/agent/p00-bootstrap-candidate",
            "jti": "test-jti-001",
            "run_id": "1001",
            "run_number": "1",
            "run_attempt": "1",
            "check_run_id": "2001",
            "nbf": 1783727995,
            "iat": 1783728000,
            "exp": 1783728300,
        }

    def _token(
        self,
        *,
        header: dict | None = None,
        claims: dict | None = None,
        raw_header: bytes | None = None,
        raw_claims: bytes | None = None,
    ) -> str:
        header_payload = raw_header or json.dumps(
            header
            or {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        claims_payload = raw_claims or json.dumps(
            claims or self.claims,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signing_input = f"{b64url(header_payload)}.{b64url(claims_payload)}".encode(
            "ascii"
        )
        signature = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self.private_key),
            ],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        return signing_input.decode("ascii") + "." + b64url(signature)

    def _verify(self, token: str, **overrides: object) -> dict:
        return verify_github_actions_oidc_token(
            token,
            approved_jwks=overrides.get("approved_jwks", [self.jwk]),
            expected_audience=overrides.get("expected_audience", self.audience),
            expected_claims=overrides.get("expected_claims", self.expected_claims),
            statement_timestamp=overrides.get(
                "statement_timestamp", self.timestamp
            ),
        )

    def _assert_error(self, code: str, token: str, **overrides: object) -> None:
        with self.assertRaises(OidcVerificationError) as caught:
            self._verify(token, **overrides)
        self.assertEqual(caught.exception.code, code)

    def test_valid_digest_bound_token_verifies_offline(self) -> None:
        result = self._verify(self._token())
        self.assertEqual(result["aud"], self.audience)
        self.assertEqual(result["repository_id"], "1296831403")

    def test_historical_token_does_not_require_current_unexpired_bearer(self) -> None:
        result = self._verify(self._token())
        self.assertEqual(result["exp"], 1783728300)

    def test_signature_bit_flip_is_rejected(self) -> None:
        token = self._token()
        prefix, encoded = token.rsplit(".", 1)
        signature = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        signature[-1] ^= 1
        self._assert_error(
            "invalid_oidc_signature", prefix + "." + b64url(bytes(signature))
        )

    def test_audience_cannot_be_replayed_for_another_statement(self) -> None:
        self._assert_error(
            "oidc_audience_mismatch",
            self._token(),
            expected_audience=self.audience[:-1] + "b",
        )

    def test_audience_array_is_rejected(self) -> None:
        claims = deepcopy(self.claims)
        claims["aud"] = [self.audience]
        self._assert_error("oidc_audience_mismatch", self._token(claims=claims))

    def test_algorithm_confusion_is_rejected(self) -> None:
        header = {"alg": "HS256", "kid": self.jwk["kid"], "typ": "JWT"}
        self._assert_error("unsupported_oidc_algorithm", self._token(header=header))

    def test_embedded_or_remote_key_selection_is_rejected(self) -> None:
        header = {
            "alg": "RS256",
            "kid": self.jwk["kid"],
            "typ": "JWT",
            "jku": "https://example.invalid/keys",
        }
        self._assert_error("invalid_oidc_header", self._token(header=header))

    def test_duplicate_header_key_is_rejected(self) -> None:
        raw = (
            b'{"alg":"RS256","alg":"RS256","kid":"'
            + self.jwk["kid"].encode("ascii")
            + b'","typ":"JWT"}'
        )
        self._assert_error("duplicate_oidc_json_key", self._token(raw_header=raw))

    def test_padded_base64url_is_rejected(self) -> None:
        token = self._token()
        header, claims, signature = token.split(".")
        self._assert_error("invalid_base64url", header + "=." + claims + "." + signature)

    def test_unknown_and_duplicate_kid_fail_closed(self) -> None:
        header = {"alg": "RS256", "kid": "unknown", "typ": "JWT"}
        self._assert_error("unknown_oidc_kid", self._token(header=header))
        self._assert_error(
            "duplicate_oidc_kid",
            self._token(),
            approved_jwks=[self.jwk, deepcopy(self.jwk)],
        )

    def test_repository_or_workflow_claim_drift_is_rejected(self) -> None:
        claims = deepcopy(self.claims)
        claims["repository_id"] = "1"
        self._assert_error("oidc_claim_mismatch", self._token(claims=claims))
        claims = deepcopy(self.claims)
        claims["workflow_sha"] = "b" * 40
        self._assert_error("oidc_claim_mismatch", self._token(claims=claims))

    def test_rerun_and_excessive_lifetime_are_rejected(self) -> None:
        claims = deepcopy(self.claims)
        claims["run_attempt"] = "2"
        self._assert_error("oidc_rerun_forbidden", self._token(claims=claims))
        claims = deepcopy(self.claims)
        claims["exp"] = claims["iat"] + 601
        self._assert_error("invalid_oidc_time", self._token(claims=claims))

    def test_statement_must_precede_token_issue_by_a_small_bound(self) -> None:
        future = datetime(2026, 7, 11, 0, 0, 1, tzinfo=timezone.utc)
        self._assert_error(
            "oidc_statement_time_mismatch",
            self._token(),
            statement_timestamp=future,
        )
        old = datetime(2026, 7, 10, 23, 57, 59, tzinfo=timezone.utc)
        self._assert_error(
            "oidc_statement_time_mismatch",
            self._token(),
            statement_timestamp=old,
        )

    def test_short_modulus_and_nonstandard_exponent_are_rejected(self) -> None:
        short = deepcopy(self.jwk)
        short["n"] = b64url(b"\x80" + b"\x00" * 127)
        self._assert_error(
            "invalid_oidc_jwk", self._token(), approved_jwks=[short]
        )
        exponent = deepcopy(self.jwk)
        exponent["e"] = "Aw"
        self._assert_error(
            "invalid_oidc_jwk", self._token(), approved_jwks=[exponent]
        )

    def test_repository_jwks_snapshot_is_strict_and_content_pinned(self) -> None:
        path = (
            REPO_ROOT
            / "execution/protected-verifier/github-actions-oidc-jwks.json"
        )
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        digest = jwks_snapshot_digest(snapshot)
        result = validate_jwks_snapshot(
            snapshot, expected_snapshot_digest=digest
        )
        self.assertEqual(result["digest"], digest)
        self.assertEqual(len(result["keys"]), 4)

        tampered = deepcopy(snapshot)
        tampered["issuer"] = "https://example.invalid"
        with self.assertRaises(OidcVerificationError) as caught:
            validate_jwks_snapshot(
                tampered, expected_snapshot_digest=digest
            )
        self.assertEqual(
            caught.exception.code, "oidc_jwks_snapshot_digest_mismatch"
        )

        with self.assertRaises(OidcVerificationError) as caught:
            validate_jwks_snapshot(
                tampered,
                expected_snapshot_digest=jwks_snapshot_digest(tampered),
            )
        self.assertEqual(caught.exception.code, "invalid_oidc_jwks_snapshot")


if __name__ == "__main__":
    unittest.main()
