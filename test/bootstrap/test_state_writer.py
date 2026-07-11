"""Offline and adversarial tests for the protected Genesis writer."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes
from tools.phasegate.oidc import OidcVerificationError, jwks_snapshot_digest
from tools.phasegate.state_writer import (
    ACTOR,
    OIDC_AUDIENCE_PREFIX,
    OIDC_SIGNATURE_SCHEME,
    REQUIRED_STATUS_CHECKS,
    STATE_EVENT_KIND,
    STATE_EVENT_NAMESPACE,
    STATE_EVENT_SCHEMA,
    StateWriterError,
    create_genesis_event,
    github_actions_token_provider,
    github_repository_protection_provider,
)


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _ruleset_api_evidence(commit: str) -> dict:
    rules = [
        {"type": "deletion"},
        {"type": "linear_history"},
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 1,
                "required_review_thread_resolution": True,
            },
        },
        {"type": "required_signatures"},
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "required_status_checks": [
                    {"context": context, "integration_id": 15368}
                    for context in REQUIRED_STATUS_CHECKS
                ],
            },
        },
    ]
    effective_rules = []
    for rule in rules:
        effective_rules.append(
            {
                **deepcopy(rule),
                "ruleset_id": 42,
                "ruleset_source_type": "Repository",
                "ruleset_source": "whyiug/agentapi-doctor",
            }
        )
    return {
        "repository": {
            "id": 1296831403,
            "name": "agentapi-doctor",
            "full_name": "whyiug/agentapi-doctor",
            "private": False,
            "visibility": "public",
            "default_branch": "main",
            "owner": {"login": "whyiug", "id": 6668626},
        },
        "branch": {
            "name": "main",
            "protected": True,
            "commit": {"sha": commit},
        },
        "effectiveRules": effective_rules,
        "rulesets": [
            {
                "id": 42,
                "name": "P00 protected main",
                "target": "branch",
                "source_type": "Repository",
                "source": "whyiug/agentapi-doctor",
                "enforcement": "active",
            }
        ],
        "rulesetDetail": {
            "id": 42,
            "name": "P00 protected main",
            "target": "branch",
            "source_type": "Repository",
            "source": "whyiug/agentapi-doctor",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []}
            },
            "rules": rules,
        },
    }


class ProtectedStateWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="phasegate-writer-test-")
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
        modulus_text = subprocess.run(
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
        modulus = bytes.fromhex(modulus_text.removeprefix("Modulus="))
        cls.jwk = {
            "kid": "writer-test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": _b64url(modulus),
            "e": "AQAB",
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.source_commit = "a" * 40
        self.workflow_execution_commit = "f" * 40
        self.control_digest = "sha256:" + "b" * 64
        self.policy_digest = "sha256:" + "c" * 64
        self.timestamp = datetime(2026, 7, 11, 0, 0, 0, tzinfo=timezone.utc)
        self.workflow_path = ".github/workflows/p00-protected-state-writer.yml"
        self.approval_result = {
            "status": "verified",
            "decision": "APPROVE",
            "approvalDigest": "sha256:" + "d" * 64,
            "requestDigest": "sha256:" + "e" * 64,
            "controlPlaneDigest": self.control_digest,
            "candidateSourceCommit": self.source_commit,
            "reviewer": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
            "trustPolicyDigest": self.policy_digest,
            "workflowExecutionCommit": self.workflow_execution_commit,
        }
        self.contract_digests = {
            "execution/phases/P00.yaml": "sha256:" + "2" * 64,
            **{
                f"execution/work-units/P00.W0{index}.yaml": (
                    "sha256:" + str(index + 2) * 64
                )
                for index in range(1, 6)
            },
        }
        self.expected_claims = {
            "repository": "whyiug/agentapi-doctor",
            "repository_id": "1296831403",
            "repository_owner": "whyiug",
            "repository_owner_id": "6668626",
            "repository_visibility": "public",
            "event_name": "workflow_dispatch",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "ref_protected": "true",
            "runner_environment": "github-hosted",
            "actor_id": "6668626",
            "workflow_ref": (
                "whyiug/agentapi-doctor/"
                + self.workflow_path
                + "@refs/heads/main"
            ),
            "workflow_sha": self.workflow_execution_commit,
            "sha": self.workflow_execution_commit,
        }
        self.jwks_snapshot = {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T00:00:00Z",
            "sourceRawDigest": "sha256:" + "9" * 64,
            "algorithms": ["RS256"],
            "historicalVerificationPolicy": {
                "networkDuringReplay": "forbidden",
                "unknownKid": "block-for-independently-approved-rotation",
                "tokenValidity": "the StateEvent timestamp must precede token issuance by at most 120 seconds and token lifetime must not exceed 600 seconds",
                "revocation": "a later policy revision may explicitly revoke a key; repository-local online refresh never grants trust",
            },
            "keys": [self.jwk],
        }
        self.jwks_snapshot_digest = jwks_snapshot_digest(self.jwks_snapshot)
        self.api_evidence = _ruleset_api_evidence(self.workflow_execution_commit)
        self.requested_audiences: list[str] = []

    def _claims(self, audience: str, **overrides: object) -> dict:
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            **self.expected_claims,
            "sub": (
                "repo:whyiug/agentapi-doctor:ref:"
                "refs/heads/main"
            ),
            "jti": "writer-jti-001",
            "run_id": "1001",
            "run_number": "1",
            "run_attempt": "1",
            "check_run_id": "2001",
            "nbf": 1783727995,
            "iat": 1783728000,
            "exp": 1783728300,
        }
        claims.update(overrides)
        return claims

    def _token(self, claims: dict) -> str:
        header = canonical_json_bytes(
            {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"}
        )
        claims_payload = canonical_json_bytes(claims)
        signing_input = f"{_b64url(header)}.{_b64url(claims_payload)}".encode("ascii")
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
        return signing_input.decode("ascii") + "." + _b64url(signature)

    def _provider(self, audience: str) -> str:
        self.requested_audiences.append(audience)
        return self._token(self._claims(audience))

    def _protection_provider(self) -> dict:
        return deepcopy(self.api_evidence)

    def _create(self, *, token_provider=None, **overrides: object) -> dict:
        arguments = {
            "approval_result": self.approval_result,
            "contract_digests": self.contract_digests,
            "source_commit": self.source_commit,
            "control_plane_digest": self.control_digest,
            "trust_policy_digest": self.policy_digest,
            "approved_jwks": self.jwks_snapshot,
            "expected_jwks_snapshot_digest": self.jwks_snapshot_digest,
            "expected_claims": self.expected_claims,
            "workflow_path": self.workflow_path,
            "workflow_execution_commit": self.workflow_execution_commit,
            "statement_timestamp": self.timestamp,
            "repository_protection_provider": self._protection_provider,
            "token_provider": self._provider if token_provider is None else token_provider,
        }
        arguments.update(overrides)
        return create_genesis_event(**arguments)

    def _expected_state(self) -> dict:
        units = {}
        for index in range(1, 6):
            unit = f"P00.W0{index}"
            active = index == 1
            units[unit] = {
                "status": "ACTIVE" if active else "NOT_STARTED",
                "contractDigest": self.contract_digests[
                    f"execution/work-units/{unit}.yaml"
                ],
                "approvalDigest": (
                    self.approval_result["approvalDigest"] if active else None
                ),
                "sourceCommit": self.source_commit if active else None,
            }
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": self.contract_digests[
                        "execution/phases/P00.yaml"
                    ],
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.source_commit,
                    "startedAt": "2026-07-11T00:00:00Z",
                    "workUnits": units,
                }
            },
        }

    def test_correct_state_digest_and_v1alpha2_envelope(self) -> None:
        event = self._create()
        self.assertEqual(event["schemaVersion"], STATE_EVENT_SCHEMA)
        self.assertEqual(event["kind"], STATE_EVENT_KIND)
        self.assertEqual(event["body"]["actor"], ACTOR)
        observation = event["body"]["repositoryProtection"]
        self.assertEqual(
            observation["repository"],
            {
                "id": "1296831403",
                "owner": "whyiug",
                "ownerId": "6668626",
                "name": "agentapi-doctor",
                "fullName": "whyiug/agentapi-doctor",
                "visibility": "public",
                "defaultBranch": "main",
            },
        )
        self.assertTrue(observation["branch"]["protected"])
        self.assertEqual(observation["ruleset"]["name"], "P00 protected main")
        self.assertEqual(observation["ruleset"]["enforcement"], "active")
        self.assertEqual(
            observation["apiLimitations"],
            ["ruleset bypass actors not observable with read-only token"],
        )
        status_rule = next(
            rule
            for rule in observation["ruleset"]["rules"]
            if rule["type"] == "required_status_checks"
        )
        self.assertEqual(
            [
                check["context"]
                for check in status_rule["parameters"]["requiredStatusChecks"]
            ],
            list(REQUIRED_STATUS_CHECKS),
        )
        evidence_projection = {
            key: observation[key]
            for key in (
                "repository",
                "branch",
                "ruleset",
                "effectiveRules",
                "apiLimitations",
            )
        }
        self.assertEqual(
            observation["apiEvidenceDigest"],
            sha256_bytes(canonical_json_bytes(evidence_projection)),
        )
        self.assertEqual(
            event["body"]["payload"]["resultingStateDigest"],
            sha256_bytes(canonical_json_bytes(self._expected_state())),
        )
        self.assertEqual(
            event["eventDigest"],
            sha256_bytes(
                canonical_json_bytes(
                    {key: value for key, value in event.items() if key != "eventDigest"}
                )
            ),
        )

    def test_audience_exactly_binds_canonical_statement(self) -> None:
        event = self._create()
        statement = {
            "schemaVersion": event["schemaVersion"],
            "kind": event["kind"],
            "body": event["body"],
        }
        statement_digest = sha256_bytes(canonical_json_bytes(statement))
        self.assertEqual(event["signature"]["statementDigest"], statement_digest)
        self.assertEqual(
            self.requested_audiences, [OIDC_AUDIENCE_PREFIX + statement_digest]
        )
        self.assertEqual(
            set(event["signature"]),
            {"scheme", "namespace", "statementDigest", "jwt"},
        )
        self.assertEqual(event["signature"]["scheme"], OIDC_SIGNATURE_SCHEME)
        self.assertEqual(event["signature"]["namespace"], STATE_EVENT_NAMESPACE)

        def wrong_audience_provider(audience: str) -> str:
            return self._token(self._claims(audience + "-other"))

        with self.assertRaises(OidcVerificationError) as caught:
            self._create(token_provider=wrong_audience_provider)
        self.assertEqual(caught.exception.code, "oidc_audience_mismatch")

    def test_tampered_token_is_rejected_before_event_is_returned(self) -> None:
        def tampered_provider(audience: str) -> str:
            token = self._token(self._claims(audience))
            prefix, encoded = token.rsplit(".", 1)
            raw = bytearray(
                base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            )
            raw[-1] ^= 1
            return prefix + "." + _b64url(bytes(raw))

        with self.assertRaises(OidcVerificationError) as caught:
            self._create(token_provider=tampered_provider)
        self.assertEqual(caught.exception.code, "invalid_oidc_signature")

    def test_wrong_protected_claim_is_rejected(self) -> None:
        def wrong_claim_provider(audience: str) -> str:
            return self._token(self._claims(audience, repository_id="1"))

        with self.assertRaises(OidcVerificationError) as caught:
            self._create(token_provider=wrong_claim_provider)
        self.assertEqual(caught.exception.code, "oidc_claim_mismatch")

        def pull_request_ref_provider(audience: str) -> str:
            return self._token(
                self._claims(audience, head_ref="refs/heads/untrusted-change")
            )

        with self.assertRaises(StateWriterError) as ref_caught:
            self._create(token_provider=pull_request_ref_provider)
        self.assertEqual(
            ref_caught.exception.code, "oidc_pull_request_claim_forbidden"
        )

    def test_repository_protection_weaknesses_fail_before_oidc_token(self) -> None:
        token_calls = 0

        def forbidden_token_provider(audience: str) -> str:
            nonlocal token_calls
            token_calls += 1
            return "unused"

        cases: list[tuple[dict, str]] = []
        wrong_repository = deepcopy(self.api_evidence)
        wrong_repository["repository"]["id"] = 1
        cases.append((wrong_repository, "repository_identity_mismatch"))
        private_repository = deepcopy(self.api_evidence)
        private_repository["repository"]["private"] = True
        cases.append((private_repository, "repository_not_public"))
        unprotected = deepcopy(self.api_evidence)
        unprotected["branch"]["protected"] = False
        cases.append((unprotected, "branch_not_protected"))
        extra_check = deepcopy(self.api_evidence)
        extra_check["rulesetDetail"]["rules"][-1]["parameters"][
            "required_status_checks"
        ].append(
            {"context": "unapproved / check", "integration_id": 15368}
        )
        cases.append((extra_check, "required_status_checks_mismatch"))
        invalid_integration = deepcopy(self.api_evidence)
        invalid_integration["rulesetDetail"]["rules"][-1]["parameters"][
            "required_status_checks"
        ][0]["integration_id"] = -1
        cases.append(
            (invalid_integration, "invalid_repository_protection_evidence")
        )
        weak_reviews = deepcopy(self.api_evidence)
        weak_reviews["rulesetDetail"]["rules"][3]["parameters"][
            "require_code_owner_review"
        ] = False
        cases.append((weak_reviews, "repository_ruleset_weakened"))
        multiple_active = deepcopy(self.api_evidence)
        second = deepcopy(multiple_active["rulesets"][0])
        second["id"] = 43
        second["name"] = "unexpected active ruleset"
        multiple_active["rulesets"].append(second)
        cases.append((multiple_active, "repository_ruleset_mismatch"))
        broad_condition = deepcopy(self.api_evidence)
        broad_condition["rulesetDetail"]["conditions"]["ref_name"]["include"] = [
            "~ALL"
        ]
        cases.append((broad_condition, "repository_ruleset_conditions_mismatch"))

        for evidence, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(StateWriterError) as caught:
                    self._create(
                        repository_protection_provider=lambda evidence=evidence: evidence,
                        token_provider=forbidden_token_provider,
                    )
                self.assertEqual(caught.exception.code, code)
        self.assertEqual(token_calls, 0)

    def test_read_only_github_api_provider_uses_fixed_get_endpoints(self) -> None:
        requested = []
        documents = {
            "/repos/whyiug/agentapi-doctor": self.api_evidence["repository"],
            "/repos/whyiug/agentapi-doctor/branches/main": self.api_evidence[
                "branch"
            ],
            "/repos/whyiug/agentapi-doctor/rules/branches/main?per_page=100&page=1": self.api_evidence[
                "effectiveRules"
            ],
            "/repos/whyiug/agentapi-doctor/rulesets?includes_parents=true&targets=branch&per_page=100&page=1": self.api_evidence[
                "rulesets"
            ],
            "/repos/whyiug/agentapi-doctor/rulesets/42?includes_parents=true": self.api_evidence[
                "rulesetDetail"
            ],
        }

        class Response:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.headers = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def getcode(self) -> int:
                return 200

            def read(self, limit: int) -> bytes:
                return self.payload[:limit]

        def opener(api_request, timeout):
            requested.append(api_request)
            self.assertEqual(timeout, 10)
            self.assertEqual(api_request.get_method(), "GET")
            self.assertIsNone(api_request.data)
            self.assertEqual(
                api_request.get_header("Authorization"), "Bearer synthetic-token"
            )
            path = api_request.full_url.removeprefix("https://api.github.com")
            return Response(canonical_json_bytes(documents[path]))

        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "whyiug/agentapi-doctor",
            "GITHUB_REPOSITORY_ID": "1296831403",
            "GITHUB_REPOSITORY_OWNER": "whyiug",
            "GITHUB_REPOSITORY_OWNER_ID": "6668626",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_SHA": self.workflow_execution_commit,
            "GITHUB_TOKEN": "synthetic-token",
        }
        result = github_repository_protection_provider(
            environ=environment, urlopen=opener
        )
        self.assertEqual(result, self.api_evidence)
        self.assertEqual(len(requested), 5)

    def test_default_provider_refuses_non_actions_environment_without_network(self) -> None:
        attempted_network = False

        def forbidden_network(*args, **kwargs):
            nonlocal attempted_network
            attempted_network = True
            raise AssertionError("network must not be reached")

        with self.assertRaises(StateWriterError) as caught:
            github_actions_token_provider(
                "urn:agentapi-doctor:state-event:v1:sha256:" + "f" * 64,
                environ={},
                urlopen=forbidden_network,
            )
        self.assertEqual(caught.exception.code, "not_github_actions")
        self.assertFalse(attempted_network)

        with self.assertRaises(StateWriterError) as protection_caught:
            github_repository_protection_provider(
                environ={},
                urlopen=forbidden_network,
            )
        self.assertEqual(protection_caught.exception.code, "not_github_actions")
        self.assertFalse(attempted_network)

        with mock.patch.dict(os.environ, {}, clear=True):
            arguments = {
                "approval_result": self.approval_result,
                "contract_digests": self.contract_digests,
                "source_commit": self.source_commit,
                "control_plane_digest": self.control_digest,
                "trust_policy_digest": self.policy_digest,
                "approved_jwks": self.jwks_snapshot,
                "expected_jwks_snapshot_digest": self.jwks_snapshot_digest,
                "expected_claims": self.expected_claims,
                "workflow_path": self.workflow_path,
                "workflow_execution_commit": self.workflow_execution_commit,
                "statement_timestamp": self.timestamp,
            }
            with self.assertRaises(StateWriterError) as create_caught:
                create_genesis_event(**arguments)
        self.assertEqual(create_caught.exception.code, "not_github_actions")

    def test_construction_performs_no_file_io(self) -> None:
        # Prepare the token before installing a tripwire over Python file I/O.
        first = self._create()
        token = first["signature"]["jwt"]
        before = sorted(Path(self.temporary.name).iterdir())
        with mock.patch("builtins.open", side_effect=AssertionError("file I/O forbidden")):
            second = self._create(token_provider=lambda audience: token)
        after = sorted(Path(self.temporary.name).iterdir())
        self.assertEqual(before, after)
        self.assertEqual(first, second)

    def test_unverified_approval_and_unbound_workflow_fail_before_provider(self) -> None:
        calls = 0

        def provider(audience: str) -> str:
            nonlocal calls
            calls += 1
            return "unused"

        approval = deepcopy(self.approval_result)
        approval["status"] = "pending"
        with self.assertRaises(StateWriterError) as caught:
            self._create(approval_result=approval, token_provider=provider)
        self.assertEqual(caught.exception.code, "approval_not_verified")
        claims = deepcopy(self.expected_claims)
        claims["workflow_ref"] = "whyiug/agentapi-doctor/.github/workflows/other.yml@main"
        with self.assertRaises(StateWriterError) as caught:
            self._create(expected_claims=claims, token_provider=provider)
        self.assertEqual(caught.exception.code, "workflow_claim_mismatch")
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
