"""End-to-end adversarial tests for the R3 SSHSIG/OIDC trust boundary."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes
from tools.phasegate.oidc import jwks_snapshot_digest
from tools.phasegate.protected import (
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
)
from tools.phasegate.protected_v2 import (
    APPROVAL_KIND,
    APPROVAL_NAMESPACE,
    APPROVAL_SCHEMA,
    verify_control_plane_approval_v2,
    validate_trust_policy_v2,
    verify_genesis_event_v2,
)
from tools.phasegate.state_writer import REQUIRED_STATUS_CHECKS, create_genesis_event


REPO_ROOT = Path(__file__).resolve().parents[2]


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def ruleset_api_evidence(commit: str) -> dict:
    rules = [
        {"type": "deletion"},
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
        {"type": "required_linear_history"},
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
        "effectiveRules": [
            {
                **deepcopy(rule),
                "ruleset_id": 42,
                "ruleset_source_type": "Repository",
                "ruleset_source": "whyiug/agentapi-doctor",
            }
            for rule in rules
        ],
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


class ProtectedV2EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="phasegate-v2-test-")
        cls.root = Path(cls.temporary.name)
        cls.reviewer_key = cls.root / "reviewer"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(cls.reviewer_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        cls.reviewer_public_key = " ".join(
            cls.reviewer_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )
        cls.rsa_key = cls.root / "oidc-test.pem"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(cls.rsa_key),
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
                str(cls.rsa_key),
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
            "kid": "protected-v2-test",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }

        cls.repo = cls.root / "repo"
        workflow = cls.repo / ".github/workflows/p00-protected-state-writer.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: test-only protected writer\n", encoding="utf-8")
        for relative in (
            "tools/phasegate/__init__.py",
            "tools/phasegate/digest.py",
            "tools/phasegate/oidc.py",
            "tools/phasegate/protected.py",
            "tools/phasegate/protected_v2.py",
            "tools/phasegate/sshsig.py",
            "tools/phasegate/state_writer.py",
            "tools/phasegate/validation.py",
        ):
            target = cls.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / relative, target)
        subprocess.run(["/usr/bin/git", "init", "-q", str(cls.repo)], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "config", "user.name", "test"],
            check=True,
        )
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(["/usr/bin/git", "-C", str(cls.repo), "add", "."], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "commit", "-q", "-m", "source"],
            check=True,
        )
        cls.source_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        marker = cls.repo / "request-marker"
        marker.write_text("R3\n", encoding="utf-8")
        subprocess.run(["/usr/bin/git", "-C", str(cls.repo), "add", "."], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "commit", "-q", "-m", "request"],
            check=True,
        )
        cls.workflow_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        cls.workflow_digest = sha256_bytes(workflow.read_bytes())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.control_digest = "sha256:" + "1" * 64
        self.timestamp = datetime(2026, 7, 11, 1, 0, 0, tzinfo=timezone.utc)
        self.snapshot = {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T00:00:00Z",
            "sourceRawDigest": "sha256:" + "2" * 64,
            "algorithms": ["RS256"],
            "historicalVerificationPolicy": {
                "networkDuringReplay": "forbidden",
                "unknownKid": "block-for-independently-approved-rotation",
                "tokenValidity": "the StateEvent timestamp must precede token issuance by at most 120 seconds and token lifetime must not exceed 600 seconds",
                "revocation": "a later policy revision may explicitly revoke a key; repository-local online refresh never grants trust",
            },
            "keys": [self.jwk],
        }
        self.snapshot_digest = jwks_snapshot_digest(self.snapshot)
        self.api_evidence = ruleset_api_evidence(self.workflow_commit)
        self.policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.policy["controlPlaneDigest"] = self.control_digest
        self.policy["signatureSchemes"]["stateEvent"][
            "jwksSnapshotDigest"
        ] = self.snapshot_digest
        principal = self.policy["sshPrincipals"][0]
        principal["identity"] = "reviewer@test.invalid"
        principal["organization"] = "independent-test"
        principal["publicKey"] = self.reviewer_public_key
        principal["fingerprint"] = _ssh_public_key_fingerprint(
            self.reviewer_public_key, "test"
        )
        self.policy_digest = document_digest(self.policy)
        self.component_digests = {
            ".github/workflows/p00-protected-state-writer.yml": self.workflow_digest,
            **{
                relative: sha256_bytes((self.repo / relative).read_bytes())
                for relative in (
                    "tools/phasegate/__init__.py",
                    "tools/phasegate/digest.py",
                    "tools/phasegate/oidc.py",
                    "tools/phasegate/protected.py",
                    "tools/phasegate/protected_v2.py",
                    "tools/phasegate/sshsig.py",
                    "tools/phasegate/state_writer.py",
                    "tools/phasegate/validation.py",
                )
            },
            "execution/phases/P00.yaml": "sha256:" + "3" * 64,
            **{
                f"execution/work-units/P00.W0{index}.yaml": "sha256:"
                + str(index + 3) * 64
                for index in range(1, 6)
            },
        }
        self.request = {
            "schemaVersion": "urn:agentapi-doctor:bootstrap-request:v1alpha3",
            "kind": "BootstrapControlPlaneReviewRequest",
            "requestId": "P00.B00-R3",
            "revision": 3,
            "previousRequest": {
                "requestId": "P00.B00-R2",
                "revision": 2,
                "requestDigest": "sha256:3fc6b9adfc077a2b3f78c2a811a8d61f9fb72c0e7a6c03ff269ff0ee4cc35ca0",
                "controlPlaneDigest": "sha256:8423ed10cd3af376e58382226ba1550f3831d93542ffb580bc1c755e1dee44c6",
                "candidateSourceCommit": "5babc022f1a714024c903122eb150ed49c515e6d",
                "requestCommit": "8faf45512ec5384e816390ad1a46a403c103c5dc",
            },
            "requestStatus": "pending_review",
            "candidate": {
                "baseCommit": "8faf45512ec5384e816390ad1a46a403c103c5dc",
                "candidateSourceCommit": self.source_commit,
                "gitObjectFormat": "sha1",
                "canonicalPlanPath": "agentapi-doctor-Plan.md",
                "controlPlaneDigest": self.control_digest,
            },
            "componentDigests": self.component_digests,
            "digestGroups": {"all": "sha256:" + "8" * 64},
            "testSuites": [],
            "diff": {},
            "decisionsRequested": [{"id": "decision-1", "question": "approve"}],
            "ambiguities": [{"id": "ambiguity-1", "question": "resolve"}],
            "limitations": ["test-only"],
            "nextAuthorizedAction": "test-only",
        }
        self.request_digest = document_digest(self.request)
        self.approval = self._approval()

    def _sign(self, payload: bytes) -> str:
        return subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(self.reviewer_key),
                "-n",
                APPROVAL_NAMESPACE,
            ],
            input=payload,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout.decode("ascii")

    def _approval(self) -> dict:
        body = {
            "attestationId": "r3-test-approval",
            "requestId": "P00.B00-R3",
            "requestRevision": 3,
            "requestDigest": self.request_digest,
            "decision": "APPROVE",
            "candidateSourceCommit": self.source_commit,
            "workflowExecutionCommit": self.workflow_commit,
            "controlPlaneDigest": self.control_digest,
            "digestGroups": self.request["digestGroups"],
            "reviewedDecisionIds": ["decision-1"],
            "reviewedAmbiguityIds": ["ambiguity-1"],
            "scope": {"phase": "P00", "bootstrapId": "P00.B00"},
            "reason": "Independent synthetic R3 review.",
            "validFrom": "2026-07-11T00:00:00Z",
            "validUntil": "2026-08-11T00:00:00Z",
            "constraints": [],
            "conflictOfInterest": {
                "independent": True,
                "statement": "Synthetic reviewer is separate from fixture producer.",
            },
            "reviewer": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
            "trustPolicyDigest": self.policy_digest,
            "jwksSnapshotDigest": self.snapshot_digest,
        }
        unsigned = {"schemaVersion": APPROVAL_SCHEMA, "kind": APPROVAL_KIND, "body": body}
        envelope = {
            **unsigned,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": APPROVAL_NAMESPACE,
                "principal": "reviewer@test.invalid",
                "value": self._sign(canonical_json_bytes(unsigned)),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    def _verify_approval(self, approval: dict | None = None, **pins: str) -> dict:
        return verify_control_plane_approval_v2(
            request=self.request,
            approval=approval or self.approval,
            policy=self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=pins.get("policy", self.policy_digest),
            expected_jwks_snapshot_digest=pins.get("jwks", self.snapshot_digest),
            expected_control_plane_digest=self.control_digest,
            expected_candidate_source_commit=self.source_commit,
            expected_request_digest=self.request_digest,
            expected_workflow_execution_commit=self.workflow_commit,
            consumption_time=self.timestamp,
        )

    def _token(self, audience: str, **claim_overrides: object) -> str:
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
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
            "workflow_ref": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
            "workflow_sha": self.workflow_commit,
            "sha": self.workflow_commit,
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "jti": "v2-test-jti",
            "run_id": "100",
            "run_number": "1",
            "run_attempt": "1",
            "check_run_id": "200",
            "nbf": 1783731595,
            "iat": 1783731600,
            "exp": 1783731900,
        }
        claims.update(claim_overrides)
        header = canonical_json_bytes(
            {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"}
        )
        signing_input = (
            b64url(header) + "." + b64url(canonical_json_bytes(claims))
        ).encode("ascii")
        signature = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self.rsa_key),
            ],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        return signing_input.decode("ascii") + "." + b64url(signature)

    def _event(self, approval_result: dict) -> dict:
        claims = {
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
            "workflow_ref": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
            "workflow_sha": self.workflow_commit,
            "sha": self.workflow_commit,
        }
        return create_genesis_event(
            approval_result=approval_result,
            contract_digests=self.component_digests,
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            trust_policy_digest=self.policy_digest,
            approved_jwks=self.snapshot,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_claims=claims,
            workflow_path=".github/workflows/p00-protected-state-writer.yml",
            workflow_execution_commit=self.workflow_commit,
            statement_timestamp=self.timestamp,
            repository_protection_provider=lambda: deepcopy(self.api_evidence),
            token_provider=self._token,
        )

    def _reseal_event(self, event: dict, **claim_overrides: object) -> dict:
        sealed = deepcopy(event)
        statement = {
            "schemaVersion": sealed["schemaVersion"],
            "kind": sealed["kind"],
            "body": sealed["body"],
        }
        statement_digest = sha256_bytes(canonical_json_bytes(statement))
        sealed["signature"]["statementDigest"] = statement_digest
        sealed["signature"]["jwt"] = self._token(
            "urn:agentapi-doctor:state-event:v1:" + statement_digest,
            **claim_overrides,
        )
        sealed["eventDigest"] = document_digest(
            sealed, omit_field="eventDigest"
        )
        return sealed

    def test_valid_r3_approval_and_oidc_genesis_verify_end_to_end(self) -> None:
        approval_result = self._verify_approval()
        policy_result = validate_trust_policy_v2(
            self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=self.policy_digest,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_control_plane_digest=self.control_digest,
        )
        self.assertEqual(
            policy_result["reviewerDelegation"]["namespace"],
            "agentapi-doctor/reviewer-delegation/v1",
        )
        self.assertEqual(
            policy_result["machineProvenance"]["audiencePrefix"],
            "urn:agentapi-doctor:provenance:v1:",
        )
        self.assertIn(
            "agentapi-doctor/criterion-result/machine/v1",
            policy_result["machineProvenance"]["allowedNamespaces"],
        )
        self.assertEqual(
            tuple(policy_result["delegationRoots"]),
            ("reviewer@test.invalid",),
        )
        event = self._event(approval_result)
        view = verify_genesis_event_v2(
            event=event,
            policy_result=policy_result,
            approval_result=approval_result,
            jwks_snapshot=self.snapshot,
            expected_control_plane_digest=self.control_digest,
            expected_chain_head_digest=event["eventDigest"],
            contract_digests=self.component_digests,
            repo_root=self.repo,
        )
        self.assertEqual(view["activeWorkUnit"], "P00.W01")
        self.assertEqual(view["chain"]["eventCount"], 1)
        protection = view["provenance"]["repositoryProtection"]
        self.assertEqual(protection["repositoryId"], "1296831403")
        self.assertEqual(protection["visibility"], "public")
        self.assertEqual(protection["branch"], "main")
        self.assertEqual(protection["rulesetId"], 42)
        self.assertEqual(
            protection["apiLimitations"],
            ["ruleset bypass actors not observable with read-only token"],
        )
        self.assertEqual(
            protection["apiEvidenceDigest"],
            event["body"]["repositoryProtection"]["apiEvidenceDigest"],
        )

        pull_request_token = self._reseal_event(
            event, base_ref="refs/heads/main"
        )
        with self.assertRaises(ProtectedVerificationError) as caught:
            verify_genesis_event_v2(
                event=pull_request_token,
                policy_result=policy_result,
                approval_result=approval_result,
                jwks_snapshot=self.snapshot,
                expected_control_plane_digest=self.control_digest,
                expected_chain_head_digest=pull_request_token["eventDigest"],
                contract_digests=self.component_digests,
                repo_root=self.repo,
            )
        self.assertEqual(caught.exception.code, "oidc_pull_request_claim_forbidden")

    def test_repository_protection_observation_is_strictly_verified(self) -> None:
        approval_result = self._verify_approval()
        policy_result = validate_trust_policy_v2(
            self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=self.policy_digest,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_control_plane_digest=self.control_digest,
        )
        original = self._event(approval_result)
        cases = []

        wrong_identity = deepcopy(original)
        wrong_identity["body"]["repositoryProtection"]["repository"]["id"] = "1"
        cases.append((wrong_identity, "repository_identity_mismatch"))
        unprotected = deepcopy(original)
        unprotected["body"]["repositoryProtection"]["branch"]["protected"] = False
        cases.append((unprotected, "branch_not_protected"))
        missing_check = deepcopy(original)
        ruleset = missing_check["body"]["repositoryProtection"]["ruleset"]
        effective = missing_check["body"]["repositoryProtection"]["effectiveRules"]
        ruleset["rules"][-1]["parameters"]["requiredStatusChecks"] = ruleset[
            "rules"
        ][-1]["parameters"]["requiredStatusChecks"][:-1]
        effective[-1]["parameters"]["requiredStatusChecks"] = effective[-1][
            "parameters"
        ]["requiredStatusChecks"][:-1]
        cases.append((missing_check, "required_status_checks_mismatch"))
        weak_control = deepcopy(original)
        protection = weak_control["body"]["repositoryProtection"]
        for rules in (
            protection["ruleset"]["rules"],
            protection["effectiveRules"],
        ):
            next(
                rule for rule in rules if rule["type"] == "pull_request"
            )["parameters"]["requireCodeOwnerReview"] = False
        cases.append((weak_control, "repository_ruleset_weakened"))
        hidden_bypass_claim = deepcopy(original)
        hidden_bypass_claim["body"]["repositoryProtection"]["apiLimitations"] = []
        cases.append(
            (hidden_bypass_claim, "repository_protection_limitation_mismatch")
        )
        bad_evidence_digest = deepcopy(original)
        bad_evidence_digest["body"]["repositoryProtection"][
            "apiEvidenceDigest"
        ] = "sha256:" + "0" * 64
        cases.append(
            (
                bad_evidence_digest,
                "repository_protection_evidence_digest_mismatch",
            )
        )

        for candidate, code in cases:
            with self.subTest(code=code):
                event = self._reseal_event(candidate)
                with self.assertRaises(ProtectedVerificationError) as caught:
                    verify_genesis_event_v2(
                        event=event,
                        policy_result=policy_result,
                        approval_result=approval_result,
                        jwks_snapshot=self.snapshot,
                        expected_control_plane_digest=self.control_digest,
                        expected_chain_head_digest=event["eventDigest"],
                        contract_digests=self.component_digests,
                        repo_root=self.repo,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_policy_request_approval_and_coi_tamper_fail_closed(self) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            self._verify_approval(policy="sha256:" + "0" * 64)
        self.assertEqual(caught.exception.code, "trust_policy_digest_mismatch")
        tampered = deepcopy(self.approval)
        tampered["body"]["conflictOfInterest"]["independent"] = False
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        with self.assertRaises(ProtectedVerificationError) as caught:
            self._verify_approval(tampered)
        self.assertEqual(caught.exception.code, "reviewer_not_independent")

    def test_delegation_and_go_no_go_policy_drift_fail_closed(self) -> None:
        cases = []
        redelegation = deepcopy(self.policy)
        redelegation["reviewerDelegation"]["delegatedMayDelegate"] = True
        cases.append((redelegation, "reviewer_delegation_policy_drift"))

        delegated_control_approval = deepcopy(self.policy)
        delegated_control_approval["reviewerDelegation"][
            "allowedCapabilities"
        ].append("approve-control-plane")
        cases.append(
            (delegated_control_approval, "reviewer_delegation_policy_drift")
        )

        no_root = deepcopy(self.policy)
        no_root["sshPrincipals"][0]["capabilities"].remove("delegate-reviewer")
        cases.append((no_root, "invalid_delegation_root"))

        weak_threshold = deepcopy(self.policy)
        weak_threshold["thresholds"]["p00GoNoGo"] = 1
        cases.append((weak_threshold, "unsupported_signature_threshold"))

        same_organization_allowed = deepcopy(self.policy)
        same_organization_allowed["humanCriterionRoleGrants"]["P00-H-GO-NOGO"][
            "distinctOrganizations"
        ] = False
        cases.append((same_organization_allowed, "invalid_fact_policy"))

        audience_replay = deepcopy(self.policy)
        audience_replay["signatureSchemes"]["machineProvenance"][
            "audiencePrefix"
        ] = "urn:agentapi-doctor:state-event:v1:"
        cases.append((audience_replay, "invalid_machine_provenance_policy"))

        missing_executed_component = deepcopy(self.policy)
        missing_executed_component["signatureSchemes"]["machineProvenance"][
            "requiredComponentPaths"
        ].remove("tools/phasegate/oidc_provenance.py")
        cases.append(
            (missing_executed_component, "invalid_machine_provenance_policy")
        )

        for candidate, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(ProtectedVerificationError) as caught:
                    validate_trust_policy_v2(
                        candidate,
                        jwks_snapshot=self.snapshot,
                        expected_policy_digest=document_digest(candidate),
                        expected_jwks_snapshot_digest=self.snapshot_digest,
                        expected_control_plane_digest=self.control_digest,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_workflow_source_or_oidc_protection_claim_drift_is_rejected(self) -> None:
        approval_result = self._verify_approval()
        policy_result = validate_trust_policy_v2(
            self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=self.policy_digest,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_control_plane_digest=self.control_digest,
        )
        event = self._event(approval_result)
        bad = deepcopy(event)
        bad["body"]["writer"]["workflowExecutionCommit"] = self.source_commit
        with self.assertRaises(ProtectedVerificationError) as caught:
            verify_genesis_event_v2(
                event=bad,
                policy_result=policy_result,
                approval_result=approval_result,
                jwks_snapshot=self.snapshot,
                expected_control_plane_digest=self.control_digest,
                expected_chain_head_digest=event["eventDigest"],
                contract_digests=self.component_digests,
                repo_root=self.repo,
            )
        self.assertIn(caught.exception.code, {"chain_head_digest_mismatch", "event_digest_mismatch"})

        with self.assertRaises(Exception):
            # The writer self-verifier refuses an unprotected-ref token before
            # an event can be returned.
            create_genesis_event(
                approval_result=approval_result,
                contract_digests=self.component_digests,
                source_commit=self.source_commit,
                control_plane_digest=self.control_digest,
                trust_policy_digest=self.policy_digest,
                approved_jwks=self.snapshot,
                expected_jwks_snapshot_digest=self.snapshot_digest,
                expected_claims={
                    **{
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
                        "workflow_ref": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
                        "workflow_sha": self.workflow_commit,
                        "sha": self.workflow_commit,
                    }
                },
                workflow_path=".github/workflows/p00-protected-state-writer.yml",
                workflow_execution_commit=self.workflow_commit,
                statement_timestamp=self.timestamp,
                repository_protection_provider=lambda: deepcopy(self.api_evidence),
                token_provider=lambda audience: self._token(
                    audience, ref_protected="false"
                ),
            )


if __name__ == "__main__":
    unittest.main()
