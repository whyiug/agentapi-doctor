"""Adversarial tests for protected-workflow OIDC provenance."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib import parse

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes
from tools.phasegate.gate_runner import combine_runs, record_run
from tools.phasegate.oidc import jwks_snapshot_digest
from tools.phasegate.oidc_provenance import (
    OIDC_PROVENANCE_AUDIENCE_PREFIX,
    OidcProvenanceError,
    build_oidc_provenance_verifier,
    create_signed_machine_criterion_result,
    github_actions_provenance_token_provider,
)
from tools.phasegate.protected import (
    ProtectedVerificationError,
    _state_core_digest,
    document_digest,
)
from tools.phasegate.protected_v2 import validate_trust_policy_v2
from tools.phasegate.provenance import (
    HUMAN_CRITERION_NAMESPACE,
    MACHINE_CRITERION_NAMESPACE,
    FREEZE_KIND,
    FREEZE_NAMESPACE,
    FREEZE_SCHEMA,
    SubjectBinding,
    VerifiedSignerResult,
    verify_signed_criterion_result,
    verify_signed_protected_input_freeze,
)
from tools.phasegate.state_chain_v2 import (
    EXECUTED_VERIFIER_PATHS,
    VerifiedGenesisAnchorV2,
    _mark_verified as _mark_state_verified,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def digest(character: str) -> str:
    return "sha256:" + character * 64


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


class ProtectedWorkflowOidcProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="oidc-provenance-")
        cls.private_key = Path(cls.temporary.name) / "oidc.pem"
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
            "kid": "oidc-provenance-test",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }
        cls.repo = Path(cls.temporary.name) / "repo"
        policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        required_paths = policy["signatureSchemes"]["machineProvenance"][
            "requiredComponentPaths"
        ]
        for relative in required_paths:
            target = cls.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / relative, target)
        cls.canonical_component = "execution/catalogs/canonical-fixture.json"
        canonical_path = cls.repo / cls.canonical_component
        canonical_path.parent.mkdir(parents=True, exist_ok=True)
        canonical_path.write_text(
            '{\n  "kind": "CanonicalFixture",\n  "values": [3, 2, 1]\n}\n',
            encoding="utf-8",
        )
        subprocess.run(["/usr/bin/git", "init", "-q", str(cls.repo)], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "config", "user.name", "test"],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["/usr/bin/git", "-C", str(cls.repo), "add", "."], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "commit", "-q", "-m", "source"],
            check=True,
        )
        cls.approved_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        cls.components = {
            relative: sha256_bytes((cls.repo / relative).read_bytes())
            for relative in required_paths
        }
        canonical_document = json.loads(canonical_path.read_text(encoding="utf-8"))
        cls.components[cls.canonical_component] = document_digest(canonical_document)
        cls.canonical_raw_digest = sha256_bytes(canonical_path.read_bytes())
        product = cls.repo / "src/product-only.txt"
        product.parent.mkdir(parents=True)
        product.write_text("product-only descendant\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "add", str(product.relative_to(cls.repo))],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "commit",
                "-q",
                "-m",
                "product-only descendant",
            ],
            check=True,
        )
        cls.product_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        changed_component = cls.repo / "tools/phasegate/oidc_provenance.py"
        changed_component.write_text(
            changed_component.read_text(encoding="utf-8") + "# changed\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "add",
                "tools/phasegate/oidc_provenance.py",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "commit",
                "-q",
                "-m",
                "changed protected component",
            ],
            check=True,
        )
        cls.changed_component_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        approved_tree = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "rev-parse",
                cls.approved_commit + "^{tree}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        cls.unrelated_commit = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.repo),
                "commit-tree",
                approved_tree,
                "-m",
                "unrelated root",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.timestamp = datetime(2026, 7, 11, 1, 0, 0, tzinfo=timezone.utc)
        self.source_commit = self.__class__.product_commit
        self.control_digest = digest("1")
        self.contract_digest = digest("2")
        self.snapshot = {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T00:00:00Z",
            "sourceRawDigest": digest("3"),
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
        self.policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.policy["controlPlaneDigest"] = self.control_digest
        self.policy["signatureSchemes"]["stateEvent"][
            "jwksSnapshotDigest"
        ] = self.snapshot_digest
        self.policy_digest = document_digest(self.policy)
        self.policy_result = validate_trust_policy_v2(
            self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=self.policy_digest,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_control_plane_digest=self.control_digest,
        )
        self.components = dict(self.__class__.components)
        self.approval_digest = digest("0")
        work_units = {
            f"P00.W0{index}": {
                "status": "ACTIVE" if index == 1 else "NOT_STARTED",
                "contractDigest": digest(str(index)),
                "approvalDigest": self.approval_digest if index == 1 else None,
                "sourceCommit": self.__class__.approved_commit
                if index == 1
                else None,
            }
            for index in range(1, 6)
        }
        state_core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": digest("a"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.__class__.approved_commit,
                    "startedAt": "2026-07-11T00:00:00Z",
                    "workUnits": work_units,
                }
            },
        }
        self.current = _mark_state_verified(
            VerifiedGenesisAnchorV2(
                state_core=state_core,
                state_digest=_state_core_digest(state_core),
                chain_head_digest=digest("b"),
                head_sequence=0,
                event_count=1,
                timestamp=datetime(2026, 7, 11, tzinfo=timezone.utc),
                head_source_commit=self.__class__.approved_commit,
                attachments=(),
                control_plane_digest=self.control_digest,
                trust_policy_digest=self.policy_digest,
                jwks_snapshot_digest=self.snapshot_digest,
                workflow_execution_commit=self.__class__.approved_commit,
                workflow_run_id="10",
                workflow_check_run_id="20",
                approved_component_digests=tuple(sorted(self.components.items())),
                state_signer_digest=document_digest(
                    self.policy_result["stateSigner"]
                ),
                bootstrap_approval_digest=self.approval_digest,
                bootstrap_request_digest=digest("c"),
            )
        )
        self.verifier = self._verifier(MACHINE_CRITERION_NAMESPACE)
        self.inputs = {
            "planDigest": digest("4"),
            "supportLockDigest": digest("5"),
            "toolchainDigest": digest("6"),
            "dependencySetDigest": digest("7"),
            "gateRunnerDigest": digest("8"),
            "evaluatorSetDigest": digest("9"),
            "metricDefinitionsDigest": digest("a"),
            "protectedAcceptanceDigest": digest("b"),
        }
        self.criterion = {
            "id": "P00-M-BOOTSTRAP-CONTROL",
            "kind": "MACHINE",
            "evaluator": "evaluator://bootstrap/control-plane/v1",
            "evaluatorDigest": digest("c"),
            "evaluatorStatus": "implemented",
            "evidenceSchema": "evidence-schema://test/machine/v1",
            "evidenceSchemaDigest": digest("d"),
            "datasetDigest": digest("e"),
            "thresholdDigest": digest("f"),
        }
        self.freeze = self._freeze()
        self.run_pair = self._run_pair()

    def _verifier(self, namespace: str, **overrides: object):
        values = {
            "current": self.current,
            "policy_result": self.policy_result,
            "approved_jwks_snapshot": self.snapshot,
            "repo_root": self.__class__.repo,
            "current_source_commit": self.source_commit,
            "current_workflow_execution_commit": self.source_commit,
            "expected_namespace": namespace,
        }
        values.update(overrides)
        return build_oidc_provenance_verifier(**values)

    def _token(
        self, audience: str, *, verifier=None, **claim_overrides: object
    ) -> str:
        authority = verifier or self.verifier
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            **dict(authority.expected_claims),
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "jti": "oidc-provenance-jti",
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
                str(self.private_key),
            ],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        return signing_input.decode("ascii") + "." + b64url(signature)

    def _freeze(self):
        subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            contract_digest=self.contract_digest,
        )
        body = {
            "freezeId": "freeze-P00.W01-oidc-provenance",
            "subject": {
                "phase": subject.phase,
                "workUnit": subject.work_unit,
                "sourceCommit": subject.source_commit,
                "controlPlaneDigest": subject.control_plane_digest,
                "contractDigest": subject.contract_digest,
            },
            "contractApprovalDigest": digest("0"),
            "protectedInputs": self.inputs,
            "criteria": [self.criterion],
            "issuedAt": "2026-07-11T00:00:00Z",
            "actor": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "review-org",
            },
            "authorityDigest": digest("f"),
        }
        statement = {"schemaVersion": FREEZE_SCHEMA, "kind": FREEZE_KIND, "body": body}
        payload = canonical_json_bytes(statement)
        envelope = {
            **statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": FREEZE_NAMESPACE,
                "principal": "reviewer@test.invalid",
                "value": "synthetic-fixture-signature",
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=FREEZE_NAMESPACE,
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-org",
            statement_digest=sha256_bytes(payload),
            authority_digest=digest("f"),
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
        )
        return verify_signed_protected_input_freeze(
            envelope,
            expected_subject=subject,
            expected_contract_approval_digest=digest("0"),
            expected_protected_inputs=self.inputs,
            expected_criteria=[self.criterion],
            expected_authority_digest=digest("f"),
            verified_signer_result=signer,
        )

    def _command(self, label: str) -> dict:
        return {
            "exitCode": 0,
            "durationMs": 60_000,
            "startedAt": "2026-07-11T00:10:00Z",
            "finishedAt": "2026-07-11T00:11:00Z",
            "environmentDigest": digest("1" if label == "A" else "2"),
            "logDigest": digest("3" if label == "A" else "4"),
            "artifactManifestDigest": digest("5" if label == "A" else "6"),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "semanticAssertions": [
                {
                    "id": "candidate-semantically-valid",
                    "status": "PASS",
                    "evidenceDigest": digest("7"),
                }
            ],
        }

    def _run_pair(self):
        run_a = record_run(
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            label="A",
            command_result=self._command("A"),
        )
        run_b = record_run(
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            label="B",
            command_result=self._command("B"),
        )
        return combine_runs(
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_a=run_a,
            run_b=run_b,
        )

    def _payload(self, verifier=None) -> bytes:
        authority = verifier or self.verifier
        return canonical_json_bytes(
            {
                "schemaVersion": "urn:test:generic-provenance:v1",
                "kind": "GenericProtectedProof",
                "body": {
                    "subject": {
                        "sourceCommit": self.source_commit,
                        "controlPlaneDigest": self.control_digest,
                    },
                    "issuedAt": "2026-07-11T01:00:00Z",
                    "actor": {
                        "principal": authority.principal,
                        "role": authority.role,
                        "organization": authority.organization,
                    },
                    "authorityDigest": authority.authority_digest,
                },
            }
        )

    def _signature(
        self, verifier, payload: bytes, **claim_overrides: object
    ) -> dict:
        audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + sha256_bytes(payload)
        return {
            "scheme": "github-actions-oidc-jwt-rs256-v1",
            "namespace": verifier.namespace,
            "principal": verifier.principal,
            "value": self._token(
                audience, verifier=verifier, **claim_overrides
            ),
        }

    def _assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(
            (OidcProvenanceError, ProtectedVerificationError)
        ) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_generic_callback_supports_every_approved_machine_proof_namespace(
        self,
    ) -> None:
        namespaces = self.policy["signatureSchemes"]["machineProvenance"][
            "allowedNamespaces"
        ]
        required_paths = self.policy["signatureSchemes"]["machineProvenance"][
            "requiredComponentPaths"
        ]
        self.assertEqual(
            required_paths,
            sorted(
                (
                    self.policy["githubActionsStateSigner"]["workflowPath"],
                    *EXECUTED_VERIFIER_PATHS,
                )
            ),
        )
        self.assertEqual(len(namespaces), 7)
        self.assertIn(
            "agentapi-doctor/lifecycle-evidence/invalidation/v1", namespaces
        )
        for namespace in namespaces:
            with self.subTest(namespace=namespace):
                verifier = self._verifier(namespace)
                payload = self._payload(verifier)
                result = verifier(
                    payload,
                    self._signature(verifier, payload),
                    namespace,
                )
                self.assertEqual(result.namespace, namespace)
                self.assertEqual(result.role, "protected-workflow")
                self.assertEqual(result.source_commit, self.source_commit)
                self.assertEqual(
                    result.control_plane_digest, self.control_digest
                )
                self.assertEqual(result.authority_digest, verifier.authority_digest)

    def test_machine_writer_consumes_seals_and_self_verifies(self) -> None:
        seen = []

        def provider(audience: str) -> str:
            seen.append(audience)
            return self._token(audience)

        envelope, result = create_signed_machine_criterion_result(
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=provider,
        )
        self.assertTrue(result.signature_verified)
        self.assertTrue(result.criterion_satisfied)
        self.assertEqual(result.signer.authority_digest, self.verifier.authority_digest)
        self.assertEqual(envelope["body"]["runPairDigest"], result.run_pair_digest)
        self.assertEqual(
            set(envelope["signature"]),
            {"scheme", "namespace", "principal", "value"},
        )
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].startswith(OIDC_PROVENANCE_AUDIENCE_PREFIX))
        json.dumps(envelope, allow_nan=False, sort_keys=True)

    def test_product_descendant_succeeds_but_component_change_and_fork_fail(
        self,
    ) -> None:
        self.assertNotEqual(
            self.current.head_source_commit, self.verifier.source_commit
        )
        self.assertEqual(self.verifier.source_commit, self.__class__.product_commit)
        self.assertEqual(
            self.verifier.approval_digest,
            self.current.bootstrap_approval_digest,
        )
        self.assertNotEqual(
            self.components[self.__class__.canonical_component],
            self.__class__.canonical_raw_digest,
        )
        self.assertIn(
            (
                self.__class__.canonical_component,
                self.components[self.__class__.canonical_component],
            ),
            self.verifier.component_digests,
        )
        self.assertEqual(
            self.verifier.component_set_digest,
            sha256_bytes(
                canonical_json_bytes({"componentDigests": self.components})
            ),
        )
        self._assert_error(
            "approved_component_digest_mismatch",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current_source_commit=self.__class__.changed_component_commit,
            current_workflow_execution_commit=self.__class__.changed_component_commit,
        )
        self._assert_error(
            "source_commit_not_descendant",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current_source_commit=self.__class__.unrelated_commit,
            current_workflow_execution_commit=self.__class__.unrelated_commit,
        )

    def test_token_namespace_result_commit_and_pull_request_replay_fail(self) -> None:
        envelope, _ = create_signed_machine_criterion_result(
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=self._token,
        )
        changed_result = deepcopy(envelope)
        changed_result["body"]["resultId"] += "-replayed"
        changed_result["attestationDigest"] = document_digest(
            changed_result, omit_field="attestationDigest"
        )
        self._assert_error(
            "oidc_audience_mismatch",
            verify_signed_criterion_result,
            changed_result,
            freeze=self.freeze,
            expected_authority_digest=self.verifier.authority_digest,
            signer_verifier=self.verifier,
        )

        wrong_namespace = deepcopy(envelope)
        wrong_namespace["signature"]["namespace"] = HUMAN_CRITERION_NAMESPACE
        wrong_namespace["attestationDigest"] = document_digest(
            wrong_namespace, omit_field="attestationDigest"
        )
        self._assert_error(
            "signature_namespace_mismatch",
            verify_signed_criterion_result,
            wrong_namespace,
            freeze=self.freeze,
            expected_authority_digest=self.verifier.authority_digest,
            signer_verifier=self.verifier,
        )

        self._assert_error(
            "oidc_claim_mismatch",
            create_signed_machine_criterion_result,
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=lambda audience: self._token(
                audience, workflow_sha="b" * 40
            ),
        )
        self._assert_error(
            "oidc_rerun_forbidden",
            create_signed_machine_criterion_result,
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=lambda audience: self._token(
                audience, run_attempt="2"
            ),
        )
        for claim in ("head_ref", "base_ref"):
            with self.subTest(claim=claim):
                self._assert_error(
                    "oidc_pull_request_claim_forbidden",
                    create_signed_machine_criterion_result,
                    freeze=self.freeze,
                    criterion_id=self.criterion["id"],
                    run_pair=self.run_pair,
                    verifier=self.verifier,
                    issued_at=self.timestamp,
                    token_provider=lambda audience, name=claim: self._token(
                        audience, **{name: ""}
                    ),
                )

    def test_actor_authority_source_control_and_component_bindings_are_exact(self) -> None:
        mutations = (
            ("actor", "actor_principal_mismatch"),
            ("authority", "authority_digest_mismatch"),
            ("source", "source_commit_mismatch"),
            ("control", "control_plane_digest_mismatch"),
        )
        for field, code in mutations:
            with self.subTest(field=field):
                document = json.loads(self._payload().decode("utf-8"))
                if field == "actor":
                    document["body"]["actor"]["principal"] = "other@test.invalid"
                elif field == "authority":
                    document["body"]["authorityDigest"] = digest("0")
                elif field == "source":
                    document["body"]["subject"]["sourceCommit"] = "b" * 40
                else:
                    document["body"]["subject"]["controlPlaneDigest"] = digest("0")
                payload = canonical_json_bytes(document)
                self._assert_error(
                    code,
                    self.verifier,
                    payload,
                    self._signature(self.verifier, payload),
                    self.verifier.namespace,
                )

        self._assert_error(
            "source_workflow_commit_mismatch",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current_workflow_execution_commit=self.__class__.approved_commit,
        )
        self._assert_error(
            "approved_component_digest_mismatch",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current_source_commit=self.__class__.changed_component_commit,
            current_workflow_execution_commit=self.__class__.changed_component_commit,
        )
        self._assert_error(
            "source_commit_not_descendant",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current_source_commit=self.__class__.unrelated_commit,
            current_workflow_execution_commit=self.__class__.unrelated_commit,
        )
        missing_pins = tuple(
            item
            for item in self.current.approved_component_digests
            if item[0] != "tools/phasegate/oidc_provenance.py"
        )
        self._assert_error(
            "unverified_internal_result",
            self._verifier,
            MACHINE_CRITERION_NAMESPACE,
            current=replace(
                self.current, approved_component_digests=missing_pins
            ),
        )

    def test_forged_freeze_pair_and_verifier_fail_before_token_acquisition(self) -> None:
        calls = []

        def provider(_audience: str) -> str:
            calls.append(True)
            raise AssertionError("must not acquire a token")

        self._assert_error(
            "unverified_internal_result",
            create_signed_machine_criterion_result,
            freeze=replace(self.freeze),
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=provider,
        )
        self._assert_error(
            "unsealed_run_pair",
            create_signed_machine_criterion_result,
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=deepcopy(self.run_pair),
            verifier=self.verifier,
            issued_at=self.timestamp,
            token_provider=provider,
        )
        self._assert_error(
            "unverified_oidc_authority",
            create_signed_machine_criterion_result,
            freeze=self.freeze,
            criterion_id=self.criterion["id"],
            run_pair=self.run_pair,
            verifier=replace(self.verifier),
            issued_at=self.timestamp,
            token_provider=provider,
        )
        self.assertEqual(calls, [])

    def test_default_provider_is_actions_only_fixed_endpoint_and_secret_safe(self) -> None:
        audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + digest("a")
        self._assert_error(
            "not_github_actions",
            github_actions_provenance_token_provider,
            audience,
            environ={},
        )
        secret = "never-print-this-bearer"
        with self.assertRaises(OidcProvenanceError) as caught:
            github_actions_provenance_token_provider(
                audience,
                environ={
                    "GITHUB_ACTIONS": "true",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": secret,
                },
            )
        self.assertEqual(caught.exception.code, "unsafe_oidc_endpoint")
        self.assertNotIn(secret, str(caught.exception))

        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _maximum):
                return b'{ "value": "synthetic.jwt.value" }'

        def urlopen(value, timeout):
            requests.append((value, timeout))
            return Response()

        token = github_actions_provenance_token_provider(
            audience,
            environ={
                "GITHUB_ACTIONS": "true",
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?api-version=1",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": secret,
            },
            urlopen=urlopen,
        )
        self.assertEqual(token, "synthetic.jwt.value")
        self.assertEqual(len(requests), 1)
        query = dict(parse.parse_qsl(parse.urlsplit(requests[0][0].full_url).query))
        self.assertEqual(query["audience"], audience)


if __name__ == "__main__":
    unittest.main()
