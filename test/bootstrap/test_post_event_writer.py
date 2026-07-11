"""Adversarial tests for the protected post-Genesis event writer."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.chain_witness import (  # noqa: E402
    VerifiedChainHeadWitness,
    _mark_verified as _mark_witness_verified,
)
from tools.phasegate.digest import sha256_bytes  # noqa: E402
from tools.phasegate.oidc import jwks_snapshot_digest  # noqa: E402
from tools.phasegate.post_event_writer import (  # noqa: E402
    PostEventWriterError,
    create_post_genesis_event,
)
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    _state_core_digest,
    document_digest,
)
from tools.phasegate.protected_v2 import (  # noqa: E402
    OIDC_AUDIENCE_PREFIX,
    STATE_VIEW_SCHEMA,
    _expected_oidc_claims,
)
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    VerifiedTransitionApprovalResult,
    VerifiedTransitionProofResult,
    VerifiedWorkUnitTransition,
    _mark_verified as _mark_provenance_verified,
)
from tools.phasegate.state_chain_v2 import (  # noqa: E402
    EXECUTED_VERIFIER_PATHS,
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    authorize_evidence_attachment_v2,
    verify_genesis_anchor_v2,
    verify_next_event_v2,
)


def D(character: str) -> str:
    return "sha256:" + character * 64


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


class PostEventWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="post-event-writer-")
        cls.private_key = Path(cls.temporary.name) / "oidc-test.pem"
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
        cls.jwk = {
            "kid": "post-event-writer-test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(bytes.fromhex(modulus_output.removeprefix("Modulus="))),
            "e": "AQAB",
        }
        cls.repo = Path(cls.temporary.name) / "verified-repo"
        cls.repo.mkdir()
        cls.workflow_path = ".github/workflows/p00-protected-state-writer.yml"
        cls.executed_paths = tuple(
            dict.fromkeys((cls.workflow_path, *EXECUTED_VERIFIER_PATHS))
        )
        for index, relative in enumerate(cls.executed_paths):
            target = cls.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                f"approved protected component {index}: {relative}\n",
                encoding="utf-8",
            )
        cls._git("init", "-q")
        cls._git("config", "user.name", "Post Event Writer Test")
        cls._git("config", "user.email", "post-event-writer@test.invalid")
        cls._git("add", ".")
        cls._git("commit", "-q", "-m", "approved protected components")
        cls.base_commit = cls._git_output("rev-parse", "HEAD")
        cls.approved_component_digests = {
            relative: sha256_bytes((cls.repo / relative).read_bytes())
            for relative in cls.executed_paths
        }
        request = cls.repo / "bootstrap-request.json"
        request.write_text("{}\n", encoding="utf-8")
        cls._git("add", "bootstrap-request.json")
        cls._git("commit", "-q", "-m", "bind bootstrap review request")
        cls.bootstrap_workflow_commit = cls._git_output("rev-parse", "HEAD")
        product = cls.repo / "product.txt"
        product.write_text("forward-only product change\n", encoding="utf-8")
        cls._git("add", "product.txt")
        cls._git("commit", "-q", "-m", "forward product change")
        cls.current_commit = cls._git_output("rev-parse", "HEAD")
        changed_component = cls.repo / "tools/phasegate/state_chain_v2.py"
        changed_component.write_text(
            changed_component.read_text(encoding="utf-8") + "changed verifier\n",
            encoding="utf-8",
        )
        cls._git("add", "tools/phasegate/state_chain_v2.py")
        cls._git("commit", "-q", "-m", "changed protected component")
        cls.changed_component_commit = cls._git_output("rev-parse", "HEAD")

    @classmethod
    def _git(cls, *arguments: str) -> None:
        subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=cls.repo,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

    @classmethod
    def _git_output(cls, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=cls.repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.control_digest = D("1")
        self.contract_digest = D("2")
        self.genesis_head = D("3")
        self.genesis_timestamp = datetime(2026, 7, 11, 11, 0, tzinfo=timezone.utc)
        self.event_timestamp = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)
        self.snapshot = self._snapshot()
        self.snapshot_digest = jwks_snapshot_digest(self.snapshot)
        self.policy_result = self._policy_result()
        self.approval_result = {
            "status": "verified",
            "decision": "APPROVE",
            "approvalDigest": D("4"),
            "requestDigest": D("5"),
            "controlPlaneDigest": self.control_digest,
            "candidateSourceCommit": self.base_commit,
            "workflowExecutionCommit": self.bootstrap_workflow_commit,
            "trustPolicyDigest": self.policy_result["digest"],
            "jwksSnapshotDigest": self.snapshot_digest,
            "componentDigests": deepcopy(self.approved_component_digests),
        }
        self.genesis_core = self._core(
            status="ACTIVE",
            source_commit=self.base_commit,
            approval_digest=self.approval_result["approvalDigest"],
        )
        self.genesis = self._genesis_anchor()
        self.subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=self.current_commit,
            control_plane_digest=self.control_digest,
            contract_digest=self.contract_digest,
        )
        self.transition = self._transition(
            subject=self.subject,
            prior_state_digest=self.genesis.state_digest,
            prior_chain_head_digest=self.genesis_head,
        )
        self.witness = self._witness(self.genesis, digest=D("6"))

    def _snapshot(self) -> dict:
        return {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T05:35:09Z",
            "sourceRawDigest": D("f"),
            "algorithms": ["RS256"],
            "historicalVerificationPolicy": {
                "networkDuringReplay": "forbidden",
                "unknownKid": "block-for-independently-approved-rotation",
                "tokenValidity": "the StateEvent timestamp must precede token issuance by at most 120 seconds and token lifetime must not exceed 600 seconds",
                "revocation": "a later policy revision may explicitly revoke a key; repository-local online refresh never grants trust",
            },
            "keys": [self.jwk],
        }

    def _policy_result(self) -> dict:
        signer = {
            "identity": "github-actions:test/post-event-writer",
            "organization": "github-actions",
            "role": "protected-workflow",
            "repository": "whyiug/agentapi-doctor",
            "repositoryId": "1296831403",
            "repositoryOwner": "whyiug",
            "repositoryOwnerId": "6668626",
            "repositoryVisibility": "public",
            "workflowPath": self.workflow_path,
            "workflowRef": f"whyiug/agentapi-doctor/{self.workflow_path}@refs/heads/main",
            "eventName": "workflow_dispatch",
            "ref": "refs/heads/main",
            "refType": "branch",
            "refProtected": "true",
            "runnerEnvironment": "github-hosted",
            "allowedActorIds": ["6668626"],
        }
        document = {
            "schemaVersion": "urn:test:trust-policy:v1",
            "controlPlaneDigest": self.control_digest,
        }
        return {
            "document": document,
            "digest": document_digest(document),
            "stateSigner": signer,
            "jwks": {"digest": self.snapshot_digest},
        }

    def _core(self, *, status: str, source_commit: str, approval_digest: str) -> dict:
        active = status == "ACTIVE"
        pending = status in {
            "MACHINE_CONVERGED",
            "BLOCKED",
            "WAITING_EXTERNAL",
            "REVIEW_PENDING",
        }
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01" if active else None,
            "pendingWorkUnit": "P00.W01" if pending else None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("a"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.base_commit,
                    "startedAt": "2026-07-11T11:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": status,
                            "contractDigest": self.contract_digest,
                            "approvalDigest": approval_digest,
                            "sourceCommit": source_commit,
                        }
                    },
                }
            },
        }

    def _genesis_anchor(self) -> VerifiedGenesisAnchorV2:
        view = {
            "schemaVersion": STATE_VIEW_SCHEMA,
            **deepcopy(self.genesis_core),
            "stateDigest": _state_core_digest(self.genesis_core),
            "attachments": [],
            "chain": {
                "eventCount": 1,
                "headSequence": 0,
                "headDigest": self.genesis_head,
            },
            "provenance": {
                "workflowRunId": "900",
                "workflowCheckRunId": "1900",
            },
        }
        event = {
            "body": {
                "timestamp": "2026-07-11T11:00:00Z",
                "sourceCommit": self.base_commit,
            }
        }
        with mock.patch(
            "tools.phasegate.state_chain_v2.verify_genesis_event_v2",
            return_value=view,
        ):
            return verify_genesis_anchor_v2(
                event=event,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                jwks_snapshot=self.snapshot,
                expected_control_plane_digest=self.control_digest,
                expected_chain_head_digest=self.genesis_head,
                contract_digests={"unused": D("0")},
                repo_root=self.repo,
            )

    def _transition(
        self,
        *,
        subject: SubjectBinding,
        prior_state_digest: str,
        prior_chain_head_digest: str,
    ) -> VerifiedWorkUnitTransition:
        return _mark_provenance_verified(
            VerifiedWorkUnitTransition(
                transition_type="CONVERGENCE",
                subject=subject,
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prior_state_digest=prior_state_digest,
                prior_chain_head_digest=prior_chain_head_digest,
                proof_digest=D("7"),
                approval_digest=D("8"),
                evidence_digest=D("7"),
                criterion_result_digests=(D("9"),),
            )
        )

    def _position(
        self, current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2
    ) -> tuple[str, str, int, int, str, str]:
        if isinstance(current, VerifiedGenesisAnchorV2):
            return (
                current.chain_head_digest,
                current.state_digest,
                current.event_count,
                current.head_sequence,
                current.head_source_commit,
                current.trust_policy_digest,
            )
        return (
            current.head_digest,
            current.state_digest,
            current.event_count,
            current.head_sequence,
            current.head_source_commit,
            current.trust_policy_digest,
        )

    def _witness(
        self,
        current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
        *,
        digest: str,
        witnessed_at: datetime | None = None,
    ) -> VerifiedChainHeadWitness:
        head, state, count, sequence, source, policy = self._position(current)
        observed = witnessed_at or datetime(2026, 7, 11, 11, 30, tzinfo=timezone.utc)
        return _mark_witness_verified(
            VerifiedChainHeadWitness(
                attestation_digest=digest,
                witness_id=f"witness-{sequence:08d}",
                prior_chain_head_digest=head,
                prior_state_digest=state,
                prior_event_count=count,
                prior_head_sequence=sequence,
                prior_source_commit=source,
                control_plane_digest=self.control_digest,
                trust_policy_digest=policy,
                witnessed_at=observed,
                valid_until=observed.replace(hour=13, minute=0),
                principal="maintainer@test.invalid",
                organization="test-org",
            )
        )

    def _claims(
        self,
        *,
        audience: str,
        timestamp: datetime,
        commit: str,
        run: int,
        overrides: dict | None = None,
    ) -> dict:
        epoch = int(timestamp.timestamp())
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            **_expected_oidc_claims(
                self.policy_result, workflow_execution_commit=commit
            ),
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "jti": f"post-event-writer-jti-{run}",
            "run_id": str(1000 + run),
            "run_number": str(run),
            "run_attempt": "1",
            "check_run_id": str(2000 + run),
            "nbf": epoch - 5,
            "iat": epoch,
            "exp": epoch + 300,
        }
        claims.update(overrides or {})
        return claims

    def _token(self, claims: dict) -> str:
        header = {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"}
        signing_input = (
            b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
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

    def _provider(
        self,
        *,
        timestamp: datetime,
        commit: str,
        run: int,
        overrides: dict | None = None,
    ):
        def provide(audience: str) -> str:
            self.assertTrue(audience.startswith(OIDC_AUDIENCE_PREFIX))
            return self._token(
                self._claims(
                    audience=audience,
                    timestamp=timestamp,
                    commit=commit,
                    run=run,
                    overrides=overrides,
                )
            )

        return provide

    def _create_transition(self, **overrides):
        arguments = {
            "current": self.genesis,
            "verified_event_input": self.transition,
            "chain_head_witness": self.witness,
            "policy_result": self.policy_result,
            "approval_result": self.approval_result,
            "approved_jwks_snapshot": self.snapshot,
            "repo_root": self.repo,
            "workflow_execution_commit": self.current_commit,
            "statement_timestamp": self.event_timestamp,
            "token_provider": self._provider(
                timestamp=self.event_timestamp,
                commit=self.current_commit,
                run=1,
            ),
        }
        arguments.update(overrides)
        return create_post_genesis_event(**arguments)

    def _attachment_bundle(self):
        signer = VerifiedSignerResult(
            scheme="github-actions-oidc-v1",
            namespace="test",
            principal="workflow@test.invalid",
            role="protected-workflow",
            organization="github-actions",
            statement_digest=D("1"),
            authority_digest=self.policy_result["digest"],
            source_commit=self.current_commit,
            control_plane_digest=self.control_digest,
        )
        criterion = CriterionBinding(
            criterion_id="C-MACHINE",
            kind="MACHINE",
            evaluator="evaluator://test/v1",
            evaluator_digest=D("a"),
            evidence_schema="evidence-schema://test/v1",
            evidence_schema_digest=D("b"),
            dataset_digest=D("c"),
            threshold_digest=D("d"),
        )
        freeze = _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("e"),
                statement_digest=D("f"),
                freeze_id="freeze-test",
                subject=self.subject,
                contract_approval_digest=D("1"),
                protected_inputs=(),
                criteria=(criterion,),
                signer=signer,
            )
        )
        result = _mark_provenance_verified(
            VerifiedCriterionResult(
                attestation_digest=D("9"),
                statement_digest=D("2"),
                result_id="result-test",
                freeze_digest=freeze.attestation_digest,
                subject=self.subject,
                criterion=criterion,
                outcome="PASS",
                evidence_digest=D("3"),
                run_pair_digest=D("3"),
                signature_verified=True,
                fact_status="not_applicable",
                criterion_satisfied=True,
                signer=signer,
            )
        )
        proof = _mark_provenance_verified(
            VerifiedTransitionProofResult(
                attestation_digest=D("7"),
                statement_digest=D("4"),
                proof_id="proof-test",
                freeze_digest=freeze.attestation_digest,
                subject=self.subject,
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prior_state_digest=self.genesis.state_digest,
                prior_chain_head_digest=self.genesis_head,
                criterion_results=(
                    (
                        criterion.criterion_id,
                        criterion.kind,
                        result.attestation_digest,
                        result.evidence_digest,
                    ),
                ),
                signer=signer,
            )
        )
        approval = _mark_provenance_verified(
            VerifiedTransitionApprovalResult(
                attestation_digest=D("8"),
                statement_digest=D("5"),
                approval_id="approval-test",
                proof_digest=proof.attestation_digest,
                subject=self.subject,
                from_state=proof.from_state,
                to_state=proof.to_state,
                decision="APPROVE",
                authorized=True,
                signer=signer,
            )
        )
        return authorize_evidence_attachment_v2(
            freeze=freeze,
            criterion_results=[result],
            proof=proof,
            approval=approval,
        )

    def assert_writer_code(self, code: str, **overrides) -> None:
        with self.assertRaises(PostEventWriterError) as caught:
            self._create_transition(**overrides)
        self.assertEqual(caught.exception.code, code)

    def test_valid_transition_and_attachment_are_projected_and_self_verified(
        self,
    ) -> None:
        event, chain = self._create_transition()
        self.assertEqual(event["body"]["sequence"], 1)
        self.assertEqual(event["body"]["previousDigest"], self.genesis_head)
        self.assertEqual(
            event["body"]["payload"]["chainHeadWitnessDigest"],
            self.witness.attestation_digest,
        )
        self.assertEqual(chain.head_digest, event["eventDigest"])
        self.assertEqual(chain.event_count, 2)
        self.assertEqual(
            chain.state_core["phases"]["P00"]["workUnits"]["P00.W01"]["status"],
            "MACHINE_CONVERGED",
        )
        attachment = self._attachment_bundle()
        attachment_time = self.event_timestamp.replace(minute=1)
        witness = self._witness(
            chain,
            digest=D("b"),
            witnessed_at=self.event_timestamp.replace(second=30),
        )
        attached_event, attached_chain = create_post_genesis_event(
            current=chain,
            verified_event_input=attachment,
            chain_head_witness=witness,
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            workflow_execution_commit=self.current_commit,
            statement_timestamp=attachment_time,
            token_provider=self._provider(
                timestamp=attachment_time,
                commit=self.current_commit,
                run=2,
            ),
        )
        self.assertEqual(attached_event["body"]["eventType"], "EvidenceAttachment")
        self.assertEqual(
            attached_event["body"]["payload"]["evidenceSourceCommit"],
            self.current_commit,
        )
        self.assertEqual(attached_chain.state_digest, chain.state_digest)
        self.assertEqual(attached_chain.event_count, 3)
        self.assertEqual(len(attached_chain.attachments), 1)

    def test_forged_or_copied_current_input_and_witness_fail_before_token(self) -> None:
        def forbidden(_audience: str) -> str:
            self.fail("token provider must not run for an unsealed input")

        cases = {
            "current": {"current": deepcopy(self.genesis)},
            "transition": {"verified_event_input": deepcopy(self.transition)},
            "witness": {"chain_head_witness": deepcopy(self.witness)},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                overrides["token_provider"] = forbidden
                self.assert_writer_code("unverified_internal_result", **overrides)

    def test_every_stale_witness_binding_is_rejected(self) -> None:
        replacements = {
            "head": {"prior_chain_head_digest": D("d")},
            "state": {"prior_state_digest": D("d")},
            "count": {"prior_event_count": 2},
            "sequence": {"prior_head_sequence": 1},
            "source": {"prior_source_commit": "f" * 40},
            "control": {"control_plane_digest": D("d")},
            "policy": {"trust_policy_digest": D("d")},
        }
        for name, changes in replacements.items():
            with self.subTest(name=name):
                stale = _mark_witness_verified(replace(self.witness, **changes))
                self.assert_writer_code(
                    "chain_witness_binding_mismatch",
                    chain_head_witness=stale,
                    token_provider=lambda _audience: self.fail(
                        "stale witness must fail before token acquisition"
                    ),
                )

    def test_nonmonotonic_time_and_stale_replay_are_rejected(self) -> None:
        self.assert_writer_code(
            "nonmonotonic_event_time",
            statement_timestamp=self.genesis_timestamp,
            token_provider=lambda _audience: self.fail(
                "nonmonotonic event must fail before token acquisition"
            ),
        )
        _event, chain = self._create_transition()
        with self.assertRaises(PostEventWriterError) as caught:
            create_post_genesis_event(
                current=chain,
                verified_event_input=self.transition,
                chain_head_witness=self.witness,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                approved_jwks_snapshot=self.snapshot,
                repo_root=self.repo,
                workflow_execution_commit=self.current_commit,
                statement_timestamp=self.event_timestamp.replace(minute=1),
                token_provider=lambda _audience: self.fail(
                    "stale replay must fail before token acquisition"
                ),
            )
        self.assertEqual(caught.exception.code, "chain_witness_binding_mismatch")

    def test_workflow_run_replay_is_rejected_incrementally(self) -> None:
        _event, chain = self._create_transition()
        attachment = self._attachment_bundle()
        attachment_time = self.event_timestamp.replace(minute=1)
        witness = self._witness(
            chain,
            digest=D("b"),
            witnessed_at=self.event_timestamp.replace(second=30),
        )
        with self.assertRaises(PostEventWriterError) as caught:
            create_post_genesis_event(
                current=chain,
                verified_event_input=attachment,
                chain_head_witness=witness,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                approved_jwks_snapshot=self.snapshot,
                repo_root=self.repo,
                workflow_execution_commit=self.current_commit,
                statement_timestamp=attachment_time,
                token_provider=self._provider(
                    timestamp=attachment_time,
                    commit=self.current_commit,
                    run=1,
                ),
            )
        self.assertEqual(caught.exception.code, "oidc_run_replay")

    def test_payload_and_event_digest_mutation_fail_incremental_verification(
        self,
    ) -> None:
        event, _chain = self._create_transition()
        tampered_payload = deepcopy(event)
        tampered_payload["body"]["payload"]["proofDigest"] = D("f")
        tampered_payload["eventDigest"] = document_digest(
            tampered_payload, omit_field="eventDigest"
        )
        for expected, tampered in (
            ("signature_binding_mismatch", tampered_payload),
            (
                "event_digest_mismatch",
                {**deepcopy(event), "eventDigest": D("f")},
            ),
        ):
            with self.subTest(code=expected):
                with self.assertRaises(ProtectedVerificationError) as caught:
                    verify_next_event_v2(
                        current=self.genesis,
                        event=tampered,
                        verified_event_input=self.transition,
                        expected_chain_head_witness_digest=self.witness.attestation_digest,
                        policy_result=self.policy_result,
                        approval_result=self.approval_result,
                        jwks_snapshot=self.snapshot,
                        repo_root=self.repo,
                        approved_component_digests=self.approved_component_digests,
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_pr_ref_and_current_commit_oidc_mismatch_are_rejected(self) -> None:
        cases = {
            "oidc_pull_request_ref_forbidden": {"head_ref": "refs/heads/topic"},
            "oidc_claim_mismatch": {"sha": self.base_commit},
        }
        for expected, overrides in cases.items():
            with self.subTest(code=expected):
                self.assert_writer_code(
                    expected,
                    token_provider=self._provider(
                        timestamp=self.event_timestamp,
                        commit=self.current_commit,
                        run=20,
                        overrides=overrides,
                    ),
                )

    def test_bootstrap_trust_jwks_and_component_blob_substitution_are_rejected(
        self,
    ) -> None:
        substituted_policy = deepcopy(self.policy_result)
        substituted_policy["digest"] = D("d")
        self.assert_writer_code(
            "genesis_trust_binding_mismatch",
            policy_result=substituted_policy,
            token_provider=lambda _audience: self.fail(
                "substituted policy must fail before token acquisition"
            ),
        )
        substituted_approval = deepcopy(self.approval_result)
        substituted_approval["approvalDigest"] = D("d")
        self.assert_writer_code(
            "genesis_trust_binding_mismatch",
            approval_result=substituted_approval,
        )
        changed_subject = replace(
            self.subject, source_commit=self.changed_component_commit
        )
        changed_transition = self._transition(
            subject=changed_subject,
            prior_state_digest=self.genesis.state_digest,
            prior_chain_head_digest=self.genesis_head,
        )
        self.assert_writer_code(
            "workflow_source_digest_mismatch",
            verified_event_input=changed_transition,
            workflow_execution_commit=self.changed_component_commit,
            token_provider=self._provider(
                timestamp=self.event_timestamp,
                commit=self.changed_component_commit,
                run=30,
            ),
        )
        wrong_snapshot = deepcopy(self.snapshot)
        wrong_snapshot["keys"][0]["kid"] = "substituted-key-id"
        self.assert_writer_code(
            "oidc_jwks_snapshot_digest_mismatch",
            approved_jwks_snapshot=wrong_snapshot,
        )


if __name__ == "__main__":
    unittest.main()
