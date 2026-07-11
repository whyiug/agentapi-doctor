"""Adversarial tests for R3 post-Genesis state-chain replay."""

from __future__ import annotations

import base64
from copy import deepcopy
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

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.oidc import jwks_snapshot_digest  # noqa: E402
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    _state_core_digest,
    _validate_state_invariants,
    document_digest,
)
from tools.phasegate.protected_v2 import (  # noqa: E402
    OIDC_AUDIENCE_PREFIX,
    OIDC_SIGNATURE_SCHEME,
    STATE_EVENT_KIND,
    STATE_EVENT_NAMESPACE,
    STATE_EVENT_SCHEMA,
    STATE_VIEW_SCHEMA,
    _expected_oidc_claims,
)
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    PhaseSubject,
    PhaseUnitStateBinding,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    VerifiedLifecycleTransition,
    VerifiedPhaseTransition,
    VerifiedTransitionApprovalResult,
    VerifiedTransitionProofResult,
    VerifiedWorkUnitTransition,
    _mark_verified as _mark_provenance_verified,
)
from tools.phasegate.state_chain_v2 import (  # noqa: E402
    EXECUTED_VERIFIER_PATHS,
    VerifiedEvidenceAttachmentV2,
    authorize_evidence_attachment_v2,
    project_evidence_attachment_payload_v2,
    project_state_transition_payload_v2,
    require_verified_state_context_v2,
    replay_post_genesis_chain_v2,
    verify_projected_state_transition_v2,
    verify_genesis_anchor_v2,
    verify_next_event_v2,
    verify_projected_evidence_attachment_v2,
)


def D(character: str) -> str:
    return "sha256:" + character * 64


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


class StateChainV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="state-chain-v2-")
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
        modulus = bytes.fromhex(modulus_output.removeprefix("Modulus="))
        cls.jwk = {
            "kid": "state-chain-test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }
        cls.repo = Path(cls.temporary.name) / "verified-repo"
        cls.repo.mkdir()
        cls.workflow_path = ".github/workflows/p00-protected-state-writer.yml"
        cls.executed_paths = (cls.workflow_path, *EXECUTED_VERIFIER_PATHS)
        for index, relative in enumerate(cls.executed_paths):
            target = cls.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                f"approved protected component {index}: {relative}\n",
                encoding="utf-8",
            )
        subprocess.run(
            ["/usr/bin/git", "init", "-q"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "config", "user.name", "State Chain Test"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "config", "user.email", "state-chain@test.invalid"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "add", "."], cwd=cls.repo, check=True, timeout=10
        )
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "approved components"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        cls.approved_commit = subprocess.run(
            ["/usr/bin/git", "rev-parse", "HEAD"],
            cwd=cls.repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        cls.approved_component_digests = {
            relative: sha256_bytes((cls.repo / relative).read_bytes())
            for relative in cls.executed_paths
        }
        product = cls.repo / "product.txt"
        product.write_text("forward-only product change\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "add", "product.txt"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "forward product"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        cls.forward_commit = subprocess.run(
            ["/usr/bin/git", "rev-parse", "HEAD"],
            cwd=cls.repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        changed_component = cls.repo / "tools/phasegate/state_chain_v2.py"
        changed_component.write_text(
            changed_component.read_text(encoding="utf-8") + "changed\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["/usr/bin/git", "add", "tools/phasegate/state_chain_v2.py"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "changed verifier"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        cls.changed_component_commit = subprocess.run(
            ["/usr/bin/git", "rev-parse", "HEAD"],
            cwd=cls.repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        changed_workflow = cls.repo / cls.workflow_path
        changed_workflow.write_text(
            changed_workflow.read_text(encoding="utf-8") + "changed workflow\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["/usr/bin/git", "add", cls.workflow_path],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "changed workflow"],
            cwd=cls.repo,
            check=True,
            timeout=10,
        )
        cls.changed_workflow_commit = subprocess.run(
            ["/usr/bin/git", "rev-parse", "HEAD"],
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
        self.source_commit = self.approved_commit
        self.workflow_commit = self.approved_commit
        self.control_digest = D("1")
        self.contract_digest = D("2")
        self.policy_digest = D("3")
        self.genesis_head = D("a")
        self.genesis_timestamp = "2026-07-11T11:00:00Z"
        self.snapshot = self._snapshot()
        self.snapshot_digest = jwks_snapshot_digest(self.snapshot)
        self.policy_result = self._policy_result()
        self.approval_result = {
            "status": "verified",
            "decision": "APPROVE",
            "approvalDigest": D("d"),
            "requestDigest": D("e"),
            "controlPlaneDigest": self.control_digest,
            "trustPolicyDigest": self.policy_digest,
            "workflowExecutionCommit": self.workflow_commit,
            "jwksSnapshotDigest": self.snapshot_digest,
            "componentDigests": deepcopy(self.approved_component_digests),
        }
        self.subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            contract_digest=self.contract_digest,
        )
        self.genesis_core = self._core("ACTIVE", D("4"), self.source_commit)
        self.genesis = self._genesis_anchor(self.genesis_core)

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
            "identity": "github-actions:test/state-chain",
            "organization": "github-actions",
            "role": "protected-workflow",
            "repository": "whyiug/agentapi-doctor",
            "repositoryId": "1296831403",
            "repositoryOwner": "whyiug",
            "repositoryOwnerId": "6668626",
            "repositoryVisibility": "public",
            "workflowPath": ".github/workflows/p00-protected-state-writer.yml",
            "workflowRef": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
            "eventName": "workflow_dispatch",
            "ref": "refs/heads/main",
            "refType": "branch",
            "refProtected": "true",
            "runnerEnvironment": "github-hosted",
            "allowedActorIds": ["6668626"],
        }
        return {
            "document": {"controlPlaneDigest": self.control_digest},
            "digest": self.policy_digest,
            "stateSigner": signer,
            "jwks": {"digest": self.snapshot_digest},
        }

    def _core(self, status: str, approval_digest: str, source_commit: str) -> dict:
        pending = status in {
            "MACHINE_CONVERGED",
            "BLOCKED",
            "WAITING_EXTERNAL",
            "REVIEW_PENDING",
        }
        active = status == "ACTIVE"
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01" if active else None,
            "pendingWorkUnit": "P00.W01" if pending else None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("5"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.source_commit,
                    "startedAt": self.genesis_timestamp,
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

    def _genesis_anchor(self, core: dict):
        view = {
            "schemaVersion": STATE_VIEW_SCHEMA,
            **deepcopy(core),
            "stateDigest": _state_core_digest(core),
            "attachments": [],
            "chain": {
                "eventCount": 1,
                "headSequence": 0,
                "headDigest": self.genesis_head,
            },
            "provenance": {
                "workflowRunId": "999",
                "workflowCheckRunId": "1999",
            },
        }
        event = {
            "body": {
                "timestamp": self.genesis_timestamp,
                "sourceCommit": self.source_commit,
            }
        }
        with mock.patch(
            "tools.phasegate.state_chain_v2.verify_genesis_event_v2",
            return_value=view,
        ) as verifier:
            anchor = verify_genesis_anchor_v2(
                event=event,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                jwks_snapshot=self.snapshot,
                expected_control_plane_digest=self.control_digest,
                expected_chain_head_digest=self.genesis_head,
                contract_digests={"unused": D("0")},
                repo_root=self.repo,
            )
        verifier.assert_called_once()
        return anchor

    def _claims(
        self,
        audience: str,
        timestamp: str,
        run: int,
        *,
        workflow_commit: str | None = None,
    ) -> dict:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        epoch = int(parsed.timestamp())
        expected = _expected_oidc_claims(
            self.policy_result,
            workflow_execution_commit=workflow_commit or self.workflow_commit,
        )
        return {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            **expected,
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "jti": f"state-chain-jti-{run}",
            "run_id": str(1000 + run),
            "run_number": str(run),
            "run_attempt": "1",
            "check_run_id": str(2000 + run),
            "nbf": epoch - 5,
            "iat": epoch,
            "exp": epoch + 300,
        }

    def _token(self, claims: dict) -> str:
        header = {
            "alg": "RS256",
            "kid": self.jwk["kid"],
            "typ": "JWT",
        }
        header_raw = json.dumps(
            header, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        claims_raw = json.dumps(
            claims, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signing_input = f"{b64url(header_raw)}.{b64url(claims_raw)}".encode("ascii")
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

    def _event(
        self,
        *,
        event_type: str,
        sequence: int,
        previous_digest: str,
        timestamp: str,
        source_commit: str,
        payload: dict,
        run: int,
    ) -> dict:
        payload = deepcopy(payload)
        payload.setdefault("chainHeadWitnessDigest", D("b"))
        claims_policy = _expected_oidc_claims(
            self.policy_result,
            workflow_execution_commit=source_commit,
        )
        body = {
            "eventType": event_type,
            "eventId": f"evt-{sequence:08d}",
            "sequence": sequence,
            "previousDigest": previous_digest,
            "timestamp": timestamp,
            "actor": {
                "principal": self.policy_result["stateSigner"]["identity"],
                "role": "protected-workflow",
                "organization": "github-actions",
            },
            "sourceCommit": source_commit,
            "controlPlaneDigest": self.control_digest,
            "trustPolicyDigest": self.policy_digest,
            "reasonCode": "test-protected-event",
            "reason": "Synthetic local chain-verifier fixture.",
            "writer": {
                "jwksSnapshotDigest": self.snapshot_digest,
                "claimsPolicyDigest": sha256_bytes(
                    canonical_json_bytes(claims_policy)
                ),
                "workflowPath": self.policy_result["stateSigner"]["workflowPath"],
                "workflowExecutionCommit": source_commit,
            },
            "payload": payload,
        }
        statement = {
            "schemaVersion": STATE_EVENT_SCHEMA,
            "kind": STATE_EVENT_KIND,
            "body": body,
        }
        statement_digest = sha256_bytes(canonical_json_bytes(statement))
        token = self._token(
            self._claims(
                OIDC_AUDIENCE_PREFIX + statement_digest,
                timestamp,
                run,
                workflow_commit=source_commit,
            )
        )
        envelope = {
            **statement,
            "signature": {
                "scheme": OIDC_SIGNATURE_SCHEME,
                "namespace": STATE_EVENT_NAMESPACE,
                "statementDigest": statement_digest,
                "jwt": token,
            },
            "eventDigest": D("0"),
        }
        envelope["eventDigest"] = document_digest(
            envelope, omit_field="eventDigest"
        )
        return envelope

    def _transition(self):
        return _mark_provenance_verified(
            VerifiedWorkUnitTransition(
                transition_type="CONVERGENCE",
                subject=self.subject,
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prior_state_digest=_state_core_digest(self.genesis_core),
                prior_chain_head_digest=self.genesis_head,
                proof_digest=D("6"),
                approval_digest=D("7"),
                evidence_digest=D("6"),
                criterion_result_digests=(D("8"),),
            )
        )

    def _transition_event(self, transition: VerifiedWorkUnitTransition):
        resulting = self._core(
            "MACHINE_CONVERGED",
            transition.approval_digest,
            transition.subject.source_commit,
        )
        payload = {
            "transitionType": transition.transition_type,
            "phase": transition.subject.phase,
            "workUnit": transition.subject.work_unit,
            "fromState": transition.from_state,
            "toState": transition.to_state,
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": transition.prior_chain_head_digest,
            "contractDigest": transition.subject.contract_digest,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "evidenceDigest": transition.evidence_digest,
            "criterionResultDigests": list(transition.criterion_result_digests),
            "resultingStateDigest": _state_core_digest(resulting),
        }
        return self._event(
            event_type="StateTransition",
            sequence=1,
            previous_digest=self.genesis_head,
            timestamp="2026-07-11T12:00:00Z",
            source_commit=self.source_commit,
            payload=payload,
            run=1,
        )

    def _provenance_bundle(self):
        signer = VerifiedSignerResult(
            scheme="github-actions-oidc-v1",
            namespace="test",
            principal="workflow@test.invalid",
            role="protected-workflow",
            organization="github-actions",
            statement_digest=D("1"),
            authority_digest=self.policy_digest,
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
        )
        criterion = CriterionBinding(
            criterion_id="C-MACHINE",
            kind="MACHINE",
            evaluator="evaluator://test/v1",
            evaluator_digest=D("9"),
            evidence_schema="evidence-schema://test/v1",
            evidence_schema_digest=D("a"),
            dataset_digest=D("b"),
            threshold_digest=D("c"),
        )
        freeze = _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("d"),
                statement_digest=D("e"),
                freeze_id="freeze-test",
                subject=self.subject,
                contract_approval_digest=D("f"),
                protected_inputs=(),
                criteria=(criterion,),
                signer=signer,
            )
        )
        result = _mark_provenance_verified(
            VerifiedCriterionResult(
                attestation_digest=D("8"),
                statement_digest=D("1"),
                result_id="result-test",
                freeze_digest=freeze.attestation_digest,
                subject=self.subject,
                criterion=criterion,
                outcome="PASS",
                evidence_digest=D("2"),
                run_pair_digest=D("2"),
                signature_verified=True,
                fact_status="not_applicable",
                criterion_satisfied=True,
                signer=signer,
            )
        )
        proof = _mark_provenance_verified(
            VerifiedTransitionProofResult(
                attestation_digest=D("6"),
                statement_digest=D("3"),
                proof_id="proof-test",
                freeze_digest=freeze.attestation_digest,
                subject=self.subject,
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prior_state_digest=_state_core_digest(self.genesis_core),
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
                attestation_digest=D("7"),
                statement_digest=D("4"),
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
        bundle = authorize_evidence_attachment_v2(
            freeze=freeze,
            criterion_results=[result],
            proof=proof,
            approval=approval,
        )
        return bundle, freeze, result, proof, approval

    def _attachment_event(
        self,
        bundle: VerifiedEvidenceAttachmentV2,
        *,
        previous_digest: str,
        state_digest: str,
        run: int = 2,
    ) -> dict:
        payload = {
            "phase": bundle.subject_phase,
            "workUnit": bundle.subject_work_unit,
            "priorStateDigest": state_digest,
            "priorChainHeadDigest": previous_digest,
            "contractDigest": bundle.contract_digest,
            "evidenceSourceCommit": bundle.source_commit,
            "freezeDigest": bundle.freeze_digest,
            "criterionResultDigests": list(bundle.criterion_result_digests),
            "proofDigest": bundle.proof_digest,
            "approvalDigest": bundle.approval_digest,
            "attachmentDigest": bundle.attachment_digest,
            "resultingStateDigest": state_digest,
        }
        return self._event(
            event_type="EvidenceAttachment",
            sequence=2,
            previous_digest=previous_digest,
            timestamp="2026-07-11T12:01:00Z",
            source_commit=bundle.source_commit,
            payload=payload,
            run=run,
        )

    def _replay(self, **kwargs):
        return replay_post_genesis_chain_v2(
            **kwargs,
            repo_root=self.repo,
            approved_component_digests=self.approved_component_digests,
        )

    def _assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_valid_transition_and_attachment_replay(self) -> None:
        transition = self._transition()
        transition_event = self._transition_event(transition)
        bundle, *_ = self._provenance_bundle()
        resulting_core = self._core("MACHINE_CONVERGED", D("7"), self.source_commit)
        attachment_event = self._attachment_event(
            bundle,
            previous_digest=transition_event["eventDigest"],
            state_digest=_state_core_digest(resulting_core),
        )
        attachment_projection = project_evidence_attachment_payload_v2(
            state_core=resulting_core,
            current_chain_head_digest=transition_event["eventDigest"],
            chain_head_witness_digest=D("b"),
            attachment=bundle,
        )
        self.assertEqual(
            verify_projected_evidence_attachment_v2(attachment_projection),
            attachment_event["body"]["payload"],
        )
        result = self._replay(
            genesis=self.genesis,
            events=[transition_event, attachment_event],
            verified_event_inputs=[transition, bundle],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=attachment_event["eventDigest"],
        )
        self.assertEqual(result.state_digest, _state_core_digest(resulting_core))
        self.assertEqual(result.head_sequence, 2)
        self.assertEqual(result.event_count, 3)
        self.assertEqual(len(result.attachments), 1)
        self.assertEqual(result.attachments[0]["freezeDigest"], bundle.freeze_digest)

    def test_main_forward_with_unchanged_components_activates_unique_pointer(self) -> None:
        activation_source = self.forward_commit
        activation_contract = D("9")
        core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("5"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.source_commit,
                    "startedAt": self.genesis_timestamp,
                    "workUnits": {
                        "P00.W01": {
                            "status": "CONVERGED",
                            "contractDigest": self.contract_digest,
                            "approvalDigest": D("7"),
                            "sourceCommit": self.source_commit,
                        },
                        "P00.W02": {
                            "status": "READY",
                            "contractDigest": activation_contract,
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }
        anchor = self._genesis_anchor(core)
        subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W02",
            source_commit=activation_source,
            control_plane_digest=self.control_digest,
            contract_digest=activation_contract,
        )
        transition = _mark_provenance_verified(
            VerifiedWorkUnitTransition(
                transition_type="ACTIVATION",
                subject=subject,
                from_state="READY",
                to_state="ACTIVE",
                prior_state_digest=_state_core_digest(core),
                prior_chain_head_digest=self.genesis_head,
                proof_digest=D("a"),
                approval_digest=D("b"),
                evidence_digest=D("a"),
                criterion_result_digests=(),
            )
        )
        resulting = deepcopy(core)
        resulting["activeWorkUnit"] = "P00.W02"
        resulting["phases"]["P00"]["workUnits"]["P00.W02"].update(
            {
                "status": "ACTIVE",
                "approvalDigest": transition.approval_digest,
                "sourceCommit": activation_source,
            }
        )
        payload = {
            "transitionType": "ACTIVATION",
            "phase": "P00",
            "workUnit": "P00.W02",
            "fromState": "READY",
            "toState": "ACTIVE",
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": self.genesis_head,
            "contractDigest": activation_contract,
            "proofDigest": transition.proof_digest,
            "approvalDigest": transition.approval_digest,
            "evidenceDigest": transition.evidence_digest,
            "criterionResultDigests": [],
            "resultingStateDigest": _state_core_digest(resulting),
        }
        event = self._event(
            event_type="StateTransition",
            sequence=1,
            previous_digest=self.genesis_head,
            timestamp="2026-07-11T12:00:00Z",
            source_commit=activation_source,
            payload=payload,
            run=30,
        )
        result = self._replay(
            genesis=anchor,
            events=[event],
            verified_event_inputs=[transition],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=event["eventDigest"],
        )
        self.assertEqual(result.state_core["activeWorkUnit"], "P00.W02")
        self.assertIsNone(result.state_core["pendingWorkUnit"])
        self.assertEqual(result.state_digest, _state_core_digest(resulting))

    def test_genesis_trust_substitution_and_nested_state_mutation_are_rejected(self) -> None:
        replaced_policy = deepcopy(self.policy_result)
        replaced_policy["digest"] = D("f")
        self._assert_error(
            "genesis_trust_binding_mismatch",
            self._replay,
            genesis=self.genesis,
            events=[],
            verified_event_inputs=[],
            policy_result=replaced_policy,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=self.genesis_head,
        )
        replaced_signer = deepcopy(self.policy_result)
        replaced_signer["stateSigner"]["identity"] = "github-actions:substituted"
        self._assert_error(
            "genesis_trust_binding_mismatch",
            self._replay,
            genesis=self.genesis,
            events=[],
            verified_event_inputs=[],
            policy_result=replaced_signer,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=self.genesis_head,
        )
        self.genesis.state_core["activeWorkUnit"] = None
        self._assert_error(
            "state_digest_mismatch",
            self._replay,
            genesis=self.genesis,
            events=[],
            verified_event_inputs=[],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=self.genesis_head,
        )

    def test_main_forward_with_changed_workflow_or_component_is_rejected(self) -> None:
        for run, changed_commit in enumerate(
            (self.changed_component_commit, self.changed_workflow_commit), start=31
        ):
            with self.subTest(commit=changed_commit):
                changed_subject = SubjectBinding(
                    phase="P00",
                    work_unit="P00.W01",
                    source_commit=changed_commit,
                    control_plane_digest=self.control_digest,
                    contract_digest=self.contract_digest,
                )
                transition = _mark_provenance_verified(
                    VerifiedWorkUnitTransition(
                        transition_type="CONVERGENCE",
                        subject=changed_subject,
                        from_state="ACTIVE",
                        to_state="MACHINE_CONVERGED",
                        prior_state_digest=_state_core_digest(self.genesis_core),
                        prior_chain_head_digest=self.genesis_head,
                        proof_digest=D("6"),
                        approval_digest=D("7"),
                        evidence_digest=D("6"),
                        criterion_result_digests=(D("8"),),
                    )
                )
                resulting = self._core("MACHINE_CONVERGED", D("7"), changed_commit)
                payload = {
                    "transitionType": "CONVERGENCE",
                    "phase": "P00",
                    "workUnit": "P00.W01",
                    "fromState": "ACTIVE",
                    "toState": "MACHINE_CONVERGED",
                    "priorStateDigest": transition.prior_state_digest,
                    "priorChainHeadDigest": transition.prior_chain_head_digest,
                    "contractDigest": self.contract_digest,
                    "proofDigest": transition.proof_digest,
                    "approvalDigest": transition.approval_digest,
                    "evidenceDigest": transition.evidence_digest,
                    "criterionResultDigests": list(
                        transition.criterion_result_digests
                    ),
                    "resultingStateDigest": _state_core_digest(resulting),
                }
                event = self._event(
                    event_type="StateTransition",
                    sequence=1,
                    previous_digest=self.genesis_head,
                    timestamp="2026-07-11T12:00:00Z",
                    source_commit=changed_commit,
                    payload=payload,
                    run=run,
                )
                self._assert_error(
                    "workflow_source_digest_mismatch",
                    self._replay,
                    genesis=self.genesis,
                    events=[event],
                    verified_event_inputs=[transition],
                    policy_result=self.policy_result,
                    approval_result=self.approval_result,
                    jwks_snapshot=self.snapshot,
                    expected_chain_head_digest=event["eventDigest"],
                )

    def test_external_head_pin_detects_truncation_and_is_required(self) -> None:
        transition = self._transition()
        event = self._transition_event(transition)
        arguments = {
            "genesis": self.genesis,
            "events": [event],
            "verified_event_inputs": [transition],
            "policy_result": self.policy_result,
            "approval_result": self.approval_result,
            "jwks_snapshot": self.snapshot,
        }
        self._assert_error(
            "chain_head_digest_mismatch",
            self._replay,
            **arguments,
            expected_chain_head_digest=self.genesis_head,
        )
        self._assert_error(
            "invalid_digest",
            self._replay,
            **arguments,
            expected_chain_head_digest=None,
        )

    def test_reorder_and_cross_kind_event_inputs_are_rejected(self) -> None:
        transition = self._transition()
        transition_event = self._transition_event(transition)
        bundle, *_ = self._provenance_bundle()
        resulting = self._core("MACHINE_CONVERGED", D("7"), self.source_commit)
        attachment_event = self._attachment_event(
            bundle,
            previous_digest=transition_event["eventDigest"],
            state_digest=_state_core_digest(resulting),
        )
        self._assert_error(
            "event_chain_discontinuity",
            self._replay,
            genesis=self.genesis,
            events=[attachment_event, transition_event],
            verified_event_inputs=[bundle, transition],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=transition_event["eventDigest"],
        )
        self._assert_error(
            "event_input_kind_mismatch",
            self._replay,
            genesis=self.genesis,
            events=[transition_event],
            verified_event_inputs=[bundle],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=transition_event["eventDigest"],
        )

    def test_transition_payload_source_and_proof_replay_are_rejected(self) -> None:
        transition = self._transition()
        for location, field, value in (
            ("payload", "proofDigest", D("f")),
            ("body", "sourceCommit", self.forward_commit),
            ("body", "controlPlaneDigest", D("f")),
        ):
            with self.subTest(field=field):
                event = self._transition_event(transition)
                if location == "payload":
                    event["body"]["payload"][field] = value
                else:
                    event["body"][field] = value
                if field == "sourceCommit":
                    claims_policy = _expected_oidc_claims(
                        self.policy_result,
                        workflow_execution_commit=value,
                    )
                    event["body"]["writer"]["workflowExecutionCommit"] = value
                    event["body"]["writer"]["claimsPolicyDigest"] = sha256_bytes(
                        canonical_json_bytes(claims_policy)
                    )
                event = self._resign_event(event, run=10)
                expected = (
                    "control_plane_digest_mismatch"
                    if field == "controlPlaneDigest"
                    else "transition_binding_mismatch"
                )
                self._assert_error(
                    expected,
                    self._replay,
                    genesis=self.genesis,
                    events=[event],
                    verified_event_inputs=[transition],
                    policy_result=self.policy_result,
                    approval_result=self.approval_result,
                    jwks_snapshot=self.snapshot,
                    expected_chain_head_digest=event["eventDigest"],
                )

    def _resign_event(self, event: dict, *, run: int) -> dict:
        statement = {
            "schemaVersion": event["schemaVersion"],
            "kind": event["kind"],
            "body": event["body"],
        }
        statement_digest = sha256_bytes(canonical_json_bytes(statement))
        event["signature"] = {
            "scheme": OIDC_SIGNATURE_SCHEME,
            "namespace": STATE_EVENT_NAMESPACE,
            "statementDigest": statement_digest,
            "jwt": self._token(
                self._claims(
                    OIDC_AUDIENCE_PREFIX + statement_digest,
                    event["body"]["timestamp"],
                    run,
                    workflow_commit=event["body"]["sourceCommit"],
                )
            ),
        }
        event["eventDigest"] = document_digest(event, omit_field="eventDigest")
        return event

    def test_attachment_cannot_mutate_state_or_consume_unverified_bundle(self) -> None:
        bundle, *_ = self._provenance_bundle()
        event = self._attachment_event(
            bundle,
            previous_digest=self.genesis_head,
            state_digest=_state_core_digest(self.genesis_core),
        )
        event["body"]["sequence"] = 1
        event["body"]["eventId"] = "evt-00000001"
        event["body"]["payload"]["resultingStateDigest"] = D("f")
        event = self._resign_event(event, run=20)
        self._assert_error(
            "attachment_state_mutation",
            self._replay,
            genesis=self.genesis,
            events=[event],
            verified_event_inputs=[bundle],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=event["eventDigest"],
        )
        clean = self._attachment_event(
            bundle,
            previous_digest=self.genesis_head,
            state_digest=_state_core_digest(self.genesis_core),
            run=21,
        )
        clean["body"]["sequence"] = 1
        clean["body"]["eventId"] = "evt-00000001"
        clean = self._resign_event(clean, run=21)
        self._assert_error(
            "unverified_internal_result",
            self._replay,
            genesis=self.genesis,
            events=[clean],
            verified_event_inputs=[deepcopy(bundle)],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=clean["eventDigest"],
        )

    def test_oidc_statement_tamper_and_workflow_run_replay_are_rejected(self) -> None:
        transition = self._transition()
        event = self._transition_event(transition)
        event["body"]["reason"] = "tampered after token issue"
        event["eventDigest"] = document_digest(event, omit_field="eventDigest")
        self._assert_error(
            "signature_binding_mismatch",
            self._replay,
            genesis=self.genesis,
            events=[event],
            verified_event_inputs=[transition],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=event["eventDigest"],
        )
        first = self._transition_event(transition)
        bundle, *_ = self._provenance_bundle()
        resulting = self._core("MACHINE_CONVERGED", D("7"), self.source_commit)
        second = self._attachment_event(
            bundle,
            previous_digest=first["eventDigest"],
            state_digest=_state_core_digest(resulting),
            run=1,
        )
        self._assert_error(
            "oidc_run_replay",
            self._replay,
            genesis=self.genesis,
            events=[first, second],
            verified_event_inputs=[transition, bundle],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=second["eventDigest"],
        )

    def test_nonempty_head_or_base_ref_claim_is_rejected(self) -> None:
        transition = self._transition()
        for claim_name in ("head_ref", "base_ref"):
            with self.subTest(claim=claim_name):
                event = self._transition_event(transition)
                statement_digest = event["signature"]["statementDigest"]
                claims = self._claims(
                    OIDC_AUDIENCE_PREFIX + statement_digest,
                    event["body"]["timestamp"],
                    40,
                    workflow_commit=event["body"]["sourceCommit"],
                )
                claims[claim_name] = "refs/heads/untrusted"
                event["signature"]["jwt"] = self._token(claims)
                event["eventDigest"] = document_digest(
                    event, omit_field="eventDigest"
                )
                self._assert_error(
                    "oidc_pull_request_ref_forbidden",
                    self._replay,
                    genesis=self.genesis,
                    events=[event],
                    verified_event_inputs=[transition],
                    policy_result=self.policy_result,
                    approval_result=self.approval_result,
                    jwks_snapshot=self.snapshot,
                    expected_chain_head_digest=event["eventDigest"],
                )

    def test_evidence_authorization_rejects_copied_provenance(self) -> None:
        _, freeze, result, proof, approval = self._provenance_bundle()
        self._assert_error(
            "unverified_internal_result",
            authorize_evidence_attachment_v2,
            freeze=deepcopy(freeze),
            criterion_results=[result],
            proof=proof,
            approval=approval,
        )
        self._assert_error(
            "unverified_internal_result",
            authorize_evidence_attachment_v2,
            freeze=freeze,
            criterion_results=[deepcopy(result)],
            proof=proof,
            approval=approval,
        )

    def test_lifecycle_block_and_resume_replay_updates_only_sealed_pointers(self) -> None:
        blocked = _mark_provenance_verified(
            VerifiedLifecycleTransition(
                transition_type="INVALIDATION",
                subject=self.subject,
                from_state="ACTIVE",
                to_state="BLOCKED",
                prior_state_digest=_state_core_digest(self.genesis_core),
                prior_chain_head_digest=self.genesis_head,
                contract_approval_digest=D("d"),
                impact_map_digest=D("e"),
                prerequisites=(),
                reason_code="test-protected-event",
                reason="Synthetic local chain-verifier fixture.",
                blocker_resolution_digest=None,
                invalidation_kind="CONTROL",
                invalidation_digest=D("c"),
                proof_digest=D("6"),
                approval_digest=D("7"),
            )
        )
        blocked_core = self._core("BLOCKED", D("7"), self.source_commit)
        blocked_payload = {
            "transitionType": blocked.transition_type,
            "phase": blocked.subject.phase,
            "workUnit": blocked.subject.work_unit,
            "fromState": blocked.from_state,
            "toState": blocked.to_state,
            "priorStateDigest": blocked.prior_state_digest,
            "priorChainHeadDigest": blocked.prior_chain_head_digest,
            "contractDigest": blocked.subject.contract_digest,
            "contractApprovalDigest": blocked.contract_approval_digest,
            "impactMapDigest": blocked.impact_map_digest,
            "prerequisites": [],
            "blockerResolutionDigest": None,
            "invalidationKind": "CONTROL",
            "invalidationDigest": D("c"),
            "proofDigest": D("6"),
            "approvalDigest": D("7"),
            "chainHeadWitnessDigest": D("b"),
            "resultingStateDigest": _state_core_digest(blocked_core),
        }
        projection = project_state_transition_payload_v2(
            state_core=self.genesis_core,
            current_chain_head_digest=self.genesis_head,
            chain_head_witness_digest=D("b"),
            transition=blocked,
        )
        projected_payload, projected_core = verify_projected_state_transition_v2(
            projection
        )
        self.assertEqual(projected_payload, blocked_payload)
        self.assertEqual(projected_core, blocked_core)
        self._assert_error(
            "unverified_internal_result",
            verify_projected_state_transition_v2,
            deepcopy(projection),
        )
        mutated_projection = project_state_transition_payload_v2(
            state_core=self.genesis_core,
            current_chain_head_digest=self.genesis_head,
            chain_head_witness_digest=D("b"),
            transition=blocked,
        )
        mutated_projection.payload["proofDigest"] = D("0")
        self._assert_error(
            "projected_transition_mutated",
            verify_projected_state_transition_v2,
            mutated_projection,
        )
        first = self._event(
            event_type="StateTransition",
            sequence=1,
            previous_digest=self.genesis_head,
            timestamp="2026-07-11T12:00:00Z",
            source_commit=self.source_commit,
            payload=blocked_payload,
            run=31,
        )
        incremental = verify_next_event_v2(
            current=self.genesis,
            event=first,
            verified_event_input=blocked,
            expected_chain_head_witness_digest=D("b"),
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            approved_component_digests=self.approved_component_digests,
        )
        self.assertEqual(incremental.head_digest, first["eventDigest"])
        self.assertEqual(incremental.head_source_commit, self.source_commit)
        self.assertIs(require_verified_state_context_v2(incremental), incremental)
        self._assert_error(
            "unverified_internal_result",
            require_verified_state_context_v2,
            deepcopy(incremental),
        )
        substituted = deepcopy(self.approval_result)
        substituted["approvalDigest"] = D("0")
        self._assert_error(
            "genesis_trust_binding_mismatch",
            verify_next_event_v2,
            current=self.genesis,
            event=first,
            verified_event_input=blocked,
            expected_chain_head_witness_digest=D("b"),
            policy_result=self.policy_result,
            approval_result=substituted,
            jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            approved_component_digests=self.approved_component_digests,
        )
        resumed = _mark_provenance_verified(
            VerifiedLifecycleTransition(
                transition_type="RESUME",
                subject=self.subject,
                from_state="BLOCKED",
                to_state="ACTIVE",
                prior_state_digest=_state_core_digest(blocked_core),
                prior_chain_head_digest=first["eventDigest"],
                contract_approval_digest=D("d"),
                impact_map_digest=D("e"),
                prerequisites=(),
                reason_code="test-protected-event",
                reason="Synthetic local chain-verifier fixture.",
                blocker_resolution_digest=D("c"),
                invalidation_kind=None,
                invalidation_digest=None,
                proof_digest=D("8"),
                approval_digest=D("9"),
            )
        )
        resumed_core = self._core("ACTIVE", D("9"), self.source_commit)
        resumed_payload = {
            "transitionType": resumed.transition_type,
            "phase": resumed.subject.phase,
            "workUnit": resumed.subject.work_unit,
            "fromState": resumed.from_state,
            "toState": resumed.to_state,
            "priorStateDigest": resumed.prior_state_digest,
            "priorChainHeadDigest": resumed.prior_chain_head_digest,
            "contractDigest": resumed.subject.contract_digest,
            "contractApprovalDigest": resumed.contract_approval_digest,
            "impactMapDigest": resumed.impact_map_digest,
            "prerequisites": [],
            "blockerResolutionDigest": D("c"),
            "invalidationKind": None,
            "invalidationDigest": None,
            "proofDigest": D("8"),
            "approvalDigest": D("9"),
            "chainHeadWitnessDigest": D("b"),
            "resultingStateDigest": _state_core_digest(resumed_core),
        }
        second = self._event(
            event_type="StateTransition",
            sequence=2,
            previous_digest=first["eventDigest"],
            timestamp="2026-07-11T13:00:00Z",
            source_commit=self.source_commit,
            payload=resumed_payload,
            run=32,
        )
        result = self._replay(
            genesis=self.genesis,
            events=[first, second],
            verified_event_inputs=[blocked, resumed],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=second["eventDigest"],
        )
        self.assertEqual(result.state_core["activeWorkUnit"], "P00.W01")
        self.assertIsNone(result.state_core["pendingWorkUnit"])
        self.assertEqual(
            result.head_timestamp,
            datetime(2026, 7, 11, 13, 0, 0, tzinfo=timezone.utc),
        )
        self._assert_error(
            "unverified_internal_result",
            self._replay,
            genesis=self.genesis,
            events=[first],
            verified_event_inputs=[deepcopy(blocked)],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=first["eventDigest"],
        )

    def test_phase_aggregate_replay_never_creates_a_work_unit_pointer(self) -> None:
        contracts = [D(character) for character in "24678"]
        core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("5"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.source_commit,
                    "startedAt": self.genesis_timestamp,
                    "workUnits": {
                        f"P00.W0{index}": {
                            "status": "CONVERGED",
                            "contractDigest": contracts[index - 1],
                            "approvalDigest": D("f"),
                            "sourceCommit": self.source_commit,
                        }
                        for index in range(1, 6)
                    },
                }
            },
        }
        genesis = self._genesis_anchor(core)
        units = tuple(
            PhaseUnitStateBinding(
                work_unit=f"P00.W0{index}",
                status="CONVERGED",
                contract_digest=contracts[index - 1],
                source_commit=self.source_commit,
                approval_digest=D("f"),
            )
            for index in range(1, 6)
        )
        transition = _mark_provenance_verified(
            VerifiedPhaseTransition(
                transition_type="PHASE_AGGREGATE",
                subject=PhaseSubject(
                    phase="P00",
                    source_commit=self.source_commit,
                    control_plane_digest=self.control_digest,
                    aggregate_contract_digest=D("5"),
                ),
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prior_state_digest=_state_core_digest(core),
                prior_chain_head_digest=self.genesis_head,
                freeze_digest=D("6"),
                proof_digest=D("7"),
                approval_digest=D("8"),
                go_nogo_authorization_digest=None,
                evidence_digest=D("7"),
                criterion_result_digests=(D("9"),),
                unit_states=units,
            )
        )
        resulting = deepcopy(core)
        resulting["activePhase"] = None
        resulting["phases"]["P00"]["status"] = "MACHINE_CONVERGED"
        resulting["phases"]["P00"]["sourceCommit"] = self.source_commit
        resulting["phases"]["P00"]["approvalDigest"] = D("8")
        payload = {
            "transitionType": "PHASE_AGGREGATE",
            "phase": "P00",
            "fromState": "ACTIVE",
            "toState": "MACHINE_CONVERGED",
            "priorStateDigest": transition.prior_state_digest,
            "priorChainHeadDigest": transition.prior_chain_head_digest,
            "aggregateContractDigest": D("5"),
            "freezeDigest": D("6"),
            "proofDigest": D("7"),
            "approvalDigest": D("8"),
            "goNoGoAuthorizationDigest": None,
            "evidenceDigest": D("7"),
            "criterionResultDigests": [D("9")],
            "unitStates": [
                {
                    "workUnit": unit.work_unit,
                    "status": unit.status,
                    "contractDigest": unit.contract_digest,
                    "sourceCommit": unit.source_commit,
                    "approvalDigest": unit.approval_digest,
                }
                for unit in units
            ],
            "chainHeadWitnessDigest": D("b"),
            "resultingStateDigest": _state_core_digest(resulting),
        }
        projection = project_state_transition_payload_v2(
            state_core=core,
            current_chain_head_digest=self.genesis_head,
            chain_head_witness_digest=D("b"),
            transition=transition,
        )
        projected_payload, projected_core = verify_projected_state_transition_v2(
            projection
        )
        self.assertEqual(projected_payload, payload)
        self.assertEqual(projected_core, resulting)
        event = self._event(
            event_type="StateTransition",
            sequence=1,
            previous_digest=self.genesis_head,
            timestamp="2026-07-11T12:00:00Z",
            source_commit=self.source_commit,
            payload=payload,
            run=33,
        )
        result = self._replay(
            genesis=genesis,
            events=[event],
            verified_event_inputs=[transition],
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            jwks_snapshot=self.snapshot,
            expected_chain_head_digest=event["eventDigest"],
        )
        self.assertEqual(result.state_core["phases"]["P00"]["status"], "MACHINE_CONVERGED")
        self.assertIsNone(result.state_core["activePhase"])
        self.assertIsNone(result.state_core["activeWorkUnit"])
        self.assertIsNone(result.state_core["pendingWorkUnit"])

    def test_converged_phase_cannot_retain_a_rejected_work_unit(self) -> None:
        core = self._core("CONVERGED", D("4"), self.source_commit)
        core["activePhase"] = None
        core["phases"]["P00"]["status"] = "CONVERGED"
        _validate_state_invariants(core)

        core["phases"]["P00"]["workUnits"]["P00.W01"]["status"] = "REJECTED"
        with self.assertRaises(ProtectedVerificationError) as caught:
            _validate_state_invariants(core)
        self.assertEqual(
            caught.exception.code, "phase_unit_convergence_mismatch"
        )


if __name__ == "__main__":
    unittest.main()
