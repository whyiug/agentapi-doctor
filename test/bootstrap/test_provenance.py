"""Adversarial tests for protected convergence provenance."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.protected import (  # noqa: E402
    ALLOWED_TRANSITIONS,
    APPROVAL_NAMESPACE,
    POLICY_KIND,
    POLICY_SCHEMA,
    STATE_EVENT_NAMESPACE,
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
    trusted_ssh_keygen_digest,
)
from tools.phasegate.sshsig import verify_sshsig  # noqa: E402
from tools.phasegate.provenance import (  # noqa: E402
    ACTIVATION_APPROVAL_KIND,
    ACTIVATION_APPROVAL_NAMESPACE,
    ACTIVATION_APPROVAL_SCHEMA,
    ACTIVATION_PROOF_KIND,
    ACTIVATION_PROOF_NAMESPACE,
    ACTIVATION_PROOF_SCHEMA,
    CRITERION_KIND,
    CRITERION_NAMESPACES,
    CRITERION_SCHEMA,
    FREEZE_KIND,
    FREEZE_NAMESPACE,
    FREEZE_SCHEMA,
    LIFECYCLE_APPROVAL_KIND,
    LIFECYCLE_APPROVAL_NAMESPACE,
    LIFECYCLE_APPROVAL_SCHEMA,
    LIFECYCLE_PROOF_KIND,
    LIFECYCLE_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_SCHEMA,
    PHASE_APPROVAL_KIND,
    PHASE_APPROVAL_NAMESPACE,
    PHASE_APPROVAL_SCHEMA,
    PHASE_CRITERION_KIND,
    PHASE_CRITERION_NAMESPACES,
    PHASE_CRITERION_SCHEMA,
    PHASE_FREEZE_KIND,
    PHASE_FREEZE_NAMESPACE,
    PHASE_FREEZE_SCHEMA,
    PHASE_GO_NOGO_KIND,
    PHASE_GO_NOGO_NAMESPACE,
    PHASE_GO_NOGO_SCHEMA,
    PHASE_PROOF_KIND,
    PHASE_PROOF_NAMESPACE,
    PHASE_PROOF_SCHEMA,
    PROOF_KIND,
    PROOF_NAMESPACE,
    PROOF_SCHEMA,
    TRANSITION_APPROVAL_KIND,
    TRANSITION_APPROVAL_NAMESPACE,
    TRANSITION_APPROVAL_SCHEMA,
    SubjectBinding,
    PhaseSubject,
    VerifiedSignerResult,
    authorize_activation_transition,
    authorize_convergence_transition,
    authorize_lifecycle_transition,
    authorize_phase_transition,
    verify_activation_approval,
    verify_activation_proof,
    verify_criterion_authorization,
    verify_signed_criterion_result,
    verify_signed_phase_criterion_result,
    verify_signed_phase_protected_input_freeze,
    verify_signed_protected_input_freeze,
    verify_ssh_reviewer_signature,
    verify_transition_approval,
    verify_lifecycle_approval,
    verify_lifecycle_proof,
    verify_phase_go_nogo_authorization,
    verify_phase_state_context,
    verify_phase_transition_approval,
    verify_phase_transition_proof,
    verify_verified_transition_proof,
    verify_work_unit_state_context,
)


FIXED_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
D = lambda character: "sha256:" + character * 64  # noqa: E731


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is required")
class ProtectedProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="phasegate-provenance-")
        cls.root = Path(cls.temporary.name)
        cls.counter = 0
        cls.reviewer_key = cls._generate_key("reviewer")
        cls.workflow_key = cls._generate_key("workflow")
        cls.external_key = cls._generate_key("external")
        cls.maintainer_key = cls._generate_key("maintainer")
        _, cls.ssh_keygen_digest = trusted_ssh_keygen_digest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _generate_key(cls, name: str) -> Path:
        path = cls.root / name
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
                str(path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return path

    @classmethod
    def _public_key(cls, key: Path) -> str:
        return " ".join(key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])

    @classmethod
    def _sign(cls, payload: bytes, key: Path, namespace: str) -> str:
        cls.counter += 1
        message = cls.root / f"message-{cls.counter:05d}.json"
        message.write_bytes(payload)
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                namespace,
                str(message),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        signature_path = Path(str(message) + ".sig")
        value = signature_path.read_text(encoding="utf-8")
        signature_path.unlink()
        message.unlink()
        return value

    def setUp(self) -> None:
        self.subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit="a" * 40,
            control_plane_digest=D("1"),
            contract_digest=D("2"),
        )
        self.policy = self._policy()
        self.policy_digest = document_digest(self.policy)
        self.inputs = {
            "planDigest": D("3"),
            "supportLockDigest": D("4"),
            "toolchainDigest": D("5"),
            "dependencySetDigest": D("6"),
            "gateRunnerDigest": D("7"),
            "evaluatorSetDigest": D("8"),
            "metricDefinitionsDigest": D("9"),
            "protectedAcceptanceDigest": D("a"),
        }
        self.criteria = [
            self._criterion("C-HUMAN", "HUMAN", "b"),
            self._criterion("C-MACHINE", "MACHINE", "c"),
            self._criterion("C-X", "EXTERNAL", "d"),
        ]
        self.freeze_doc = self._freeze(self.criteria)
        self.freeze = self._verify_freeze(self.freeze_doc, self.criteria)
        self.machine_doc = self._criterion_result(self.criteria[1])
        self.machine = self._verify_machine(self.machine_doc, self.freeze)
        self.active_context = self._state_context("ACTIVE")

    def _principal(self, identity: str, role: str, capability: str, key: Path, org: str) -> dict:
        public_key = self._public_key(key)
        return {
            "identity": identity,
            "organization": org,
            "role": role,
            "publicKey": public_key,
            "fingerprint": _ssh_public_key_fingerprint(public_key, identity),
            "capabilities": [capability],
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2027-01-01T00:00:00Z",
        }

    def _policy(self) -> dict:
        return {
            "schemaVersion": POLICY_SCHEMA,
            "kind": POLICY_KIND,
            "policyId": "P00-protected-verifier",
            "revision": 1,
            "policyStatus": "configured",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "signatureScheme": {
                "type": "openssh-sshsig-v1",
                "allowedKeyTypes": ["ssh-ed25519"],
                "approvalNamespace": APPROVAL_NAMESPACE,
                "stateEventNamespace": STATE_EVENT_NAMESPACE,
            },
            "thresholds": {"controlPlaneApproval": 1, "stateEvent": 1},
            "separationOfDuties": {
                "distinctPrincipals": True,
                "distinctKeys": True,
                "distinctOrganizations": True,
                "approvalRole": "independent-reviewer",
                "stateEventRole": "protected-workflow",
            },
            "principals": [
                self._principal(
                    "reviewer@test.invalid",
                    "independent-reviewer",
                    "approve-control-plane",
                    self.reviewer_key,
                    "review-test",
                ),
                self._principal(
                    "workflow@test.invalid",
                    "protected-workflow",
                    "sign-state-event",
                    self.workflow_key,
                    "workflow-test",
                ),
            ],
            "revokedFingerprints": [],
            "requiredExternalPins": [
                "trustPolicyDigest",
                "controlPlaneDigest",
                "candidateSourceCommit",
                "requestDigest",
                "chainHeadDigest",
                "sshKeygenDigest",
            ],
            "allowedTransitions": {
                key: list(value) for key, value in ALLOWED_TRANSITIONS.items()
            },
        }

    def _criterion(self, criterion_id: str, kind: str, character: str) -> dict:
        evaluator_prefix = "evaluator" if kind == "MACHINE" else "attestation"
        alphabet = "0123456789abcdef"
        start = alphabet.index(character)
        return {
            "id": criterion_id,
            "kind": kind,
            "evaluator": f"{evaluator_prefix}://test/{criterion_id.lower()}/v1",
            "evaluatorDigest": D(character),
            "evaluatorStatus": {
                "MACHINE": "implemented",
                "HUMAN": "human-only",
                "EXTERNAL": "external-only",
                "TIME": "time-only",
            }[kind],
            "evidenceSchema": f"evidence-schema://test/{criterion_id.lower()}/v1",
            "evidenceSchemaDigest": D(alphabet[(start + 1) % len(alphabet)]),
            "datasetDigest": D(alphabet[(start + 2) % len(alphabet)]),
            "thresholdDigest": D(alphabet[(start + 3) % len(alphabet)]),
        }

    def _subject(self, subject: SubjectBinding | None = None) -> dict:
        value = subject or self.subject
        return {
            "phase": value.phase,
            "workUnit": value.work_unit,
            "sourceCommit": value.source_commit,
            "controlPlaneDigest": value.control_plane_digest,
            "contractDigest": value.contract_digest,
        }

    def _state_core(self, status: str) -> dict:
        pending = status in {
            "MACHINE_CONVERGED",
            "BLOCKED",
            "WAITING_EXTERNAL",
            "REVIEW_PENDING",
        }
        active = status == "ACTIVE"
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01" if active else None,
            "pendingWorkUnit": "P00.W01" if pending else None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("1"),
                    "controlPlaneDigest": self.subject.control_plane_digest,
                    "baseCommit": self.subject.source_commit,
                    "startedAt": "2026-07-11T09:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": status,
                            "contractDigest": self.subject.contract_digest,
                            "approvalDigest": D("f"),
                            "sourceCommit": self.subject.source_commit,
                        },
                        "P00.W02": {
                            "status": "NOT_STARTED",
                            "contractDigest": D("4"),
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }

    def _state_context(self, status: str):
        core = self._state_core(status)
        return verify_work_unit_state_context(
            core,
            expected_state_digest=document_digest(core),
            expected_chain_head_digest=D("b"),
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            work_unit="P00.W01",
            expected_status=status,
            expected_contract_digest=self.subject.contract_digest,
        )

    def _activation_target(self) -> SubjectBinding:
        return SubjectBinding(
            phase="P00",
            work_unit="P00.W02",
            source_commit="b" * 40,
            control_plane_digest=self.subject.control_plane_digest,
            contract_digest=D("4"),
        )

    def _activation_state_context(self, *, chain_head: str = D("b")):
        core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "activePhase": "P00",
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("1"),
                    "controlPlaneDigest": self.subject.control_plane_digest,
                    "baseCommit": self.subject.source_commit,
                    "startedAt": "2026-07-11T09:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": "CONVERGED",
                            "contractDigest": self.subject.contract_digest,
                            "approvalDigest": D("f"),
                            "sourceCommit": self.subject.source_commit,
                        },
                        "P00.W02": {
                            "status": "READY",
                            "contractDigest": D("4"),
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }
        return verify_work_unit_state_context(
            core,
            expected_state_digest=document_digest(core),
            expected_chain_head_digest=chain_head,
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            work_unit="P00.W02",
            expected_status="READY",
            expected_contract_digest=D("4"),
            prerequisite_units=["P00.W01"],
        )

    def _actor(self, role: str) -> dict:
        if role == "independent-reviewer":
            return {
                "principal": "reviewer@test.invalid",
                "role": role,
                "organization": "review-test",
            }
        if role == "protected-workflow":
            return {
                "principal": "workflow@test.invalid",
                "role": role,
                "organization": "workflow-test",
            }
        if role == "authorized-maintainer":
            return {
                "principal": "maintainer@test.invalid",
                "role": role,
                "organization": "maintainer-test",
            }
        if role == "independent-external-reviewer":
            return {
                "principal": "external-reviewer@test.invalid",
                "role": role,
                "organization": "external-review-test",
            }
        return {
            "principal": "external@test.invalid",
            "role": role,
            "organization": "external-test",
        }

    def _envelope(
        self,
        schema: str,
        kind: str,
        body: dict,
        key: Path,
        namespace: str,
        principal: str,
    ) -> dict:
        core = {"schemaVersion": schema, "kind": kind, "body": body}
        signature = {
            "scheme": "openssh-sshsig-v1",
            "namespace": namespace,
            "principal": principal,
            "value": self._sign(canonical_json_bytes(core), key, namespace),
        }
        envelope = {**core, "signature": signature, "attestationDigest": D("0")}
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    def _resign(
        self, document: dict, key: Path, namespace: str, principal: str
    ) -> dict:
        return self._envelope(
            document["schemaVersion"], document["kind"], document["body"], key, namespace, principal
        )

    def _freeze(self, criteria: list[dict], inputs: dict | None = None) -> dict:
        return self._envelope(
            FREEZE_SCHEMA,
            FREEZE_KIND,
            {
                "freezeId": "freeze-P00.W01-001",
                "subject": self._subject(),
                "contractApprovalDigest": D("f"),
                "protectedInputs": inputs or self.inputs,
                "criteria": criteria,
                "issuedAt": "2026-07-11T10:00:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            FREEZE_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _reviewer_result(self, document: dict, namespace: str) -> VerifiedSignerResult:
        payload = canonical_json_bytes(
            {
                "schemaVersion": document["schemaVersion"],
                "kind": document["kind"],
                "body": document["body"],
            }
        )
        verify_ssh_reviewer_signature(
            payload,
            document["signature"]["value"],
            self._public_key(self.reviewer_key),
            namespace,
        )
        return VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=namespace,
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest=sha256_bytes(payload),
            authority_digest=self.policy_digest,
            source_commit=document["body"]["subject"]["sourceCommit"],
            control_plane_digest=document["body"]["subject"]["controlPlaneDigest"],
        )

    def _verify_freeze(self, document: dict, criteria: list[dict], inputs: dict | None = None):
        signer = self._reviewer_result(document, FREEZE_NAMESPACE)
        return verify_signed_protected_input_freeze(
            document,
            expected_subject=self.subject,
            expected_contract_approval_digest=D("f"),
            expected_protected_inputs=inputs or self.inputs,
            expected_criteria=criteria,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
        )

    def _external_signer_callback(
        self,
        *,
        key: Path,
        principal: str,
        role: str,
        organization: str,
    ):
        public_key = self._public_key(key)

        def verify(payload: bytes, signature: dict, namespace: str) -> VerifiedSignerResult:
            verify_sshsig(
                payload=payload,
                armored_signature=signature["value"],
                public_key=public_key,
                expected_namespace=namespace,
            )
            body = json.loads(payload)["body"]
            return VerifiedSignerResult(
                scheme="openssh-sshsig-v1",
                namespace=namespace,
                principal=principal,
                role=role,
                organization=organization,
                statement_digest=sha256_bytes(payload),
                authority_digest=self.policy_digest,
                source_commit=body["subject"]["sourceCommit"],
                control_plane_digest=body["subject"]["controlPlaneDigest"],
            )

        return verify

    def _workflow_callback(self, role: str = "protected-workflow"):
        return self._external_signer_callback(
            key=self.workflow_key,
            principal="workflow@test.invalid",
            role=role,
            organization="workflow-test",
        )

    def _run(self, label: str, criterion: dict) -> dict:
        run = {
            "label": label,
            "environmentClass": (
                "development-isolated" if label == "A" else "clean-checkout-offline"
            ),
            "environmentDigest": D("1" if label == "A" else "2"),
            "sourceCommit": self.subject.source_commit,
            "controlPlaneDigest": self.subject.control_plane_digest,
            "contractDigest": self.subject.contract_digest,
            "planDigest": self.inputs["planDigest"],
            "supportLockDigest": self.inputs["supportLockDigest"],
            "dependencySetDigest": self.inputs["dependencySetDigest"],
            "toolchainDigest": self.inputs["toolchainDigest"],
            "gateRunnerDigest": self.inputs["gateRunnerDigest"],
            "evaluatorSetDigest": self.inputs["evaluatorSetDigest"],
            "metricDefinitionsDigest": self.inputs["metricDefinitionsDigest"],
            "protectedAcceptanceDigest": self.inputs["protectedAcceptanceDigest"],
            "evaluatorDigest": criterion["evaluatorDigest"],
            "datasetDigest": criterion["datasetDigest"],
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "startedAt": "2026-07-11T10:00:00Z",
            "finishedAt": "2026-07-11T10:01:00Z",
            "commands": [
                {
                    "command": "make test-bootstrap",
                    "exitCode": 0,
                    "durationMs": 60000,
                    "summary": {"passed": 14, "failed": 0, "skipped": 0},
                    "logDigest": D("b"),
                    "artifactManifestDigest": D("c"),
                }
            ],
            "deterministicResultSetDigest": D("e"),
            "runEvidenceDigest": D("0"),
        }
        run["runEvidenceDigest"] = document_digest(run, omit_field="runEvidenceDigest")
        return run

    def _criterion_result(
        self, criterion: dict, *, subject: dict | None = None, freeze=None
    ) -> dict:
        kind = criterion["kind"]
        if kind == "MACHINE":
            pair = {
                "verificationPairId": "pair-P00.W01-001",
                "runA": self._run("A", criterion),
                "runB": self._run("B", criterion),
            }
            pair_digest = document_digest(pair)
            role, key, principal, outcome = (
                "protected-workflow",
                self.workflow_key,
                "workflow@test.invalid",
                "PASS",
            )
            evidence_digest = pair_digest
        elif kind == "HUMAN":
            pair = pair_digest = None
            role, key, principal, outcome = (
                "independent-reviewer",
                self.reviewer_key,
                "reviewer@test.invalid",
                "APPROVE",
            )
            evidence_digest = D("f")
        else:
            pair = pair_digest = None
            role = "external-attestor" if kind == "EXTERNAL" else "time-attestor"
            key, principal, outcome = self.external_key, "external@test.invalid", "ATTESTED"
            evidence_digest = D("f")
        return self._envelope(
            CRITERION_SCHEMA,
            CRITERION_KIND,
            {
                "resultId": "result-" + criterion["id"],
                "freezeDigest": (freeze or self.freeze).attestation_digest,
                "subject": subject or self._subject(),
                "criterion": criterion,
                "outcome": outcome,
                "evidenceDigest": evidence_digest,
                "runPair": pair,
                "runPairDigest": pair_digest,
                "humanReview": (
                    {
                        "reason": "The exact criterion evidence is approved.",
                        "conflictOfInterest": {
                            "independent": True,
                            "statement": "Independent test reviewer.",
                        },
                    }
                    if kind == "HUMAN"
                    else None
                ),
                "issuedAt": "2026-07-11T10:30:00Z",
                "actor": self._actor(role),
                "authorityDigest": self.policy_digest,
            },
            key,
            CRITERION_NAMESPACES[kind],
            principal,
        )

    def _verify_machine(self, document: dict, freeze):
        return verify_signed_criterion_result(
            document,
            freeze=freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )

    def _proof(
        self, results, context=None, to_state="MACHINE_CONVERGED"
    ) -> dict:
        state_context = context or self.active_context
        projection = [
            {
                "criterionId": result.criterion.criterion_id,
                "kind": result.criterion.kind,
                "resultDigest": result.attestation_digest,
                "evidenceDigest": result.evidence_digest,
            }
            for result in sorted(results, key=lambda item: item.criterion.criterion_id)
        ]
        return self._envelope(
            PROOF_SCHEMA,
            PROOF_KIND,
            {
                "proofId": "proof-P00.W01-001",
                "freezeDigest": self.freeze.attestation_digest,
                "subject": self._subject(),
                "fromState": state_context.status,
                "toState": to_state,
                "priorStateDigest": state_context.state_digest,
                "priorChainHeadDigest": state_context.chain_head_digest,
                "criterionResults": projection,
                "issuedAt": "2026-07-11T11:00:00Z",
                "actor": self._actor("protected-workflow"),
                "authorityDigest": self.policy_digest,
            },
            self.workflow_key,
            PROOF_NAMESPACE,
            "workflow@test.invalid",
        )

    def _verify_proof(
        self, document: dict, results, context=None, to_state="MACHINE_CONVERGED"
    ):
        state_context = context or self.active_context
        return verify_verified_transition_proof(
            document,
            freeze=self.freeze,
            criterion_results=results,
            state_context=state_context,
            expected_to_state=to_state,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )

    def _approval(self, proof) -> dict:
        projection = [
            {
                "criterionId": item[0],
                "kind": item[1],
                "resultDigest": item[2],
                "evidenceDigest": item[3],
            }
            for item in proof.criterion_results
        ]
        return self._envelope(
            TRANSITION_APPROVAL_SCHEMA,
            TRANSITION_APPROVAL_KIND,
            {
                "approvalId": "approval-P00.W01-001",
                "proofDigest": proof.attestation_digest,
                "freezeDigest": proof.freeze_digest,
                "subject": self._subject(),
                "fromState": proof.from_state,
                "toState": proof.to_state,
                "priorStateDigest": proof.prior_state_digest,
                "priorChainHeadDigest": proof.prior_chain_head_digest,
                "criterionResults": projection,
                "decision": "APPROVE",
                "reason": "Exact machine convergence proof reviewed.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent test reviewer.",
                },
                "issuedAt": "2026-07-11T11:30:00Z",
                "validUntil": "2026-07-12T11:30:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            TRANSITION_APPROVAL_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _activation_proof(self, context, target: SubjectBinding | None = None) -> dict:
        subject = target or self._activation_target()
        return self._envelope(
            ACTIVATION_PROOF_SCHEMA,
            ACTIVATION_PROOF_KIND,
            {
                "proofId": "activation-proof-P00.W02-001",
                "subject": self._subject(subject),
                "fromState": "READY",
                "toState": "ACTIVE",
                "priorStateDigest": context.state_digest,
                "priorChainHeadDigest": context.chain_head_digest,
                "contractApprovalDigest": D("d"),
                "impactMapDigest": D("e"),
                "prerequisites": [
                    {
                        "phase": item.phase,
                        "workUnit": item.work_unit,
                        "status": item.status,
                        "stateDigest": item.state_digest,
                        "contractDigest": item.contract_digest,
                        "sourceCommit": item.source_commit,
                        "approvalDigest": item.approval_digest,
                    }
                    for item in context.prerequisites
                ],
                "issuedAt": "2026-07-11T11:00:00Z",
                "actor": self._actor("protected-workflow"),
                "authorityDigest": self.policy_digest,
            },
            self.workflow_key,
            ACTIVATION_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )

    def _verify_activation_proof(self, document: dict, context):
        return verify_activation_proof(
            document,
            state_context=context,
            expected_subject=self._activation_target(),
            expected_contract_approval_digest=D("d"),
            expected_impact_map_digest=D("e"),
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )

    def _activation_approval(self, proof) -> dict:
        return self._envelope(
            ACTIVATION_APPROVAL_SCHEMA,
            ACTIVATION_APPROVAL_KIND,
            {
                "approvalId": "activation-approval-P00.W02-001",
                "proofDigest": proof.attestation_digest,
                "subject": self._subject(proof.subject),
                "fromState": "READY",
                "toState": "ACTIVE",
                "priorStateDigest": proof.prior_state_digest,
                "priorChainHeadDigest": proof.prior_chain_head_digest,
                "contractApprovalDigest": proof.contract_approval_digest,
                "impactMapDigest": proof.impact_map_digest,
                "prerequisites": [
                    {
                        "phase": item.phase,
                        "workUnit": item.work_unit,
                        "status": item.status,
                        "stateDigest": item.state_digest,
                        "contractDigest": item.contract_digest,
                        "sourceCommit": item.source_commit,
                        "approvalDigest": item.approval_digest,
                    }
                    for item in proof.prerequisites
                ],
                "decision": "APPROVE",
                "reason": "Exact activation and prerequisite state reviewed.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent test reviewer.",
                },
                "issuedAt": "2026-07-11T11:30:00Z",
                "validUntil": "2026-07-12T11:30:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            ACTIVATION_APPROVAL_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _verify_activation_approval(self, document: dict, proof):
        signer = self._reviewer_result(document, ACTIVATION_APPROVAL_NAMESPACE)
        return verify_activation_approval(
            document,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
            now=FIXED_NOW,
        )

    def _readiness_state_context(self):
        core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "activePhase": "P00",
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("1"),
                    "controlPlaneDigest": self.subject.control_plane_digest,
                    "baseCommit": self.subject.source_commit,
                    "startedAt": "2026-07-11T09:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": "CONVERGED",
                            "contractDigest": self.subject.contract_digest,
                            "approvalDigest": D("f"),
                            "sourceCommit": self.subject.source_commit,
                        },
                        "P00.W02": {
                            "status": "NOT_STARTED",
                            "contractDigest": D("4"),
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }
        return verify_work_unit_state_context(
            core,
            expected_state_digest=document_digest(core),
            expected_chain_head_digest=D("b"),
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            work_unit="P00.W02",
            expected_status="NOT_STARTED",
            expected_contract_digest=D("4"),
        )

    def _lifecycle_proof_document(
        self,
        context,
        subject: SubjectBinding,
        *,
        to_state: str,
        transition_type: str,
        blocker: str | None = None,
        invalidation_kind: str | None = None,
        invalidation_digest: str | None = None,
    ) -> dict:
        return self._envelope(
            LIFECYCLE_PROOF_SCHEMA,
            LIFECYCLE_PROOF_KIND,
            {
                "proofId": f"lifecycle-{subject.work_unit}-{transition_type.lower()}",
                "transitionType": transition_type,
                "subject": self._subject(subject),
                "fromState": context.status,
                "toState": to_state,
                "priorStateDigest": context.state_digest,
                "priorChainHeadDigest": context.chain_head_digest,
                "contractApprovalDigest": D("d"),
                "impactMapDigest": D("e"),
                "prerequisites": [
                    {
                        "phase": item.phase,
                        "workUnit": item.work_unit,
                        "status": item.status,
                        "stateDigest": item.state_digest,
                        "contractDigest": item.contract_digest,
                        "sourceCommit": item.source_commit,
                        "approvalDigest": item.approval_digest,
                    }
                    for item in context.prerequisites
                ],
                "reasonCode": f"test-{transition_type.lower()}",
                "reason": "Synthetic exact lifecycle evidence.",
                "blockerResolutionDigest": blocker,
                "invalidationKind": invalidation_kind,
                "invalidationDigest": invalidation_digest,
                "issuedAt": "2026-07-11T11:00:00Z",
                "actor": self._actor("protected-workflow"),
                "authorityDigest": self.policy_digest,
            },
            self.workflow_key,
            LIFECYCLE_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )

    def _verify_lifecycle_proof(self, document, context, subject, to_state):
        return verify_lifecycle_proof(
            document,
            state_context=context,
            expected_subject=subject,
            expected_to_state=to_state,
            expected_contract_approval_digest=D("d"),
            expected_impact_map_digest=D("e"),
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )

    def _lifecycle_approval_document(self, proof) -> dict:
        return self._envelope(
            LIFECYCLE_APPROVAL_SCHEMA,
            LIFECYCLE_APPROVAL_KIND,
            {
                "approvalId": "lifecycle-approval-test",
                "proofDigest": proof.attestation_digest,
                "transitionType": proof.transition_type,
                "subject": self._subject(proof.subject),
                "fromState": proof.from_state,
                "toState": proof.to_state,
                "priorStateDigest": proof.prior_state_digest,
                "priorChainHeadDigest": proof.prior_chain_head_digest,
                "contractApprovalDigest": proof.contract_approval_digest,
                "impactMapDigest": proof.impact_map_digest,
                "prerequisites": [
                    {
                        "phase": item.phase,
                        "workUnit": item.work_unit,
                        "status": item.status,
                        "stateDigest": item.state_digest,
                        "contractDigest": item.contract_digest,
                        "sourceCommit": item.source_commit,
                        "approvalDigest": item.approval_digest,
                    }
                    for item in proof.prerequisites
                ],
                "reasonCode": proof.reason_code,
                "reason": proof.reason,
                "blockerResolutionDigest": proof.blocker_resolution_digest,
                "invalidationKind": proof.invalidation_kind,
                "invalidationDigest": proof.invalidation_digest,
                "decision": "APPROVE",
                "approvalReason": "Independent lifecycle review.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent test reviewer.",
                },
                "issuedAt": "2026-07-11T11:30:00Z",
                "validUntil": "2026-07-12T11:30:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            LIFECYCLE_APPROVAL_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _verify_lifecycle_approval(self, document, proof):
        return verify_lifecycle_approval(
            document,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="reviewer@test.invalid",
                role="independent-reviewer",
                organization="review-test",
            ),
            now=FIXED_NOW,
        )

    def _phase_subject_binding(self) -> PhaseSubject:
        return PhaseSubject(
            phase="P00",
            source_commit=self.subject.source_commit,
            control_plane_digest=self.subject.control_plane_digest,
            aggregate_contract_digest=D("5"),
        )

    def _phase_subject_document(self) -> dict:
        subject = self._phase_subject_binding()
        return {
            "phase": subject.phase,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "aggregateContractDigest": subject.aggregate_contract_digest,
        }

    def _phase_core(self, status: str) -> dict:
        contracts = [D(character) for character in "24678"]
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "activePhase": "P00" if status == "ACTIVE" else None,
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": status,
                    "aggregateContractDigest": D("5"),
                    "controlPlaneDigest": self.subject.control_plane_digest,
                    "baseCommit": self.subject.source_commit,
                    "startedAt": "2026-07-11T09:00:00Z",
                    "workUnits": {
                        f"P00.W0{index}": {
                            "status": "CONVERGED",
                            "contractDigest": contracts[index - 1],
                            "approvalDigest": D("f"),
                            "sourceCommit": self.subject.source_commit,
                        }
                        for index in range(1, 6)
                    },
                }
            },
        }

    def _phase_context(self, status: str, head: str = D("b")):
        core = self._phase_core(status)
        return verify_phase_state_context(
            core,
            expected_state_digest=document_digest(core),
            expected_chain_head_digest=head,
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            expected_status=status,
            expected_aggregate_contract_digest=D("5"),
        )

    def _phase_freeze_document(self, criteria: list[dict]) -> dict:
        return self._envelope(
            PHASE_FREEZE_SCHEMA,
            PHASE_FREEZE_KIND,
            {
                "freezeId": "phase-freeze-P00-001",
                "subject": self._phase_subject_document(),
                "aggregateContractApprovalDigest": D("d"),
                "unitContractDigests": {
                    unit.work_unit: unit.contract_digest
                    for unit in self._phase_context("REVIEW_PENDING").units
                },
                "protectedInputs": self.inputs,
                "criteria": criteria,
                "issuedAt": "2026-07-11T10:00:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            PHASE_FREEZE_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _verify_phase_freeze(self, document: dict, criteria: list[dict]):
        context = self._phase_context("REVIEW_PENDING")
        return verify_signed_phase_protected_input_freeze(
            document,
            expected_subject=self._phase_subject_binding(),
            expected_aggregate_contract_approval_digest=D("d"),
            expected_unit_contract_digests={
                unit.work_unit: unit.contract_digest for unit in context.units
            },
            expected_protected_inputs=self.inputs,
            expected_criteria=criteria,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="reviewer@test.invalid",
                role="independent-reviewer",
                organization="review-test",
            ),
        )

    def _phase_machine_document(self, criterion: dict, freeze) -> dict:
        runs = []
        for label in ("A", "B"):
            run = self._run(label, criterion)
            run["contractDigest"] = D("5")
            run["runEvidenceDigest"] = document_digest(
                run, omit_field="runEvidenceDigest"
            )
            runs.append(run)
        pair = {
            "verificationPairId": "phase-pair-P00-001",
            "runA": runs[0],
            "runB": runs[1],
        }
        pair_digest = document_digest(pair)
        return self._envelope(
            PHASE_CRITERION_SCHEMA,
            PHASE_CRITERION_KIND,
            {
                "resultId": "phase-result-P00-M-AGGREGATE",
                "freezeDigest": freeze.attestation_digest,
                "subject": self._phase_subject_document(),
                "criterion": criterion,
                "outcome": "PASS",
                "evidenceDigest": pair_digest,
                "runPair": pair,
                "runPairDigest": pair_digest,
                "humanReview": None,
                "issuedAt": "2026-07-11T10:30:00Z",
                "actor": self._actor("protected-workflow"),
                "authorityDigest": self.policy_digest,
            },
            self.workflow_key,
            PHASE_CRITERION_NAMESPACES["MACHINE"],
            "workflow@test.invalid",
        )

    def _phase_proof_document(self, freeze, results, context, to_state: str) -> dict:
        deferred = "P00-H-GO-NOGO" if to_state == "CONVERGED" else None
        return self._envelope(
            PHASE_PROOF_SCHEMA,
            PHASE_PROOF_KIND,
            {
                "proofId": "phase-proof-P00-001",
                "freezeDigest": freeze.attestation_digest,
                "subject": self._phase_subject_document(),
                "fromState": context.status,
                "toState": to_state,
                "priorStateDigest": context.state_digest,
                "priorChainHeadDigest": context.chain_head_digest,
                "unitStates": [
                    {
                        "workUnit": unit.work_unit,
                        "status": unit.status,
                        "contractDigest": unit.contract_digest,
                        "sourceCommit": unit.source_commit,
                        "approvalDigest": unit.approval_digest,
                    }
                    for unit in context.units
                ],
                "criterionResults": [
                    {
                        "criterionId": result.criterion.criterion_id,
                        "kind": result.criterion.kind,
                        "resultDigest": result.attestation_digest,
                        "evidenceDigest": result.evidence_digest,
                    }
                    for result in sorted(results, key=lambda item: item.criterion.criterion_id)
                ],
                "deferredGoNoGoCriterionId": deferred,
                "issuedAt": "2026-07-11T11:00:00Z",
                "actor": self._actor("protected-workflow"),
                "authorityDigest": self.policy_digest,
            },
            self.workflow_key,
            PHASE_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )

    def _phase_approval_document(self, proof) -> dict:
        return self._envelope(
            PHASE_APPROVAL_SCHEMA,
            PHASE_APPROVAL_KIND,
            {
                "approvalId": "phase-approval-P00-001",
                "proofDigest": proof.attestation_digest,
                "freezeDigest": proof.freeze_digest,
                "subject": self._phase_subject_document(),
                "fromState": proof.from_state,
                "toState": proof.to_state,
                "priorStateDigest": proof.prior_state_digest,
                "priorChainHeadDigest": proof.prior_chain_head_digest,
                "unitStates": [
                    {
                        "workUnit": unit.work_unit,
                        "status": unit.status,
                        "contractDigest": unit.contract_digest,
                        "sourceCommit": unit.source_commit,
                        "approvalDigest": unit.approval_digest,
                    }
                    for unit in proof.unit_states
                ],
                "criterionResults": [
                    {
                        "criterionId": item[0],
                        "kind": item[1],
                        "resultDigest": item[2],
                        "evidenceDigest": item[3],
                    }
                    for item in proof.criterion_results
                ],
                "deferredGoNoGoCriterionId": proof.deferred_go_nogo_criterion_id,
                "decision": "APPROVE",
                "reason": "Independent aggregate proof review.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent test reviewer.",
                },
                "issuedAt": "2026-07-11T11:30:00Z",
                "validUntil": "2026-07-12T11:30:00Z",
                "actor": self._actor("independent-reviewer"),
                "authorityDigest": self.policy_digest,
            },
            self.reviewer_key,
            PHASE_APPROVAL_NAMESPACE,
            "reviewer@test.invalid",
        )

    def _go_nogo_document(self, proof, role: str) -> dict:
        actor = self._actor(role)
        key = self.maintainer_key if role == "authorized-maintainer" else self.external_key
        return self._envelope(
            PHASE_GO_NOGO_SCHEMA,
            PHASE_GO_NOGO_KIND,
            {
                "authorizationId": f"go-no-go-{role}",
                "proofDigest": proof.attestation_digest,
                "freezeDigest": proof.freeze_digest,
                "subject": self._phase_subject_document(),
                "fromState": proof.from_state,
                "toState": proof.to_state,
                "priorStateDigest": proof.prior_state_digest,
                "priorChainHeadDigest": proof.prior_chain_head_digest,
                "criterionId": "P00-H-GO-NOGO",
                "decision": "APPROVE",
                "reason": "P00 may converge on the reviewed aggregate evidence.",
                "conflictOfInterest": {
                    "independent": role == "independent-external-reviewer",
                    "statement": "Exact role and organization disclosed.",
                },
                "issuedAt": "2026-07-11T11:30:00Z",
                "validUntil": "2026-07-12T11:30:00Z",
                "actor": actor,
                "authorityDigest": self.policy_digest,
            },
            key,
            PHASE_GO_NOGO_NAMESPACE,
            actor["principal"],
        )

    def _assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_valid_freeze_machine_pair_proof_and_reviewer_approval(self) -> None:
        proof_doc = self._proof([self.machine])
        proof = self._verify_proof(proof_doc, [self.machine])
        approval_doc = self._approval(proof)
        signer = self._reviewer_result(approval_doc, TRANSITION_APPROVAL_NAMESPACE)
        approval = verify_transition_approval(
            approval_doc,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
            now=FIXED_NOW,
        )
        self.assertTrue(approval.authorized)
        self.assertEqual(proof.criterion_results[0][0], "C-MACHINE")

    def test_random_run_digest_is_rejected_even_when_statement_is_resigned(self) -> None:
        document = deepcopy(self.machine_doc)
        document["body"]["runPair"]["runA"]["runEvidenceDigest"] = D("f")
        pair_digest = document_digest(document["body"]["runPair"])
        document["body"]["runPairDigest"] = pair_digest
        document["body"]["evidenceDigest"] = pair_digest
        document = self._resign(
            document,
            self.workflow_key,
            CRITERION_NAMESPACES["MACHINE"],
            "workflow@test.invalid",
        )
        self._assert_error(
            "run_evidence_digest_mismatch", self._verify_machine, document, self.freeze
        )

    def test_cross_unit_source_and_control_replay_are_rejected(self) -> None:
        mutations = {
            "workUnit": "P00.W02",
            "sourceCommit": "b" * 40,
            "controlPlaneDigest": D("f"),
            "contractDigest": D("f"),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                document = deepcopy(self.machine_doc)
                document["body"]["subject"][field] = value
                document = self._resign(
                    document,
                    self.workflow_key,
                    CRITERION_NAMESPACES["MACHINE"],
                    "workflow@test.invalid",
                )
                self._assert_error(
                    "subject_binding_mismatch", self._verify_machine, document, self.freeze
                )

    def test_planned_evaluator_cannot_be_frozen(self) -> None:
        criteria = deepcopy(self.criteria)
        criteria[1]["evaluatorStatus"] = "planned"
        document = self._freeze(criteria)
        signer = self._reviewer_result(document, FREEZE_NAMESPACE)
        self._assert_error(
            "evaluator_not_implemented",
            verify_signed_protected_input_freeze,
            document,
            expected_subject=self.subject,
            expected_contract_approval_digest=D("f"),
            expected_protected_inputs=self.inputs,
            expected_criteria=criteria,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
        )

    def test_evaluator_and_dataset_are_exactly_contract_bound(self) -> None:
        for field in ("evaluatorDigest", "datasetDigest"):
            with self.subTest(field=field):
                document = deepcopy(self.machine_doc)
                document["body"]["criterion"][field] = D("f")
                document = self._resign(
                    document,
                    self.workflow_key,
                    CRITERION_NAMESPACES["MACHINE"],
                    "workflow@test.invalid",
                )
                self._assert_error(
                    "criterion_binding_mismatch", self._verify_machine, document, self.freeze
                )

    def test_run_a_b_identity_and_deterministic_bindings_are_recomputed(self) -> None:
        mutations = {
            ("runA", "controlPlaneDigest"): D("f"),
            ("runB", "evaluatorDigest"): D("f"),
            ("runA", "datasetDigest"): D("f"),
            ("runB", "deterministicResultSetDigest"): D("f"),
        }
        for (run_name, field), value in mutations.items():
            with self.subTest(run=run_name, field=field):
                document = deepcopy(self.machine_doc)
                run = document["body"]["runPair"][run_name]
                run[field] = value
                run["runEvidenceDigest"] = document_digest(
                    run, omit_field="runEvidenceDigest"
                )
                pair_digest = document_digest(document["body"]["runPair"])
                document["body"]["runPairDigest"] = pair_digest
                document["body"]["evidenceDigest"] = pair_digest
                document = self._resign(
                    document,
                    self.workflow_key,
                    CRITERION_NAMESPACES["MACHINE"],
                    "workflow@test.invalid",
                )
                expected = (
                    "deterministic_result_mismatch"
                    if field == "deterministicResultSetDigest"
                    else "run_binding_mismatch"
                )
                self._assert_error(expected, self._verify_machine, document, self.freeze)

    def test_machine_pass_requires_real_successful_run_commands(self) -> None:
        for field, value in (("exitCode", 1), ("passed", 0)):
            with self.subTest(field=field):
                document = deepcopy(self.machine_doc)
                run = document["body"]["runPair"]["runA"]
                if field == "passed":
                    run["commands"][0]["summary"][field] = value
                else:
                    run["commands"][0][field] = value
                run["runEvidenceDigest"] = document_digest(
                    run, omit_field="runEvidenceDigest"
                )
                pair_digest = document_digest(document["body"]["runPair"])
                document["body"]["runPairDigest"] = pair_digest
                document["body"]["evidenceDigest"] = pair_digest
                document = self._resign(
                    document,
                    self.workflow_key,
                    CRITERION_NAMESPACES["MACHINE"],
                    "workflow@test.invalid",
                )
                self._assert_error(
                    "machine_run_not_successful",
                    self._verify_machine,
                    document,
                    self.freeze,
                )

    def test_missing_and_duplicate_criterion_results_fail_closed(self) -> None:
        for projection in ([], [self.machine, self.machine]):
            with self.subTest(count=len(projection)):
                proof_doc = self._proof(projection)
                self._assert_error(
                    "incomplete_criterion_set",
                    self._verify_proof,
                    proof_doc,
                    projection,
                )

    def test_wrong_role_and_namespace_are_rejected(self) -> None:
        self._assert_error(
            "actor_principal_mismatch",
            verify_signed_criterion_result,
            self.machine_doc,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(role="independent-reviewer"),
        )
        document = deepcopy(self.machine_doc)
        document["signature"]["namespace"] = FREEZE_NAMESPACE
        document["attestationDigest"] = document_digest(
            document, omit_field="attestationDigest"
        )
        self._assert_error(
            "signature_namespace_mismatch", self._verify_machine, document, self.freeze
        )
        cross_kind = deepcopy(self.machine_doc)
        cross_kind["body"]["criterion"]["kind"] = "HUMAN"
        cross_kind["attestationDigest"] = document_digest(
            cross_kind, omit_field="attestationDigest"
        )
        self._assert_error(
            "signature_namespace_mismatch",
            verify_signed_criterion_result,
            cross_kind,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )

    def test_freeze_replacement_invalidates_prior_results(self) -> None:
        replaced_inputs = deepcopy(self.inputs)
        replaced_inputs["protectedAcceptanceDigest"] = D("f")
        replacement_doc = self._freeze(self.criteria, replaced_inputs)
        replacement = self._verify_freeze(
            replacement_doc, self.criteria, replaced_inputs
        )
        self._assert_error(
            "freeze_digest_mismatch", self._verify_machine, self.machine_doc, replacement
        )

    def test_generic_external_signature_does_not_establish_external_fact(self) -> None:
        external_doc = self._criterion_result(self.criteria[2])
        external = verify_signed_criterion_result(
            external_doc,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.external_key,
                principal="external@test.invalid",
                role="external-attestor",
                organization="external-test",
            ),
        )
        self.assertTrue(external.signature_verified)
        self.assertEqual(external.fact_status, "signature_verified_fact_unverified")
        self.assertFalse(external.criterion_satisfied)
        waiting_context = self._state_context("WAITING_EXTERNAL")
        proof_doc = self._proof(
            [self.machine, external],
            context=waiting_context,
            to_state="REVIEW_PENDING",
        )
        self._assert_error(
            "external_fact_not_verified",
            self._verify_proof,
            proof_doc,
            [self.machine, external],
            waiting_context,
            "REVIEW_PENDING",
        )

    def test_generic_time_signature_also_remains_fact_unverified(self) -> None:
        time_criterion = self._criterion("C-TIME", "TIME", "e")
        criteria = sorted(
            [*self.criteria, time_criterion], key=lambda item: item["id"]
        )
        freeze_doc = self._freeze(criteria)
        freeze = self._verify_freeze(freeze_doc, criteria)
        time_doc = self._criterion_result(time_criterion, freeze=freeze)
        result = verify_signed_criterion_result(
            time_doc,
            freeze=freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.external_key,
                principal="external@test.invalid",
                role="time-attestor",
                organization="external-test",
            ),
        )
        self.assertEqual(result.fact_status, "signature_verified_fact_unverified")
        self.assertFalse(result.criterion_satisfied)

    def test_human_result_is_complete_only_with_reviewer_signature(self) -> None:
        human_doc = self._criterion_result(self.criteria[0])
        signer = self._reviewer_result(
            human_doc, CRITERION_NAMESPACES["HUMAN"]
        )
        result = verify_signed_criterion_result(
            human_doc,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
        )
        self.assertTrue(result.criterion_satisfied)
        self.assertEqual(result.outcome, "APPROVE")

    def test_proof_and_approval_cannot_be_replayed(self) -> None:
        proof_doc = self._proof([self.machine])
        proof = self._verify_proof(proof_doc, [self.machine])
        blocked_context = self._state_context("BLOCKED")
        self._assert_error(
            "transition_replay",
            self._verify_proof,
            proof_doc,
            [self.machine],
            blocked_context,
            "ACTIVE",
        )
        approval_doc = self._approval(proof)
        second_doc = deepcopy(proof_doc)
        second_doc["body"]["proofId"] = "proof-P00.W01-002"
        second_doc = self._resign(
            second_doc, self.workflow_key, PROOF_NAMESPACE, "workflow@test.invalid"
        )
        second = self._verify_proof(second_doc, [self.machine])
        signer = self._reviewer_result(approval_doc, TRANSITION_APPROVAL_NAMESPACE)
        self._assert_error(
            "proof_digest_mismatch",
            verify_transition_approval,
            approval_doc,
            proof=second,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
            now=FIXED_NOW,
        )

    def test_transition_approval_requires_reviewer_role_and_namespace(self) -> None:
        proof = self._verify_proof(self._proof([self.machine]), [self.machine])
        approval_doc = self._approval(proof)
        self._assert_error(
            "actor_principal_mismatch",
            verify_transition_approval,
            approval_doc,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="reviewer@test.invalid",
                role="protected-workflow",
                organization="review-test",
            ),
            now=FIXED_NOW,
        )
        wrong_namespace = deepcopy(approval_doc)
        wrong_namespace["signature"]["namespace"] = PROOF_NAMESPACE
        wrong_namespace["attestationDigest"] = document_digest(
            wrong_namespace, omit_field="attestationDigest"
        )
        signer = self._reviewer_result(approval_doc, TRANSITION_APPROVAL_NAMESPACE)
        self._assert_error(
            "signature_namespace_mismatch",
            verify_transition_approval,
            wrong_namespace,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
            now=FIXED_NOW,
        )

    def test_valid_activation_consumes_verified_state_proof_and_approval(self) -> None:
        context = self._activation_state_context()
        proof = self._verify_activation_proof(
            self._activation_proof(context), context
        )
        approval = self._verify_activation_approval(
            self._activation_approval(proof), proof
        )
        transition = authorize_activation_transition(
            state_context=context, proof=proof, approval=approval
        )
        self.assertEqual(transition.transition_type, "ACTIVATION")
        self.assertEqual(transition.subject.work_unit, "P00.W02")
        self.assertEqual(transition.from_state, "READY")
        self.assertEqual(transition.to_state, "ACTIVE")
        self.assertEqual(transition.approval_digest, approval.attestation_digest)

    def test_activation_binds_prerequisite_state_contract_source_and_control(self) -> None:
        context = self._activation_state_context()
        document = self._activation_proof(context)
        mutations = (
            ("priorStateDigest", D("f"), "activation_state_replay"),
            ("contractApprovalDigest", D("f"), "contract_approval_digest_mismatch"),
            ("impactMapDigest", D("f"), "impact_map_digest_mismatch"),
        )
        for field, value, code in mutations:
            with self.subTest(field=field):
                changed = deepcopy(document)
                changed["body"][field] = value
                changed = self._resign(
                    changed,
                    self.workflow_key,
                    ACTIVATION_PROOF_NAMESPACE,
                    "workflow@test.invalid",
                )
                self._assert_error(
                    code, self._verify_activation_proof, changed, context
                )
        changed = deepcopy(document)
        changed["body"]["prerequisites"][0]["stateDigest"] = D("f")
        changed = self._resign(
            changed,
            self.workflow_key,
            ACTIVATION_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )
        self._assert_error(
            "prerequisite_binding_mismatch",
            self._verify_activation_proof,
            changed,
            context,
        )
        changed = deepcopy(document)
        changed["body"]["subject"]["sourceCommit"] = "c" * 40
        changed = self._resign(
            changed,
            self.workflow_key,
            ACTIVATION_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )
        self._assert_error(
            "subject_binding_mismatch",
            self._verify_activation_proof,
            changed,
            context,
        )

    def test_activation_proof_and_approval_cannot_replay_on_new_chain_head(self) -> None:
        context = self._activation_state_context()
        proof_document = self._activation_proof(context)
        proof = self._verify_activation_proof(proof_document, context)
        approval_document = self._activation_approval(proof)
        newer_context = self._activation_state_context(chain_head=D("c"))
        self._assert_error(
            "activation_state_replay",
            self._verify_activation_proof,
            proof_document,
            newer_context,
        )
        second_document = deepcopy(proof_document)
        second_document["body"]["proofId"] = "activation-proof-P00.W02-002"
        second_document = self._resign(
            second_document,
            self.workflow_key,
            ACTIVATION_PROOF_NAMESPACE,
            "workflow@test.invalid",
        )
        second = self._verify_activation_proof(second_document, context)
        signer = self._reviewer_result(
            approval_document, ACTIVATION_APPROVAL_NAMESPACE
        )
        self._assert_error(
            "proof_digest_mismatch",
            verify_activation_approval,
            approval_document,
            proof=second,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=signer,
            now=FIXED_NOW,
        )

    def test_convergence_authorization_consumes_exact_internal_results(self) -> None:
        proof = self._verify_proof(self._proof([self.machine]), [self.machine])
        approval_document = self._approval(proof)
        approval_signer = self._reviewer_result(
            approval_document, TRANSITION_APPROVAL_NAMESPACE
        )
        convergence_approval = verify_transition_approval(
            approval_document,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=approval_signer,
            now=FIXED_NOW,
        )
        transition = authorize_convergence_transition(
            state_context=self.active_context,
            freeze=self.freeze,
            criterion_results=[self.machine],
            proof=proof,
            approval=convergence_approval,
        )
        self.assertEqual(transition.transition_type, "CONVERGENCE")
        self.assertEqual(transition.to_state, "MACHINE_CONVERGED")
        self.assertEqual(
            transition.criterion_result_digests,
            (self.machine.attestation_digest,),
        )

    def test_forged_registry_or_copied_verified_objects_cannot_authorize(self) -> None:
        proof = self._verify_proof(self._proof([self.machine]), [self.machine])
        approval_document = self._approval(proof)
        approval = verify_transition_approval(
            approval_document,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            verified_signer_result=self._reviewer_result(
                approval_document, TRANSITION_APPROVAL_NAMESPACE
            ),
            now=FIXED_NOW,
        )
        self._assert_error(
            "unverified_internal_result",
            authorize_convergence_transition,
            state_context=self.active_context,
            freeze=self.freeze,
            criterion_results={"C-MACHINE": self.machine},
            proof=proof,
            approval=approval,
        )
        self._assert_error(
            "unverified_internal_result",
            authorize_convergence_transition,
            state_context=self.active_context,
            freeze=self.freeze,
            criterion_results=[deepcopy(self.machine)],
            proof=proof,
            approval=approval,
        )
        context = self._activation_state_context()
        activation_proof = self._verify_activation_proof(
            self._activation_proof(context), context
        )
        activation_approval = self._verify_activation_approval(
            self._activation_approval(activation_proof), activation_proof
        )
        self._assert_error(
            "unverified_internal_result",
            authorize_activation_transition,
            state_context=context,
            proof=deepcopy(activation_proof),
            approval=activation_approval,
        )

    def test_activation_state_context_rejects_random_digest_and_unmet_prerequisite(self) -> None:
        core = self._activation_state_context()
        self.assertEqual(core.status, "READY")
        raw = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.subject.control_plane_digest,
            "activePhase": "P00",
            "activeWorkUnit": None,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "workUnits": {
                        "P00.W01": {
                            "status": "NOT_STARTED",
                            "contractDigest": self.subject.contract_digest,
                            "approvalDigest": D("f"),
                            "sourceCommit": self.subject.source_commit,
                        },
                        "P00.W02": {
                            "status": "READY",
                            "contractDigest": D("4"),
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }
        self._assert_error(
            "state_digest_mismatch",
            verify_work_unit_state_context,
            raw,
            expected_state_digest=D("f"),
            expected_chain_head_digest=D("b"),
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            work_unit="P00.W02",
            expected_status="READY",
            expected_contract_digest=D("4"),
            prerequisite_units=["P00.W01"],
        )
        self._assert_error(
            "prerequisite_not_converged",
            verify_work_unit_state_context,
            raw,
            expected_state_digest=document_digest(raw),
            expected_chain_head_digest=D("b"),
            expected_control_plane_digest=self.subject.control_plane_digest,
            phase="P00",
            work_unit="P00.W02",
            expected_status="READY",
            expected_contract_digest=D("4"),
            prerequisite_units=["P00.W01"],
        )

    def test_w01_to_w02_readiness_then_activation_is_fully_authorized(self) -> None:
        readiness_context = self._readiness_state_context()
        target = self._activation_target()
        proof = self._verify_lifecycle_proof(
            self._lifecycle_proof_document(
                readiness_context,
                target,
                to_state="READY",
                transition_type="READINESS",
            ),
            readiness_context,
            target,
            "READY",
        )
        approval = self._verify_lifecycle_approval(
            self._lifecycle_approval_document(proof), proof
        )
        readiness = authorize_lifecycle_transition(
            state_context=readiness_context, proof=proof, approval=approval
        )
        self.assertEqual(readiness.from_state, "NOT_STARTED")
        self.assertEqual(readiness.to_state, "READY")
        self.assertEqual(
            [item.work_unit for item in readiness.prerequisites], ["P00.W01"]
        )

        active_context = self._activation_state_context()
        activation_proof = self._verify_activation_proof(
            self._activation_proof(active_context), active_context
        )
        activation_approval = self._verify_activation_approval(
            self._activation_approval(activation_proof), activation_proof
        )
        activation = authorize_activation_transition(
            state_context=active_context,
            proof=activation_proof,
            approval=activation_approval,
        )
        self.assertEqual((activation.from_state, activation.to_state), ("READY", "ACTIVE"))
        self._assert_error(
            "unverified_internal_result",
            authorize_lifecycle_transition,
            state_context=readiness_context,
            proof=deepcopy(proof),
            approval=approval,
        )

    def test_resume_invalidation_and_supersession_have_distinct_evidence(self) -> None:
        cases = [
            (
                self._state_context("BLOCKED"),
                self.subject,
                "ACTIVE",
                "RESUME",
                D("c"),
                None,
                None,
            ),
            (
                self._state_context("CONVERGED"),
                self.subject,
                "REJECTED",
                "INVALIDATION",
                None,
                "IMPACT",
                D("c"),
            ),
            (
                self._readiness_state_context(),
                self._activation_target(),
                "SUPERSEDED",
                "SUPERSESSION",
                None,
                "SUPERSESSION",
                D("c"),
            ),
        ]
        for context, subject, to_state, kind, blocker, invalidation_kind, invalidation_digest in cases:
            with self.subTest(kind=kind):
                document = self._lifecycle_proof_document(
                    context,
                    subject,
                    to_state=to_state,
                    transition_type=kind,
                    blocker=blocker,
                    invalidation_kind=invalidation_kind,
                    invalidation_digest=invalidation_digest,
                )
                proof = self._verify_lifecycle_proof(
                    document, context, subject, to_state
                )
                approval = self._verify_lifecycle_approval(
                    self._lifecycle_approval_document(proof), proof
                )
                transition = authorize_lifecycle_transition(
                    state_context=context, proof=proof, approval=approval
                )
                self.assertEqual(transition.transition_type, kind)
        missing_resolution = self._lifecycle_proof_document(
            self._state_context("BLOCKED"),
            self.subject,
            to_state="ACTIVE",
            transition_type="RESUME",
        )
        self._assert_error(
            "invalid_digest",
            self._verify_lifecycle_proof,
            missing_resolution,
            self._state_context("BLOCKED"),
            self.subject,
            "ACTIVE",
        )
        wrong_reopen = self._lifecycle_proof_document(
            self._state_context("CONVERGED"),
            self.subject,
            to_state="REJECTED",
            transition_type="INVALIDATION",
            invalidation_kind="SUPERSESSION",
            invalidation_digest=D("c"),
        )
        self._assert_error(
            "invalid_invalidation_kind",
            self._verify_lifecycle_proof,
            wrong_reopen,
            self._state_context("CONVERGED"),
            self.subject,
            "REJECTED",
        )

    def test_phase_aggregate_requires_five_units_and_two_role_go_nogo(self) -> None:
        criteria = [
            self._criterion("P00-H-GO-NOGO", "HUMAN", "b"),
            self._criterion("P00-M-AGGREGATE", "MACHINE", "c"),
        ]
        freeze_document = self._phase_freeze_document(criteria)
        self.assertNotIn("workUnit", freeze_document["body"]["subject"])
        freeze = self._verify_phase_freeze(freeze_document, criteria)
        machine_document = self._phase_machine_document(criteria[1], freeze)
        machine = verify_signed_phase_criterion_result(
            machine_document,
            freeze=freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )
        context = self._phase_context("REVIEW_PENDING")
        proof_document = self._phase_proof_document(
            freeze, [machine], context, "CONVERGED"
        )
        proof = verify_phase_transition_proof(
            proof_document,
            freeze=freeze,
            criterion_results=[machine],
            state_context=context,
            expected_to_state="CONVERGED",
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._workflow_callback(),
        )
        approval_document = self._phase_approval_document(proof)
        approval = verify_phase_transition_approval(
            approval_document,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="reviewer@test.invalid",
                role="independent-reviewer",
                organization="review-test",
            ),
            now=FIXED_NOW,
        )
        go_documents = [
            self._go_nogo_document(proof, "authorized-maintainer"),
            self._go_nogo_document(proof, "independent-external-reviewer"),
        ]
        go = verify_phase_go_nogo_authorization(
            go_documents,
            proof=proof,
            expected_authority_digest=self.policy_digest,
            signer_verifiers=[
                self._external_signer_callback(
                    key=self.maintainer_key,
                    principal="maintainer@test.invalid",
                    role="authorized-maintainer",
                    organization="maintainer-test",
                ),
                self._external_signer_callback(
                    key=self.external_key,
                    principal="external-reviewer@test.invalid",
                    role="independent-external-reviewer",
                    organization="external-review-test",
                ),
            ],
            now=FIXED_NOW,
        )
        transition = authorize_phase_transition(
            state_context=context,
            freeze=freeze,
            criterion_results=[machine],
            proof=proof,
            approval=approval,
            go_nogo_authorization=go,
        )
        self.assertEqual(transition.transition_type, "PHASE_AGGREGATE")
        self.assertEqual(len(transition.unit_states), 5)
        self._assert_error(
            "go_nogo_threshold_not_met",
            verify_phase_go_nogo_authorization,
            go_documents[:1],
            proof=proof,
            expected_authority_digest=self.policy_digest,
            signer_verifiers=[self._workflow_callback()],
            now=FIXED_NOW,
        )
        self._assert_error(
            "unverified_internal_result",
            authorize_phase_transition,
            state_context=context,
            freeze=freeze,
            criterion_results=[machine],
            proof=proof,
            approval=approval,
            go_nogo_authorization=deepcopy(go),
        )

    def test_criterion_authorization_preserves_real_human_role(self) -> None:
        criterion = self.criteria[0]
        document = self._criterion_result(criterion)
        document["body"]["actor"] = {
            "principal": "rights@test.invalid",
            "role": "independent-rights-reviewer",
            "organization": "rights-test",
        }
        document = self._resign(
            document,
            self.reviewer_key,
            CRITERION_NAMESPACES["HUMAN"],
            "rights@test.invalid",
        )
        raw_authorization = object()

        def adapter(value):
            self.assertIs(value, raw_authorization)
            return {
                "criterionId": criterion["id"],
                "principal": "rights@test.invalid",
                "organization": "rights-test",
                "role": "independent-rights-reviewer",
                "capability": "attest-human-result",
                "authorityDigest": self.policy_digest,
                "delegationDigest": None,
            }

        authorization = verify_criterion_authorization(
            raw_authorization,
            expected_criterion_id=criterion["id"],
            expected_kind="HUMAN",
            expected_authority_digest=self.policy_digest,
            authorization_adapter=adapter,
        )
        result = verify_signed_criterion_result(
            document,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="rights@test.invalid",
                role="independent-rights-reviewer",
                organization="rights-test",
            ),
            criterion_authorization=authorization,
        )
        self.assertEqual(result.signer.role, "independent-rights-reviewer")
        self._assert_error(
            "unverified_internal_result",
            verify_signed_criterion_result,
            document,
            freeze=self.freeze,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._external_signer_callback(
                key=self.reviewer_key,
                principal="rights@test.invalid",
                role="independent-rights-reviewer",
                organization="rights-test",
            ),
            criterion_authorization=deepcopy(authorization),
        )


if __name__ == "__main__":
    unittest.main()
