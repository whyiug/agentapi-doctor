from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes
from tools.phasegate.control_context import (
    criterion_documents,
    derive_work_unit_control_context,
)
from tools.phasegate.execution_artifact import (
    ASSERTION_SCHEMA,
    ENVIRONMENT_SCHEMA,
    CapturedRunArtifact,
    _environment_digest,
    _manifest_digest,
    serialize_execution_artifact_bundle,
)
from tools.phasegate.gate_runner import combine_runs, record_run
from tools.phasegate.oidc import jwks_snapshot_digest, validate_jwks_snapshot
from tools.phasegate.oidc_provenance import (
    OIDC_PROVENANCE_AUDIENCE_PREFIX,
    build_oidc_provenance_verifier,
    create_signed_machine_criterion_result,
)
from tools.phasegate.protected import document_digest
from tools.phasegate.provenance import (
    ACTIVATION_APPROVAL_KIND,
    ACTIVATION_APPROVAL_NAMESPACE,
    ACTIVATION_APPROVAL_SCHEMA,
    ACTIVATION_PROOF_KIND,
    ACTIVATION_PROOF_NAMESPACE,
    ACTIVATION_PROOF_SCHEMA,
    FREEZE_KIND,
    FREEZE_NAMESPACE,
    FREEZE_SCHEMA,
    LIFECYCLE_APPROVAL_KIND,
    LIFECYCLE_APPROVAL_NAMESPACE,
    LIFECYCLE_APPROVAL_SCHEMA,
    LIFECYCLE_PROOF_KIND,
    LIFECYCLE_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_SCHEMA,
    PROOF_KIND,
    PROOF_NAMESPACE,
    PROOF_SCHEMA,
    TRANSITION_APPROVAL_KIND,
    TRANSITION_APPROVAL_NAMESPACE,
    TRANSITION_APPROVAL_SCHEMA,
    SubjectBinding,
    VerifiedSignerResult,
    verify_signed_protected_input_freeze,
    verify_work_unit_state_context,
)
from tools.phasegate.serialized_bundle import (
    BUNDLE_KIND,
    BUNDLE_SCHEMA,
    OP_ACTIVATION,
    OP_ATTACHMENT,
    OP_CONVERGENCE,
    OP_READINESS,
    SerializedBundleError,
    require_verified_serialized_bundle,
    verify_serialized_authorization_bundle,
)
from tools.phasegate.sshsig import verify_sshsig
from tools.phasegate.state_chain_v2 import (
    EXECUTED_VERIFIER_PATHS,
    VerifiedEvidenceAttachmentV2,
    VerifiedGenesisAnchorV2,
    verify_genesis_anchor_v2,
)

from test_control_context import ApprovedControlFixture


REPO_ROOT = Path(__file__).resolve().parents[2]


def D(character: str) -> str:
    return "sha256:" + character * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class SerializedBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for executable in ("/usr/bin/git", "/usr/bin/openssl", "/usr/bin/ssh-keygen"):
            if not Path(executable).is_file():
                raise unittest.SkipTest(
                    f"required fixture tool is absent: {executable}"
                )
        cls.temporary = tempfile.TemporaryDirectory(prefix="serialized-bundle-")
        cls.root = Path(cls.temporary.name)
        cls.ssh_key = cls.root / "reviewer"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "reviewer@example.invalid",
                "-f",
                str(cls.ssh_key),
            ],
            check=True,
        )
        public_fields = (
            cls.ssh_key.with_suffix(".pub").read_text(encoding="utf-8").split()
        )
        cls.ssh_public = " ".join(public_fields[:2])
        fingerprint = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-E",
                "sha256",
                "-lf",
                str(cls.ssh_key.with_suffix(".pub")),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[1]
        cls.ssh_fingerprint = fingerprint

        cls.rsa_key = cls.root / "oidc.pem"
        cls.rsa_public = cls.root / "oidc-public.pem"
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
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                str(cls.rsa_key),
                "-pubout",
                "-out",
                str(cls.rsa_public),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        modulus_hex = (
            subprocess.run(
                [
                    "/usr/bin/openssl",
                    "rsa",
                    "-pubin",
                    "-in",
                    str(cls.rsa_public),
                    "-modulus",
                    "-noout",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
            .split("=", 1)[1]
        )
        modulus = bytes.fromhex(modulus_hex).lstrip(b"\x00")
        cls.jwk = {
            "kty": "RSA",
            "kid": "serialized-bundle-test-key",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }

        cls.repo = cls.root / "repo"
        cls.approved = ApprovedControlFixture(cls.repo)
        cls.workflow_path = ".github/workflows/p00-protected-state-writer.yml"
        cls.commit = cls.approved.commit
        cls.components = cls.approved.components

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.now = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)
        self.control = self.__class__.approved.control_plane_digest
        self.contracts = {
            "P00.W01": self.components["execution/work-units/P00.W01.yaml"],
            "P00.W02": self.components["execution/work-units/P00.W02.yaml"],
        }
        self.contract_approval = D("6")
        self.impact_map = self.components["execution/impact-map.yaml"]
        self.snapshot = {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T00:00:00Z",
            "sourceRawDigest": D("5"),
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
        self.state_signer = {
            "identity": "github-actions:whyiug/agentapi-doctor:p00-state-writer",
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
            "runAttempt": "1",
            "workflowShaSource": "approval.body.workflowExecutionCommit",
            "shaMustEqualWorkflowSha": True,
            "headAndBaseRefMustBeEmpty": True,
        }
        self.machine_policy = {
            "type": "github-actions-oidc-rs256-v1",
            "audiencePrefix": OIDC_PROVENANCE_AUDIENCE_PREFIX,
            "signerPolicyRef": "githubActionsStateSigner",
            "allowedNamespaces": [
                ACTIVATION_PROOF_NAMESPACE,
                "agentapi-doctor/criterion-result/machine/v1",
                "agentapi-doctor/lifecycle-evidence/invalidation/v1",
                LIFECYCLE_PROOF_NAMESPACE,
                "agentapi-doctor/phase-criterion-result/machine/v1",
                "agentapi-doctor/phase-transition-proof/v1",
                PROOF_NAMESPACE,
            ],
            "requiredComponentPaths": sorted(
                (self.workflow_path, *EXECUTED_VERIFIER_PATHS)
            ),
            "componentApprovalBinding": "authorityDigest binds the exact approved component digest map",
            "runAttempt": "1",
            "shaMustEqualWorkflowSha": True,
            "headAndBaseRefMustBeAbsent": True,
        }
        self.principal = {
            "identity": "reviewer@example.invalid",
            "organization": "reviewer-org",
            "roles": ["authorized-maintainer", "independent-reviewer"],
            "publicKey": self.ssh_public,
            "fingerprint": self.ssh_fingerprint,
            "capabilities": [
                "approve-transition",
                "attest-human-result",
                "delegate-reviewer",
                "freeze-protected-input",
                "witness-chain-head",
            ],
            "validFrom": "2026-07-11T00:00:00Z",
            "validUntil": "2027-07-11T00:00:00Z",
        }
        delegation_policy = {
            "namespace": "agentapi-doctor/reviewer-delegation/v1",
            "rootCapability": "delegate-reviewer",
            "allowedRoles": [],
            "allowedCapabilities": [],
            "roleGrants": {},
            "maxValiditySeconds": 7776000,
            "priorChainHeadRequired": True,
            "delegatedMayApproveControlPlane": False,
            "delegatedMaySignStateEvent": False,
            "delegatedMayDelegate": False,
        }
        self.policy = {
            "controlPlaneDigest": self.control,
            "signatureSchemes": {"machineProvenance": self.machine_policy},
            "reviewerDelegation": delegation_policy,
            "sshPrincipals": [self.principal],
            "humanCriterionRoleGrants": {},
        }
        self.policy_digest = document_digest(self.policy)
        self.policy_result = {
            "document": self.policy,
            "digest": self.policy_digest,
            "principals": {self.principal["identity"]: self.principal},
            "revokedFingerprints": set(),
            "delegationRoots": {self.principal["identity"]: self.principal},
            "reviewerDelegation": delegation_policy,
            "machineProvenance": self.machine_policy,
            "stateSigner": self.state_signer,
            "jwks": validate_jwks_snapshot(
                self.snapshot, expected_snapshot_digest=self.snapshot_digest
            ),
        }
        self.approval_result = {
            "status": "verified",
            "decision": "APPROVE",
            "approvalDigest": D("6"),
            "requestDigest": D("7"),
            "controlPlaneDigest": self.control,
            "trustPolicyDigest": self.policy_digest,
            "jwksSnapshotDigest": self.snapshot_digest,
            "workflowExecutionCommit": self.commit,
            "candidateSourceCommit": self.commit,
            "componentDigests": self.components,
        }
        self.protected_inputs: dict[str, str] = {}
        self.criteria: list[dict[str, str]] = []

    def _subject(self, work_unit: str) -> SubjectBinding:
        return SubjectBinding(
            phase="P00",
            work_unit=work_unit,
            source_commit=self.commit,
            control_plane_digest=self.control,
            contract_digest=self.contracts[work_unit],
        )

    def _state_core(self, *, w01: str, w02: str, active: str | None) -> dict:
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control,
            "activePhase": "P00",
            "activeWorkUnit": active,
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": self.components[
                        "execution/phases/P00.yaml"
                    ],
                    "controlPlaneDigest": self.control,
                    "baseCommit": self.commit,
                    "startedAt": "2026-07-11T00:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": w01,
                            "contractDigest": self.contracts["P00.W01"],
                            "approvalDigest": D("6") if w01 != "NOT_STARTED" else None,
                            "sourceCommit": self.commit
                            if w01 != "NOT_STARTED"
                            else None,
                        },
                        "P00.W02": {
                            "status": w02,
                            "contractDigest": self.contracts["P00.W02"],
                            "approvalDigest": D("6")
                            if w02 in {"READY", "ACTIVE"}
                            else None,
                            "sourceCommit": self.commit
                            if w02 in {"READY", "ACTIVE"}
                            else None,
                        },
                    },
                }
            },
        }

    def _current(self, state_core: dict) -> VerifiedGenesisAnchorV2:
        state_digest = document_digest(state_core)
        view = {
            "schemaVersion": "urn:agentapi-doctor:execution:v1alpha2",
            **deepcopy(state_core),
            "stateDigest": state_digest,
            "chain": {"eventCount": 1, "headSequence": 0, "headDigest": D("0")},
            "attachments": [],
            "provenance": {"workflowRunId": "10", "workflowCheckRunId": "20"},
        }
        event = {
            "body": {
                "timestamp": "2026-07-11T11:00:00Z",
                "sourceCommit": self.commit,
            }
        }
        with patch(
            "tools.phasegate.state_chain_v2.verify_genesis_event_v2",
            return_value=view,
        ):
            return verify_genesis_anchor_v2(
                event=event,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                jwks_snapshot=self.snapshot,
                expected_control_plane_digest=self.control,
                expected_chain_head_digest=D("0"),
                contract_digests=self.components,
                repo_root=self.repo,
            )

    def _control_context(
        self, current: VerifiedGenesisAnchorV2, work_unit: str
    ):
        authority = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace=PROOF_NAMESPACE,
        )
        return derive_work_unit_control_context(
            current=current,
            oidc_authority=authority,
            repo_root=self.repo,
            work_unit=work_unit,
        )

    def _subject_doc(self, subject: SubjectBinding) -> dict[str, str]:
        return {
            "phase": subject.phase,
            "workUnit": subject.work_unit,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "contractDigest": subject.contract_digest,
        }

    def _ssh_signature(self, payload: bytes, namespace: str) -> str:
        path = self.root / "statement.json"
        signature_path = self.root / "statement.json.sig"
        path.write_bytes(payload)
        signature_path.unlink(missing_ok=True)
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(self.ssh_key),
                "-n",
                namespace,
                str(path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_text(encoding="ascii")

    def _ssh_envelope(self, schema: str, kind: str, namespace: str, body: dict) -> dict:
        statement = {"schemaVersion": schema, "kind": kind, "body": body}
        signature = self._ssh_signature(canonical_json_bytes(statement), namespace)
        envelope = {
            **statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": namespace,
                "principal": self.principal["identity"],
                "value": signature,
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    def _oidc_token(
        self,
        audience: str,
        verifier,
        *,
        run: int = 30,
        claim_overrides: dict[str, object] | None = None,
    ) -> str:
        issued = int(self.now.timestamp())
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "aud": audience,
            "iat": issued,
            "nbf": issued - 30,
            "exp": issued + 300,
            "jti": f"bundle-token-{run}",
            "run_id": str(run),
            "run_number": str(run),
            "check_run_id": str(run + 1),
            "run_attempt": "1",
            **dict(verifier.expected_claims),
        }
        claims.update(claim_overrides or {})
        header = {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"}
        signing_input = (
            b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        ).encode("ascii")
        signature = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.rsa_key)],
            input=signing_input,
            check=True,
            capture_output=True,
        ).stdout
        return signing_input.decode("ascii") + "." + b64url(signature)

    def _oidc_envelope(
        self, schema: str, kind: str, namespace: str, body: dict, verifier, *, run: int
    ) -> dict:
        statement = {"schemaVersion": schema, "kind": kind, "body": body}
        audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + sha256_bytes(
            canonical_json_bytes(statement)
        )
        envelope = {
            **statement,
            "signature": {
                "scheme": "github-actions-oidc-jwt-rs256-v1",
                "namespace": namespace,
                "principal": verifier.principal,
                "value": self._oidc_token(audience, verifier, run=run),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    def _root_callback(self, namespace: str):
        def verify(payload: bytes, signature: dict, supplied: str):
            self.assertEqual(supplied, namespace)
            verify_sshsig(
                payload,
                armored_signature=signature["value"],
                public_key=self.ssh_public,
                expected_namespace=namespace,
            )
            return VerifiedSignerResult(
                scheme="openssh-sshsig-v1",
                namespace=namespace,
                principal=self.principal["identity"],
                role="independent-reviewer",
                organization=self.principal["organization"],
                statement_digest=sha256_bytes(payload),
                authority_digest=self.policy_digest,
                source_commit=self.commit,
                control_plane_digest=self.control,
            )

        return verify

    def _witness(self, current: VerifiedGenesisAnchorV2) -> dict:
        body = {
            "witnessId": "witness-0001",
            "priorChainHeadDigest": current.chain_head_digest,
            "priorStateDigest": current.state_digest,
            "priorEventCount": current.event_count,
            "priorHeadSequence": current.head_sequence,
            "priorSourceCommit": current.head_source_commit,
            "controlPlaneDigest": self.control,
            "trustPolicyDigest": self.policy_digest,
            "witnessedAt": "2026-07-11T11:55:00Z",
            "validUntil": "2026-07-11T12:30:00Z",
            "reason": "Observed exact protected chain head before append.",
            "actor": {
                "principal": self.principal["identity"],
                "role": "independent-reviewer",
                "organization": self.principal["organization"],
            },
        }
        return self._ssh_envelope(
            "urn:agentapi-doctor:chain-head-witness:v1alpha1",
            "ChainHeadWitness",
            "agentapi-doctor/chain-head-witness/v1",
            body,
        )

    def _freeze_and_result(self, current: VerifiedGenesisAnchorV2):
        context = self._control_context(current, "P00.W01")
        subject = context.subject
        self.protected_inputs = dict(context.protected_inputs)
        self.criteria = criterion_documents(context.criteria)
        self.contract_approval = context.contract_approval_digest
        self.impact_map = context.impact_map_digest
        freeze_body = {
            "freezeId": "freeze-w01",
            "subject": self._subject_doc(subject),
            "contractApprovalDigest": self.contract_approval,
            "protectedInputs": dict(sorted(self.protected_inputs.items())),
            "criteria": self.criteria,
            "issuedAt": "2026-07-11T11:40:00Z",
            "actor": {
                "principal": self.principal["identity"],
                "role": "independent-reviewer",
                "organization": self.principal["organization"],
            },
            "authorityDigest": self.policy_digest,
        }
        raw_freeze = self._ssh_envelope(
            FREEZE_SCHEMA, FREEZE_KIND, FREEZE_NAMESPACE, freeze_body
        )
        freeze = verify_signed_protected_input_freeze(
            raw_freeze,
            expected_subject=subject,
            expected_contract_approval_digest=self.contract_approval,
            expected_protected_inputs=self.protected_inputs,
            expected_criteria=self.criteria,
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._root_callback(FREEZE_NAMESPACE),
        )
        stdout = canonical_json_bytes(
            {
                "schemaVersion": "urn:agentapi-doctor:phasegate-result:v1",
                "status": "pass",
                "reasonCode": "candidate_valid",
                "controlPlaneDigest": self.control,
                "componentCount": len(self.components),
            }
        )
        stderr = b""
        tool_facts = {
            key: list(value) if key == "unshareArguments" else value
            for key, value in context.executor_preflight.tool_facts
        }
        output_limit = 1024 * 1024
        facts = {
            "schemaVersion": "urn:agentapi-doctor:phasegate-result:v1",
            "status": "pass",
            "reasonCode": "candidate_valid",
            "controlPlaneDigest": self.control,
            "componentCount": len(self.components),
        }
        assertion = {
            "id": "candidate-semantically-valid",
            "status": "PASS",
            "evidenceDigest": document_digest(
                {
                    "schemaVersion": ASSERTION_SCHEMA,
                    "evaluator": self.criteria[0]["evaluator"],
                    "assertionId": "candidate-semantically-valid",
                    "status": "PASS",
                    "facts": facts,
                }
            ),
        }
        log_digest = sha256_bytes(stdout + b"\x00stderr\x00" + stderr)

        def command(label: str) -> dict:
            environment = {
                "schemaVersion": ENVIRONMENT_SCHEMA,
                "environmentClass": (
                    "development-isolated"
                    if label == "A"
                    else "clean-checkout-offline"
                ),
                "minimalEnvironment": True,
                "temporaryHome": True,
                "networkCredentialsInherited": False,
                "networkNamespace": "linux-user-net-unshare",
                "networkNamespaceFailClosed": True,
                "shell": False,
                "outputLimitBytes": output_limit,
            }
            return {
                "exitCode": 0,
                "durationMs": 1000,
                "startedAt": "2026-07-11T11:41:00Z",
                "finishedAt": "2026-07-11T11:41:01Z",
                "environmentDigest": _environment_digest(
                    label=label, environment=environment, tools=tool_facts
                ),
                "logDigest": log_digest,
                "artifactManifestDigest": _manifest_digest(
                    label=label,
                    evaluator=self.criteria[0]["evaluator"],
                    log_digest=log_digest,
                    output_bytes=len(stdout) + len(stderr),
                    exit_code=0,
                ),
                "sourceDirtyBeforeRun": False,
                "cleanCheckout": label == "B",
                "semanticAssertions": [assertion],
            }

        command_a = command("A")
        run_a = record_run(
            freeze=freeze,
            criterion_id=self.criteria[0]["id"],
            label="A",
            command_result=command_a,
        )
        command_b = command("B")
        run_b = record_run(
            freeze=freeze,
            criterion_id=self.criteria[0]["id"],
            label="B",
            command_result=command_b,
        )
        pair = combine_runs(
            freeze=freeze,
            criterion_id=self.criteria[0]["id"],
            run_a=run_a,
            run_b=run_b,
        )
        captured = [
            CapturedRunArtifact(
                label=label,
                stdout=stdout,
                stderr=stderr,
                command_result=command_result,
                evaluator_evidence=None,
                output_limit_bytes=output_limit,
                git_digest=tool_facts["gitDigest"],
                python_digest=tool_facts["pythonDigest"],
                unshare_digest=tool_facts["unshareDigest"],
            )
            for label, command_result in (("A", command_a), ("B", command_b))
        ]
        execution_artifact = serialize_execution_artifact_bundle(
            freeze=freeze,
            criterion_id=self.criteria[0]["id"],
            run_pair=pair,
            captured_runs=captured,
        )
        verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace="agentapi-doctor/criterion-result/machine/v1",
        )
        raw_result, verified_result = create_signed_machine_criterion_result(
            freeze=freeze,
            criterion_id=self.criteria[0]["id"],
            run_pair=pair,
            verifier=verifier,
            issued_at=self.now,
            token_provider=lambda audience: self._oidc_token(
                audience, verifier, run=40
            ),
        )
        return (
            subject,
            raw_freeze,
            raw_result,
            verified_result,
            json.loads(execution_artifact),
        )

    def _operation(
        self,
        *,
        operation: str,
        subject: SubjectBinding,
        current: VerifiedGenesisAnchorV2,
        from_state: str,
        to_state: str,
        prerequisites: list[str],
    ) -> dict:
        context = self._control_context(current, subject.work_unit)
        expected_criteria = criterion_documents(context.criteria)
        expected_inputs = dict(context.protected_inputs)
        return {
            "operationId": "operation-0001",
            "type": operation,
            "subject": self._subject_doc(subject),
            "fromState": from_state,
            "toState": to_state,
            "priorStateDigest": current.state_digest,
            "priorChainHeadDigest": current.chain_head_digest,
            "workflowExecutionCommit": self.commit,
            "contractApprovalDigest": context.contract_approval_digest,
            "impactMapDigest": context.impact_map_digest,
            "protectedInputsDigest": document_digest(
                {"protectedInputs": dict(sorted(expected_inputs.items()))}
            ),
            "criteriaDigest": document_digest({"criteria": expected_criteria}),
            "prerequisiteUnits": list(context.prerequisite_units),
        }

    def _bundle_bytes(self, document: dict) -> bytes:
        bundle = deepcopy(document)
        bundle["bundleDigest"] = document_digest(bundle)
        return canonical_json_bytes(bundle)

    def _convergence_bundle(self, current: VerifiedGenesisAnchorV2) -> bytes:
        subject, freeze, result, verified_result, execution_artifact = (
            self._freeze_and_result(current)
        )
        state_context = verify_work_unit_state_context(
            dict(current.state_core),
            expected_state_digest=current.state_digest,
            expected_chain_head_digest=current.chain_head_digest,
            expected_control_plane_digest=self.control,
            phase="P00",
            work_unit="P00.W01",
            expected_status="ACTIVE",
            expected_contract_digest=self.contracts["P00.W01"],
        )
        proof_verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace=PROOF_NAMESPACE,
        )
        projection = [
            {
                "criterionId": verified_result.criterion.criterion_id,
                "kind": verified_result.criterion.kind,
                "resultDigest": verified_result.attestation_digest,
                "evidenceDigest": verified_result.evidence_digest,
            }
        ]
        proof_body = {
            "proofId": "proof-w01-machine",
            "freezeDigest": freeze["attestationDigest"],
            "subject": self._subject_doc(subject),
            "fromState": "ACTIVE",
            "toState": "MACHINE_CONVERGED",
            "priorStateDigest": state_context.state_digest,
            "priorChainHeadDigest": state_context.chain_head_digest,
            "criterionResults": projection,
            "issuedAt": "2026-07-11T12:00:00Z",
            "actor": {
                "principal": proof_verifier.principal,
                "role": proof_verifier.role,
                "organization": proof_verifier.organization,
            },
            "authorityDigest": proof_verifier.authority_digest,
        }
        proof = self._oidc_envelope(
            PROOF_SCHEMA,
            PROOF_KIND,
            PROOF_NAMESPACE,
            proof_body,
            proof_verifier,
            run=50,
        )
        approval_body = {
            "approvalId": "approval-w01-machine",
            "proofDigest": proof["attestationDigest"],
            "freezeDigest": freeze["attestationDigest"],
            "subject": self._subject_doc(subject),
            "fromState": "ACTIVE",
            "toState": "MACHINE_CONVERGED",
            "priorStateDigest": state_context.state_digest,
            "priorChainHeadDigest": state_context.chain_head_digest,
            "criterionResults": projection,
            "decision": "APPROVE",
            "reason": "Independent approval of the exact machine proof.",
            "conflictOfInterest": {
                "independent": True,
                "statement": "Reviewed independently of the workflow signer.",
            },
            "issuedAt": "2026-07-11T11:59:00Z",
            "validUntil": "2026-07-11T12:20:00Z",
            "actor": {
                "principal": self.principal["identity"],
                "role": "independent-reviewer",
                "organization": self.principal["organization"],
            },
            "authorityDigest": self.policy_digest,
        }
        approval = self._ssh_envelope(
            TRANSITION_APPROVAL_SCHEMA,
            TRANSITION_APPROVAL_KIND,
            TRANSITION_APPROVAL_NAMESPACE,
            approval_body,
        )
        document = {
            "schemaVersion": BUNDLE_SCHEMA,
            "kind": BUNDLE_KIND,
            "bundleId": "bundle-w01-convergence",
            "operation": self._operation(
                operation=OP_CONVERGENCE,
                subject=subject,
                current=current,
                from_state="ACTIVE",
                to_state="MACHINE_CONVERGED",
                prerequisites=[],
            ),
            "chainHeadWitness": self._witness(current),
            "delegations": [],
            "revocations": [],
            "protectedInputFreeze": freeze,
            "criterionResults": [result],
            "lateBoundDatasetSelections": [],
            "machineExecutionArtifacts": [
                {
                    "criterionId": self.criteria[0]["id"],
                    "evidence": execution_artifact,
                }
            ],
            "externalFactEvidence": [],
            "proof": proof,
            "approval": approval,
        }
        return self._bundle_bytes(document)

    def _readiness_bundle(self, current: VerifiedGenesisAnchorV2) -> bytes:
        subject = self._subject("P00.W02")
        context = verify_work_unit_state_context(
            dict(current.state_core),
            expected_state_digest=current.state_digest,
            expected_chain_head_digest=current.chain_head_digest,
            expected_control_plane_digest=self.control,
            phase="P00",
            work_unit="P00.W02",
            expected_status="NOT_STARTED",
            expected_contract_digest=self.contracts["P00.W02"],
            prerequisite_units=("P00.W01",),
        )
        verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace=LIFECYCLE_PROOF_NAMESPACE,
        )
        prerequisites = [
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
        ]
        projection = {
            "transitionType": "READINESS",
            "subject": self._subject_doc(subject),
            "fromState": "NOT_STARTED",
            "toState": "READY",
            "priorStateDigest": context.state_digest,
            "priorChainHeadDigest": context.chain_head_digest,
            "contractApprovalDigest": self.contract_approval,
            "impactMapDigest": self.impact_map,
            "prerequisites": prerequisites,
            "reasonCode": "prerequisites-converged",
            "reason": "Every exact predecessor is converged under the protected state.",
            "blockerResolutionDigest": None,
            "invalidationKind": None,
            "invalidationDigest": None,
        }
        proof = self._oidc_envelope(
            LIFECYCLE_PROOF_SCHEMA,
            LIFECYCLE_PROOF_KIND,
            LIFECYCLE_PROOF_NAMESPACE,
            {
                "proofId": "proof-w02-readiness",
                **projection,
                "issuedAt": "2026-07-11T12:00:00Z",
                "actor": {
                    "principal": verifier.principal,
                    "role": verifier.role,
                    "organization": verifier.organization,
                },
                "authorityDigest": verifier.authority_digest,
            },
            verifier,
            run=60,
        )
        approval = self._ssh_envelope(
            LIFECYCLE_APPROVAL_SCHEMA,
            LIFECYCLE_APPROVAL_KIND,
            LIFECYCLE_APPROVAL_NAMESPACE,
            {
                "approvalId": "approval-w02-readiness",
                "proofDigest": proof["attestationDigest"],
                **projection,
                "decision": "APPROVE",
                "approvalReason": "Approve explicit W02 readiness only.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent of the protected workflow signer.",
                },
                "issuedAt": "2026-07-11T11:59:00Z",
                "validUntil": "2026-07-11T12:20:00Z",
                "actor": {
                    "principal": self.principal["identity"],
                    "role": "independent-reviewer",
                    "organization": self.principal["organization"],
                },
                "authorityDigest": self.policy_digest,
            },
        )
        return self._bundle_bytes(
            {
                "schemaVersion": BUNDLE_SCHEMA,
                "kind": BUNDLE_KIND,
                "bundleId": "bundle-w02-readiness",
                "operation": self._operation(
                    operation=OP_READINESS,
                    subject=subject,
                    current=current,
                    from_state="NOT_STARTED",
                    to_state="READY",
                    prerequisites=["P00.W01"],
                ),
                "chainHeadWitness": self._witness(current),
                "delegations": [],
                "revocations": [],
                "protectedInputFreeze": None,
                "criterionResults": [],
                "lateBoundDatasetSelections": [],
                "machineExecutionArtifacts": [],
                "externalFactEvidence": [],
                "proof": proof,
                "approval": approval,
            }
        )

    def _activation_bundle(self, current: VerifiedGenesisAnchorV2) -> bytes:
        subject = self._subject("P00.W02")
        context = verify_work_unit_state_context(
            dict(current.state_core),
            expected_state_digest=current.state_digest,
            expected_chain_head_digest=current.chain_head_digest,
            expected_control_plane_digest=self.control,
            phase="P00",
            work_unit="P00.W02",
            expected_status="READY",
            expected_contract_digest=self.contracts["P00.W02"],
            prerequisite_units=("P00.W01",),
        )
        verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace=ACTIVATION_PROOF_NAMESPACE,
        )
        prerequisites = [
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
        ]
        projection = {
            "subject": self._subject_doc(subject),
            "fromState": "READY",
            "toState": "ACTIVE",
            "priorStateDigest": context.state_digest,
            "priorChainHeadDigest": context.chain_head_digest,
            "contractApprovalDigest": self.contract_approval,
            "impactMapDigest": self.impact_map,
            "prerequisites": prerequisites,
        }
        proof = self._oidc_envelope(
            ACTIVATION_PROOF_SCHEMA,
            ACTIVATION_PROOF_KIND,
            ACTIVATION_PROOF_NAMESPACE,
            {
                "proofId": "proof-w02-activation",
                **projection,
                "issuedAt": "2026-07-11T12:00:00Z",
                "actor": {
                    "principal": verifier.principal,
                    "role": verifier.role,
                    "organization": verifier.organization,
                },
                "authorityDigest": verifier.authority_digest,
            },
            verifier,
            run=70,
        )
        approval = self._ssh_envelope(
            ACTIVATION_APPROVAL_SCHEMA,
            ACTIVATION_APPROVAL_KIND,
            ACTIVATION_APPROVAL_NAMESPACE,
            {
                "approvalId": "approval-w02-activation",
                "proofDigest": proof["attestationDigest"],
                **projection,
                "decision": "APPROVE",
                "reason": "Approve explicit W02 activation only.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Independent of the protected workflow signer.",
                },
                "issuedAt": "2026-07-11T11:59:00Z",
                "validUntil": "2026-07-11T12:20:00Z",
                "actor": {
                    "principal": self.principal["identity"],
                    "role": "independent-reviewer",
                    "organization": self.principal["organization"],
                },
                "authorityDigest": self.policy_digest,
            },
        )
        return self._bundle_bytes(
            {
                "schemaVersion": BUNDLE_SCHEMA,
                "kind": BUNDLE_KIND,
                "bundleId": "bundle-w02-activation",
                "operation": self._operation(
                    operation=OP_ACTIVATION,
                    subject=subject,
                    current=current,
                    from_state="READY",
                    to_state="ACTIVE",
                    prerequisites=["P00.W01"],
                ),
                "chainHeadWitness": self._witness(current),
                "delegations": [],
                "revocations": [],
                "protectedInputFreeze": None,
                "criterionResults": [],
                "lateBoundDatasetSelections": [],
                "machineExecutionArtifacts": [],
                "externalFactEvidence": [],
                "proof": proof,
                "approval": approval,
            }
        )

    def _verify(
        self,
        raw: bytes,
        *,
        current: VerifiedGenesisAnchorV2,
        operation: str,
        to_state: str,
        subject: SubjectBinding,
    ):
        context = self._control_context(current, subject.work_unit)
        return verify_serialized_authorization_bundle(
            raw,
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_workflow_execution_commit=self.commit,
            expected_operation=operation,
            expected_to_state=to_state,
            control_context=context,
            verification_time=self.now,
        )

    def test_real_sshsig_and_rsa_w01_machine_convergence_roundtrip(self) -> None:
        current = self._current(
            self._state_core(w01="ACTIVE", w02="NOT_STARTED", active="P00.W01")
        )
        raw = self._convergence_bundle(current)
        result = self._verify(
            raw,
            current=current,
            operation=OP_CONVERGENCE,
            to_state="MACHINE_CONVERGED",
            subject=self._subject("P00.W01"),
        )
        self.assertEqual(result.event_input.transition_type, "CONVERGENCE")
        self.assertEqual(result.event_input.to_state, "MACHINE_CONVERGED")
        self.assertIsNotNone(result.freeze)
        self.assertEqual(len(result.criterion_results), 1)
        self.assertEqual(
            result.criterion_results[0].criterion.criterion_id,
            "P00-M-BOOTSTRAP-CONTROL",
        )
        projection = result.machine_execution_results[0]
        raw_artifact = json.loads(raw)["machineExecutionArtifacts"][0]["evidence"]
        self.assertEqual(projection.criterion_id, "P00-M-BOOTSTRAP-CONTROL")
        self.assertEqual(
            projection.verification_pair_id,
            raw_artifact["runPair"]["verificationPairId"],
        )
        self.assertEqual(projection.run_pair_digest, raw_artifact["runPairDigest"])
        self.assertEqual(
            projection.execution_bundle_digest, raw_artifact["bundleDigest"]
        )
        self.assertEqual(
            projection.evaluator_dataset_freeze_digest,
            result.freeze.attestation_digest,
        )
        context = self._control_context(current, "P00.W01")
        self.assertEqual(
            (projection.dataset_catalog_path, projection.dataset_slot_digest),
            context.dataset_catalog_bindings[0][1:],
        )
        self.assertIsNone(projection.dataset_selection_digest)
        self.assertEqual(
            projection.verifier_authority_digest,
            result.criterion_results[0].signer.authority_digest,
        )
        self.assertIs(require_verified_serialized_bundle(result), result)
        with self.assertRaises(SerializedBundleError) as caught:
            require_verified_serialized_bundle(deepcopy(result))
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_attachment_roundtrip_reverifies_freeze_result_and_witness(self) -> None:
        current = self._current(
            self._state_core(w01="ACTIVE", w02="NOT_STARTED", active="P00.W01")
        )
        subject, freeze, result, _, execution_artifact = self._freeze_and_result(
            current
        )
        document = {
            "schemaVersion": BUNDLE_SCHEMA,
            "kind": BUNDLE_KIND,
            "bundleId": "bundle-w01-attachment",
            "operation": self._operation(
                operation=OP_ATTACHMENT,
                subject=subject,
                current=current,
                from_state="ACTIVE",
                to_state="ACTIVE",
                prerequisites=[],
            ),
            "chainHeadWitness": self._witness(current),
            "delegations": [],
            "revocations": [],
            "protectedInputFreeze": freeze,
            "criterionResults": [result],
            "lateBoundDatasetSelections": [],
            "machineExecutionArtifacts": [
                {
                    "criterionId": self.criteria[0]["id"],
                    "evidence": execution_artifact,
                }
            ],
            "externalFactEvidence": [],
            "proof": None,
            "approval": None,
        }
        verified = self._verify(
            self._bundle_bytes(document),
            current=current,
            operation=OP_ATTACHMENT,
            to_state="ACTIVE",
            subject=subject,
        )
        self.assertIsInstance(verified.event_input, VerifiedEvidenceAttachmentV2)
        self.assertEqual(len(verified.event_input.criterion_result_digests), 1)

    def test_real_sshsig_and_rsa_w02_readiness_and_activation_roundtrips(self) -> None:
        readiness_current = self._current(
            self._state_core(w01="CONVERGED", w02="NOT_STARTED", active=None)
        )
        subject = self._subject("P00.W02")
        readiness = self._verify(
            self._readiness_bundle(readiness_current),
            current=readiness_current,
            operation=OP_READINESS,
            to_state="READY",
            subject=subject,
        )
        self.assertEqual(readiness.event_input.transition_type, "READINESS")
        self.assertEqual(readiness.event_input.to_state, "READY")

        activation_current = self._current(
            self._state_core(w01="CONVERGED", w02="READY", active=None)
        )
        activation = self._verify(
            self._activation_bundle(activation_current),
            current=activation_current,
            operation=OP_ACTIVATION,
            to_state="ACTIVE",
            subject=subject,
        )
        self.assertEqual(activation.event_input.transition_type, "ACTIVATION")
        self.assertEqual(activation.event_input.to_state, "ACTIVE")

    def test_canonical_schema_digest_head_namespace_and_commit_mutants_fail(
        self,
    ) -> None:
        current = self._current(
            self._state_core(w01="ACTIVE", w02="NOT_STARTED", active="P00.W01")
        )
        raw = self._convergence_bundle(current)
        parsed = json.loads(raw)
        mutants: list[tuple[str, bytes]] = []
        mutants.append(("noncanonical_bundle", raw + b"\n"))
        extra = deepcopy(parsed)
        extra["unexpected"] = True
        mutants.append(("invalid_bundle_schema", canonical_json_bytes(extra)))
        missing = deepcopy(parsed)
        missing.pop("approval")
        mutants.append(("invalid_bundle_schema", canonical_json_bytes(missing)))
        digest = deepcopy(parsed)
        digest["bundleDigest"] = D("9")
        mutants.append(("bundle_digest_mismatch", canonical_json_bytes(digest)))
        stale = deepcopy(parsed)
        stale["chainHeadWitness"]["body"]["priorChainHeadDigest"] = D("8")
        stale["bundleDigest"] = document_digest(stale, omit_field="bundleDigest")
        mutants.append(("chain_witness_digest_mismatch", canonical_json_bytes(stale)))
        namespace = deepcopy(parsed)
        namespace["proof"]["signature"]["namespace"] = ACTIVATION_PROOF_NAMESPACE
        namespace["proof"]["attestationDigest"] = document_digest(
            namespace["proof"], omit_field="attestationDigest"
        )
        namespace["bundleDigest"] = document_digest(
            namespace, omit_field="bundleDigest"
        )
        mutants.append(
            ("signature_namespace_mismatch", canonical_json_bytes(namespace))
        )
        token_commit = deepcopy(parsed)
        proof_verifier = build_oidc_provenance_verifier(
            current=current,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_source_commit=self.commit,
            current_workflow_execution_commit=self.commit,
            expected_namespace=PROOF_NAMESPACE,
        )
        proof_statement = {
            key: token_commit["proof"][key] for key in ("schemaVersion", "kind", "body")
        }
        proof_audience = OIDC_PROVENANCE_AUDIENCE_PREFIX + sha256_bytes(
            canonical_json_bytes(proof_statement)
        )
        token_commit["proof"]["signature"]["value"] = self._oidc_token(
            proof_audience,
            proof_verifier,
            run=80,
            claim_overrides={"workflow_sha": "0" * 40, "sha": "0" * 40},
        )
        token_commit["proof"]["attestationDigest"] = document_digest(
            token_commit["proof"], omit_field="attestationDigest"
        )
        token_commit["bundleDigest"] = document_digest(
            token_commit, omit_field="bundleDigest"
        )
        mutants.append(("oidc_claim_mismatch", canonical_json_bytes(token_commit)))
        commit = deepcopy(parsed)
        commit["operation"]["workflowExecutionCommit"] = "0" * 40
        commit["bundleDigest"] = document_digest(commit, omit_field="bundleDigest")
        mutants.append(("operation_binding_mismatch", canonical_json_bytes(commit)))
        for expected, candidate in mutants:
            with self.subTest(expected=expected):
                with self.assertRaises(SerializedBundleError) as caught:
                    self._verify(
                        candidate,
                        current=current,
                        operation=OP_CONVERGENCE,
                        to_state="MACHINE_CONVERGED",
                        subject=self._subject("P00.W01"),
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_raw_execution_and_external_fact_evidence_sets_are_closed(self) -> None:
        current = self._current(
            self._state_core(w01="ACTIVE", w02="NOT_STARTED", active="P00.W01")
        )
        parsed = json.loads(self._convergence_bundle(current))

        def encoded(document: dict) -> bytes:
            document["bundleDigest"] = document_digest(
                document, omit_field="bundleDigest"
            )
            return canonical_json_bytes(document)

        missing_machine = deepcopy(parsed)
        missing_machine["machineExecutionArtifacts"] = []

        extra_external = deepcopy(parsed)
        extra_external["externalFactEvidence"] = [
            {"criterionId": "P00-X-CROSSPLATFORM", "evidence": {}}
        ]

        tampered_stdout = deepcopy(parsed)
        tampered_stdout["machineExecutionArtifacts"][0]["evidence"]["runs"][0][
            "stdout"
        ]["data"] = base64.b64encode(b"{}").decode("ascii")
        inner_artifact = tampered_stdout["machineExecutionArtifacts"][0]["evidence"]
        inner_artifact["bundleDigest"] = document_digest(
            inner_artifact, omit_field="bundleDigest"
        )

        copied_run_pair = deepcopy(parsed)
        copied_run_pair["criterionResults"][0]["body"]["runPair"]["runA"][
            "environmentDigest"
        ] = D("9")

        cases = (
            (missing_machine, "machine_execution_artifact_set_mismatch"),
            (extra_external, "external_fact_evidence_set_mismatch"),
            (tampered_stdout, "raw_output_digest_mismatch"),
            (copied_run_pair, "machine_execution_binding_mismatch"),
        )
        for mutant, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(SerializedBundleError) as caught:
                    self._verify(
                        encoded(mutant),
                        current=current,
                        operation=OP_CONVERGENCE,
                        to_state="MACHINE_CONVERGED",
                        subject=self._subject("P00.W01"),
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_duplicate_key_random_documents_wrong_role_and_unsupported_phase_fail(
        self,
    ) -> None:
        current = self._current(
            self._state_core(w01="ACTIVE", w02="NOT_STARTED", active="P00.W01")
        )
        raw = self._convergence_bundle(current)
        duplicate = raw.replace(b'{"approval":', b'{"approval":null,"approval":', 1)
        with self.assertRaises(SerializedBundleError) as caught:
            self._verify(
                duplicate,
                current=current,
                operation=OP_CONVERGENCE,
                to_state="MACHINE_CONVERGED",
                subject=self._subject("P00.W01"),
            )
        self.assertEqual(caught.exception.code, "duplicate_bundle_key")

        parsed = json.loads(raw)
        parsed["delegations"] = [{"attestationDigest": D("9")}]
        parsed["bundleDigest"] = document_digest(parsed, omit_field="bundleDigest")
        with self.assertRaises(SerializedBundleError):
            self._verify(
                canonical_json_bytes(parsed),
                current=current,
                operation=OP_CONVERGENCE,
                to_state="MACHINE_CONVERGED",
                subject=self._subject("P00.W01"),
            )

        wrong_role = json.loads(raw)
        wrong_role["approval"]["body"]["actor"]["role"] = "authorized-maintainer"
        statement = {
            key: wrong_role["approval"][key]
            for key in ("schemaVersion", "kind", "body")
        }
        wrong_role["approval"]["signature"]["value"] = self._ssh_signature(
            canonical_json_bytes(statement), TRANSITION_APPROVAL_NAMESPACE
        )
        wrong_role["approval"]["attestationDigest"] = document_digest(
            wrong_role["approval"], omit_field="attestationDigest"
        )
        wrong_role["bundleDigest"] = document_digest(
            wrong_role, omit_field="bundleDigest"
        )
        with self.assertRaises(SerializedBundleError) as caught:
            self._verify(
                canonical_json_bytes(wrong_role),
                current=current,
                operation=OP_CONVERGENCE,
                to_state="MACHINE_CONVERGED",
                subject=self._subject("P00.W01"),
            )
        self.assertEqual(caught.exception.code, "actor_principal_mismatch")

        copied_context = deepcopy(self._control_context(current, "P00.W01"))
        with self.assertRaises(SerializedBundleError) as caught:
            verify_serialized_authorization_bundle(
                raw,
                current=current,
                policy_result=self.policy_result,
                approved_jwks_snapshot=self.snapshot,
                repo_root=self.repo,
                current_workflow_execution_commit=self.commit,
                expected_operation=OP_CONVERGENCE,
                expected_to_state="MACHINE_CONVERGED",
                control_context=copied_context,
                verification_time=self.now,
            )
        self.assertEqual(caught.exception.code, "unverified_internal_result")


if __name__ == "__main__":
    unittest.main()
