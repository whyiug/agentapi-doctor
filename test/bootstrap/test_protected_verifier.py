from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.main import _protected_artifact_layout  # noqa: E402
from tools.phasegate.protected import (  # noqa: E402
    APPROVAL_KIND,
    APPROVAL_NAMESPACE,
    APPROVAL_SCHEMA,
    POLICY_KIND,
    POLICY_SCHEMA,
    PREVIOUS_CANDIDATE_COMMIT,
    PREVIOUS_CONTROL_PLANE_DIGEST,
    PREVIOUS_REQUEST_DIGEST,
    STATE_EVENT_KIND,
    STATE_EVENT_NAMESPACE,
    STATE_EVENT_SCHEMA,
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    _state_core_digest,
    canonical_state_view_bytes,
    compare_state_view,
    document_digest,
    load_strict_document,
    replay_state_events,
    trusted_ssh_keygen_digest,
    validate_trust_policy,
    verify_control_plane_approval,
)


FIXED_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
CONTROL_DIGEST = "sha256:" + "1" * 64
SOURCE_COMMIT = "a" * 40


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is required")
class ProtectedVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="agentapi-doctor-protected-verifier-"
        )
        self.root = Path(self.temporary.name)
        self.message_counter = 0
        self.reviewer_key = self._generate_key("reviewer")
        self.workflow_key = self._generate_key("workflow")
        self.rogue_key = self._generate_key("rogue")
        _, self.ssh_keygen_digest = trusted_ssh_keygen_digest()
        self.policy = self._configured_policy()
        self.policy_digest = document_digest(self.policy)
        self.request = self._request()
        self.request_digest = document_digest(self.request)
        self.approval = self._approval()
        self.approval_result = self._verify_approval()
        self.contract_digests = {
            "execution/phases/P00.yaml": "sha256:" + "2" * 64,
            **{
                f"execution/work-units/P00.W0{index}.yaml": (
                    "sha256:" + str(index + 2) * 64
                )
                for index in range(1, 6)
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _generate_key(self, name: str) -> Path:
        path = self.root / "keys" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                shutil.which("ssh-keygen") or "ssh-keygen",
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

    def _public_key(self, private_key: Path) -> str:
        fields = private_key.with_suffix(".pub").read_text(encoding="utf-8").split()
        return " ".join(fields[:2])

    def _principal(
        self, identity: str, role: str, capability: str, private_key: Path
    ) -> dict:
        public_key = self._public_key(private_key)
        return {
            "identity": identity,
            "organization": (
                "independent-review-test"
                if capability == "approve-control-plane"
                else "agentapi-doctor-test"
            ),
            "role": role,
            "publicKey": public_key,
            "fingerprint": _ssh_public_key_fingerprint(public_key, identity),
            "capabilities": [capability],
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2027-01-01T00:00:00Z",
        }

    def _configured_policy(self) -> dict:
        return {
            "schemaVersion": POLICY_SCHEMA,
            "kind": POLICY_KIND,
            "policyId": "P00-protected-verifier",
            "revision": 1,
            "policyStatus": "configured",
            "controlPlaneDigest": CONTROL_DIGEST,
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
                ),
                self._principal(
                    "workflow@test.invalid",
                    "protected-workflow",
                    "sign-state-event",
                    self.workflow_key,
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
                "NOT_STARTED": ["READY", "REJECTED", "SUPERSEDED"],
                "READY": ["ACTIVE", "REJECTED", "SUPERSEDED"],
                "ACTIVE": [
                    "MACHINE_CONVERGED",
                    "BLOCKED",
                    "REJECTED",
                    "SUPERSEDED",
                ],
                "BLOCKED": ["ACTIVE", "REJECTED", "SUPERSEDED"],
                "MACHINE_CONVERGED": [
                    "CONVERGED",
                    "WAITING_EXTERNAL",
                    "REVIEW_PENDING",
                    "REJECTED",
                ],
                "WAITING_EXTERNAL": [
                    "CONVERGED",
                    "REVIEW_PENDING",
                    "REJECTED",
                ],
                "REVIEW_PENDING": ["CONVERGED", "REJECTED"],
                "CONVERGED": ["REJECTED"],
                "REJECTED": ["READY"],
                "SUPERSEDED": [],
            },
        }

    def _request(self) -> dict:
        decisions = [
            {"id": "digest-projection", "question": "Accept the projection?"},
            {"id": "protected-verifier-format", "question": "Accept verifier?"},
        ]
        return {
            "schemaVersion": "urn:agentapi-doctor:bootstrap-request:v1alpha2",
            "kind": "BootstrapControlPlaneReviewRequest",
            "requestId": "P00.B00-R2",
            "revision": 2,
            "previousRequest": {
                "requestId": "P00.B00",
                "revision": 1,
                "requestDigest": PREVIOUS_REQUEST_DIGEST,
                "controlPlaneDigest": PREVIOUS_CONTROL_PLANE_DIGEST,
                "candidateSourceCommit": PREVIOUS_CANDIDATE_COMMIT,
            },
            "requestStatus": "pending_review",
            "candidate": {
                "baseCommit": PREVIOUS_CANDIDATE_COMMIT,
                "candidateSourceCommit": SOURCE_COMMIT,
                "gitObjectFormat": "sha1",
                "canonicalPlanPath": "agentapi-doctor-Plan.md",
                "controlPlaneDigest": CONTROL_DIGEST,
            },
            "componentDigests": {},
            "digestGroups": {"gateRunnerDigest": "sha256:" + "9" * 64},
            "antiPlaceholderTests": {},
            "protectedVerifierTests": {},
            "diff": {},
            "decisionsRequested": decisions,
            "limitations": [],
            "nextAuthorizedAction": "independent review",
        }

    def _sign(self, statement: dict, private_key: Path, namespace: str) -> str:
        self.message_counter += 1
        message = self.root / f"message-{self.message_counter:04d}.json"
        message.write_bytes(canonical_json_bytes(statement))
        subprocess.run(
            [
                shutil.which("ssh-keygen") or "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                namespace,
                str(message),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        signature = message.with_name(message.name + ".sig").read_text(encoding="utf-8")
        message.unlink()
        message.with_name(message.name + ".sig").unlink()
        return signature

    def _seal_envelope(
        self,
        envelope: dict,
        *,
        private_key: Path,
        principal: str,
        namespace: str,
        digest_field: str,
    ) -> dict:
        result = deepcopy(envelope)
        signed = {
            "schemaVersion": result["schemaVersion"],
            "kind": result["kind"],
            "body": result["body"],
        }
        result["signature"] = {
            "scheme": "openssh-sshsig-v1",
            "namespace": namespace,
            "principal": principal,
            "value": self._sign(signed, private_key, namespace),
        }
        result[digest_field] = "sha256:" + "0" * 64
        result[digest_field] = document_digest(result, omit_field=digest_field)
        return result

    def _approval(self, **overrides: object) -> dict:
        body = {
            "attestationId": "approval-test-001",
            "requestId": "P00.B00-R2",
            "requestRevision": 2,
            "requestDigest": self.request_digest,
            "decision": "APPROVE",
            "candidateSourceCommit": SOURCE_COMMIT,
            "controlPlaneDigest": CONTROL_DIGEST,
            "digestGroups": deepcopy(self.request["digestGroups"]),
            "reviewedDecisionIds": [
                item["id"] for item in self.request["decisionsRequested"]
            ],
            "scope": {"phase": "P00", "bootstrapId": "P00.B00"},
            "reason": "Independent synthetic test review.",
            "validFrom": "2026-07-01T00:00:00Z",
            "validUntil": "2026-08-01T00:00:00Z",
            "constraints": [],
            "conflictOfInterest": {
                "independent": True,
                "statement": "No conflict in this synthetic fixture.",
            },
            "reviewer": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-review-test",
            },
            "trustPolicyDigest": self.policy_digest,
            "sshKeygenDigest": self.ssh_keygen_digest,
        }
        body.update(overrides)
        return self._seal_envelope(
            {
                "schemaVersion": APPROVAL_SCHEMA,
                "kind": APPROVAL_KIND,
                "body": body,
            },
            private_key=self.reviewer_key,
            principal=body["reviewer"]["principal"],
            namespace=APPROVAL_NAMESPACE,
            digest_field="attestationDigest",
        )

    def _verify_approval(self, approval: dict | None = None, **pins: str) -> dict:
        return verify_control_plane_approval(
            request=self.request,
            approval=approval or self.approval,
            policy=self.policy,
            expected_policy_digest=pins.get(
                "expected_policy_digest", self.policy_digest
            ),
            expected_control_plane_digest=pins.get(
                "expected_control_plane_digest", CONTROL_DIGEST
            ),
            expected_candidate_source_commit=pins.get(
                "expected_candidate_source_commit", SOURCE_COMMIT
            ),
            expected_request_digest=pins.get(
                "expected_request_digest", self.request_digest
            ),
            expected_ssh_keygen_digest=pins.get(
                "expected_ssh_keygen_digest", self.ssh_keygen_digest
            ),
            now=FIXED_NOW,
        )

    def _assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _initial_core(self) -> dict:
        units = {}
        for index in range(1, 6):
            unit = f"P00.W0{index}"
            units[unit] = {
                "status": "ACTIVE" if index == 1 else "NOT_STARTED",
                "contractDigest": self.contract_digests[
                    f"execution/work-units/{unit}.yaml"
                ],
                "approvalDigest": (
                    self.approval_result["approvalDigest"] if index == 1 else None
                ),
                "sourceCommit": SOURCE_COMMIT if index == 1 else None,
            }
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": CONTROL_DIGEST,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": self.contract_digests[
                        "execution/phases/P00.yaml"
                    ],
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "baseCommit": SOURCE_COMMIT,
                    "startedAt": "2026-07-11T12:00:00Z",
                    "workUnits": units,
                }
            },
        }

    def _genesis(self, **body_overrides: object) -> dict:
        core = self._initial_core()
        payload = {
            "requestId": "P00.B00-R2",
            "requestDigest": self.request_digest,
            "approvalDigest": self.approval_result["approvalDigest"],
            "planVersion": "1.0",
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "aggregateContractDigest": self.contract_digests[
                "execution/phases/P00.yaml"
            ],
            "workUnitContractDigests": {
                f"P00.W0{index}": self.contract_digests[
                    f"execution/work-units/P00.W0{index}.yaml"
                ]
                for index in range(1, 6)
            },
            "resultingStateDigest": _state_core_digest(core),
        }
        body = {
            "eventType": "Genesis",
            "eventId": "evt-00000000",
            "sequence": 0,
            "previousDigest": None,
            "timestamp": "2026-07-11T12:00:00Z",
            "actor": {
                "principal": "workflow@test.invalid",
                "role": "protected-workflow",
                "organization": "agentapi-doctor-test",
            },
            "sourceCommit": SOURCE_COMMIT,
            "controlPlaneDigest": CONTROL_DIGEST,
            "trustPolicyDigest": self.policy_digest,
            "reasonCode": "approved-bootstrap-genesis",
            "reason": "Synthetic signed Genesis for verifier tests.",
            "payload": payload,
        }
        body.update(body_overrides)
        return self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": body,
            },
            private_key=self.workflow_key,
            principal=body["actor"]["principal"],
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )

    def _replay(self, events: list[dict], **overrides: object) -> dict:
        return replay_state_events(
            events=events,
            policy=self.policy,
            approval_result=self.approval_result,
            expected_policy_digest=self.policy_digest,
            expected_control_plane_digest=CONTROL_DIGEST,
            expected_chain_head_digest=overrides.get(
                "expected_chain_head_digest", events[-1]["eventDigest"]
            ),
            expected_ssh_keygen_digest=self.ssh_keygen_digest,
            contract_digests=self.contract_digests,
            repo_root=self.root,
            prior_events=overrides.get("prior_events", ()),
        )

    def test_pending_policy_cannot_authorize(self) -> None:
        pending = deepcopy(self.policy)
        pending["policyStatus"] = "pending_trust_roots"
        pending["principals"] = []
        digest = document_digest(pending)
        self._assert_error(
            "trust_policy_not_configured",
            validate_trust_policy,
            pending,
            expected_policy_digest=digest,
            expected_control_plane_digest=CONTROL_DIGEST,
        )

    def test_external_policy_pin_rejects_replaced_roster(self) -> None:
        replaced = deepcopy(self.policy)
        replaced["principals"][0] = self._principal(
            "rogue@test.invalid",
            "independent-reviewer",
            "approve-control-plane",
            self.rogue_key,
        )
        self._assert_error(
            "trust_policy_digest_mismatch",
            validate_trust_policy,
            replaced,
            expected_policy_digest=self.policy_digest,
            expected_control_plane_digest=CONTROL_DIGEST,
        )

    def test_one_key_cannot_approve_and_sign_state(self) -> None:
        dual_role = deepcopy(self.policy)
        dual_role["principals"][0]["capabilities"] = [
            "approve-control-plane",
            "sign-state-event",
        ]
        digest = document_digest(dual_role)
        self._assert_error(
            "separation_of_duties_violation",
            validate_trust_policy,
            dual_role,
            expected_policy_digest=digest,
            expected_control_plane_digest=CONTROL_DIGEST,
        )

    def test_valid_approval_is_verified_without_state_write(self) -> None:
        before = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        result = self._verify_approval()
        after = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        self.assertEqual(result["decision"], "APPROVE")
        self.assertEqual(result["candidateSourceCommit"], SOURCE_COMMIT)
        self.assertEqual(before, after)

    def test_signed_approval_tamper_is_rejected(self) -> None:
        tampered = deepcopy(self.approval)
        tampered["body"]["reason"] = "Changed after signing."
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        self._assert_error("signature_invalid", self._verify_approval, tampered)

    def test_path_substitution_cannot_replace_ssh_keygen(self) -> None:
        fake_directory = self.root / "fake-path"
        fake_directory.mkdir()
        fake = fake_directory / "ssh-keygen"
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        tampered = deepcopy(self.approval)
        tampered["body"]["reason"] = "The signature no longer matches."
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        original_path = os.environ.get("PATH")
        os.environ["PATH"] = str(fake_directory)
        try:
            self._assert_error("signature_invalid", self._verify_approval, tampered)
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path

    def test_parent_directory_symlink_input_is_rejected(self) -> None:
        real = self.root / "real-input"
        real.mkdir()
        write_json(real / "request.json", self.request)
        alias = self.root / "aliased-input"
        alias.symlink_to(real, target_is_directory=True)
        self._assert_error(
            "unsafe_input_path",
            load_strict_document,
            alias / "request.json",
            label="request",
        )

    def test_approval_bundle_cannot_hide_state_artifacts(self) -> None:
        transitions = self.root / "execution/transitions"
        transitions.mkdir(parents=True)
        parsed = SimpleNamespace(
            command="approval-verify",
            approval=str(self.root / "external-approval.json"),
        )
        self._assert_error(
            "unexpected_protected_artifact",
            _protected_artifact_layout,
            parsed,
            self.root,
        )

    def test_approval_namespace_replay_is_rejected(self) -> None:
        tampered = deepcopy(self.approval)
        tampered["signature"]["namespace"] = STATE_EVENT_NAMESPACE
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        self._assert_error(
            "signature_namespace_mismatch", self._verify_approval, tampered
        )

    def test_unlisted_approval_signer_is_rejected(self) -> None:
        rogue = deepcopy(self.approval)
        rogue["body"]["reviewer"] = {
            "principal": "rogue@test.invalid",
            "role": "independent-reviewer",
            "organization": "agentapi-doctor-test",
        }
        rogue = self._seal_envelope(
            {
                "schemaVersion": APPROVAL_SCHEMA,
                "kind": APPROVAL_KIND,
                "body": rogue["body"],
            },
            private_key=self.rogue_key,
            principal="rogue@test.invalid",
            namespace=APPROVAL_NAMESPACE,
            digest_field="attestationDigest",
        )
        self._assert_error("signer_not_allowed", self._verify_approval, rogue)

    def test_claimed_reviewer_role_must_match_policy(self) -> None:
        role_drift = self._approval(
            reviewer={
                "principal": "reviewer@test.invalid",
                "role": "protected-workflow",
                "organization": "agentapi-doctor-test",
            }
        )
        self._assert_error("role_not_authorized", self._verify_approval, role_drift)

    def test_request_digest_pin_is_required(self) -> None:
        self._assert_error(
            "request_digest_mismatch",
            self._verify_approval,
            expected_request_digest="sha256:" + "f" * 64,
        )

    def test_candidate_source_commit_pin_is_required(self) -> None:
        self._assert_error(
            "candidate_commit_unbound",
            self._verify_approval,
            expected_candidate_source_commit="c" * 40,
        )

    def test_expired_approval_is_rejected(self) -> None:
        expired = self._approval(validUntil="2026-07-10T00:00:00Z")
        self._assert_error("approval_outside_validity", self._verify_approval, expired)

    def test_valid_signed_genesis_replays_to_unique_active_unit(self) -> None:
        genesis = self._genesis()
        view = self._replay([genesis])
        self.assertEqual(view["activePhase"], "P00")
        self.assertEqual(view["activeWorkUnit"], "P00.W01")
        self.assertEqual(view["chain"]["headDigest"], genesis["eventDigest"])

    def test_active_rejection_clears_pointers_without_false_conflict(self) -> None:
        genesis = self._genesis()
        prior = self._initial_core()
        resulting = deepcopy(prior)
        unit = resulting["phases"]["P00"]["workUnits"]["P00.W01"]
        unit["status"] = "REJECTED"
        resulting["activeWorkUnit"] = None
        payload = {
            "scope": "workUnit",
            "phase": "P00",
            "workUnit": "P00.W01",
            "fromStatus": "ACTIVE",
            "toStatus": "REJECTED",
            "contractDigest": self.contract_digests[
                "execution/work-units/P00.W01.yaml"
            ],
            "evidenceDigest": None,
            "approvalDigest": None,
            "priorStateDigest": _state_core_digest(prior),
            "resultingStateDigest": _state_core_digest(resulting),
        }
        transition = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": {
                    "eventType": "StateTransition",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": genesis["eventDigest"],
                    "timestamp": "2026-07-11T12:00:01Z",
                    "actor": {
                        "principal": "workflow@test.invalid",
                        "role": "protected-workflow",
                        "organization": "agentapi-doctor-test",
                    },
                    "sourceCommit": SOURCE_COMMIT,
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "trustPolicyDigest": self.policy_digest,
                    "reasonCode": "control-plane-invalidation",
                    "reason": "Synthetic rejection clears the active unit.",
                    "payload": payload,
                },
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        view = self._replay([genesis, transition])
        self.assertIsNone(view["activeWorkUnit"])
        self.assertIsNone(view["pendingWorkUnit"])

    def test_second_genesis_is_rejected(self) -> None:
        genesis = self._genesis()
        second = self._genesis(
            eventId="evt-00000001",
            sequence=1,
            previousDigest=genesis["eventDigest"],
            timestamp="2026-07-11T12:00:01Z",
        )
        self._assert_error("invalid_genesis", self._replay, [genesis, second])

    def test_event_chain_reordering_is_rejected(self) -> None:
        genesis = self._genesis()
        moved = deepcopy(genesis)
        moved["body"]["sequence"] = 1
        moved["body"]["eventId"] = "evt-00000001"
        moved = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": moved["body"],
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        self._assert_error("event_order_mismatch", self._replay, [moved])

    def test_external_chain_head_detects_signed_tail_truncation(self) -> None:
        genesis = self._genesis()
        self._assert_error(
            "chain_head_digest_mismatch",
            self._replay,
            [genesis],
            expected_chain_head_digest="sha256:" + "e" * 64,
        )

    def test_prior_chain_prefix_cannot_be_rewritten(self) -> None:
        genesis = self._genesis()
        prior = deepcopy(genesis)
        prior["body"]["reason"] = "Protected prior history."
        self._assert_error(
            "event_history_rewritten",
            self._replay,
            [genesis],
            prior_events=[prior],
        )

    def test_illegal_state_transition_is_rejected(self) -> None:
        genesis = self._genesis()
        core = self._initial_core()
        payload = {
            "scope": "workUnit",
            "phase": "P00",
            "workUnit": "P00.W01",
            "fromStatus": "ACTIVE",
            "toStatus": "CONVERGED",
            "contractDigest": self.contract_digests[
                "execution/work-units/P00.W01.yaml"
            ],
            "evidenceDigest": "sha256:" + "d" * 64,
            "approvalDigest": self.approval_result["approvalDigest"],
            "priorStateDigest": _state_core_digest(core),
            "resultingStateDigest": _state_core_digest(core),
        }
        transition = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": {
                    "eventType": "StateTransition",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": genesis["eventDigest"],
                    "timestamp": "2026-07-11T12:00:01Z",
                    "actor": {
                        "principal": "workflow@test.invalid",
                        "role": "protected-workflow",
                        "organization": "agentapi-doctor-test",
                    },
                    "sourceCommit": SOURCE_COMMIT,
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "trustPolicyDigest": self.policy_digest,
                    "reasonCode": "test-invalid-transition",
                    "reason": "This signed event must still fail semantic replay.",
                    "payload": payload,
                },
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        self._assert_error(
            "invalid_state_transition", self._replay, [genesis, transition]
        )

    def test_machine_transition_requires_approved_evidence_result(self) -> None:
        genesis = self._genesis()
        prior = self._initial_core()
        resulting = deepcopy(prior)
        unit = resulting["phases"]["P00"]["workUnits"]["P00.W01"]
        unit["status"] = "MACHINE_CONVERGED"
        resulting["activeWorkUnit"] = None
        resulting["pendingWorkUnit"] = "P00.W01"
        payload = {
            "scope": "workUnit",
            "phase": "P00",
            "workUnit": "P00.W01",
            "fromStatus": "ACTIVE",
            "toStatus": "MACHINE_CONVERGED",
            "contractDigest": self.contract_digests[
                "execution/work-units/P00.W01.yaml"
            ],
            "evidenceDigest": "sha256:" + "d" * 64,
            "approvalDigest": None,
            "priorStateDigest": _state_core_digest(prior),
            "resultingStateDigest": _state_core_digest(resulting),
        }
        transition = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": {
                    "eventType": "StateTransition",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": genesis["eventDigest"],
                    "timestamp": "2026-07-11T12:00:01Z",
                    "actor": {
                        "principal": "workflow@test.invalid",
                        "role": "protected-workflow",
                        "organization": "agentapi-doctor-test",
                    },
                    "sourceCommit": SOURCE_COMMIT,
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "trustPolicyDigest": self.policy_digest,
                    "reasonCode": "machine-evidence-verified",
                    "reason": "Synthetic evidence moves the active unit to pending.",
                    "payload": payload,
                },
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        self._assert_error(
            "unverified_transition_evidence",
            self._replay,
            [genesis, transition],
        )

    def test_state_transition_cannot_consume_random_approval_digest(self) -> None:
        genesis = self._genesis()
        prior = self._initial_core()
        resulting = deepcopy(prior)
        unit = resulting["phases"]["P00"]["workUnits"]["P00.W02"]
        unit["status"] = "READY"
        unit["sourceCommit"] = SOURCE_COMMIT
        unit["approvalDigest"] = "sha256:" + "e" * 64
        payload = {
            "scope": "workUnit",
            "phase": "P00",
            "workUnit": "P00.W02",
            "fromStatus": "NOT_STARTED",
            "toStatus": "READY",
            "contractDigest": self.contract_digests[
                "execution/work-units/P00.W02.yaml"
            ],
            "evidenceDigest": None,
            "approvalDigest": "sha256:" + "e" * 64,
            "priorStateDigest": _state_core_digest(prior),
            "resultingStateDigest": _state_core_digest(resulting),
        }
        transition = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": {
                    "eventType": "StateTransition",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": genesis["eventDigest"],
                    "timestamp": "2026-07-11T12:00:01Z",
                    "actor": {
                        "principal": "workflow@test.invalid",
                        "role": "protected-workflow",
                        "organization": "agentapi-doctor-test",
                    },
                    "sourceCommit": SOURCE_COMMIT,
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "trustPolicyDigest": self.policy_digest,
                    "reasonCode": "unverified-ready-approval",
                    "reason": "A signed event cannot replace approval verification.",
                    "payload": payload,
                },
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        self._assert_error(
            "unverified_transition_approval",
            self._replay,
            [genesis, transition],
        )

    def test_evidence_attachment_is_bound_and_does_not_change_state(self) -> None:
        genesis = self._genesis()
        core = self._initial_core()
        pointer = "execution/gates/p00/evidence/index.json"
        evidence_pointer = "execution/gates/p00/evidence/result.json"
        evidence_path = self.root / evidence_pointer
        write_json(evidence_path, {"result": "PASS", "fixture": "synthetic"})
        evidence_digest = sha256_bytes(evidence_path.read_bytes())
        evidence_schema = "evidence-schema://bootstrap/control-plane-report/v1"
        write_json(
            self.root / "execution/evidence-schemas/catalog.yaml",
            {
                "controlPlaneDigest": CONTROL_DIGEST,
                "schemas": [
                    {
                        "id": evidence_schema,
                        "kind": "MACHINE",
                        "status": "implemented",
                    }
                ],
            },
        )
        index = {
            "schemaVersion": "urn:agentapi-doctor:evidence-index:v1alpha1",
            "phase": "P00",
            "workUnit": "P00.W01",
            "sourceCommit": SOURCE_COMMIT,
            "controlPlaneDigest": CONTROL_DIGEST,
            "evidenceKind": "RunPair",
            "evidenceSchema": evidence_schema,
            "evidenceDigest": evidence_digest,
            "evidencePointer": evidence_pointer,
            "verificationPairId": "pair-test-001",
        }
        index_path = self.root / pointer
        write_json(index_path, index)
        payload = {
            "phase": "P00",
            "workUnit": "P00.W01",
            "evidenceKind": index["evidenceKind"],
            "evidenceSchema": index["evidenceSchema"],
            "evidenceDigest": index["evidenceDigest"],
            "evidenceIndexPointer": pointer,
            "evidenceIndexDigest": sha256_bytes(index_path.read_bytes()),
            "verificationPairId": index["verificationPairId"],
            "stateDigest": _state_core_digest(core),
        }
        attachment = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": {
                    "eventType": "EvidenceAttachment",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": genesis["eventDigest"],
                    "timestamp": "2026-07-11T12:00:01Z",
                    "actor": {
                        "principal": "workflow@test.invalid",
                        "role": "protected-workflow",
                        "organization": "agentapi-doctor-test",
                    },
                    "sourceCommit": SOURCE_COMMIT,
                    "controlPlaneDigest": CONTROL_DIGEST,
                    "trustPolicyDigest": self.policy_digest,
                    "reasonCode": "attach-test-evidence",
                    "reason": "Attach a bound synthetic evidence index.",
                    "payload": payload,
                },
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        view = self._replay([genesis, attachment])
        self.assertEqual(view["stateDigest"], _state_core_digest(core))
        self.assertEqual(len(view["attachments"]), 1)

        index["evidenceSchema"] = "evidence-schema://unknown/fixed-pass/v1"
        write_json(index_path, index)
        unknown_payload = deepcopy(payload)
        unknown_payload["evidenceSchema"] = index["evidenceSchema"]
        unknown_payload["evidenceIndexDigest"] = sha256_bytes(index_path.read_bytes())
        unknown_body = deepcopy(attachment["body"])
        unknown_body["payload"] = unknown_payload
        unknown = self._seal_envelope(
            {
                "schemaVersion": STATE_EVENT_SCHEMA,
                "kind": STATE_EVENT_KIND,
                "body": unknown_body,
            },
            private_key=self.workflow_key,
            principal="workflow@test.invalid",
            namespace=STATE_EVENT_NAMESPACE,
            digest_field="eventDigest",
        )
        self._assert_error("unknown_evidence_schema", self._replay, [genesis, unknown])

    def test_hand_edited_phase_state_view_is_rejected(self) -> None:
        view = self._replay([self._genesis()])
        path = self.root / "phase-state.yaml"
        path.write_bytes(canonical_state_view_bytes(view))
        compare_state_view(path, view)
        path.write_text("{}\n", encoding="utf-8")
        self._assert_error("phase_state_view_drift", compare_state_view, path, view)


if __name__ == "__main__":
    unittest.main()
