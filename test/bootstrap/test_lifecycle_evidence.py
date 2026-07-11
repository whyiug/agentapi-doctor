"""Adversarial tests for raw lifecycle evidence and identity seals."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
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

from tools.phasegate.digest import (  # noqa: E402
    canonical_json_bytes,
    compute_control_plane_digest,
    sha256_bytes,
)
from tools.phasegate.chain_witness import (  # noqa: E402
    CHAIN_WITNESS_KIND,
    CHAIN_WITNESS_NAMESPACE,
    CHAIN_WITNESS_SCHEMA,
)
from tools.phasegate.lifecycle_evidence import (  # noqa: E402
    BLOCKER_RESOLUTION_KIND,
    BLOCKER_RESOLUTION_NAMESPACE,
    BLOCKER_RESOLUTION_SCHEMA,
    INVALIDATION_KIND,
    INVALIDATION_NAMESPACE,
    INVALIDATION_SCHEMA,
    OIDC_SCHEME,
    SSHSIG_SCHEME,
    SUPERSESSION_KIND,
    SUPERSESSION_NAMESPACE,
    SUPERSESSION_SCHEMA,
    LifecycleEvidenceError,
    compute_invalidation_projection,
    invalidation_body,
    require_verified_blocker_resolution,
    require_verified_invalidation_evidence,
    require_verified_supersession_approval,
    verify_blocker_resolution,
    verify_invalidation_evidence,
    verify_supersession_approval,
)
from tools.phasegate.lifecycle_bundle import (  # noqa: E402
    BUNDLE_KIND,
    BUNDLE_SCHEMA,
    OP_CONTROL_INVALIDATION,
    OP_INVALIDATION,
    OP_RESUME,
    OP_SUPERSESSION,
    LifecycleBundleError,
    lifecycle_chain_head_witness_for_state_writer,
    lifecycle_primary_evidence_for_writer,
    lifecycle_transition_for_state_writer,
    require_verified_lifecycle_bundle,
    verify_lifecycle_authorization_bundle,
)
from tools.phasegate.protected import (  # noqa: E402
    _ssh_public_key_fingerprint,
    document_digest,
)
from tools.phasegate.provenance import (  # noqa: E402
    LIFECYCLE_APPROVAL_KIND,
    LIFECYCLE_APPROVAL_NAMESPACE,
    LIFECYCLE_APPROVAL_SCHEMA,
    LIFECYCLE_PROOF_KIND,
    LIFECYCLE_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_SCHEMA,
    SubjectBinding,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    _mark_verified as _mark_provenance_verified,
    verify_work_unit_state_context,
)
from tools.phasegate.provenance_writer import (  # noqa: E402
    ProvenanceWriterError,
    create_signed_lifecycle_proof,
)
from tools.phasegate.sshsig import verify_sshsig  # noqa: E402


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def D(character: str) -> str:
    return "sha256:" + character * 64


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@unittest.skipUnless(
    shutil.which("ssh-keygen") and shutil.which("openssl") and shutil.which("git"),
    "OpenSSH, OpenSSL, and Git are required",
)
class LifecycleEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="lifecycle-evidence-")
        cls.root = Path(cls.temporary.name)
        cls.counter = 0
        cls.reviewer_key = cls.root / "reviewer"
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
                str(cls.reviewer_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        cls.rsa_private = cls.root / "workflow.pem"
        cls.rsa_public = cls.root / "workflow.pub.pem"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(cls.rsa_private),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                str(cls.rsa_private),
                "-pubout",
                "-out",
                str(cls.rsa_public),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        cls._create_git_fixture()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout.strip()

    @classmethod
    def _create_git_fixture(cls) -> None:
        cls.repo = cls.root / "repo"
        (cls.repo / "execution").mkdir(parents=True)
        (cls.repo / "execution/work-units").mkdir()
        (cls.repo / "evidence").mkdir()
        (cls.repo / "rfcs").mkdir()
        (cls.repo / "tools").mkdir()
        (cls.repo / "src").mkdir()
        subprocess.run(
            ["/usr/bin/git", "init", "-q", str(cls.repo)],
            check=True,
            timeout=10,
        )
        cls._git("config", "user.email", "test@example.invalid")
        cls._git("config", "user.name", "Lifecycle Test")
        placeholder = "sha256:__CONTROL_PLANE_DIGEST__"
        inputs = [
            {
                "path": "execution/control-plane-inputs.yaml",
                "kind": "manifest",
                "required": True,
            },
            {
                "path": "execution/impact-map.yaml",
                "kind": "catalog",
                "required": True,
            },
            {
                "path": "execution/work-units/P00.W01.yaml",
                "kind": "contract",
                "required": True,
            },
            {
                "path": "rfcs/0042-replace-contract.md",
                "kind": "text",
                "required": True,
            },
            {"path": "tools/check.py", "kind": "text", "required": True},
        ]
        manifest = {
            "schemaVersion": "urn:test:manifest:v1",
            "kind": "TestManifest",
            "controlPlaneDigest": placeholder,
            "inputs": inputs,
        }
        impact = {
            "schemaVersion": "urn:agentapi-doctor:impact-map:v1",
            "kind": "ImpactMapCandidate",
            "mapStatus": "approved",
            "controlPlaneDigest": placeholder,
            "defaultImpact": "manual-review-required",
            "stateEffects": {
                "ACTIVE": "BLOCKED",
                "READY": "REJECTED",
                "MACHINE_CONVERGED": "REJECTED",
                "WAITING_EXTERNAL": "REJECTED",
                "REVIEW_PENDING": "REJECTED",
                "CONVERGED": "REJECTED",
                "NOT_STARTED": "REJECTED_OR_SUPERSEDED",
            },
            "mappings": [
                {
                    "id": "application",
                    "paths": ["src/**"],
                    "affected": ["P00.W01", "P00"],
                    "reason": "Application changes invalidate exact work evidence.",
                },
                {
                    "id": "control",
                    "paths": ["tools/**"],
                    "affected": ["P00.W01", "P00"],
                    "reason": "Verifier changes invalidate the protected control plane.",
                },
            ],
            "spellingOnlyPolicy": "Independent semantic review is required.",
        }
        (cls.repo / "execution/control-plane-inputs.yaml").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "execution/impact-map.yaml").write_text(
            json.dumps(impact, indent=2) + "\n", encoding="utf-8"
        )
        contract = {
            "schemaVersion": "urn:test:contract:v1",
            "kind": "TestContract",
            "id": "P00.W01",
            "controlPlaneDigest": placeholder,
            "objective": "Base contract",
        }
        (cls.repo / "execution/work-units/P00.W01.yaml").write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "rfcs/0042-replace-contract.md").write_text(
            "# RFC 0042\n\nBase decision text.\n", encoding="utf-8"
        )
        (cls.repo / "evidence/blocker-resolution.json").write_text(
            '{"status":"resolved","regression":"pass"}\n', encoding="utf-8"
        )
        (cls.repo / "tools/check.py").write_text("VALUE = 1\n", encoding="utf-8")
        aggregate, _ = compute_control_plane_digest(cls.repo, inputs)
        manifest["controlPlaneDigest"] = aggregate
        impact["controlPlaneDigest"] = aggregate
        contract["controlPlaneDigest"] = aggregate
        (cls.repo / "execution/control-plane-inputs.yaml").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "execution/impact-map.yaml").write_text(
            json.dumps(impact, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "execution/work-units/P00.W01.yaml").write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
        observed, components = compute_control_plane_digest(cls.repo, inputs)
        if observed != aggregate:
            raise AssertionError("fixture control-plane digest did not converge")
        cls.control_digest = aggregate
        cls.components = {item["path"]: item["digest"] for item in components}
        cls.impact_digest = cls.components["execution/impact-map.yaml"]
        cls._git("add", ".")
        cls._git("commit", "-q", "-m", "base")
        cls.base_commit = cls._git("rev-parse", "HEAD")
        (cls.repo / "src/app.py").write_text("VALUE = 1\n", encoding="utf-8")
        cls._git("add", "src/app.py")
        cls._git("commit", "-q", "-m", "impact-only")
        cls.impact_commit = cls._git("rev-parse", "HEAD")
        (cls.repo / "tools/check.py").write_text("VALUE = 2\n", encoding="utf-8")
        cls._git("add", "tools/check.py")
        cls._git("commit", "-q", "-m", "control-drift")
        cls.control_commit = cls._git("rev-parse", "HEAD")
        main_branch = cls._git("branch", "--show-current")
        cls._git("switch", "-q", "-c", "replacement", cls.base_commit)
        contract["objective"] = "RFC-approved replacement contract"
        (cls.repo / "execution/work-units/P00.W01.yaml").write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "rfcs/0042-replace-contract.md").write_text(
            "# RFC 0042\n\nExplicitly supersede P00.W01 with the replacement contract.\n",
            encoding="utf-8",
        )
        replacement_control, _ = compute_control_plane_digest(cls.repo, inputs)
        manifest["controlPlaneDigest"] = replacement_control
        impact["controlPlaneDigest"] = replacement_control
        contract["controlPlaneDigest"] = replacement_control
        (cls.repo / "execution/control-plane-inputs.yaml").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "execution/impact-map.yaml").write_text(
            json.dumps(impact, indent=2) + "\n", encoding="utf-8"
        )
        (cls.repo / "execution/work-units/P00.W01.yaml").write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
        replacement_observed, replacement_components = compute_control_plane_digest(
            cls.repo, inputs
        )
        if replacement_observed != replacement_control:
            raise AssertionError("replacement control-plane digest did not converge")
        cls.replacement_control_digest = replacement_control
        cls.replacement_components = {
            item["path"]: item["digest"] for item in replacement_components
        }
        cls._git("add", ".")
        cls._git("commit", "-q", "-m", "replacement")
        cls.replacement_commit = cls._git("rev-parse", "HEAD")
        cls._git("switch", "-q", main_branch)

    @classmethod
    def _ssh_sign(cls, payload: bytes, namespace: str) -> str:
        cls.counter += 1
        message = cls.root / f"ssh-message-{cls.counter}.json"
        message.write_bytes(payload)
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(cls.reviewer_key),
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
        signature = signature_path.read_text(encoding="utf-8")
        signature_path.unlink()
        message.unlink()
        return signature

    @classmethod
    def _ssh_envelope(
        cls,
        schema: str,
        kind: str,
        namespace: str,
        body: dict,
    ) -> dict:
        statement = {"schemaVersion": schema, "kind": kind, "body": body}
        signature = cls._ssh_sign(canonical_json_bytes(statement), namespace)
        envelope = {
            **statement,
            "signature": {
                "scheme": SSHSIG_SCHEME,
                "namespace": namespace,
                "principal": "reviewer@example.invalid",
                "value": signature,
            },
            "attestationDigest": None,
        }
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    def _chain_policy(self) -> dict:
        public_key = " ".join(
            self.reviewer_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )
        return {
            "digest": D("a"),
            "principals": {
                "maintainer@example.invalid": {
                    "identity": "maintainer@example.invalid",
                    "organization": "maintainer-org",
                    "roles": ["authorized-maintainer"],
                    "publicKey": public_key,
                    "fingerprint": _ssh_public_key_fingerprint(
                        public_key, "test.chainWitness.publicKey"
                    ),
                    "capabilities": ["witness-chain-head"],
                    "validFrom": "2026-07-11T00:00:00Z",
                    "validUntil": "2026-07-12T00:00:00Z",
                }
            },
            "revokedFingerprints": set(),
        }

    def _chain_witness(self, state, *, body_overrides: dict | None = None) -> dict:
        body = {
            "witnessId": "lifecycle-chain-witness",
            "priorChainHeadDigest": state.chain_head_digest,
            "priorStateDigest": state.state_digest,
            "priorEventCount": 3,
            "priorHeadSequence": 2,
            "priorSourceCommit": self.base_commit,
            "controlPlaneDigest": state.control_plane_digest,
            "trustPolicyDigest": D("a"),
            "witnessedAt": "2026-07-11T11:45:00Z",
            "validUntil": "2026-07-11T12:45:00Z",
            "reason": "Observed the exact current chain head before lifecycle append.",
            "actor": {
                "principal": "maintainer@example.invalid",
                "role": "authorized-maintainer",
                "organization": "maintainer-org",
            },
        }
        body.update(body_overrides or {})
        statement = {
            "schemaVersion": CHAIN_WITNESS_SCHEMA,
            "kind": CHAIN_WITNESS_KIND,
            "body": body,
        }
        signature = self._ssh_sign(
            canonical_json_bytes(statement), CHAIN_WITNESS_NAMESPACE
        )
        envelope = {
            **statement,
            "signature": {
                "scheme": SSHSIG_SCHEME,
                "namespace": CHAIN_WITNESS_NAMESPACE,
                "principal": "maintainer@example.invalid",
                "value": signature,
            },
            "attestationDigest": None,
        }
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    @classmethod
    def _oidc_envelope(
        cls,
        schema: str,
        kind: str,
        namespace: str,
        body: dict,
    ) -> dict:
        statement = {"schemaVersion": schema, "kind": kind, "body": body}
        payload = canonical_json_bytes(statement)
        claims = {
            "namespace": namespace,
            "principal": "github-actions:lifecycle-test",
            "role": body["actor"]["role"],
            "organization": body["actor"]["organization"],
            "statementDigest": sha256_bytes(payload),
            "authorityDigest": body["authorityDigest"],
            "sourceCommit": body["subject"]["sourceCommit"],
            "controlPlaneDigest": body["subject"]["controlPlaneDigest"],
        }
        header = {"alg": "RS256", "kid": "lifecycle-test", "typ": "JWT"}
        signing_input = (
            _b64url(canonical_json_bytes(header))
            + "."
            + _b64url(canonical_json_bytes(claims))
        ).encode("ascii")
        signature = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(cls.rsa_private),
            ],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        token = signing_input.decode("ascii") + "." + _b64url(signature)
        envelope = {
            **statement,
            "signature": {
                "scheme": OIDC_SCHEME,
                "namespace": namespace,
                "principal": "github-actions:lifecycle-test",
                "value": token,
            },
            "attestationDigest": None,
        }
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    @classmethod
    def _verify_rsa_token(cls, token: str) -> dict:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        cls.counter += 1
        message = cls.root / f"rsa-message-{cls.counter}"
        signature = cls.root / f"rsa-signature-{cls.counter}"
        message.write_bytes(f"{encoded_header}.{encoded_claims}".encode("ascii"))
        signature.write_bytes(_b64decode(encoded_signature))
        completed = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(cls.rsa_public),
                "-signature",
                str(signature),
                str(message),
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        message.unlink()
        signature.unlink()
        if completed.returncode != 0:
            raise AssertionError("test OIDC signature verification failed")
        return json.loads(_b64decode(encoded_claims))

    def _subject(self, source_commit: str) -> SubjectBinding:
        return SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=source_commit,
            control_plane_digest=self.control_digest,
            contract_digest=D("2"),
        )

    def _state(self, status: str, *, source_commit: str | None = None):
        source = source_commit or self.base_commit
        pending = status in {
            "BLOCKED",
            "MACHINE_CONVERGED",
            "WAITING_EXTERNAL",
            "REVIEW_PENDING",
        }
        active = status == "ACTIVE"
        core = {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01" if active else None,
            "pendingWorkUnit": "P00.W01" if pending else None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": D("1"),
                    "controlPlaneDigest": self.control_digest,
                    "baseCommit": self.base_commit,
                    "startedAt": "2026-07-11T09:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": status,
                            "contractDigest": D("2"),
                            "approvalDigest": D("3"),
                            "sourceCommit": (
                                None
                                if status in {"NOT_STARTED", "READY"}
                                else source
                            ),
                        }
                    },
                }
            },
        }
        return verify_work_unit_state_context(
            core,
            expected_state_digest=document_digest(core),
            expected_chain_head_digest=D("4"),
            expected_control_plane_digest=self.control_digest,
            phase="P00",
            work_unit="P00.W01",
            expected_status=status,
            expected_contract_digest=D("2"),
        )

    def _ssh_verifier(
        self,
        subject: SubjectBinding,
        *,
        namespace: str,
        role: str = "independent-reviewer",
    ):
        public_key = " ".join(
            self.reviewer_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )

        def verify(payload: bytes, signature: dict, observed_namespace: str):
            verify_sshsig(
                payload,
                armored_signature=signature["value"],
                public_key=public_key,
                expected_namespace=observed_namespace,
            )
            return VerifiedSignerResult(
                scheme=SSHSIG_SCHEME,
                namespace=namespace,
                principal="reviewer@example.invalid",
                role=role,
                organization="review-org",
                statement_digest=sha256_bytes(payload),
                authority_digest=D("5"),
                source_commit=subject.source_commit,
                control_plane_digest=subject.control_plane_digest,
            )

        return verify

    def _oidc_verifier(
        self,
        subject: SubjectBinding,
        *,
        role: str = "protected-workflow",
    ):
        def verify(payload: bytes, signature: dict, namespace: str):
            claims = self._verify_rsa_token(signature["value"])
            expected = {
                "namespace": namespace,
                "principal": signature["principal"],
                "role": role,
                "organization": "github-actions",
                "statementDigest": sha256_bytes(payload),
                "authorityDigest": D("5"),
                "sourceCommit": subject.source_commit,
                "controlPlaneDigest": subject.control_plane_digest,
            }
            if claims != expected:
                raise AssertionError("test OIDC claims differ from exact bindings")
            return VerifiedSignerResult(
                scheme=OIDC_SCHEME,
                namespace=namespace,
                principal=signature["principal"],
                role=role,
                organization="github-actions",
                statement_digest=sha256_bytes(payload),
                authority_digest=D("5"),
                source_commit=subject.source_commit,
                control_plane_digest=subject.control_plane_digest,
            )

        return verify

    def _blocker_body(self, subject: SubjectBinding, state) -> dict:
        return {
            "resolutionId": "resolution-1",
            "subject": {
                "phase": subject.phase,
                "workUnit": subject.work_unit,
                "sourceCommit": subject.source_commit,
                "controlPlaneDigest": subject.control_plane_digest,
                "contractDigest": subject.contract_digest,
            },
            "fromState": "BLOCKED",
            "toState": "ACTIVE",
            "priorStateDigest": state.state_digest,
            "priorChainHeadDigest": state.chain_head_digest,
            "artifactDigestAlgorithm": "git-blob-content-sha256-v1",
            "resolutionArtifacts": [
                {
                    "path": "evidence/blocker-resolution.json",
                    "digest": sha256_bytes(
                        (self.repo / "evidence/blocker-resolution.json").read_bytes()
                    ),
                    "validator": "evaluator://blocker-resolution/v1",
                    "assertions": ["blocker-cleared", "regression-pass"],
                }
            ],
            "reasonCode": "approved-blocker-resolution",
            "reason": "Independent review confirmed the blocker and regression are resolved.",
            "conflictOfInterest": {
                "independent": True,
                "requesterPrincipal": "agent@example.invalid",
                "requesterOrganization": "implementation-org",
                "declaration": "No financial, employment, or reporting conflict exists.",
            },
            "issuedAt": "2026-07-11T11:00:00Z",
            "validUntil": "2026-07-12T11:00:00Z",
            "actor": {
                "principal": "reviewer@example.invalid",
                "role": "independent-reviewer",
                "organization": "review-org",
            },
            "authorityDigest": D("5"),
        }

    @staticmethod
    def _subject_document(subject: SubjectBinding) -> dict[str, str]:
        return {
            "phase": subject.phase,
            "workUnit": subject.work_unit,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "contractDigest": subject.contract_digest,
        }

    def _lifecycle_proof_document(self, state, subject, primary) -> dict:
        if hasattr(primary, "artifacts"):
            transition_type = "RESUME"
            to_state = "ACTIVE"
            blocker_digest = primary.attestation_digest
            invalidation_kind = None
            invalidation_digest = None
        else:
            transition_type = "INVALIDATION"
            to_state = primary.to_state
            blocker_digest = None
            invalidation_kind = primary.invalidation_kind
            invalidation_digest = primary.attestation_digest
        body = {
            "proofId": f"bundle-{transition_type.lower()}-proof",
            "transitionType": transition_type,
            "subject": self._subject_document(subject),
            "fromState": state.status,
            "toState": to_state,
            "priorStateDigest": state.state_digest,
            "priorChainHeadDigest": state.chain_head_digest,
            "contractApprovalDigest": D("7"),
            "impactMapDigest": self.impact_digest,
            "prerequisites": [],
            "reasonCode": primary.reason_code,
            "reason": primary.reason,
            "blockerResolutionDigest": blocker_digest,
            "invalidationKind": invalidation_kind,
            "invalidationDigest": invalidation_digest,
            "issuedAt": "2026-07-11T12:00:00Z",
            "actor": {
                "principal": "github-actions:lifecycle-test",
                "role": "protected-workflow",
                "organization": "github-actions",
            },
            "authorityDigest": D("5"),
        }
        return self._oidc_envelope(
            LIFECYCLE_PROOF_SCHEMA,
            LIFECYCLE_PROOF_KIND,
            LIFECYCLE_PROOF_NAMESPACE,
            body,
        )

    def _lifecycle_approval_document(self, proof_document: dict) -> dict:
        proof = proof_document["body"]
        projection_fields = (
            "transitionType",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractApprovalDigest",
            "impactMapDigest",
            "prerequisites",
            "reasonCode",
            "reason",
            "blockerResolutionDigest",
            "invalidationKind",
            "invalidationDigest",
        )
        body = {
            "approvalId": "bundle-lifecycle-approval",
            "proofDigest": proof_document["attestationDigest"],
            **{field: deepcopy(proof[field]) for field in projection_fields},
            "decision": "APPROVE",
            "approvalReason": "Independent review approves the exact lifecycle proof.",
            "conflictOfInterest": {
                "independent": True,
                "statement": "Reviewer is independent from implementation and workflow identities.",
            },
            "issuedAt": "2026-07-11T11:30:00Z",
            "validUntil": "2026-07-12T11:30:00Z",
            "actor": {
                "principal": "reviewer@example.invalid",
                "role": "independent-reviewer",
                "organization": "review-org",
            },
            "authorityDigest": D("5"),
        }
        return self._ssh_envelope(
            LIFECYCLE_APPROVAL_SCHEMA,
            LIFECYCLE_APPROVAL_KIND,
            LIFECYCLE_APPROVAL_NAMESPACE,
            body,
        )

    def _bundle_bytes(
        self,
        *,
        operation: str,
        state,
        subject: SubjectBinding,
        to_state: str,
        primary_document: dict,
        proof_document: dict,
        approval_document: dict,
        chain_head_witness: dict | None = None,
    ) -> bytes:
        bundle = {
            "schemaVersion": BUNDLE_SCHEMA,
            "kind": BUNDLE_KIND,
            "bundleId": f"bundle-{operation}",
            "operation": operation,
            "chainHeadWitness": (
                self._chain_witness(state)
                if chain_head_witness is None
                else chain_head_witness
            ),
            "subject": self._subject_document(subject),
            "fromState": state.status,
            "toState": to_state,
            "priorStateDigest": state.state_digest,
            "priorChainHeadDigest": state.chain_head_digest,
            "baseCommit": state.recorded_source_commit,
            "headCommit": subject.source_commit,
            "contractApprovalDigest": D("7"),
            "impactMapDigest": self.impact_digest,
            "primaryEvidence": primary_document,
            "proof": proof_document,
            "approval": approval_document,
            "bundleDigest": None,
        }
        bundle["bundleDigest"] = document_digest(bundle, omit_field="bundleDigest")
        return canonical_json_bytes(bundle)

    def _import_lifecycle_bundle(
        self,
        raw: bytes,
        *,
        state,
        subject: SubjectBinding,
        operation: str,
    ):
        return verify_lifecycle_authorization_bundle(
            raw,
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            expected_operation=operation,
            expected_contract_approval_digest=D("7"),
            expected_impact_map_digest=self.impact_digest,
            approved_component_digests=self.components,
            policy_result=self._chain_policy(),
            expected_prior_event_count=3,
            expected_prior_head_sequence=2,
            expected_prior_source_commit=self.base_commit,
            expected_trust_policy_digest=D("a"),
            expected_human_authority_digest=D("5"),
            expected_invalidation_authority_digest=D("5"),
            expected_proof_authority_digest=D("5"),
            blocker_signer_verifier=(
                self._ssh_verifier(
                    subject, namespace=BLOCKER_RESOLUTION_NAMESPACE
                )
                if operation == OP_RESUME
                else None
            ),
            invalidation_signer_verifier=(
                self._oidc_verifier(subject)
                if operation in {OP_INVALIDATION, OP_CONTROL_INVALIDATION}
                else None
            ),
            proof_signer_verifier=self._oidc_verifier(subject),
            approval_signer_verifier=self._ssh_verifier(
                subject, namespace=LIFECYCLE_APPROVAL_NAMESPACE
            ),
            verification_time=NOW,
        )

    def _resume_bundle_material(self):
        state = self._state("BLOCKED")
        subject = self._subject(self.impact_commit)
        primary_document = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            self._blocker_body(subject, state),
        )
        primary = verify_blocker_resolution(
            primary_document,
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            expected_authority_digest=D("5"),
            signer_verifier=self._ssh_verifier(
                subject, namespace=BLOCKER_RESOLUTION_NAMESPACE
            ),
            verification_time=NOW,
        )
        proof = self._lifecycle_proof_document(state, subject, primary)
        approval = self._lifecycle_approval_document(proof)
        raw = self._bundle_bytes(
            operation=OP_RESUME,
            state=state,
            subject=subject,
            to_state="ACTIVE",
            primary_document=primary_document,
            proof_document=proof,
            approval_document=approval,
        )
        return state, subject, primary_document, proof, approval, raw

    def _impact_bundle_material(self):
        state, subject, head, _computation, primary_document = (
            self._invalidation_document(head=self.impact_commit)
        )
        primary = self._verify_invalidation(
            state, subject, head, primary_document
        )
        proof = self._lifecycle_proof_document(state, subject, primary)
        approval = self._lifecycle_approval_document(proof)
        raw = self._bundle_bytes(
            operation=OP_INVALIDATION,
            state=state,
            subject=subject,
            to_state="BLOCKED",
            primary_document=primary_document,
            proof_document=proof,
            approval_document=approval,
        )
        return state, subject, primary_document, proof, approval, raw

    def test_blocker_resolution_is_ssh_verified_state_bound_and_identity_sealed(self) -> None:
        subject = self._subject(self.impact_commit)
        state = self._state("BLOCKED")
        document = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            self._blocker_body(subject, state),
        )
        result = verify_blocker_resolution(
            document,
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            expected_authority_digest=D("5"),
            signer_verifier=self._ssh_verifier(
                subject, namespace=BLOCKER_RESOLUTION_NAMESPACE
            ),
            verification_time=NOW,
        )
        self.assertEqual(result.to_state, "ACTIVE")
        self.assertEqual(result.artifacts[0].assertions[-1], "regression-pass")
        self.assertIs(require_verified_blocker_resolution(result), result)
        with self.assertRaises(LifecycleEvidenceError) as caught:
            require_verified_blocker_resolution(replace(result))
        self.assertEqual(caught.exception.code, "unverified_lifecycle_evidence")
        object.__setattr__(result, "reason", "post-verification mutation")
        with self.assertRaises(LifecycleEvidenceError) as caught:
            require_verified_blocker_resolution(result)
        self.assertEqual(caught.exception.code, "mutated_lifecycle_evidence")

    def test_blocker_rejects_tamper_wrong_state_role_and_empty_manifest(self) -> None:
        subject = self._subject(self.impact_commit)
        state = self._state("BLOCKED")
        body = self._blocker_body(subject, state)
        valid = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            body,
        )
        tampered = deepcopy(valid)
        tampered["body"]["reason"] += " tampered"
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        cases = [
            (tampered, state, self._ssh_verifier(subject, namespace=BLOCKER_RESOLUTION_NAMESPACE)),
            (valid, self._state("ACTIVE"), self._ssh_verifier(subject, namespace=BLOCKER_RESOLUTION_NAMESPACE)),
            (
                valid,
                state,
                self._ssh_verifier(
                    subject,
                    namespace=BLOCKER_RESOLUTION_NAMESPACE,
                    role="protected-workflow",
                ),
            ),
        ]
        for document, context, verifier in cases:
            with self.subTest(status=context.status):
                with self.assertRaises(Exception):
                    verify_blocker_resolution(
                        document,
                        repo_root=self.repo,
                        state_context=context,
                        expected_subject=subject,
                        expected_authority_digest=D("5"),
                        signer_verifier=verifier,
                        verification_time=NOW,
                    )
        empty_body = self._blocker_body(subject, state)
        empty_body["resolutionArtifacts"] = []
        empty = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            empty_body,
        )
        with self.assertRaises(LifecycleEvidenceError) as caught:
            verify_blocker_resolution(
                empty,
                repo_root=self.repo,
                state_context=state,
                expected_subject=subject,
                expected_authority_digest=D("5"),
                signer_verifier=self._ssh_verifier(
                    subject, namespace=BLOCKER_RESOLUTION_NAMESPACE
                ),
                verification_time=NOW,
            )
        self.assertEqual(caught.exception.code, "empty_blocker_resolution_manifest")

    def test_resume_canonical_bundle_freshly_verifies_to_authorized_transition(self) -> None:
        state, subject, _primary, _proof, _approval, raw = (
            self._resume_bundle_material()
        )
        bundle = self._import_lifecycle_bundle(
            raw, state=state, subject=subject, operation=OP_RESUME
        )
        self.assertIs(require_verified_lifecycle_bundle(bundle), bundle)
        self.assertEqual(bundle.event_input.transition_type, "RESUME")
        self.assertEqual(bundle.event_input.to_state, "ACTIVE")
        self.assertIs(
            lifecycle_primary_evidence_for_writer(bundle), bundle.primary_evidence
        )
        self.assertIs(
            lifecycle_transition_for_state_writer(bundle), bundle.event_input
        )
        self.assertIs(
            lifecycle_chain_head_witness_for_state_writer(bundle),
            bundle.chain_head_witness,
        )
        self.assertEqual(bundle.chain_head_witness.prior_event_count, 3)
        with self.assertRaises(LifecycleBundleError) as caught:
            require_verified_lifecycle_bundle(replace(bundle))
        self.assertEqual(caught.exception.code, "unverified_lifecycle_bundle")
        mutated = self._import_lifecycle_bundle(
            raw, state=state, subject=subject, operation=OP_RESUME
        )
        object.__setattr__(mutated, "source_commit", self.base_commit)
        with self.assertRaises(LifecycleBundleError) as caught:
            require_verified_lifecycle_bundle(mutated)
        self.assertEqual(caught.exception.code, "mutated_lifecycle_bundle")
        inner_mutated = self._import_lifecycle_bundle(
            raw, state=state, subject=subject, operation=OP_RESUME
        )
        object.__setattr__(
            inner_mutated.primary_evidence, "attestation_digest", D("9")
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            lifecycle_transition_for_state_writer(inner_mutated)
        self.assertEqual(caught.exception.code, "mutated_lifecycle_bundle")

    def test_impact_bundle_and_writer_fail_closed_without_atomic_batch(self) -> None:
        state, subject, primary_document, _proof, _approval, raw = (
            self._impact_bundle_material()
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                raw, state=state, subject=subject, operation=OP_INVALIDATION
            )
        self.assertEqual(
            caught.exception.code, "unsupported_invalidation_batch_semantics"
        )

        primary = self._verify_invalidation(
            state, subject, self.impact_commit, primary_document
        )
        freeze = _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("d"),
                statement_digest=D("e"),
                freeze_id="impact-invalidation-writer-freeze",
                subject=subject,
                contract_approval_digest=D("f"),
                protected_inputs=(),
                criteria=(),
                signer=primary.signer,
            )
        )
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_lifecycle_proof(
                freeze=freeze,
                state_context=state,
                verifier=None,  # type: ignore[arg-type]
                issued_at=NOW,
                lifecycle_evidence=primary,
                token_provider=lambda _audience: self.fail(
                    "invalidation must fail before token acquisition"
                ),
            )
        self.assertEqual(
            caught.exception.code, "unsupported_invalidation_batch_semantics"
        )

    def test_bundle_rejects_stale_cross_head_and_copied_chain_witness(self) -> None:
        state, subject, _primary, _proof, _approval, raw = (
            self._resume_bundle_material()
        )

        def with_witness(overrides: dict) -> bytes:
            document = json.loads(raw)
            document["chainHeadWitness"] = self._chain_witness(
                state, body_overrides=overrides
            )
            document["bundleDigest"] = document_digest(
                document, omit_field="bundleDigest"
            )
            return canonical_json_bytes(document)

        stale = with_witness({"validUntil": "2026-07-11T11:59:59Z"})
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                stale, state=state, subject=subject, operation=OP_RESUME
            )
        self.assertEqual(caught.exception.code, "chain_witness_outside_validity")

        cross_head = with_witness({"priorChainHeadDigest": D("9")})
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                cross_head, state=state, subject=subject, operation=OP_RESUME
            )
        self.assertEqual(caught.exception.code, "chain_witness_binding_mismatch")

        bundle = self._import_lifecycle_bundle(
            raw, state=state, subject=subject, operation=OP_RESUME
        )
        copied_witness = replace(bundle.chain_head_witness)
        object.__setattr__(bundle, "chain_head_witness", copied_witness)
        with self.assertRaises(LifecycleBundleError) as caught:
            lifecycle_transition_for_state_writer(bundle)
        self.assertEqual(caught.exception.code, "unverified_internal_result")

        mutated = self._import_lifecycle_bundle(
            raw, state=state, subject=subject, operation=OP_RESUME
        )
        object.__setattr__(
            mutated.chain_head_witness,
            "valid_until",
            datetime(2026, 7, 12, 12, 45, tzinfo=timezone.utc),
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            lifecycle_chain_head_witness_for_state_writer(mutated)
        self.assertEqual(caught.exception.code, "mutated_lifecycle_bundle")

    def test_bundle_rejects_noncanonical_tamper_replay_coi_source_and_digest_only(self) -> None:
        state, subject, _primary, _proof, _approval, raw = (
            self._resume_bundle_material()
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                raw + b"\n", state=state, subject=subject, operation=OP_RESUME
            )
        self.assertEqual(caught.exception.code, "noncanonical_lifecycle_bundle")

        def encoded(mutator) -> bytes:
            document = json.loads(raw)
            mutator(document)
            document["bundleDigest"] = document_digest(
                document, omit_field="bundleDigest"
            )
            return canonical_json_bytes(document)

        replay = encoded(
            lambda document: document.__setitem__("priorChainHeadDigest", D("9"))
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                replay, state=state, subject=subject, operation=OP_RESUME
            )
        self.assertEqual(caught.exception.code, "lifecycle_bundle_replay")

        tampered = encoded(
            lambda document: document["primaryEvidence"]["body"].__setitem__(
                "reason", "Tampered resolution reason without a fresh SSHSIG."
            )
        )
        with self.assertRaises(LifecycleBundleError):
            self._import_lifecycle_bundle(
                tampered, state=state, subject=subject, operation=OP_RESUME
            )

        document = json.loads(raw)
        coi_body = document["primaryEvidence"]["body"]
        coi_body["conflictOfInterest"]["independent"] = False
        document["primaryEvidence"] = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            coi_body,
        )
        document["bundleDigest"] = document_digest(
            document, omit_field="bundleDigest"
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                canonical_json_bytes(document),
                state=state,
                subject=subject,
                operation=OP_RESUME,
            )
        self.assertEqual(caught.exception.code, "conflict_of_interest")

        document = json.loads(raw)
        source_body = document["primaryEvidence"]["body"]
        source_body["subject"]["sourceCommit"] = self.base_commit
        document["primaryEvidence"] = self._ssh_envelope(
            BLOCKER_RESOLUTION_SCHEMA,
            BLOCKER_RESOLUTION_KIND,
            BLOCKER_RESOLUTION_NAMESPACE,
            source_body,
        )
        document["bundleDigest"] = document_digest(
            document, omit_field="bundleDigest"
        )
        with self.assertRaises(LifecycleBundleError):
            self._import_lifecycle_bundle(
                canonical_json_bytes(document),
                state=state,
                subject=subject,
                operation=OP_RESUME,
            )

        document = json.loads(raw)
        proof_body = document["proof"]["body"]
        proof_body["blockerResolutionDigest"] = D("8")
        document["proof"] = self._oidc_envelope(
            LIFECYCLE_PROOF_SCHEMA,
            LIFECYCLE_PROOF_KIND,
            LIFECYCLE_PROOF_NAMESPACE,
            proof_body,
        )
        document["bundleDigest"] = document_digest(
            document, omit_field="bundleDigest"
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                canonical_json_bytes(document),
                state=state,
                subject=subject,
                operation=OP_RESUME,
            )
        self.assertEqual(caught.exception.code, "primary_evidence_projection_mismatch")

    def test_bundle_structurally_rejects_control_and_supersession(self) -> None:
        state, _control_authority_subject, _head, _projection, control_evidence = (
            self._invalidation_document(head=self.control_commit)
        )
        expected_subject = self._subject(self.control_commit)
        control_raw = self._bundle_bytes(
            # A hostile producer may label CONTROL drift as ordinary IMPACT;
            # the importer must derive and reject it mechanically.
            operation=OP_INVALIDATION,
            state=state,
            subject=expected_subject,
            to_state="BLOCKED",
            primary_document=control_evidence,
            proof_document={},
            approval_document={},
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                control_raw,
                state=state,
                subject=expected_subject,
                operation=OP_INVALIDATION,
            )
        self.assertEqual(
            caught.exception.code, "unsupported_invalidation_batch_semantics"
        )

        explicit_control_raw = self._bundle_bytes(
            operation=OP_CONTROL_INVALIDATION,
            state=state,
            subject=expected_subject,
            to_state="BLOCKED",
            primary_document=control_evidence,
            proof_document={},
            approval_document={},
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                explicit_control_raw,
                state=state,
                subject=expected_subject,
                operation=OP_CONTROL_INVALIDATION,
            )
        self.assertEqual(
            caught.exception.code, "unsupported_invalidation_batch_semantics"
        )

        supersession_raw = self._bundle_bytes(
            operation=OP_SUPERSESSION,
            state=state,
            subject=expected_subject,
            to_state="SUPERSEDED",
            primary_document={},
            proof_document={},
            approval_document={},
        )
        with self.assertRaises(LifecycleBundleError) as caught:
            self._import_lifecycle_bundle(
                supersession_raw,
                state=state,
                subject=expected_subject,
                operation=OP_SUPERSESSION,
            )
        self.assertEqual(caught.exception.code, "unsupported_control_plane_revision")

    def _invalidation_document(self, *, head: str, status: str = "ACTIVE"):
        state = self._state(status)
        # Standard IMPACT authority executes at the unchanged approved head.
        # CONTROL drift must instead be inspected by the dedicated authority
        # executing the still-approved base revision.
        authority_source = self.base_commit if head == self.control_commit else head
        subject = self._subject(authority_source)
        computation = compute_invalidation_projection(
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            base_commit=self.base_commit,
            head_commit=head,
            approved_component_digests=self.components,
            expected_impact_map_digest=self.impact_digest,
        )
        body = invalidation_body(
            computation,
            invalidation_id="invalidation-1",
            issued_at=NOW,
            actor={
                "principal": "github-actions:lifecycle-test",
                "role": "protected-workflow",
                "organization": "github-actions",
            },
            authority_digest=D("5"),
        )
        document = self._oidc_envelope(
            INVALIDATION_SCHEMA,
            INVALIDATION_KIND,
            INVALIDATION_NAMESPACE,
            body,
        )
        return state, subject, head, computation, document

    def _verify_invalidation(
        self, state, subject, head, document, *, role="protected-workflow"
    ):
        return verify_invalidation_evidence(
            document,
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            base_commit=self.base_commit,
            head_commit=head,
            approved_component_digests=self.components,
            expected_impact_map_digest=self.impact_digest,
            expected_authority_digest=D("5"),
            signer_verifier=self._oidc_verifier(subject, role=role),
            verification_time=NOW,
        )

    def test_invalidation_mechanically_distinguishes_impact_and_control(self) -> None:
        impact_state, impact_subject, impact_head, impact_computation, impact_document = (
            self._invalidation_document(head=self.impact_commit)
        )
        self.assertEqual(impact_computation.invalidation_kind, "IMPACT")
        self.assertEqual(impact_computation.changed_paths, ("src/app.py",))
        impact = self._verify_invalidation(
            impact_state, impact_subject, impact_head, impact_document
        )
        self.assertFalse(impact.control_drift_detected)
        self.assertEqual(impact.authority_mode, "STANDARD_APPROVED_HEAD")
        self.assertIs(require_verified_invalidation_evidence(impact), impact)

        control_state, control_subject, control_head, control_computation, control_document = (
            self._invalidation_document(head=self.control_commit)
        )
        self.assertEqual(control_computation.invalidation_kind, "CONTROL")
        self.assertIn("tools/check.py", control_computation.changed_components)
        control = self._verify_invalidation(
            control_state, control_subject, control_head, control_document
        )
        self.assertEqual(control.to_state, "BLOCKED")
        self.assertEqual(control.subject.source_commit, self.base_commit)
        self.assertEqual(control.authority_mode, "APPROVED_BASE_REVISION_CHECK")
        freeze = _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("d"),
                statement_digest=D("e"),
                freeze_id="control-invalidation-writer-freeze",
                subject=control_subject,
                contract_approval_digest=D("f"),
                protected_inputs=(),
                criteria=(),
                signer=control.signer,
            )
        )
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_lifecycle_proof(
                freeze=freeze,
                state_context=control_state,
                verifier=None,  # type: ignore[arg-type]
                issued_at=NOW,
                lifecycle_evidence=control,
                token_provider=lambda _audience: self.fail(
                    "CONTROL drift must fail before token acquisition"
                ),
            )
        self.assertEqual(
            caught.exception.code, "unsupported_invalidation_batch_semantics"
        )

    def test_invalidation_non_active_evidence_state_becomes_rejected(self) -> None:
        state, subject, head, computation, document = self._invalidation_document(
            head=self.impact_commit, status="CONVERGED"
        )
        self.assertEqual(computation.to_state, "REJECTED")
        result = self._verify_invalidation(state, subject, head, document)
        self.assertEqual(result.from_state, "CONVERGED")
        self.assertEqual(result.to_state, "REJECTED")

    def test_invalidation_rejects_caller_paths_wrong_head_role_and_reconstruction(self) -> None:
        state, subject, head, _computation, document = self._invalidation_document(
            head=self.impact_commit
        )
        changed = deepcopy(document)
        changed["body"]["changedPaths"] = ["tools/check.py"]
        changed = self._oidc_envelope(
            INVALIDATION_SCHEMA,
            INVALIDATION_KIND,
            INVALIDATION_NAMESPACE,
            changed["body"],
        )
        with self.assertRaises(LifecycleEvidenceError) as caught:
            self._verify_invalidation(state, subject, head, changed)
        self.assertEqual(caught.exception.code, "invalidation_projection_mismatch")
        with self.assertRaises(LifecycleEvidenceError) as caught:
            verify_invalidation_evidence(
                document,
                repo_root=self.repo,
                state_context=state,
                expected_subject=subject,
                base_commit=self.base_commit,
                head_commit=self.control_commit,
                approved_component_digests=self.components,
                expected_impact_map_digest=self.impact_digest,
                expected_authority_digest=D("5"),
                signer_verifier=self._oidc_verifier(subject),
                verification_time=NOW,
            )
        self.assertEqual(
            caught.exception.code, "invalidation_authority_source_mismatch"
        )
        with self.assertRaises(Exception):
            self._verify_invalidation(
                state, subject, head, document, role="independent-reviewer"
            )
        result = self._verify_invalidation(state, subject, head, document)
        with self.assertRaises(LifecycleEvidenceError):
            require_verified_invalidation_evidence(replace(result))

    def _supersession_body(self, subject: SubjectBinding, state) -> dict:
        replacement = SubjectBinding(
            phase=subject.phase,
            work_unit=subject.work_unit,
            source_commit=self.replacement_commit,
            control_plane_digest=self.replacement_control_digest,
            contract_digest=self.replacement_components[
                "execution/work-units/P00.W01.yaml"
            ],
        )
        return {
            "approvalId": "supersession-1",
            "subject": {
                "phase": subject.phase,
                "workUnit": subject.work_unit,
                "sourceCommit": subject.source_commit,
                "controlPlaneDigest": subject.control_plane_digest,
                "contractDigest": subject.contract_digest,
            },
            "replacementSubject": {
                "phase": replacement.phase,
                "workUnit": replacement.work_unit,
                "sourceCommit": replacement.source_commit,
                "controlPlaneDigest": replacement.control_plane_digest,
                "contractDigest": replacement.contract_digest,
            },
            "fromState": state.status,
            "toState": "SUPERSEDED",
            "priorStateDigest": state.state_digest,
            "priorChainHeadDigest": state.chain_head_digest,
            "decision": {
                "kind": "RFC",
                "decisionId": "RFC-0042",
                "path": "rfcs/0042-replace-contract.md",
                "digest": self.replacement_components[
                    "rfcs/0042-replace-contract.md"
                ],
            },
            "reasonCode": "plan-rfc-explicit-supersession",
            "reason": "RFC-0042 explicitly replaces the old contract and control revision.",
            "conflictOfInterest": {
                "independent": True,
                "requesterPrincipal": "agent@example.invalid",
                "requesterOrganization": "implementation-org",
                "declaration": "No financial, employment, or reporting conflict exists.",
            },
            "issuedAt": "2026-07-11T11:00:00Z",
            "validUntil": "2026-07-12T11:00:00Z",
            "actor": {
                "principal": "reviewer@example.invalid",
                "role": "independent-reviewer",
                "organization": "review-org",
            },
            "authorityDigest": D("5"),
        }

    def test_supersession_is_explicit_ssh_approved_and_identity_sealed(self) -> None:
        subject = self._subject(self.base_commit)
        state = self._state("ACTIVE")
        document = self._ssh_envelope(
            SUPERSESSION_SCHEMA,
            SUPERSESSION_KIND,
            SUPERSESSION_NAMESPACE,
            self._supersession_body(subject, state),
        )
        result = verify_supersession_approval(
            document,
            repo_root=self.repo,
            state_context=state,
            expected_subject=subject,
            expected_authority_digest=D("5"),
            signer_verifier=self._ssh_verifier(
                subject, namespace=SUPERSESSION_NAMESPACE
            ),
            verification_time=NOW,
        )
        self.assertEqual(result.decision.kind, "RFC")
        self.assertNotEqual(
            result.replacement_subject.control_plane_digest,
            result.subject.control_plane_digest,
        )
        self.assertIs(require_verified_supersession_approval(result), result)
        with self.assertRaises(LifecycleEvidenceError):
            require_verified_supersession_approval(replace(result))
        freeze = _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("d"),
                statement_digest=D("e"),
                freeze_id="supersession-writer-freeze",
                subject=subject,
                contract_approval_digest=D("f"),
                protected_inputs=(),
                criteria=(),
                signer=result.signer,
            )
        )
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_lifecycle_proof(
                freeze=freeze,
                state_context=state,
                verifier=None,  # type: ignore[arg-type]
                issued_at=NOW,
                lifecycle_evidence=result,
                token_provider=lambda _audience: self.fail(
                    "unsupported replacement must fail before token acquisition"
                ),
            )
        self.assertEqual(caught.exception.code, "unsupported_control_plane_revision")

    def test_supersession_rejects_silent_swap_wrong_decision_and_coi(self) -> None:
        subject = self._subject(self.base_commit)
        state = self._state("ACTIVE")
        bodies = []
        same = self._supersession_body(subject, state)
        same["replacementSubject"] = deepcopy(same["subject"])
        bodies.append(same)
        wrong_path = self._supersession_body(subject, state)
        wrong_path["decision"]["path"] = "docs/not-an-rfc.md"
        bodies.append(wrong_path)
        coi = self._supersession_body(subject, state)
        coi["conflictOfInterest"]["requesterOrganization"] = "review-org"
        bodies.append(coi)
        for body in bodies:
            document = self._ssh_envelope(
                SUPERSESSION_SCHEMA,
                SUPERSESSION_KIND,
                SUPERSESSION_NAMESPACE,
                body,
            )
            with self.subTest(path=body["decision"]["path"]):
                with self.assertRaises(LifecycleEvidenceError):
                    verify_supersession_approval(
                        document,
                        repo_root=self.repo,
                        state_context=state,
                        expected_subject=subject,
                        expected_authority_digest=D("5"),
                        signer_verifier=self._ssh_verifier(
                            subject, namespace=SUPERSESSION_NAMESPACE
                        ),
                        verification_time=NOW,
                    )


if __name__ == "__main__":
    unittest.main()
