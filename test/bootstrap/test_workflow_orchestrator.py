"""Real-crypto tests for the raw protected workflow replay boundary."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.chain_artifact import (  # noqa: E402
    encode_chain_artifact,
    parse_chain_artifact,
)
from tools.phasegate.chain_witness import (  # noqa: E402
    VerifiedChainHeadWitness,
    _mark_verified as _mark_chain_witness,
)
from tools.phasegate.control_context import (  # noqa: E402
    DATASET_REVIEWER_CAPABILITY,
    DATASET_REVIEWER_ROLE,
    DATASET_SELECTION_KIND,
    DATASET_SELECTION_NAMESPACE,
    DATASET_SELECTION_SCHEMA,
    criterion_documents,
    derive_phase_control_context,
    derive_work_unit_control_context,
    finalize_late_bound_dataset_context,
)
from tools.phasegate.delegation import (  # noqa: E402
    DELEGATION_KIND,
    DELEGATION_SCHEMA,
    build_effective_reviewer_roster,
)
from tools.phasegate.digest import (  # noqa: E402
    canonical_json_bytes,
    compute_control_plane_digest,
    read_input_manifest,
    sha256_bytes,
)
from tools.phasegate.execution_artifact import (  # noqa: E402
    ASSERTION_SCHEMA,
    ENVIRONMENT_SCHEMA,
    CapturedRunArtifact,
    _environment_digest,
    _manifest_digest,
    serialize_execution_artifact_bundle,
)
from tools.phasegate.phase_bundle import (  # noqa: E402
    BUNDLE_KIND as PHASE_BUNDLE_KIND,
    BUNDLE_SCHEMA as PHASE_BUNDLE_SCHEMA,
    OP_PHASE_TRANSITION,
    PhaseBundleError,
    verify_serialized_phase_authorization_bundle,
)
from tools.phasegate.phase_evidence import (  # noqa: E402
    PHASE_DATASET_ID,
    VerifiedPhaseAggregateEvidence,
    _projection as _phase_evidence_projection,
    _seal as _seal_phase_evidence,
)
from tools.phasegate.evidence_index import (  # noqa: E402
    VerifiedProtectedChainReplay,
    machine_index_digest,
    seal_verified_protected_chain_replay,
    state_view,
)
from tools.phasegate.gate_runner import combine_runs, record_run  # noqa: E402
from tools.phasegate.oidc import jwks_snapshot_digest  # noqa: E402
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    build_paired_input,
)
from tools.phasegate.oidc_provenance import (  # noqa: E402
    build_oidc_provenance_verifier,
    create_signed_machine_criterion_result,
)
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
)
from tools.phasegate.protected_v2 import (  # noqa: E402
    APPROVAL_KIND,
    APPROVAL_NAMESPACE,
    APPROVAL_SCHEMA,
    REVIEWER_DELEGATION_NAMESPACE,
    validate_trust_policy_v2,
    verify_control_plane_approval_v2,
)
from tools.phasegate.provenance import (  # noqa: E402
    ACTIVATION_APPROVAL_KIND,
    ACTIVATION_APPROVAL_NAMESPACE,
    ACTIVATION_APPROVAL_SCHEMA,
    ACTIVATION_PROOF_NAMESPACE,
    FREEZE_KIND,
    FREEZE_NAMESPACE,
    FREEZE_SCHEMA,
    LIFECYCLE_APPROVAL_KIND,
    LIFECYCLE_APPROVAL_NAMESPACE,
    LIFECYCLE_APPROVAL_SCHEMA,
    LIFECYCLE_PROOF_NAMESPACE,
    PHASE_APPROVAL_KIND,
    PHASE_APPROVAL_NAMESPACE,
    PHASE_APPROVAL_SCHEMA,
    PHASE_FREEZE_KIND,
    PHASE_FREEZE_NAMESPACE,
    PHASE_FREEZE_SCHEMA,
    PHASE_PROOF_NAMESPACE,
    PhaseSubject,
    PhaseUnitStateBinding,
    PROOF_NAMESPACE,
    TRANSITION_APPROVAL_KIND,
    TRANSITION_APPROVAL_NAMESPACE,
    TRANSITION_APPROVAL_SCHEMA,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    VerifiedPhaseTransition,
    _mark_verified as _mark_provenance_verified,
    verify_phase_state_context,
    verify_signed_phase_protected_input_freeze,
    verify_signed_protected_input_freeze,
    verify_work_unit_state_context,
)
from tools.phasegate.provenance_writer import (  # noqa: E402
    create_signed_activation_proof,
    create_signed_lifecycle_proof,
    create_signed_work_unit_transition_proof,
    create_signed_phase_machine_criterion_result,
    create_signed_phase_transition_proof,
)
from tools.phasegate.run_executor import execute_phase_pair  # noqa: E402
from tools.phasegate.serialized_bundle import (  # noqa: E402
    BUNDLE_KIND,
    BUNDLE_SCHEMA,
    OP_ACTIVATION,
    OP_ATTACHMENT,
    OP_CONVERGENCE,
    OP_READINESS,
)
from tools.phasegate.sshsig import verify_sshsig  # noqa: E402
from tools.phasegate.state_chain_v2 import (  # noqa: E402
    EXECUTED_VERIFIER_PATHS,
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    _mark_verified as _mark_state_verified,
    verify_next_event_v2,
)
from tools.phasegate.state_writer import (  # noqa: E402
    REQUIRED_STATUS_CHECKS,
    create_genesis_event,
)
from tools.phasegate.workflow_orchestrator import (  # noqa: E402
    WorkflowOrchestratorError,
    append_post_genesis,
    replay_protected_chain,
    require_verified_protected_chain_replay,
    verified_machine_evidence_index,
)
from tools.phasegate import workflow_orchestrator as orchestrator_module  # noqa: E402


def D(character: str) -> str:
    return "sha256:" + character * 64


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def ruleset_evidence(commit: str) -> dict:
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
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "rules": rules,
        },
    }


class WorkflowOrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for executable in ("/usr/bin/git", "/usr/bin/openssl", "/usr/bin/ssh-keygen"):
            if not Path(executable).is_file():
                raise unittest.SkipTest(f"missing fixture executable: {executable}")
        cls.temporary = tempfile.TemporaryDirectory(prefix="workflow-orchestrator-")
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
            timeout=15,
        )
        cls.reviewer_public = " ".join(
            cls.reviewer_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )
        cls.reviewer_fingerprint = _ssh_public_key_fingerprint(
            cls.reviewer_public, "test.reviewerPublic"
        )
        cls.rsa_key = cls.root / "oidc.pem"
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
            timeout=15,
        ).stdout.strip()
        modulus = bytes.fromhex(modulus_text.removeprefix("Modulus="))
        cls.jwk = {
            "kid": "workflow-orchestrator-test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": "AQAB",
        }
        cls.genesis_time = datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc)
        cls.repo = cls.root / "repo"
        cls.repo.mkdir()
        _, entries = read_input_manifest(REPO_ROOT)
        for entry in entries:
            source = REPO_ROOT / entry["path"]
            target = cls.repo / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        manifest_path = cls.repo / "execution/control-plane-inputs.yaml"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["inputs"].sort(key=lambda item: item["path"].encode("utf-8"))
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        contract_path = cls.repo / "execution/work-units/P00.W01.yaml"
        gate_path = cls.repo / "execution/gates/p00/P00.W01.yaml"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        machine = next(
            criterion
            for criterion in contract["convergence"]
            if criterion["id"] == "P00-M-BOOTSTRAP-CONTROL"
        )
        contract["convergence"] = [machine]
        gate["criteria"] = [deepcopy(machine)]
        contract_path.write_text(
            json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        gate_path.write_text(
            json.dumps(gate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        snapshot = {
            "schemaVersion": "urn:agentapi-doctor:github-actions-oidc-jwks:v1alpha1",
            "kind": "GitHubActionsOidcJwksSnapshotCandidate",
            "snapshotStatus": "candidate-unapproved",
            "issuer": "https://token.actions.githubusercontent.com",
            "discoveryUrl": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
            "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "retrievedAt": "2026-07-11T00:00:00Z",
            "sourceRawDigest": D("a"),
            "algorithms": ["RS256"],
            "historicalVerificationPolicy": {
                "networkDuringReplay": "forbidden",
                "unknownKid": "block-for-independently-approved-rotation",
                "tokenValidity": "the StateEvent timestamp must precede token issuance by at most 120 seconds and token lifetime must not exceed 600 seconds",
                "revocation": "a later policy revision may explicitly revoke a key; repository-local online refresh never grants trust",
            },
            "keys": [cls.jwk],
        }
        cls.snapshot = snapshot
        cls.snapshot_digest = jwks_snapshot_digest(snapshot)
        snapshot_path = (
            cls.repo / "execution/protected-verifier/github-actions-oidc-jwks.json"
        )
        snapshot_path.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        policy_path = cls.repo / "execution/protected-verifier/trust-policy.yaml"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        principal = policy["sshPrincipals"][0]
        principal["identity"] = "reviewer@test.invalid"
        principal["organization"] = "independent-test"
        principal["publicKey"] = cls.reviewer_public
        principal["fingerprint"] = cls.reviewer_fingerprint
        policy["signatureSchemes"]["stateEvent"][
            "jwksSnapshotDigest"
        ] = cls.snapshot_digest
        policy["signatureSchemes"]["machineProvenance"][
            "requiredComponentPaths"
        ] = sorted(
            (
                ".github/workflows/p00-protected-state-writer.yml",
                *EXECUTED_VERIFIER_PATHS,
            )
        )
        policy_path.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        digest, _ = compute_control_plane_digest(cls.repo)
        cls._bind_control_digest(digest)
        rebound, components = compute_control_plane_digest(cls.repo)
        if rebound != digest:
            raise AssertionError("fixture control-plane self-reference drift")
        cls.control_digest = rebound
        cls.components = {item["path"]: item["digest"] for item in components}
        cls.policy = json.loads(policy_path.read_text(encoding="utf-8"))
        cls.policy_digest = document_digest(cls.policy)

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
            ["/usr/bin/git", "-C", str(cls.repo), "commit", "-q", "-m", "candidate"],
            check=True,
        )
        cls.candidate_commit = cls._git_commit()
        cls.request = cls._request()
        request_path = cls.repo / "execution/approval-requests/P00.B00-R3.yaml"
        request_path.parent.mkdir(parents=True, exist_ok=True)
        request_path.write_text(
            json.dumps(cls.request, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        subprocess.run(["/usr/bin/git", "-C", str(cls.repo), "add", "."], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "commit", "-q", "-m", "request"],
            check=True,
        )
        cls.request_commit = cls._git_commit()
        cls.request_digest = document_digest(cls.request)
        cls.approval = cls._approval()
        cls.approval_result = verify_control_plane_approval_v2(
            request=cls.request,
            approval=cls.approval,
            policy=cls.policy,
            jwks_snapshot=cls.snapshot,
            expected_policy_digest=cls.policy_digest,
            expected_jwks_snapshot_digest=cls.snapshot_digest,
            expected_control_plane_digest=cls.control_digest,
            expected_candidate_source_commit=cls.candidate_commit,
            expected_request_digest=cls.request_digest,
            expected_workflow_execution_commit=cls.request_commit,
            consumption_time=cls.genesis_time,
        )
        cls.policy_result = validate_trust_policy_v2(
            cls.policy,
            jwks_snapshot=cls.snapshot,
            expected_policy_digest=cls.policy_digest,
            expected_jwks_snapshot_digest=cls.snapshot_digest,
            expected_control_plane_digest=cls.control_digest,
        )
        cls.genesis = cls._genesis()
        cls.raw_chain = encode_chain_artifact(
            bootstrap_approval=cls.approval,
            genesis_event=cls.genesis,
            entries=(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _bind_control_digest(cls, digest: str) -> None:
        _, entries = read_input_manifest(cls.repo)
        structured = {"json", "json-yaml", "manifest", "contract", "catalog", "gate"}

        def bind(value):
            if isinstance(value, dict):
                return {
                    key: digest if key == "controlPlaneDigest" else bind(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [bind(item) for item in value]
            return value

        for entry in entries:
            if entry["kind"] not in structured:
                continue
            path = cls.repo / entry["path"]
            value = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(
                json.dumps(bind(value), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    @classmethod
    def _git_commit(cls) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(cls.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @classmethod
    def _request(cls) -> dict:
        return {
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
                "candidateSourceCommit": cls.candidate_commit,
                "gitObjectFormat": "sha1",
                "canonicalPlanPath": "agentapi-doctor-Plan.md",
                "controlPlaneDigest": cls.control_digest,
            },
            "componentDigests": cls.components,
            "digestGroups": {"all": D("b")},
            "testSuites": [],
            "diff": {},
            "decisionsRequested": [{"id": "decision-1", "question": "approve"}],
            "ambiguities": [{"id": "ambiguity-1", "question": "resolve"}],
            "limitations": ["synthetic local fixture"],
            "nextAuthorizedAction": "local test only",
        }

    @classmethod
    def _ssh_sign(cls, payload: bytes, namespace: str) -> str:
        return subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(cls.reviewer_key),
                "-n",
                namespace,
            ],
            input=payload,
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout.decode("ascii")

    @classmethod
    def _approval(cls) -> dict:
        body = {
            "attestationId": "workflow-orchestrator-bootstrap-approval",
            "requestId": "P00.B00-R3",
            "requestRevision": 3,
            "requestDigest": document_digest(cls.request),
            "decision": "APPROVE",
            "candidateSourceCommit": cls.candidate_commit,
            "workflowExecutionCommit": cls.request_commit,
            "controlPlaneDigest": cls.control_digest,
            "digestGroups": cls.request["digestGroups"],
            "reviewedDecisionIds": ["decision-1"],
            "reviewedAmbiguityIds": ["ambiguity-1"],
            "scope": {"phase": "P00", "bootstrapId": "P00.B00"},
            "reason": "Independent synthetic fixture review.",
            "validFrom": "2026-07-11T00:00:00Z",
            "validUntil": "2026-08-11T00:00:00Z",
            "constraints": [],
            "conflictOfInterest": {
                "independent": True,
                "statement": "Fixture reviewer is separate from workflow signer.",
            },
            "reviewer": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
            "trustPolicyDigest": cls.policy_digest,
            "jwksSnapshotDigest": cls.snapshot_digest,
        }
        statement = {
            "schemaVersion": APPROVAL_SCHEMA,
            "kind": APPROVAL_KIND,
            "body": body,
        }
        envelope = {
            **statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": APPROVAL_NAMESPACE,
                "principal": "reviewer@test.invalid",
                "value": cls._ssh_sign(canonical_json_bytes(statement), APPROVAL_NAMESPACE),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    @classmethod
    def _token(
        cls,
        audience: str,
        *,
        commit: str,
        when: datetime,
        run_id: int,
    ) -> str:
        signer = cls.policy["githubActionsStateSigner"]
        issued = int(when.timestamp())
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "repository": signer["repository"],
            "repository_id": signer["repositoryId"],
            "repository_owner": signer["repositoryOwner"],
            "repository_owner_id": signer["repositoryOwnerId"],
            "repository_visibility": signer["repositoryVisibility"],
            "event_name": signer["eventName"],
            "ref": signer["ref"],
            "ref_type": signer["refType"],
            "ref_protected": signer["refProtected"],
            "runner_environment": signer["runnerEnvironment"],
            "actor_id": signer["allowedActorIds"][0],
            "workflow_ref": signer["workflowRef"],
            "workflow_sha": commit,
            "sha": commit,
            "jti": f"workflow-orchestrator-{run_id}",
            "run_id": str(run_id),
            "run_number": str(run_id),
            "run_attempt": "1",
            "check_run_id": str(run_id + 1000),
            "nbf": issued - 30,
            "iat": issued,
            "exp": issued + 300,
        }
        header = canonical_json_bytes(
            {"alg": "RS256", "kid": cls.jwk["kid"], "typ": "JWT"}
        )
        signing_input = (
            b64url(header) + "." + b64url(canonical_json_bytes(claims))
        ).encode("ascii")
        signature = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(cls.rsa_key)],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout
        return signing_input.decode("ascii") + "." + b64url(signature)

    @classmethod
    def _genesis(cls) -> dict:
        signer = cls.policy["githubActionsStateSigner"]
        claims = {
            "repository": signer["repository"],
            "repository_id": signer["repositoryId"],
            "repository_owner": signer["repositoryOwner"],
            "repository_owner_id": signer["repositoryOwnerId"],
            "repository_visibility": signer["repositoryVisibility"],
            "event_name": signer["eventName"],
            "ref": signer["ref"],
            "ref_type": signer["refType"],
            "ref_protected": signer["refProtected"],
            "runner_environment": signer["runnerEnvironment"],
            "actor_id": signer["allowedActorIds"][0],
            "workflow_ref": signer["workflowRef"],
            "workflow_sha": cls.request_commit,
            "sha": cls.request_commit,
        }
        return create_genesis_event(
            approval_result=cls.approval_result,
            contract_digests=cls.components,
            source_commit=cls.candidate_commit,
            control_plane_digest=cls.control_digest,
            trust_policy_digest=cls.policy_digest,
            approved_jwks=cls.snapshot,
            expected_jwks_snapshot_digest=cls.snapshot_digest,
            expected_claims=claims,
            workflow_path=".github/workflows/p00-protected-state-writer.yml",
            workflow_execution_commit=cls.request_commit,
            statement_timestamp=cls.genesis_time,
            repository_protection_provider=lambda: ruleset_evidence(cls.request_commit),
            token_provider=lambda audience: cls._token(
                audience,
                commit=cls.request_commit,
                when=cls.genesis_time,
                run_id=100,
            ),
        )

    @staticmethod
    def _text(value: datetime) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _head(current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2) -> str:
        return (
            current.chain_head_digest
            if isinstance(current, VerifiedGenesisAnchorV2)
            else current.head_digest
        )

    @staticmethod
    def _head_time(
        current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    ) -> datetime:
        return (
            current.timestamp
            if isinstance(current, VerifiedGenesisAnchorV2)
            else current.head_timestamp
        )

    @staticmethod
    def _head_source(
        current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    ) -> str:
        return current.head_source_commit

    @classmethod
    def _ssh_envelope(
        cls, schema: str, kind: str, namespace: str, body: dict
    ) -> dict:
        statement = {"schemaVersion": schema, "kind": kind, "body": body}
        envelope = {
            **statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": namespace,
                "principal": "reviewer@test.invalid",
                "value": cls._ssh_sign(canonical_json_bytes(statement), namespace),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    @staticmethod
    def _subject_document(subject) -> dict[str, str]:
        return {
            "phase": subject.phase,
            "workUnit": subject.work_unit,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "contractDigest": subject.contract_digest,
        }

    @classmethod
    def _root_signer(cls, namespace: str):
        def verify(payload: bytes, signature: dict, supplied_namespace: str):
            if supplied_namespace != namespace:
                raise AssertionError("fixture namespace drift")
            verify_sshsig(
                payload,
                armored_signature=signature["value"],
                public_key=cls.reviewer_public,
                expected_namespace=namespace,
            )
            return VerifiedSignerResult(
                scheme="openssh-sshsig-v1",
                namespace=namespace,
                principal="reviewer@test.invalid",
                role="independent-reviewer",
                organization="independent-test",
                statement_digest=sha256_bytes(payload),
                authority_digest=cls.policy_digest,
                source_commit=cls.request_commit,
                control_plane_digest=cls.control_digest,
            )

        return verify

    @classmethod
    def _authority(cls, current, namespace: str):
        return build_oidc_provenance_verifier(
            current=current,
            policy_result=cls.policy_result,
            approved_jwks_snapshot=cls.snapshot,
            repo_root=cls.repo,
            current_source_commit=cls.request_commit,
            current_workflow_execution_commit=cls.request_commit,
            expected_namespace=namespace,
        )

    @classmethod
    def _context(cls, current, work_unit: str):
        return derive_work_unit_control_context(
            current=current,
            oidc_authority=cls._authority(current, PROOF_NAMESPACE),
            repo_root=cls.repo,
            work_unit=work_unit,
        )

    @classmethod
    def _freeze(
        cls,
        current,
        *,
        work_unit: str,
        issued_at: datetime,
        seed: int,
    ) -> tuple[object, dict, VerifiedProtectedInputFreeze]:
        context = cls._context(current, work_unit)
        criteria = criterion_documents(context.criteria)
        body = {
            "freezeId": f"freeze-{work_unit.lower()}-{seed}",
            "subject": cls._subject_document(context.subject),
            "contractApprovalDigest": context.contract_approval_digest,
            "protectedInputs": dict(context.protected_inputs),
            "criteria": criteria,
            "issuedAt": cls._text(issued_at),
            "actor": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
            "authorityDigest": cls.policy_digest,
        }
        raw = cls._ssh_envelope(
            FREEZE_SCHEMA, FREEZE_KIND, FREEZE_NAMESPACE, body
        )
        verified = verify_signed_protected_input_freeze(
            raw,
            expected_subject=context.subject,
            expected_contract_approval_digest=context.contract_approval_digest,
            expected_protected_inputs=dict(context.protected_inputs),
            expected_criteria=criteria,
            expected_authority_digest=cls.policy_digest,
            signer_verifier=cls._root_signer(FREEZE_NAMESPACE),
        )
        return context, raw, verified

    @classmethod
    def _state_context(cls, current, context):
        status = current.state_core["phases"]["P00"]["workUnits"][
            context.subject.work_unit
        ]["status"]
        return verify_work_unit_state_context(
            dict(current.state_core),
            expected_state_digest=current.state_digest,
            expected_chain_head_digest=cls._head(current),
            expected_control_plane_digest=cls.control_digest,
            phase="P00",
            work_unit=context.subject.work_unit,
            expected_status=status,
            expected_contract_digest=context.subject.contract_digest,
            prerequisite_units=context.prerequisite_units,
        )

    @classmethod
    def _machine_evidence(
        cls,
        current,
        *,
        context,
        freeze: VerifiedProtectedInputFreeze,
        issued_at: datetime,
        seed: int,
    ) -> tuple[dict, object, dict]:
        criterion = next(item for item in context.criteria if item.kind == "MACHINE")
        facts = {
            "schemaVersion": "urn:agentapi-doctor:phasegate-result:v1",
            "status": "pass",
            "reasonCode": "candidate_valid",
            "controlPlaneDigest": cls.control_digest,
            "componentCount": len(cls.components),
        }
        stdout = canonical_json_bytes(facts)
        stderr = b""
        output_limit = 1024 * 1024
        tools = {
            key: list(value) if key == "unshareArguments" else value
            for key, value in context.executor_preflight.tool_facts
        }
        assertion = {
            "id": "candidate-semantically-valid",
            "status": "PASS",
            "evidenceDigest": document_digest(
                {
                    "schemaVersion": ASSERTION_SCHEMA,
                    "evaluator": criterion.evaluator,
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
                "startedAt": cls._text(issued_at),
                "finishedAt": cls._text(issued_at + timedelta(seconds=1)),
                "environmentDigest": _environment_digest(
                    label=label, environment=environment, tools=tools
                ),
                "logDigest": log_digest,
                "artifactManifestDigest": _manifest_digest(
                    label=label,
                    evaluator=criterion.evaluator,
                    log_digest=log_digest,
                    output_bytes=len(stdout) + len(stderr),
                    exit_code=0,
                ),
                "sourceDirtyBeforeRun": False,
                "cleanCheckout": label == "B",
                "semanticAssertions": [assertion],
            }

        command_a = command("A")
        command_b = command("B")
        run_a = record_run(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            label="A",
            command_result=command_a,
        )
        run_b = record_run(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            label="B",
            command_result=command_b,
        )
        pair = combine_runs(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
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
                git_digest=tools["gitDigest"],
                python_digest=tools["pythonDigest"],
                unshare_digest=tools["unshareDigest"],
            )
            for label, command_result in (("A", command_a), ("B", command_b))
        ]
        execution = serialize_execution_artifact_bundle(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            run_pair=pair,
            captured_runs=captured,
        )
        verifier = cls._authority(
            current, "agentapi-doctor/criterion-result/machine/v1"
        )
        raw_result, verified_result = create_signed_machine_criterion_result(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            run_pair=pair,
            verifier=verifier,
            issued_at=issued_at,
            token_provider=lambda audience: cls._token(
                audience,
                commit=cls.request_commit,
                when=issued_at,
                run_id=seed,
            ),
        )
        return raw_result, verified_result, json.loads(execution)

    @classmethod
    def _witness(cls, current, *, event_time: datetime, seed: int) -> dict:
        witnessed = max(
            cls._head_time(current),
            event_time - timedelta(minutes=5),
        )
        if witnessed >= event_time:
            witnessed = cls._head_time(current)
        body = {
            "witnessId": f"witness-{seed}",
            "priorChainHeadDigest": cls._head(current),
            "priorStateDigest": current.state_digest,
            "priorEventCount": current.event_count,
            "priorHeadSequence": current.head_sequence,
            "priorSourceCommit": cls._head_source(current),
            "controlPlaneDigest": cls.control_digest,
            "trustPolicyDigest": cls.policy_digest,
            "witnessedAt": cls._text(witnessed),
            "validUntil": cls._text(event_time + timedelta(minutes=10)),
            "reason": "Observed exact protected chain head before local fixture append.",
            "actor": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
        }
        return cls._ssh_envelope(
            "urn:agentapi-doctor:chain-head-witness:v1alpha1",
            "ChainHeadWitness",
            "agentapi-doctor/chain-head-witness/v1",
            body,
        )

    @classmethod
    def _operation(cls, current, context, *, operation: str, to_state: str, seed: int) -> dict:
        status = current.state_core["phases"]["P00"]["workUnits"][
            context.subject.work_unit
        ]["status"]
        return {
            "operationId": f"operation-{seed}",
            "type": operation,
            "subject": cls._subject_document(context.subject),
            "fromState": status,
            "toState": to_state,
            "priorStateDigest": current.state_digest,
            "priorChainHeadDigest": cls._head(current),
            "workflowExecutionCommit": cls.request_commit,
            "contractApprovalDigest": context.contract_approval_digest,
            "impactMapDigest": context.impact_map_digest,
            "protectedInputsDigest": document_digest(
                {"protectedInputs": dict(context.protected_inputs)}
            ),
            "criteriaDigest": document_digest(
                {"criteria": criterion_documents(context.criteria)}
            ),
            "prerequisiteUnits": list(context.prerequisite_units),
        }

    @staticmethod
    def _bundle_bytes(document: dict) -> bytes:
        value = deepcopy(document)
        value["bundleDigest"] = document_digest(value)
        return canonical_json_bytes(value)

    @classmethod
    def _convergence_or_attachment_bundle(
        cls,
        current,
        *,
        event_time: datetime,
        seed: int,
        attachment: bool,
    ) -> bytes:
        context, raw_freeze, freeze = cls._freeze(
            current,
            work_unit="P00.W01",
            issued_at=event_time - timedelta(minutes=10),
            seed=seed,
        )
        raw_result, verified_result, execution = cls._machine_evidence(
            current,
            context=context,
            freeze=freeze,
            issued_at=event_time - timedelta(minutes=4),
            seed=seed + 1,
        )
        if attachment:
            operation = OP_ATTACHMENT
            status = current.state_core["phases"]["P00"]["workUnits"]["P00.W01"][
                "status"
            ]
            proof = None
            approval = None
        else:
            operation = OP_CONVERGENCE
            state = cls._state_context(current, context)
            verifier = cls._authority(current, PROOF_NAMESPACE)
            proof, _verified_proof = create_signed_work_unit_transition_proof(
                freeze=freeze,
                criterion_results=[verified_result],
                state_context=state,
                verifier=verifier,
                issued_at=event_time - timedelta(minutes=2),
                token_provider=lambda audience: cls._token(
                    audience,
                    commit=cls.request_commit,
                    when=event_time - timedelta(minutes=2),
                    run_id=seed + 2,
                ),
            )
            status = proof["body"]["toState"]
            projection = {
                key: deepcopy(proof["body"][key])
                for key in (
                    "freezeDigest",
                    "subject",
                    "fromState",
                    "toState",
                    "priorStateDigest",
                    "priorChainHeadDigest",
                    "criterionResults",
                )
            }
            approval = cls._ssh_envelope(
                TRANSITION_APPROVAL_SCHEMA,
                TRANSITION_APPROVAL_KIND,
                TRANSITION_APPROVAL_NAMESPACE,
                {
                    "approvalId": f"approval-{seed}",
                    "proofDigest": proof["attestationDigest"],
                    **projection,
                    "decision": "APPROVE",
                    "reason": "Independent approval of exact synthetic proof.",
                    "conflictOfInterest": {
                        "independent": True,
                        "statement": "Fixture reviewer is separate from workflow signer.",
                    },
                    "issuedAt": cls._text(event_time - timedelta(minutes=1)),
                    "validUntil": cls._text(event_time + timedelta(minutes=10)),
                    "actor": {
                        "principal": "reviewer@test.invalid",
                        "role": "independent-reviewer",
                        "organization": "independent-test",
                    },
                    "authorityDigest": cls.policy_digest,
                },
            )
        return cls._bundle_bytes(
            {
                "schemaVersion": BUNDLE_SCHEMA,
                "kind": BUNDLE_KIND,
                "bundleId": f"bundle-{seed}",
                "operation": cls._operation(
                    current,
                    context,
                    operation=operation,
                    to_state=status,
                    seed=seed,
                ),
                "chainHeadWitness": cls._witness(
                    current, event_time=event_time, seed=seed
                ),
                "delegations": [],
                "revocations": [],
                "protectedInputFreeze": raw_freeze,
                "criterionResults": [raw_result],
                "lateBoundDatasetSelections": [],
                "machineExecutionArtifacts": [
                    {
                        "criterionId": verified_result.criterion.criterion_id,
                        "evidence": execution,
                    }
                ],
                "externalFactEvidence": [],
                "proof": proof,
                "approval": approval,
            }
        )

    @classmethod
    def _lifecycle_bundle(
        cls,
        current,
        *,
        event_time: datetime,
        seed: int,
        activation: bool,
    ) -> bytes:
        context, _raw_freeze, freeze = cls._freeze(
            current,
            work_unit="P00.W02",
            issued_at=event_time - timedelta(minutes=10),
            seed=seed,
        )
        state = cls._state_context(current, context)
        if activation:
            operation = OP_ACTIVATION
            namespace = ACTIVATION_PROOF_NAMESPACE
            proof, _ = create_signed_activation_proof(
                freeze=freeze,
                state_context=state,
                verifier=cls._authority(current, namespace),
                issued_at=event_time - timedelta(minutes=2),
                token_provider=lambda audience: cls._token(
                    audience,
                    commit=cls.request_commit,
                    when=event_time - timedelta(minutes=2),
                    run_id=seed + 1,
                ),
            )
            approval_schema = ACTIVATION_APPROVAL_SCHEMA
            approval_kind = ACTIVATION_APPROVAL_KIND
            approval_namespace = ACTIVATION_APPROVAL_NAMESPACE
            approval_reason_field = "reason"
            projection_fields = (
                "subject",
                "fromState",
                "toState",
                "priorStateDigest",
                "priorChainHeadDigest",
                "contractApprovalDigest",
                "impactMapDigest",
                "prerequisites",
            )
        else:
            operation = OP_READINESS
            namespace = LIFECYCLE_PROOF_NAMESPACE
            proof, _ = create_signed_lifecycle_proof(
                freeze=freeze,
                state_context=state,
                verifier=cls._authority(current, namespace),
                issued_at=event_time - timedelta(minutes=2),
                token_provider=lambda audience: cls._token(
                    audience,
                    commit=cls.request_commit,
                    when=event_time - timedelta(minutes=2),
                    run_id=seed + 1,
                ),
            )
            approval_schema = LIFECYCLE_APPROVAL_SCHEMA
            approval_kind = LIFECYCLE_APPROVAL_KIND
            approval_namespace = LIFECYCLE_APPROVAL_NAMESPACE
            approval_reason_field = "approvalReason"
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
        projection = {
            key: deepcopy(proof["body"][key]) for key in projection_fields
        }
        approval = cls._ssh_envelope(
            approval_schema,
            approval_kind,
            approval_namespace,
            {
                "approvalId": f"approval-{seed}",
                "proofDigest": proof["attestationDigest"],
                **projection,
                "decision": "APPROVE",
                approval_reason_field: "Independent approval of exact lifecycle proof.",
                "conflictOfInterest": {
                    "independent": True,
                    "statement": "Fixture reviewer is separate from workflow signer.",
                },
                "issuedAt": cls._text(event_time - timedelta(minutes=1)),
                "validUntil": cls._text(event_time + timedelta(minutes=10)),
                "actor": {
                    "principal": "reviewer@test.invalid",
                    "role": "independent-reviewer",
                    "organization": "independent-test",
                },
                "authorityDigest": cls.policy_digest,
            },
        )
        return cls._bundle_bytes(
            {
                "schemaVersion": BUNDLE_SCHEMA,
                "kind": BUNDLE_KIND,
                "bundleId": f"bundle-{seed}",
                "operation": cls._operation(
                    current,
                    context,
                    operation=operation,
                    to_state="ACTIVE" if activation else "READY",
                    seed=seed,
                ),
                "chainHeadWitness": cls._witness(
                    current, event_time=event_time, seed=seed
                ),
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

    def test_real_sshsig_oidc_genesis_replay_recomputes_full_control_map(self) -> None:
        replay = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        )
        self.assertIs(require_verified_protected_chain_replay(replay), replay)
        self.assertEqual(replay.event_count, 1)
        self.assertEqual(replay.head_sequence, 0)
        self.assertEqual(replay.control_plane_digest, self.control_digest)
        self.assertEqual(replay.state_view["activeWorkUnit"], "P00.W01")
        copied = deepcopy(replay)
        with self.assertRaises(WorkflowOrchestratorError) as caught:
            require_verified_protected_chain_replay(copied)
        self.assertEqual(caught.exception.code, "unverified_internal_result")
        replay.state_view["activeWorkUnit"] = "P00.W02"
        with self.assertRaises(WorkflowOrchestratorError) as caught:
            require_verified_protected_chain_replay(replay)
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_raw_chain_append_e2e_reaches_w02_active(self) -> None:
        chain = self.raw_chain
        current = replay_protected_chain(
            chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        ).current
        steps = [
            (OP_CONVERGENCE, "MACHINE_CONVERGED", "P00.W01", False, 10),
            (OP_ATTACHMENT, "MACHINE_CONVERGED", "P00.W01", True, 20),
            (OP_CONVERGENCE, "CONVERGED", "P00.W01", False, 30),
            (OP_READINESS, "READY", "P00.W02", False, 40),
            (OP_ACTIVATION, "ACTIVE", "P00.W02", True, 50),
        ]
        for operation, to_state, work_unit, flag, seed in steps:
            event_time = datetime(2026, 7, 11, 9, seed, tzinfo=timezone.utc)
            if operation in {OP_CONVERGENCE, OP_ATTACHMENT}:
                bundle = self._convergence_or_attachment_bundle(
                    current,
                    event_time=event_time,
                    seed=seed,
                    attachment=flag,
                )
            else:
                bundle = self._lifecycle_bundle(
                    current,
                    event_time=event_time,
                    seed=seed,
                    activation=flag,
                )
            chain, view = append_post_genesis(
                chain,
                bundle,
                repo_root=self.repo,
                expected_bootstrap_request_commit=self.request_commit,
                expected_current_chain_head_digest=self._head(current),
                expected_operation=operation,
                expected_to_state=to_state,
                expected_work_unit=work_unit,
                current_workflow_execution_commit=self.request_commit,
                statement_timestamp=event_time,
                token_provider=lambda audience, event_time=event_time, seed=seed: self._token(
                    audience,
                    commit=self.request_commit,
                    when=event_time,
                    run_id=seed + 500,
                ),
            )
            replay = replay_protected_chain(
                chain,
                repo_root=self.repo,
                expected_bootstrap_request_commit=self.request_commit,
                expected_chain_head_digest=view["chain"]["headDigest"],
            )
            current = replay.current
            self.assertEqual(
                view["phases"]["P00"]["workUnits"][work_unit]["status"],
                to_state,
            )
        self.assertEqual(current.event_count, 6)
        self.assertEqual(current.state_core["activeWorkUnit"], "P00.W02")
        self.assertEqual(
            current.state_core["phases"]["P00"]["workUnits"]["P00.W01"][
                "status"
            ],
            "CONVERGED",
        )
        self.assertEqual(len(current.attachments), 1)
        index = verified_machine_evidence_index(replay)
        self.assertEqual(len(index), 3)
        self.assertEqual([item.event_sequence for item in index], [1, 2, 3])
        self.assertEqual(
            [item.operation for item in index],
            [OP_CONVERGENCE, OP_ATTACHMENT, OP_CONVERGENCE],
        )
        self.assertTrue(
            all(
                item.criterion_id == "P00-M-BOOTSTRAP-CONTROL"
                and item.outcome == "PASS"
                and item.verification_pair_id
                and item.execution_bundle_digest.startswith("sha256:")
                and item.run_pair_digest == item.evidence_digest
                for item in index
            )
        )
        self.assertRegex(
            replay.machine_evidence_index_digest, r"^sha256:[0-9a-f]{64}$"
        )
        object.__setattr__(index[0], "verification_pair_id", "forged-pair")
        with self.assertRaises(WorkflowOrchestratorError) as caught:
            require_verified_protected_chain_replay(replay)
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_machine_raw_artifact_stdout_summary_and_missing_mutants_fail(self) -> None:
        replay = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        )
        event_time = datetime(2026, 7, 11, 9, 10, tzinfo=timezone.utc)
        raw = self._convergence_or_attachment_bundle(
            replay.current,
            event_time=event_time,
            seed=110,
            attachment=False,
        )
        original = json.loads(raw)
        outer = deepcopy(original)
        outer["bundleDigest"] = D("0")
        with self.assertRaises(WorkflowOrchestratorError) as caught:
            append_post_genesis(
                self.raw_chain,
                canonical_json_bytes(outer),
                repo_root=self.repo,
                expected_bootstrap_request_commit=self.request_commit,
                expected_current_chain_head_digest=self.genesis["eventDigest"],
                expected_operation=OP_CONVERGENCE,
                expected_to_state="MACHINE_CONVERGED",
                expected_work_unit="P00.W01",
                current_workflow_execution_commit=self.request_commit,
                statement_timestamp=event_time,
                token_provider=lambda _audience: (_ for _ in ()).throw(
                    AssertionError("outer digest mutant reached token provider")
                ),
            )
        self.assertEqual(caught.exception.code, "bundle_digest_mismatch")
        mutants = []
        missing = deepcopy(original)
        missing["machineExecutionArtifacts"] = []
        mutants.append((missing, {"machine_execution_artifact_set_mismatch"}))
        stdout = deepcopy(original)
        stdout["machineExecutionArtifacts"][0]["evidence"]["runs"][0]["stdout"][
            "data"
        ] = base64.b64encode(b"{}").decode("ascii")
        stdout_evidence = stdout["machineExecutionArtifacts"][0]["evidence"]
        stdout_evidence["bundleDigest"] = document_digest(
            stdout_evidence, omit_field="bundleDigest"
        )
        mutants.append((stdout, {"raw_output_digest_mismatch"}))
        summary = deepcopy(original)
        summary["machineExecutionArtifacts"][0]["evidence"]["runs"][0][
            "semanticAssertions"
        ][0]["status"] = "FAIL"
        summary_evidence = summary["machineExecutionArtifacts"][0]["evidence"]
        summary_evidence["bundleDigest"] = document_digest(
            summary_evidence, omit_field="bundleDigest"
        )
        mutants.append(
            (
                summary,
                {"semantic_assertion_mismatch", "artifact_digest_mismatch"},
            )
        )
        for mutant, codes in mutants:
            mutant["bundleDigest"] = document_digest(
                mutant, omit_field="bundleDigest"
            )
            with self.subTest(codes=codes):
                with self.assertRaises(WorkflowOrchestratorError) as caught:
                    append_post_genesis(
                        self.raw_chain,
                        canonical_json_bytes(mutant),
                        repo_root=self.repo,
                        expected_bootstrap_request_commit=self.request_commit,
                        expected_current_chain_head_digest=self.genesis["eventDigest"],
                        expected_operation=OP_CONVERGENCE,
                        expected_to_state="MACHINE_CONVERGED",
                        expected_work_unit="P00.W01",
                        current_workflow_execution_commit=self.request_commit,
                        statement_timestamp=event_time,
                        token_provider=lambda _audience: (_ for _ in ()).throw(
                            AssertionError("mutant reached token provider")
                        ),
                    )
                self.assertIn(caught.exception.code, codes)

    def test_cross_process_replay_uses_only_raw_artifact_and_git_objects(self) -> None:
        artifact = self.root / "chain.json"
        artifact.write_bytes(self.raw_chain)
        script = """
from pathlib import Path
import sys
from tools.phasegate.workflow_orchestrator import replay_protected_chain
value = replay_protected_chain(
    Path(sys.argv[1]).read_bytes(),
    repo_root=Path(sys.argv[2]),
    expected_bootstrap_request_commit=sys.argv[3],
    expected_chain_head_digest=sys.argv[4],
)
print(value.event_count, value.state_view['activeWorkUnit'], value.head_digest)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(artifact),
                str(self.repo),
                self.request_commit,
                self.genesis["eventDigest"],
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
            env={
                "HOME": str(self.root / "isolated-home"),
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(REPO_ROOT),
                "TZ": "UTC",
            },
        )
        self.assertEqual(
            result.stdout.strip(),
            f"1 P00.W01 {self.genesis['eventDigest']}",
        )

    def test_head_request_commit_and_component_mutants_fail_closed(self) -> None:
        cases = [
            ("head", D("0"), self.request_commit, "chain_head_digest_mismatch"),
            (
                "request-commit",
                self.genesis["eventDigest"],
                self.candidate_commit,
                "git_object_unavailable",
            ),
        ]
        for name, head, request_commit, code in cases:
            with self.subTest(name=name):
                with self.assertRaises(WorkflowOrchestratorError) as caught:
                    replay_protected_chain(
                        self.raw_chain,
                        repo_root=self.repo,
                        expected_bootstrap_request_commit=request_commit,
                        expected_chain_head_digest=head,
                    )
                self.assertEqual(caught.exception.code, code)

        component = self.repo / "execution/work-units/P00.W01.yaml"
        original = component.read_bytes()
        component.write_bytes(original + b"\n")
        subprocess.run(["/usr/bin/git", "-C", str(self.repo), "add", str(component)], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "commit", "-q", "-m", "tamper"],
            check=True,
        )
        tampered_commit = self._git_commit()
        try:
            with self.assertRaises(WorkflowOrchestratorError) as caught:
                replay_protected_chain(
                    self.raw_chain,
                    repo_root=self.repo,
                    expected_bootstrap_request_commit=tampered_commit,
                    expected_chain_head_digest=self.genesis["eventDigest"],
                )
            self.assertIn(
                caught.exception.code,
                {"workflow_execution_commit_mismatch", "request_digest_mismatch"},
            )
        finally:
            subprocess.run(
                ["/usr/bin/git", "-C", str(self.repo), "reset", "--hard", "-q", self.request_commit],
                check=True,
            )

    def test_phase_and_unsupported_lifecycle_entries_fail_before_bundle_import(self) -> None:
        for transition_type, work_unit, code in (
            ("RESUME", "P00.W01", "unsupported_lifecycle_operation"),
            ("PHASE", "P00", "unsupported_lifecycle_operation"),
        ):
            with self.subTest(transition_type=transition_type):
                body = {
                    **deepcopy(self.genesis["body"]),
                    "eventType": "StateTransition",
                    "eventId": "evt-00000001",
                    "sequence": 1,
                    "previousDigest": self.genesis["eventDigest"],
                    "timestamp": "2026-07-11T08:01:00Z",
                    "sourceCommit": self.request_commit,
                    "reasonCode": "unsupported-test",
                    "reason": "Synthetic unsupported transition.",
                    "payload": {
                        "transitionType": transition_type,
                        "phase": "P00",
                        "workUnit": work_unit,
                        "toState": "ACTIVE",
                    },
                }
                event = {
                    "schemaVersion": self.genesis["schemaVersion"],
                    "kind": self.genesis["kind"],
                    "body": body,
                    "signature": deepcopy(self.genesis["signature"]),
                }
                event["eventDigest"] = document_digest(event)
                artifact = encode_chain_artifact(
                    bootstrap_approval=self.approval,
                    genesis_event=self.genesis,
                    entries=((event, {}),),
                )
                with self.assertRaises(WorkflowOrchestratorError) as caught:
                    replay_protected_chain(
                        artifact,
                        repo_root=self.repo,
                        expected_bootstrap_request_commit=self.request_commit,
                        expected_chain_head_digest=event["eventDigest"],
                    )
                self.assertEqual(caught.exception.code, code)

    def test_real_crypto_phase_bundle_fresh_import_and_inner_mutant(self) -> None:
        genesis = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        ).current
        core = deepcopy(dict(genesis.state_core))
        core["activePhase"] = "P00"
        core["activeWorkUnit"] = None
        core["pendingWorkUnit"] = None
        phase = core["phases"]["P00"]
        phase["status"] = "ACTIVE"
        for index, (unit_id, unit) in enumerate(sorted(phase["workUnits"].items())):
            unit["status"] = "CONVERGED"
            unit["sourceCommit"] = self.request_commit
            unit["approvalDigest"] = sha256_bytes(f"approval:{index}".encode())
        current = _mark_state_verified(
            replace(
                genesis,
                state_core=core,
                state_digest=document_digest(core),
                head_source_commit=self.request_commit,
            )
        )
        phase_context = derive_phase_control_context(
            current=current,
            oidc_authority=self._authority(current, PHASE_PROOF_NAMESPACE),
            repo_root=self.repo,
            phase="P00",
        )
        aggregate = next(
            item
            for item in phase_context.criteria
            if item.criterion_id == "P00-M-AGGREGATE"
        )
        records = [
            {
                "id": criterion_id,
                "criterionId": criterion_id,
                "kind": "MACHINE",
                "evaluator": evaluator,
                "result": "PASS",
                "evidenceDigest": sha256_bytes(f"evidence:{criterion_id}".encode()),
                "verificationPairId": f"verified-child-{index:02d}",
                "sourceCommit": self.request_commit,
                "controlPlaneDigest": self.control_digest,
                "evaluatorDigest": sha256_bytes(f"evaluator:{criterion_id}".encode()),
                "datasetFreezeDigest": sha256_bytes(f"freeze:{criterion_id}".encode()),
                "datasetDigest": sha256_bytes(f"dataset:{criterion_id}".encode()),
                "verifierDigest": sha256_bytes(f"verifier:{criterion_id}".encode()),
            }
            for index, (criterion_id, evaluator) in enumerate(
                sorted(AGGREGATE_CRITERIA.items())
            )
        ]
        evaluator_input = build_paired_input(
            aggregate.evaluator,
            records,
            source_commit=self.request_commit,
            control_plane_digest=self.control_digest,
            evaluator_digest=aggregate.evaluator_digest,
            dataset_id=PHASE_DATASET_ID,
        )
        manifest = {
            "schemaVersion": "urn:agentapi-doctor:p00-dataset-records:v1alpha1",
            "datasetId": PHASE_DATASET_ID,
            "records": records,
        }
        index_digest = machine_index_digest(())
        provisional = VerifiedPhaseAggregateEvidence(
            evidence_digest="",
            source_machine_index_digest=index_digest,
            phase_context_digest=phase_context.context_digest,
            source_commit=self.request_commit,
            control_plane_digest=self.control_digest,
            aggregate_contract_digest=phase_context.subject.aggregate_contract_digest,
            dataset_digest=evaluator_input["datasetDigest"],
            dataset_manifest=manifest,
            records=tuple(records),
            evaluator_input=evaluator_input,
        )
        evidence = _seal_phase_evidence(
            replace(
                provisional,
                evidence_digest=document_digest(
                    _phase_evidence_projection(provisional)
                ),
            )
        )
        replay = seal_verified_protected_chain_replay(
            VerifiedProtectedChainReplay(
                artifact_digest=D("a"),
                bootstrap_request_commit=self.request_commit,
                candidate_source_commit=self.candidate_commit,
                control_plane_digest=self.control_digest,
                trust_policy_digest=self.policy_digest,
                jwks_snapshot_digest=self.snapshot_digest,
                event_count=current.event_count,
                head_sequence=current.head_sequence,
                head_digest=current.chain_head_digest,
                head_source_commit=current.head_source_commit,
                state_digest=current.state_digest,
                machine_evidence_index_digest=index_digest,
                machine_evidence_index=(),
                state_view=state_view(current),
                current=current,
            )
        )
        dataset_key = self.root / "real-phase-dataset-reviewer"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(dataset_key),
            ],
            check=True,
            timeout=15,
        )
        dataset_public = " ".join(
            dataset_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
        )
        dataset_fingerprint = _ssh_public_key_fingerprint(
            dataset_public, "datasetReviewer.publicKey"
        )
        root = self.policy["sshPrincipals"][0]
        delegation_body = {
            "delegationId": "real-phase-dataset-delegation",
            "policyDigest": self.policy_digest,
            "controlPlaneDigest": self.control_digest,
            "sourceCommit": self.request_commit,
            "priorChainHeadDigest": current.chain_head_digest,
            "delegator": {
                "identity": root["identity"],
                "organization": root["organization"],
                "fingerprint": root["fingerprint"],
            },
            "delegate": {
                "identity": "phase-dataset-reviewer@test.invalid",
                "organization": "phase-dataset-review-org",
                "roles": [DATASET_REVIEWER_ROLE],
                "publicKey": dataset_public,
                "fingerprint": dataset_fingerprint,
                "capabilities": [DATASET_REVIEWER_CAPABILITY],
                "criterionAllowlist": ["P00-M-AGGREGATE"],
                "validFrom": "2026-07-11T09:00:00Z",
                "validUntil": "2026-08-11T09:00:00Z",
            },
            "issuedAt": "2026-07-11T09:00:00Z",
            "reason": "Review the exact raw-chain aggregate dataset.",
        }
        delegation = self._ssh_envelope(
            DELEGATION_SCHEMA,
            DELEGATION_KIND,
            REVIEWER_DELEGATION_NAMESPACE,
            delegation_body,
        )
        roster = build_effective_reviewer_roster(
            policy_result=self.policy_result,
            delegations=[delegation],
            revocations=[],
            expected_policy_digest=self.policy_digest,
            expected_control_plane_digest=self.control_digest,
            expected_source_commit=self.request_commit,
            expected_prior_chain_head_digest=current.chain_head_digest,
            now=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        selection_body = {
            "selectionId": "real-phase-aggregate-selection",
            "baseContextDigest": phase_context.context_digest,
            "subject": {
                "phase": "P00",
                "sourceCommit": self.request_commit,
                "controlPlaneDigest": self.control_digest,
                "aggregateContractDigest": phase_context.subject.aggregate_contract_digest,
            },
            "criterionIds": ["P00-M-AGGREGATE"],
            "datasetCatalog": {
                "path": phase_context.dataset_catalog_bindings[0][1],
                "slotDigest": phase_context.dataset_catalog_bindings[0][2],
            },
            "datasetManifest": manifest,
            "datasetArtifactDigest": document_digest(manifest),
            "recordIds": sorted(item["id"] for item in records),
            "datasetDigest": evaluator_input["datasetDigest"],
            "issuedAt": "2026-07-11T11:00:00Z",
            "validUntil": "2026-07-11T13:00:00Z",
            "actor": {
                "principal": "phase-dataset-reviewer@test.invalid",
                "role": DATASET_REVIEWER_ROLE,
                "organization": "phase-dataset-review-org",
            },
            "conflictOfInterest": {
                "independent": True,
                "statement": "Independent review of exact aggregate records.",
            },
            "authorityDigest": roster.authority_digest,
        }
        selection_statement = {
            "schemaVersion": DATASET_SELECTION_SCHEMA,
            "kind": DATASET_SELECTION_KIND,
            "body": selection_body,
        }
        selection_signature = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(dataset_key),
                "-n",
                DATASET_SELECTION_NAMESPACE,
            ],
            input=canonical_json_bytes(selection_statement),
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout.decode("ascii")
        selection = {
            **selection_statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": DATASET_SELECTION_NAMESPACE,
                "principal": "phase-dataset-reviewer@test.invalid",
                "value": selection_signature,
            },
        }
        selection["attestationDigest"] = document_digest(selection)
        finalized = finalize_late_bound_dataset_context(
            base_context=phase_context,
            raw_selections=[selection],
            roster=roster,
            verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        freeze_body = {
            "freezeId": "real-phase-freeze",
            "subject": {
                "phase": "P00",
                "sourceCommit": self.request_commit,
                "controlPlaneDigest": self.control_digest,
                "aggregateContractDigest": finalized.subject.aggregate_contract_digest,
            },
            "aggregateContractApprovalDigest": finalized.aggregate_contract_approval_digest,
            "unitContractDigests": dict(finalized.unit_contract_digests),
            "protectedInputs": dict(finalized.protected_inputs),
            "criteria": criterion_documents(finalized.criteria),
            "issuedAt": "2026-07-11T11:20:00Z",
            "actor": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "independent-test",
            },
            "authorityDigest": self.policy_digest,
        }
        raw_freeze = self._ssh_envelope(
            PHASE_FREEZE_SCHEMA,
            PHASE_FREEZE_KIND,
            PHASE_FREEZE_NAMESPACE,
            freeze_body,
        )
        freeze = verify_signed_phase_protected_input_freeze(
            raw_freeze,
            expected_subject=finalized.subject,
            expected_aggregate_contract_approval_digest=(
                finalized.aggregate_contract_approval_digest
            ),
            expected_unit_contract_digests=dict(finalized.unit_contract_digests),
            expected_protected_inputs=dict(finalized.protected_inputs),
            expected_criteria=criterion_documents(finalized.criteria),
            expected_authority_digest=self.policy_digest,
            signer_verifier=self._root_signer(PHASE_FREEZE_NAMESPACE),
        )
        execution = execute_phase_pair(
            repo_root=self.repo,
            freeze=freeze,
            criterion_id="P00-M-AGGREGATE",
            evaluator_input=evaluator_input,
        )
        result_time = datetime(2026, 7, 11, 11, 35, tzinfo=timezone.utc)
        raw_result, result = create_signed_phase_machine_criterion_result(
            freeze=freeze,
            criterion_id="P00-M-AGGREGATE",
            run_pair=execution.run_pair,
            verifier=self._authority(
                current, "agentapi-doctor/phase-criterion-result/machine/v1"
            ),
            issued_at=result_time,
            token_provider=lambda audience: self._token(
                audience,
                commit=self.request_commit,
                when=result_time,
                run_id=9101,
            ),
        )
        state_context = verify_phase_state_context(
            dict(current.state_core),
            expected_state_digest=current.state_digest,
            expected_chain_head_digest=current.chain_head_digest,
            expected_control_plane_digest=self.control_digest,
            phase="P00",
            expected_status="ACTIVE",
            expected_aggregate_contract_digest=finalized.subject.aggregate_contract_digest,
        )
        proof_time = datetime(2026, 7, 11, 11, 45, tzinfo=timezone.utc)
        raw_proof, proof = create_signed_phase_transition_proof(
            freeze=freeze,
            criterion_results=[result],
            state_context=state_context,
            verifier=self._authority(current, PHASE_PROOF_NAMESPACE),
            issued_at=proof_time,
            token_provider=lambda audience: self._token(
                audience,
                commit=self.request_commit,
                when=proof_time,
                run_id=9102,
            ),
        )
        approval_body = {
            "approvalId": "real-phase-approval",
            "proofDigest": proof.attestation_digest,
            "freezeDigest": proof.freeze_digest,
            "subject": freeze_body["subject"],
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
            "reason": "Independent review of exact aggregate proof.",
            "conflictOfInterest": {
                "independent": True,
                "statement": "Independent fixture reviewer.",
            },
            "issuedAt": "2026-07-11T11:50:00Z",
            "validUntil": "2026-07-11T12:30:00Z",
            "actor": freeze_body["actor"],
            "authorityDigest": self.policy_digest,
        }
        raw_approval = self._ssh_envelope(
            PHASE_APPROVAL_SCHEMA,
            PHASE_APPROVAL_KIND,
            PHASE_APPROVAL_NAMESPACE,
            approval_body,
        )
        event_time = datetime(2026, 7, 11, 12, tzinfo=timezone.utc)
        operation = {
            "operationId": "real-phase-active-machine",
            "type": OP_PHASE_TRANSITION,
            "subject": freeze_body["subject"],
            "fromState": "ACTIVE",
            "toState": "MACHINE_CONVERGED",
            "priorStateDigest": current.state_digest,
            "priorChainHeadDigest": current.chain_head_digest,
            "workflowExecutionCommit": self.request_commit,
            "phaseContextDigest": finalized.context_digest,
            "aggregateEvidenceDigest": evidence.evidence_digest,
            "aggregateContractApprovalDigest": finalized.aggregate_contract_approval_digest,
            "impactMapDigest": finalized.impact_map_digest,
            "unitContractDigests": dict(finalized.unit_contract_digests),
            "protectedInputsDigest": document_digest(
                {"protectedInputs": dict(finalized.protected_inputs)}
            ),
            "criteriaDigest": document_digest(
                {"criteria": criterion_documents(finalized.criteria)}
            ),
        }
        raw_bundle = self._bundle_bytes(
            {
                "schemaVersion": PHASE_BUNDLE_SCHEMA,
                "kind": PHASE_BUNDLE_KIND,
                "bundleId": "real-phase-bundle",
                "operation": operation,
                "chainHeadWitness": self._witness(
                    current, event_time=event_time, seed=9190
                ),
                "delegations": [delegation],
                "revocations": [],
                "lateBoundDatasetSelections": [selection],
                "phaseProtectedInputFreeze": raw_freeze,
                "phaseMachineExecutionArtifact": json.loads(
                    execution.artifact_bundle
                ),
                "phaseCriterionResult": raw_result,
                "proof": raw_proof,
                "approval": raw_approval,
                "goNoGo": [],
            }
        )
        imported = verify_serialized_phase_authorization_bundle(
            raw_bundle,
            replay=replay,
            policy_result=self.policy_result,
            approved_jwks_snapshot=self.snapshot,
            repo_root=self.repo,
            current_workflow_execution_commit=self.request_commit,
            expected_to_state="MACHINE_CONVERGED",
            control_context=phase_context,
            aggregate_evidence=evidence,
            verification_time=event_time,
        )
        self.assertEqual(imported.event_input.to_state, "MACHINE_CONVERGED")
        self.assertEqual(imported.machine_execution.run_pair_digest, result.run_pair_digest)

        mutant = json.loads(raw_bundle)
        mutant["proof"]["body"]["issuedAt"] = "2026-07-11T11:45:01Z"
        mutant["proof"]["attestationDigest"] = document_digest(
            mutant["proof"], omit_field="attestationDigest"
        )
        mutant_raw = self._bundle_bytes(
            {key: value for key, value in mutant.items() if key != "bundleDigest"}
        )
        with self.assertRaises(PhaseBundleError):
            verify_serialized_phase_authorization_bundle(
                mutant_raw,
                replay=replay,
                policy_result=self.policy_result,
                approved_jwks_snapshot=self.snapshot,
                repo_root=self.repo,
                current_workflow_execution_commit=self.request_commit,
                expected_to_state="MACHINE_CONVERGED",
                control_context=phase_context,
                aggregate_evidence=evidence,
                verification_time=event_time,
            )

    def test_phase_append_orchestrator_e2e_and_duplicate_event_reject(self) -> None:
        genesis = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        ).current
        core = deepcopy(dict(genesis.state_core))
        core["activePhase"] = "P00"
        core["activeWorkUnit"] = None
        core["pendingWorkUnit"] = None
        phase = core["phases"]["P00"]
        phase["status"] = "ACTIVE"
        for index, (_unit_id, unit) in enumerate(sorted(phase["workUnits"].items())):
            unit["status"] = "CONVERGED"
            unit["sourceCommit"] = self.request_commit
            unit["approvalDigest"] = sha256_bytes(f"phase-unit:{index}".encode())
        current = _mark_state_verified(
            replace(
                genesis,
                state_core=core,
                state_digest=document_digest(core),
                head_source_commit=self.request_commit,
            )
        )
        trust = orchestrator_module._BootstrapTrust(
            request=self.request,
            policy=self.policy,
            jwks=self.snapshot,
            policy_result=self.policy_result,
            approval_result=self.approval_result,
            candidate_source_commit=self.candidate_commit,
            control_plane_digest=self.control_digest,
            request_digest=self.request_digest,
            policy_digest=self.policy_digest,
            jwks_digest=self.snapshot_digest,
        )
        raw_chain = self.raw_chain
        transitions = (
            ("ACTIVE", "MACHINE_CONVERGED"),
            ("MACHINE_CONVERGED", "REVIEW_PENDING"),
            ("REVIEW_PENDING", "CONVERGED"),
        )
        final_event = None
        final_transition = None
        final_witness = None
        for offset, (from_state, to_state) in enumerate(transitions):
            self.assertEqual(
                current.state_core["phases"]["P00"]["status"], from_state
            )
            head = self._head(current)
            units = tuple(
                PhaseUnitStateBinding(
                    work_unit=unit_id,
                    status=unit["status"],
                    contract_digest=unit["contractDigest"],
                    source_commit=unit["sourceCommit"],
                    approval_digest=unit["approvalDigest"],
                )
                for unit_id, unit in sorted(
                    current.state_core["phases"]["P00"]["workUnits"].items()
                )
            )
            transition = _mark_provenance_verified(
                VerifiedPhaseTransition(
                    transition_type="PHASE_AGGREGATE",
                    subject=PhaseSubject(
                        phase="P00",
                        source_commit=self.request_commit,
                        control_plane_digest=self.control_digest,
                        aggregate_contract_digest=(
                            current.state_core["phases"]["P00"]
                            ["aggregateContractDigest"]
                        ),
                    ),
                    from_state=from_state,
                    to_state=to_state,
                    prior_state_digest=current.state_digest,
                    prior_chain_head_digest=head,
                    freeze_digest=sha256_bytes(f"freeze:{offset}".encode()),
                    proof_digest=sha256_bytes(f"proof:{offset}".encode()),
                    approval_digest=sha256_bytes(f"approval:{offset}".encode()),
                    go_nogo_authorization_digest=(
                        sha256_bytes(b"final-go-no-go")
                        if to_state == "CONVERGED"
                        else None
                    ),
                    evidence_digest=sha256_bytes(f"evidence:{offset}".encode()),
                    criterion_result_digests=(
                        sha256_bytes(f"result:{offset}".encode()),
                    ),
                    unit_states=units,
                )
            )
            event_time = datetime(
                2026, 7, 11, 12, offset + 1, tzinfo=timezone.utc
            )
            witness = _mark_chain_witness(
                VerifiedChainHeadWitness(
                    attestation_digest=sha256_bytes(f"witness:{offset}".encode()),
                    witness_id=f"phase-witness-{offset}",
                    prior_chain_head_digest=head,
                    prior_state_digest=current.state_digest,
                    prior_event_count=current.event_count,
                    prior_head_sequence=current.head_sequence,
                    prior_source_commit=current.head_source_commit,
                    control_plane_digest=self.control_digest,
                    trust_policy_digest=self.policy_digest,
                    witnessed_at=self._head_time(current),
                    valid_until=event_time + timedelta(minutes=10),
                    principal="reviewer@test.invalid",
                    organization="independent-test",
                )
            )
            parsed = parse_chain_artifact(raw_chain)
            replay = orchestrator_module._replay_snapshot(
                parsed=parsed,
                current=current,
                trust=trust,
                request_commit=self.request_commit,
                machine_index=(),
            )
            details = orchestrator_module._ReplayDetails(
                parsed=parsed, replay=replay, trust=trust
            )
            imported = SimpleNamespace(
                event_input=transition,
                chain_head_witness=witness,
            )
            context = SimpleNamespace(
                component_digests=tuple(sorted(self.components.items()))
            )
            captured = []
            original_create = orchestrator_module.create_post_genesis_event

            def capture_create(**kwargs):
                result = original_create(**kwargs)
                captured.append(result[1])
                return result

            with (
                patch.object(
                    orchestrator_module, "_replay_details", return_value=details
                ),
                patch.object(
                    orchestrator_module,
                    "build_oidc_provenance_verifier",
                    return_value=SimpleNamespace(),
                ),
                patch.object(
                    orchestrator_module,
                    "derive_phase_control_context",
                    return_value=context,
                ),
                patch.object(
                    orchestrator_module,
                    "derive_work_unit_control_context",
                    return_value=SimpleNamespace(),
                ),
                patch.object(
                    orchestrator_module,
                    "build_p00_phase_aggregate_evidence",
                    return_value=SimpleNamespace(),
                ),
                patch.object(
                    orchestrator_module,
                    "verify_serialized_phase_authorization_bundle",
                    return_value=imported,
                ),
                patch.object(
                    orchestrator_module,
                    "create_post_genesis_event",
                    side_effect=capture_create,
                ),
            ):
                raw_chain, view = append_post_genesis(
                    raw_chain,
                    canonical_json_bytes({}),
                    repo_root=self.repo,
                    expected_bootstrap_request_commit=self.request_commit,
                    expected_current_chain_head_digest=head,
                    expected_operation=OP_PHASE_TRANSITION,
                    expected_to_state=to_state,
                    expected_work_unit=None,
                    expected_phase="P00",
                    current_workflow_execution_commit=self.request_commit,
                    statement_timestamp=event_time,
                    token_provider=lambda audience, run=9200 + offset: self._token(
                        audience,
                        commit=self.request_commit,
                        when=event_time,
                        run_id=run,
                    ),
                )
            self.assertEqual(len(captured), 1)
            current = captured[0]
            final_event = parse_chain_artifact(raw_chain).events[-1]
            self.assertEqual(
                final_event["body"]["payload"]["transitionType"],
                "PHASE_AGGREGATE",
            )
            self.assertNotIn("workUnit", final_event["body"]["payload"])
            self.assertEqual(view["phases"]["P00"]["status"], to_state)
            final_transition = transition
            final_witness = witness
        self.assertEqual(current.state_core["phases"]["P00"]["status"], "CONVERGED")
        assert final_event is not None
        assert final_transition is not None
        assert final_witness is not None
        with self.assertRaises(ProtectedVerificationError):
            verify_next_event_v2(
                current=current,
                event=final_event,
                verified_event_input=final_transition,
                expected_chain_head_witness_digest=final_witness.attestation_digest,
                policy_result=self.policy_result,
                approval_result=self.approval_result,
                jwks_snapshot=self.snapshot,
                repo_root=self.repo,
                approved_component_digests=self.components,
            )
        mutant = deepcopy(final_event)
        mutant["body"]["payload"]["workUnit"] = "P00.W05"
        with self.assertRaises(WorkflowOrchestratorError) as caught:
            orchestrator_module._event_intent(current, mutant)
        self.assertEqual(caught.exception.code, "phase_is_not_work_unit")


if __name__ == "__main__":
    unittest.main()
