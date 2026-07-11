from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.control_context import (
    ControlContextError,
    DATASET_REVIEWER_CAPABILITY,
    DATASET_REVIEWER_ROLE,
    DATASET_SELECTION_KIND,
    DATASET_SELECTION_NAMESPACE,
    DATASET_SELECTION_SCHEMA,
    criterion_documents,
    derive_phase_control_context,
    derive_work_unit_control_context,
    finalize_late_bound_dataset_context,
    require_verified_executor_preflight,
    require_verified_phase_control_context,
    require_verified_work_unit_control_context,
)
from tools.phasegate.delegation import (
    DELEGATION_KIND,
    DELEGATION_SCHEMA,
    REVOCATION_KIND,
    REVOCATION_SCHEMA,
    EffectiveReviewerPrincipal,
    EffectiveReviewerRoleGrant,
    EffectiveReviewerRoster,
    _mark_verified as _mark_roster_verified,
    build_effective_reviewer_roster,
)
from tools.phasegate.digest import (
    canonical_json_bytes,
    compute_control_plane_digest,
    sha256_bytes,
)
from tools.phasegate.oidc_provenance import (
    OidcProvenanceVerifier,
    _mark_verified as _mark_oidc_verified,
)
from tools.phasegate.oidc import jwks_snapshot_digest
from tools.phasegate.protected import (
    _ssh_public_key_fingerprint,
    _state_core_digest,
    document_digest,
)
from tools.phasegate.protected_v2 import (
    REVIEWER_DELEGATION_NAMESPACE,
    validate_trust_policy_v2,
)
from tools.phasegate.state_chain_v2 import (
    EXECUTED_VERIFIER_PATHS,
    VerifiedGenesisAnchorV2,
    _mark_verified as _mark_state_verified,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def D(character: str) -> str:
    return "sha256:" + character * 64


class ApprovedControlFixture:
    def __init__(self, root: Path, mutator=None) -> None:
        self.root = root
        self.documents = self._documents()
        if mutator is not None:
            mutator(self.documents)
        self._write_candidate()
        digest, _ = compute_control_plane_digest(root)
        self.control_plane_digest = digest
        for document in self.documents.values():
            if "controlPlaneDigest" in document:
                document["controlPlaneDigest"] = digest
        self._write_candidate()
        recomputed, components = compute_control_plane_digest(root)
        if recomputed != digest:
            raise AssertionError("normalized controlPlaneDigest changed aggregate")
        self.components = {item["path"]: item["digest"] for item in components}
        self._commit()
        self.current = self._current()
        self.authority = self._authority()

    def _criterion(self) -> dict:
        return {
            "id": "P00-M-BOOTSTRAP-CONTROL",
            "kind": "MACHINE",
            "evaluator": "evaluator://bootstrap/control-plane/v1",
            "threshold": "all protected bootstrap assertions pass",
            "evidenceSchema": "evidence-schema://bootstrap/control-plane-report/v1",
        }

    def _phase_criterion(self) -> dict:
        return {
            "id": "P00-M-AGGREGATE",
            "kind": "MACHINE",
            "evaluator": "evaluator://phase/aggregate/v1",
            "threshold": "all P00 work units and machine criteria pass",
            "evidenceSchema": "evidence-schema://phase/aggregate-report/v1",
        }

    def _w02_criterion(self) -> dict:
        return {
            "id": "P00-H-W02-REVIEW",
            "kind": "HUMAN",
            "evaluator": "attestation://review/w02/v1",
            "threshold": "independent review approved",
            "evidenceSchema": "evidence-schema://attestation/human-review/v1",
        }

    def _documents(self) -> dict[str, dict]:
        placeholder = "sha256:__CONTROL_PLANE_DIGEST__"
        work_criterion = self._criterion()
        phase_criterion = self._phase_criterion()
        w02_criterion = self._w02_criterion()
        return {
            "execution/protected-verifier/workflow-contract.yaml": {
                "schemaVersion": "urn:agentapi-doctor:protected-verifier-workflow-contract:v1alpha2",
                "kind": "ProtectedStateWorkflowContractCandidate",
                "controlPlaneDigest": placeholder,
                "workflows": {
                    "crossPlatform": ".github/workflows/p00-bootstrap-cross-platform.yml",
                    "stateWriter": ".github/workflows/p00-protected-state-writer.yml",
                },
                "actionPins": [
                    {
                        "repository": "actions/checkout",
                        "version": "v4",
                        "commit": "1" * 40,
                    },
                    {
                        "repository": "actions/upload-artifact",
                        "version": "v4",
                        "commit": "2" * 40,
                    },
                ],
                "runtime": {
                    "runner": "ubuntu-24.04",
                    "pythonDependencies": "stdlib only",
                    "candidateDependencyInstall": "forbidden",
                    "runAttempt": 1,
                    "timeoutMinutes": 10,
                    "toolchainRecordedInArtifact": True,
                },
                "networkPolicy": {"dependencyInstall": "forbidden"},
            },
            "execution/evaluators/catalog.yaml": {
                "schemaVersion": "urn:agentapi-doctor:evaluator-catalog:v1",
                "kind": "EvaluatorCatalogCandidate",
                "catalogStatus": "candidate-unapproved",
                "controlPlaneDigest": placeholder,
                "evaluators": [
                    {
                        "id": "evaluator://bootstrap/control-plane/v1",
                        "kind": "MACHINE",
                        "status": "implemented",
                        "implementation": {
                            "type": "builtin",
                            "handler": "bootstrap.control_plane",
                        },
                        "implementationPaths": ["tools/phasegate/evaluator.py"],
                        "protectedTests": ["test/bootstrap/protected.py"],
                    },
                    {
                        "id": "evaluator://phase/aggregate/v1",
                        "kind": "MACHINE",
                        "status": "implemented",
                        "implementation": {
                            "type": "builtin",
                            "handler": "p00.aggregate",
                        },
                        "implementationPaths": ["tools/phasegate/evaluator.py"],
                        "protectedTests": ["test/bootstrap/protected.py"],
                    },
                    {
                        "id": "attestation://review/w02/v1",
                        "kind": "HUMAN",
                        "status": "human-only",
                        "implementation": {"type": "attestation", "handler": None},
                        "producer": "independent-reviewer",
                    },
                ],
            },
            "execution/evidence-schemas/catalog.yaml": {
                "schemaVersion": "urn:agentapi-doctor:evidence-schema-catalog:v1",
                "kind": "EvidenceSchemaCatalogCandidate",
                "catalogStatus": "candidate-unapproved",
                "controlPlaneDigest": placeholder,
                "schemas": [
                    {
                        "id": "evidence-schema://bootstrap/control-plane-report/v1",
                        "kind": "MACHINE",
                        "status": "implemented",
                        "requiredFields": ["criterionId", "result"],
                    },
                    {
                        "id": "evidence-schema://phase/aggregate-report/v1",
                        "kind": "MACHINE",
                        "status": "implemented",
                        "requiredFields": ["criterionId", "result"],
                    },
                    {
                        "id": "evidence-schema://attestation/human-review/v1",
                        "kind": "HUMAN",
                        "status": "human-only",
                        "requiredFields": ["criterionId", "decision"],
                    },
                ],
            },
            "execution/metrics/definitions.yaml": {
                "schemaVersion": "urn:agentapi-doctor:metric-catalog:v1",
                "kind": "MetricDefinitionCatalogCandidate",
                "catalogStatus": "candidate-unapproved",
                "controlPlaneDigest": placeholder,
                "metrics": [
                    {
                        "id": "unused_fixture_metric",
                        "evaluator": "evaluator://bootstrap/control-plane/v1",
                        "evaluatorDigest": D("1"),
                        "datasetCatalog": "execution/catalogs/p00/bootstrap.yaml",
                        "datasetStatus": "fixed",
                        "datasetDigest": D("2"),
                        "threshold": "unused",
                    }
                ],
            },
            "execution/catalogs/p00/acceptance.yaml": {
                "schemaVersion": "urn:agentapi-doctor:protected-acceptance-catalog:v1",
                "kind": "ProtectedAcceptanceCatalogCandidate",
                "catalogStatus": "candidate-unapproved",
                "controlPlaneDigest": placeholder,
                "criteria": [
                    {
                        "id": work_criterion["id"],
                        "owner": "P00.W01",
                        "kind": "MACHINE",
                        "evaluator": work_criterion["evaluator"],
                        "evaluatorStatus": "implemented",
                    },
                    {
                        "id": phase_criterion["id"],
                        "owner": "P00",
                        "kind": "MACHINE",
                        "evaluator": phase_criterion["evaluator"],
                        "evaluatorStatus": "implemented",
                    },
                    {
                        "id": w02_criterion["id"],
                        "owner": "P00.W02",
                        "kind": "HUMAN",
                        "evaluator": w02_criterion["evaluator"],
                        "evaluatorStatus": "human-only",
                    },
                ],
            },
            "execution/catalogs/p00/bootstrap.yaml": {
                "schemaVersion": "urn:agentapi-doctor:protected-catalog:v1",
                "kind": "BootstrapAcceptanceDefinitionCandidate",
                "catalogStatus": "candidate-unapproved",
                "protected": True,
                "controlPlaneDigest": placeholder,
                "requiredAssertions": [{"id": "real-path", "semantic": "execute it"}],
            },
            "execution/catalogs/p00/go-no-go.yaml": {
                "schemaVersion": "urn:agentapi-doctor:protected-catalog:v1",
                "kind": "GoNoGoAcceptanceDefinitionCandidate",
                "catalogStatus": "candidate-unapproved",
                "protected": True,
                "controlPlaneDigest": placeholder,
                "requiredAssertions": [{"id": "aggregate", "semantic": "recompute"}],
            },
            "execution/catalogs/p00/competitor-research.yaml": {
                "schemaVersion": "urn:agentapi-doctor:protected-catalog:v1",
                "kind": "CompetitorResearchAcceptanceDefinitionCandidate",
                "catalogStatus": "candidate-unapproved",
                "protected": True,
                "controlPlaneDigest": placeholder,
                "requiredAssertions": [{"id": "review", "semantic": "independent"}],
            },
            "execution/impact-map.yaml": {
                "schemaVersion": "urn:agentapi-doctor:impact-map:v1",
                "kind": "ImpactMapCandidate",
                "mapStatus": "candidate-unapproved",
                "controlPlaneDigest": placeholder,
                "rules": [],
            },
            "execution/work-units/P00.W01.yaml": {
                "schemaVersion": "urn:agentapi-doctor:goal-contract:v1",
                "kind": "WorkUnitContractCandidate",
                "contractStatus": "candidate-unapproved",
                "id": "P00.W01",
                "phase": "P00",
                "controlPlaneDigest": placeholder,
                "protectedAcceptanceInputs": [
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/bootstrap.yaml",
                ],
                "convergence": [deepcopy(work_criterion)],
            },
            "execution/gates/p00/P00.W01.yaml": {
                "schemaVersion": "urn:agentapi-doctor:gate-definition:v1",
                "kind": "WorkUnitGateDefinitionCandidate",
                "id": "gate://p00/P00.W01/v1",
                "phase": "P00",
                "workUnit": "P00.W01",
                "contract": "execution/work-units/P00.W01.yaml",
                "controlPlaneDigest": placeholder,
                "criteria": [deepcopy(work_criterion)],
                "protectedInputs": [
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/bootstrap.yaml",
                    "execution/evaluators/catalog.yaml",
                    "execution/evidence-schemas/catalog.yaml",
                    "test/bootstrap/protected.py",
                ],
            },
            "execution/work-units/P00.W02.yaml": {
                "schemaVersion": "urn:agentapi-doctor:goal-contract:v1",
                "kind": "WorkUnitContractCandidate",
                "contractStatus": "candidate-unapproved",
                "id": "P00.W02",
                "phase": "P00",
                "controlPlaneDigest": placeholder,
                "protectedAcceptanceInputs": [
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/competitor-research.yaml",
                ],
                "convergence": [deepcopy(w02_criterion)],
            },
            "execution/gates/p00/P00.W02.yaml": {
                "schemaVersion": "urn:agentapi-doctor:gate-definition:v1",
                "kind": "WorkUnitGateDefinitionCandidate",
                "id": "gate://p00/P00.W02/v1",
                "phase": "P00",
                "workUnit": "P00.W02",
                "contract": "execution/work-units/P00.W02.yaml",
                "controlPlaneDigest": placeholder,
                "criteria": [deepcopy(w02_criterion)],
                "protectedInputs": [
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/competitor-research.yaml",
                    "execution/evaluators/catalog.yaml",
                    "execution/evidence-schemas/catalog.yaml",
                ],
                "datasetPolicy": {
                    "status": "late_bound_requires_signed_freeze",
                    "digest": None,
                    "missingOrUnfrozenResult": "insufficient_samples",
                },
            },
            "execution/phases/P00.yaml": {
                "schemaVersion": "urn:agentapi-doctor:goal-contract:v1",
                "kind": "PhaseAggregateContractCandidate",
                "contractStatus": "candidate-unapproved",
                "id": "P00",
                "phase": "P00",
                "controlPlaneDigest": placeholder,
                "workUnits": ["P00.W01", "P00.W02"],
                "protectedAcceptanceInputs": [
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/go-no-go.yaml",
                ],
                "convergence": [deepcopy(phase_criterion)],
            },
            "execution/gates/p00/aggregate.yaml": {
                "schemaVersion": "urn:agentapi-doctor:gate-definition:v1",
                "kind": "PhaseAggregateGateDefinitionCandidate",
                "id": "gate://p00/aggregate/v1",
                "phase": "P00",
                "workUnit": None,
                "contract": "execution/phases/P00.yaml",
                "controlPlaneDigest": placeholder,
                "criteria": [deepcopy(phase_criterion)],
                "protectedInputs": [
                    "execution/phases/P00.yaml",
                    "execution/catalogs/p00/acceptance.yaml",
                    "execution/catalogs/p00/go-no-go.yaml",
                    "execution/metrics/definitions.yaml",
                    "execution/evaluators/catalog.yaml",
                    "execution/evidence-schemas/catalog.yaml",
                ],
            },
        }

    def _write_candidate(self) -> None:
        text_files = {
            "agentapi-doctor-Plan.md": "approved plan\n",
            ".github/workflows/p00-bootstrap-cross-platform.yml": (
                REPO_ROOT / ".github/workflows/p00-bootstrap-cross-platform.yml"
            ).read_text(encoding="utf-8"),
            ".github/workflows/p00-protected-state-writer.yml": (
                REPO_ROOT / ".github/workflows/p00-protected-state-writer.yml"
            ).read_text(encoding="utf-8"),
            "tools/phasegate/evaluator.py": "def evaluate():\n    return True\n",
            "test/bootstrap/protected.py": "def test_mutant():\n    assert True\n",
        }
        for path in EXECUTED_VERIFIER_PATHS:
            text_files.setdefault(path, (REPO_ROOT / path).read_text(encoding="utf-8"))
        paths = [(path, "text") for path in text_files]
        paths.extend((path, self._kind(path)) for path in self.documents)
        paths.append(("execution/control-plane-inputs.yaml", "manifest"))
        manifest = {
            "schemaVersion": "urn:agentapi-doctor:control-plane-inputs:v1",
            "kind": "ControlPlaneInputManifestCandidate",
            "manifestStatus": "candidate-unapproved",
            "digestAlgorithm": "sha256",
            "canonicalization": "bootstrap-canonical-json-v1",
            "controlPlaneDigestPlaceholder": "sha256:__CONTROL_PLANE_DIGEST__",
            "normalization": {},
            "inputs": [
                {"path": path, "kind": kind, "required": True}
                for path, kind in sorted(paths)
            ],
            "excluded": [],
        }
        for path, value in text_files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value, encoding="utf-8")
        for path, value in self.documents.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(canonical_json_bytes(value))
        target = self.root / "execution/control-plane-inputs.yaml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canonical_json_bytes(manifest))

    def _kind(self, path: str) -> str:
        if "/gates/" in path:
            return "gate"
        if "/work-units/" in path or "/phases/" in path:
            return "contract"
        if path.endswith("impact-map.yaml"):
            return "manifest"
        return "catalog"

    def _commit(self) -> None:
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(self.root), "config", "user.name", "test"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(self.root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(self.root), "commit", "-q", "-m", "approved"], check=True)
        self.commit = subprocess.run(
            ["/usr/bin/git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _state_core(self) -> dict:
        return {
            "planVersion": "1.0",
            "controlPlaneDigest": self.control_plane_digest,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "phases": {
                "P00": {
                    "status": "ACTIVE",
                    "aggregateContractDigest": self.components["execution/phases/P00.yaml"],
                    "controlPlaneDigest": self.control_plane_digest,
                    "baseCommit": self.commit,
                    "startedAt": "2026-07-11T00:00:00Z",
                    "workUnits": {
                        "P00.W01": {
                            "status": "ACTIVE",
                            "contractDigest": self.components["execution/work-units/P00.W01.yaml"],
                            "approvalDigest": D("a"),
                            "sourceCommit": self.commit,
                        },
                        "P00.W02": {
                            "status": "NOT_STARTED",
                            "contractDigest": self.components[
                                "execution/work-units/P00.W02.yaml"
                            ],
                            "approvalDigest": None,
                            "sourceCommit": None,
                        },
                    },
                }
            },
        }

    def _current(self) -> VerifiedGenesisAnchorV2:
        core = self._state_core()
        return _mark_state_verified(
            VerifiedGenesisAnchorV2(
                state_core=core,
                state_digest=_state_core_digest(core),
                chain_head_digest=D("b"),
                head_sequence=0,
                event_count=1,
                timestamp=datetime(2026, 7, 11, tzinfo=timezone.utc),
                head_source_commit=self.commit,
                attachments=(),
                control_plane_digest=self.control_plane_digest,
                trust_policy_digest=D("c"),
                jwks_snapshot_digest=D("d"),
                workflow_execution_commit=self.commit,
                workflow_run_id="10",
                workflow_check_run_id="20",
                approved_component_digests=tuple(sorted(self.components.items())),
                state_signer_digest=D("e"),
                bootstrap_approval_digest=D("a"),
                bootstrap_request_digest=D("f"),
            )
        )

    def _authority(self) -> OidcProvenanceVerifier:
        components = tuple(sorted(self.components.items()))
        component_set_digest = sha256_bytes(
            canonical_json_bytes({"componentDigests": dict(components)})
        )
        return _mark_oidc_verified(
            OidcProvenanceVerifier(
                namespace="agentapi-doctor/criterion-result/machine/v1",
                principal="github-actions:test",
                role="protected-workflow",
                organization="github-actions",
                policy_digest=D("c"),
                jwks_snapshot_digest=D("d"),
                control_plane_digest=self.control_plane_digest,
                source_commit=self.commit,
                workflow_execution_commit=self.commit,
                approval_digest=D("a"),
                bootstrap_request_digest=D("f"),
                chain_head_digest=D("b"),
                state_digest=self.current.state_digest,
                component_set_digest=component_set_digest,
                component_digests=components,
                expected_claims=(),
                authority_digest=D("1"),
                approved_jwks_json="{}",
            )
        )

    def context(self):
        return derive_work_unit_control_context(
            current=self.current,
            oidc_authority=self.authority,
            repo_root=self.root,
            work_unit="P00.W01",
        )

    def with_component_map(self, components: dict[str, str]):
        tuples = tuple(sorted(components.items()))
        current = _mark_state_verified(
            replace(self.current, approved_component_digests=tuples)
        )
        authority = _mark_oidc_verified(
            replace(
                self.authority,
                component_digests=tuples,
                component_set_digest=sha256_bytes(
                    canonical_json_bytes({"componentDigests": dict(tuples)})
                ),
            )
        )
        return current, authority


class ControlContextTests(unittest.TestCase):
    def fixture(self, mutator=None):
        temporary = tempfile.TemporaryDirectory(prefix="control-context-")
        self.addCleanup(temporary.cleanup)
        return ApprovedControlFixture(Path(temporary.name), mutator)

    def signed_dataset_selection(
        self,
        fixture,
        context,
        *,
        suffix: str,
        roster=None,
        principal=None,
        key=None,
    ):
        criterion_ids = list(context.late_bound_dataset_criteria)
        if roster is None and principal is None and key is None:
            key = fixture.root / f".dataset-reviewer-{suffix}"
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "dataset-reviewer@example.invalid",
                    "-f",
                    str(key),
                ],
                check=True,
            )
            public_fields = key.with_suffix(".pub").read_text(
                encoding="utf-8"
            ).split()
            public_key = " ".join(public_fields[:2])
            grant = EffectiveReviewerRoleGrant(
                role=DATASET_REVIEWER_ROLE,
                capabilities=(DATASET_REVIEWER_CAPABILITY,),
                criteria=tuple(criterion_ids),
            )
            principal = EffectiveReviewerPrincipal(
                identity="dataset-reviewer@example.invalid",
                organization="independent-dataset-org",
                roles=(DATASET_REVIEWER_ROLE,),
                public_key=public_key,
                fingerprint="test-fixture-fingerprint",
                capabilities=(DATASET_REVIEWER_CAPABILITY,),
                criterion_allowlist=tuple(criterion_ids),
                role_grants=(grant,),
                valid_from="2026-07-11T00:00:00Z",
                valid_until="2027-07-11T00:00:00Z",
                origin="delegation",
                delegation_digest=D("6"),
            )
            roster = _mark_roster_verified(
                EffectiveReviewerRoster(
                    policy_digest=D("1"),
                    control_plane_digest=context.subject.control_plane_digest,
                    source_commit=context.subject.source_commit,
                    prior_chain_head_digest=D("2"),
                    delegation_digests=(D("6"),),
                    revocation_digests=(),
                    principals=(principal,),
                    authority_digest=D("3"),
                )
            )
        elif roster is None or principal is None or key is None:
            raise AssertionError("roster, principal, and key are one test fixture")
        records = [{"id": "case-001", "value": 1}, {"id": "case-002", "value": 2}]
        manifest = {
            "schemaVersion": "urn:agentapi-doctor:p00-dataset-records:v1alpha1",
            "datasetId": f"p00-{suffix}-final",
            "records": records,
        }
        catalog_path = context.dataset_catalog_bindings[0][1]
        slot_digest = context.dataset_catalog_bindings[0][2]
        subject = {
            "phase": context.subject.phase,
            "sourceCommit": context.subject.source_commit,
            "controlPlaneDigest": context.subject.control_plane_digest,
        }
        if hasattr(context.subject, "work_unit"):
            subject.update(
                {
                    "workUnit": context.subject.work_unit,
                    "contractDigest": context.subject.contract_digest,
                }
            )
        else:
            subject["aggregateContractDigest"] = (
                context.subject.aggregate_contract_digest
            )
        body = {
            "selectionId": f"selection-{suffix}-final",
            "baseContextDigest": context.context_digest,
            "subject": subject,
            "criterionIds": criterion_ids,
            "datasetCatalog": {"path": catalog_path, "slotDigest": slot_digest},
            "datasetManifest": manifest,
            "datasetArtifactDigest": document_digest(manifest),
            "recordIds": [record["id"] for record in records],
            "datasetDigest": sha256_bytes(canonical_json_bytes(records)),
            "issuedAt": "2026-07-11T11:00:00Z",
            "validUntil": "2026-07-11T13:00:00Z",
            "actor": {
                "principal": principal.identity,
                "role": DATASET_REVIEWER_ROLE,
                "organization": principal.organization,
            },
            "conflictOfInterest": {
                "independent": True,
                "statement": "No financial, employment, or authorship conflict.",
            },
            "authorityDigest": roster.authority_digest,
        }
        statement = {
            "schemaVersion": DATASET_SELECTION_SCHEMA,
            "kind": DATASET_SELECTION_KIND,
            "body": body,
        }
        statement_path = fixture.root / f".dataset-selection-{suffix}.json"
        statement_path.write_bytes(canonical_json_bytes(statement))
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(key),
                "-n",
                DATASET_SELECTION_NAMESPACE,
                str(statement_path),
            ],
            check=True,
            capture_output=True,
        )
        envelope = {
            **statement,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": DATASET_SELECTION_NAMESPACE,
                "principal": principal.identity,
                "value": statement_path.with_suffix(".json.sig").read_text(
                    encoding="ascii"
                ),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return roster, envelope, body

    def test_context_is_mechanically_derived_and_identity_sealed(self) -> None:
        fixture = self.fixture()
        context = fixture.context()
        self.assertIs(require_verified_work_unit_control_context(context), context)
        self.assertIs(
            require_verified_executor_preflight(context.executor_preflight),
            context.executor_preflight,
        )
        self.assertEqual(context.subject.source_commit, fixture.commit)
        self.assertEqual(
            context.subject.contract_digest,
            fixture.components["execution/work-units/P00.W01.yaml"],
        )
        inputs = dict(context.protected_inputs)
        self.assertEqual(inputs["planDigest"], fixture.components["agentapi-doctor-Plan.md"])
        self.assertEqual(
            inputs["evaluatorSetDigest"],
            fixture.components["execution/evaluators/catalog.yaml"],
        )
        criterion = criterion_documents(context.criteria)[0]
        self.assertEqual(
            criterion["evaluatorDigest"],
            fixture.components["tools/phasegate/evaluator.py"],
        )
        self.assertEqual(
            criterion["datasetDigest"],
            fixture.components["execution/catalogs/p00/bootstrap.yaml"],
        )
        with self.assertRaises(ControlContextError) as caught:
            require_verified_work_unit_control_context(deepcopy(context))
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_full_component_map_rejects_extra_missing_and_digest_drift(self) -> None:
        fixture = self.fixture()
        mutations = []
        missing = dict(fixture.components)
        missing.pop("execution/catalogs/p00/bootstrap.yaml")
        mutations.append(("component_map_mismatch", missing))
        extra = dict(fixture.components)
        extra["unapproved.txt"] = D("9")
        mutations.append(("component_map_mismatch", extra))
        drift = dict(fixture.components)
        drift["execution/evaluators/catalog.yaml"] = D("8")
        mutations.append(("approved_component_digest_mismatch", drift))
        for expected, components in mutations:
            with self.subTest(expected=expected):
                current, authority = fixture.with_component_map(components)
                with self.assertRaises(ControlContextError) as caught:
                    derive_work_unit_control_context(
                        current=current,
                        oidc_authority=authority,
                        repo_root=fixture.root,
                        work_unit="P00.W01",
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_threshold_evaluator_schema_and_dataset_mutants_fail_closed(self) -> None:
        def threshold(documents):
            documents["execution/gates/p00/P00.W01.yaml"]["criteria"][0]["threshold"] = "always pass"

        def evaluator(documents):
            for path in (
                "execution/gates/p00/P00.W01.yaml",
                "execution/work-units/P00.W01.yaml",
            ):
                key = "criteria" if "/gates/" in path else "convergence"
                documents[path][key][0]["evaluator"] = "evaluator://missing/v1"

        def schema(documents):
            documents["execution/evidence-schemas/catalog.yaml"]["schemas"][0]["kind"] = "HUMAN"

        def dataset(documents):
            documents["execution/catalogs/p00/bootstrap.yaml"]["protected"] = False

        cases = (
            (threshold, "contract_gate_criteria_mismatch"),
            (evaluator, "missing_criterion_catalog_entry"),
            (schema, "criterion_catalog_mismatch"),
            (dataset, "dataset_catalog_not_protected"),
        )
        for mutator, expected in cases:
            with self.subTest(expected=expected):
                fixture = self.fixture(mutator)
                with self.assertRaises(ControlContextError) as caught:
                    fixture.context()
                self.assertEqual(caught.exception.code, expected)

    def test_phase_context_uses_real_aggregate_contract_and_unit_set(self) -> None:
        fixture = self.fixture()
        context = derive_phase_control_context(
            current=fixture.current,
            oidc_authority=fixture.authority,
            repo_root=fixture.root,
            phase="P00",
        )
        self.assertEqual(
            context.subject.aggregate_contract_digest,
            fixture.components["execution/phases/P00.yaml"],
        )
        self.assertEqual(
            context.unit_contract_digests,
            (
                ("P00.W01", fixture.components["execution/work-units/P00.W01.yaml"]),
                ("P00.W02", fixture.components["execution/work-units/P00.W02.yaml"]),
            ),
        )

    def test_signed_dataset_selection_finalizes_phase_aggregate_context(self) -> None:
        def late_bound(documents):
            documents["execution/gates/p00/aggregate.yaml"]["datasetPolicy"] = {
                "status": "late_bound_requires_signed_freeze",
                "digest": None,
                "missingOrUnfrozenResult": "insufficient_samples",
            }

        fixture = self.fixture(late_bound)
        context = derive_phase_control_context(
            current=fixture.current,
            oidc_authority=fixture.authority,
            repo_root=fixture.root,
            phase="P00",
        )
        self.assertEqual(context.late_bound_dataset_criteria, ("P00-M-AGGREGATE",))
        roster, envelope, body = self.signed_dataset_selection(
            fixture, context, suffix="aggregate"
        )
        finalized = finalize_late_bound_dataset_context(
            base_context=context,
            raw_selections=[envelope],
            roster=roster,
            verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        self.assertIs(require_verified_phase_control_context(finalized), finalized)
        self.assertEqual(finalized.late_bound_dataset_criteria, ())
        self.assertEqual(finalized.criteria[0].dataset_digest, body["datasetDigest"])
        self.assertEqual(
            finalized.dataset_selection_digests,
            (envelope["attestationDigest"],),
        )

    def test_raw_dataset_reviewer_delegation_and_revocation_are_enforced(self) -> None:
        def late_bound(documents):
            documents["execution/gates/p00/aggregate.yaml"]["datasetPolicy"] = {
                "status": "late_bound_requires_signed_freeze",
                "digest": None,
                "missingOrUnfrozenResult": "insufficient_samples",
            }

        fixture = self.fixture(late_bound)
        context = derive_phase_control_context(
            current=fixture.current,
            oidc_authority=fixture.authority,
            repo_root=fixture.root,
            phase="P00",
        )

        def generate_key(name: str) -> Path:
            key = fixture.root / f".{name}"
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(key),
                ],
                check=True,
            )
            return key

        def public_key(key: Path) -> str:
            return " ".join(
                key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
            )

        def envelope(*, schema: str, kind: str, body: dict, key: Path) -> dict:
            unsigned = {"schemaVersion": schema, "kind": kind, "body": body}
            signature = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    REVIEWER_DELEGATION_NAMESPACE,
                ],
                input=canonical_json_bytes(unsigned),
                check=True,
                capture_output=True,
            ).stdout.decode("ascii")
            signed = {
                **unsigned,
                "signature": {
                    "scheme": "openssh-sshsig-v1",
                    "namespace": REVIEWER_DELEGATION_NAMESPACE,
                    "principal": "dataset-root@example.invalid",
                    "value": signature,
                },
            }
            signed["attestationDigest"] = document_digest(signed)
            return signed

        root_key = generate_key("dataset-root")
        reviewer_key = generate_key("dataset-delegate")
        snapshot = json.loads(
            (
                REPO_ROOT
                / "execution/protected-verifier/github-actions-oidc-jwks.json"
            ).read_text(encoding="utf-8")
        )
        policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        policy["controlPlaneDigest"] = context.subject.control_plane_digest
        policy["signatureSchemes"]["stateEvent"]["jwksSnapshotDigest"] = (
            jwks_snapshot_digest(snapshot)
        )
        root = policy["sshPrincipals"][0]
        root.update(
            {
                "identity": "dataset-root@example.invalid",
                "organization": "dataset-root-org",
                "publicKey": public_key(root_key),
            }
        )
        root["fingerprint"] = _ssh_public_key_fingerprint(
            root["publicKey"], "policy.sshPrincipals[0]"
        )
        policy_digest = document_digest(policy)
        policy_result = validate_trust_policy_v2(
            policy,
            jwks_snapshot=snapshot,
            expected_policy_digest=policy_digest,
            expected_jwks_snapshot_digest=jwks_snapshot_digest(snapshot),
            expected_control_plane_digest=context.subject.control_plane_digest,
        )
        reviewer_public_key = public_key(reviewer_key)
        reviewer_fingerprint = _ssh_public_key_fingerprint(
            reviewer_public_key, "delegation.delegate.publicKey"
        )
        delegation = envelope(
            schema=DELEGATION_SCHEMA,
            kind=DELEGATION_KIND,
            key=root_key,
            body={
                "delegationId": "delegation-dataset-aggregate",
                "policyDigest": policy_digest,
                "controlPlaneDigest": context.subject.control_plane_digest,
                "sourceCommit": context.subject.source_commit,
                "priorChainHeadDigest": fixture.current.chain_head_digest,
                "delegator": {
                    "identity": root["identity"],
                    "organization": root["organization"],
                    "fingerprint": root["fingerprint"],
                },
                "delegate": {
                    "identity": "dataset-reviewer@example.invalid",
                    "organization": "independent-dataset-org",
                    "roles": [DATASET_REVIEWER_ROLE],
                    "publicKey": reviewer_public_key,
                    "fingerprint": reviewer_fingerprint,
                    "capabilities": [DATASET_REVIEWER_CAPABILITY],
                    "criterionAllowlist": ["P00-M-AGGREGATE"],
                    "validFrom": "2026-07-11T10:00:00Z",
                    "validUntil": "2026-08-11T10:00:00Z",
                },
                "issuedAt": "2026-07-11T10:00:00Z",
                "reason": "Delegate the exact aggregate dataset freeze review.",
            },
        )
        roster = build_effective_reviewer_roster(
            policy_result=policy_result,
            delegations=[delegation],
            revocations=[],
            expected_policy_digest=policy_digest,
            expected_control_plane_digest=context.subject.control_plane_digest,
            expected_source_commit=context.subject.source_commit,
            expected_prior_chain_head_digest=fixture.current.chain_head_digest,
            now=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        principal = next(
            item
            for item in roster.principals
            if item.identity == "dataset-reviewer@example.invalid"
        )
        _, selection, _ = self.signed_dataset_selection(
            fixture,
            context,
            suffix="raw-delegation",
            roster=roster,
            principal=principal,
            key=reviewer_key,
        )
        finalized = finalize_late_bound_dataset_context(
            base_context=context,
            raw_selections=[selection],
            roster=roster,
            verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(finalized.late_bound_dataset_criteria, ())

        revocation = envelope(
            schema=REVOCATION_SCHEMA,
            kind=REVOCATION_KIND,
            key=root_key,
            body={
                "revocationId": "revocation-dataset-aggregate",
                "delegationDigest": delegation["attestationDigest"],
                "policyDigest": policy_digest,
                "controlPlaneDigest": context.subject.control_plane_digest,
                "sourceCommit": context.subject.source_commit,
                "priorChainHeadDigest": fixture.current.chain_head_digest,
                "delegator": {
                    "identity": root["identity"],
                    "organization": root["organization"],
                    "fingerprint": root["fingerprint"],
                },
                "delegateIdentity": principal.identity,
                "delegateFingerprint": reviewer_fingerprint,
                "issuedAt": "2026-07-11T11:00:00Z",
                "reason": "Withdraw the aggregate dataset reviewer.",
            },
        )
        revoked_roster = build_effective_reviewer_roster(
            policy_result=policy_result,
            delegations=[delegation],
            revocations=[revocation],
            expected_policy_digest=policy_digest,
            expected_control_plane_digest=context.subject.control_plane_digest,
            expected_source_commit=context.subject.source_commit,
            expected_prior_chain_head_digest=fixture.current.chain_head_digest,
            now=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        _, revoked_selection, _ = self.signed_dataset_selection(
            fixture,
            context,
            suffix="revoked-delegation",
            roster=revoked_roster,
            principal=principal,
            key=reviewer_key,
        )
        with self.assertRaises(ControlContextError) as caught:
            finalize_late_bound_dataset_context(
                base_context=context,
                raw_selections=[revoked_selection],
                roster=revoked_roster,
                verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "signer_not_allowed")

    def test_later_transition_approval_does_not_replace_contract_approval(self) -> None:
        fixture = self.fixture()
        core = deepcopy(dict(fixture.current.state_core))
        core["activeWorkUnit"] = None
        core["pendingWorkUnit"] = "P00.W01"
        unit = core["phases"]["P00"]["workUnits"]["P00.W01"]
        unit["status"] = "MACHINE_CONVERGED"
        unit["approvalDigest"] = D("9")
        state_digest = _state_core_digest(core)
        current = _mark_state_verified(
            replace(fixture.current, state_core=core, state_digest=state_digest)
        )
        authority = _mark_oidc_verified(
            replace(fixture.authority, state_digest=state_digest)
        )
        context = derive_work_unit_control_context(
            current=current,
            oidc_authority=authority,
            repo_root=fixture.root,
            work_unit="P00.W01",
        )
        self.assertEqual(context.contract_approval_digest, D("a"))
        self.assertNotEqual(context.contract_approval_digest, unit["approvalDigest"])

    def test_late_bound_dataset_is_explicitly_non_convergent_slot(self) -> None:
        def late_bound(documents):
            documents["execution/gates/p00/P00.W01.yaml"]["datasetPolicy"] = {
                "status": "late_bound_requires_signed_freeze",
                "digest": None,
                "missingOrUnfrozenResult": "insufficient_samples",
            }

        fixture = self.fixture(late_bound)
        context = fixture.context()
        self.assertEqual(
            context.late_bound_dataset_criteria,
            ("P00-M-BOOTSTRAP-CONTROL",),
        )

    def test_signed_raw_dataset_selection_finalizes_shared_catalog_once(self) -> None:
        def late_bound(documents):
            first = documents["execution/gates/p00/P00.W01.yaml"]["criteria"][0]
            second = deepcopy(first)
            second["id"] = "P00-M-BOOTSTRAP-SECOND"
            documents["execution/gates/p00/P00.W01.yaml"]["criteria"].append(second)
            documents["execution/work-units/P00.W01.yaml"]["convergence"].append(
                deepcopy(second)
            )
            documents["execution/catalogs/p00/acceptance.yaml"]["criteria"].append(
                {
                    "id": second["id"],
                    "owner": "P00.W01",
                    "kind": "MACHINE",
                    "evaluator": second["evaluator"],
                    "evaluatorStatus": "implemented",
                }
            )
            documents["execution/gates/p00/P00.W01.yaml"]["datasetPolicy"] = {
                "status": "late_bound_requires_signed_freeze",
                "digest": None,
                "missingOrUnfrozenResult": "insufficient_samples",
            }

        fixture = self.fixture(late_bound)
        context = fixture.context()
        roster, envelope, body = self.signed_dataset_selection(
            fixture, context, suffix="w01"
        )
        criterion_ids = list(context.late_bound_dataset_criteria)
        finalized = finalize_late_bound_dataset_context(
            base_context=context,
            raw_selections=[envelope],
            roster=roster,
            verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(finalized.late_bound_dataset_criteria, ())
        self.assertEqual(
            {item.dataset_digest for item in finalized.criteria},
            {body["datasetDigest"]},
        )
        self.assertEqual(finalized.dataset_selection_digests, (envelope["attestationDigest"],))
        self.assertEqual(
            finalized.dataset_selection_bindings,
            tuple(
                (criterion_id, envelope["attestationDigest"])
                for criterion_id in criterion_ids
            ),
        )

        split = [deepcopy(envelope), deepcopy(envelope)]
        split[0]["body"]["criterionIds"] = [criterion_ids[0]]
        split[1]["body"]["criterionIds"] = [criterion_ids[1]]
        with self.assertRaises(ControlContextError) as caught:
            finalize_late_bound_dataset_context(
                base_context=context,
                raw_selections=split,
                roster=roster,
                verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "dataset_selection_set_mismatch")

        tampered = deepcopy(envelope)
        tampered["body"]["datasetDigest"] = D("9")
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        with self.assertRaises(ControlContextError) as caught:
            finalize_late_bound_dataset_context(
                base_context=context,
                raw_selections=[tampered],
                roster=roster,
                verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "dataset_artifact_digest_mismatch")

        conflicted = deepcopy(envelope)
        conflicted["body"]["conflictOfInterest"]["independent"] = False
        conflicted["attestationDigest"] = document_digest(
            conflicted, omit_field="attestationDigest"
        )
        with self.assertRaises(ControlContextError) as caught:
            finalize_late_bound_dataset_context(
                base_context=context,
                raw_selections=[conflicted],
                roster=roster,
                verification_time=datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "dataset_reviewer_conflict")


if __name__ == "__main__":
    unittest.main()
