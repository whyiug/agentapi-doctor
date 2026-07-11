from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.chain_witness import (  # noqa: E402
    VerifiedChainHeadWitness,
    _mark_verified as _mark_witness,
)
from tools.phasegate.control_context import (  # noqa: E402
    VerifiedExecutorPreflight,
    VerifiedPhaseControlContext,
    _VERIFIED_CONTEXTS,
    _VERIFIED_PREFLIGHTS,
    _mark as _mark_control,
    criterion_documents,
)
from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.execution_artifact import (  # noqa: E402
    VerifiedPhaseExecutionArtifact,
)
from tools.phasegate.gate_runner import (  # noqa: E402
    combine_phase_runs,
    record_phase_run,
)
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    build_paired_input,
    canonical_digest,
    evaluate_strict,
)
from tools.phasegate.phase_bundle import (  # noqa: E402
    BUNDLE_KIND,
    BUNDLE_SCHEMA,
    OP_PHASE_TRANSITION,
    PhaseBundleError,
    require_verified_serialized_phase_bundle,
    verify_serialized_phase_authorization_bundle,
)
from tools.phasegate.phase_evidence import (  # noqa: E402
    PHASE_DATASET_ID,
    VerifiedPhaseAggregateEvidence,
    _projection as _evidence_projection,
    _seal as _seal_evidence,
)
from tools.phasegate.protected import document_digest  # noqa: E402
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    PhaseSubject,
    PhaseUnitStateBinding,
    VerifiedPhaseCriterionResult,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedPhaseStateContext,
    VerifiedPhaseTransition,
    VerifiedSignerResult,
    _mark_verified as _mark_provenance,
)


def D(value: str) -> str:
    return sha256_bytes(value.encode())


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


class PhaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = "1" * 40
        self.control = D("control")
        self.state_digest = D("state")
        self.head_digest = D("head")
        self.policy_digest = D("policy")
        self.subject = PhaseSubject(
            phase="P00",
            source_commit=self.source,
            control_plane_digest=self.control,
            aggregate_contract_digest=D("aggregate-contract"),
        )
        self.inputs = {
            "planDigest": D("plan"),
            "supportLockDigest": D("support"),
            "toolchainDigest": D("tools"),
            "dependencySetDigest": D("dependencies"),
            "gateRunnerDigest": D("runner"),
            "evaluatorSetDigest": D("evaluators"),
            "metricDefinitionsDigest": D("metrics"),
            "protectedAcceptanceDigest": D("acceptance"),
        }
        self.records = self._aggregate_records()
        self.payload = build_paired_input(
            "evaluator://phase/aggregate/v1",
            self.records,
            source_commit=self.source,
            control_plane_digest=self.control,
            evaluator_digest=D("aggregate-evaluator"),
            dataset_id=PHASE_DATASET_ID,
        )
        self.criterion = CriterionBinding(
            criterion_id="P00-M-AGGREGATE",
            kind="MACHINE",
            evaluator="evaluator://phase/aggregate/v1",
            evaluator_digest=D("aggregate-evaluator"),
            evidence_schema="evidence-schema://phase/aggregate-report/v1",
            evidence_schema_digest=D("aggregate-schema"),
            dataset_digest=self.payload["datasetDigest"],
            threshold_digest=D("aggregate-threshold"),
            evaluator_status="implemented",
        )
        self.human = CriterionBinding(
            criterion_id="P00-H-GO-NOGO",
            kind="HUMAN",
            evaluator="attestation://review/go-no-go/v1",
            evaluator_digest=D("human-evaluator"),
            evidence_schema="evidence-schema://attestation/human-review/v1",
            evidence_schema_digest=D("human-schema"),
            dataset_digest=D("go-nogo-slot"),
            threshold_digest=D("human-threshold"),
            evaluator_status="human-only",
        )
        self.unit_contracts = tuple(
            (f"P00.W0{index}", D(f"contract:{index}"))
            for index in range(1, 6)
        )
        self.preflight = _mark_control(
            _VERIFIED_PREFLIGHTS,
            VerifiedExecutorPreflight(
                preflight_digest=D("preflight"),
                source_commit=self.source,
                support_lock_digest=self.inputs["supportLockDigest"],
                dependency_set_digest=self.inputs["dependencySetDigest"],
                toolchain_digest=self.inputs["toolchainDigest"],
                tool_facts=(),
            ),
        )
        self.base_context = self._context(finalized=False)
        self.final_context = self._context(finalized=True)
        self.evidence = self._evidence()
        self.freeze = self._freeze()
        self.execution, self.result = self._execution_and_result()
        self.state_context = self._state_context("ACTIVE")
        self.witness = _mark_witness(
            VerifiedChainHeadWitness(
                attestation_digest=D("witness"),
                witness_id="phase-witness",
                prior_chain_head_digest=self.head_digest,
                prior_state_digest=self.state_digest,
                prior_event_count=9,
                prior_head_sequence=8,
                prior_source_commit=self.source,
                control_plane_digest=self.control,
                trust_policy_digest=self.policy_digest,
                witnessed_at=NOW,
                valid_until=datetime(2026, 7, 11, 13, tzinfo=timezone.utc),
                principal="reviewer@test.invalid",
                organization="review-org",
            )
        )
        self.transition = self._transition("ACTIVE", "MACHINE_CONVERGED")
        self.current = SimpleNamespace(
            state_core=self._state_core("ACTIVE"),
            state_digest=self.state_digest,
        )
        self.replay = SimpleNamespace(
            current=self.current,
            state_digest=self.state_digest,
            head_digest=self.head_digest,
            event_count=9,
            head_sequence=8,
            head_source_commit=self.source,
            control_plane_digest=self.control,
            machine_evidence_index_digest=D("machine-index"),
        )
        self.roster = SimpleNamespace(authority_digest=D("roster"))

    def _aggregate_records(self) -> list[dict]:
        return [
            {
                "id": criterion_id,
                "criterionId": criterion_id,
                "kind": "MACHINE",
                "evaluator": evaluator,
                "result": "PASS",
                "evidenceDigest": D(f"evidence:{criterion_id}"),
                "verificationPairId": f"child-pair-{index:02d}",
                "sourceCommit": self.source,
                "controlPlaneDigest": self.control,
                "evaluatorDigest": D(f"evaluator:{criterion_id}"),
                "datasetFreezeDigest": D(f"freeze:{criterion_id}"),
                "datasetDigest": D(f"dataset:{criterion_id}"),
                "verifierDigest": D(f"verifier:{criterion_id}"),
            }
            for index, (criterion_id, evaluator) in enumerate(
                sorted(AGGREGATE_CRITERIA.items())
            )
        ]

    def _context(self, *, finalized: bool) -> VerifiedPhaseControlContext:
        context = VerifiedPhaseControlContext(
            context_digest=D("final-context" if finalized else "base-context"),
            subject=self.subject,
            aggregate_contract_approval_digest=D("contract-approval"),
            impact_map_digest=D("impact"),
            unit_contract_digests=self.unit_contracts,
            protected_inputs=tuple(sorted(self.inputs.items())),
            criteria=(self.criterion, self.human) if finalized else (
                self.criterion.__class__(
                    **{**self.criterion.__dict__, "dataset_digest": D("aggregate-slot")}
                ),
                self.human,
            ),
            component_digests=(),
            component_set_digest=D("components"),
            gate_path="execution/gates/p00/aggregate.yaml",
            contract_path="execution/phases/P00.yaml",
            late_bound_dataset_criteria=() if finalized else ("P00-M-AGGREGATE",),
            dataset_catalog_bindings=(
                (
                    "P00-M-AGGREGATE",
                    "execution/catalogs/p00/go-no-go.yaml",
                    D("aggregate-slot"),
                ),
                (
                    "P00-H-GO-NOGO",
                    "execution/catalogs/p00/go-no-go.yaml",
                    D("go-nogo-slot"),
                ),
            ),
            dataset_selection_digests=(D("selection"),) if finalized else (),
            dataset_selection_bindings=(
                (("P00-M-AGGREGATE", D("selection")),) if finalized else ()
            ),
            executor_preflight=self.preflight,
        )
        return _mark_control(_VERIFIED_CONTEXTS, context)

    def _evidence(self) -> VerifiedPhaseAggregateEvidence:
        manifest = {
            "schemaVersion": "urn:agentapi-doctor:p00-dataset-records:v1alpha1",
            "datasetId": PHASE_DATASET_ID,
            "records": self.records,
        }
        provisional = VerifiedPhaseAggregateEvidence(
            evidence_digest="",
            source_machine_index_digest=D("machine-index"),
            phase_context_digest=self.base_context.context_digest,
            source_commit=self.source,
            control_plane_digest=self.control,
            aggregate_contract_digest=self.subject.aggregate_contract_digest,
            dataset_digest=self.payload["datasetDigest"],
            dataset_manifest=manifest,
            records=tuple(self.records),
            evaluator_input=self.payload,
        )
        value = VerifiedPhaseAggregateEvidence(
            **{
                **provisional.__dict__,
                "evidence_digest": document_digest(_evidence_projection(provisional)),
            }
        )
        return _seal_evidence(value)

    def _signer(self, role: str = "protected-workflow") -> VerifiedSignerResult:
        return VerifiedSignerResult(
            scheme="test",
            namespace="test",
            principal=f"{role}@test.invalid",
            role=role,
            organization=f"{role}-org",
            statement_digest=D(f"statement:{role}"),
            authority_digest=D(f"authority:{role}"),
            source_commit=self.source,
            control_plane_digest=self.control,
        )

    def _freeze(self) -> VerifiedPhaseProtectedInputFreeze:
        return _mark_provenance(
            VerifiedPhaseProtectedInputFreeze(
                attestation_digest=D("phase-freeze"),
                statement_digest=D("phase-freeze-statement"),
                freeze_id="phase-freeze",
                subject=self.subject,
                aggregate_contract_approval_digest=D("contract-approval"),
                unit_contract_digests=self.unit_contracts,
                protected_inputs=tuple(sorted(self.inputs.items())),
                criteria=(self.criterion, self.human),
                signer=self._signer("independent-reviewer"),
            )
        )

    def _command(self, label: str, evaluator_evidence: dict) -> dict:
        assertion_digest = canonical_digest(
            {
                "schemaVersion": "urn:agentapi-doctor:protected-command-assertion:v1",
                "evaluator": self.criterion.evaluator,
                "assertionId": "protected-evaluator-executed",
                "evidenceDigest": evaluator_evidence["evidenceDigest"],
            }
        )
        return {
            "exitCode": 0,
            "durationMs": 1000,
            "startedAt": "2026-07-11T10:00:00Z",
            "finishedAt": "2026-07-11T10:00:01Z",
            "environmentDigest": D(f"environment:{label}"),
            "logDigest": D(f"log:{label}"),
            "artifactManifestDigest": D(f"artifact:{label}"),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "semanticAssertions": [
                {
                    "id": "protected-evaluator-executed",
                    "status": "PASS",
                    "evidenceDigest": assertion_digest,
                }
            ],
        }

    def _execution_and_result(self):
        evidence = evaluate_strict(self.criterion.evaluator, self.payload)
        runs = [
            record_phase_run(
                freeze=self.freeze,
                criterion_id=self.criterion.criterion_id,
                label=label,
                command_result=self._command(label, evidence),
                evaluator_input=self.payload,
                evaluator_evidence=evidence,
            )
            for label in ("A", "B")
        ]
        pair = combine_phase_runs(
            freeze=self.freeze,
            criterion_id=self.criterion.criterion_id,
            run_a=runs[0],
            run_b=runs[1],
        )
        execution = VerifiedPhaseExecutionArtifact(
            run_pair=pair,
            run_pair_digest=document_digest(pair),
            bundle_digest=D("execution-bundle"),
            criterion_id=self.criterion.criterion_id,
            evaluator=self.criterion.evaluator,
            evaluator_dataset_freeze_digest=self.payload["datasetFreezeDigest"],
        )
        result = _mark_provenance(
            VerifiedPhaseCriterionResult(
                attestation_digest=D("phase-result"),
                statement_digest=D("phase-result-statement"),
                result_id="phase-result",
                freeze_digest=self.freeze.attestation_digest,
                subject=self.subject,
                criterion=self.criterion,
                outcome="PASS",
                evidence_digest=execution.run_pair_digest,
                run_pair_digest=execution.run_pair_digest,
                signature_verified=True,
                fact_status="not_applicable",
                criterion_satisfied=True,
                signer=self._signer(),
            )
        )
        return execution, result

    def _state_core(self, status: str) -> dict:
        return {
            "controlPlaneDigest": self.control,
            "phases": {
                "P00": {
                    "status": status,
                    "workUnits": {
                        unit: {"status": "CONVERGED"}
                        for unit, _digest in self.unit_contracts
                    },
                }
            },
        }

    def _state_context(self, status: str) -> VerifiedPhaseStateContext:
        return _mark_provenance(
            VerifiedPhaseStateContext(
                state_digest=self.state_digest,
                chain_head_digest=self.head_digest,
                control_plane_digest=self.control,
                phase="P00",
                status=status,
                aggregate_contract_digest=self.subject.aggregate_contract_digest,
                base_commit=self.source,
                units=tuple(
                    PhaseUnitStateBinding(
                        work_unit=unit,
                        status="CONVERGED",
                        contract_digest=digest,
                        source_commit=self.source,
                        approval_digest=D(f"approval:{unit}"),
                    )
                    for unit, digest in self.unit_contracts
                ),
            )
        )

    def _transition(self, from_state: str, to_state: str) -> VerifiedPhaseTransition:
        return _mark_provenance(
            VerifiedPhaseTransition(
                transition_type="PHASE_AGGREGATE",
                subject=self.subject,
                from_state=from_state,
                to_state=to_state,
                prior_state_digest=self.state_digest,
                prior_chain_head_digest=self.head_digest,
                freeze_digest=self.freeze.attestation_digest,
                proof_digest=D(f"proof:{from_state}:{to_state}"),
                approval_digest=D(f"approval:{from_state}:{to_state}"),
                go_nogo_authorization_digest=(
                    D("go-no-go") if to_state == "CONVERGED" else None
                ),
                evidence_digest=D(f"proof:{from_state}:{to_state}"),
                criterion_result_digests=(self.result.attestation_digest,),
                unit_states=self._state_context(from_state).units,
            )
        )

    def _operation(self, from_state: str, to_state: str) -> dict:
        return {
            "operationId": f"phase-{from_state.lower()}-{to_state.lower()}",
            "type": OP_PHASE_TRANSITION,
            "subject": {
                "phase": "P00",
                "sourceCommit": self.source,
                "controlPlaneDigest": self.control,
                "aggregateContractDigest": self.subject.aggregate_contract_digest,
            },
            "fromState": from_state,
            "toState": to_state,
            "priorStateDigest": self.state_digest,
            "priorChainHeadDigest": self.head_digest,
            "workflowExecutionCommit": self.source,
            "phaseContextDigest": self.final_context.context_digest,
            "aggregateEvidenceDigest": self.evidence.evidence_digest,
            "aggregateContractApprovalDigest": D("contract-approval"),
            "impactMapDigest": D("impact"),
            "unitContractDigests": dict(self.unit_contracts),
            "protectedInputsDigest": document_digest(
                {"protectedInputs": dict(self.final_context.protected_inputs)}
            ),
            "criteriaDigest": document_digest(
                {"criteria": criterion_documents(self.final_context.criteria)}
            ),
        }

    def _raw(self, *, from_state="ACTIVE", to_state="MACHINE_CONVERGED", go=None):
        selection = {
            "body": {
                "criterionIds": ["P00-M-AGGREGATE"],
                "datasetManifest": self.evidence.dataset_manifest,
                "datasetDigest": self.evidence.dataset_digest,
            }
        }
        document = {
            "schemaVersion": BUNDLE_SCHEMA,
            "kind": BUNDLE_KIND,
            "bundleId": f"phase-bundle-{from_state.lower()}-{to_state.lower()}",
            "operation": self._operation(from_state, to_state),
            "chainHeadWitness": {"raw": "witness"},
            "delegations": [],
            "revocations": [],
            "lateBoundDatasetSelections": [selection],
            "phaseProtectedInputFreeze": {"raw": "freeze"},
            "phaseMachineExecutionArtifact": {
                "evaluatorInput": self.evidence.evaluator_input,
                "raw": "execution",
            },
            "phaseCriterionResult": {
                "body": {
                    "runPair": dict(self.execution.run_pair),
                    "runPairDigest": self.execution.run_pair_digest,
                    "evidenceDigest": self.execution.run_pair_digest,
                }
            },
            "proof": {"raw": "proof"},
            "approval": {"raw": "approval"},
            "goNoGo": [] if go is None else go,
        }
        document["bundleDigest"] = document_digest(document)
        return canonical_json_bytes(document)

    def _patches(self, *, state="ACTIVE", transition=None):
        selected_transition = transition or self.transition
        return (
            patch("tools.phasegate.phase_bundle.require_verified_protected_chain_replay", side_effect=lambda value: value),
            patch("tools.phasegate.phase_bundle.require_verified_phase_control_context", side_effect=lambda value: value),
            patch("tools.phasegate.phase_bundle.require_verified_phase_aggregate_evidence", side_effect=lambda value: value),
            patch("tools.phasegate.phase_bundle._current_fields", return_value=(self.current, self._state_core(state))),
            patch("tools.phasegate.phase_bundle.verify_phase_state_context", return_value=self._state_context(state)),
            patch("tools.phasegate.phase_bundle.verify_chain_head_witness", return_value=self.witness),
            patch("tools.phasegate.phase_bundle.build_effective_reviewer_roster", return_value=self.roster),
            patch("tools.phasegate.phase_bundle.finalize_late_bound_dataset_context", return_value=self.final_context),
            patch("tools.phasegate.phase_bundle._policy_sshsig_verifier", return_value=lambda *_args: self._signer("independent-reviewer")),
            patch("tools.phasegate.phase_bundle.verify_signed_phase_protected_input_freeze", return_value=self.freeze),
            patch("tools.phasegate.phase_bundle.verify_phase_execution_artifact_bundle", return_value=self.execution),
            patch("tools.phasegate.phase_bundle.build_oidc_provenance_verifier", return_value=SimpleNamespace(authority_digest=D("oidc"))),
            patch("tools.phasegate.phase_bundle.verify_signed_phase_criterion_result", return_value=self.result),
            patch("tools.phasegate.phase_bundle.verify_phase_transition_proof", return_value=SimpleNamespace()),
            patch("tools.phasegate.phase_bundle.verify_phase_transition_approval", return_value=SimpleNamespace()),
            patch("tools.phasegate.phase_bundle.authorize_phase_transition", return_value=selected_transition),
        )

    def _verify(self, raw: bytes, *, state="ACTIVE", to_state="MACHINE_CONVERGED", transition=None):
        patches = self._patches(state=state, transition=transition)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], patches[12], patches[13], patches[14], patches[15]:
            return verify_serialized_phase_authorization_bundle(
                raw,
                replay=self.replay,
                policy_result={"digest": self.policy_digest},
                approved_jwks_snapshot={},
                repo_root=REPO_ROOT,
                current_workflow_execution_commit=self.source,
                expected_to_state=to_state,
                control_context=self.base_context,
                aggregate_evidence=self.evidence,
                verification_time=NOW,
            )

    def test_exact_raw_bundle_builds_fresh_phase_transition(self) -> None:
        imported = self._verify(self._raw())
        self.assertIs(require_verified_serialized_phase_bundle(imported), imported)
        self.assertEqual(imported.event_input.to_state, "MACHINE_CONVERGED")
        self.assertEqual(imported.machine_execution.run_pair_digest, self.result.run_pair_digest)
        with self.assertRaises(PhaseBundleError) as caught:
            require_verified_serialized_phase_bundle(deepcopy(imported))
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_noncanonical_summary_and_aggregate_input_mutants_reject(self) -> None:
        document = json.loads(self._raw())
        raw = json.dumps(document, sort_keys=True).encode()
        with self.assertRaises(PhaseBundleError) as caught:
            self._verify(raw)
        self.assertEqual(caught.exception.code, "noncanonical_bundle")

        document = json.loads(self._raw())
        document["callerSummary"] = {"outcome": "PASS"}
        document["bundleDigest"] = document_digest(document, omit_field="bundleDigest")
        with self.assertRaises(PhaseBundleError) as caught:
            self._verify(canonical_json_bytes(document))
        self.assertEqual(caught.exception.code, "invalid_bundle_schema")

        document = json.loads(self._raw())
        document["phaseMachineExecutionArtifact"]["evaluatorInput"]["datasetDigest"] = D("forged")
        document["bundleDigest"] = document_digest(document, omit_field="bundleDigest")
        with self.assertRaises(PhaseBundleError) as caught:
            self._verify(canonical_json_bytes(document))
        self.assertEqual(caught.exception.code, "aggregate_execution_input_mismatch")

    def test_final_transition_requires_exact_two_role_go_nogo(self) -> None:
        final_transition = self._transition("REVIEW_PENDING", "CONVERGED")
        raw = self._raw(from_state="REVIEW_PENDING", to_state="CONVERGED")
        with self.assertRaises(PhaseBundleError) as caught:
            self._verify(
                raw,
                state="REVIEW_PENDING",
                to_state="CONVERGED",
                transition=final_transition,
            )
        self.assertEqual(caught.exception.code, "go_nogo_threshold_not_met")


if __name__ == "__main__":
    unittest.main()
