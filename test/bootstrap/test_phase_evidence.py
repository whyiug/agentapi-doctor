from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.digest import sha256_bytes  # noqa: E402
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    evaluate_strict,
)
from tools.phasegate.phase_evidence import (  # noqa: E402
    EXPECTED_CRITERION_UNITS,
    PhaseEvidenceError,
    build_p00_phase_aggregate_evidence,
    require_verified_phase_aggregate_evidence,
)
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    PhaseSubject,
    SubjectBinding,
)
from tools.phasegate.evidence_index import (  # noqa: E402
    VerifiedMachineEvidenceRecord,
)


def D(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


class PhaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = "1" * 40
        self.control = D("control")
        self.contracts = {
            work_unit: D(f"contract:{work_unit}")
            for work_unit in sorted(set(EXPECTED_CRITERION_UNITS.values()))
        }
        self.catalogs = {
            "P00.W01": ("execution/catalogs/p00/bootstrap.yaml", D("slot:w01")),
            "P00.W02": (
                "execution/catalogs/p00/competitor-research.yaml",
                D("slot:w02"),
            ),
            "P00.W03": ("execution/catalogs/p00/corpus.yaml", D("slot:w03")),
            "P00.W04": (
                "execution/catalogs/p00/risk-experiments.yaml",
                D("slot:w04"),
            ),
            "P00.W05": ("execution/catalogs/p00/go-no-go.yaml", D("slot:w05")),
        }
        self.datasets = {
            work_unit: D(f"dataset:{work_unit}") for work_unit in self.contracts
        }
        self.catalogs["P00.W01"] = (
            self.catalogs["P00.W01"][0],
            self.datasets["P00.W01"],
        )
        self.work_contexts = self._work_contexts()
        self.phase_context = SimpleNamespace(
            context_digest=D("phase-context"),
            subject=PhaseSubject(
                phase="P00",
                source_commit=self.source,
                control_plane_digest=self.control,
                aggregate_contract_digest=D("phase-contract"),
            ),
            unit_contract_digests=tuple(sorted(self.contracts.items())),
            criteria=(
                CriterionBinding(
                    criterion_id="P00-M-AGGREGATE",
                    kind="MACHINE",
                    evaluator="evaluator://phase/aggregate/v1",
                    evaluator_digest=D("aggregate-evaluator"),
                    evidence_schema="evidence-schema://phase/aggregate-report/v1",
                    evidence_schema_digest=D("aggregate-schema"),
                    dataset_digest=D("aggregate-slot"),
                    threshold_digest=D("aggregate-threshold"),
                    evaluator_status="implemented",
                ),
            ),
        )
        self.records = self._records()
        self.replay = self._replay(self.records)

    def _work_contexts(self) -> list[SimpleNamespace]:
        grouped: dict[str, list[str]] = {work_unit: [] for work_unit in self.contracts}
        for criterion_id, work_unit in EXPECTED_CRITERION_UNITS.items():
            grouped[work_unit].append(criterion_id)
        contexts = []
        for work_unit in sorted(grouped):
            criteria = tuple(
                CriterionBinding(
                    criterion_id=criterion_id,
                    kind="MACHINE",
                    evaluator=AGGREGATE_CRITERIA[criterion_id],
                    evaluator_digest=D(f"evaluator:{criterion_id}"),
                    evidence_schema=f"evidence-schema://{criterion_id.lower()}/v1",
                    evidence_schema_digest=D(f"schema:{criterion_id}"),
                    dataset_digest=self.catalogs[work_unit][1],
                    threshold_digest=D(f"threshold:{criterion_id}"),
                    evaluator_status="implemented",
                )
                for criterion_id in sorted(grouped[work_unit])
            )
            path, slot = self.catalogs[work_unit]
            contexts.append(
                SimpleNamespace(
                    context_digest=D(f"context:{work_unit}"),
                    subject=SubjectBinding(
                        phase="P00",
                        work_unit=work_unit,
                        source_commit=self.source,
                        control_plane_digest=self.control,
                        contract_digest=self.contracts[work_unit],
                    ),
                    criteria=criteria,
                    late_bound_dataset_criteria=(
                        ()
                        if work_unit == "P00.W01"
                        else tuple(criterion.criterion_id for criterion in criteria)
                    ),
                    dataset_catalog_bindings=tuple(
                        (criterion.criterion_id, path, slot) for criterion in criteria
                    ),
                )
            )
        return contexts

    def _records(self) -> tuple[VerifiedMachineEvidenceRecord, ...]:
        contexts = {
            context.subject.work_unit: context for context in self.work_contexts
        }
        records = []
        for sequence, criterion_id in enumerate(sorted(AGGREGATE_CRITERIA), start=1):
            work_unit = EXPECTED_CRITERION_UNITS[criterion_id]
            criterion = next(
                item
                for item in contexts[work_unit].criteria
                if item.criterion_id == criterion_id
            )
            pair_digest = D(f"pair-digest:{criterion_id}")
            records.append(
                VerifiedMachineEvidenceRecord(
                    event_sequence=sequence,
                    event_digest=D(f"event:{criterion_id}"),
                    bundle_digest=D(f"bundle:{criterion_id}"),
                    operation="work-unit-convergence",
                    phase="P00",
                    work_unit=work_unit,
                    source_commit=self.source,
                    control_plane_digest=self.control,
                    contract_digest=self.contracts[work_unit],
                    criterion_id=criterion_id,
                    evaluator=criterion.evaluator,
                    evaluator_digest=criterion.evaluator_digest,
                    verifier_digest=D(f"verifier:{criterion_id}"),
                    evaluator_dataset_freeze_digest=D(
                        f"evaluator-freeze:{work_unit}"
                    ),
                    dataset_catalog_path=self.catalogs[work_unit][0],
                    dataset_slot_digest=self.catalogs[work_unit][1],
                    dataset_selection_digest=(
                        None
                        if work_unit == "P00.W01"
                        else D(f"selection:{work_unit}")
                    ),
                    dataset_digest=self.datasets[work_unit],
                    freeze_digest=D(f"freeze:{work_unit}"),
                    result_digest=D(f"result:{criterion_id}"),
                    evidence_digest=pair_digest,
                    verification_pair_id=f"pair-{sequence:02d}",
                    run_pair_digest=pair_digest,
                    execution_bundle_digest=D(f"execution:{criterion_id}"),
                    outcome="PASS",
                )
            )
        return tuple(records)

    def _replay(self, records) -> SimpleNamespace:
        units = {
            work_unit: {
                "status": "CONVERGED",
                "contractDigest": self.contracts[work_unit],
            }
            for work_unit in self.contracts
        }
        return SimpleNamespace(
            head_source_commit=self.source,
            control_plane_digest=self.control,
            machine_evidence_index_digest=D("machine-index"),
            machine_evidence_index=tuple(records),
            current=SimpleNamespace(
                state_core={"phases": {"P00": {"workUnits": units}}}
            ),
        )

    def _build(self, *, replay=None, phase=None, contexts=None):
        selected_replay = self.replay if replay is None else replay
        selected_phase = self.phase_context if phase is None else phase
        selected_contexts = self.work_contexts if contexts is None else contexts
        with (
            patch(
                "tools.phasegate.phase_evidence.require_verified_protected_chain_replay",
                side_effect=lambda value: value,
            ),
            patch(
                "tools.phasegate.phase_evidence.require_verified_phase_control_context",
                side_effect=lambda value: value,
            ),
            patch(
                "tools.phasegate.phase_evidence.require_verified_work_unit_control_context",
                side_effect=lambda value, **_kwargs: value,
            ),
        ):
            return build_p00_phase_aggregate_evidence(
                selected_replay,
                phase_context=selected_phase,
                work_unit_contexts=selected_contexts,
            )

    def test_exact_twelve_records_recompute_reference_pass(self) -> None:
        evidence = self._build()
        self.assertIs(require_verified_phase_aggregate_evidence(evidence), evidence)
        self.assertEqual(len(evidence.records), 12)
        result = evaluate_strict(
            "evaluator://phase/aggregate/v1", evidence.evaluator_input
        )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["reasonCode"], "threshold_met")
        self.assertEqual(
            evidence.records[0]["datasetFreezeDigest"],
            self.records[0].evaluator_dataset_freeze_digest,
        )
        self.assertNotEqual(
            evidence.records[0]["datasetFreezeDigest"], self.records[0].freeze_digest
        )
        copied = deepcopy(evidence)
        with self.assertRaises(PhaseEvidenceError) as caught:
            require_verified_phase_aggregate_evidence(copied)
        self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_exact_duplicate_result_deduplicates_but_conflict_rejects(self) -> None:
        duplicate = replace(
            self.records[0],
            event_sequence=99,
            event_digest=D("duplicate-event"),
            bundle_digest=D("duplicate-bundle"),
            operation="evidence-attachment",
        )
        replay = self._replay((*self.records, duplicate))
        self.assertEqual(len(self._build(replay=replay).records), 12)
        conflict = replace(duplicate, result_digest=D("conflicting-result"))
        with self.assertRaises(PhaseEvidenceError) as caught:
            self._build(replay=self._replay((*self.records, conflict)))
        self.assertEqual(caught.exception.code, "conflicting_machine_result")

    def test_historical_source_records_are_ignored(self) -> None:
        historical = tuple(
            replace(
                item,
                event_sequence=item.event_sequence + 100,
                event_digest=D(f"historical:{item.criterion_id}"),
                source_commit="0" * 40,
                result_digest=D(f"old-result:{item.criterion_id}"),
            )
            for item in self.records
        )
        evidence = self._build(replay=self._replay((*historical, *self.records)))
        self.assertEqual(len(evidence.records), 12)

    def test_missing_fail_source_evaluator_contract_and_unit_mutants_reject(self) -> None:
        cases = []
        cases.append((self._replay(self.records[1:]), "missing_machine_criterion"))
        cases.append(
            (
                self._replay((replace(self.records[0], outcome="FAIL"), *self.records[1:])),
                "aggregate_record_binding_mismatch",
            )
        )
        cases.append(
            (
                self._replay((replace(self.records[0], source_commit="2" * 40), *self.records[1:])),
                "missing_machine_criterion",
            )
        )
        cases.append(
            (
                self._replay((replace(self.records[0], evaluator="evaluator://wrong/v1"), *self.records[1:])),
                "aggregate_record_binding_mismatch",
            )
        )
        cases.append(
            (
                self._replay((replace(self.records[0], contract_digest=D("wrong")), *self.records[1:])),
                "aggregate_subject_mismatch",
            )
        )
        broken_units = self._replay(self.records)
        broken_units.current.state_core["phases"]["P00"]["workUnits"]["P00.W05"][
            "status"
        ] = "ACTIVE"
        cases.append((broken_units, "phase_units_not_converged"))
        for replay, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(PhaseEvidenceError) as caught:
                    self._build(replay=replay)
                self.assertEqual(caught.exception.code, code)

    def test_shared_catalog_slot_dataset_fork_rejects(self) -> None:
        target = "P00-M-REPRO"
        replacement_digest = D("forked-corpus")
        contexts = deepcopy(self.work_contexts)
        w03 = next(item for item in contexts if item.subject.work_unit == "P00.W03")
        w03.criteria = tuple(
            replace(item, dataset_digest=replacement_digest)
            if item.criterion_id == target
            else item
            for item in w03.criteria
        )
        records = tuple(
            replace(item, dataset_digest=replacement_digest)
            if item.criterion_id == target
            else item
            for item in self.records
        )
        with self.assertRaises(PhaseEvidenceError) as caught:
            self._build(replay=self._replay(records), contexts=contexts)
        self.assertEqual(caught.exception.code, "dataset_selection_fork")

    def test_late_bound_work_context_uses_reverified_machine_dataset(self) -> None:
        contexts = deepcopy(self.work_contexts)
        w03 = next(item for item in contexts if item.subject.work_unit == "P00.W03")
        late_ids = tuple(item.criterion_id for item in w03.criteria)
        w03.late_bound_dataset_criteria = late_ids
        slot_digest = self.catalogs["P00.W03"][1]
        w03.criteria = tuple(
            replace(item, dataset_digest=slot_digest) for item in w03.criteria
        )
        evidence = self._build(contexts=contexts)
        by_id = {item["criterionId"]: item for item in evidence.records}
        for criterion_id in late_ids:
            self.assertEqual(
                by_id[criterion_id]["datasetDigest"], self.datasets["P00.W03"]
            )
            self.assertNotEqual(by_id[criterion_id]["datasetDigest"], slot_digest)


if __name__ == "__main__":
    unittest.main()
