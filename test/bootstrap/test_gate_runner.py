from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.gate_runner import (  # noqa: E402
    FIXED_COMMANDS,
    GateRunnerError,
    combine_phase_runs,
    combine_runs,
    criterion_result_projection,
    phase_criterion_result_projection,
    record_phase_run,
    record_run,
)
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    EVALUATORS,
    build_paired_input,
    evaluate_strict,
)
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    PhaseSubject,
    SubjectBinding,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    _mark_verified,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


SOURCE_COMMIT = "a" * 40
CONTROL_DIGEST = digest("1")
CONTRACT_DIGEST = digest("2")
EVALUATOR_DIGEST = digest("3")
REPRO_EVALUATOR = "evaluator://corpus/reproduction/v1"
REPRO_CRITERION = "P00-M-REPRO"
CONTROL_EVALUATOR = "evaluator://bootstrap/control-plane/v1"
CONTROL_CRITERION = "P00-M-BOOTSTRAP-CONTROL"
ANTI_EVALUATOR = "evaluator://bootstrap/anti-placeholder/v1"
ANTI_CRITERION = "P00-M-ANTI-PLACEHOLDER"
AGGREGATE_EVALUATOR = "evaluator://phase/aggregate/v1"
AGGREGATE_CRITERION = "P00-M-AGGREGATE"


class GateRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs = {
            "planDigest": digest("4"),
            "supportLockDigest": digest("5"),
            "toolchainDigest": digest("6"),
            "dependencySetDigest": digest("7"),
            "gateRunnerDigest": digest("8"),
            "evaluatorSetDigest": digest("9"),
            "metricDefinitionsDigest": digest("a"),
            "protectedAcceptanceDigest": digest("b"),
        }

    def _records(self, successful: int = 16) -> list[dict]:
        result = []
        for index in range(20):
            expected = f"failure-{index}"
            completed = index < successful
            result.append(
                {
                    "id": f"repro-{index:02d}",
                    "executionStatus": "completed" if completed else "errored",
                    "realCodePath": True,
                    "localOnly": True,
                    "publicTargetContacted": False,
                    "weaponizedPayload": False,
                    "expectedFailureFingerprint": expected,
                    "observedFailureFingerprint": expected if completed else None,
                }
            )
        return result

    def _payload(self, records: list[dict], *, source: str = SOURCE_COMMIT) -> dict:
        return build_paired_input(
            REPRO_EVALUATOR,
            records,
            source_commit=source,
            control_plane_digest=CONTROL_DIGEST,
            evaluator_digest=EVALUATOR_DIGEST,
            dataset_id="p00-reproduction",
        )

    def _criterion(
        self,
        criterion_id: str,
        evaluator: str,
        dataset_digest: str,
    ) -> CriterionBinding:
        return CriterionBinding(
            criterion_id=criterion_id,
            kind="MACHINE",
            evaluator=evaluator,
            evaluator_digest=EVALUATOR_DIGEST,
            evidence_schema="evidence-schema://test/machine/v1",
            evidence_schema_digest=digest("c"),
            dataset_digest=dataset_digest,
            threshold_digest=digest("d"),
        )

    def _freeze(self, dataset_digest: str) -> VerifiedProtectedInputFreeze:
        subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W03",
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
            contract_digest=CONTRACT_DIGEST,
        )
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace="agentapi-doctor/protected-input-freeze/v1",
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest=digest("e"),
            authority_digest=digest("f"),
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
        )
        criteria = sorted(
            (
                self._criterion(REPRO_CRITERION, REPRO_EVALUATOR, dataset_digest),
                self._criterion(CONTROL_CRITERION, CONTROL_EVALUATOR, digest("0")),
                self._criterion(ANTI_CRITERION, ANTI_EVALUATOR, digest("0")),
            ),
            key=lambda item: item.criterion_id,
        )
        return _mark_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=digest("f"),
                statement_digest=digest("e"),
                freeze_id="freeze-P00.W03-gate-runner",
                subject=subject,
                contract_approval_digest=digest("d"),
                protected_inputs=tuple(sorted(self.inputs.items())),
                criteria=tuple(criteria),
                signer=signer,
            )
        )

    def _command(
        self,
        label: str,
        *,
        assertions: list[tuple[str, str, str]] | None = None,
        exit_code: int = 0,
        dirty: bool = False,
        clean: bool | None = None,
    ) -> dict:
        values = assertions or [("outer-workflow-verified", "PASS", digest("1"))]
        semantic_assertions = [
            {"id": name, "status": status, "evidenceDigest": evidence_digest}
            for name, status, evidence_digest in sorted(values)
        ]
        return {
            "exitCode": exit_code,
            "durationMs": 60_000,
            "startedAt": "2026-07-11T10:00:00Z",
            "finishedAt": "2026-07-11T10:01:00Z",
            "environmentDigest": digest("2" if label == "A" else "3"),
            "logDigest": digest("4" if label == "A" else "5"),
            "artifactManifestDigest": digest("6" if label == "A" else "7"),
            "sourceDirtyBeforeRun": dirty,
            "cleanCheckout": (label == "B") if clean is None else clean,
            "semanticAssertions": semantic_assertions,
        }

    def _aggregate_records(self) -> list[dict]:
        return [
            {
                "id": criterion,
                "criterionId": criterion,
                "kind": "MACHINE",
                "evaluator": evaluator,
                "result": "PASS",
                "evidenceDigest": digest(format(index + 1, "x")),
                "verificationPairId": f"pair-child-{index:02d}",
                "sourceCommit": SOURCE_COMMIT,
                "controlPlaneDigest": CONTROL_DIGEST,
                "evaluatorDigest": digest("b"),
                "datasetFreezeDigest": digest("c"),
                "datasetDigest": digest("d"),
                "verifierDigest": digest("e"),
            }
            for index, (criterion, evaluator) in enumerate(
                sorted(AGGREGATE_CRITERIA.items())
            )
        ]

    def _phase_freeze(self, dataset_digest: str) -> VerifiedPhaseProtectedInputFreeze:
        subject = PhaseSubject(
            phase="P00",
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
            aggregate_contract_digest=CONTRACT_DIGEST,
        )
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace="agentapi-doctor/phase-protected-input-freeze/v1",
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest=digest("e"),
            authority_digest=digest("f"),
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
        )
        criterion = self._criterion(
            AGGREGATE_CRITERION, AGGREGATE_EVALUATOR, dataset_digest
        )
        return _mark_verified(
            VerifiedPhaseProtectedInputFreeze(
                attestation_digest=digest("f"),
                statement_digest=digest("e"),
                freeze_id="freeze-P00-aggregate-gate-runner",
                subject=subject,
                aggregate_contract_approval_digest=digest("d"),
                unit_contract_digests=tuple(
                    (f"P00.W0{index}", digest(str(index))) for index in range(1, 6)
                ),
                protected_inputs=tuple(sorted(self.inputs.items())),
                criteria=(criterion,),
                signer=signer,
            )
        )

    def _p00_run(
        self,
        freeze: VerifiedProtectedInputFreeze,
        payload: dict,
        evidence: dict,
        label: str,
        *,
        assertions: list[tuple[str, str, str]] | None = None,
    ):
        return record_run(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            label=label,
            command_result=self._command(label, assertions=assertions),
            evaluator_input=payload,
            evaluator_evidence=evidence,
        )

    def test_fixed_command_table_covers_two_bootstrap_and_all_p00_builtins(
        self,
    ) -> None:
        self.assertEqual(
            set(FIXED_COMMANDS),
            set(EVALUATORS) | {CONTROL_EVALUATOR, ANTI_EVALUATOR},
        )
        self.assertEqual(len(EVALUATORS), 11)

    def test_valid_pass_pair_is_direct_signed_criterion_projection(self) -> None:
        payload = self._payload(self._records(16))
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        self.assertEqual(evidence["result"], "PASS")
        freeze = self._freeze(payload["datasetDigest"])
        run_a = self._p00_run(freeze, payload, evidence, "A")
        run_b = self._p00_run(freeze, payload, evidence, "B")
        pair = combine_runs(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            run_a=run_a,
            run_b=run_b,
        )
        projection = criterion_result_projection(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            run_pair=pair,
        )
        self.assertEqual(projection["outcome"], "PASS")
        self.assertEqual(projection["evidenceDigest"], pair.run_pair_digest)
        self.assertIs(projection["runPair"], pair)
        self.assertEqual(pair["runA"]["environmentClass"], "development-isolated")
        self.assertEqual(pair["runB"]["environmentClass"], "clean-checkout-offline")
        self.assertFalse(pair["runA"]["cleanCheckout"])
        self.assertTrue(pair["runB"]["cleanCheckout"])
        self.assertEqual(
            pair["runA"]["commands"][0]["command"],
            FIXED_COMMANDS[REPRO_EVALUATOR],
        )
        self.assertGreater(pair["runA"]["commands"][0]["summary"]["passed"], 0)
        json.dumps(pair, allow_nan=False, sort_keys=True)
        with self.assertRaises(TypeError):
            pair["runA"] = {}

    def test_valid_threshold_failure_produces_fail_pair(self) -> None:
        payload = self._payload(self._records(15))
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        self.assertEqual(evidence["result"], "FAIL")
        freeze = self._freeze(payload["datasetDigest"])
        pair = combine_runs(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            run_a=self._p00_run(freeze, payload, evidence, "A"),
            run_b=self._p00_run(freeze, payload, evidence, "B"),
        )
        projection = criterion_result_projection(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            run_pair=pair,
        )
        self.assertEqual(pair.outcome, "FAIL")
        self.assertEqual(projection["outcome"], "FAIL")
        self.assertEqual(pair["runA"]["commands"][0]["summary"]["failed"], 1)

    def test_both_bootstrap_builtins_are_supported(self) -> None:
        payload = self._payload(self._records())
        freeze = self._freeze(payload["datasetDigest"])
        cases = (
            (
                CONTROL_CRITERION,
                CONTROL_EVALUATOR,
                "candidate-semantically-valid",
            ),
            (
                ANTI_CRITERION,
                ANTI_EVALUATOR,
                "anti-placeholder-suite-passed",
            ),
        )
        for criterion_id, evaluator, assertion_id in cases:
            with self.subTest(evaluator=evaluator):
                assertions = [(assertion_id, "PASS", digest("8"))]
                run_a = record_run(
                    freeze=freeze,
                    criterion_id=criterion_id,
                    label="A",
                    command_result=self._command("A", assertions=assertions),
                )
                run_b = record_run(
                    freeze=freeze,
                    criterion_id=criterion_id,
                    label="B",
                    command_result=self._command("B", assertions=assertions),
                )
                pair = combine_runs(
                    freeze=freeze,
                    criterion_id=criterion_id,
                    run_a=run_a,
                    run_b=run_b,
                )
                self.assertEqual(pair.outcome, "PASS")
                self.assertEqual(
                    pair["runA"]["commands"][0]["command"], FIXED_COMMANDS[evaluator]
                )

    def test_unverified_handmade_or_copied_freeze_is_rejected(self) -> None:
        payload = self._payload(self._records())
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        verified = self._freeze(payload["datasetDigest"])
        for candidate in (replace(verified), deepcopy(verified)):
            with self.subTest(candidate=id(candidate)):
                with self.assertRaises(GateRunnerError) as caught:
                    self._p00_run(candidate, payload, evidence, "A")
                self.assertEqual(caught.exception.code, "unverified_internal_result")

    def test_forged_evidence_and_cross_bound_input_are_rejected(self) -> None:
        payload = self._payload(self._records())
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        freeze = self._freeze(payload["datasetDigest"])
        forged = deepcopy(evidence)
        forged["result"] = "FAIL"
        with self.assertRaises(GateRunnerError) as caught:
            self._p00_run(freeze, payload, forged, "A")
        self.assertEqual(caught.exception.code, "evaluator_evidence_mismatch")

        other_input = self._payload(self._records(), source="b" * 40)
        other_evidence = evaluate_strict(REPRO_EVALUATOR, other_input)
        with self.assertRaises(GateRunnerError) as caught:
            self._p00_run(freeze, other_input, other_evidence, "A")
        self.assertEqual(caught.exception.code, "evaluator_binding_mismatch")

    def test_a_b_deterministic_drift_is_rejected(self) -> None:
        payload = self._payload(self._records())
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        freeze = self._freeze(payload["datasetDigest"])
        run_a = self._p00_run(
            freeze,
            payload,
            evidence,
            "A",
            assertions=[("outer-workflow-verified", "PASS", digest("1"))],
        )
        run_b = self._p00_run(
            freeze,
            payload,
            evidence,
            "B",
            assertions=[("outer-workflow-verified", "PASS", digest("2"))],
        )
        with self.assertRaises(GateRunnerError) as caught:
            combine_runs(
                freeze=freeze,
                criterion_id=REPRO_CRITERION,
                run_a=run_a,
                run_b=run_b,
            )
        self.assertEqual(caught.exception.code, "deterministic_evidence_mismatch")

    def test_deepcopied_or_cross_criterion_runs_and_pairs_are_rejected(self) -> None:
        payload = self._payload(self._records())
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        freeze = self._freeze(payload["datasetDigest"])
        run_a = self._p00_run(freeze, payload, evidence, "A")
        run_b = self._p00_run(freeze, payload, evidence, "B")
        for copied in (replace(run_a), deepcopy(run_a)):
            with self.subTest(copy=id(copied)):
                with self.assertRaises(GateRunnerError) as caught:
                    combine_runs(
                        freeze=freeze,
                        criterion_id=REPRO_CRITERION,
                        run_a=copied,
                        run_b=run_b,
                    )
                self.assertEqual(caught.exception.code, "unsealed_run_result")

        bootstrap_b = record_run(
            freeze=freeze,
            criterion_id=CONTROL_CRITERION,
            label="B",
            command_result=self._command(
                "B",
                assertions=[("candidate-semantically-valid", "PASS", digest("8"))],
            ),
        )
        with self.assertRaises(GateRunnerError) as caught:
            combine_runs(
                freeze=freeze,
                criterion_id=REPRO_CRITERION,
                run_a=run_a,
                run_b=bootstrap_b,
            )
        self.assertEqual(caught.exception.code, "cross_criterion_run")

        pair = combine_runs(
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            run_a=run_a,
            run_b=run_b,
        )
        for copied_pair in (deepcopy(pair), dict(pair)):
            with self.subTest(pair=id(copied_pair)):
                with self.assertRaises(GateRunnerError) as caught:
                    criterion_result_projection(
                        freeze=freeze,
                        criterion_id=REPRO_CRITERION,
                        run_pair=copied_pair,
                    )
                self.assertEqual(caught.exception.code, "unsealed_run_pair")

    def test_dirty_wrong_checkout_and_handwritten_summary_are_rejected(self) -> None:
        payload = self._payload(self._records())
        evidence = evaluate_strict(REPRO_EVALUATOR, payload)
        freeze = self._freeze(payload["datasetDigest"])
        dirty = self._command("A", dirty=True)
        wrong_checkout = self._command("B", clean=False)
        handwritten = self._command("A")
        handwritten["summary"] = {"passed": 999, "failed": 0, "skipped": 0}
        for command, code in (
            (dirty, "dirty_source"),
            (wrong_checkout, "clean_checkout_mismatch"),
            (handwritten, "invalid_command_result"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(GateRunnerError) as caught:
                    record_run(
                        freeze=freeze,
                        criterion_id=REPRO_CRITERION,
                        label="B" if command is wrong_checkout else "A",
                        command_result=command,
                        evaluator_input=payload,
                        evaluator_evidence=evidence,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_module_has_no_io_network_or_process_capability(self) -> None:
        path = REPO_ROOT / "tools/phasegate/gate_runner.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        forbidden = {
            "asyncio",
            "http",
            "os",
            "pathlib",
            "requests",
            "shutil",
            "socket",
            "subprocess",
            "urllib",
        }
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(imports & forbidden)
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(calls & {"open", "read_text", "write_text", "run", "Popen"})

    def test_phase_pair_uses_aggregate_contract_and_strict_projection(self) -> None:
        payload = build_paired_input(
            AGGREGATE_EVALUATOR,
            self._aggregate_records(),
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
            evaluator_digest=EVALUATOR_DIGEST,
            dataset_id="p00-phase-aggregate",
        )
        evidence = evaluate_strict(AGGREGATE_EVALUATOR, payload)
        self.assertEqual(evidence["result"], "PASS")
        freeze = self._phase_freeze(payload["datasetDigest"])
        runs = [
            record_phase_run(
                freeze=freeze,
                criterion_id=AGGREGATE_CRITERION,
                label=label,
                command_result=self._command(label),
                evaluator_input=payload,
                evaluator_evidence=evidence,
            )
            for label in ("A", "B")
        ]
        pair = combine_phase_runs(
            freeze=freeze,
            criterion_id=AGGREGATE_CRITERION,
            run_a=runs[0],
            run_b=runs[1],
        )
        projection = phase_criterion_result_projection(
            freeze=freeze,
            criterion_id=AGGREGATE_CRITERION,
            run_pair=pair,
        )
        self.assertEqual(projection["outcome"], "PASS")
        self.assertIs(projection["runPair"], pair)
        self.assertEqual(pair["runA"]["contractDigest"], CONTRACT_DIGEST)

    def test_phase_and_work_unit_pair_seals_cannot_cross_or_be_copied(self) -> None:
        payload = build_paired_input(
            AGGREGATE_EVALUATOR,
            self._aggregate_records(),
            source_commit=SOURCE_COMMIT,
            control_plane_digest=CONTROL_DIGEST,
            evaluator_digest=EVALUATOR_DIGEST,
            dataset_id="p00-phase-aggregate",
        )
        evidence = evaluate_strict(AGGREGATE_EVALUATOR, payload)
        phase_freeze = self._phase_freeze(payload["datasetDigest"])
        phase_a = record_phase_run(
            freeze=phase_freeze,
            criterion_id=AGGREGATE_CRITERION,
            label="A",
            command_result=self._command("A"),
            evaluator_input=payload,
            evaluator_evidence=evidence,
        )
        phase_b = record_phase_run(
            freeze=phase_freeze,
            criterion_id=AGGREGATE_CRITERION,
            label="B",
            command_result=self._command("B"),
            evaluator_input=payload,
            evaluator_evidence=evidence,
        )
        phase_pair = combine_phase_runs(
            freeze=phase_freeze,
            criterion_id=AGGREGATE_CRITERION,
            run_a=phase_a,
            run_b=phase_b,
        )
        work_payload = self._payload(self._records())
        work_evidence = evaluate_strict(REPRO_EVALUATOR, work_payload)
        work_freeze = self._freeze(work_payload["datasetDigest"])
        work_pair = combine_runs(
            freeze=work_freeze,
            criterion_id=REPRO_CRITERION,
            run_a=self._p00_run(work_freeze, work_payload, work_evidence, "A"),
            run_b=self._p00_run(work_freeze, work_payload, work_evidence, "B"),
        )
        cases = (
            (
                "unsealed_phase_run_pair",
                lambda: phase_criterion_result_projection(
                    freeze=phase_freeze,
                    criterion_id=AGGREGATE_CRITERION,
                    run_pair=work_pair,
                ),
            ),
            (
                "unsealed_run_pair",
                lambda: criterion_result_projection(
                    freeze=work_freeze,
                    criterion_id=REPRO_CRITERION,
                    run_pair=phase_pair,
                ),
            ),
            (
                "unsealed_phase_run_pair",
                lambda: phase_criterion_result_projection(
                    freeze=phase_freeze,
                    criterion_id=AGGREGATE_CRITERION,
                    run_pair=deepcopy(phase_pair),
                ),
            ),
        )
        for code, operation in cases:
            with self.subTest(code=code):
                with self.assertRaises(GateRunnerError) as caught:
                    operation()
                self.assertEqual(caught.exception.code, code)
        with self.assertRaises(GateRunnerError) as caught:
            combine_phase_runs(
                freeze=phase_freeze,
                criterion_id=AGGREGATE_CRITERION,
                run_a=self._p00_run(work_freeze, work_payload, work_evidence, "A"),
                run_b=phase_b,
            )
        self.assertEqual(caught.exception.code, "freeze_identity_mismatch")


if __name__ == "__main__":
    unittest.main()
