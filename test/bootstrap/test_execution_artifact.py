from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "test/bootstrap"))

from test_run_executor import (  # noqa: E402
    CONTROL_CRITERION,
    CONTROL_EVALUATOR,
    REPRO_CRITERION,
    REPRO_EVALUATOR,
    RunExecutorTests,
    TemporaryGateRepository,
)
from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.execution_artifact import (  # noqa: E402
    CapturedRunArtifact,
    ExecutionArtifactError,
    SYNTHETIC_SECRET_CANARY,
    serialize_execution_artifact_bundle,
    verify_phase_execution_artifact_bundle,
    verify_execution_artifact_bundle,
)
from tools.phasegate.gate_runner import (  # noqa: E402
    SealedPhaseRunPair,
    criterion_result_projection,
)
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    build_paired_input,
)
from tools.phasegate.protected import document_digest  # noqa: E402
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    PhaseSubject,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedSignerResult,
    _mark_verified,
)
from tools.phasegate.run_executor import execute_pair, execute_phase_pair  # noqa: E402


class ExecutionArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = TemporaryGateRepository()
        helper = RunExecutorTests(methodName="runTest")
        cls.freeze = helper._freeze(
            cls.repository.commit,
            criterion_id=CONTROL_CRITERION,
            evaluator=CONTROL_EVALUATOR,
        )
        cls.execution = execute_pair(
            repo_root=cls.repository.root,
            freeze=cls.freeze,
            criterion_id=CONTROL_CRITERION,
        )
        cls.raw = cls.execution.artifact_bundle

    @classmethod
    def tearDownClass(cls) -> None:
        cls.repository.close()

    def _document(self) -> dict:
        return json.loads(self.raw)

    def _canonical_with_bundle_digest(self, document: dict) -> bytes:
        document["bundleDigest"] = document_digest(document, omit_field="bundleDigest")
        return canonical_json_bytes(document)

    def _phase_material(self):
        control_digest = "sha256:" + "6" * 64
        evaluator_digest = "sha256:" + "2" * 64
        records = [
            {
                "id": criterion_id,
                "criterionId": criterion_id,
                "kind": "MACHINE",
                "evaluator": evaluator,
                "result": "PASS",
                "evidenceDigest": sha256_bytes(f"evidence:{criterion_id}".encode()),
                "verificationPairId": f"pair-child-{index:02d}",
                "sourceCommit": self.repository.commit,
                "controlPlaneDigest": control_digest,
                "evaluatorDigest": sha256_bytes(f"evaluator:{criterion_id}".encode()),
                "datasetFreezeDigest": sha256_bytes(f"freeze:{criterion_id}".encode()),
                "datasetDigest": sha256_bytes(f"dataset:{criterion_id}".encode()),
                "verifierDigest": sha256_bytes(f"verifier:{criterion_id}".encode()),
            }
            for index, (criterion_id, evaluator) in enumerate(
                sorted(AGGREGATE_CRITERIA.items())
            )
        ]
        payload = build_paired_input(
            "evaluator://phase/aggregate/v1",
            records,
            source_commit=self.repository.commit,
            control_plane_digest=control_digest,
            evaluator_digest=evaluator_digest,
            dataset_id="p00-phase-aggregate",
        )
        criterion = CriterionBinding(
            criterion_id="P00-M-AGGREGATE",
            kind="MACHINE",
            evaluator="evaluator://phase/aggregate/v1",
            evaluator_digest=evaluator_digest,
            evidence_schema="evidence-schema://phase/aggregate-report/v1",
            evidence_schema_digest="sha256:" + "3" * 64,
            dataset_digest=payload["datasetDigest"],
            threshold_digest="sha256:" + "4" * 64,
        )
        work_freeze = RunExecutorTests(methodName="runTest")._freeze(
            self.repository.commit,
            criterion_id=REPRO_CRITERION,
            evaluator=REPRO_EVALUATOR,
            dataset_digest=payload["datasetDigest"],
        )
        subject = PhaseSubject(
            phase="P00",
            source_commit=self.repository.commit,
            control_plane_digest=control_digest,
            aggregate_contract_digest="sha256:" + "7" * 64,
        )
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace="agentapi-doctor/phase-protected-input-freeze/v1",
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest="sha256:" + "8" * 64,
            authority_digest="sha256:" + "9" * 64,
            source_commit=self.repository.commit,
            control_plane_digest=control_digest,
        )
        freeze = _mark_verified(
            VerifiedPhaseProtectedInputFreeze(
                attestation_digest="sha256:" + "a" * 64,
                statement_digest="sha256:" + "8" * 64,
                freeze_id="freeze-phase-execution-artifact-test",
                subject=subject,
                aggregate_contract_approval_digest="sha256:" + "b" * 64,
                unit_contract_digests=tuple(
                    (f"P00.W0{index}", sha256_bytes(f"unit:{index}".encode()))
                    for index in range(1, 6)
                ),
                protected_inputs=work_freeze.protected_inputs,
                criteria=(criterion,),
                signer=signer,
            )
        )
        return freeze, payload

    def test_cross_process_canonical_roundtrip_recomputes_same_sealed_pair(
        self,
    ) -> None:
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json,sys; value=json.load(sys.stdin);"
                    "sys.stdout.write(json.dumps(value,ensure_ascii=False,"
                    "allow_nan=False,sort_keys=True,separators=(',',':')))"
                ),
            ],
            input=self.raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(process.stdout, self.raw)
        verified = verify_execution_artifact_bundle(
            process.stdout,
            freeze=self.freeze,
            expected_criterion_id=CONTROL_CRITERION,
        )
        self.assertEqual(verified.run_pair_digest, self.execution.run_pair_digest)
        self.assertEqual(
            verified.evaluator_dataset_freeze_digest,
            self.freeze.attestation_digest,
        )
        projection = criterion_result_projection(
            freeze=self.freeze,
            criterion_id=CONTROL_CRITERION,
            run_pair=verified.run_pair,
        )
        self.assertEqual(projection["runPairDigest"], self.execution.run_pair_digest)

    def test_p00_evaluator_dataset_freeze_comes_from_recomputed_input(self) -> None:
        helper = RunExecutorTests(methodName="runTest")
        payload = build_paired_input(
            REPRO_EVALUATOR,
            helper._reproduction_records(),
            source_commit=self.repository.commit,
            control_plane_digest="sha256:" + "6" * 64,
            evaluator_digest="sha256:" + "2" * 64,
            dataset_id="p00-reproduction",
        )
        freeze = helper._freeze(
            self.repository.commit,
            criterion_id=REPRO_CRITERION,
            evaluator=REPRO_EVALUATOR,
            dataset_digest=payload["datasetDigest"],
        )
        execution = execute_pair(
            repo_root=self.repository.root,
            freeze=freeze,
            criterion_id=REPRO_CRITERION,
            evaluator_input=payload,
        )
        verified = verify_execution_artifact_bundle(
            execution.artifact_bundle,
            freeze=freeze,
            expected_criterion_id=REPRO_CRITERION,
        )
        self.assertEqual(
            verified.evaluator_dataset_freeze_digest,
            payload["datasetFreezeDigest"],
        )
        self.assertNotEqual(
            verified.evaluator_dataset_freeze_digest,
            freeze.attestation_digest,
        )

        mutant = json.loads(execution.artifact_bundle)
        mutant["evaluatorInput"]["datasetFreezeDigest"] = "sha256:" + "9" * 64
        raw = self._canonical_with_bundle_digest(mutant)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw,
                freeze=freeze,
                expected_criterion_id=REPRO_CRITERION,
            )
        self.assertEqual(caught.exception.code, "dataset_freeze_digest_mismatch")

    def test_phase_bundle_roundtrip_uses_disjoint_schema_and_pair_seal(self) -> None:
        freeze, payload = self._phase_material()
        execution = execute_phase_pair(
            repo_root=self.repository.root,
            freeze=freeze,
            criterion_id="P00-M-AGGREGATE",
            evaluator_input=payload,
        )
        self.assertIsInstance(execution.run_pair, SealedPhaseRunPair)
        verified = verify_phase_execution_artifact_bundle(
            execution.artifact_bundle,
            freeze=freeze,
            expected_criterion_id="P00-M-AGGREGATE",
        )
        self.assertEqual(verified.run_pair_digest, execution.run_pair_digest)
        self.assertEqual(
            verified.evaluator_dataset_freeze_digest,
            payload["datasetFreezeDigest"],
        )
        document = json.loads(execution.artifact_bundle)
        self.assertIn("aggregateContractDigest", document)
        self.assertNotIn("contractDigest", document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                execution.artifact_bundle,
                freeze=RunExecutorTests(methodName="runTest")._freeze(
                    self.repository.commit,
                    criterion_id=REPRO_CRITERION,
                    evaluator=REPRO_EVALUATOR,
                    dataset_digest=payload["datasetDigest"],
                ),
                expected_criterion_id=REPRO_CRITERION,
            )
        self.assertEqual(caught.exception.code, "invalid_artifact_schema")

    def test_fresh_verified_freeze_can_import_cross_process_bundle(self) -> None:
        helper = RunExecutorTests(methodName="runTest")
        fresh = helper._freeze(
            self.repository.commit,
            criterion_id=CONTROL_CRITERION,
            evaluator=CONTROL_EVALUATOR,
        )
        self.assertIsNot(fresh, self.freeze)
        verified = verify_execution_artifact_bundle(
            self.raw, freeze=fresh, expected_criterion_id=CONTROL_CRITERION
        )
        self.assertEqual(verified.run_pair_digest, self.execution.run_pair_digest)

    def test_noncanonical_json_and_duplicate_keys_are_rejected(self) -> None:
        noncanonical = json.dumps(self._document(), sort_keys=True).encode()
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                noncanonical,
                freeze=self.freeze,
                expected_criterion_id=CONTROL_CRITERION,
            )
        self.assertEqual(caught.exception.code, "noncanonical_json")
        duplicate = self.raw.replace(
            b'{"bundleDigest":',
            b'{"bundleDigest":"sha256:' + b"0" * 64 + b'","bundleDigest":',
            1,
        )
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                duplicate,
                freeze=self.freeze,
                expected_criterion_id=CONTROL_CRITERION,
            )
        self.assertEqual(caught.exception.code, "duplicate_key")

    def test_missing_raw_stderr_and_unknown_field_are_rejected(self) -> None:
        document = self._document()
        del document["runs"][0]["stderr"]
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "invalid_artifact_schema")
        document = self._document()
        document["runs"][0]["surprise"] = True
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "invalid_artifact_schema")

    def test_raw_byte_tamper_is_detected_before_serialized_summary_is_trusted(
        self,
    ) -> None:
        document = self._document()
        encoded = document["runs"][0]["stdout"]["data"]
        raw_output = bytearray(base64.b64decode(encoded))
        raw_output[-2] ^= 1
        document["runs"][0]["stdout"]["data"] = base64.b64encode(raw_output).decode()
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertIn(
            caught.exception.code,
            {"raw_output_digest_mismatch", "invalid_raw_evaluator_output"},
        )

    def test_forged_run_pair_summary_is_rejected_by_raw_recomputation(self) -> None:
        document = self._document()
        summary = document["runPair"]["runA"]["commands"][0]["summary"]
        summary["passed"] = 0
        summary["failed"] = 1
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "run_pair_recompute_mismatch")

    def test_log_manifest_and_artifact_digest_mutations_are_rejected(self) -> None:
        for field, code in (
            ("logDigest", "log_digest_mismatch"),
            ("artifactManifestDigest", "artifact_manifest_digest_mismatch"),
            ("artifactDigest", "artifact_digest_mismatch"),
        ):
            with self.subTest(field=field):
                document = self._document()
                document["runs"][0][field] = "sha256:" + "0" * 64
                raw = self._canonical_with_bundle_digest(document)
                with self.assertRaises(ExecutionArtifactError) as caught:
                    verify_execution_artifact_bundle(
                        raw,
                        freeze=self.freeze,
                        expected_criterion_id=CONTROL_CRITERION,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_a_b_toolchain_identity_and_freeze_digest_are_closed(self) -> None:
        document = self._document()
        document["runs"][1]["toolFacts"]["gitDigest"] = "sha256:" + "0" * 64
        document["runs"][1]["artifactDigest"] = document_digest(
            document["runs"][1], omit_field="artifactDigest"
        )
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "toolchain_mismatch")

        document = self._document()
        for run in document["runs"]:
            run["toolFacts"]["gitDigest"] = "sha256:" + "0" * 64
            run["artifactDigest"] = document_digest(run, omit_field="artifactDigest")
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "toolchain_freeze_mismatch")

    def test_wrong_freeze_source_commit_and_checkout_identity_are_rejected(
        self,
    ) -> None:
        helper = RunExecutorTests(methodName="runTest")
        wrong_freeze = helper._freeze(
            "f" * 40,
            criterion_id=CONTROL_CRITERION,
            evaluator=CONTROL_EVALUATOR,
        )
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                self.raw,
                freeze=wrong_freeze,
                expected_criterion_id=CONTROL_CRITERION,
            )
        self.assertEqual(caught.exception.code, "artifact_binding_mismatch")
        document = self._document()
        document["runs"][0]["checkoutIdentity"]["sourceCommit"] = "f" * 40
        raw = self._canonical_with_bundle_digest(document)
        with self.assertRaises(ExecutionArtifactError) as caught:
            verify_execution_artifact_bundle(
                raw, freeze=self.freeze, expected_criterion_id=CONTROL_CRITERION
            )
        self.assertEqual(caught.exception.code, "checkout_identity_mismatch")

    def test_timeout_truncation_and_false_destruction_proof_are_rejected(self) -> None:
        for section, field, code in (
            ("execution", "timedOut", "incomplete_execution"),
            ("execution", "outputTruncated", "incomplete_execution"),
            (
                "producerObservedDestruction",
                "checkoutAbsent",
                "producer_observation_mismatch",
            ),
        ):
            with self.subTest(field=field):
                document = self._document()
                document["runs"][0][section][field] = (
                    True if section == "execution" else False
                )
                raw = self._canonical_with_bundle_digest(document)
                with self.assertRaises(ExecutionArtifactError) as caught:
                    verify_execution_artifact_bundle(
                        raw,
                        freeze=self.freeze,
                        expected_criterion_id=CONTROL_CRITERION,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_synthetic_canary_and_host_path_are_never_serialized(self) -> None:
        self.assertNotIn(str(self.repository.root).encode(), self.raw)
        self.assertNotIn(b"RUN_EXECUTOR_SENTINEL_SECRET", self.raw)
        for leaked in (SYNTHETIC_SECRET_CANARY, b"/tmp/private-run/credential"):
            with self.subTest(leaked=leaked):
                document = self._document()
                output = document["runs"][0]["stderr"]
                output["data"] = base64.b64encode(leaked).decode()
                output["byteLength"] = len(leaked)
                output["digest"] = sha256_bytes(leaked)
                raw = self._canonical_with_bundle_digest(document)
                with self.assertRaises(ExecutionArtifactError) as caught:
                    verify_execution_artifact_bundle(
                        raw,
                        freeze=self.freeze,
                        expected_criterion_id=CONTROL_CRITERION,
                    )
                self.assertEqual(caught.exception.code, "sensitive_output_rejected")

    def test_copied_in_memory_pair_seal_cannot_be_serialized(self) -> None:
        copied = deepcopy(self.execution.run_pair)
        dummy = CapturedRunArtifact(
            label="A",
            stdout=b"",
            stderr=b"",
            command_result={},
            evaluator_evidence=None,
            output_limit_bytes=1,
            git_digest="sha256:" + "0" * 64,
            python_digest="sha256:" + "0" * 64,
            unshare_digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(ExecutionArtifactError) as caught:
            serialize_execution_artifact_bundle(
                freeze=self.freeze,
                criterion_id=CONTROL_CRITERION,
                run_pair=copied,
                captured_runs=(
                    dummy,
                    deepcopy(dummy).__class__(**{**dummy.__dict__, "label": "B"}),
                ),
            )
        self.assertEqual(caught.exception.code, "unsealed_run_pair")


if __name__ == "__main__":
    unittest.main()
