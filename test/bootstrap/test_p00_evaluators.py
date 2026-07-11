from __future__ import annotations

from copy import deepcopy
import inspect
import unittest

from tools.phasegate.p00_evaluators import (
    AGGREGATE_CRITERIA,
    EVALUATORS,
    build_paired_input,
    canonical_digest,
    evaluate,
    evaluate_json,
)


SOURCE_COMMIT = "1" * 40
CONTROL_DIGEST = "sha256:" + "2" * 64
EVALUATOR_DIGEST = "sha256:" + "3" * 64


def digest(character: str) -> str:
    return "sha256:" + character * 64


def primary_source(index: int = 0) -> dict:
    return {
        "sourceType": "primary",
        "originalURL": f"https://source.example/original/{index}",
        "resolvedURL": f"https://source.example/resolved/{index}",
        "retrievedAt": "2026-07-11T00:00:00Z",
        "revision": f"rev-{index}",
        "contentDigest": digest("a"),
        "licenseOrReuseStatus": "public-facts-only",
    }


def paired(evaluator: str, records: list[dict]) -> dict:
    return build_paired_input(
        evaluator,
        records,
        source_commit=SOURCE_COMMIT,
        control_plane_digest=CONTROL_DIGEST,
        evaluator_digest=EVALUATOR_DIGEST,
        dataset_id="p00-test-dataset",
    )


def evaluate_records(evaluator: str, records: list[dict]) -> dict:
    return evaluate(evaluator, paired(evaluator, records))


MATRIX_DIMENSIONS = {
    "capability overlap": "compared",
    "architecture": "compared",
    "evidence model": "compared",
    "client-observed behavior": "compared",
    "governance": "compared",
    "reuse or collaboration opportunity": "compared",
    "independent-project justification": "compared",
}
NAMING_CHECK_NAMES = [
    "GitHub repository and organization",
    "Go module",
    "Python package",
    "npm package",
    "OCI namespace",
    "domain",
    "obvious trademark conflict",
]


def competitive_records() -> list[dict]:
    records = []
    for index, project in enumerate(
        [
            "am-i-openai-compatible",
            "octest",
            "FauxpenAI-conformance",
            "Open Responses",
        ]
    ):
        records.append(
            {
                "id": f"project-{index}",
                "recordType": "project",
                "project": project,
                "source": primary_source(index),
                "dimensions": dict(MATRIX_DIMENSIONS),
                "claims": ["Source-backed factual comparison."],
            }
        )
    for index in range(5):
        records.append(
            {
                "id": f"interview-{index}",
                "recordType": "interview",
                "interviewId": f"interview-{index}",
                "participantRole": "maintainer",
                "organization": f"organization-{index}",
                "source": primary_source(10 + index),
                "claims": ["Interview notes record only explicit statements."],
            }
        )
    for index in range(3):
        checks = {
            name: {
                "finding": "checked against the named primary registry",
                "source": primary_source(100 + index * 10 + offset),
            }
            for offset, name in enumerate(NAMING_CHECK_NAMES)
        }
        records.append(
            {
                "id": f"name-{index}",
                "recordType": "naming",
                "candidate": f"candidate-{index}",
                "source": primary_source(20 + index),
                "checks": checks,
                "claims": ["Availability remains provisional."],
            }
        )
    return records


def provenance_records(count: int = 30) -> list[dict]:
    result = []
    for index in range(count):
        result.append(
            {
                "id": f"case-{index:02d}",
                "originalURL": f"https://issues.example/{index}",
                "resolvedURL": f"https://issues.example/{index}",
                "retrievedAt": "2026-07-11T00:00:00Z",
                "revision": f"rev-{index}",
                "contentDigest": digest(chr(ord("a") + index % 6)),
                "sourceType": "primary",
                "licenseOrReuseStatus": "public-facts-only",
                "protocol": "openai-responses",
                "client": "sdk",
                "runtime": "local-fixture",
                "model": "synthetic",
                "symptom": "stream terminated before completion",
                "adjudicatedGroundTruth": "STREAM_STATE_MACHINE",
                "syntheticEligibility": True,
                "redactionStatus": "redacted",
            }
        )
    return result


def reproduction_records() -> list[dict]:
    result = []
    for index in range(20):
        expected = f"fingerprint-{index}"
        result.append(
            {
                "id": f"repro-{index}",
                "executionStatus": "completed" if index < 16 else "errored",
                "realCodePath": True,
                "localOnly": True,
                "publicTargetContacted": False,
                "weaponizedPayload": False,
                "expectedFailureFingerprint": expected,
                "observedFailureFingerprint": expected if index < 16 else None,
            }
        )
    return result


def taxonomy_records() -> list[dict]:
    result = []
    for index in range(20):
        domain, family = ("TRANSPORT", "transport") if index % 2 == 0 else ("SDK_PARSER", "client")
        result.append(
            {
                "id": f"taxonomy-{index}",
                "groundTruthDigest": digest("b"),
                "evidenceSufficient": True,
                "faultDomain": domain,
                "faultFamily": family,
            }
        )
    return result


def replay_records() -> list[dict]:
    return [
        {
            "id": f"replay-{index}",
            "controlledFixture": True,
            "nonDeterministicEnvelopeExcluded": True,
            "replayResultDigests": [digest("c"), digest("c")],
        }
        for index in range(10)
    ]


def dual_view_records() -> list[dict]:
    result = []
    for index in range(10):
        correlated = index < 8
        result.append(
            {
                "id": f"dual-{index}",
                "captureLayerDigest": digest("d"),
                "clientViewDigest": digest("e") if correlated else None,
                "captureCorrelationId": f"correlation-{index}",
                "clientCorrelationId": f"correlation-{index}" if correlated else None,
            }
        )
    return result


def minimization_records() -> list[dict]:
    result = []
    for index in range(10):
        result.append(
            {
                "id": f"min-{index}",
                "originalRequestBytes": 600,
                "originalEventBytes": 400,
                "minimizedRequestBytes": 300 if index < 5 else 550,
                "minimizedEventBytes": 300 if index < 5 else 350,
                "originalFingerprint": f"failure-{index}",
                "minimizedFingerprint": f"failure-{index}",
                "requiredInputsPreserved": True,
            }
        )
    return result


def secret_records() -> list[dict]:
    return [
        {
            "id": f"sink-{index}",
            "sink": sink,
            "scanned": True,
            "artifactDigest": digest("e"),
            "canaryDigest": digest("f"),
            "persistedLocations": [],
        }
        for index, sink in enumerate(
            [
                "raw artifacts",
                "normalized artifacts",
                "reports",
                "logs",
                "temporary files",
                "crash output",
            ]
        )
    ]


def unknown_records() -> list[dict]:
    return [
        {
            "id": "unknown-0",
            "evidenceSufficient": False,
            "evidenceDigests": [digest("a")],
            "attribution": "UNKNOWN_FAULT_DOMAIN",
        }
    ]


DOCUMENT_NAMES = [
    "RFC-0001 compatibility layers",
    "RFC-0002 evidence and result schema",
    "RFC-0003 scenario and pack model",
    "RFC-0004 driver isolation",
    "RFC-0005 Registry trust",
    "Threat Model v1 candidate",
    "Data Policy v1 candidate",
    "Competitive Landscape",
    "known limitations",
    "naming conflict evidence",
]


def document_records() -> list[dict]:
    return [
        {
            "id": f"doc-{index}",
            "documentName": name,
            "path": f"docs/document-{index}.md",
            "content": f"# {name}\n\nProvisional source: https://docs.example/source/{index}\n",
            "sourceLicense": "original-project-content",
        }
        for index, name in enumerate(DOCUMENT_NAMES)
    ]


def aggregate_records() -> list[dict]:
    return [
        {
            "id": criterion,
            "criterionId": criterion,
            "kind": "MACHINE",
            "evaluator": evaluator,
            "result": "PASS",
            "evidenceDigest": canonical_digest({"criterion": criterion}),
            "verificationPairId": "pair-001",
            "sourceCommit": SOURCE_COMMIT,
            "controlPlaneDigest": CONTROL_DIGEST,
            "evaluatorDigest": digest("b"),
            "datasetFreezeDigest": digest("c"),
            "datasetDigest": digest("d"),
            "verifierDigest": digest("e"),
        }
        for criterion, evaluator in sorted(AGGREGATE_CRITERIA.items())
    ]


class PositiveEvaluatorTests(unittest.TestCase):
    def assert_pass(self, evaluator: str, records: list[dict]) -> dict:
        result = evaluate_records(evaluator, records)
        self.assertEqual(result["result"], "PASS", result)
        self.assertEqual(result["reasonCode"], "threshold_met")
        self.assertTrue(result["runPair"]["consistent"])
        expected = dict(result)
        evidence_digest = expected.pop("evidenceDigest")
        self.assertEqual(evidence_digest, canonical_digest(expected))
        self.assertEqual(
            set(result),
            {
                "schemaVersion",
                "criterionId",
                "evaluator",
                "evaluatorDigest",
                "sourceCommit",
                "controlPlaneDigest",
                "datasetFreezeDigest",
                "datasetDigest",
                "result",
                "reasonCode",
                "runPair",
                "recomputed",
                "recordResults",
                "issues",
                "evidenceDigest",
            },
        )
        return result

    def test_every_catalog_planned_evaluator_has_an_implementation(self) -> None:
        self.assertEqual(len(EVALUATORS), 11)

    def test_competitive_recomputed(self) -> None:
        result = self.assert_pass("evaluator://research/competitive/v1", competitive_records())
        self.assertEqual(result["recomputed"]["matrixRecordCount"], 4)
        self.assertEqual(result["recomputed"]["interviewRecordCount"], 5)
        self.assertEqual(result["recomputed"]["namingCandidateCount"], 3)

    def test_provenance_recomputed(self) -> None:
        result = self.assert_pass("evaluator://catalog/provenance-count/v1", provenance_records())
        self.assertEqual(result["recomputed"]["eligibleCount"], 30)

    def test_reproduction_recomputed(self) -> None:
        result = self.assert_pass("evaluator://corpus/reproduction/v1", reproduction_records())
        self.assertEqual(result["recomputed"], {"attempted": 20, "reproduced": 16})

    def test_taxonomy_recomputed(self) -> None:
        result = self.assert_pass("evaluator://corpus/taxonomy/v1", taxonomy_records())
        self.assertEqual(result["recomputed"]["faultDomains"], ["SDK_PARSER", "TRANSPORT"])

    def test_replay_recomputed(self) -> None:
        result = self.assert_pass("evaluator://corpus/replay/v1", replay_records())
        self.assertEqual(result["recomputed"]["deterministicReplayCount"], 10)

    def test_dual_view_recomputed(self) -> None:
        result = self.assert_pass("evaluator://experiment/dual-view/v1", dual_view_records())
        self.assertEqual(result["recomputed"]["correlatedDualViewCount"], 8)

    def test_minimization_recomputed_from_bytes(self) -> None:
        result = self.assert_pass("evaluator://experiment/minimization/v1", minimization_records())
        self.assertEqual(result["recomputed"]["qualifyingReductionCount"], 5)
        self.assertAlmostEqual(result["recordResults"][0]["reduction"], 0.4)

    def test_secret_canary_recomputed_from_locations(self) -> None:
        result = self.assert_pass("evaluator://redaction/secret-canary/v1", secret_records())
        self.assertEqual(result["recomputed"]["persistedOccurrenceCount"], 0)

    def test_unknown_consistency_recomputed(self) -> None:
        result = self.assert_pass("evaluator://attribution/unknown/v1", unknown_records())
        self.assertEqual(result["recomputed"]["unsupportedAttributionCount"], 0)

    def test_docs_recomputed_from_content(self) -> None:
        result = self.assert_pass("evaluator://docs/license-links/v1", document_records())
        self.assertEqual(result["recomputed"]["validatedLinks"], 10)

    def test_phase_aggregate_requires_exact_machine_criterion_set(self) -> None:
        result = self.assert_pass("evaluator://phase/aggregate/v1", aggregate_records())
        self.assertEqual(result["recomputed"]["criterionIds"], sorted(AGGREGATE_CRITERIA))


class FailClosedEvaluatorTests(unittest.TestCase):
    def test_missing_top_level_or_record_field_is_error(self) -> None:
        payload = paired("evaluator://corpus/reproduction/v1", reproduction_records())
        del payload["datasetFreezeDigest"]
        self.assertEqual(
            evaluate("evaluator://corpus/reproduction/v1", payload)["reasonCode"],
            "invalid_schema",
        )
        payload = paired("evaluator://corpus/reproduction/v1", reproduction_records())
        for run in payload["runs"]:
            del run["records"][0]["realCodePath"]
        self.assertEqual(
            evaluate("evaluator://corpus/reproduction/v1", payload)["result"],
            "ERROR",
        )

    def test_extra_top_level_handwritten_aggregate_is_error(self) -> None:
        payload = paired("evaluator://corpus/reproduction/v1", reproduction_records())
        payload["reproduced"] = 20
        result = evaluate("evaluator://corpus/reproduction/v1", payload)
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "invalid_schema")

    def test_extra_record_field_is_error(self) -> None:
        payload = paired("evaluator://corpus/reproduction/v1", reproduction_records())
        for run in payload["runs"]:
            run["records"][0]["reproduced"] = True
        result = evaluate("evaluator://corpus/reproduction/v1", payload)
        self.assertEqual(result["result"], "ERROR")

    def test_duplicate_record_id_is_error(self) -> None:
        payload = paired("evaluator://corpus/replay/v1", replay_records())
        for run in payload["runs"]:
            run["records"].append(deepcopy(run["records"][0]))
        result = evaluate("evaluator://corpus/replay/v1", payload)
        self.assertEqual(result["reasonCode"], "duplicate_record")

    def test_duplicate_json_key_is_error(self) -> None:
        result = evaluate_json(
            "evaluator://corpus/replay/v1",
            '{"schemaVersion":"one","schemaVersion":"two"}',
        )
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "duplicate_json_key")

    def test_non_finite_number_is_error(self) -> None:
        result = evaluate_json("evaluator://corpus/replay/v1", '{"x":NaN}')
        self.assertEqual(result["reasonCode"], "non_finite_number")

    def test_run_b_record_drift_is_error(self) -> None:
        payload = paired("evaluator://corpus/replay/v1", replay_records())
        payload["runs"][1]["records"][0]["controlledFixture"] = False
        result = evaluate("evaluator://corpus/replay/v1", payload)
        self.assertEqual(result["result"], "ERROR")
        self.assertIn(result["reasonCode"], {"dataset_digest_mismatch", "run_pair_mismatch"})

    def test_run_identity_drift_is_error(self) -> None:
        payload = paired("evaluator://corpus/replay/v1", replay_records())
        payload["runs"][1]["controlPlaneDigest"] = digest("9")
        result = evaluate("evaluator://corpus/replay/v1", payload)
        self.assertEqual(result["reasonCode"], "run_identity_mismatch")

    def test_freeze_digest_drift_is_error(self) -> None:
        payload = paired("evaluator://corpus/replay/v1", replay_records())
        payload["datasetFreeze"]["datasetId"] = "changed"
        result = evaluate("evaluator://corpus/replay/v1", payload)
        self.assertEqual(result["reasonCode"], "dataset_freeze_digest_mismatch")

    def test_competitive_prohibited_claim_fails(self) -> None:
        records = competitive_records()
        records[0]["claims"] = ["willingness inferred from silence"]
        result = evaluate_records("evaluator://research/competitive/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(len(result["recomputed"]["prohibitedClaimFindings"]), 1)

    def test_competitive_duplicate_project_is_error(self) -> None:
        records = competitive_records()
        duplicate = deepcopy(records[0])
        duplicate["id"] = "project-duplicate"
        records.append(duplicate)
        result = evaluate_records("evaluator://research/competitive/v1", records)
        self.assertEqual(result["reasonCode"], "duplicate_project_record")

    def test_provenance_does_not_count_duplicate_source(self) -> None:
        records = provenance_records()
        records[1]["resolvedURL"] = records[0]["resolvedURL"]
        records[1]["revision"] = records[0]["revision"]
        records[1]["contentDigest"] = records[0]["contentDigest"]
        result = evaluate_records("evaluator://catalog/provenance-count/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["recomputed"]["eligibleCount"], 29)

    def test_reproduction_never_trusts_attempted_count(self) -> None:
        result = evaluate_records("evaluator://corpus/reproduction/v1", reproduction_records()[:19])
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reasonCode"], "insufficient_samples")

    def test_taxonomy_rejects_family_mismatch(self) -> None:
        records = taxonomy_records()
        records[0]["faultFamily"] = "client"
        result = evaluate_records("evaluator://corpus/taxonomy/v1", records)
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "taxonomy_mapping_mismatch")

    def test_replay_requires_raw_equal_repetitions(self) -> None:
        records = replay_records()
        records[0]["replayResultDigests"][1] = digest("f")
        result = evaluate_records("evaluator://corpus/replay/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["recomputed"]["deterministicReplayCount"], 9)

    def test_dual_view_requires_ten_denominator_records(self) -> None:
        result = evaluate_records("evaluator://experiment/dual-view/v1", dual_view_records()[:8])
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reasonCode"], "insufficient_samples")

    def test_minimization_requires_preserved_fingerprint_and_inputs(self) -> None:
        records = minimization_records()
        for record in records[:5]:
            record["requiredInputsPreserved"] = False
        result = evaluate_records("evaluator://experiment/minimization/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["recomputed"]["qualifyingReductionCount"], 0)

    def test_secret_canary_raw_match_fails(self) -> None:
        records = secret_records()
        records[0]["persistedLocations"] = ["logs/runner.log:17"]
        result = evaluate_records("evaluator://redaction/secret-canary/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reasonCode"], "secret_canary_persisted")

    def test_unknown_evaluator_rejects_unsupported_attribution(self) -> None:
        records = unknown_records()
        records[0]["attribution"] = "SDK_PARSER"
        result = evaluate_records("evaluator://attribution/unknown/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["recomputed"]["unsupportedAttributionCount"], 1)

    def test_docs_reject_stable_claim_from_raw_content(self) -> None:
        records = document_records()
        records[0]["content"] += "\nThis endpoint is fully compatible.\n"
        result = evaluate_records("evaluator://docs/license-links/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["recomputed"]["stableClaimFindings"], ["doc-0"])

    def test_aggregate_missing_or_extra_criterion_fails(self) -> None:
        missing = aggregate_records()[:-1]
        result = evaluate_records("evaluator://phase/aggregate/v1", missing)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reasonCode"], "criterion_set_mismatch")
        extra = aggregate_records()
        extra.append({**deepcopy(extra[0]), "id": "P00-M-EXTRA", "criterionId": "P00-M-EXTRA"})
        result = evaluate_records("evaluator://phase/aggregate/v1", extra)
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "aggregate_evaluator_mismatch")

    def test_aggregate_child_failure_blocks_pass(self) -> None:
        records = aggregate_records()
        records[0]["result"] = "FAIL"
        result = evaluate_records("evaluator://phase/aggregate/v1", records)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reasonCode"], "child_criterion_not_passed")

    def test_aggregate_child_subject_mismatch_is_error(self) -> None:
        records = aggregate_records()
        records[0]["controlPlaneDigest"] = digest("9")
        result = evaluate_records("evaluator://phase/aggregate/v1", records)
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "aggregate_subject_mismatch")

    def test_aggregate_rejects_reused_child_evidence(self) -> None:
        records = aggregate_records()
        records[1]["evidenceDigest"] = records[0]["evidenceDigest"]
        result = evaluate_records("evaluator://phase/aggregate/v1", records)
        self.assertEqual(result["result"], "ERROR")
        self.assertEqual(result["reasonCode"], "duplicate_child_evidence")

    def test_unknown_evaluator_and_missing_fields_are_errors(self) -> None:
        result = evaluate("evaluator://unknown/v1", {})
        self.assertEqual(result["result"], "ERROR")
        self.assertNotEqual(result["evidenceDigest"], "")

    def test_module_has_no_network_or_process_imports(self) -> None:
        source = inspect.getsource(__import__("tools.phasegate.p00_evaluators", fromlist=["*"]))
        for forbidden in ("import socket", "import requests", "import urllib", "import subprocess", "from pathlib"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
