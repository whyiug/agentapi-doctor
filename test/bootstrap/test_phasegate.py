from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.validation import (  # noqa: E402
    ACTIVE_REQUEST_PATH,
    ValidationError,
    ensure_gate_is_executable,
    validate_bootstrap_candidate,
)
from tools.phasegate.digest import (  # noqa: E402
    approval_digest_groups,
    compute_control_plane_digest,
    read_input_manifest,
)


def read_document(root: Path, relative: str) -> dict:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def write_document(root: Path, relative: str, document: dict) -> None:
    (root / relative).write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


class CandidateCopy(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="agentapi-doctor-bootstrap-"
        )
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(
            REPO_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "*.pyc", ".pytest_cache"
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue_codes(self, exc: ValidationError) -> set[str]:
        return {issue.code for issue in exc.issues}

    def assert_candidate_fails_with(self, code: str) -> ValidationError:
        with self.assertRaises(ValidationError) as caught:
            validate_bootstrap_candidate(self.root)
        self.assertIn(code, self.issue_codes(caught.exception))
        return caught.exception

    def rebind_candidate(self) -> str:
        digest, _ = compute_control_plane_digest(self.root)
        _, inputs = read_input_manifest(self.root)
        json_kinds = {"json", "json-yaml", "manifest", "contract", "catalog", "gate"}
        for entry in inputs:
            if entry["kind"] not in json_kinds:
                continue
            document = read_document(self.root, entry["path"])
            if "controlPlaneDigest" in document:
                document["controlPlaneDigest"] = digest
                write_document(self.root, entry["path"], document)
        rebound, components = compute_control_plane_digest(self.root)
        self.assertEqual(rebound, digest)
        request_path = ACTIVE_REQUEST_PATH
        request = read_document(self.root, request_path)
        request["candidate"]["controlPlaneDigest"] = digest
        request["componentDigests"] = {
            item["path"]: item["digest"] for item in components
        }
        request["digestGroups"] = approval_digest_groups(components)
        write_document(self.root, request_path, request)
        return digest


class BootstrapCandidateTests(CandidateCopy):
    def test_current_candidate_is_semantically_valid(self) -> None:
        result = validate_bootstrap_candidate(self.root)
        self.assertEqual(result["mode"], "pre_genesis_candidate")
        self.assertGreaterEqual(result["contractCount"], 6)
        self.assertGreaterEqual(result["evaluatorCount"], 2)

    def test_missing_declared_input_cannot_pass(self) -> None:
        inputs = read_document(self.root, "execution/control-plane-inputs.yaml")
        victim = next(
            item["path"]
            for item in inputs["inputs"]
            if item["path"].startswith("execution/work-units/")
        )
        (self.root / victim).unlink()
        self.assert_candidate_fails_with("digest_input_error")

    def test_incomplete_contract_cannot_pass(self) -> None:
        path = "execution/work-units/P00.W01.yaml"
        contract = read_document(self.root, path)
        del contract["objective"]
        write_document(self.root, path, contract)
        self.assert_candidate_fails_with("incomplete_contract")

    def test_undeclared_control_plane_file_cannot_escape_digest(self) -> None:
        hidden = self.root / "execution/gates/p00/hidden-evaluator.yaml"
        hidden.write_text("{}\n", encoding="utf-8")
        self.assert_candidate_fails_with("undeclared_control_plane_file")

    def test_duplicate_json_key_cannot_pass(self) -> None:
        path = self.root / "execution/work-units/P00.W01.yaml"
        original = path.read_text(encoding="utf-8")
        path.write_text(
            original.replace("{", '{\n  "objective": "shadowed",', 1),
            encoding="utf-8",
        )
        self.assert_candidate_fails_with("digest_input_error")

    def test_non_finite_number_cannot_pass(self) -> None:
        path = self.root / "execution/metrics/definitions.yaml"
        original = path.read_text(encoding="utf-8")
        path.write_text(
            original.replace('"minimumN": 30', '"minimumN": NaN', 1), encoding="utf-8"
        )
        self.assert_candidate_fails_with("digest_input_error")

    def test_constant_pass_evaluator_cannot_pass(self) -> None:
        path = "execution/evaluators/catalog.yaml"
        catalog = read_document(self.root, path)
        catalog["evaluators"][0]["implementation"] = {
            "type": "constant",
            "value": "PASS",
        }
        write_document(self.root, path, catalog)
        self.assert_candidate_fails_with("placeholder_evaluator")

    def test_hand_entered_metric_result_cannot_pass(self) -> None:
        path = "execution/metrics/definitions.yaml"
        metrics = read_document(self.root, path)
        metrics["metrics"][0]["metricValue"] = 1
        write_document(self.root, path, metrics)
        self.assert_candidate_fails_with("hand_entered_metric_result")

    def test_gate_digest_mismatch_cannot_pass_after_rebind(self) -> None:
        path = "execution/gates/p00/P00.W01.yaml"
        gate = read_document(self.root, path)
        gate["controlPlaneDigest"] = "sha256:" + "0" * 64
        write_document(self.root, path, gate)
        self.assert_candidate_fails_with("gate_digest_mismatch")

    def test_request_integrity_fields_cannot_be_forged(self) -> None:
        path = ACTIVE_REQUEST_PATH
        request = read_document(self.root, path)
        request["digestGroups"] = {
            key: "sha256:" + "0" * 64 for key in request["digestGroups"]
        }
        request["antiPlaceholderTests"]["command"] = "true"
        request["diff"]["forbiddenArtifactsVerifiedAbsent"] = []
        request["approval"] = {"decision": "APPROVED"}
        write_document(self.root, path, request)
        error = self.assert_candidate_fails_with("request_digest_group_mismatch")
        codes = self.issue_codes(error)
        self.assertIn("request_anti_placeholder_drift", codes)
        self.assertIn("request_forbidden_absence_drift", codes)
        self.assertIn("agent_authored_approval_fact", codes)

    def test_empty_fail_open_gate_cannot_pass_after_rebind(self) -> None:
        path = "execution/gates/p00/P00.W02.yaml"
        gate = read_document(self.root, path)
        gate["criteria"] = []
        gate["failClosed"] = False
        write_document(self.root, path, gate)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("empty_gate_criteria")
        self.assertIn("gate_not_fail_closed", self.issue_codes(error))

    def test_contract_without_phase_cannot_pass_after_rebind(self) -> None:
        path = "execution/work-units/P00.W02.yaml"
        contract = read_document(self.root, path)
        del contract["phase"]
        write_document(self.root, path, contract)
        self.rebind_candidate()
        self.assert_candidate_fails_with("incomplete_contract")

    def test_criterion_kind_and_threshold_drift_cannot_pass_after_rebind(self) -> None:
        path = "execution/gates/p00/P00.W02.yaml"
        gate = read_document(self.root, path)
        gate["criteria"][1]["kind"] = "MACHINE"
        gate["criteria"][1]["threshold"] = ""
        write_document(self.root, path, gate)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("gate_contract_criterion_drift")
        codes = self.issue_codes(error)
        self.assertIn("criterion_evaluator_kind_mismatch", codes)
        self.assertIn("empty_criterion_threshold", codes)

    def test_protected_acceptance_catalog_cannot_be_emptied_after_rebind(self) -> None:
        path = "execution/catalogs/p00/acceptance.yaml"
        catalog = read_document(self.root, path)
        catalog["protected"] = False
        catalog["criteria"] = []
        catalog["antiGaming"] = []
        write_document(self.root, path, catalog)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("empty_acceptance_catalog")
        codes = self.issue_codes(error)
        self.assertIn("unprotected_acceptance_catalog", codes)
        self.assertIn("missing_anti_gaming_rules", codes)

    def test_bootstrap_catalog_cannot_be_emptied_after_rebind(self) -> None:
        path = "execution/catalogs/p00/bootstrap.yaml"
        catalog = read_document(self.root, path)
        catalog["requiredAssertions"] = []
        catalog["protectedNegativeCases"] = []
        catalog["forbiddenPreGenesisPaths"] = []
        write_document(self.root, path, catalog)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("bootstrap_assertion_drift")
        codes = self.issue_codes(error)
        self.assertIn("bootstrap_negative_case_drift", codes)
        self.assertIn("bootstrap_forbidden_path_drift", codes)

    def test_prerequisite_and_network_policy_cannot_be_relaxed_after_rebind(
        self,
    ) -> None:
        path = "execution/work-units/P00.W02.yaml"
        contract = read_document(self.root, path)
        contract["prerequisites"] = []
        contract["networkPolicy"]["gate"] = "online"
        contract["networkPolicy"]["researchAllowlist"] = ["*"]
        write_document(self.root, path, contract)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("prerequisite_drift")
        codes = self.issue_codes(error)
        self.assertIn("online_gate_policy", codes)
        self.assertIn("invalid_research_allowlist", codes)

    def test_contract_references_and_verification_cannot_be_replaced_after_rebind(
        self,
    ) -> None:
        path = "execution/work-units/P00.W02.yaml"
        contract = read_document(self.root, path)
        contract["readFirst"] = ["does-not-exist.md"]
        contract["protectedAcceptanceInputs"] = ["does-not-exist.yaml"]
        contract["verification"] = ["true"]
        write_document(self.root, path, contract)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("missing_read_first")
        codes = self.issue_codes(error)
        self.assertIn("unbound_protected_input", codes)
        self.assertIn("invalid_verification_command", codes)

    def test_planned_evaluator_cannot_reuse_bootstrap_handler_after_rebind(
        self,
    ) -> None:
        path = "execution/evaluators/catalog.yaml"
        catalog = read_document(self.root, path)
        evaluator = next(
            item
            for item in catalog["evaluators"]
            if item["id"] == "evaluator://docs/license-links/v1"
        )
        evaluator.update(
            {
                "status": "implemented",
                "implementation": {
                    "type": "builtin",
                    "handler": "bootstrap.control_plane",
                },
                "implementationPaths": [
                    "tools/phasegate/main.py",
                    "tools/phasegate/digest.py",
                    "tools/phasegate/validation.py",
                    "tools/phasegate/__init__.py",
                ],
                "protectedTests": ["test/bootstrap/test_phasegate.py"],
                "mayProducePass": True,
            }
        )
        write_document(self.root, path, catalog)
        self.rebind_candidate()
        self.assert_candidate_fails_with("unknown_implemented_handler")

    def test_input_kind_cannot_hide_non_json_gate(self) -> None:
        inputs_path = "execution/control-plane-inputs.yaml"
        inputs = read_document(self.root, inputs_path)
        gate_path = "execution/gates/p00/P00.W02.yaml"
        next(item for item in inputs["inputs"] if item["path"] == gate_path)["kind"] = (
            "text"
        )
        write_document(self.root, inputs_path, inputs)
        (self.root / gate_path).write_text("not-json\n", encoding="utf-8")
        self.assert_candidate_fails_with("control_plane_input_kind_mismatch")

    def test_human_attestation_schema_cannot_be_weakened_after_rebind(self) -> None:
        path = "execution/evidence-schemas/catalog.yaml"
        catalog = read_document(self.root, path)
        schema = next(
            item
            for item in catalog["schemas"]
            if item["id"] == "evidence-schema://attestation/human-review/v1"
        )
        schema["requiredFields"] = ["decision"]
        write_document(self.root, path, catalog)
        self.rebind_candidate()
        error = self.assert_candidate_fails_with("incomplete_attestation_schema")
        self.assertIn("incomplete_human_schema", self.issue_codes(error))

    def test_control_plane_digest_drift_cannot_pass(self) -> None:
        path = ACTIVE_REQUEST_PATH
        request = read_document(self.root, path)
        request["candidate"]["controlPlaneDigest"] = "sha256:" + "0" * 64
        write_document(self.root, path, request)
        self.assert_candidate_fails_with("request_digest_mismatch")

    def test_agent_authored_reviewer_identity_cannot_pass(self) -> None:
        path = ACTIVE_REQUEST_PATH
        request = read_document(self.root, path)
        request["reviewerIdentity"] = "self-approved"
        write_document(self.root, path, request)
        self.assert_candidate_fails_with("agent_authored_approval_fact")

    def test_phase_state_before_genesis_cannot_pass(self) -> None:
        (self.root / "execution/phase-state.yaml").write_text("{}\n", encoding="utf-8")
        self.assert_candidate_fails_with("forbidden_pre_genesis_state")

    def test_transition_chain_before_genesis_cannot_pass(self) -> None:
        transitions = self.root / "execution/transitions"
        transitions.mkdir(parents=True)
        (transitions / "0001.json").write_text("{}\n", encoding="utf-8")
        self.assert_candidate_fails_with("forbidden_pre_genesis_state")

    def test_missing_approval_request_cannot_pass(self) -> None:
        (self.root / ACTIVE_REQUEST_PATH).unlink()
        self.assert_candidate_fails_with("missing_approval_request")

    def test_previous_request_revision_cannot_be_rewritten(self) -> None:
        path = "execution/approval-requests/P00.B00.yaml"
        request = read_document(self.root, path)
        request["limitations"].append("rewritten history")
        write_document(self.root, path, request)
        self.assert_candidate_fails_with("previous_request_drift")

    def test_request_cannot_bind_a_nonexistent_source_commit(self) -> None:
        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        request = read_document(self.root, ACTIVE_REQUEST_PATH)
        request["candidate"]["candidateSourceCommit"] = "f" * 40
        write_document(self.root, ACTIVE_REQUEST_PATH, request)
        self.assert_candidate_fails_with("request_source_commit_mismatch")

    def test_agent_cannot_configure_trust_roots_after_rebind(self) -> None:
        path = "execution/protected-verifier/trust-policy.yaml"
        policy = read_document(self.root, path)
        policy["policyStatus"] = "configured"
        write_document(self.root, path, policy)
        self.rebind_candidate()
        self.assert_candidate_fails_with("agent_configured_trust_roots")

    def test_state_transition_policy_cannot_be_weakened_after_rebind(self) -> None:
        path = "execution/protected-verifier/trust-policy.yaml"
        policy = read_document(self.root, path)
        policy["allowedTransitions"]["ACTIVE"].append("CONVERGED")
        write_document(self.root, path, policy)
        self.rebind_candidate()
        self.assert_candidate_fails_with("transition_policy_drift")

    def test_protected_workflow_cannot_gain_write_permission_after_rebind(
        self,
    ) -> None:
        path = self.root / ".github/workflows/p00-protected-verifier-candidate.yml"
        workflow = path.read_text(encoding="utf-8")
        mutations = (
            workflow.replace("contents: read", "contents: write", 1),
            workflow.replace(
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/checkout@v4",
                1,
            ),
            workflow + "\n# continue-on-error: true\n",
            workflow + "\n# python3 candidate-input/untrusted.py\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]):
                path.write_text(mutation, encoding="utf-8")
                self.rebind_candidate()
                self.assert_candidate_fails_with("unsafe_protected_workflow_candidate")


class GateExecutionTests(CandidateCopy):
    def test_planned_machine_evaluator_is_not_executable(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            ensure_gate_is_executable(self.root, "execution/gates/p00/P00.W03.yaml")
        self.assertIn("missing_evaluator", self.issue_codes(caught.exception))

    def test_unknown_evaluator_is_not_executable(self) -> None:
        path = "execution/gates/p00/P00.W01.yaml"
        gate = read_document(self.root, path)
        gate["criteria"][0]["evaluator"] = "evaluator://unknown/fixed-pass/v1"
        write_document(self.root, path, gate)
        with self.assertRaises(ValidationError) as caught:
            ensure_gate_is_executable(self.root, path)
        self.assertIn("unknown_evaluator", self.issue_codes(caught.exception))

    def test_unit_gate_fails_before_independent_approval_and_genesis(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(self.root / "tools/phasegate/main.py"),
                "gate-unit",
                "P00.W01",
                "--root",
                str(self.root),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        output = json.loads(completed.stdout)
        self.assertEqual(output["status"], "fail")
        self.assertEqual(
            output["reasonCode"], "independent_approval_and_genesis_required"
        )

    def test_cli_bootstrap_reports_computed_digest(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(self.root / "tools/phasegate/main.py"),
                "bootstrap",
                "--root",
                str(self.root),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual(output["status"], "pass")
        self.assertRegex(output["controlPlaneDigest"], r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
