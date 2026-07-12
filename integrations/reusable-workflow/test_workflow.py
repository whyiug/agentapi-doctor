#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("validate_inputs.py")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_WORKFLOW_PATH = Path(__file__).with_name("workflow.yml")
CALLABLE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "doctor.yml"
SPEC = importlib.util.spec_from_file_location("reusable_validate_inputs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
validate_inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_inputs)


class ReusableWorkflowTests(unittest.TestCase):
    def test_callable_workflow_matches_reviewed_source(self) -> None:
        self.assertTrue(CALLABLE_WORKFLOW_PATH.is_file())
        self.assertEqual(
            CALLABLE_WORKFLOW_PATH.read_bytes(),
            SOURCE_WORKFLOW_PATH.read_bytes(),
        )

    def test_workflow_pins_third_party_actions_and_permissions(self) -> None:
        workflow = CALLABLE_WORKFLOW_PATH.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        external = [value for value in uses if not value.startswith("./")]
        self.assertTrue(external)
        for value in external:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("action_commit:", workflow)
        self.assertIn("ref: ${{ inputs.action_commit }}", workflow)
        self.assertIn("version: ${{ inputs.version }}", workflow)
        self.assertIn("cosign-release: v3.0.6", workflow)
        self.assertNotIn("secrets.", workflow.lower())
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotRegex(workflow.lower(), r"@(main|master|latest|v[0-9]+)(?:\s|$)")

    def test_candidate_is_explicitly_unpublished(self) -> None:
        candidate = json.loads(Path(__file__).with_name("candidate.json").read_text(encoding="utf-8"))
        self.assertEqual(candidate["status"], "candidate-unpublished")
        self.assertEqual(candidate["workflowPath"], ".github/workflows/doctor.yml")
        self.assertEqual(
            candidate["sourceTemplatePath"],
            "integrations/reusable-workflow/workflow.yml",
        )
        self.assertIsNone(candidate["publishedWorkflowCommit"])
        self.assertEqual(candidate["publishedEvidence"], [])

    def test_version_and_commit_validation_reject_floating_values(self) -> None:
        self.assertEqual(validate_inputs.validate_version("1.2.3-rc.4"), "1.2.3-rc.4")
        self.assertEqual(validate_inputs.validate_commit("1" * 40), "1" * 40)
        for value in ("latest", "main", "v1.2.3", "1.2.x"):
            with self.subTest(version=value), self.assertRaises(validate_inputs.InputError):
                validate_inputs.validate_version(value)
        for value in ("main", "a" * 39, "0" * 40, "A" * 40):
            with self.subTest(commit=value), self.assertRaises(validate_inputs.InputError):
                validate_inputs.validate_commit(value)

    def test_config_path_rejects_traversal_symlink_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            config = root / "config" / "doctor.yaml"
            config.parent.mkdir()
            config.write_text("schemaVersion: synthetic\n", encoding="utf-8")
            self.assertEqual(validate_inputs.validate_config_path(root, "config/doctor.yaml"), config)
            for relative in ("../outside", "/absolute", "config\\doctor.yaml", "config/../doctor.yaml"):
                with self.subTest(relative=relative), self.assertRaises(validate_inputs.InputError):
                    validate_inputs.validate_config_path(root, relative)
            link = root / "linked.yaml"
            link.symlink_to(Path(outside) / "config.yaml")
            with self.assertRaises(validate_inputs.InputError):
                validate_inputs.validate_config_path(root, "linked.yaml")
            large = root / "large.yaml"
            large.write_bytes(b"x" * (validate_inputs.MAX_CONFIG_BYTES + 1))
            with self.assertRaises(validate_inputs.InputError):
                validate_inputs.validate_config_path(root, "large.yaml")


if __name__ == "__main__":
    unittest.main()
