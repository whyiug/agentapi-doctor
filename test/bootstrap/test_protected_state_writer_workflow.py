"""Static security contract tests for the dual-mode protected state writer."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github/workflows/p00-protected-state-writer.yml"
CONTRACT = REPO_ROOT / "execution/protected-verifier/workflow-contract.yaml"

DOWNLOAD = (
    "actions/download-artifact@"
    "d3f86a106a0bac45b974a628896c90dbdf5c8093"
)


class ProtectedStateWriterWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_permissions_are_read_only_and_modes_are_exact(self) -> None:
        self.assertIn("permissions:\n", self.workflow)
        self.assertIn("  contents: read\n", self.workflow)
        self.assertIn("  actions: read\n", self.workflow)
        self.assertIn("  id-token: write\n", self.workflow)
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("actions: write", self.workflow)
        self.assertNotIn("HOME: ${{ runner.temp }}", self.workflow)
        self.assertEqual(
            self.workflow.count("HOME: /tmp/agentapi-doctor-p00-home"), 2
        )
        self.assertRegex(
            self.workflow,
            r"(?s)mode:.*?type: choice.*?options:\s+- genesis\s+- append",
        )
        self.assertRegex(
            self.workflow,
            r"(?s)Checkout exact request/workflow commit as data and Git proof.*?"
            r"path: request-input\s+fetch-depth: 0\s+persist-credentials: false",
        )
        self.assertIn("inputs.mode == 'genesis'", self.workflow)
        self.assertIn("inputs.mode == 'append'", self.workflow)
        self.assertIn("test -z \"$CANDIDATE_SHA$APPROVAL_B64\"", self.workflow)

    def test_append_downloads_only_immutable_ids_from_same_repository(self) -> None:
        self.assertEqual(self.workflow.count(f"uses: {DOWNLOAD}"), 2)
        for field in (
            "artifact-ids: ${{ inputs.chain_artifact_id }}",
            "artifact-ids: ${{ inputs.bundle_artifact_id }}",
            "run-id: ${{ inputs.chain_run_id }}",
            "run-id: ${{ inputs.bundle_run_id }}",
        ):
            self.assertIn(field, self.workflow)
        self.assertEqual(
            self.workflow.count("github-token: ${{ github.token }}"), 2
        )
        self.assertEqual(
            self.workflow.count("repository: ${{ github.repository }}"), 2
        )
        self.assertNotRegex(
            self.workflow,
            r"(?m)^\s+name:\s+\$\{\{\s*inputs\.(?:chain|bundle)",
        )
        for expression in (
            '[[ "$CHAIN_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]]',
            '[[ "$CHAIN_ARTIFACT_ID" =~ ^[1-9][0-9]{0,19}$ ]]',
            '[[ "$BUNDLE_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]]',
            '[[ "$BUNDLE_ARTIFACT_ID" =~ ^[1-9][0-9]{0,19}$ ]]',
        ):
            self.assertIn(expression, self.workflow)

    def test_artifact_bytes_are_data_only_and_cli_receives_every_pin(self) -> None:
        self.assertIn("protected-chain-append", self.workflow)
        for option in (
            "--chain",
            "--bundle",
            "--bootstrap-request-commit",
            "--expected-current-chain-head-digest",
            "--current-workflow-execution-commit",
            "--operation",
            "--to-state",
            "--phase",
            "--work-unit",
            "--output",
        ):
            self.assertIn(option, self.workflow)
        self.assertIn("--expected-bundle-digest", self.workflow)
        self.assertIn('canonical authorization bundle digest', self.workflow)
        for forbidden in (
            "bash $RUNNER_TEMP/p00-writer-input",
            "source $RUNNER_TEMP/p00-writer-input",
            "python3 $RUNNER_TEMP/p00-writer-input",
            "chmod +x",
            "eval ",
        ):
            self.assertNotIn(forbidden, self.workflow)
        self.assertIn('files[0].name != expected_name', self.workflow)
        self.assertIn('if any(item.is_symlink() for item in entries)', self.workflow)
        self.assertIn("os.O_NOFOLLOW", self.workflow)
        self.assertGreaterEqual(self.workflow.count("os.fstat(descriptor)"), 2)
        self.assertIn('test "$PHASE" = P00', self.workflow)
        self.assertRegex(
            self.workflow,
            r"(?s)phase-transition\)\s+test -z \"\$WORK_UNIT\"",
        )

    def test_contract_and_makefile_expose_the_same_append_boundary(self) -> None:
        permissions = self.contract["permissions"]
        self.assertFalse(permissions["contentsWrite"])
        self.assertEqual(permissions["githubToken"]["actions"], "read")
        append = self.contract["appendWriter"]
        self.assertTrue(append["readsArtifactsByImmutableId"])
        self.assertTrue(append["replaysFromGenesisBeforeAppend"])
        self.assertTrue(append["atomicOutputDirectory"])
        self.assertIn("phase-transition", append["supportedOperations"])
        self.assertEqual(
            append["unsupportedLifecycleWrites"],
            [
                "work-unit-control-invalidation",
                "work-unit-impact-invalidation",
                "work-unit-resume",
                "work-unit-supersession",
            ],
        )
        self.assertEqual(
            self.contract["trigger"]["appendPins"],
            [
                "bootstrapRequestCommit",
                "currentChainHeadDigest",
                "workflowExecutionCommit",
                "operation",
                "toState",
                "phase",
                "conditionalWorkUnit",
                "optionalAuthorizationBundleDigest",
            ],
        )
        self.assertEqual(
            {
                item["repository"]: item["commit"]
                for item in self.contract["actionPins"]
            }["actions/download-artifact"],
            "d3f86a106a0bac45b974a628896c90dbdf5c8093",
        )
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("protected-chain-replay:", makefile)
        self.assertIn("protected-chain-append:", makefile)
        self.assertIn("BUNDLE_DIGEST", makefile)
        self.assertIn("WORK_UNIT must be empty for phase-transition", makefile)


if __name__ == "__main__":
    unittest.main()
