"""Regression checks for GitHub workflow dependency and Product CI contracts."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProductCIWorkflowTests(unittest.TestCase):
    def workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_real_sdk_job_pins_runtime_action_and_locked_install(self) -> None:
        workflow = self.workflow()
        self.assertIn("openai-python-sdk:", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertRegex(
            workflow,
            r"(?m)^\s*uses: actions/setup-python@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$",
        )
        self.assertIn("python-version: '3.12.12'", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("--only-binary=:all:", workflow)
        self.assertIn("--no-index", workflow)
        self.assertIn("requirements-linux-x86_64-py312.lock", workflow)

    def test_real_sdk_job_repeats_all_cases_and_gates_aggregate(self) -> None:
        workflow = self.workflow()
        self.assertIn(
            "AGENTAPI_DOCTOR_OPENAI_PYTHON: ${{ runner.temp }}/openai-sdk-venv/bin/python",
            workflow,
        )
        self.assertIn(
            "go test ./internal/openaisdkcase -run '^TestRealPinnedSDK$' -count=2 -timeout=2m",
            workflow,
        )
        self.assertIn(
            "needs: [go-platform, product-gate, containers, openai-python-sdk]",
            workflow,
        )
        self.assertIn(
            "OPENAI_PYTHON_SDK: ${{ needs.openai-python-sdk.result }}", workflow
        )
        self.assertIn('test "$OPENAI_PYTHON_SDK" = success', workflow)

    def test_every_external_action_is_pinned_by_full_commit(self) -> None:
        action = re.compile(r"^\s*uses:\s+([^\s@]+)@([^\s#]+)(?:\s+#\s+.+)?$")
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "uses:" not in line or "uses: ./" in line:
                    continue
                match = action.fullmatch(line)
                self.assertIsNotNone(match, f"malformed external action at {path}:{number}")
                self.assertRegex(
                    match.group(2),
                    r"^[0-9a-f]{40}$",
                    f"floating external action at {path}:{number}",
                )

    def test_every_setup_go_reads_the_single_go_mod_version(self) -> None:
        setup_count = 0
        version_file_count = 0
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            workflow = path.read_text(encoding="utf-8")
            setup_count += workflow.count("uses: actions/setup-go@")
            version_file_count += workflow.count("go-version-file: go.mod")
            self.assertNotRegex(workflow, r"(?m)^\s+go-version:\s*")
        self.assertGreater(setup_count, 0)
        self.assertEqual(version_file_count, setup_count)


if __name__ == "__main__":
    unittest.main()
