"""Regression checks for the pinned real-SDK Product CI job."""

from pathlib import Path
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
        self.assertIn(
            "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0",
            workflow,
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


if __name__ == "__main__":
    unittest.main()
