"""Contract checks for the README's checked-in report and visual example."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicExampleTests(unittest.TestCase):
    def test_readme_failure_examples_keep_candidate_boundary_visible(self) -> None:
        examples = (
            (ROOT / "README.md", "## See a failure"),
            (ROOT / "README.zh-CN.md", "## 不只展示成功，也展示失败"),
        )
        for path, heading in examples:
            with self.subTest(path=path.name):
                readme = path.read_text(encoding="utf-8")
                section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
                for expected in (
                    "Result: CHECKS FAILED",
                    "Important conditions:",
                    "candidate_interpretations_pending_review",
                ):
                    self.assertIn(expected, section)

    def test_offline_html_exposes_the_bounded_result_and_conditions(self) -> None:
        report = (
            ROOT / "docs" / "examples" / "missing-terminal-event-report.html"
        ).read_text(encoding="utf-8")
        for expected in (
            "Content-Security-Policy",
            "builtin-openai-responses-raw-candidate@0.1.0-candidate.3",
            "<strong>Result:</strong> checks failed",
            "candidate_interpretations_pending_review",
            "provider_usage_unknown",
            "terminal_trace",
            "This report is an observation, not vendor certification.",
        ):
            self.assertIn(expected, report)
        self.assertNotIn("Profile outcome:", report)

    def test_readme_visual_uses_the_same_non_certification_language(self) -> None:
        visual = (
            ROOT / "docs" / "assets" / "agentapi-doctor-failure.svg"
        ).read_text(encoding="utf-8")
        self.assertIn("Result: CHECKS FAILED", visual)
        self.assertIn("candidate_interpretations_pending_review", visual)
        self.assertIn("terminal_count=0", visual)
        self.assertIn("not certification", visual)
        self.assertNotIn("Profile outcome:", visual)


if __name__ == "__main__":
    unittest.main()
