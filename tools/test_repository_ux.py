"""Offline contracts for supported defaults and evidence-preserving cleanup."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryUXTests(unittest.TestCase):
    def test_default_container_stage_is_doctor_with_explicit_dev_targets(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        stages = re.findall(r"(?m)^FROM\s+\S+\s+AS\s+([A-Za-z0-9._-]+)$", dockerfile)
        self.assertEqual(stages[-1], "doctor")
        self.assertEqual(len(stages), len(set(stages)))
        self.assertEqual(
            set(stages), {"build", "doctor", "registry", "reference-server"}
        )

    def test_compose_services_require_the_experimental_profile(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        services_section = compose.split("\nvolumes:", 1)[0]
        service_names = re.findall(
            r"(?m)^  ([A-Za-z0-9_-]+):$", services_section
        )
        self.assertEqual(set(service_names), {"registry", "reference"})
        for service in ("registry", "reference"):
            match = re.search(
                rf"(?ms)^  {service}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:)",
                compose,
            )
            self.assertIsNotNone(match, f"missing Compose service: {service}")
            self.assertRegex(match.group("body"), r"(?m)^    profiles: \[experimental\]$")

    def test_clean_preserves_local_evidence_and_help_states_the_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            for directory in ("bin", "dist", ".agentapi"):
                (workspace / directory).mkdir()
                (workspace / directory / "keep").write_text("test", encoding="utf-8")
            completed = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "-f",
                    str(ROOT / "Makefile"),
                    "-C",
                    str(workspace),
                    "clean",
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertFalse((workspace / "bin").exists())
            self.assertFalse((workspace / "dist").exists())
            self.assertEqual(
                (workspace / ".agentapi" / "keep").read_text(encoding="utf-8"),
                "test",
            )

        help_result = subprocess.run(
            ["make", "--no-print-directory", "-s", "help"],
            cwd=ROOT,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stdout)
        self.assertIn("supported Doctor CLI plus repository-only commands", help_result.stdout)
        self.assertIn("preserve local .agentapi evidence", help_result.stdout)


if __name__ == "__main__":
    unittest.main()
