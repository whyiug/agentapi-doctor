"""Execute the checked-in DCO gate against bounded local Git histories."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT_AUTHOR_NAME = "dependabot[bot]"
DEPENDABOT_AUTHOR_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
DEPENDABOT_SIGNOFF = "Signed-off-by: dependabot[bot] <support@github.com>"


def workflow_script() -> str:
    lines = (ROOT / ".github" / "workflows" / "dco.yml").read_text(
        encoding="utf-8"
    ).splitlines()
    marker = "      - name: Verify every proposed commit has a DCO trailer"
    try:
        step = lines.index(marker)
        run = lines.index("        run: |", step)
    except ValueError as error:
        raise AssertionError("DCO workflow gate script is missing") from error
    body: list[str] = []
    for line in lines[run + 1 :]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:] if line else line)
    script = textwrap.dedent("\n".join(body)).strip()
    if not script:
        raise AssertionError("DCO workflow gate script is empty")
    return script


class DCOWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Test Committer")
        self.git("config", "user.email", "committer@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("commit", "--quiet", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "HOME": str(self.home),
            }
        )
        return environment

    def git(self, *arguments: str, environment: dict[str, str] | None = None):
        completed = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env=environment or self.environment(),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        return completed

    def commit(self, author_name: str, author_email: str, message: str) -> str:
        environment = self.environment()
        environment.update(
            {"GIT_AUTHOR_NAME": author_name, "GIT_AUTHOR_EMAIL": author_email}
        )
        self.git(
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            message,
            environment=environment,
        )
        return self.git("rev-parse", "HEAD").stdout.strip()

    def run_gate(self, head: str, pr_author: str) -> subprocess.CompletedProcess[str]:
        environment = self.environment()
        environment.update(
            {
                "BASE_SHA": self.base,
                "HEAD_SHA": head,
                "PR_AUTHOR": pr_author,
                "RUNNER_TEMP": str(self.runner_temp),
            }
        )
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", workflow_script()],
            cwd=self.repository,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )

    def test_reference_human_exact_author_trailer_passes(self) -> None:
        head = self.commit(
            "Alice Example",
            "alice@example.invalid",
            "change\n\nSigned-off-by: Alice Example <alice@example.invalid>",
        )
        completed = self.run_gate(head, "alice")
        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_canonical_dependabot_pr_and_trailer_pass(self) -> None:
        head = self.commit(
            DEPENDABOT_AUTHOR_NAME, DEPENDABOT_AUTHOR_EMAIL, f"update\n\n{DEPENDABOT_SIGNOFF}"
        )
        completed = self.run_gate(head, "dependabot[bot]")
        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_spoofed_dependabot_commit_author_fails(self) -> None:
        head = self.commit(
            DEPENDABOT_AUTHOR_NAME,
            "attacker@example.invalid",
            f"update\n\n{DEPENDABOT_SIGNOFF}",
        )
        completed = self.run_gate(head, "dependabot[bot]")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)

    def test_spoofed_dependabot_pr_author_fails(self) -> None:
        head = self.commit(
            DEPENDABOT_AUTHOR_NAME, DEPENDABOT_AUTHOR_EMAIL, f"update\n\n{DEPENDABOT_SIGNOFF}"
        )
        completed = self.run_gate(head, "attacker")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)

    def test_dependabot_missing_canonical_trailer_fails(self) -> None:
        head = self.commit(DEPENDABOT_AUTHOR_NAME, DEPENDABOT_AUTHOR_EMAIL, "update")
        completed = self.run_gate(head, "dependabot[bot]")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)


if __name__ == "__main__":
    unittest.main()
