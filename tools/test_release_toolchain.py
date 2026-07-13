"""Offline reference-pass and old-toolchain-mutant tests for release metadata."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile

import check_release_toolchain as check


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.2.3"
GO_VERSION = "1.26.5"


class ReleaseToolchainTests(unittest.TestCase):
    def test_repository_has_one_go_1265_authority_and_release_gate(self) -> None:
        self.assertEqual(check.canonical_go_version(ROOT / "go.mod"), GO_VERSION)
        check.check_docker_version(ROOT / "Dockerfile", GO_VERSION)
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("golang.org/x/vuln/cmd/govulncheck@v1.5.0", workflow)
        self.assertIn("python3 tools/check_release_toolchain.py", workflow)
        self.assertIn('--govulncheck-command "$GOVULNCHECK"', workflow)
        self.assertLess(
            workflow.index("Generate one SPDX release SBOM"),
            workflow.index("Verify archived toolchains, SBOM, and Linux binary vulnerabilities"),
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        (self.root / "go.mod").write_text(
            "module example.invalid/doctor\n\ngo 1.26.5\n", encoding="utf-8"
        )
        (self.root / "Dockerfile").write_text(
            "FROM golang:1.26.5-alpine3.23@sha256:"
            + "a" * 64
            + " AS build\n",
            encoding="utf-8",
        )
        self.go_command = self._command(
            "fake-go",
            """
            import pathlib
            import re
            import sys
            if sys.argv[1:3] != ["version", "-m"]:
                raise SystemExit(2)
            payload = pathlib.Path(sys.argv[3]).read_text(encoding="ascii")
            match = re.fullmatch(r"toolchain=(go[0-9]+[.][0-9]+[.][0-9]+)", payload)
            if match is None:
                raise SystemExit(2)
            print(f"{sys.argv[3]}: {match.group(1)}")
            print("\tpath\tgithub.com/whyiug/agentapi-doctor/cmd/doctor")
            """,
        )
        self.govulncheck_log = self.root / "govulncheck.log"
        self.govulncheck_command = self._command(
            "fake-govulncheck",
            """
            import os
            import pathlib
            import sys
            if len(sys.argv) != 3 or sys.argv[1] != "-mode=binary":
                raise SystemExit(2)
            pathlib.Path(os.environ["FAKE_GOVULNCHECK_LOG"]).write_text(
                " ".join(sys.argv[1:]) + "\\n", encoding="utf-8"
            )
            """,
        )

    def _command(self, name: str, body: str) -> str:
        path = self.root / name
        path.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent(body).lstrip(), encoding="utf-8"
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def _write_archives(self, toolchain: str) -> None:
        payload = f"toolchain=go{toolchain}".encode("ascii")
        for operating_system, architecture, extension, member_name in check.TARGETS:
            path = self.dist / (
                f"agentapi-doctor_{VERSION}_{operating_system}_{architecture}.{extension}"
            )
            if extension == "zip":
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(member_name, payload)
            else:
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(member_name)
                    member.mode = 0o755
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))

    def _write_sbom(self, toolchain: str = GO_VERSION) -> None:
        document = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "stdlib", "versionInfo": f"go{toolchain}"}
                for _ in check.TARGETS
            ],
        }
        (self.dist / "agentapi-doctor.spdx.json").write_text(
            json.dumps(document), encoding="utf-8"
        )

    def test_reference_release_passes_and_scans_one_linux_binary(self) -> None:
        self._write_archives(GO_VERSION)
        self._write_sbom()
        with mock.patch.dict(
            os.environ, {"FAKE_GOVULNCHECK_LOG": str(self.govulncheck_log)}
        ):
            result = check.check_release(
                self.root,
                self.dist,
                VERSION,
                self.go_command,
                self.govulncheck_command,
            )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["go_version"], GO_VERSION)
        self.assertEqual(len(result["archives"]), 6)
        invocation = self.govulncheck_log.read_text(encoding="utf-8")
        self.assertIn("-mode=binary", invocation)
        self.assertIn("linux-amd64-doctor", invocation)

    def test_old_toolchain_archive_mutant_fails(self) -> None:
        self._write_archives("1.26.0")
        self._write_sbom()
        with self.assertRaisesRegex(
            check.CheckError, r"uses Go 1[.]26[.]0; expected Go 1[.]26[.]5"
        ):
            check.check_release(
                self.root,
                self.dist,
                VERSION,
                self.go_command,
                self.govulncheck_command,
            )

    def test_old_toolchain_sbom_mutant_fails(self) -> None:
        self._write_archives(GO_VERSION)
        self._write_sbom("1.26.0")
        with self.assertRaisesRegex(check.CheckError, "6 stdlib packages"):
            check.check_release(
                self.root,
                self.dist,
                VERSION,
                self.go_command,
                self.govulncheck_command,
            )


if __name__ == "__main__":
    unittest.main()
