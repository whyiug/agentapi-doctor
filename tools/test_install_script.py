"""Offline tests for the user-facing POSIX release installer."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
VERSION = "0.1.0"


class InstallScriptTests(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        subprocess.run(["sh", "-n", str(INSTALLER)], check=True)

    def test_installs_verified_linux_archive_without_network(self) -> None:
        completed, installed, executable, _ = self._run_installer()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(installed)
        self.assertTrue(executable)
        self.assertIn(f"Installed AgentAPI Doctor {VERSION}", completed.stdout)
        self.assertIn(f"doctor {VERSION}", completed.stdout)

    def test_default_version_is_the_stable_release(self) -> None:
        completed, installed, _, _ = self._run_installer(set_version=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(installed)
        self.assertIn(f"Installed AgentAPI Doctor {VERSION}", completed.stdout)

    def test_rejects_checksum_mismatch_without_installing(self) -> None:
        completed, installed, _, _ = self._run_installer(valid_checksum=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("archive checksum mismatch", completed.stderr)

    def test_darwin_uses_shasum_when_sha256sum_is_unavailable(self) -> None:
        completed, installed, executable, shasum_called = self._run_installer(
            system="Darwin", machine="arm64", shasum_only=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(installed)
        self.assertTrue(executable)
        self.assertTrue(shasum_called)

    def test_requires_https_release_base(self) -> None:
        environment = os.environ.copy()
        environment["AGENTAPI_DOCTOR_RELEASE_BASE"] = "http://example.invalid/release"
        completed = subprocess.run(
            ["/bin/sh", str(INSTALLER)],
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("release base must use HTTPS", completed.stderr)

    def _run_installer(
        self,
        *,
        system: str = "Linux",
        machine: str = "x86_64",
        valid_checksum: bool = True,
        shasum_only: bool = False,
        set_version: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], bool, bool, bool]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release"
            mock_bin = root / "mock-bin"
            destination = root / "bin"
            marker = root / "shasum-called"
            release.mkdir()
            mock_bin.mkdir()

            operating_system = "darwin" if system == "Darwin" else "linux"
            architecture = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
            asset = (
                f"agentapi-doctor_{VERSION}_{operating_system}_{architecture}.tar.gz"
            )
            archive = release / asset
            binary = f"#!/bin/sh\nprintf 'doctor {VERSION} (test, built test)\\n'\n".encode()
            info = tarfile.TarInfo("doctor")
            info.mode = 0o755
            info.size = len(binary)
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.addfile(info, io.BytesIO(binary))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if not valid_checksum:
                digest = "0" * 64
            (release / "checksums.txt").write_text(
                f"{digest}  {asset}\n", encoding="utf-8"
            )

            self._write_executable(
                mock_bin / "uname",
                f"#!/bin/sh\n[ \"${{1:-}}\" = -s ] && echo {system} || echo {machine}\n",
            )
            self._write_executable(
                mock_bin / "curl",
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    set -eu
                    output=
                    url=
                    while [ "$#" -gt 0 ]; do
                      case "$1" in
                        --output) output=$2; shift 2 ;;
                        http*) url=$1; shift ;;
                        *) shift ;;
                      esac
                    done
                    cp "$FAKE_RELEASE_DIR/${url##*/}" "$output"
                    """
                ),
            )

            path = f"{mock_bin}:{os.environ['PATH']}"
            if shasum_only:
                for command in (
                    "awk",
                    "cp",
                    "gzip",
                    "install",
                    "mkdir",
                    "mktemp",
                    "rm",
                    "tar",
                ):
                    source = shutil.which(command)
                    if source is None:
                        self.fail(f"test host is missing required command: {command}")
                    (mock_bin / command).symlink_to(source)
                shasum = shutil.which("shasum")
                if shasum is None:
                    self.fail("test host is missing shasum")
                self._write_executable(
                    mock_bin / "shasum",
                    f'#!/bin/sh\nprintf called > "$SHASUM_MARKER"\nexec "{shasum}" "$@"\n',
                )
                path = str(mock_bin)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": path,
                    "FAKE_RELEASE_DIR": str(release),
                    "SHASUM_MARKER": str(marker),
                    "AGENTAPI_DOCTOR_INSTALL_DIR": str(destination),
                    "AGENTAPI_DOCTOR_RELEASE_BASE": "https://example.invalid/release",
                }
            )
            if set_version:
                environment["AGENTAPI_DOCTOR_VERSION"] = VERSION
            else:
                environment.pop("AGENTAPI_DOCTOR_VERSION", None)
            completed = subprocess.run(
                ["/bin/sh", str(INSTALLER)],
                capture_output=True,
                text=True,
                env=environment,
            )
            installed = destination / "doctor"
            return (
                completed,
                installed.is_file(),
                installed.is_file() and bool(installed.stat().st_mode & stat.S_IXUSR),
                marker.is_file(),
            )

    @staticmethod
    def _write_executable(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
