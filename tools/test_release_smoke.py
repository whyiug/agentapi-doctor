from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
from unittest import mock
import tarfile
import tempfile
import unittest
import zipfile

import release_smoke


class ReleaseSmokeSafetyTests(unittest.TestCase):
    def archive(self, root: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
        path = root / "bundle.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for metadata, payload in members:
                metadata.size = len(payload)
                archive.addfile(metadata, io.BytesIO(payload))
        return path

    def test_safe_extract_accepts_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = tarfile.TarInfo("doctor")
            metadata.mode = 0o755
            archive = self.archive(root, [(metadata, b"synthetic-binary")])
            destination = root / "output"
            destination.mkdir()
            release_smoke.safe_extract(archive, destination)
            self.assertEqual((destination / "doctor").read_bytes(), b"synthetic-binary")

    def test_safe_extract_accepts_windows_zip_and_rejects_zip_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bundle.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("doctor.exe", b"synthetic-binary")
            destination = root / "output"
            destination.mkdir()
            release_smoke.safe_extract(archive, destination)
            self.assertEqual(
                (destination / "doctor.exe").read_bytes(), b"synthetic-binary"
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bundle.zip"
            link = zipfile.ZipInfo("doctor.exe")
            link.create_system = 3
            link.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(link, b"target")
            destination = root / "output"
            destination.mkdir()
            with self.assertRaises(ValueError):
                release_smoke.safe_extract(archive, destination)

    def test_safe_extract_rejects_links_traversal_and_special_files(self) -> None:
        cases: list[tarfile.TarInfo] = []
        traversal = tarfile.TarInfo("../escape")
        cases.append(traversal)
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "doctor"
        cases.append(link)
        device = tarfile.TarInfo("device")
        device.type = tarfile.CHRTYPE
        cases.append(device)
        for index, metadata in enumerate(cases):
            with (
                self.subTest(metadata=metadata.name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                archive = self.archive(root, [(metadata, b"")])
                destination = root / f"output-{index}"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    release_smoke.safe_extract(archive, destination)

    def test_checksum_parser_rejects_unsafe_and_duplicate_names(self) -> None:
        digest = "a" * 64
        for text in (
            f"{digest}  ../escape.tar.gz\n",
            f"{digest}  same.tar.gz\n{digest}  same.tar.gz\n",
            f"{digest} same.tar.gz\n",
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "checksums.txt"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    release_smoke.parse_checksums(path)

    def test_archive_selection_is_bound_to_exact_version(self) -> None:
        digest = "a" * 64
        checksums = {
            "agentapi-doctor_1.2.3_linux_amd64.tar.gz": digest,
            "agentapi-doctor_v1.2.3_linux_amd64.tar.gz": digest,
            "agentapi-doctor_9.9.9_linux_amd64.tar.gz": digest,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                release_smoke, "platform_tokens", return_value=("linux", "amd64")
            ),
        ):
            selected = release_smoke.choose_archive(Path(temporary), checksums, "1.2.3")
            self.assertEqual(selected.name, "agentapi-doctor_1.2.3_linux_amd64.tar.gz")

    def test_windows_archive_selection_uses_zip(self) -> None:
        digest = "a" * 64
        checksums = {"agentapi-doctor_1.2.3_windows_arm64.zip": digest}
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                release_smoke, "platform_tokens", return_value=("windows", "arm64")
            ),
        ):
            selected = release_smoke.choose_archive(
                Path(temporary), checksums, "1.2.3"
            )
            self.assertEqual(
                selected.name, "agentapi-doctor_1.2.3_windows_arm64.zip"
            )

    def test_archive_selection_rejects_prefixed_or_missing_version(self) -> None:
        digest = "a" * 64
        checksums = {
            "agentapi-doctor_v1.2.3_linux_amd64.tar.gz": digest,
            "agentapi-doctor_9.9.9_linux_amd64.tar.gz": digest,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                release_smoke, "platform_tokens", return_value=("linux", "amd64")
            ),
        ):
            with self.assertRaises(ValueError):
                release_smoke.choose_archive(Path(temporary), checksums, "1.2.3")
            with self.assertRaises(ValueError):
                release_smoke.choose_archive(Path(temporary), checksums, "v1.2.3")

    @unittest.skipIf(os.name == "nt", "synthetic POSIX executable fixture")
    def test_smoke_runs_exact_version_and_interpretable_demo(self) -> None:
        version = "1.2.3-rc.4"
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = f"""#!/bin/sh
case "$1" in
  version)
    printf '%s\\n' '{json.dumps({"status": "pass", "data": {"version": version, "commit": commit}})}'
    ;;
  demo)
    printf '%s\\n' \\
      'Result: CHECKS PASSED' \\
      'Cases: 4 candidate / 4 applicable / 4 executed' \\
      'Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0' \\
      'candidate_interpretations_pending_review'
    ;;
  *) exit 2 ;;
esac
"""
            archive = root / f"agentapi-doctor_{version}_linux_amd64.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, payload, mode in (
                    ("doctor", script.encode(), 0o755),
                    ("LICENSE", b"license", 0o644),
                    ("NOTICE", b"notice", 0o644),
                    ("THIRD_PARTY_LICENSES.txt", b"third party", 0o644),
                ):
                    metadata = tarfile.TarInfo(name)
                    metadata.mode = mode
                    metadata.size = len(payload)
                    bundle.addfile(metadata, io.BytesIO(payload))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / "checksums.txt").write_text(
                f"{digest}  {archive.name}\n", encoding="utf-8"
            )
            with mock.patch.object(
                release_smoke, "platform_tokens", return_value=("linux", "amd64")
            ):
                elapsed = release_smoke.smoke(
                    root, version, commit, maximum_seconds=10
                )
            self.assertGreaterEqual(elapsed, 0)


if __name__ == "__main__":
    unittest.main()
