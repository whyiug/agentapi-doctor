from __future__ import annotations

import io
from pathlib import Path
from unittest import mock
import tarfile
import tempfile
import unittest

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
            "agentapi-doctor_registry_1.2.3_linux_amd64.tar.gz": digest,
            "agentapi-doctor_reference-server_1.2.3_linux_amd64.tar.gz": digest,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                release_smoke, "platform_tokens", return_value=("linux", "amd64")
            ),
        ):
            selected = release_smoke.choose_archive(Path(temporary), checksums, "1.2.3")
            self.assertEqual(selected.name, "agentapi-doctor_1.2.3_linux_amd64.tar.gz")
            for component, expected in {
                "doctor": "agentapi-doctor_1.2.3_linux_amd64.tar.gz",
                "registry": "agentapi-doctor_registry_1.2.3_linux_amd64.tar.gz",
                "reference-server": "agentapi-doctor_reference-server_1.2.3_linux_amd64.tar.gz",
            }.items():
                self.assertEqual(
                    release_smoke.choose_component_archive(
                        Path(temporary), checksums, "1.2.3", component
                    ).name,
                    expected,
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


if __name__ == "__main__":
    unittest.main()
