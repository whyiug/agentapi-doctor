from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import release_assets


class ReleaseAssetManifestTests(unittest.TestCase):
    version = "1.2.3-rc.4"

    def populate(self, root: Path) -> None:
        checksummed = release_assets.checksummed_release_assets(self.version)
        for name in checksummed:
            (root / name).write_bytes(f"asset:{name}".encode())
        lines = [
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
            for name in sorted(checksummed)
        ]
        (root / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_builds_deterministic_exact_version_manifest(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            first = release_assets.build_manifest(root, self.version)
            second = release_assets.build_manifest(root, self.version)
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], release_assets.MANIFEST_SCHEMA)
            self.assertEqual(first["version"], self.version)
            names = [asset["name"] for asset in first["assets"]]
            self.assertEqual(
                names, sorted(release_assets.required_release_assets(self.version))
            )
            self.assertEqual(
                json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
            )

    def test_accepts_only_named_optional_release_assets(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            for name in release_assets.OPTIONAL_UNCHECKSUMMED_ASSETS:
                (root / name).write_text(f"optional:{name}\n", encoding="utf-8")
            for name in release_assets.OPTIONAL_CHECKSUMMED_ASSETS:
                asset = root / name
                asset.write_text(f"optional:{name}\n", encoding="utf-8")
                digest = hashlib.sha256(asset.read_bytes()).hexdigest()
                with (root / "checksums.txt").open("a", encoding="utf-8") as manifest:
                    manifest.write(f"{digest}  {name}\n")
            manifest = release_assets.build_manifest(root, self.version)
            kinds = {asset["name"]: asset["kind"] for asset in manifest["assets"]}
            for name, kind in release_assets.OPTIONAL_ASSETS.items():
                self.assertEqual(kinds[name], kind)

    def test_optional_oci_subjects_must_be_checksummed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            asset = root / "oci-images.json"
            asset.write_text('{"schema":"synthetic"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum asset set mismatch"):
                release_assets.build_manifest(root, self.version)

            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            with (root / "checksums.txt").open("a", encoding="utf-8") as manifest:
                manifest.write(f"{digest}  {asset.name}\n")
            release_assets.build_manifest(root, self.version)

    def test_image_sboms_are_optional_but_must_be_checksummed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            asset = root / "agentapi-doctor-image.spdx.json"
            asset.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum asset set mismatch"):
                release_assets.build_manifest(root, self.version)
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            with (root / "checksums.txt").open("a", encoding="utf-8") as manifest:
                manifest.write(f"{digest}  {asset.name}\n")
            release_assets.build_manifest(root, self.version)

    def test_required_sboms_and_package_manifests_are_checksummed(self) -> None:
        covered = release_assets.checksummed_release_assets(self.version)
        self.assertTrue(
            {
                "agentapi-doctor.cdx.json",
                "agentapi-doctor.spdx.json",
                "agentapi-doctor.json",
                "agentapi-doctor.rb",
            }
            <= covered
        )
        self.assertNotIn("checksums.txt", covered)
        self.assertTrue(
            set(release_assets.OPTIONAL_UNCHECKSUMMED_ASSETS).isdisjoint(covered)
        )

    def test_rejects_unknown_unsafe_missing_and_duplicate_names(self) -> None:
        cases = ("unknown.bin", "unsafe name", "AGENTAPI-DOCTOR.RB")
        for name in cases:
            with self.subTest(name=name), TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.populate(root)
                if name == "AGENTAPI-DOCTOR.RB":
                    (root / "agentapi-doctor.rb").write_bytes(b"one")
                (root / name).write_bytes(b"unexpected")
                with self.assertRaises(ValueError):
                    release_assets.build_manifest(root, self.version)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            missing = next(
                iter(release_assets.checksummed_release_assets(self.version))
            )
            (root / missing).unlink()
            with self.assertRaises(ValueError):
                release_assets.build_manifest(root, self.version)

    def test_stages_only_exact_allowlisted_regular_files(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "dist"
            staged = root / "release-dist"
            raw.mkdir()
            staged.mkdir()
            self.populate(raw)
            (raw / "artifacts.json").write_text("{}\n", encoding="utf-8")
            (raw / "doctor_linux_amd64").mkdir()
            (raw / "agentapi-doctor_9.9.9_linux_amd64.tar.gz").write_bytes(
                b"wrong-version"
            )
            release_assets.stage_release_assets(raw, staged, self.version)
            manifest = release_assets.build_manifest(staged, self.version)
            self.assertEqual(
                {asset["name"] for asset in manifest["assets"]},
                release_assets.required_release_assets(self.version),
            )
            self.assertFalse((staged / "artifacts.json").exists())
            self.assertFalse((staged / "doctor_linux_amd64").exists())

    def test_stage_requires_an_existing_empty_real_destination(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "dist"
            staged = root / "release-dist"
            raw.mkdir()
            staged.mkdir()
            self.populate(raw)
            (staged / "occupied").write_bytes(b"data")
            with self.assertRaises(ValueError):
                release_assets.stage_release_assets(raw, staged, self.version)
            with self.assertRaises(ValueError):
                release_assets.stage_release_assets(raw, root / "missing", self.version)

    def test_stage_rejects_selected_symlink_and_symlink_destination(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "dist"
            staged = root / "release-dist"
            raw.mkdir()
            staged.mkdir()
            self.populate(raw)
            selected = raw / "agentapi-doctor.rb"
            selected.unlink()
            try:
                os.symlink(raw / "checksums.txt", selected)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaises(ValueError):
                release_assets.stage_release_assets(raw, staged, self.version)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "dist"
            real_destination = root / "real-release-dist"
            linked_destination = root / "release-dist"
            raw.mkdir()
            real_destination.mkdir()
            self.populate(raw)
            try:
                os.symlink(
                    real_destination, linked_destination, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            with self.assertRaises(ValueError):
                release_assets.stage_release_assets(
                    raw, linked_destination, self.version
                )
            arguments = [
                "release_assets.py",
                "--stage-from",
                str(raw),
                "--directory",
                str(linked_destination),
                "--version",
                self.version,
                "--format",
                "lines",
            ]
            with mock.patch("sys.argv", arguments), self.assertRaises(ValueError):
                release_assets.main()

    def test_manifest_round_trip_and_lines_cli(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "dist"
            staged = root / "release-dist"
            raw.mkdir()
            staged.mkdir()
            self.populate(raw)
            manifest_path = root / "release-assets.json"
            output = io.StringIO()
            arguments = [
                "release_assets.py",
                "--stage-from",
                str(raw),
                "--directory",
                str(staged),
                "--version",
                self.version,
                "--format",
                "lines",
                "--write-manifest",
                str(manifest_path),
            ]
            with mock.patch("sys.argv", arguments), mock.patch("sys.stdout", output):
                self.assertEqual(release_assets.main(), 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(
                lines,
                [
                    str(staged / name)
                    for name in sorted(
                        release_assets.required_release_assets(self.version)
                    )
                ],
            )
            manifest = release_assets.build_manifest(staged, self.version)
            release_assets.verify_manifest(manifest_path, manifest)
            (
                staged
                / sorted(release_assets.checksummed_release_assets(self.version))[0]
            ).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                release_assets.verify_manifest(
                    manifest_path, release_assets.build_manifest(staged, self.version)
                )

    def test_lines_format_rejects_newline_in_directory(self) -> None:
        manifest = {"assets": [{"name": "checksums.txt"}]}
        with self.assertRaises(ValueError):
            release_assets.manifest_asset_paths(Path("bad\nroot"), manifest)

    def test_rejects_directories_and_symlinks(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            (root / "agentapi-doctor.rb").unlink()
            (root / "agentapi-doctor.rb").mkdir()
            with self.assertRaises(ValueError):
                release_assets.build_manifest(root, self.version)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            link = root / "agentapi-doctor.rb"
            link.unlink()
            try:
                os.symlink(root / "checksums.txt", link)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaises(ValueError):
                release_assets.build_manifest(root, self.version)

    def test_rejects_checksum_coverage_or_digest_drift(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            archive = (
                root
                / sorted(release_assets.checksummed_release_assets(self.version))[0]
            )
            archive.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                release_assets.build_manifest(root, self.version)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            checksums = root / "checksums.txt"
            checksums.write_text(
                checksums.read_text(encoding="utf-8") + f"{'a' * 64}  extra.tar.gz\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "checksum asset set mismatch"):
                release_assets.build_manifest(root, self.version)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            checksums = root / "checksums.txt"
            checksums.write_text(
                checksums.read_text(encoding="utf-8")
                + f"{'a' * 64}  checksums.txt.sigstore.json\n",
                encoding="utf-8",
            )
            (root / "checksums.txt.sigstore.json").write_bytes(b"signature")
            with self.assertRaisesRegex(ValueError, "checksum asset set mismatch"):
                release_assets.build_manifest(root, self.version)

    def test_rejects_v_prefix_and_other_version_archive(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            with self.assertRaises(ValueError):
                release_assets.build_manifest(root, f"v{self.version}")
            archive = f"agentapi-doctor_{self.version}_linux_amd64.tar.gz"
            wrong = archive.replace(self.version, "9.9.9")
            (root / archive).rename(root / wrong)
            with self.assertRaises(ValueError):
                release_assets.build_manifest(root, self.version)


if __name__ == "__main__":
    unittest.main()
