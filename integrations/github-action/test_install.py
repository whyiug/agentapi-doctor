#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import urllib.request

import install


class InstallerTests(unittest.TestCase):
    def test_versions_are_exact_and_never_floating(self) -> None:
        for value in ("0.1.0", "1.2.3", "2.0.0-rc.4"):
            self.assertEqual(install.validate_version(value), value)
        for value in ("latest", "v1.2.3", "1.2", "1.2.x", "main", "1.2.3/../x", ""):
            with self.subTest(value=value), self.assertRaises(install.InstallError):
                install.validate_version(value)

    def test_platform_mapping_is_closed(self) -> None:
        self.assertEqual(install.platform_identity("Linux", "x86_64"), ("linux", "amd64"))
        self.assertEqual(install.platform_identity("Darwin", "arm64"), ("darwin", "arm64"))
        self.assertEqual(install.platform_identity("Windows", "AMD64"), ("windows", "amd64"))
        with self.assertRaises(install.InstallError):
            install.platform_identity("FreeBSD", "amd64")
        with self.assertRaises(install.InstallError):
            install.platform_identity("Linux", "riscv64")

    def test_checksum_manifest_rejects_traversal_duplicates_and_floating_names(self) -> None:
        digest = "a" * 64
        parsed = install.parse_checksums(f"{digest}  safe.tar.gz\n".encode())
        self.assertEqual(parsed, {"safe.tar.gz": digest})
        for raw in (
            f"{digest}  ../escape.tar.gz\n",
            f"{digest}  nested/escape.tar.gz\n",
            f"{digest}  safe.tar.gz\n{digest}  safe.tar.gz\n",
            f"{digest.upper()}  safe.tar.gz\n",
            b"not-a-checksum\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(install.InstallError):
                install.parse_checksums(raw if isinstance(raw, bytes) else raw.encode())

    def test_redirects_reject_downgrade_unknown_hosts_and_excess_hops(self) -> None:
        handler = install.ValidatedRedirectHandler()
        request = urllib.request.Request("https://github.com/whyiug/agentapi-doctor/releases/download/v1.2.3/a")
        for location in ("http://github.com/file", "https://example.com/file", "https://user@github.com/file"):
            with self.subTest(location=location), self.assertRaises(install.InstallError):
                handler.redirect_request(request, None, 302, "Found", {}, location)
        setattr(request, "_agentapi_redirect_count", install.MAX_REDIRECTS)
        with self.assertRaises(install.InstallError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://release-assets.githubusercontent.com/file?bounded=signed-query",
            )

    def test_bounded_copy_removes_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "bounded.bin"
            with self.assertRaises(install.InstallError):
                install._copy_bounded(io.BytesIO(b"x" * 11), destination, 10)
            self.assertFalse(destination.exists())

    def test_archive_rejects_parent_paths_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("traversal", "symlink"):
                archive = root / f"{kind}.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    member = tarfile.TarInfo("../doctor" if kind == "traversal" else "doctor")
                    if kind == "symlink":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/bin/true"
                        bundle.addfile(member)
                    else:
                        payload = b"binary"
                        member.size = len(payload)
                        bundle.addfile(member, io.BytesIO(payload))
                with self.subTest(kind=kind), self.assertRaises(install.InstallError):
                    install.extract_doctor(archive, root / f"out-{kind}", "linux")

    def test_offline_install_pipeline_verifies_signature_checksum_and_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = "0.0.0-rc.1"
            archive_name = install.artifact_name(version, "linux", "amd64")
            source_archive = root / "source.tar.gz"
            with tarfile.open(source_archive, "w:gz") as bundle:
                payload = b"synthetic doctor executable\n"
                member = tarfile.TarInfo("doctor")
                member.mode = 0o755
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
                readme = b"synthetic fixture\n"
                member = tarfile.TarInfo("README.md")
                member.size = len(readme)
                bundle.addfile(member, io.BytesIO(readme))
            archive_digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
            sources = {
                install.CHECKSUM_NAME: f"{archive_digest}  {archive_name}\n".encode(),
                install.BUNDLE_NAME: b'{"synthetic":true}',
                archive_name: source_archive.read_bytes(),
            }

            def downloader(url: str, destination: Path, maximum: int) -> None:
                name = url.rsplit("/", 1)[-1]
                data = sources[name]
                self.assertLessEqual(len(data), maximum)
                destination.write_bytes(data)

            cosign = root / "cosign-fixture"
            cosign.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            cosign.chmod(0o755)
            observed_commands: list[list[str]] = []

            def runner(command, **kwargs):  # noqa: ANN001
                observed_commands.append(command)
                self.assertFalse(kwargs.get("check"))
                self.assertIn("--certificate-identity", command)
                self.assertIn("--certificate-oidc-issuer", command)
                return SimpleNamespace(returncode=0)

            result = install.install_release(
                version,
                root,
                str(cosign),
                system="Linux",
                machine="x86_64",
                downloader=downloader,
                command_runner=runner,
            )
            binary = Path(result["doctor-path"])
            self.assertEqual(binary.read_bytes(), b"synthetic doctor executable\n")
            self.assertEqual(result["artifact-name"], archive_name)
            self.assertEqual(result["artifact-sha256"], archive_digest)
            self.assertEqual(len(observed_commands), 1)

    def test_sigstore_verification_failure_is_not_downgraded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksums = root / install.CHECKSUM_NAME
            checksums.write_text(f"{'a' * 64}  synthetic.tar.gz\n", encoding="utf-8")
            bundle = root / install.BUNDLE_NAME
            bundle.write_text('{"synthetic":true}', encoding="utf-8")
            cosign = root / "cosign-fixture"
            cosign.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            cosign.chmod(0o755)

            def failed_runner(command, **kwargs):  # noqa: ANN001
                return SimpleNamespace(returncode=1)

            with self.assertRaises(install.InstallError):
                install.verify_sigstore(
                    checksums,
                    bundle,
                    "1.2.3",
                    str(cosign),
                    runner=failed_runner,
                )

    def test_installation_parent_symlink_is_rejected_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "agentapi-doctor").symlink_to(outside, target_is_directory=True)

            def should_not_download(url: str, destination: Path, maximum: int) -> None:
                self.fail(f"unexpected download {url} -> {destination} ({maximum})")

            with self.assertRaises(install.InstallError):
                install.install_release(
                    "1.2.3",
                    root,
                    "cosign",
                    system="Linux",
                    machine="amd64",
                    downloader=should_not_download,
                )

    def test_action_metadata_has_no_floating_or_pipe_to_shell_install(self) -> None:
        action_path = Path(__file__).with_name("action.yml")
        action = action_path.read_text(encoding="utf-8")
        lowered = action.lower()
        self.assertIn("required: true", action)
        self.assertIn("install.py", action)
        self.assertNotIn("latest", lowered)
        self.assertNotIn("curl", lowered)
        self.assertNotIn("wget", lowered)
        self.assertNotRegex(lowered, r"\|\s*(?:ba)?sh")
        self.assertNotIn("secrets.", lowered)

    def test_candidate_metadata_does_not_claim_a_release(self) -> None:
        candidate = json.loads(Path(__file__).with_name("candidate.json").read_text(encoding="utf-8"))
        self.assertEqual(candidate["status"], "candidate-unpublished")
        self.assertIsNone(candidate["releaseVersion"])
        self.assertIsNone(candidate["actionCommit"])
        self.assertEqual(candidate["verification"]["publishedEvidence"], [])


if __name__ == "__main__":
    unittest.main()
