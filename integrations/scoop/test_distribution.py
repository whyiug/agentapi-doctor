#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


DIRECTORY = Path(__file__).parent


def load_module(name: str, filename: str):  # noqa: ANN001
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation = load_module("scoop_validate", "validate.py")
sys.modules["validate"] = validation
generator = load_module("scoop_generate", "generate.py")


class ScoopDistributionTests(unittest.TestCase):
    version = "0.0.0-rc.1"

    def checksum_bytes(self, *, omit: str | None = None) -> bytes:
        lines = []
        for index, (target, template) in enumerate(validation.TARGETS.items(), start=8):
            if target != omit:
                lines.append(f"{index:064x}  {template.format(version=self.version)}")
        return ("\n".join(lines) + "\n").encode()

    def test_candidate_has_only_null_release_placeholders(self) -> None:
        candidate = validation.load_json(DIRECTORY / "candidate.json")
        validation.validate_candidate(candidate)
        self.assertEqual(candidate["status"], "candidate-unpublished")
        self.assertIsNone(candidate["version"])
        self.assertTrue(all(value["sha256"] is None for value in candidate["artifacts"].values()))
        schema = json.loads((DIRECTORY / "candidate.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["version"]["type"], "null")
        self.assertEqual(
            schema["$defs"]["windowsAmd64"]["allOf"][1]["properties"]["archiveTemplate"]["const"],
            "agentapi-doctor_{version}_windows_amd64.zip",
        )
        self.assertEqual(
            schema["$defs"]["windowsArm64"]["allOf"][1]["properties"]["archiveTemplate"]["const"],
            "agentapi-doctor_{version}_windows_arm64.zip",
        )

    def test_windows_archives_are_zip_and_reject_tarball_mutant(self) -> None:
        candidate = validation.load_json(DIRECTORY / "candidate.json")
        self.assertTrue(
            all(value["archiveTemplate"].endswith(".zip") for value in candidate["artifacts"].values())
        )
        mutant = json.loads(json.dumps(candidate))
        mutant["artifacts"]["windows-amd64"]["archiveTemplate"] = (
            "agentapi-doctor_{version}_windows_amd64.tar.gz"
        )
        with self.assertRaises(validation.ValidationError):
            validation.validate_candidate(mutant)
        with self.assertRaises(validation.ValidationError):
            validation.release_url(
                self.version,
                f"agentapi-doctor_{self.version}_windows_amd64.tar.gz",
            )

    def test_generator_emits_exact_architecture_urls_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksums = root / "checksums.txt"
            checksums.write_bytes(self.checksum_bytes())
            output = root / "output"
            output.mkdir()
            manifest = generator.generate(self.version, checksums, output)
            validation.validate_rendered_manifest(manifest, self.version, checksums)
            document = validation.load_json(manifest)
            self.assertEqual(set(document["architecture"]), {"64bit", "arm64"})
            self.assertNotIn("autoupdate", document)
            self.assertNotIn("checkver", document)

    def test_generator_rejects_missing_checksum_floating_version_and_output_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            checksums = root / "checksums.txt"
            checksums.write_bytes(self.checksum_bytes(omit="windows-arm64"))
            output = root / "output"
            output.mkdir()
            with self.assertRaises(validation.ValidationError):
                generator.generate(self.version, checksums, output)
            checksums.write_bytes(self.checksum_bytes())
            with self.assertRaises(validation.ValidationError):
                generator.generate("latest", checksums, output)
            linked = root / "linked-output"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(validation.ValidationError):
                generator.generate(self.version, checksums, linked)

    def test_parsers_reject_traversal_duplicate_and_oversized_files(self) -> None:
        digest = "b" * 64
        for raw in (
            f"{digest}  ../escape.tar.gz\n".encode(),
            f"{digest}  same.tar.gz\n{digest}  same.tar.gz\n".encode(),
        ):
            with self.subTest(raw=raw), self.assertRaises(validation.ValidationError):
                validation.parse_checksums(raw)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b"x" * (validation.MAX_JSON_BYTES + 1))
            with self.assertRaises(validation.ValidationError):
                validation.load_json(path)

    def test_template_unknown_token_fails_closed(self) -> None:
        with self.assertRaises(validation.ValidationError):
            generator.render_template('{"version":"{{VERSION}}","x":"{{UNKNOWN}}"}', {"VERSION": self.version})


if __name__ == "__main__":
    unittest.main()
