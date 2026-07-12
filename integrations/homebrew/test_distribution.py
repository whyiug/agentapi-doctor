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


validation = load_module("homebrew_validate", "validate.py")
sys.modules["validate"] = validation
generator = load_module("homebrew_generate", "generate.py")


class HomebrewDistributionTests(unittest.TestCase):
    version = "0.0.0-rc.1"

    def checksum_bytes(self, *, omit: str | None = None) -> bytes:
        lines = []
        for index, (target, template) in enumerate(validation.TARGETS.items(), start=1):
            if target == omit:
                continue
            filename = template.format(version=self.version)
            lines.append(f"{index:064x}  {filename}")
        return ("\n".join(lines) + "\n").encode()

    def test_candidate_schema_and_null_placeholders(self) -> None:
        candidate = validation.load_json(DIRECTORY / "candidate.json")
        validation.validate_candidate(candidate)
        self.assertEqual(candidate["status"], "candidate-unpublished")
        self.assertIsNone(candidate["version"])
        self.assertTrue(all(value["sha256"] is None for value in candidate["artifacts"].values()))
        schema = json.loads((DIRECTORY / "candidate.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["status"]["const"], "candidate-unpublished")
        self.assertEqual(schema["properties"]["version"]["type"], "null")

    def test_generator_renders_only_exact_urls_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksums = root / "checksums.txt"
            checksums.write_bytes(self.checksum_bytes())
            output = root / "output"
            output.mkdir()
            formula = generator.generate(self.version, checksums, output)
            validation.validate_rendered_formula(formula, self.version, checksums)
            rendered = formula.read_text(encoding="utf-8")
            self.assertNotIn("{{", rendered)
            self.assertNotIn("latest", rendered.lower())
            self.assertEqual(rendered.count("sha256 \""), 4)

    def test_generator_rejects_missing_checksum_floating_version_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksums = root / "checksums.txt"
            checksums.write_bytes(self.checksum_bytes(omit="linux-arm64"))
            output = root / "output"
            output.mkdir()
            with self.assertRaises(validation.ValidationError):
                generator.generate(self.version, checksums, output)
            checksums.write_bytes(self.checksum_bytes())
            with self.assertRaises(validation.ValidationError):
                generator.generate("latest", checksums, output)
            (output / generator.OUTPUT_NAME).write_text("do not overwrite", encoding="utf-8")
            with self.assertRaises(validation.ValidationError):
                generator.generate(self.version, checksums, output)

    def test_checksum_and_candidate_parsers_reject_traversal_duplicates_and_symlinks(self) -> None:
        digest = "a" * 64
        for raw in (
            f"{digest}  ../escape.tar.gz\n".encode(),
            f"{digest}  safe.tar.gz\n{digest}  safe.tar.gz\n".encode(),
        ):
            with self.subTest(raw=raw), self.assertRaises(validation.ValidationError):
                validation.parse_checksums(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"status":"candidate-unpublished","status":"published"}', encoding="utf-8")
            with self.assertRaises(validation.ValidationError):
                validation.load_json(duplicate)
            target = root / "checksums.txt"
            target.write_bytes(self.checksum_bytes())
            link = root / "linked.txt"
            link.symlink_to(target)
            with self.assertRaises(validation.ValidationError):
                validation.read_regular(link, validation.MAX_CHECKSUM_BYTES)

    def test_template_unknown_token_fails_closed(self) -> None:
        with self.assertRaises(validation.ValidationError):
            generator.render_template("{{VERSION}} {{UNREVIEWED}}", {"VERSION": self.version})


if __name__ == "__main__":
    unittest.main()
