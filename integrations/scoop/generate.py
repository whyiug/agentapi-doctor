#!/usr/bin/env python3
"""Render a Scoop manifest only from an exact version and local checksums."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping, Sequence

import validate


OUTPUT_NAME = "agentapi-doctor.json"
TOKEN_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def render_template(template: str, values: Mapping[str, str]) -> str:
    observed = set(TOKEN_RE.findall(template))
    if observed != set(values):
        raise validate.ValidationError("Scoop template has missing or unknown tokens")
    rendered = TOKEN_RE.sub(lambda match: values[match.group(1)], template)
    if "{{" in rendered or "}}" in rendered:
        raise validate.ValidationError("Scoop template left unresolved tokens")
    try:
        json.loads(rendered, object_pairs_hook=validate._pairs)
    except json.JSONDecodeError as error:
        raise validate.ValidationError("rendered Scoop template is not strict JSON") from error
    return rendered


def safe_output_directory(path: Path) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise validate.ValidationError("output directory must already exist") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise validate.ValidationError("output directory must be a real non-symlink directory")
    return resolved


def write_exclusive(path: Path, content: str) -> None:
    if path.name != OUTPUT_NAME or path.exists() or path.is_symlink():
        raise validate.ValidationError("generator refuses an existing or unexpected output path")
    encoded = content.encode("utf-8")
    if not encoded or len(encoded) > validate.MAX_JSON_BYTES:
        raise validate.ValidationError("rendered Scoop manifest violates its byte limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


def generate(version: str, checksums_path: Path, output_directory: Path) -> Path:
    version = validate.validate_version(version)
    validate.validate_candidate(validate.load_json(Path(__file__).with_name("candidate.json")))
    checksums = validate.required_checksums(version, checksums_path)
    try:
        template = validate.read_regular(Path(__file__).with_name("agentapi-doctor.json.tmpl"), validate.MAX_JSON_BYTES).decode("utf-8")
    except UnicodeDecodeError as error:
        raise validate.ValidationError("Scoop template must be UTF-8") from error
    values: dict[str, str] = {"VERSION": version}
    for target, archive_template in validate.TARGETS.items():
        filename = archive_template.format(version=version)
        token = target.replace("-", "_").upper()
        values[f"{token}_URL"] = validate.release_url(version, filename)
        values[f"{token}_SHA256"] = checksums[target]
    rendered = render_template(template, values)
    destination = safe_output_directory(output_directory) / OUTPUT_NAME
    write_exclusive(destination, rendered)
    validate.validate_rendered_manifest(destination, version, checksums_path)
    return destination


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        destination = generate(arguments.version, arguments.checksums, arguments.output_dir)
    except validate.ValidationError as error:
        print(f"scoop generator: {error}", file=sys.stderr)
        return 2
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
