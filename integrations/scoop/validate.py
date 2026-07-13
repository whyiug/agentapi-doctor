#!/usr/bin/env python3
"""Offline validator for the unpublished Scoop candidate and rendered manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence


SCHEMA_VERSION = "urn:agentapi-doctor:scoop-distribution-candidate:v1"
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?$"
)
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})[ \t]+([A-Za-z0-9][A-Za-z0-9._-]{0,199})$")
MAX_JSON_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4 * 1024 * 1024
TARGETS = {
    "windows-amd64": "agentapi-doctor_{version}_windows_amd64.zip",
    "windows-arm64": "agentapi-doctor_{version}_windows_arm64.zip",
}
RELEASE_ROOT = "https://github.com/whyiug/agentapi-doctor/releases/download"


class ValidationError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def read_regular(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidationError(f"file is unavailable: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"file must be a regular non-symlink: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ValidationError(f"file violates its byte limit: {path.name}")
    raw = path.read_bytes()
    if len(raw) > maximum:
        raise ValidationError(f"file violates its byte limit: {path.name}")
    return raw


def load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(read_regular(path, maximum), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("manifest must be strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValidationError("manifest root must be an object")
    return value


def validate_candidate(document: dict[str, Any]) -> None:
    required = {
        "schemaVersion",
        "kind",
        "status",
        "package",
        "manifestTemplate",
        "version",
        "releaseTag",
        "artifacts",
        "verification",
        "publishedEvidence",
    }
    if set(document) != required:
        raise ValidationError("candidate has missing or unknown fields")
    if (
        document["schemaVersion"] != SCHEMA_VERSION
        or document["kind"] != "ScoopDistributionCandidate"
        or document["status"] != "candidate-unpublished"
        or document["package"] != "agentapi-doctor"
        or document["manifestTemplate"] != "integrations/scoop/agentapi-doctor.json.tmpl"
    ):
        raise ValidationError("candidate identity or status is invalid")
    if document["version"] is not None or document["releaseTag"] is not None or document["publishedEvidence"] != []:
        raise ValidationError("unpublished candidate must not claim release identity or evidence")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != set(TARGETS):
        raise ValidationError("candidate artifact target set is invalid")
    for target, template in TARGETS.items():
        value = artifacts[target]
        if (
            not isinstance(value, dict)
            or set(value) != {"archiveTemplate", "sha256"}
            or value["archiveTemplate"] != template
            or value["sha256"] is not None
        ):
            raise ValidationError(f"candidate artifact placeholder is invalid: {target}")
    if document["verification"] != {
        "checksumAlgorithm": "sha256",
        "checksumManifest": "checksums.txt",
        "sigstoreBundleRequired": True,
    }:
        raise ValidationError("candidate verification policy is invalid")


def validate_version(value: str) -> str:
    if VERSION_RE.fullmatch(value or "") is None:
        raise ValidationError("version must be an exact SemVer or SemVer-rc.N")
    return value


def parse_checksums(raw: bytes) -> dict[str, str]:
    if not raw or len(raw) > MAX_CHECKSUM_BYTES or b"\x00" in raw:
        raise ValidationError("checksum manifest is empty, oversized, or contains NUL")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValidationError("checksum manifest must be UTF-8") from error
    if not lines or len(lines) > 256:
        raise ValidationError("checksum manifest entry count is outside the bound")
    result: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise ValidationError("checksum manifest contains a malformed or unsafe entry")
        digest, filename = match.groups()
        if filename.startswith("-") or filename in {".", ".."} or filename in result:
            raise ValidationError("checksum manifest contains an unsafe or duplicate filename")
        result[filename] = digest
    return result


def required_checksums(version: str, path: Path) -> dict[str, str]:
    version = validate_version(version)
    manifest = parse_checksums(read_regular(path, MAX_CHECKSUM_BYTES))
    selected: dict[str, str] = {}
    for target, template in TARGETS.items():
        digest = manifest.get(template.format(version=version))
        if digest is None:
            raise ValidationError(f"checksum manifest is missing required artifact: {target}")
        selected[target] = digest
    return selected


def release_url(version: str, filename: str) -> str:
    validate_version(version)
    if not re.fullmatch(r"agentapi-doctor_[A-Za-z0-9._-]+_windows_(?:amd64|arm64)\.zip", filename):
        raise ValidationError("release filename is outside the Scoop target set")
    return f"{RELEASE_ROOT}/v{version}/{filename}"


def validate_rendered_manifest(path: Path, version: str, checksums_path: Path) -> None:
    version = validate_version(version)
    checksums = required_checksums(version, checksums_path)
    document = load_json(path)
    if set(document) != {"version", "description", "homepage", "license", "architecture", "bin"}:
        raise ValidationError("rendered Scoop manifest has missing or unknown fields")
    if document["version"] != version or document["bin"] != "doctor.exe" or document["license"] != "Apache-2.0":
        raise ValidationError("rendered Scoop package identity is invalid")
    if document["homepage"] != "https://github.com/whyiug/agentapi-doctor":
        raise ValidationError("rendered Scoop homepage is invalid")
    architectures = document["architecture"]
    if not isinstance(architectures, dict) or set(architectures) != {"64bit", "arm64"}:
        raise ValidationError("rendered Scoop architecture set is invalid")
    mappings = {"64bit": "windows-amd64", "arm64": "windows-arm64"}
    for scoop_arch, target in mappings.items():
        value = architectures[scoop_arch]
        if not isinstance(value, dict) or set(value) != {"url", "hash"}:
            raise ValidationError(f"rendered Scoop entry is invalid: {scoop_arch}")
        filename = TARGETS[target].format(version=version)
        if value != {"url": release_url(version, filename), "hash": checksums[target]}:
            raise ValidationError(f"rendered Scoop URL/checksum is not exact: {scoop_arch}")
        if "latest" in value["url"].lower() or not value["url"].startswith("https://github.com/"):
            raise ValidationError("rendered Scoop URL is floating or insecure")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=Path(__file__).with_name("candidate.json"))
    parser.add_argument("--rendered", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--checksums", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        validate_candidate(load_json(arguments.candidate))
        if arguments.rendered is not None:
            if arguments.version is None or arguments.checksums is None:
                raise ValidationError("rendered validation requires --version and --checksums")
            validate_rendered_manifest(arguments.rendered, arguments.version, arguments.checksums)
    except ValidationError as error:
        print(f"scoop validation: {error}", file=sys.stderr)
        return 2
    print("scoop distribution candidate: VALID candidate-unpublished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
