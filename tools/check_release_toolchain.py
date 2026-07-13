#!/usr/bin/env python3
"""Verify the exact Go toolchain embedded in final release archives and SBOM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Sequence
import zipfile


GO_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
ARCHIVE_LIMIT = 256 * 1024 * 1024
BINARY_LIMIT = 128 * 1024 * 1024
TARGETS = (
    ("linux", "amd64", "tar.gz", "doctor"),
    ("linux", "arm64", "tar.gz", "doctor"),
    ("darwin", "amd64", "tar.gz", "doctor"),
    ("darwin", "arm64", "tar.gz", "doctor"),
    ("windows", "amd64", "zip", "doctor.exe"),
    ("windows", "arm64", "zip", "doctor.exe"),
)


class CheckError(RuntimeError):
    """A release artifact failed a bounded toolchain check."""


def canonical_go_version(go_mod: Path) -> str:
    try:
        lines = go_mod.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CheckError("go.mod is unavailable") from error
    directives = [line.split() for line in lines if line.startswith("go ")]
    if len(directives) != 1 or len(directives[0]) != 2:
        raise CheckError("go.mod must contain exactly one canonical go directive")
    version = directives[0][1]
    if GO_VERSION.fullmatch(version) is None:
        raise CheckError("go.mod must pin an exact Go patch version")
    if any(line.startswith("toolchain ") for line in lines):
        raise CheckError("go.mod must not carry a second toolchain version authority")
    return version


def check_docker_version(dockerfile: Path, expected: str) -> None:
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except OSError as error:
        raise CheckError("Dockerfile is unavailable") from error
    match = re.search(
        r"(?m)^FROM golang:([^\s@]+)@sha256:([0-9a-f]{64}) AS build$", text
    )
    if match is None:
        raise CheckError("Dockerfile build image must use a pinned golang digest")
    image_version = match.group(1).split("-", 1)[0]
    if image_version != expected:
        raise CheckError(
            f"Dockerfile Go version {image_version} differs from go.mod {expected}"
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CheckError(f"SBOM contains duplicate JSON key: {key}")
        result[key] = value
    return result


def check_sbom(sbom_path: Path, expected: str) -> None:
    try:
        size = sbom_path.stat().st_size
        if size <= 0 or size > 16 * 1024 * 1024 or sbom_path.is_symlink():
            raise CheckError("release SBOM violates its file boundary")
        document = json.loads(
            sbom_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except CheckError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("release SBOM is not strict UTF-8 JSON") from error
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise CheckError("release SBOM is not the expected SPDX 2.3 document")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise CheckError("release SBOM packages are missing")
    stdlib_versions = [
        package.get("versionInfo")
        for package in packages
        if isinstance(package, dict) and package.get("name") == "stdlib"
    ]
    wanted = f"go{expected}"
    if len(stdlib_versions) != len(TARGETS) or any(
        version != wanted for version in stdlib_versions
    ):
        raise CheckError(
            f"release SBOM must contain {len(TARGETS)} stdlib packages at {wanted}"
        )


def _bounded_archive(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CheckError(f"release archive is unavailable: {path.name}") from error
    if path.is_symlink() or not path.is_file() or not 0 < metadata.st_size <= ARCHIVE_LIMIT:
        raise CheckError(f"release archive violates its file boundary: {path.name}")


def _read_tar_binary(path: Path, member_name: str) -> bytes:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            matches = [member for member in archive.getmembers() if member.name == member_name]
            if len(matches) != 1 or not matches[0].isfile():
                raise CheckError(f"{path.name} must contain one regular {member_name}")
            if not 0 < matches[0].size <= BINARY_LIMIT:
                raise CheckError(f"{path.name} binary violates its size boundary")
            handle = archive.extractfile(matches[0])
            if handle is None:
                raise CheckError(f"{path.name} binary cannot be read")
            payload = handle.read(BINARY_LIMIT + 1)
    except CheckError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise CheckError(f"invalid release tar archive: {path.name}") from error
    if len(payload) != matches[0].size or len(payload) > BINARY_LIMIT:
        raise CheckError(f"{path.name} binary read was incomplete or oversized")
    return payload


def _read_zip_binary(path: Path, member_name: str) -> bytes:
    try:
        with zipfile.ZipFile(path) as archive:
            matches = [member for member in archive.infolist() if member.filename == member_name]
            if len(matches) != 1 or matches[0].is_dir():
                raise CheckError(f"{path.name} must contain one regular {member_name}")
            if not 0 < matches[0].file_size <= BINARY_LIMIT:
                raise CheckError(f"{path.name} binary violates its size boundary")
            with archive.open(matches[0]) as handle:
                payload = handle.read(BINARY_LIMIT + 1)
    except CheckError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise CheckError(f"invalid release zip archive: {path.name}") from error
    if len(payload) != matches[0].file_size or len(payload) > BINARY_LIMIT:
        raise CheckError(f"{path.name} binary read was incomplete or oversized")
    return payload


def _run(command: Sequence[str], label: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{label} could not run") from error
    if completed.returncode != 0:
        output = completed.stdout.strip()
        detail = f": {output}" if output else ""
        raise CheckError(f"{label} failed{detail}")
    return completed


def _check_binary_metadata(binary: Path, expected: str, go_command: str) -> None:
    completed = _run([go_command, "version", "-m", str(binary)], "go version -m")
    first_line = completed.stdout.splitlines()[0] if completed.stdout else ""
    match = re.fullmatch(r".+: go([0-9]+\.[0-9]+\.[0-9]+)", first_line)
    if match is None:
        raise CheckError("go version -m returned malformed binary metadata")
    if match.group(1) != expected:
        raise CheckError(
            f"archived binary uses Go {match.group(1)}; expected Go {expected}"
        )


def check_release(
    root: Path,
    dist: Path,
    release_version: str,
    go_command: str = "go",
    govulncheck_command: str = "govulncheck",
) -> dict[str, Any]:
    if re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?",
        release_version,
    ) is None:
        raise CheckError("release version is not an exact supported SemVer")
    expected = canonical_go_version(root / "go.mod")
    check_docker_version(root / "Dockerfile", expected)
    check_sbom(dist / "agentapi-doctor.spdx.json", expected)

    checked: list[str] = []
    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-toolchain-") as temporary:
        temporary_root = Path(temporary)
        linux_amd64: Path | None = None
        for operating_system, architecture, extension, member_name in TARGETS:
            archive_name = (
                f"agentapi-doctor_{release_version}_{operating_system}_{architecture}."
                f"{extension}"
            )
            archive_path = dist / archive_name
            _bounded_archive(archive_path)
            if extension == "zip":
                payload = _read_zip_binary(archive_path, member_name)
            else:
                payload = _read_tar_binary(archive_path, member_name)
            binary_path = temporary_root / f"{operating_system}-{architecture}-{member_name}"
            binary_path.write_bytes(payload)
            _check_binary_metadata(binary_path, expected, go_command)
            checked.append(archive_name)
            if operating_system == "linux" and architecture == "amd64":
                linux_amd64 = binary_path
        if linux_amd64 is None:
            raise CheckError("Linux amd64 release binary was not checked")
        _run(
            [govulncheck_command, "-mode=binary", str(linux_amd64)],
            "govulncheck release binary scan",
        )

    return {
        "archives": checked,
        "go_version": expected,
        "govulncheck_target": "linux-amd64",
        "status": "pass",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--go-command", default="go")
    parser.add_argument("--govulncheck-command", default="govulncheck")
    arguments = parser.parse_args(argv)
    try:
        result = check_release(
            arguments.root,
            arguments.dist,
            arguments.release_version,
            arguments.go_command,
            arguments.govulncheck_command,
        )
    except CheckError as error:
        print(f"release toolchain check: FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
