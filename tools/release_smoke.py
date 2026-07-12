#!/usr/bin/env python3
"""Offline release-archive verification used by the protected release workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile


MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
RELEASE_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("invalid checksum line")
        if Path(name).name != name or name in result:
            raise ValueError("unsafe or duplicate checksum filename")
        result[name] = digest
    if not result:
        raise ValueError("checksum file is empty")
    return result


def verify(directory: Path, checksums: dict[str, str]) -> None:
    for name, expected in checksums.items():
        artifact = directory / name
        if not artifact.is_file() or artifact.is_symlink():
            raise ValueError(f"missing regular artifact: {name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"checksum mismatch: {name}")


def platform_tokens() -> tuple[str, str]:
    os_name = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(
        platform.system().lower()
    )
    machine = platform.machine().lower()
    arch = (
        "arm64"
        if machine in {"arm64", "aarch64"}
        else "amd64"
        if machine in {"amd64", "x86_64"}
        else None
    )
    if not os_name or not arch:
        raise ValueError(
            f"unsupported smoke platform: {platform.system()} {platform.machine()}"
        )
    return os_name, arch


def choose_archive(directory: Path, checksums: dict[str, str], version: str) -> Path:
    if RELEASE_VERSION.fullmatch(version) is None:
        raise ValueError("release version must be an exact SemVer without a v prefix")
    os_name, arch = platform_tokens()
    expected = f"agentapi-doctor_{version}_{os_name}_{arch}.tar.gz"
    if expected not in checksums:
        raise ValueError(f"checksum manifest is missing exact archive: {expected}")
    return directory / expected


def safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive member count is outside the safety bound")
        seen: set[str] = set()
        total = 0
        for member in members:
            target = destination / member.name
            if (
                not member.name
                or member.name in seen
                or member.name.startswith(("/", "\\"))
                or ".." in Path(member.name).parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError(f"unsafe archive member: {member.name}")
            seen.add(member.name)
            if os.path.commonpath([destination.resolve(), target.resolve()]) != str(
                destination.resolve()
            ):
                raise ValueError(f"archive member escapes destination: {member.name}")
            if member.isfile():
                if member.size < 0 or member.size > MAX_EXTRACTED_BYTES - total:
                    raise ValueError("archive exceeds the extracted-byte safety bound")
                total += member.size
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError(f"archive file has no readable payload: {member.name}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o755 if member.mode & 0o111 else 0o644)
            with source, os.fdopen(descriptor, "wb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(
                            f"archive member is shorter than declared: {member.name}"
                        )
                    output.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError(
                        f"archive member is longer than declared: {member.name}"
                    )


def smoke(directory: Path, version: str) -> None:
    checksums = parse_checksums(directory / "checksums.txt")
    verify(directory, checksums)
    archive = choose_archive(directory, checksums, version)
    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-smoke-") as temporary:
        destination = Path(temporary)
        safe_extract(archive, destination)
        binary = destination / (
            "doctor.exe" if platform.system().lower() == "windows" else "doctor"
        )
        if not binary.is_file():
            raise ValueError("doctor binary is absent from archive")
        completed = subprocess.run(
            [str(binary), "version", "--json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        payload = json.loads(completed.stdout)
        if (
            payload.get("status") != "pass"
            or payload.get("data", {}).get("version") != version
        ):
            raise ValueError(f"unexpected version response: {payload}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    smoke(arguments.directory.resolve(), arguments.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
