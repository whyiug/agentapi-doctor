#!/usr/bin/env python3
"""Verify one native Doctor release archive and run its offline demo."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile


MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4 * 1024 * 1024
RELEASE_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def parse_checksums(path: Path) -> dict[str, str]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_CHECKSUM_BYTES
    ):
        raise ValueError("checksum file is not a bounded regular file")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("checksum file must be UTF-8") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("invalid checksum line")
        if (
            not name
            or Path(name).name != name
            or "/" in name
            or "\\" in name
            or name in result
        ):
            raise ValueError("unsafe or duplicate checksum filename")
        result[name] = digest
    if not result:
        raise ValueError("checksum file is empty")
    return result


def verify_asset(path: Path, expected: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing regular artifact: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError(f"checksum mismatch: {path.name}")


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


def archive_name(version: str, operating_system: str, architecture: str) -> str:
    if RELEASE_VERSION.fullmatch(version) is None:
        raise ValueError("release version must be an exact SemVer without a v prefix")
    if operating_system not in {"linux", "darwin", "windows"}:
        raise ValueError("unsupported release operating system")
    if architecture not in {"amd64", "arm64"}:
        raise ValueError("unsupported release architecture")
    extension = "zip" if operating_system == "windows" else "tar.gz"
    return f"agentapi-doctor_{version}_{operating_system}_{architecture}.{extension}"


def choose_archive(directory: Path, checksums: dict[str, str], version: str) -> Path:
    operating_system, architecture = platform_tokens()
    expected = archive_name(version, operating_system, architecture)
    if expected not in checksums:
        raise ValueError(f"checksum manifest is missing exact archive: {expected}")
    return directory / expected


def _safe_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or path.is_absolute()
        or ".." in path.parts
    ):
        raise ValueError(f"unsafe archive member: {name}")


def _destination_path(destination: Path, name: str) -> Path:
    _safe_member_name(name)
    target = destination.joinpath(*PurePosixPath(name).parts)
    if os.path.commonpath([destination.resolve(), target.resolve()]) != str(
        destination.resolve()
    ):
        raise ValueError(f"archive member escapes destination: {name}")
    return target


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive member count is outside the safety bound")
        seen: set[str] = set()
        total = 0
        for member in members:
            _destination_path(destination, member.name)
            if member.name in seen or not (member.isfile() or member.isdir()):
                raise ValueError(f"unsafe archive member: {member.name}")
            seen.add(member.name)
            if member.isfile():
                if member.size < 0 or member.size > MAX_EXTRACTED_BYTES - total:
                    raise ValueError("archive exceeds the extracted-byte safety bound")
                total += member.size
        for member in members:
            target = _destination_path(destination, member.name)
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


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive member count is outside the safety bound")
        seen: set[str] = set()
        total = 0
        for member in members:
            _destination_path(destination, member.filename)
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if member.filename in seen or (
                not member.is_dir() and kind not in {0, stat.S_IFREG}
            ):
                raise ValueError(f"unsafe archive member: {member.filename}")
            seen.add(member.filename)
            if not member.is_dir():
                if member.file_size < 0 or member.file_size > MAX_EXTRACTED_BYTES - total:
                    raise ValueError("archive exceeds the extracted-byte safety bound")
                total += member.file_size
        for member in members:
            target = _destination_path(destination, member.filename)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            mode = member.external_attr >> 16
            descriptor = os.open(target, flags, 0o755 if mode & 0o111 else 0o644)
            with bundle.open(member, "r") as source, os.fdopen(descriptor, "wb") as output:
                remaining = member.file_size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(
                            f"archive member is shorter than declared: {member.filename}"
                        )
                    output.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError(
                        f"archive member is longer than declared: {member.filename}"
                    )


def safe_extract(archive: Path, destination: Path) -> None:
    if archive.name.endswith(".tar.gz"):
        _safe_extract_tar(archive, destination)
        return
    if archive.name.endswith(".zip"):
        _safe_extract_zip(archive, destination)
        return
    raise ValueError(f"unsupported release archive format: {archive.name}")


def _remaining_timeout(started_at: float, maximum_seconds: float) -> float:
    remaining = maximum_seconds - (time.time() - started_at)
    if remaining <= 0:
        raise ValueError("release smoke exceeded its time budget")
    return min(remaining, 90.0)


def smoke(
    directory: Path,
    version: str,
    commit: str | None = None,
    *,
    started_at: float | None = None,
    maximum_seconds: float = 120.0,
) -> float:
    if not 0 < maximum_seconds <= 600:
        raise ValueError("release smoke time budget is outside the supported bound")
    started = time.time() if started_at is None else started_at
    if started <= 0 or started > time.time() + 5:
        raise ValueError("release smoke start time is invalid")
    checksums = parse_checksums(directory / "checksums.txt")
    archive = choose_archive(directory, checksums, version)
    verify_asset(archive, checksums[archive.name])
    if commit is not None and re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("release commit must be a full lowercase SHA-1")
    operating_system, _ = platform_tokens()
    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-smoke-") as temporary:
        root = Path(temporary)
        extracted = root / "archive"
        extracted.mkdir()
        safe_extract(archive, extracted)
        for notice in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
            path = extracted / notice
            if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
                raise ValueError(f"release archive is missing {notice}")
        executable = "doctor.exe" if operating_system == "windows" else "doctor"
        binary = extracted / executable
        if not binary.is_file() or binary.is_symlink():
            raise ValueError("doctor binary is absent from archive")
        version_run = subprocess.run(
            [str(binary), "version", "--json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=_remaining_timeout(started, maximum_seconds),
        )
        payload = json.loads(version_run.stdout)
        identity = payload.get("data", {})
        if payload.get("status") != "pass" or identity.get("version") != version:
            raise ValueError(f"unexpected doctor version response: {payload}")
        if commit is not None and identity.get("commit") != commit:
            raise ValueError(f"unexpected doctor commit response: {payload}")

        demo_directory = root / "demo"
        demo_directory.mkdir()
        demo_run = subprocess.run(
            [str(binary), "demo", "--format", "terminal"],
            cwd=demo_directory,
            check=True,
            capture_output=True,
            text=True,
            timeout=_remaining_timeout(started, maximum_seconds),
        )
        required_output = (
            "Profile outcome: COMPATIBLE",
            "Cases: 4 candidate / 4 applicable / 4 executed",
            "Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0",
        )
        if any(marker not in demo_run.stdout for marker in required_output):
            raise ValueError("doctor demo did not produce the expected interpretable result")

    elapsed = time.time() - started
    if elapsed < 0 or elapsed > maximum_seconds:
        raise ValueError(
            f"release smoke took {elapsed:.3f}s, exceeding {maximum_seconds:.3f}s"
        )
    print(
        json.dumps(
            {
                "archive": archive.name,
                "demo": "pass",
                "elapsed_seconds": round(elapsed, 3),
                "version": version,
            },
            sort_keys=True,
        )
    )
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--started-at-epoch", type=float)
    parser.add_argument("--max-seconds", type=float, default=120.0)
    arguments = parser.parse_args()
    smoke(
        arguments.directory.resolve(),
        arguments.version,
        arguments.commit,
        started_at=arguments.started_at_epoch,
        maximum_seconds=arguments.max_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
