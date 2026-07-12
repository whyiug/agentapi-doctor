#!/usr/bin/env python3
"""Build a strict, deterministic manifest for top-level release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any


MANIFEST_SCHEMA = "urn:agentapi-doctor:release-asset-manifest:v1"
SAFE_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}")
RELEASE_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,199})")
MAX_CHECKSUM_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
OPERATING_SYSTEMS = ("darwin", "linux", "windows")
ARCHITECTURES = ("amd64", "arm64")

# Signing and provenance exports are added only after the checksum-covered
# release set is assembled, so they are allowlisted but never checksum inputs.
OPTIONAL_UNCHECKSUMMED_ASSETS = {
    "agentapi-doctor.intoto.jsonl": "provenance",
    "agentapi-doctor.slsa-provenance.json": "provenance",
    "checksums.txt.sigstore.json": "signature",
}

# OCI subjects do not exist until the verified multi-architecture images have
# been pushed. If this optional final-publication asset is present, it must be
# covered by checksums.txt before the manifest can be signed or uploaded.
OPTIONAL_CHECKSUMMED_ASSETS = {"oci-images.json": "oci-subjects"}
OPTIONAL_ASSETS = OPTIONAL_UNCHECKSUMMED_ASSETS | OPTIONAL_CHECKSUMMED_ASSETS


def validate_version(version: str) -> None:
    if RELEASE_VERSION.fullmatch(version) is None:
        raise ValueError("release version must be an exact SemVer without a v prefix")


def expected_release_assets(version: str) -> dict[str, str]:
    """Return the exact required and optional filename allowlist for ``version``."""

    validate_version(version)
    assets: dict[str, str] = {}
    for operating_system in OPERATING_SYSTEMS:
        for architecture in ARCHITECTURES:
            assets[
                f"agentapi-doctor_{version}_{operating_system}_{architecture}.tar.gz"
            ] = "doctor-archive"
            assets[
                f"agentapi-doctor_reference-server_{version}_{operating_system}_{architecture}.tar.gz"
            ] = "reference-server-archive"
    for architecture in ARCHITECTURES:
        assets[f"agentapi-doctor_registry_{version}_linux_{architecture}.tar.gz"] = (
            "registry-archive"
        )
    assets[f"agentapi-doctor_{version}_source.tar.gz"] = "source-archive"
    assets["agentapi-doctor.cdx.json"] = "sbom"
    assets["agentapi-doctor.json"] = "package-manifest"
    assets["agentapi-doctor.rb"] = "package-manifest"
    assets["agentapi-doctor.spdx.json"] = "sbom"
    assets["checksums.txt"] = "checksums"
    assets.update(OPTIONAL_ASSETS)
    return assets


def required_release_assets(version: str) -> set[str]:
    """Return files that must exist before a release candidate can be uploaded."""

    allowed = expected_release_assets(version)
    return {name for name in allowed if name not in OPTIONAL_ASSETS}


def checksummed_release_assets(version: str) -> set[str]:
    """Return exact GoReleaser outputs covered by ``checksums.txt``."""

    return required_release_assets(version) - {"checksums.txt"}


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"release asset is missing: {path.name}") from error
    if path.is_symlink() or not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError(
            f"release asset is not a regular non-symlink file: {path.name}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"release asset is not a regular file: {path.name}")
    if (metadata.st_dev, metadata.st_ino) != (
        path_metadata.st_dev,
        path_metadata.st_ino,
    ):
        os.close(descriptor)
        raise ValueError(f"release asset changed while being opened: {path.name}")
    return descriptor, metadata


def _asset_record(path: Path, kind: str) -> dict[str, Any]:
    descriptor, metadata = _open_regular(path)
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(descriptor, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
    if total != metadata.st_size:
        raise ValueError(f"release asset changed while being read: {path.name}")
    return {
        "kind": kind,
        "name": path.name,
        "sha256": digest.hexdigest(),
        "size": metadata.st_size,
    }


def _require_real_directory(path: Path, *, empty: bool = False) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"directory does not exist: {path}") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"path must be a real directory: {path}")
    if empty:
        with os.scandir(path) as iterator:
            if next(iterator, None) is not None:
                raise ValueError(f"staging directory must be empty: {path}")


def _copy_regular(source: Path, destination: Path) -> None:
    source_descriptor, _ = _open_regular(source)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        destination_descriptor = os.open(destination, flags, 0o644)
    except BaseException:
        os.close(source_descriptor)
        raise
    with (
        os.fdopen(source_descriptor, "rb") as input_stream,
        os.fdopen(destination_descriptor, "wb") as output_stream,
    ):
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)


def stage_release_assets(source: Path, destination: Path, version: str) -> None:
    """Copy only exact allowlisted top-level assets into an empty staging root."""

    validate_version(version)
    _require_real_directory(source)
    _require_real_directory(destination, empty=True)
    if source.resolve() == destination.resolve():
        raise ValueError("source and staging directories must differ")

    for name in sorted(expected_release_assets(version)):
        candidate = source / name
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(
                f"selected release asset is not a regular non-symlink file: {name}"
            )
        _copy_regular(candidate, destination / name)


def _read_regular(path: Path, maximum: int) -> bytes:
    descriptor, metadata = _open_regular(path)
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        os.close(descriptor)
        raise ValueError(f"release asset violates size bounds: {path.name}")
    with os.fdopen(descriptor, "rb") as stream:
        payload = stream.read(maximum + 1)
    if len(payload) != metadata.st_size:
        raise ValueError(f"release asset changed while being read: {path.name}")
    return payload


def _parse_checksums(path: Path) -> dict[str, str]:
    payload = _read_regular(path, MAX_CHECKSUM_BYTES)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("checksum manifest must be UTF-8") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError("checksum manifest contains a malformed or unsafe entry")
        digest, name = match.groups()
        if name in result or name.casefold() in {item.casefold() for item in result}:
            raise ValueError(f"checksum manifest contains a duplicate filename: {name}")
        result[name] = digest
    if not result:
        raise ValueError("checksum manifest is empty")
    return result


def _validate_checksums(directory: Path, version: str) -> None:
    checksums = _parse_checksums(directory / "checksums.txt")
    expected = checksummed_release_assets(version)
    expected.update(
        name
        for name in OPTIONAL_CHECKSUMMED_ASSETS
        if (directory / name).is_file() and not (directory / name).is_symlink()
    )
    if set(checksums) != expected:
        missing = sorted(expected - set(checksums))
        unknown = sorted(set(checksums) - expected)
        raise ValueError(
            f"checksum asset set mismatch; missing={missing}, unknown={unknown}"
        )
    for name, expected_digest in checksums.items():
        record = _asset_record(directory / name, "checksummed-asset")
        if record["sha256"] != expected_digest:
            raise ValueError(f"checksum mismatch: {name}")


def build_manifest(directory: Path, version: str) -> dict[str, Any]:
    """Validate ``directory`` and return its deterministic release asset manifest."""

    validate_version(version)
    _require_real_directory(directory)

    allowlist = expected_release_assets(version)
    required = required_release_assets(version)
    with os.scandir(directory) as iterator:
        entries = sorted(iterator, key=lambda item: item.name)
    names = [entry.name for entry in entries]
    folded: set[str] = set()
    for name in names:
        if SAFE_FILENAME.fullmatch(name) is None:
            raise ValueError(f"unsafe release asset filename: {name!r}")
        normalized = name.casefold()
        if normalized in folded:
            raise ValueError(f"duplicate release asset filename: {name}")
        folded.add(normalized)

    unknown = sorted(set(names) - set(allowlist))
    missing = sorted(required - set(names))
    if unknown or missing:
        raise ValueError(
            f"release asset set mismatch; missing={missing}, unknown={unknown}"
        )

    records: list[dict[str, Any]] = []
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"release asset is not a regular file: {entry.name}")
        records.append(_asset_record(directory / entry.name, allowlist[entry.name]))

    _validate_checksums(directory, version)
    return {
        "assets": records,
        "schema": MANIFEST_SCHEMA,
        "version": version,
    }


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    """Encode a manifest in the only accepted deterministic representation."""

    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_manifest(
    path: Path, manifest: dict[str, Any], release_directory: Path
) -> None:
    """Exclusively create a canonical manifest outside the release asset root."""

    release_root = release_directory.resolve()
    output = path.resolve(strict=False)
    if output == release_root or release_root in output.parents:
        raise ValueError(
            "release manifest must be written outside the release asset directory"
        )
    payload = encode_manifest(manifest)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def verify_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """Require an existing manifest to be byte-identical to canonical output."""

    if _read_regular(path, MAX_MANIFEST_BYTES) != encode_manifest(manifest):
        raise ValueError(
            "release asset manifest does not match the validated directory"
        )


def manifest_asset_paths(directory: Path, manifest: dict[str, Any]) -> list[str]:
    """Return newline-safe absolute paths for a shell ``mapfile`` consumer."""

    result: list[str] = []
    for asset in manifest["assets"]:
        path = str(directory / asset["name"])
        if "\n" in path or "\r" in path:
            raise ValueError("release asset path cannot be represented in lines format")
        result.append(path)
    return result


def _absolute_without_following_links(path: Path) -> Path:
    return Path(os.path.abspath(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory_positional", nargs="?", type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--stage-from", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--format", choices=("json", "lines"), default="json")
    manifests = parser.add_mutually_exclusive_group()
    manifests.add_argument("--write-manifest", type=Path)
    manifests.add_argument("--verify-manifest", type=Path)
    arguments = parser.parse_args()
    if arguments.directory is not None and arguments.directory_positional is not None:
        parser.error(
            "provide the release directory either positionally or with --directory, not both"
        )
    directory_argument = arguments.directory or arguments.directory_positional
    if directory_argument is None:
        parser.error("a release directory is required")
    directory = _absolute_without_following_links(directory_argument)
    if arguments.stage_from is not None:
        stage_release_assets(
            _absolute_without_following_links(arguments.stage_from),
            directory,
            arguments.version,
        )
    manifest = build_manifest(directory, arguments.version)
    if arguments.write_manifest is not None:
        write_manifest(arguments.write_manifest, manifest, directory)
    if arguments.verify_manifest is not None:
        verify_manifest(arguments.verify_manifest, manifest)
    if arguments.format == "lines":
        for path in manifest_asset_paths(directory, manifest):
            print(path)
    else:
        print(encode_manifest(manifest).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
