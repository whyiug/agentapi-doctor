#!/usr/bin/env python3
"""Offline validation for immutable reusable-workflow inputs."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Sequence


VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?$"
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_CONFIG_BYTES = 1024 * 1024


class InputError(ValueError):
    pass


def validate_version(value: str) -> str:
    if VERSION_RE.fullmatch(value or "") is None:
        raise InputError("version must be an exact SemVer or SemVer-rc.N")
    return value


def validate_commit(value: str) -> str:
    if COMMIT_RE.fullmatch(value or "") is None or value == "0" * 40:
        raise InputError("action_commit must be a nonzero full lowercase Git commit SHA")
    return value


def validate_config_path(workspace: Path, relative: str) -> Path:
    if not relative or len(relative.encode("utf-8")) > 512 or "\\" in relative or "\x00" in relative:
        raise InputError("config path must be a bounded POSIX repository-relative path")
    logical = PurePosixPath(relative)
    if logical.is_absolute() or any(part in {"", ".", ".."} for part in logical.parts):
        raise InputError("config path must not be absolute or traverse parents")
    try:
        workspace_metadata = workspace.lstat()
        root = workspace.resolve(strict=True)
    except OSError as error:
        raise InputError("workspace does not exist") from error
    if stat.S_ISLNK(workspace_metadata.st_mode) or not stat.S_ISDIR(workspace_metadata.st_mode):
        raise InputError("workspace must be a real directory")
    candidate = workspace.joinpath(*logical.parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise InputError("config must exist inside the workspace") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise InputError("config must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_CONFIG_BYTES:
        raise InputError("config size is outside the supported bound")
    return candidate


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--action-commit", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--workspace", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        validate_version(arguments.version)
        validate_commit(arguments.action_commit)
        validate_config_path(arguments.workspace, arguments.config)
    except InputError as error:
        print(f"reusable workflow input validation: {error}", file=sys.stderr)
        return 2
    print("validated immutable reusable-workflow inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
