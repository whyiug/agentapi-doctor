#!/usr/bin/env python3
"""Validate the exact, reviewed release notes bound to one immutable tag."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import stat
import sys
from typing import Sequence


MAX_NOTES_BYTES = 256 * 1024
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?$")
PLACEHOLDER_RE = re.compile(r"\b(?:TBD|TODO|FIXME)\b|<[A-Za-z][^>]*>", re.IGNORECASE)
REQUIRED_HEADINGS = (
    "## Summary",
    "## Compatibility and breaking changes",
    "## Migration",
    "## Known issues",
    "## Support window",
    "## Verification",
)


class NotesError(ValueError):
    pass


def read_regular(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise NotesError("release notes file is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NotesError("release notes must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_NOTES_BYTES:
        raise NotesError("release notes size is outside the supported bound")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise NotesError("release notes must be UTF-8") from error


def validate(path: Path, tag: str) -> None:
    if TAG_RE.fullmatch(tag) is None:
        raise NotesError("tag must be an exact v-prefixed SemVer or SemVer-rc.N")
    text = read_regular(path)
    lines = text.splitlines()
    if not lines or lines[0] != f"# AgentAPI Doctor {tag}":
        raise NotesError("release notes title must bind the exact tag")
    if PLACEHOLDER_RE.search(text):
        raise NotesError("release notes contain an unresolved placeholder")
    positions: list[int] = []
    for heading in REQUIRED_HEADINGS:
        matches = [index for index, line in enumerate(lines) if line == heading]
        if len(matches) != 1:
            raise NotesError(f"release notes require exactly one {heading!r} section")
        positions.append(matches[0])
    if positions != sorted(positions):
        raise NotesError("release note sections are out of order")
    for index, start in enumerate(positions):
        end = positions[index + 1] if index + 1 < len(positions) else len(lines)
        content = [line for line in lines[start + 1 : end] if line.strip()]
        if not content:
            raise NotesError(f"release note section {REQUIRED_HEADINGS[index]!r} is empty")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--file", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        validate(arguments.file, arguments.tag)
    except NotesError as error:
        print(f"release notes: {error}", file=sys.stderr)
        return 2
    print(f"release notes: VALID {arguments.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
