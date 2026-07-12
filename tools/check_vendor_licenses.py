#!/usr/bin/env python3
"""Verify that every vendored Go module retains a root license notice.

This is an offline inventory check, not a legal compatibility opinion.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


NOTICE_PREFIXES = ("COPYING", "LICENSE", "NOTICE")


def modules(manifest: Path) -> list[str]:
    result: list[str] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.startswith("# ") or line.startswith("# => "):
            continue
        fields = line[2:].split()
        if len(fields) >= 2 and fields[1].startswith("v"):
            result.append(fields[0])
    return sorted(set(result))


def check(root: Path) -> list[str]:
    vendor = root.resolve() / "vendor"
    manifest = vendor / "modules.txt"
    if not manifest.is_file():
        return ["vendor/modules.txt is missing"]
    failures: list[str] = []
    for module in modules(manifest):
        directory = vendor.joinpath(*module.split("/"))
        if not directory.is_dir():
            failures.append(f"{module}: vendored module directory is missing")
            continue
        notices = [
            path
            for path in directory.iterdir()
            if path.is_file() and path.name.upper().startswith(NOTICE_PREFIXES)
        ]
        if not notices:
            failures.append(f"{module}: no root LICENSE, COPYING, or NOTICE file")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        failures = check(arguments.root)
    except (OSError, UnicodeError) as error:
        print(f"vendor license inventory failed: {error}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"vendor license inventory passed ({len(modules(arguments.root / 'vendor' / 'modules.txt'))} modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
