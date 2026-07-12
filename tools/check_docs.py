#!/usr/bin/env python3
"""Fail closed when a repository-local Markdown link has no target.

The checker is deliberately offline.  It verifies only paths owned by this
repository; HTTP(S), mail, and other external destinations are left to a
separate, explicitly networked review.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\((?:<([^>\n]+)>|([^\s)]+))(?:\s+['\"][^\n)]*['\"])?\)")
REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|([^\s]+))", re.MULTILINE)
EXCLUDED_PARTS = frozenset({".git", ".venv", "dist", "node_modules", "vendor", "__pycache__"})
EXTERNAL_SCHEMES = frozenset({"data", "http", "https", "mailto", "tel"})


def markdown_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if path.is_file() and not any(part in EXCLUDED_PARTS for part in path.relative_to(root).parts)
    )


def destinations(content: str) -> list[str]:
    result: list[str] = []
    for pattern in (INLINE_LINK, REFERENCE_LINK):
        for match in pattern.finditer(content):
            result.append(match.group(1) or match.group(2))
    return result


def local_target(root: Path, source: Path, destination: str) -> Path | None:
    value = destination.strip()
    if not value or value.startswith("#"):
        return None
    parsed = urlsplit(value)
    if parsed.scheme.lower() in EXTERNAL_SCHEMES or parsed.scheme or parsed.netloc:
        return None
    decoded = unquote(parsed.path)
    if not decoded:
        return None
    if "\x00" in decoded or "\\" in decoded:
        return root / "__invalid_markdown_link__"
    if decoded.startswith("/"):
        candidate = root / decoded.lstrip("/")
    else:
        candidate = source.parent / decoded
    return candidate.resolve(strict=False)


def check(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    failures: list[str] = []
    for source in markdown_files(root):
        try:
            content = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            failures.append(f"{source.relative_to(root)}: cannot read UTF-8 Markdown: {error}")
            continue
        for destination in destinations(content):
            target = local_target(root, source, destination)
            if target is None:
                continue
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{source.relative_to(root)}: local link escapes repository: {destination}")
                continue
            if not target.exists():
                failures.append(f"{source.relative_to(root)}: missing local link target: {destination}")
    return sorted(set(failures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        failures = check(arguments.root)
    except OSError as error:
        print(f"documentation check failed: {error}", file=sys.stderr)
        return 2
    if failures:
        print("documentation link check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"documentation link check passed ({len(markdown_files(arguments.root.resolve()))} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
