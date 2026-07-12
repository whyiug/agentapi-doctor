#!/usr/bin/env python3
"""Generate the license and notice bundle distributed with release binaries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

if __package__:
    from tools.check_vendor_licenses import modules
else:
    from check_vendor_licenses import modules


NOTICE_PREFIXES = ("COPYING", "LICENSE", "NOTICE", "PATENTS")
HEADER = """AgentAPI Doctor third-party licenses and notices

This file is generated from the root license, notice, and patent files retained
for each module in vendor/modules.txt. It is an attribution bundle, not a legal
compatibility opinion. The corresponding source is identified by go.mod,
go.sum, and vendor/modules.txt in the source release.
"""


def notice_files(root: Path, module: str) -> list[Path]:
    directory = root / "vendor" / Path(*module.split("/"))
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.name.upper().startswith(NOTICE_PREFIXES)
    )


def render(root: Path) -> bytes:
    sections = [HEADER.rstrip(), ""]
    manifest = root / "vendor" / "modules.txt"
    for module in modules(manifest):
        files = notice_files(root, module)
        if not files:
            raise ValueError(f"{module}: no license or notice files")
        sections.extend(("=" * 79, f"MODULE: {module}", "=" * 79, ""))
        for path in files:
            try:
                content = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            except UnicodeError as error:
                raise ValueError(f"{path}: notice is not UTF-8") from error
            sections.extend((f"--- {path.name} ---", "", content.rstrip(), ""))
    return ("\n".join(sections).rstrip() + "\n").encode("utf-8")


def write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("THIRD_PARTY_LICENSES.txt"))
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    output = arguments.output
    if not output.is_absolute():
        output = root / output
    payload = render(root)
    if arguments.check:
        if not output.is_file() or output.read_bytes() != payload:
            raise SystemExit(f"third-party notice bundle is stale: {output}")
        print(f"third-party notice bundle passed ({len(modules(root / 'vendor' / 'modules.txt'))} modules)")
        return 0
    write_atomic(output, payload)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
