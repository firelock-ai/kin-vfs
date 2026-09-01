#!/usr/bin/env python3
"""Keep public platform claims aligned with the shipped and proven VFS surfaces."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


WINDOWS_ROW_PREFIX = "| Native Windows |"
WINDOWS_REQUIRED = (
    "Not shipped for VFS projection",
    "no Windows projection files",
    "VFS protocol",
    "graph truth",
)
WINDOWS_FORBIDDEN = (
    "/vfs/write-notify",
    "write-through notification targets a daemon route that no longer exists",
)


def windows_platform_row(readme: str) -> str:
    rows = [line for line in readme.splitlines() if line.startswith(WINDOWS_ROW_PREFIX)]
    if len(rows) != 1:
        raise ValueError(
            f"README must contain exactly one {WINDOWS_ROW_PREFIX!r} row; found {len(rows)}"
        )
    return rows[0]


def validate_windows_claims(readme: str, row: str) -> list[str]:
    errors = [
        f"missing current Windows boundary: {fragment}"
        for fragment in WINDOWS_REQUIRED
        if fragment not in row
    ]
    errors.extend(
        f"stale Windows write mechanism remains: {fragment}"
        for fragment in WINDOWS_FORBIDDEN
        if fragment in readme
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="kin-vfs repository root",
    )
    args = parser.parse_args(argv)
    readme_path = args.root.resolve() / "README.md"

    try:
        readme = readme_path.read_text(encoding="utf-8")
        row = windows_platform_row(readme)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: cannot validate {readme_path}: {error}", file=sys.stderr)
        return 1

    errors = validate_windows_claims(readme, row)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: README keeps Windows packaging and graph-write proof distinct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
