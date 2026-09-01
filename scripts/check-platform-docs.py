#!/usr/bin/env python3
"""Keep public platform claims aligned with the shipped and proven VFS surfaces."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


WINDOWS_ROW_PREFIX = "| Native Windows |"
SHIM_BULLET_PREFIX = "- **`crates/kin-vfs-shim`:**"
REQUIRED_CLAIMS = {
    WINDOWS_ROW_PREFIX: (
        "**Not shipped for VFS projection, though the ProjFS provider's read and "
        "write paths are proven against a live filesystem.**",
        "The Kin archive still carries no Windows projection files, and no shipped "
        "binary starts the provider, so a native Windows install has no projection today.",
        "Writes, deletes, and renames cross the VFS protocol into graph truth, and a "
        "second cold projection reads the edited graph-owned bytes back.",
        "This is source and CI proof, not shipped Windows support.",
    ),
    SHIM_BULLET_PREFIX: (
        "The provider's read and write paths are exercised live in CI, including graph "
        "admission and cold-projection readback.",
        "No shipped binary starts it, so it is not yet a Windows projection path a user can run.",
    ),
}
STALE_WINDOWS_CLAIMS = (
    "/vfs/write-notify",
    "does not reach graph truth",
    "rather than that the graph took the write",
    "write-through notification targets a daemon route that no longer exists",
)


def unique_claim_line(readme: str, prefix: str) -> str:
    lines = [line for line in readme.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        raise ValueError(
            f"README must contain exactly one line starting {prefix!r}; found {len(lines)}"
        )
    return lines[0]


def validate_windows_claims(lines: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for prefix, required in REQUIRED_CLAIMS.items():
        errors.extend(
            f"missing current Windows boundary in {prefix}: {claim}"
            for claim in required
            if claim not in lines[prefix]
        )

    scoped_claims = "\n".join(lines.values())
    errors.extend(
        f"stale or contradictory Windows mechanism remains: {claim}"
        for claim in STALE_WINDOWS_CLAIMS
        if claim in scoped_claims
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
        lines = {
            prefix: unique_claim_line(readme, prefix) for prefix in REQUIRED_CLAIMS
        }
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: cannot validate {readme_path}: {error}", file=sys.stderr)
        return 1

    errors = validate_windows_claims(lines)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: README keeps Windows packaging and graph-write proof distinct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
