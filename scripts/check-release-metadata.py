#!/usr/bin/env python3
"""Fail when the excluded FUSE package drifts from the product version."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


def load_manifest(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a TOML table")
    return document


def string_at(
    document: dict[str, object], path: Path, *keys: str
) -> str:
    value: object = document
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            dotted = ".".join(keys)
            raise ValueError(f"{path} has no string {dotted}")
        value = value[key]
    if not isinstance(value, str) or not value:
        dotted = ".".join(keys)
        raise ValueError(f"{path} has no string {dotted}")
    return value


def release_versions(root: Path) -> tuple[str, str]:
    root_manifest = root / "Cargo.toml"
    fuse_manifest = root / "crates" / "kin-vfs-fuse" / "Cargo.toml"
    workspace = string_at(
        load_manifest(root_manifest), root_manifest, "workspace", "package", "version"
    )
    fuse = string_at(load_manifest(fuse_manifest), fuse_manifest, "package", "version")
    return workspace, fuse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="kin-vfs repository root",
    )
    args = parser.parse_args(argv)

    try:
        workspace, fuse = release_versions(args.root.resolve())
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if workspace != fuse:
        print(
            "ERROR: release version drift: "
            f"workspace.package={workspace}, kin-vfs-fuse.package={fuse}",
            file=sys.stderr,
        )
        return 1

    print(f"OK: workspace and kin-vfs-fuse share release version {workspace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
