#!/usr/bin/env python3
"""Keep every release version authority equal, and keep the bumper aware of them all.

The release version lives in more than one file. Root ``Cargo.toml`` carries
``[workspace.package].version`` for every member, and each package the workspace
excludes carries its own literal ``[package].version``, because an excluded
package cannot inherit one. Cargo keeps nothing in step across that boundary.

Neither does the automation, unless it is told. The dependency wave bumps the
consumer's own version so its pin PR can pass the version gate, but it only
bumps the manifests its ``manifests:`` input names (see the "Bump own version"
step of ``cargo-dependency-wave.yml``, which loops over that input). An input
narrower than the set of authorities below moves one file, leaves the other at
the previous version, and produces that drift on every run rather than once.

So this guard does two things. It compares every authority, and it requires the
wave's declared manifest set to cover every authority it compared. Excluding a
new package, or narrowing the input, is then red on the pull request that does
it rather than on the next wave PR.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


WAVE_WORKFLOW = Path(".github") / "workflows" / "kin-dependency-wave.yml"
ROOT_MANIFEST = "Cargo.toml"

# The `manifests:` input is a plain YAML scalar holding a space-separated list.
# Reading it with a scanner rather than a YAML parser is deliberate: the CI step
# that runs this guard installs nothing, so an import of a non-stdlib parser
# would turn a real drift into a ModuleNotFoundError, which is a check that
# cannot fail for the reason it exists.
MANIFESTS_KEY_RE = re.compile(r"^\s*manifests:\s*(?P<value>.*?)\s*$")
INLINE_COMMENT_RE = re.compile(r"\s#.*$")


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


def excluded_authorities(root: Path) -> list[tuple[str, str, str]]:
    """Return (relative manifest, package name, version) per excluded package.

    Derived from ``[workspace].exclude`` rather than from a hardcoded path, so a
    newly excluded package joins the comparison and the coverage requirement
    without anyone remembering to edit this file.
    """

    root_manifest = root / ROOT_MANIFEST
    document = load_manifest(root_manifest)
    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        raise ValueError(f"{root_manifest} has no [workspace] table")
    excluded = workspace.get("exclude", [])
    if not isinstance(excluded, list) or any(
        not isinstance(entry, str) for entry in excluded
    ):
        raise ValueError(f"{root_manifest} has a non-string [workspace].exclude")

    authorities: list[tuple[str, str, str]] = []
    for entry in excluded:
        relative = f"{entry.rstrip('/')}/{ROOT_MANIFEST}"
        manifest = root / relative
        if not manifest.is_file():
            # An excluded directory need not hold a package at all.
            continue
        document = load_manifest(manifest)
        if "package" not in document:
            continue
        # A package with a [package] table and no literal version is loud rather
        # than skipped: an excluded package cannot inherit one, so a missing
        # version is a broken manifest, and skipping it would let deleting a
        # line disable this guard.
        authorities.append(
            (
                relative,
                string_at(document, manifest, "package", "name"),
                string_at(document, manifest, "package", "version"),
            )
        )
    return authorities


def wave_manifests(path: Path) -> list[str]:
    """Read the dependency wave's declared manifest set from its workflow."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error

    values: list[str] = []
    for line in text.splitlines():
        match = MANIFESTS_KEY_RE.match(line)
        if match:
            values.append(match.group("value"))
    if len(values) != 1:
        raise ValueError(
            f"{path} has {len(values)} `manifests:` keys; expected exactly one"
        )

    value = INLINE_COMMENT_RE.sub("", values[0]).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    if not value:
        raise ValueError(f"{path} has an empty `manifests:` value")
    return value.split()


def check(root: Path) -> tuple[list[str], list[str]]:
    """Return (failure lines, ok lines) for the release version authorities."""

    root_manifest = root / ROOT_MANIFEST
    workspace_version = string_at(
        load_manifest(root_manifest), root_manifest, "workspace", "package", "version"
    )
    authorities = excluded_authorities(root)

    failures: list[str] = []
    drifted = [
        f"{name}.package={version}"
        for _relative, name, version in authorities
        if version != workspace_version
    ]
    if drifted:
        failures.append(
            "release version drift: "
            f"workspace.package={workspace_version}, " + ", ".join(drifted)
        )

    declared = set(wave_manifests(root / WAVE_WORKFLOW))
    required = [ROOT_MANIFEST] + [relative for relative, _name, _v in authorities]
    missing = [relative for relative in required if relative not in declared]
    if missing:
        failures.append(
            f"{WAVE_WORKFLOW.as_posix()} declares manifests "
            + " ".join(sorted(declared))
            + ", which does not cover "
            + ", ".join(missing)
            + "; the dependency wave bumps only the manifests it is given, so an "
            "authority missing there drifts on every run"
        )

    named = ", ".join(relative for relative, _name, _v in authorities) or "no excluded package"
    return failures, [
        f"OK: workspace and {named} share release version {workspace_version}",
        f"OK: {WAVE_WORKFLOW.as_posix()} covers every release version authority",
    ]


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
        failures, ok = check(args.root.resolve())
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    for line in ok:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
