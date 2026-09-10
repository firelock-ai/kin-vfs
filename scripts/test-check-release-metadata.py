#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


CHECK = Path(__file__).with_name("check-release-metadata.py")
WORKFLOW = Path(".github") / "workflows" / "kin-dependency-wave.yml"
BOTH_MANIFESTS = "Cargo.toml crates/kin-vfs-fuse/Cargo.toml"


class ReleaseMetadataGuardTests(unittest.TestCase):
    def run_guard(
        self,
        workspace: str,
        fuse: str | None,
        *,
        excluded: str = "crates/kin-vfs-fuse",
        declared: str | None = BOTH_MANIFESTS,
        workflow_body: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates" / "kin-vfs-fuse").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                "[workspace]\n"
                f'exclude = ["{excluded}"]\n'
                f'[workspace.package]\nversion = "{workspace}"\n',
                encoding="utf-8",
            )
            fuse_text = "[package]\nname = \"kin-vfs-fuse\"\n"
            if fuse is not None:
                fuse_text += f'version = "{fuse}"\n'
            (root / "crates" / "kin-vfs-fuse" / "Cargo.toml").write_text(
                fuse_text, encoding="utf-8"
            )
            if workflow_body is None and declared is not None:
                workflow_body = (
                    "jobs:\n"
                    "  dependency-wave:\n"
                    "    with:\n"
                    f"      manifests: {declared}\n"
                    "      auto-merge: true\n"
                )
            if workflow_body is not None:
                (root / WORKFLOW).parent.mkdir(parents=True, exist_ok=True)
                (root / WORKFLOW).write_text(workflow_body, encoding="utf-8")
            return subprocess.run(
                ["python3", str(CHECK), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_matching_versions_pass(self) -> None:
        result = self.run_guard("0.4.21", "0.4.21")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("share release version 0.4.21", result.stdout)
        self.assertIn("covers every release version authority", result.stdout)

    def test_drift_fails_and_names_both_versions(self) -> None:
        result = self.run_guard("0.4.21", "0.4.6")
        self.assertEqual(result.returncode, 1)
        self.assertIn("workspace.package=0.4.21", result.stderr)
        self.assertIn("kin-vfs-fuse.package=0.4.6", result.stderr)

    def test_missing_explicit_fuse_version_fails_loud(self) -> None:
        result = self.run_guard("0.4.21", None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no string package.version", result.stderr)

    def test_wave_input_missing_an_authority_fails(self) -> None:
        """The drift's cause, caught on the edit that creates it."""

        result = self.run_guard("0.4.21", "0.4.21", declared="Cargo.toml")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not cover", result.stderr)
        self.assertIn("crates/kin-vfs-fuse/Cargo.toml", result.stderr)

    def test_wave_input_missing_the_root_manifest_fails(self) -> None:
        result = self.run_guard(
            "0.4.21", "0.4.21", declared="crates/kin-vfs-fuse/Cargo.toml"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not cover", result.stderr)
        self.assertIn("Cargo.toml", result.stderr)

    def test_newly_excluded_package_joins_the_requirement(self) -> None:
        """The set is derived from [workspace].exclude, not hardcoded here."""

        result = self.run_guard(
            "0.4.21", "0.4.21", declared=BOTH_MANIFESTS, excluded="crates/other"
        )
        # `crates/other` holds no manifest, so it contributes no authority and
        # the root manifest alone is required; the declared set still covers it.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no excluded package", result.stdout)

    def test_absent_workflow_fails_rather_than_passing_quietly(self) -> None:
        result = self.run_guard("0.4.21", "0.4.21", declared=None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot read", result.stderr)

    def test_empty_manifests_value_fails(self) -> None:
        result = self.run_guard(
            "0.4.21",
            "0.4.21",
            workflow_body="jobs:\n  dependency-wave:\n    with:\n      manifests:\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("empty `manifests:` value", result.stderr)

    def test_duplicate_manifests_keys_fail(self) -> None:
        result = self.run_guard(
            "0.4.21",
            "0.4.21",
            workflow_body=(
                "jobs:\n"
                "  a:\n    with:\n"
                f"      manifests: {BOTH_MANIFESTS}\n"
                "  b:\n    with:\n"
                f"      manifests: {BOTH_MANIFESTS}\n"
            ),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("`manifests:` keys; expected exactly one", result.stderr)

    def test_quoted_and_commented_value_is_read(self) -> None:
        result = self.run_guard(
            "0.4.21",
            "0.4.21",
            workflow_body=(
                "jobs:\n  dependency-wave:\n    with:\n"
                f'      manifests: "{BOTH_MANIFESTS}"  # both authorities\n'
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
