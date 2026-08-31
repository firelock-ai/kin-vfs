#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


CHECK = Path(__file__).with_name("check-release-metadata.py")


class ReleaseMetadataGuardTests(unittest.TestCase):
    def run_guard(self, workspace: str, fuse: str | None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates" / "kin-vfs-fuse").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                f'[workspace.package]\nversion = "{workspace}"\n', encoding="utf-8"
            )
            fuse_text = "[package]\nname = \"kin-vfs-fuse\"\n"
            if fuse is not None:
                fuse_text += f'version = "{fuse}"\n'
            (root / "crates" / "kin-vfs-fuse" / "Cargo.toml").write_text(
                fuse_text, encoding="utf-8"
            )
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

    def test_drift_fails_and_names_both_versions(self) -> None:
        result = self.run_guard("0.4.21", "0.4.6")
        self.assertEqual(result.returncode, 1)
        self.assertIn("workspace.package=0.4.21", result.stderr)
        self.assertIn("kin-vfs-fuse.package=0.4.6", result.stderr)

    def test_missing_explicit_fuse_version_fails_loud(self) -> None:
        result = self.run_guard("0.4.21", None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no string package.version", result.stderr)


if __name__ == "__main__":
    unittest.main()
