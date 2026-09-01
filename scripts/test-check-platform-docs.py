#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


CHECK = Path(__file__).with_name("check-platform-docs.py")


class PlatformDocsGuardTests(unittest.TestCase):
    def run_guard(
        self, windows_row: str, extra_readme: str = ""
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Kin VFS\n\n" + windows_row + "\n" + extra_readme,
                encoding="utf-8",
            )
            return subprocess.run(
                ["python3", str(CHECK), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_current_packaging_and_write_truth_pass(self) -> None:
        result = self.run_guard(
            "| Native Windows | **Not shipped for VFS projection.** The archive has "
            "no Windows projection files. The live provider crosses the VFS protocol "
            "and reaches graph truth. |"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("packaging and graph-write proof distinct", result.stdout)

    def test_stale_write_notify_claim_fails(self) -> None:
        result = self.run_guard(
            "| Native Windows | **Not shipped for VFS projection.** The archive has "
            "no Windows projection files. The VFS protocol uses /vfs/write-notify "
            "before graph truth. |"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale Windows write mechanism remains", result.stderr)

    def test_stale_structure_claim_outside_the_platform_row_fails(self) -> None:
        result = self.run_guard(
            "| Native Windows | **Not shipped for VFS projection.** The archive has "
            "no Windows projection files. The live provider crosses the VFS protocol "
            "and reaches graph truth. |",
            "The write-through notification targets a daemon route that no longer exists.\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale Windows write mechanism remains", result.stderr)

    def test_shipped_boundary_cannot_disappear(self) -> None:
        result = self.run_guard(
            "| Native Windows | The live provider crosses the VFS protocol and reaches "
            "graph truth. |"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not shipped for VFS projection", result.stderr)
        self.assertIn("no Windows projection files", result.stderr)


if __name__ == "__main__":
    unittest.main()
