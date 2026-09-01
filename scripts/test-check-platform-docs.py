#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


CHECK = Path(__file__).with_name("check-platform-docs.py")
CURRENT_WINDOWS_ROW = (
    "| Native Windows | **Not shipped for VFS projection, though the ProjFS provider's "
    "read and write paths are proven against a live filesystem.** The Kin archive still "
    "carries no Windows projection files, and no shipped binary starts the provider, so "
    "a native Windows install has no projection today. Writes, deletes, and renames cross "
    "the VFS protocol into graph truth, and a second cold projection reads the edited "
    "graph-owned bytes back. This is source and CI proof, not shipped Windows support. |"
)
CURRENT_SHIM_BULLET = (
    "- **`crates/kin-vfs-shim`:** The provider's read and write paths are exercised live "
    "in CI, including graph admission and cold-projection readback. No shipped binary "
    "starts it, so it is not yet a Windows projection path a user can run."
)


class PlatformDocsGuardTests(unittest.TestCase):
    def run_guard(
        self,
        windows_row: str = CURRENT_WINDOWS_ROW,
        shim_bullet: str = CURRENT_SHIM_BULLET,
        extra_readme: str = "",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Kin VFS\n\n"
                + windows_row
                + "\n\n## Structure\n\n"
                + shim_bullet
                + "\n"
                + extra_readme,
                encoding="utf-8",
            )
            return subprocess.run(
                ["python3", str(CHECK), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_current_packaging_and_write_truth_pass(self) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("packaging and graph-write proof distinct", result.stdout)

    def test_stale_write_notify_claim_fails(self) -> None:
        result = self.run_guard(
            windows_row=CURRENT_WINDOWS_ROW.replace(
                "Writes, deletes, and renames cross the VFS protocol into graph truth, "
                "and a second cold projection reads the edited graph-owned bytes back.",
                "Writes emit /vfs/write-notify rather than reaching graph truth.",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale or contradictory Windows mechanism remains", result.stderr)

    def test_negated_graph_write_claim_fails(self) -> None:
        result = self.run_guard(
            windows_row=CURRENT_WINDOWS_ROW.replace(
                "This is source and CI proof, not shipped Windows support.",
                "The provider does not reach graph truth. This is source and CI proof, "
                "not shipped Windows support.",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not reach graph truth", result.stderr)

    def test_unix_write_notify_outside_windows_claims_is_allowed(self) -> None:
        result = self.run_guard(
            extra_readme="The Unix shim still sends /vfs/write-notify from working-copy writes.\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_structure_claim_outside_the_platform_row_fails(self) -> None:
        result = self.run_guard(
            shim_bullet=CURRENT_SHIM_BULLET.replace(
                "The provider's read and write paths are exercised live in CI, including "
                "graph admission and cold-projection readback.",
                "The write-through notification targets a daemon route that no longer exists.",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale or contradictory Windows mechanism remains", result.stderr)

    def test_cold_projection_boundary_cannot_disappear(self) -> None:
        result = self.run_guard(
            shim_bullet=CURRENT_SHIM_BULLET.replace(
                "graph admission and cold-projection readback",
                "graph admission and readback",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("cold-projection readback", result.stderr)

    def test_vague_write_proof_paraphrase_is_not_enough(self) -> None:
        result = self.run_guard(
            windows_row=CURRENT_WINDOWS_ROW.replace(
                "Writes, deletes, and renames cross the VFS protocol into graph truth, "
                "and a second cold projection reads the edited graph-owned bytes back.",
                "Windows writes are covered by CI.",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Writes, deletes, and renames", result.stderr)

    def test_shipped_boundary_cannot_disappear(self) -> None:
        result = self.run_guard(
            windows_row=CURRENT_WINDOWS_ROW.replace(
                "**Not shipped for VFS projection, though the ProjFS provider's read and "
                "write paths are proven against a live filesystem.**",
                "**Supported for VFS projection.**",
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not shipped for VFS projection", result.stderr)


if __name__ == "__main__":
    unittest.main()
