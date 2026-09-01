// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::process::Command;

#[test]
fn version_reports_the_cli_package_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_kin-vfs"))
        .arg("--version")
        .output()
        .expect("kin-vfs should launch");

    assert!(
        output.status.success(),
        "kin-vfs --version failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output should be UTF-8"),
        format!("kin-vfs {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        output.stderr.is_empty(),
        "version output should not write stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
