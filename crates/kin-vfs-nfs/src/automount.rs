// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OS-specific NFS mount/unmount helpers.
//!
//! Handles the platform-specific commands to mount the NFS share:
//! - macOS: `mount_nfs` (built-in)
//! - Linux: `mount -t nfs` (built-in)
//! - Windows: `mount` or `net use` (built-in NFS client)

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// Ensure the mount point directory exists.
///
/// For `/Volumes/*` paths on macOS, uses `sudo mkdir` since `/Volumes/`
/// is root-owned. Other paths use normal `create_dir_all`.
pub fn ensure_mount_point(mount_point: &Path) -> Result<()> {
    if mount_point.exists() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    if mount_point.starts_with("/Volumes") {
        let output = Command::new("sudo")
            .args(["mkdir", "-p", mount_point.to_str().unwrap()])
            .output()
            .context("failed to run sudo mkdir for /Volumes mount point")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sudo mkdir failed: {}", stderr.trim());
        }
        let _ = Command::new("sudo")
            .args(["chown", &whoami(), mount_point.to_str().unwrap()])
            .output();
        info!(path = %mount_point.display(), "created /Volumes mount point");
        return Ok(());
    }

    std::fs::create_dir_all(mount_point)
        .with_context(|| format!("creating mount point {}", mount_point.display()))?;
    info!(path = %mount_point.display(), "created mount point directory");
    Ok(())
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

/// Mount the NFS share at the given mount point.
///
/// Uses OS-specific commands:
/// - macOS: `mount_nfs -o locallocks,nolockd,tcp,port={port} 127.0.0.1:/ {mount_point}`
/// - Linux: `mount -t nfs -o nolock,tcp,port={port},vers=3 127.0.0.1:/ {mount_point}`
pub fn mount_nfs(port: u16, mount_point: &Path) -> Result<()> {
    ensure_mount_point(mount_point)?;

    if is_mounted(mount_point)? {
        info!(path = %mount_point.display(), "already mounted");
        return Ok(());
    }

    let output = mount_command(port, mount_point)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "mount failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    info!(port, path = %mount_point.display(), "NFS share mounted");
    Ok(())
}

/// Run the platform-specific mount command.
#[cfg(target_os = "macos")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    let opts = format!("locallocks,nolockd,noresvport,tcp,port={port}");
    debug!(command = "mount_nfs", opts = %opts, "mounting");
    Command::new("mount_nfs")
        .args(["-o", &opts, "127.0.0.1:/", mount_point.to_str().unwrap()])
        .output()
        .context("failed to run mount_nfs")
}

#[cfg(target_os = "linux")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    let opts = format!("nolock,tcp,port={port},vers=3");
    debug!(command = "mount", opts = %opts, "mounting");
    Command::new("mount")
        .args([
            "-t",
            "nfs",
            "-o",
            &opts,
            "127.0.0.1:/",
            mount_point.to_str().unwrap(),
        ])
        .output()
        .context("failed to run mount")
}

#[cfg(target_os = "windows")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "mount", "mounting (Windows)");
    Command::new("mount")
        .args([
            "-o",
            &format!("nolock,port={port}"),
            "\\\\127.0.0.1\\kin",
            mount_point.to_str().unwrap(),
        ])
        .output()
        .context("failed to run mount")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn mount_command(_port: u16, _mount_point: &Path) -> Result<std::process::Output> {
    bail!("NFS mount not supported on this platform")
}

/// Unmount the NFS share.
pub fn unmount(mount_point: &Path) -> Result<()> {
    if !is_mounted(mount_point)? {
        info!(path = %mount_point.display(), "not mounted, nothing to unmount");
        return Ok(());
    }

    let output = unmount_command(mount_point)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "unmount failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    info!(path = %mount_point.display(), "NFS share unmounted");
    Ok(())
}

/// Run the platform-specific unmount command.
#[cfg(target_os = "macos")]
fn unmount_command(mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "diskutil unmount", "unmounting");
    Command::new("diskutil")
        .args(["unmount", mount_point.to_str().unwrap()])
        .output()
        .context("failed to run diskutil unmount")
}

#[cfg(target_os = "linux")]
fn unmount_command(mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "umount", "unmounting");
    Command::new("umount")
        .arg(mount_point.to_str().unwrap())
        .output()
        .context("failed to run umount")
}

#[cfg(target_os = "windows")]
fn unmount_command(mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "net use /delete", "unmounting (Windows)");
    Command::new("net")
        .args(["use", mount_point.to_str().unwrap(), "/delete"])
        .output()
        .context("failed to run net use /delete")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn unmount_command(_mount_point: &Path) -> Result<std::process::Output> {
    bail!("NFS unmount not supported on this platform")
}

/// Check if a path is currently a mount point.
///
/// On Unix, compares the device ID of the path with its parent.
/// If they differ, the path is a mount point.
#[cfg(unix)]
pub fn is_mounted(mount_point: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    if !mount_point.exists() {
        return Ok(false);
    }

    let parent = mount_point.parent().unwrap_or(Path::new("/"));
    let mount_meta = std::fs::metadata(mount_point)?;
    let parent_meta = std::fs::metadata(parent)?;

    // Different device IDs means it's a mount point.
    Ok(mount_meta.dev() != parent_meta.dev())
}

#[cfg(not(unix))]
pub fn is_mounted(mount_point: &Path) -> Result<bool> {
    // On non-Unix, fall back to checking if the directory is non-empty
    // (a mounted NFS share will have entries).
    if !mount_point.exists() {
        return Ok(false);
    }
    let entries: Vec<_> = std::fs::read_dir(mount_point)?.take(1).collect();
    Ok(!entries.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_mount_point_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mnt = dir.path().join("mnt");
        assert!(!mnt.exists());
        ensure_mount_point(&mnt).unwrap();
        assert!(mnt.exists());
        assert!(mnt.is_dir());
    }

    #[test]
    fn test_ensure_mount_point_existing() {
        let dir = tempfile::tempdir().unwrap();
        // Already exists — should not fail.
        ensure_mount_point(dir.path()).unwrap();
    }

    #[test]
    fn test_is_mounted_non_mount() {
        let dir = tempfile::tempdir().unwrap();
        // A regular temp dir is not a mount point.
        assert!(!is_mounted(dir.path()).unwrap());
    }

    #[test]
    fn test_is_mounted_nonexistent() {
        assert!(!is_mounted(Path::new("/tmp/kin-vfs-nfs-test-nonexistent")).unwrap());
    }
}
