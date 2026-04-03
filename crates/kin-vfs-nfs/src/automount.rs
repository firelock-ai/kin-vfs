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
        info!("creating {} (requires admin privileges)", mount_point.display());
        let status = Command::new("sudo")
            .args(["mkdir", "-p", mount_point.to_str().unwrap()])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("failed to run sudo mkdir for /Volumes mount point")?;
        if !status.success() {
            bail!("sudo mkdir failed (exit {})", status.code().unwrap_or(-1));
        }
        let _ = Command::new("sudo")
            .args(["chown", &whoami(), mount_point.to_str().unwrap()])
            .status();
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

/// Returns the NFS host to use in mount commands.
/// Prefers `kin.local` (shows nicely in Finder) if it resolves,
/// falls back to `127.0.0.1`.
fn nfs_host() -> &'static str {
    use std::net::ToSocketAddrs;
    if format!("{NFS_HOSTNAME}:0")
        .to_socket_addrs()
        .map(|a| a.count() > 0)
        .unwrap_or(false)
    {
        NFS_HOSTNAME
    } else {
        "127.0.0.1"
    }
}

/// The hostname alias used for the NFS mount source.
/// Shows as the server name in Finder sidebar instead of "127.0.0.1".
const NFS_HOSTNAME: &str = "kin.local";

/// Ensure the `kin.local` hostname resolves to 127.0.0.1.
///
/// Adds a `/etc/hosts` entry if not already present. Requires sudo on
/// first run — the user sees a password prompt in their terminal.
pub fn ensure_hostname_alias() -> Result<()> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    if hosts.contains(NFS_HOSTNAME) {
        return Ok(());
    }

    info!("adding {NFS_HOSTNAME} to /etc/hosts (requires admin privileges)");
    let entry = format!("127.0.0.1 {NFS_HOSTNAME}");
    let status = Command::new("sudo")
        .args(["sh", "-c", &format!("echo '{}' >> /etc/hosts", entry)])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("failed to update /etc/hosts")?;

    if !status.success() {
        // Non-fatal: fall back to 127.0.0.1 (shows IP in Finder instead of name)
        tracing::warn!("could not add {NFS_HOSTNAME} to /etc/hosts — Finder will show 127.0.0.1");
    }
    Ok(())
}

/// Mount the NFS share at the given mount point.
///
/// On first run, ensures the `kin.local` hostname alias exists so Finder
/// shows "kin.local" in the sidebar instead of "127.0.0.1".
pub fn mount_nfs(port: u16, mount_point: &Path) -> Result<()> {
    ensure_mount_point(mount_point)?;
    ensure_hostname_alias()?;

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
    let host = nfs_host();
    let opts = format!(
        "tcp,port={port},mountport={port},nolockd,noresvport,vers=3"
    );
    debug!(command = "mount", host = %host, opts = %opts, "mounting");
    Command::new("mount")
        .args(["-t", "nfs", "-o", &opts, &format!("{host}:/"), mount_point.to_str().unwrap()])
        .output()
        .context("failed to run mount -t nfs")
}

#[cfg(target_os = "linux")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    let host = nfs_host();
    let opts = format!("nolock,tcp,port={port},mountport={port},vers=3");
    debug!(command = "mount", host = %host, opts = %opts, "mounting");
    Command::new("mount")
        .args([
            "-t",
            "nfs",
            "-o",
            &opts,
            &format!("{host}:/"),
            mount_point.to_str().unwrap(),
        ])
        .output()
        .context("failed to run mount")
}

#[cfg(target_os = "windows")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    let host = nfs_host();
    debug!(command = "mount", host = %host, "mounting (Windows)");
    Command::new("mount")
        .args([
            "-o",
            &format!("nolock,port={port}"),
            &format!("\\\\{host}\\kin"),
            mount_point.to_str().unwrap(),
        ])
        .output()
        .context("failed to run mount")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn mount_command(_port: u16, _mount_point: &Path) -> Result<std::process::Output> {
    bail!("NFS mount not supported on this platform")
}

/// Unmount the NFS share. Handles stacked mounts by unmounting all layers.
pub fn unmount(mount_point: &Path) -> Result<()> {
    if !is_mounted(mount_point)? {
        info!(path = %mount_point.display(), "not mounted, nothing to unmount");
        return Ok(());
    }

    // Use unmount_all to handle stacked mounts (from repeated mount calls).
    #[cfg(unix)]
    unmount_all(mount_point)?;

    #[cfg(not(unix))]
    {
        let output = unmount_command(mount_point)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("unmount failed (exit {}): {}", output.status.code().unwrap_or(-1), stderr.trim());
        }
    }

    if is_mounted(mount_point)? {
        bail!("failed to fully unmount {}", mount_point.display());
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

/// Check if a path is currently an NFS mount point by parsing `mount` output.
/// More reliable than device-ID comparison for NFS mounts that can stack.
#[cfg(unix)]
pub fn is_mounted(mount_point: &Path) -> Result<bool> {
    let mp_str = mount_point.to_str().unwrap_or("");
    if mp_str.is_empty() {
        return Ok(false);
    }

    let output = Command::new("mount")
        .output()
        .context("failed to run mount")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().any(|line| line.contains(&format!(" on {mp_str} "))))
}

/// Unmount all stacked mounts at a path. NFS mounts can stack if mount is
/// called multiple times on the same path. This loops until none remain.
#[cfg(unix)]
pub fn unmount_all(mount_point: &Path) -> Result<()> {
    let mut attempts = 0;
    while is_mounted(mount_point)? && attempts < 10 {
        let _ = unmount_command(mount_point);
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
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
