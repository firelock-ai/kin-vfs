// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OS-specific NFS mount/unmount helpers.
//!
//! Handles the platform-specific commands to mount the NFS share:
//! - macOS: `mount_nfs` (built-in)
//! - Linux: `mount -t nfs` (built-in)
//! - Windows: `mount` or `net use` (built-in NFS client)

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// Where a system tool is allowed to come from.
///
/// `Command::new("mount")` resolves through `PATH`, and `PATH` belongs to
/// whoever started the process. A `mount`, `umount`, `diskutil` or `sudo`
/// planted earlier in it runs with this process's rights, and the `sudo` case
/// harvests the password the user is about to type into a prompt that looks
/// exactly right. These directories are root-owned on both platforms and
/// SIP-protected on macOS, so naming the tool out of them rather than out of
/// the environment is the whole fix.
#[cfg(unix)]
const TOOL_DIRECTORIES: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// The absolute path of a system tool, refused when it is not in one of the
/// trusted directories.
///
/// Refusing rather than falling back to `PATH`: a fallback would make the
/// guard advisory, and the caller's own error path already handles a mount
/// command that could not run.
#[cfg(unix)]
pub fn system_tool(name: &str) -> Result<PathBuf> {
    for directory in TOOL_DIRECTORIES {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "{name} was not found in any of {}; refusing to resolve it through PATH, \
         where a planted binary would run in its place",
        TOOL_DIRECTORIES.join(", ")
    )
}

/// The Windows equivalent: system tools live under `%SystemRoot%\System32`,
/// and `PATH` is searched only after the application directory there, so the
/// same planting works.
#[cfg(windows)]
pub fn system_tool(name: &str) -> Result<PathBuf> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let candidate = Path::new(&root).join("System32").join(name);
    if candidate.is_file() {
        return Ok(candidate);
    }
    bail!(
        "{name} was not found at {}; refusing to resolve it through PATH",
        candidate.display()
    )
}

/// Ensure the mount point directory exists.
pub fn ensure_mount_point(mount_point: &Path) -> Result<()> {
    if mount_point.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(mount_point)
        .with_context(|| format!("creating mount point {}", mount_point.display()))?;
    info!(path = %mount_point.display(), "created mount point directory");
    Ok(())
}

/// The NFS host to use in mount commands.
///
/// `kin.local` reads better in the Finder sidebar than `127.0.0.1`, and it is
/// used only when it resolves to loopback and nothing else. The name is an
/// mDNS name: on a shared network any machine can answer for it, and "does it
/// resolve" is answered `true` by an attacker's host as readily as by the
/// `/etc/hosts` line this tool adds. Mounting there would send every read and
/// write of the projection to that machine, so anything but loopback falls
/// back to the literal address.
fn nfs_host() -> &'static str {
    if resolves_only_to_loopback(NFS_HOSTNAME) {
        NFS_HOSTNAME
    } else {
        debug!(
            host = NFS_HOSTNAME,
            "not loopback; mounting 127.0.0.1 instead"
        );
        "127.0.0.1"
    }
}

/// Whether every address `host` resolves to is a loopback address.
fn resolves_only_to_loopback(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addresses) = format!("{host}:0").to_socket_addrs() else {
        return false;
    };
    all_loopback(addresses.map(|address| address.ip()))
}

/// Whether a resolution is entirely loopback.
///
/// An empty resolution is `false`, not `true`: a name that resolves to nothing
/// is not a name that resolves to loopback, and `all` over an empty set says
/// yes. That is the shape this function exists to get right, so it is the case
/// the tests below start from.
fn all_loopback(addresses: impl IntoIterator<Item = std::net::IpAddr>) -> bool {
    let mut seen = false;
    for address in addresses {
        seen = true;
        if !address.is_loopback() {
            return false;
        }
    }
    seen
}

/// The hostname alias used for the NFS mount source.
/// Shows as the server name in Finder sidebar instead of "127.0.0.1".
const NFS_HOSTNAME: &str = "kin.local";

/// Whether `/etc/hosts` already maps something to `host`.
///
/// A substring search over the whole file answers yes to a commented-out line
/// and to a longer name that merely contains this one, and both mean the entry
/// is not there. Each line is `<address> <name>...` up to an optional `#`
/// comment, so the names are the fields after the first, compared whole.
fn hosts_file_names(hosts: &str, host: &str) -> bool {
    hosts.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("");
        line.split_whitespace().skip(1).any(|name| name == host)
    })
}

/// Ensure the `kin.local` hostname resolves to 127.0.0.1.
///
/// Adds a `/etc/hosts` entry if not already present. Requires sudo on
/// first run — the user sees a password prompt in their terminal.
pub fn ensure_hostname_alias() -> Result<()> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    if hosts_file_names(&hosts, NFS_HOSTNAME) {
        return Ok(());
    }

    info!("adding {NFS_HOSTNAME} to /etc/hosts (requires admin privileges)");
    let entry = format!("127.0.0.1 {NFS_HOSTNAME}");
    let shell = system_tool("sh")?;
    let status = Command::new(system_tool("sudo")?)
        .arg(shell)
        .args(["-c", &format!("echo '{}' >> /etc/hosts", entry)])
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
    let opts = format!("tcp,port={port},mountport={port},nolockd,noresvport,vers=3");
    debug!(command = "mount", host = %host, opts = %opts, "mounting");
    Command::new(system_tool("mount")?)
        .args([
            "-t",
            "nfs",
            "-o",
            &opts,
            &format!("{host}:/"),
            mount_point.to_str().unwrap(),
        ])
        .output()
        .context("failed to run mount -t nfs")
}

#[cfg(target_os = "linux")]
fn mount_command(port: u16, mount_point: &Path) -> Result<std::process::Output> {
    let host = nfs_host();
    let opts = format!("nolock,tcp,port={port},mountport={port},vers=3");
    debug!(command = "mount", host = %host, opts = %opts, "mounting");
    Command::new(system_tool("mount")?)
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
    Command::new(system_tool("mount.exe")?)
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
            bail!(
                "unmount failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            );
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
    Command::new(system_tool("diskutil")?)
        .args(["unmount", mount_point.to_str().unwrap()])
        .output()
        .context("failed to run diskutil unmount")
}

#[cfg(target_os = "linux")]
fn unmount_command(mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "umount", "unmounting");
    Command::new(system_tool("umount")?)
        .arg(mount_point.to_str().unwrap())
        .output()
        .context("failed to run umount")
}

#[cfg(target_os = "windows")]
fn unmount_command(mount_point: &Path) -> Result<std::process::Output> {
    debug!(command = "net use /delete", "unmounting (Windows)");
    Command::new(system_tool("net.exe")?)
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
    // Compare resolved paths. `mount` reports the real path, and on macOS both
    // `/tmp` and `$TMPDIR` are symlinks, so a literal string compare answers
    // "not mounted" for a healthy mount under either of them. That reads
    // exactly like a mount that never happened, which is how a mounted export
    // came to report itself unmounted and an unmount then skipped it.
    let Some(target) = resolved(mount_point) else {
        return Ok(false);
    };

    let output = Command::new(system_tool("mount")?)
        .output()
        .context("failed to run mount")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().any(|line| {
        mounted_path(line)
            .and_then(|path| resolved(Path::new(path)))
            .is_some_and(|path| path == target)
    }))
}

/// The mount point in one `mount` output line, which reads
/// `<source> on <path> (<options>)`.
#[cfg(unix)]
fn mounted_path(line: &str) -> Option<&str> {
    let after = line.split_once(" on ")?.1;
    // Options always follow, so the last " (" is the boundary. Splitting on the
    // first would truncate any mount point containing " (" in its own name.
    Some(after[..after.rfind(" (")?].trim())
}

/// A path with symlinks resolved, or `None` when it does not exist.
#[cfg(unix)]
fn resolved(path: &Path) -> Option<std::path::PathBuf> {
    std::fs::canonicalize(path).ok()
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

    #[test]
    fn a_mount_line_yields_its_mount_point() {
        assert_eq!(
            mounted_path("kin.local:/ on /Users/x/Kin (nfs, nodev, nosuid)"),
            Some("/Users/x/Kin")
        );
        // A mount point whose own name contains " (" still ends at the options.
        assert_eq!(
            mounted_path("kin.local:/ on /Users/x/My (old) Kin (nfs, nodev)"),
            Some("/Users/x/My (old) Kin")
        );
        assert_eq!(mounted_path("not a mount line"), None);
    }

    #[test]
    fn a_resolution_counts_as_loopback_only_when_every_address_is() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let loopback_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        assert!(all_loopback([loopback_v4]));
        assert!(all_loopback([loopback_v4, loopback_v6]));
        // The mDNS case: a machine on the LAN answers for `kin.local` beside
        // the hosts-file entry, and mounting there sends the projection to it.
        assert!(!all_loopback([loopback_v4, lan]));
        assert!(!all_loopback([lan]));
        // A name that resolves to nothing is not loopback. `all` over an empty
        // iterator would have said it was.
        assert!(!all_loopback([]));
    }

    #[test]
    fn a_literal_loopback_address_resolves_to_loopback() {
        // No DNS: `ToSocketAddrs` parses a literal without a lookup, so this
        // is the wiring control for the function above with nothing on the
        // network able to change the answer.
        assert!(resolves_only_to_loopback("127.0.0.1"));
        assert!(!resolves_only_to_loopback("192.0.2.1"));
    }

    #[test]
    fn the_hosts_entry_is_read_as_a_mapping_rather_than_as_a_substring() {
        assert!(hosts_file_names("127.0.0.1 kin.local\n", "kin.local"));
        assert!(hosts_file_names(
            "127.0.0.1\tlocalhost kin.local other\n",
            "kin.local"
        ));
        // A commented-out line is not an entry, and the substring test the
        // guard replaced answered yes to both of these.
        assert!(!hosts_file_names(
            "# kin.local is not set up\n",
            "kin.local"
        ));
        assert!(!hosts_file_names(
            "127.0.0.1 host # kin.local\n",
            "kin.local"
        ));
        // A longer name that merely contains this one is a different host.
        assert!(!hosts_file_names(
            "127.0.0.1 not-kin.local.example\n",
            "kin.local"
        ));
        // The address column is never a name.
        assert!(!hosts_file_names("kin.local 127.0.0.1\n", "kin.local"));
        assert!(!hosts_file_names("", "kin.local"));
    }

    #[cfg(unix)]
    #[test]
    fn a_system_tool_is_named_absolutely_or_refused() {
        let shell = system_tool("sh").expect("every unix host has a shell");
        assert!(
            shell.is_absolute() && TOOL_DIRECTORIES.iter().any(|d| shell.starts_with(d)),
            "a tool must be named out of a trusted directory, got {shell:?}"
        );
        assert!(
            system_tool("kin-vfs-tool-that-does-not-exist").is_err(),
            "an absent tool must be refused rather than left to PATH"
        );
    }

    /// The bug this guards: `/tmp` is a symlink to `/private/tmp` on macOS, so
    /// `mount` reports the resolved path and a literal compare against the
    /// symlinked one finds nothing.
    #[test]
    fn a_symlinked_path_and_its_target_resolve_to_one_answer() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(resolved(&link), resolved(&real));
        assert!(resolved(&real).is_some());
        assert!(resolved(&dir.path().join("absent")).is_none());
    }
}
