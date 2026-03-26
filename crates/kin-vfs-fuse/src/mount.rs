// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FUSE mount lifecycle: mount, unmount, and availability detection.
//!
//! Supports macFUSE (kernel extension) and FUSE-T (userspace FUSE) on macOS,
//! and libfuse on Linux. The mount is read-only — the virtual filesystem
//! serves files from a `ContentProvider` at the specified mount point.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_vfs_core::ContentProvider;

use crate::filesystem::KinFuseFs;

/// Errors from mount/unmount operations.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("mount point does not exist: {0}")]
    MountPointNotFound(PathBuf),

    #[error("mount point is not a directory: {0}")]
    MountPointNotDir(PathBuf),

    #[error("mount point is not empty: {0}")]
    MountPointNotEmpty(PathBuf),

    #[error("FUSE not available: {0}")]
    FuseNotAvailable(String),

    #[error("mount failed: {0}")]
    MountFailed(String),

    #[error("unmount failed: {0}")]
    UnmountFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Check if macFUSE or FUSE-T is available on the system.
///
/// On macOS, checks for:
/// 1. FUSE-T (preferred, userspace): `/usr/local/lib/libfuse-t.dylib`
/// 2. macFUSE (kernel ext): `/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse`
///
/// On Linux, checks for:
/// 1. `fusermount3` (FUSE 3.x)
/// 2. `fusermount` (FUSE 2.x)
pub fn fuse_available() -> Result<FuseVariant, MountError> {
    #[cfg(target_os = "macos")]
    {
        // FUSE-T: userspace FUSE (preferred — no kernel extension needed).
        if Path::new("/usr/local/lib/libfuse-t.dylib").exists()
            || Path::new("/opt/homebrew/lib/libfuse-t.dylib").exists()
        {
            return Ok(FuseVariant::FuseT);
        }

        // macFUSE: kernel extension.
        if Path::new("/Library/Filesystems/macfuse.fs").exists() {
            return Ok(FuseVariant::MacFuse);
        }

        Err(MountError::FuseNotAvailable(
            "neither macFUSE nor FUSE-T is installed. \
             Install via: brew install macfuse  (or)  brew install fuse-t"
                .to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    {
        // Check for fusermount3 (FUSE 3.x) or fusermount (FUSE 2.x).
        for cmd in &["fusermount3", "fusermount"] {
            if which(cmd).is_some() {
                return Ok(FuseVariant::LibFuse);
            }
        }

        Err(MountError::FuseNotAvailable(
            "libfuse not found. Install via: apt install fuse3  (or)  dnf install fuse3"
                .to_string(),
        ))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(MountError::FuseNotAvailable(
            "FUSE mount mode is only supported on macOS and Linux".to_string(),
        ))
    }
}

/// Which FUSE implementation is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseVariant {
    /// macFUSE kernel extension.
    MacFuse,
    /// FUSE-T userspace FUSE (macOS).
    FuseT,
    /// libfuse (Linux).
    LibFuse,
}

impl std::fmt::Display for FuseVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacFuse => write!(f, "macFUSE"),
            Self::FuseT => write!(f, "FUSE-T"),
            Self::LibFuse => write!(f, "libfuse"),
        }
    }
}

/// Options for mounting the FUSE filesystem.
pub struct MountOptions {
    /// Path to mount the virtual filesystem.
    pub mount_point: PathBuf,
    /// Allow non-root users to access the mount (requires `user_allow_other` in /etc/fuse.conf).
    pub allow_other: bool,
    /// Enable auto-unmount when the daemon exits.
    pub auto_unmount: bool,
    /// Filesystem name shown in `mount` output and `df`.
    pub fs_name: String,
    /// Read-only mount (always true for kin-vfs, but explicit for FUSE options).
    pub read_only: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mount_point: PathBuf::new(),
            allow_other: false,
            auto_unmount: true,
            fs_name: "kin-vfs".to_string(),
            read_only: true,
        }
    }
}

/// Mount a `ContentProvider` as a FUSE filesystem at the given mount point.
///
/// This function blocks until the filesystem is unmounted (via `umount` or
/// the returned `BackgroundMount` handle). The caller should run this on a
/// dedicated thread or in a blocking task.
///
/// # Errors
///
/// Returns `MountError` if:
/// - The mount point doesn't exist or isn't an empty directory
/// - FUSE is not available on the system
/// - The mount operation itself fails
pub fn mount_blocking<P: ContentProvider + 'static>(
    provider: Arc<P>,
    options: MountOptions,
) -> Result<(), MountError> {
    // Validate mount point.
    if !options.mount_point.exists() {
        return Err(MountError::MountPointNotFound(
            options.mount_point.clone(),
        ));
    }
    if !options.mount_point.is_dir() {
        return Err(MountError::MountPointNotDir(options.mount_point.clone()));
    }

    // Check that FUSE is available and log the variant.
    let variant = fuse_available()?;
    tracing::info!("FUSE variant detected: {variant}");

    // Get the mounting user's uid/gid.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let fs = KinFuseFs::new(provider, uid, gid);

    // Build FUSE mount options.
    let mut fuse_options = vec![
        fuser::MountOption::FSName(options.fs_name),
        fuser::MountOption::RO,
        fuser::MountOption::NoAtime,
        fuser::MountOption::DefaultPermissions,
    ];

    if options.auto_unmount {
        fuse_options.push(fuser::MountOption::AutoUnmount);
    }
    if options.allow_other {
        fuse_options.push(fuser::MountOption::AllowOther);
    }

    // Additional macOS-specific options.
    #[cfg(target_os = "macos")]
    {
        // volname sets the volume name shown in Finder.
        fuse_options.push(fuser::MountOption::CUSTOM("volname=kin-vfs".to_string()));
        // noapplexattr suppresses Apple extended attribute operations.
        fuse_options.push(fuser::MountOption::CUSTOM("noapplexattr".to_string()));
        // noappledouble suppresses ._* resource fork files.
        fuse_options.push(fuser::MountOption::CUSTOM("noappledouble".to_string()));
    }

    tracing::info!(
        "mounting kin-vfs at {} (variant: {variant}, read-only: {})",
        options.mount_point.display(),
        options.read_only,
    );

    fuser::mount2(fs, &options.mount_point, &fuse_options)
        .map_err(|e| MountError::MountFailed(e.to_string()))?;

    tracing::info!(
        "FUSE filesystem unmounted from {}",
        options.mount_point.display()
    );

    Ok(())
}

/// Unmount a FUSE filesystem at the given path.
///
/// On macOS, uses `umount`. On Linux, uses `fusermount -u` or `fusermount3 -u`.
pub fn unmount(mount_point: &Path) -> Result<(), MountError> {
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("umount")
            .arg(mount_point)
            .status()
            .map_err(|e| MountError::UnmountFailed(format!("failed to run umount: {e}")))?;

        if !status.success() {
            return Err(MountError::UnmountFailed(format!(
                "umount exited with status {}",
                status
            )));
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Try fusermount3 first, fall back to fusermount.
        let cmd = if which("fusermount3").is_some() {
            "fusermount3"
        } else {
            "fusermount"
        };

        let status = std::process::Command::new(cmd)
            .arg("-u")
            .arg(mount_point)
            .status()
            .map_err(|e| {
                MountError::UnmountFailed(format!("failed to run {cmd}: {e}"))
            })?;

        if !status.success() {
            return Err(MountError::UnmountFailed(format!(
                "{cmd} exited with status {}",
                status
            )));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return Err(MountError::UnmountFailed(
            "unmount not supported on this platform".to_string(),
        ));
    }

    Ok(())
}

/// Check if a command exists in PATH.
#[cfg(target_os = "linux")]
fn which(cmd: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(cmd);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}
