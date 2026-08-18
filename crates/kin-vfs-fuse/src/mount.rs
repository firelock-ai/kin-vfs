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
use crate::write::WorkspaceWriter;

/// Errors from mount/unmount operations.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("mount point does not exist: {0}")]
    MountPointNotFound(PathBuf),

    #[error("mount point is not a directory: {0}")]
    MountPointNotDir(PathBuf),

    #[error("mount point is not empty: {0}")]
    MountPointNotEmpty(PathBuf),

    #[error(
        "refusing to mount a workspace onto itself or inside itself: \
         mount point {mount_point} is within workspace {workspace}. \
         A write through the mount lands on the workspace path underneath it, \
         so this would fold the projection back onto its own source. \
         Pick a mount point outside the workspace."
    )]
    MountPointInsideWorkspace {
        mount_point: PathBuf,
        workspace: PathBuf,
    },

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
        // The mount goes through the setuid helper, not through a linked
        // library, so the helper that exists is the capability that exists.
        if which("fusermount3").is_some() {
            return Ok(FuseVariant::Fusermount3);
        }
        if which("fusermount").is_some() {
            return Ok(FuseVariant::Fusermount);
        }

        Err(MountError::FuseNotAvailable(format!(
            "the FUSE helper (fusermount3) is not installed. Install it with: {}",
            linux_fuse_install_line()
        )))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(MountError::FuseNotAvailable(
            "FUSE mount mode is only supported on macOS and Linux".to_string(),
        ))
    }
}

/// The exact command that installs the FUSE helper on this Linux host.
///
/// A generic "install fuse3" leaves the reader to work out their own package
/// manager, which is the step that actually stalls someone who has never
/// mounted anything. `/etc/os-release` already names the distribution, so the
/// message can name one command that will work.
#[cfg(target_os = "linux")]
pub fn linux_fuse_install_line() -> String {
    install_line_for(&std::fs::read_to_string("/etc/os-release").unwrap_or_default())
}

/// Decide the install command from the contents of an `os-release` file.
#[cfg(target_os = "linux")]
fn install_line_for(release: &str) -> String {
    let field = |key: &str| -> String {
        release
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or("")
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
    };
    let ids = format!("{} {}", field("ID="), field("ID_LIKE="));

    if ids.contains("debian") || ids.contains("ubuntu") {
        "sudo apt-get install -y fuse3".to_string()
    } else if ids.contains("fedora") || ids.contains("rhel") || ids.contains("centos") {
        "sudo dnf install -y fuse3".to_string()
    } else if ids.contains("alpine") {
        "sudo apk add fuse3".to_string()
    } else if ids.contains("arch") {
        "sudo pacman -S --noconfirm fuse3".to_string()
    } else if ids.contains("suse") {
        "sudo zypper install -y fuse3".to_string()
    } else {
        "your package manager's fuse3 package (it provides /usr/bin/fusermount3)".to_string()
    }
}

/// Which FUSE implementation is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseVariant {
    /// macFUSE kernel extension.
    MacFuse,
    /// FUSE-T userspace FUSE (macOS).
    FuseT,
    /// Linux, FUSE 3.x: mounted through the setuid `fusermount3` helper.
    ///
    /// Named for the helper rather than for a library because nothing is
    /// linked: the crate hands the mount to `fusermount3` and receives the
    /// `/dev/fuse` descriptor back over a socket.
    Fusermount3,
    /// Linux, FUSE 2.x: mounted through the older `fusermount` helper.
    Fusermount,
}

impl std::fmt::Display for FuseVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacFuse => write!(f, "macFUSE"),
            Self::FuseT => write!(f, "FUSE-T"),
            Self::Fusermount3 => write!(f, "fusermount3"),
            Self::Fusermount => write!(f, "fusermount"),
        }
    }
}

/// Whether the kernel-side auto-unmount can be armed on this host.
///
/// `fusermount3` refuses `allow_other` for a non-root user unless
/// `/etc/fuse.conf` carries an uncommented `user_allow_other`, and libfuse
/// requires `allow_other` (or `allow_root`) whenever `auto_unmount` is asked
/// for. So the default Debian/Ubuntu configuration cannot arm auto-unmount for
/// an ordinary user, and the failure it produces names neither cause: the mount
/// dies with `ENOENT`, which reads as a missing path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoUnmountPolicy {
    /// Auto-unmount can be armed.
    Available,
    /// Auto-unmount cannot be armed, with the reason and the one-line fix.
    Unavailable { reason: String, remedy: String },
}

impl AutoUnmountPolicy {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Decide whether auto-unmount can be armed for the current user.
pub fn auto_unmount_policy() -> AutoUnmountPolicy {
    #[cfg(target_os = "linux")]
    {
        // Root may pass allow_other regardless of /etc/fuse.conf.
        if unsafe { libc::geteuid() } == 0 {
            return AutoUnmountPolicy::Available;
        }
        if fuse_conf_allows_other() {
            return AutoUnmountPolicy::Available;
        }
        AutoUnmountPolicy::Unavailable {
            reason: "auto-unmount needs the allow_other mount option, and fusermount3 \
                     grants that to a non-root user only when /etc/fuse.conf carries \
                     user_allow_other"
                .to_string(),
            remedy: "echo user_allow_other | sudo tee -a /etc/fuse.conf".to_string(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        AutoUnmountPolicy::Available
    }
}

/// Whether `/etc/fuse.conf` carries an uncommented `user_allow_other`.
///
/// The line must stand alone; the shipped file documents the option in a
/// comment block, so a substring match on the whole file reports every default
/// installation as permitting it.
#[cfg(target_os = "linux")]
fn fuse_conf_allows_other() -> bool {
    std::fs::read_to_string("/etc/fuse.conf")
        .map(|conf| conf_allows_other(&conf))
        .unwrap_or(false)
}

/// Decide the `allow_other` policy from the contents of an `fuse.conf`.
#[cfg(target_os = "linux")]
fn conf_allows_other(conf: &str) -> bool {
    conf.lines().any(|line| line.trim() == "user_allow_other")
}

/// Everything a caller needs to know before it starts a mount.
#[derive(Debug, Clone)]
pub struct MountPreflight {
    /// The FUSE implementation that will service the mount.
    pub variant: FuseVariant,
    /// Whether auto-unmount can be armed, and what to do when it cannot.
    pub auto_unmount: AutoUnmountPolicy,
}

/// Check everything that can be checked before a mount is attempted.
///
/// This exists so a missing dependency is refused up front with the exact
/// command that fixes it, rather than surfacing several layers down as a
/// kernel errno that names neither the dependency nor the fix.
pub fn preflight(mount_point: &Path, workspace_root: &Path) -> Result<MountPreflight, MountError> {
    let variant = fuse_available()?;

    if !mount_point.exists() {
        return Err(MountError::MountPointNotFound(mount_point.to_path_buf()));
    }
    if !mount_point.is_dir() {
        return Err(MountError::MountPointNotDir(mount_point.to_path_buf()));
    }

    // A write through the mount lands on the workspace path beneath it, so a
    // mount point inside the workspace would have the projection writing into
    // its own source.
    let mount_canonical = mount_point
        .canonicalize()
        .unwrap_or_else(|_| mount_point.to_path_buf());
    let workspace_canonical = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    if mount_canonical.starts_with(&workspace_canonical) {
        return Err(MountError::MountPointInsideWorkspace {
            mount_point: mount_canonical,
            workspace: workspace_canonical,
        });
    }

    Ok(MountPreflight {
        variant,
        auto_unmount: auto_unmount_policy(),
    })
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
    /// Mount read-only. Set automatically from whether a writer is supplied:
    /// with `MountOption::RO` in place the kernel refuses writes before they
    /// ever reach the filesystem, so a writable mount must not carry it.
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
    mount_blocking_with_writer(provider, options, None)
}

/// Mount a `ContentProvider`, optionally accepting writes through it.
///
/// With a writer, saved bytes land on the workspace's real path and the graph
/// must acknowledge the change before the operation reports success. Without
/// one the mount is read-only and every mutation returns EROFS.
///
/// This function blocks until the filesystem is unmounted. The caller should
/// run it on a dedicated thread or in a blocking task.
///
/// # Errors
///
/// Returns `MountError` if the mount point doesn't exist or isn't a directory,
/// if FUSE is not available, or if the mount operation itself fails.
pub fn mount_blocking_with_writer<P: ContentProvider + 'static>(
    provider: Arc<P>,
    options: MountOptions,
    writer: Option<Arc<WorkspaceWriter>>,
) -> Result<(), MountError> {
    // Validate mount point.
    if !options.mount_point.exists() {
        return Err(MountError::MountPointNotFound(options.mount_point.clone()));
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

    let writable = writer.is_some();
    let fs = match writer {
        Some(writer) => KinFuseFs::writable(provider, uid, gid, writer),
        None => KinFuseFs::new(provider, uid, gid),
    };

    // Build FUSE mount options.
    let mut fuse_options = vec![
        fuser::MountOption::FSName(options.fs_name),
        fuser::MountOption::NoAtime,
        fuser::MountOption::DefaultPermissions,
    ];
    if options.read_only {
        fuse_options.push(fuser::MountOption::RO);
    }

    // Auto-unmount is what keeps a killed mount process from leaving a dead
    // mount point behind, so it is armed wherever the host permits it. Where
    // the host does not, mounting without it beats refusing to mount at all,
    // but the loss is stated rather than absorbed.
    if options.auto_unmount {
        match auto_unmount_policy() {
            AutoUnmountPolicy::Available => {
                fuse_options.push(fuser::MountOption::AutoUnmount);
            }
            AutoUnmountPolicy::Unavailable { reason, remedy } => {
                tracing::warn!(
                    "mounting without auto-unmount: {reason}. \
                     Enable it with: {remedy}. \
                     Until then, a mount whose process is killed leaves a stale \
                     mount point behind; clear it with `kin-vfs unmount`."
                );
            }
        }
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
        "mounting kin-vfs at {} (variant: {variant}, writable: {writable})",
        options.mount_point.display(),
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
            .map_err(|e| MountError::UnmountFailed(format!("failed to run {cmd}: {e}")))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_commented_out_option_does_not_permit_allow_other() {
        // The shipped /etc/fuse.conf documents the option in a comment block.
        // A substring search over the whole file reports every default Debian
        // and Ubuntu install as permitting it, and the mount then dies with a
        // kernel ENOENT that names neither the option nor the file.
        let shipped =
            "# user_allow_other - Using the allow_other mount option\n\n#user_allow_other\n";
        assert!(!conf_allows_other(shipped));
        assert!(conf_allows_other("user_allow_other\n"));
        assert!(conf_allows_other(
            "mount_max = 1000\n  user_allow_other  \n"
        ));
        assert!(!conf_allows_other("user_allow_other_but_not_really\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_install_line_names_this_host_package_manager() {
        assert_eq!(
            install_line_for("ID=debian\nVERSION_ID=\"12\"\n"),
            "sudo apt-get install -y fuse3"
        );
        assert_eq!(
            install_line_for("ID=ubuntu\nID_LIKE=debian\n"),
            "sudo apt-get install -y fuse3"
        );
        assert_eq!(install_line_for("ID=fedora\n"), "sudo dnf install -y fuse3");
        assert_eq!(install_line_for("ID=alpine\n"), "sudo apk add fuse3");
        // An unknown distribution still names the package rather than
        // guessing a command that would fail.
        assert!(install_line_for("ID=plan9\n").contains("fuse3"));
    }

    #[test]
    fn a_mount_point_inside_the_workspace_is_refused() {
        // A write through the mount lands on the workspace path beneath it, so
        // this would have the projection writing into its own source.
        let workspace = TempDir::new().unwrap();
        let inside = workspace.path().join("mnt");
        std::fs::create_dir(&inside).unwrap();

        match preflight(&inside, workspace.path()) {
            Err(MountError::MountPointInsideWorkspace { .. }) => {}
            Err(MountError::FuseNotAvailable(_)) => {
                // No FUSE on this host: the refusal under test cannot be
                // reached, so there is nothing to assert.
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_workspace_root_itself_is_refused_as_a_mount_point() {
        let workspace = TempDir::new().unwrap();
        match preflight(workspace.path(), workspace.path()) {
            Err(MountError::MountPointInsideWorkspace { .. }) => {}
            Err(MountError::FuseNotAvailable(_)) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_mount_point_outside_the_workspace_is_allowed_through() {
        let workspace = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        match preflight(elsewhere.path(), workspace.path()) {
            Ok(_) | Err(MountError::FuseNotAvailable(_)) => {}
            other => panic!("expected the check to pass, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_mount_point_is_named_as_missing() {
        let workspace = TempDir::new().unwrap();
        let missing = TempDir::new().unwrap().path().join("nope");
        match preflight(&missing, workspace.path()) {
            Err(MountError::MountPointNotFound(_)) | Err(MountError::FuseNotAvailable(_)) => {}
            other => panic!("expected a missing mount point, got {other:?}"),
        }
    }
}
