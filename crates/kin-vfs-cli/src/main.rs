// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs CLI: start, stop, and query the VFS daemon.
//! With the `fuse` feature: mount and unmount FUSE virtual mounts.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use kin_vfs_core::ContentProvider;
use kin_vfs_daemon::{KinDaemonProvider, VfsDaemonServer};

#[derive(Parser)]
#[command(name = "kin-vfs", about = "Virtual filesystem daemon for Kin")]
enum Cli {
    /// Start the VFS daemon for a workspace.
    Start {
        /// Path to the workspace root (must contain .kin/).
        #[arg(long, default_value = ".")]
        workspace: String,
    },
    /// Stop the running VFS daemon.
    Stop {
        /// Path to the workspace root (must contain .kin/).
        #[arg(long, default_value = ".")]
        workspace: String,
    },
    /// Show VFS daemon status.
    Status {
        /// Path to the workspace root (must contain .kin/).
        #[arg(long, default_value = ".")]
        workspace: String,
    },

    /// Mount the VFS as a FUSE filesystem (requires macFUSE/FUSE-T or libfuse).
    #[cfg(feature = "fuse")]
    Mount {
        /// Path to the workspace root (must contain .kin/).
        #[arg(long, default_value = ".")]
        workspace: String,
        /// Directory to mount the virtual filesystem at.
        #[arg(long)]
        mount_point: String,
        /// Allow other users to access the mount.
        #[arg(long, default_value_t = false)]
        allow_other: bool,
        /// Disable auto-unmount on daemon exit.
        #[arg(long, default_value_t = false)]
        no_auto_unmount: bool,
    },

    /// Unmount a FUSE virtual filesystem.
    #[cfg(feature = "fuse")]
    Unmount {
        /// Path where the VFS is mounted.
        #[arg(long)]
        mount_point: String,
    },

    /// Check if FUSE is available on this system.
    #[cfg(feature = "fuse")]
    FuseStatus,
}

/// Find the workspace root by walking up from `start` looking for `.kin/`.
fn find_workspace(start: &Path) -> Result<PathBuf> {
    let mut dir = std::fs::canonicalize(start)
        .with_context(|| format!("cannot resolve path: {}", start.display()))?;
    loop {
        if dir.join(".kin").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!(
                "no .kin/ directory found above {}",
                start.display()
            );
        }
    }
}

fn sock_path(ws: &Path) -> PathBuf {
    ws.join(".kin/vfs.sock")
}

fn pid_path(ws: &Path) -> PathBuf {
    ws.join(".kin/vfs.pid")
}

// ---------------------------------------------------------------------------
// Placeholder ContentProvider — returns empty results for everything.
// Will be replaced by KinDaemonProvider in Phase 5.
// ---------------------------------------------------------------------------

struct PlaceholderProvider;

impl ContentProvider for PlaceholderProvider {
    fn read_file(&self, path: &str) -> kin_vfs_core::VfsResult<Vec<u8>> {
        Err(kin_vfs_core::VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn read_range(&self, path: &str, _offset: u64, _len: u64) -> kin_vfs_core::VfsResult<Vec<u8>> {
        Err(kin_vfs_core::VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn stat(&self, path: &str) -> kin_vfs_core::VfsResult<kin_vfs_core::VirtualStat> {
        Err(kin_vfs_core::VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn read_dir(&self, path: &str) -> kin_vfs_core::VfsResult<Vec<kin_vfs_core::DirEntry>> {
        Err(kin_vfs_core::VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn exists(&self, _path: &str) -> kin_vfs_core::VfsResult<bool> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Check if kin-daemon is running on the default port.
fn kin_daemon_available() -> bool {
    let provider = KinDaemonProvider::default_local();
    provider.is_available()
}

async fn cmd_start(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let sock = sock_path(&ws);
    let pid_file = pid_path(&ws);

    // If the socket already exists, the daemon may be running.
    if sock.exists() {
        // Quick check: try connecting.
        match tokio::net::UnixStream::connect(&sock).await {
            Ok(_) => {
                println!(
                    "VFS daemon already running on {}",
                    sock.display()
                );
                return Ok(());
            }
            Err(_) => {
                // Stale socket — clean it up.
                let _ = std::fs::remove_file(&sock);
            }
        }
    }

    // Write our PID before starting so stop can find us.
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file: {}", pid_file.display()))?;

    // Choose provider: use KinDaemonProvider if kin-daemon is running,
    // otherwise fall back to PlaceholderProvider.
    let result = if kin_daemon_available() {
        let provider = KinDaemonProvider::default_local();
        let server = VfsDaemonServer::new(provider, &sock);

        println!(
            "VFS daemon started on {} (workspace: {}, provider: kin-daemon)",
            sock.display(),
            ws.display()
        );

        server.run().await
    } else {
        eprintln!("warning: kin-daemon not reachable on :4219 — VFS will serve empty results");
        eprintln!("         Start kin-daemon first, then restart kin-vfs");

        let provider = PlaceholderProvider;
        let server = VfsDaemonServer::new(provider, &sock);

        println!(
            "VFS daemon started on {} (workspace: {}, provider: placeholder)",
            sock.display(),
            ws.display()
        );

        server.run().await
    };

    // Clean up on exit.
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);

    result.map_err(Into::into)
}

async fn cmd_stop(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let pid_file = pid_path(&ws);
    let sock = sock_path(&ws);

    if !pid_file.exists() {
        bail!("no PID file found — is the daemon running?");
    }

    let pid_str = std::fs::read_to_string(&pid_file)
        .with_context(|| format!("failed to read PID file: {}", pid_file.display()))?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}: {:?}", pid_file.display(), pid_str))?;

    // Send SIGTERM.
    // Safety: we're sending a standard signal to a process we own.
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // ESRCH means the process is already gone — that's fine, just clean up.
        if err.raw_os_error() != Some(libc::ESRCH) {
            bail!("failed to send SIGTERM to PID {}: {}", pid, err);
        }
    }

    // Clean up socket and PID file.
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);

    println!("VFS daemon stopped (PID {})", pid);
    Ok(())
}

async fn cmd_status(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let sock = sock_path(&ws);
    let pid_file = pid_path(&ws);

    println!("Workspace: {}", ws.display());
    println!("Socket:    {}", sock.display());

    if !sock.exists() {
        println!("Status:    stopped (no socket)");
        return Ok(());
    }

    // Read PID if available.
    let pid = if pid_file.exists() {
        std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
    } else {
        None
    };

    // Try connecting to verify the daemon is actually alive.
    match tokio::net::UnixStream::connect(&sock).await {
        Ok(_stream) => {
            print!("Status:    running");
            if let Some(p) = pid {
                print!(" (PID {})", p);
            }
            println!();
        }
        Err(_) => {
            println!("Status:    stopped (stale socket)");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// FUSE mount/unmount subcommands
// ---------------------------------------------------------------------------

#[cfg(feature = "fuse")]
fn cmd_mount(
    workspace: &str,
    mount_point: &str,
    allow_other: bool,
    auto_unmount: bool,
) -> Result<()> {
    use std::sync::Arc;
    use kin_vfs_fuse::{MountOptions, mount_blocking};

    let ws = find_workspace(Path::new(workspace))?;
    let mp = PathBuf::from(mount_point);

    // Create mount point if it doesn't exist.
    if !mp.exists() {
        std::fs::create_dir_all(&mp)
            .with_context(|| format!("failed to create mount point: {}", mp.display()))?;
    }

    // Choose provider: use KinDaemonProvider if kin-daemon is running.
    let options = MountOptions {
        mount_point: mp.clone(),
        allow_other,
        auto_unmount,
        fs_name: format!("kin-vfs:{}", ws.display()),
        read_only: true,
    };

    if kin_daemon_available() {
        let provider = Arc::new(KinDaemonProvider::default_local());
        println!(
            "Mounting kin-vfs at {} (workspace: {}, provider: kin-daemon)",
            mp.display(),
            ws.display()
        );
        mount_blocking(provider, options)?;
    } else {
        eprintln!("warning: kin-daemon not reachable on :4219 — VFS will serve empty results");
        eprintln!("         Start kin-daemon first, then restart kin-vfs");

        let provider = Arc::new(PlaceholderProvider);
        println!(
            "Mounting kin-vfs at {} (workspace: {}, provider: placeholder)",
            mp.display(),
            ws.display()
        );
        mount_blocking(provider, options)?;
    }

    Ok(())
}

#[cfg(feature = "fuse")]
fn cmd_unmount(mount_point: &str) -> Result<()> {
    let mp = PathBuf::from(mount_point);
    kin_vfs_fuse::unmount(&mp)?;
    println!("Unmounted kin-vfs from {}", mp.display());
    Ok(())
}

#[cfg(feature = "fuse")]
fn cmd_fuse_status() -> Result<()> {
    match kin_vfs_fuse::fuse_available() {
        Ok(variant) => {
            println!("FUSE available: {variant}");
            Ok(())
        }
        Err(e) => {
            println!("FUSE not available: {e}");
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KIN_VFS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli {
        Cli::Start { workspace } => cmd_start(&workspace).await,
        Cli::Stop { workspace } => cmd_stop(&workspace).await,
        Cli::Status { workspace } => cmd_status(&workspace).await,
        #[cfg(feature = "fuse")]
        Cli::Mount {
            workspace,
            mount_point,
            allow_other,
            no_auto_unmount,
        } => {
            // Mount is blocking (FUSE event loop), so run on a blocking thread.
            tokio::task::spawn_blocking(move || {
                cmd_mount(&workspace, &mount_point, allow_other, !no_auto_unmount)
            })
            .await?
        }
        #[cfg(feature = "fuse")]
        Cli::Unmount { mount_point } => cmd_unmount(&mount_point),
        #[cfg(feature = "fuse")]
        Cli::FuseStatus => cmd_fuse_status(),
    }
}
