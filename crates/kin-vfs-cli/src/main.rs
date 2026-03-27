// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs CLI: start, stop, and query the VFS daemon.
//!
//! On Unix (Linux/macOS), the daemon listens on a Unix domain socket.
//! On Windows, the daemon listens on a named pipe (`\\.\pipe\kin-vfs-{hash}`).
//! With the `fuse` feature: mount and unmount FUSE virtual mounts.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
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

#[cfg(unix)]
fn sock_path(ws: &Path) -> PathBuf {
    ws.join(".kin/vfs.sock")
}

fn pid_path(ws: &Path) -> PathBuf {
    ws.join(".kin/vfs.pid")
}

/// Compute the named pipe path for a workspace (Windows).
///
/// Uses a SHA-256 hash of the canonical workspace path to derive a unique,
/// deterministic pipe name. This matches the convention used by the shim's
/// named pipe client in `kin-vfs-shim/src/client.rs`.
#[cfg(windows)]
fn pipe_name_for_workspace(ws: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ws.hash(&mut hasher);
    let hash = hasher.finish();
    format!(r"\\.\pipe\kin-vfs-{:016x}", hash)
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Default kin-daemon URL.
const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:4219";

/// Read the daemon URL from `KIN_DAEMON_URL` env var, falling back to the default.
fn daemon_url() -> String {
    std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| DEFAULT_DAEMON_URL.to_string())
}

/// Check if kin-daemon is running at the configured URL.
fn kin_daemon_available() -> bool {
    let provider = KinDaemonProvider::new(daemon_url());
    provider.is_available()
}

// ── Unix start/stop/status ──────────────────────────────────────────────

#[cfg(unix)]
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
                // Stale socket -- clean it up.
                let _ = std::fs::remove_file(&sock);
            }
        }
    }

    // Write our PID before starting so stop can find us.
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file: {}", pid_file.display()))?;

    let (url, provider) = create_provider()?;
    let server = VfsDaemonServer::new(provider, &sock);

    println!(
        "VFS daemon started on {} (workspace: {}, provider: kin-daemon at {})",
        sock.display(),
        ws.display(),
        url,
    );

    let result = server.run().await;

    // Clean up on exit.
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);

    result.map_err(Into::into)
}

#[cfg(unix)]
async fn cmd_stop(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let pid_file = pid_path(&ws);
    let sock = sock_path(&ws);

    if !pid_file.exists() {
        bail!("no PID file found -- is the daemon running?");
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
        // ESRCH means the process is already gone -- that's fine, just clean up.
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

#[cfg(unix)]
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

    // Try connecting and sending a Ping to verify the daemon is responsive.
    match tokio::net::UnixStream::connect(&sock).await {
        Ok(stream) => {
            let (mut reader, mut writer) = stream.into_split();
            let healthy = async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let ping = rmp_serde::to_vec(&kin_vfs_daemon::VfsRequest::Ping).ok()?;
                writer.write_u32(ping.len() as u32).await.ok()?;
                writer.write_all(&ping).await.ok()?;
                writer.flush().await.ok()?;
                let len = reader.read_u32().await.ok()?;
                let mut buf = vec![0u8; len as usize];
                reader.read_exact(&mut buf).await.ok()?;
                let resp: kin_vfs_daemon::VfsResponse =
                    rmp_serde::from_slice(&buf).ok()?;
                Some(matches!(resp, kin_vfs_daemon::VfsResponse::Pong))
            }
            .await
            .unwrap_or(false);

            print!("Status:    running");
            if let Some(p) = pid {
                print!(" (PID {})", p);
            }
            if healthy {
                print!(", healthy");
            } else {
                print!(", not responding to Ping");
            }
            println!();

            // Show kin-daemon backend status
            let url = daemon_url();
            if kin_daemon_available() {
                println!("Provider:  kin-daemon ({url})");
            } else {
                println!("Provider:  kin-daemon unreachable ({url})");
            }
        }
        Err(_) => {
            println!("Status:    stopped (stale socket)");
        }
    }

    Ok(())
}

// ── Windows start/stop/status ───────────────────────────────────────────

#[cfg(windows)]
async fn cmd_start(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let pipe_name = pipe_name_for_workspace(&ws);
    let pid_file = pid_path(&ws);

    // Write our PID before starting so stop can find us.
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file: {}", pid_file.display()))?;

    let (url, provider) = create_provider()?;
    let server = VfsDaemonServer::new_named_pipe(provider, pipe_name.clone());

    println!(
        "VFS daemon started on {} (workspace: {}, provider: kin-daemon at {})",
        pipe_name,
        ws.display(),
        url,
    );

    let result = server.run().await;

    // Clean up on exit.
    let _ = std::fs::remove_file(&pid_file);

    result.map_err(Into::into)
}

#[cfg(windows)]
async fn cmd_stop(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let pid_file = pid_path(&ws);

    if !pid_file.exists() {
        bail!("no PID file found -- is the daemon running?");
    }

    let pid_str = std::fs::read_to_string(&pid_file)
        .with_context(|| format!("failed to read PID file: {}", pid_file.display()))?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}: {:?}", pid_file.display(), pid_str))?;

    // On Windows, use taskkill to terminate the daemon process.
    let status = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(_) => {
            // Process may already be gone -- that's fine, just clean up.
            tracing::debug!("taskkill returned non-zero (process may already be stopped)");
        }
        Err(e) => {
            bail!("failed to run taskkill for PID {}: {}", pid, e);
        }
    }

    let _ = std::fs::remove_file(&pid_file);

    println!("VFS daemon stopped (PID {})", pid);
    Ok(())
}

#[cfg(windows)]
async fn cmd_status(workspace: &str) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let pipe_name = pipe_name_for_workspace(&ws);
    let pid_file = pid_path(&ws);

    println!("Workspace: {}", ws.display());
    println!("Pipe:      {}", pipe_name);

    // Read PID if available.
    let pid = if pid_file.exists() {
        std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };

    // Try connecting to the named pipe to check if the daemon is running.
    match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe_name) {
        Ok(_client) => {
            print!("Status:    running");
            if let Some(p) = pid {
                print!(" (PID {})", p);
            }
            println!();

            let url = daemon_url();
            if kin_daemon_available() {
                println!("Provider:  kin-daemon ({url})");
            } else {
                println!("Provider:  kin-daemon unreachable ({url})");
            }
        }
        Err(_) => {
            if pid_file.exists() {
                println!("Status:    stopped (stale PID file)");
            } else {
                println!("Status:    stopped");
            }
        }
    }

    Ok(())
}

// ── Shared provider creation ────────────────────────────────────────────

/// Create the KinDaemonProvider, printing a warning if kin-daemon is unreachable.
fn create_provider() -> Result<(String, KinDaemonProvider)> {
    let session_id = std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let url = daemon_url();
    if !kin_daemon_available() {
        eprintln!("warning: kin-daemon not reachable at {url}");
        eprintln!("         virtual projections will be unavailable until kin-daemon comes up");
    }
    let provider = KinDaemonProvider::with_session(&url, session_id);
    Ok((url, provider))
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

    let options = MountOptions {
        mount_point: mp.clone(),
        allow_other,
        auto_unmount,
        fs_name: format!("kin-vfs:{}", ws.display()),
        read_only: true,
    };

    // Pass through KIN_SESSION_ID for session-scoped projections.
    let session_id = std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let url = daemon_url();
    if !kin_daemon_available() {
        eprintln!("warning: kin-daemon not reachable at {url}");
        eprintln!("         mounted reads will return backend errors until kin-daemon comes up");
    }
    let provider = Arc::new(KinDaemonProvider::with_session(&url, session_id));
    println!(
        "Mounting kin-vfs at {} (workspace: {}, provider: kin-daemon at {})",
        mp.display(),
        ws.display(),
        url,
    );
    mount_blocking(provider, options)?;

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
