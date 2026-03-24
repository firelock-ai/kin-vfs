// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs CLI: start, stop, and query the VFS daemon.

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
    }
}
