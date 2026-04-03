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

    /// Start the NFS server and mount at ~/.kin/mnt/.
    #[cfg(feature = "nfs")]
    NfsStart {
        /// Port to bind (0 = pick a free port).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Override mount point.
        #[arg(long)]
        mount_point: Option<String>,
    },

    /// Stop the NFS server and unmount.
    #[cfg(feature = "nfs")]
    NfsStop,

    /// Show NFS server status.
    #[cfg(feature = "nfs")]
    NfsStatus,

    /// Manage registered workspaces (for NFS mount).
    #[cfg(feature = "nfs")]
    Workspaces {
        #[command(subcommand)]
        action: Option<WorkspacesAction>,
    },

    /// Run a command with VFS file interception active.
    ///
    /// Sets DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux) so the
    /// child process sees virtual files from the blob store. Useful for
    /// scripts and CI that don't have the shell hook installed.
    ///
    /// Example: kin-vfs exec --workspace ./my-repo -- cat src/main.rs
    Exec {
        /// Path to the workspace root (must contain .kin/).
        #[arg(long, default_value = ".")]
        workspace: String,
        /// Command and arguments to run under VFS.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[cfg(feature = "nfs")]
#[derive(clap::Subcommand)]
enum WorkspacesAction {
    /// Register a workspace for the NFS mount.
    Add {
        /// Absolute path to the workspace root.
        #[arg(long)]
        path: String,
        /// kin-daemon URL for this workspace.
        #[arg(long, default_value = "http://127.0.0.1:4219")]
        daemon_url: String,
    },
    /// Deregister a workspace.
    Remove {
        /// Display name of the workspace.
        #[arg(long)]
        name: String,
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

/// Find the VFS shim library for the current platform.
fn find_shim_library() -> Option<PathBuf> {
    let name = if cfg!(target_os = "macos") {
        "libkin_vfs_shim.dylib"
    } else if cfg!(target_os = "windows") {
        "kin_vfs_shim.dll"
    } else {
        "libkin_vfs_shim.so"
    };

    // 1. ~/.kin/lib/ (standard install location)
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(&home).join(".kin/lib").join(name);
        if p.exists() {
            return Some(p);
        }
    }

    // 2. Next to current executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
            let lib_p = dir.join("../lib").join(name);
            if lib_p.exists() {
                return Some(lib_p);
            }
        }
    }

    None
}

/// Run a command with VFS interception active.
fn cmd_exec(workspace: &str, command: Vec<String>) -> Result<()> {
    let ws = find_workspace(Path::new(workspace))?;
    let shim = find_shim_library()
        .ok_or_else(|| anyhow::anyhow!(
            "VFS shim library not found. Install kin-vfs or build with: cargo build --release -p kin-vfs-shim"
        ))?;

    let sock = ws.join(".kin/vfs.sock");

    let (cmd, args) = command.split_first()
        .ok_or_else(|| anyhow::anyhow!("no command specified"))?;

    let mut child = std::process::Command::new(cmd);
    child.args(args);

    // Set VFS environment for the child process.
    child.env("KIN_VFS_WORKSPACE", &ws);
    #[cfg(unix)]
    child.env("KIN_VFS_SOCK", &sock);
    #[cfg(target_os = "macos")]
    child.env("DYLD_INSERT_LIBRARIES", &shim);
    #[cfg(target_os = "linux")]
    child.env("LD_PRELOAD", &shim);

    let status = child.status()
        .with_context(|| format!("failed to run: {}", cmd))?;

    std::process::exit(status.code().unwrap_or(1));
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
// NFS subcommands
// ---------------------------------------------------------------------------

#[cfg(feature = "nfs")]
async fn cmd_nfs_start(port: u16, mount_point: Option<String>) -> Result<()> {
    use kin_vfs_nfs::automount;
    use kin_vfs_nfs::registry::WorkspaceRegistry;
    use kin_vfs_nfs::server::{NfsServer, NfsServerConfig};

    let config_path = WorkspaceRegistry::default_config_path();
    let registry = WorkspaceRegistry::load(&config_path)
        .with_context(|| "loading workspace registry")?;

    let entries = registry.list().to_vec();
    if entries.is_empty() {
        eprintln!("warning: no workspaces registered");
        eprintln!("         use `kin-vfs workspaces add --path /path/to/repo` to add one");
    }

    let mut config = NfsServerConfig::default();
    config.port = port;
    if let Some(mp) = mount_point {
        config.mount_point = PathBuf::from(mp);
    }

    let mount_point = config.mount_point.clone();
    let server = NfsServer::start(config, entries).await?;

    println!("NFS server listening on port {}", server.port());

    // Auto-mount.
    match automount::mount_nfs(server.port(), &mount_point) {
        Ok(()) => println!("Mounted at {}", mount_point.display()),
        Err(e) => {
            eprintln!(
                "warning: auto-mount failed: {e}\n         \
                 mount manually: mount_nfs -o locallocks,nolockd,tcp,port={} 127.0.0.1:/ {}",
                server.port(),
                mount_point.display()
            );
        }
    }

    // Block until Ctrl-C.
    tokio::signal::ctrl_c().await?;

    // Unmount and stop.
    let _ = automount::unmount(&mount_point);
    server.shutdown();
    println!("NFS server stopped");

    Ok(())
}

#[cfg(feature = "nfs")]
fn cmd_nfs_stop() -> Result<()> {
    use kin_vfs_nfs::server;

    let state_dir = default_kin_dir_cli();

    let pid = server::read_pid(&state_dir);
    let port = server::read_port(&state_dir);

    match pid {
        Some(pid) if server::is_pid_alive(pid) => {
            // Send SIGTERM.
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            // Unmount.
            if let Some(p) = port {
                let mount_point = state_dir.join("mnt");
                let _ = kin_vfs_nfs::automount::unmount(&mount_point);
                println!("NFS server stopped (PID {pid}, was on port {p})");
            } else {
                println!("NFS server stopped (PID {pid})");
            }
        }
        Some(pid) => {
            println!("NFS server not running (stale PID {pid}), cleaning up state files");
        }
        None => {
            println!("NFS server not running (no PID file)");
        }
    }

    // Clean up state files.
    let _ = std::fs::remove_file(state_dir.join("nfs.port"));
    let _ = std::fs::remove_file(state_dir.join("nfs.pid"));

    Ok(())
}

#[cfg(feature = "nfs")]
fn cmd_nfs_status() -> Result<()> {
    use kin_vfs_nfs::server;

    let state_dir = default_kin_dir_cli();
    let mount_point = state_dir.join("mnt");

    let pid = server::read_pid(&state_dir);
    let port = server::read_port(&state_dir);

    match pid {
        Some(pid) if server::is_pid_alive(pid) => {
            println!("NFS server:  running (PID {})", pid);
            if let Some(p) = port {
                println!("Port:        {}", p);
            }
            let mounted = kin_vfs_nfs::automount::is_mounted(&mount_point).unwrap_or(false);
            println!(
                "Mount:       {} ({})",
                mount_point.display(),
                if mounted { "mounted" } else { "not mounted" }
            );
        }
        Some(pid) => {
            println!("NFS server:  stopped (stale PID {})", pid);
        }
        None => {
            println!("NFS server:  stopped");
        }
    }

    // Show workspaces.
    let config_path = kin_vfs_nfs::registry::WorkspaceRegistry::default_config_path();
    match kin_vfs_nfs::registry::WorkspaceRegistry::load(&config_path) {
        Ok(reg) => {
            let entries = reg.list();
            println!("Workspaces:  {} registered", entries.len());
            for e in entries {
                println!("  {} → {} ({})", e.name, e.path.display(), e.daemon_url);
            }
        }
        Err(e) => {
            println!("Workspaces:  error loading registry: {e}");
        }
    }

    Ok(())
}

#[cfg(feature = "nfs")]
fn cmd_workspaces(action: Option<WorkspacesAction>) -> Result<()> {
    use kin_vfs_nfs::registry::WorkspaceRegistry;

    let config_path = WorkspaceRegistry::default_config_path();
    let mut registry = WorkspaceRegistry::load(&config_path)
        .with_context(|| "loading workspace registry")?;

    match action {
        None => {
            // List workspaces.
            let entries = registry.list();
            if entries.is_empty() {
                println!("No workspaces registered.");
                println!("Add one with: kin-vfs workspaces add --path /path/to/repo");
            } else {
                println!("{} workspace(s):", entries.len());
                for e in entries {
                    println!("  {} → {} ({})", e.name, e.path.display(), e.daemon_url);
                }
            }
        }
        Some(WorkspacesAction::Add { path, daemon_url }) => {
            let path = PathBuf::from(&path);
            let entry = registry.register(path, daemon_url)?;
            println!("Registered workspace: {}", entry.name);
            registry.save()?;
        }
        Some(WorkspacesAction::Remove { name }) => {
            if registry.deregister(&name) {
                println!("Removed workspace: {name}");
                registry.save()?;
            } else {
                bail!("no workspace named '{name}'");
            }
        }
    }

    Ok(())
}

#[cfg(feature = "nfs")]
fn default_kin_dir_cli() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".kin")
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
        #[cfg(feature = "nfs")]
        Cli::NfsStart { port, mount_point } => cmd_nfs_start(port, mount_point).await,
        #[cfg(feature = "nfs")]
        Cli::NfsStop => cmd_nfs_stop(),
        #[cfg(feature = "nfs")]
        Cli::NfsStatus => cmd_nfs_status(),
        #[cfg(feature = "nfs")]
        Cli::Workspaces { action } => cmd_workspaces(action),
        Cli::Exec { workspace, command } => cmd_exec(&workspace, command),
    }
}
