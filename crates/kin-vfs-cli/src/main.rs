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
#[cfg(unix)]
use kin_vfs_core::InterposeStatus;
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
    /// Auto-discover kin workspaces in common locations.
    Discover,
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
            bail!("no .kin/ directory found above {}", start.display());
        }
    }
}

/// Recover the lexical spelling of the repository root supplied to the
/// launcher without resolving symlinks in the child-facing path.
///
/// `find_workspace` intentionally returns the canonical root for daemon/socket
/// identity. Intercepted syscalls may still carry the original spelling (macOS
/// `/var` beside canonical `/private/var`, or a user symlink). The shim cannot
/// call `canonicalize` from inside an interposed libc hook without recursively
/// consulting raw disk, so the launcher passes this already-verified alias.
fn lexical_workspace_alias(start: &Path, canonical_root: &Path) -> Option<PathBuf> {
    if start
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }

    let canonical_start = std::fs::canonicalize(start).ok()?;
    let suffix_depth = canonical_start
        .strip_prefix(canonical_root)
        .ok()?
        .components()
        .count();
    let mut lexical = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    for _ in 0..suffix_depth {
        if !lexical.pop() {
            return None;
        }
    }

    // Popping the canonical suffix depth from a lexical symlink is not itself
    // proof that the result names the repo root. A symlink may target a deep
    // subdirectory (`link -> repo/a/b`), in which case blindly popping two
    // lexical components can widen `link` to its parent or even `/`. Resolve the
    // candidate here, outside the injected child, and accept it only when it is
    // exactly another spelling of the canonical repository root.
    (std::fs::canonicalize(&lexical).ok()?.as_path() == canonical_root).then_some(lexical)
}

#[cfg(target_os = "macos")]
fn macos_system_workspace_alias(canonical_root: &Path) -> Option<PathBuf> {
    for (canonical_prefix, lexical_prefix) in [
        ("/private/var", "/var"),
        ("/private/tmp", "/tmp"),
        ("/private/etc", "/etc"),
    ] {
        if let Ok(suffix) = canonical_root.strip_prefix(canonical_prefix) {
            return Some(Path::new(lexical_prefix).join(suffix));
        }
    }
    None
}

fn trusted_workspace_aliases(start: &Path, canonical_root: &Path) -> Vec<PathBuf> {
    let mut aliases = Vec::new();
    if let Some(alias) = lexical_workspace_alias(start, canonical_root) {
        if alias != canonical_root
            && std::fs::canonicalize(&alias).ok().as_deref() == Some(canonical_root)
        {
            aliases.push(alias);
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(alias) = macos_system_workspace_alias(canonical_root) {
        if alias != canonical_root
            && !aliases.contains(&alias)
            && std::fs::canonicalize(&alias).ok().as_deref() == Some(canonical_root)
        {
            aliases.push(alias);
        }
    }
    aliases
}

fn set_verified_workspace_alias_env(
    child: &mut std::process::Command,
    workspace_aliases: &[PathBuf],
) -> Result<()> {
    // Nested `kin-vfs exec` launches inherit their parent's environment. Clear
    // any prior repo's aliases even when this repo has no verified aliases, or
    // the child could trust a stale parent path (including `/`).
    child.env_remove("KIN_VFS_WORKSPACE_ALIASES");
    if !workspace_aliases.is_empty() {
        let encoded = std::env::join_paths(workspace_aliases)
            .context("workspace alias contains the platform path-list separator")?;
        child.env("KIN_VFS_WORKSPACE_ALIASES", encoded);
    }
    Ok(())
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

// ── Interposition canary ────────────────────────────────────────────────
//
// `kin-vfs exec` is the only launcher that runs a child under interposition.
// If macOS strips DYLD_INSERT_LIBRARIES (SIP/hardened/signed binary) — or Linux
// drops LD_PRELOAD on re-exec — the shim never loads and the child reads raw
// disk, silently serving filesystem bytes as graph truth. To catch that, the
// launcher mints a per-run token, registers it with the daemon's canary
// registry, and injects KIN_VFS_CANARY so the shim announces on load. After the
// child exits, the launcher asks the daemon for the verdict: a never-confirmed
// token means interposition was stripped.

/// Exit code used when a stripped interposition is refused (strict mode).
/// 78 == sysexits.h `EX_CONFIG`: the run could not be trusted.
#[cfg(unix)]
const CANARY_STRIPPED_EXIT_CODE: i32 = 78;

/// What the launcher should do with an interposition verdict.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecVerdict {
    /// Graph-native (or interposition not required) — run is trusted.
    Proceed,
    /// Stripped, non-strict: surface a loud warning but keep the child's exit code.
    Flag,
    /// Stripped, strict (`KIN_VFS_STRICT=1`): refuse — exit non-zero.
    Refuse,
}

/// Pure decision seam: map an interposition verdict + strict flag to a launcher
/// action. Split out so the policy is unit-testable without a daemon or a child.
#[cfg(unix)]
fn launch_outcome(status: InterposeStatus, strict: bool) -> ExecVerdict {
    match status {
        InterposeStatus::Active | InterposeStatus::NotRequired => ExecVerdict::Proceed,
        InterposeStatus::Stripped if strict => ExecVerdict::Refuse,
        InterposeStatus::Stripped => ExecVerdict::Flag,
    }
}

/// Mint a per-launch canary token: a 128-bit CSPRNG nonce, hex-encoded and
/// `kvfs-` prefixed (a URL-safe value that passes `canary::is_valid_token`).
///
/// Uses the OS CSPRNG rather than predictable pid/time inputs — even though the
/// canary is accidental-stripping *detection* (not an adversarial-auth boundary,
/// since the child receives the token via env anyway), an unguessable nonce is
/// correct hygiene and closes the contrived guess-and-race edge. Returns `None`
/// if the OS RNG is somehow unavailable, in which case the caller skips the
/// canary (matching the daemon-unreachable degradation) instead of falling back
/// to a predictable value or panicking.
#[cfg(unix)]
fn mint_canary_token() -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;

    let mut token = String::with_capacity("kvfs-".len() + bytes.len() * 2);
    token.push_str("kvfs-");
    for b in bytes {
        token.push(HEX[(b >> 4) as usize] as char);
        token.push(HEX[(b & 0x0f) as usize] as char);
    }
    Some(token)
}

/// One synchronous request/response round-trip to the VFS daemon over its Unix
/// socket (4-byte big-endian length prefix + MessagePack). Returns `None` if the
/// daemon is unreachable or the exchange fails — callers treat that as "no
/// canary" so `exec` still works without a running daemon.
#[cfg(unix)]
fn daemon_roundtrip(
    sock: &Path,
    request: &kin_vfs_daemon::VfsRequest,
) -> Option<kin_vfs_daemon::VfsResponse> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(sock).ok()?;
    let timeout = Duration::from_millis(500);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = rmp_serde::to_vec(request).ok()?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .ok()?;
    stream.write_all(&payload).ok()?;
    stream.flush().ok()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u32::from_be_bytes(len_buf);
    if len > 16 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).ok()?;
    rmp_serde::from_slice(&buf).ok()
}

/// Register a per-launch canary expectation with the daemon and return the
/// minted token to inject into the child. Returns `None` when the daemon is
/// unreachable — there is then no graph truth to protect, so the canary is
/// skipped and `exec` behaves exactly as before.
#[cfg(unix)]
fn register_canary(sock: &Path) -> Option<String> {
    let token = mint_canary_token()?;
    match daemon_roundtrip(
        sock,
        &kin_vfs_daemon::VfsRequest::CanaryExpect {
            token: token.clone(),
        },
    ) {
        Some(kin_vfs_daemon::VfsResponse::Announced) => Some(token),
        _ => None,
    }
}

/// Ask the daemon for the interposition verdict on a previously-expected token.
#[cfg(unix)]
fn query_canary_verdict(sock: &Path, token: &str) -> Option<InterposeStatus> {
    match daemon_roundtrip(
        sock,
        &kin_vfs_daemon::VfsRequest::CanaryVerdict {
            token: token.to_string(),
        },
    ) {
        Some(kin_vfs_daemon::VfsResponse::CanaryStatus(status)) => Some(status),
        _ => None,
    }
}

/// Run a command with VFS file interception active.
// `shim`/`sock` feed the macOS/Linux env-injection branches below; the Windows
// build (ProjFS, no LD_PRELOAD/DYLD) uses neither, so allow them unused there.
#[cfg_attr(windows, allow(unused_variables))]
fn cmd_exec(workspace: &str, command: Vec<String>) -> Result<()> {
    let workspace_input = Path::new(workspace);
    let ws = find_workspace(workspace_input)?;
    let workspace_aliases = trusted_workspace_aliases(workspace_input, &ws);
    let shim = find_shim_library()
        .ok_or_else(|| anyhow::anyhow!(
            "VFS shim library not found. Install kin-vfs or build with: cargo build --release -p kin-vfs-shim"
        ))?;

    let sock = ws.join(".kin/vfs.sock");

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command specified"))?;

    let mut child = std::process::Command::new(cmd);
    child.args(args);

    // Set VFS environment for the child process.
    child.env("KIN_VFS_WORKSPACE", &ws);
    set_verified_workspace_alias_env(&mut child, &workspace_aliases)?;
    #[cfg(unix)]
    child.env("KIN_VFS_SOCK", &sock);

    // Register the interposition canary and inject its token so the shim
    // announces on load (Unix only; skipped when the daemon is unreachable).
    #[cfg(unix)]
    let canary_token = register_canary(&sock);
    #[cfg(unix)]
    if let Some(token) = &canary_token {
        child.env(kin_vfs_core::canary::CANARY_ENV, token);
    }

    #[cfg(target_os = "macos")]
    child.env("DYLD_INSERT_LIBRARIES", &shim);
    #[cfg(target_os = "linux")]
    child.env("LD_PRELOAD", &shim);

    let status = child
        .status()
        .with_context(|| format!("failed to run: {}", cmd))?;

    // After the child exits, ask the daemon whether the shim announced. A
    // never-confirmed token means interposition was stripped — surface it loudly
    // (and, in strict mode, refuse) instead of silently trusting raw-disk reads
    // as graph truth.
    #[cfg(unix)]
    if let Some(token) = &canary_token {
        if let Some(verdict) = query_canary_verdict(&sock, token) {
            let strict = std::env::var("KIN_VFS_STRICT").as_deref() == Ok("1");
            match launch_outcome(verdict, strict) {
                ExecVerdict::Proceed => {}
                ExecVerdict::Flag => {
                    eprintln!("{}", kin_vfs_core::canary::stripped_error_message(cmd));
                }
                ExecVerdict::Refuse => {
                    eprintln!("{}", kin_vfs_core::canary::stripped_error_message(cmd));
                    std::process::exit(CANARY_STRIPPED_EXIT_CODE);
                }
            }
        }
    }

    std::process::exit(status.code().unwrap_or(1));
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Default kin-daemon URL (fallback when no port file or env override exists).
const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:4219";

/// Resolve the kin-daemon URL for a served repo.
///
/// Precedence: `KIN_DAEMON_URL` env override > the port recorded by the kin
/// daemon in `<repo_root>/.kin/daemon.port` > the `:4219` default. The kin
/// daemon binds an ephemeral port (`find_free_port`) and writes the real port
/// to `.kin/daemon.port` on startup; reading it is what lets a VFS mount reach
/// the *correct* per-repo daemon instead of assuming `:4219`, which a different
/// repo's daemon may have taken.
fn daemon_url(repo_root: &Path) -> String {
    resolve_daemon_url(
        std::env::var("KIN_DAEMON_URL").ok(),
        read_daemon_port(repo_root),
    )
}

/// Pure precedence resolver (env override > port file > default), split out so
/// the ordering is unit-testable without touching the environment or filesystem.
fn resolve_daemon_url(env_override: Option<String>, port_file: Option<u16>) -> String {
    if let Some(url) = env_override
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return url;
    }
    if let Some(port) = port_file {
        return format!("http://127.0.0.1:{port}");
    }
    DEFAULT_DAEMON_URL.to_string()
}

/// Read the daemon's actual port from `<repo_root>/.kin/daemon.port`, the file
/// the kin daemon writes on startup. Mirrors kin-daemon's own `read_port_file`.
fn read_daemon_port(repo_root: &Path) -> Option<u16> {
    std::fs::read_to_string(repo_root.join(".kin").join("daemon.port"))
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
}

/// Check if kin-daemon is running for the given repo (uses [`daemon_url`]).
fn kin_daemon_available(repo_root: &Path) -> bool {
    let provider = KinDaemonProvider::new(daemon_url(repo_root));
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
                println!("VFS daemon already running on {}", sock.display());
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

    let (url, provider) = create_provider(&ws)?;
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
                let resp: kin_vfs_daemon::VfsResponse = rmp_serde::from_slice(&buf).ok()?;
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
            let url = daemon_url(&ws);
            if kin_daemon_available(&ws) {
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

    let (url, provider) = create_provider(&ws)?;
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

            let url = daemon_url(&ws);
            if kin_daemon_available(&ws) {
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
///
/// `repo_root` is the **served** repo's root (the directory containing `.kin/`),
/// so the provider adopts that repo's `.kin/daemon.token` bearer token when the
/// kin-daemon requires one.
fn create_provider(repo_root: &Path) -> Result<(String, KinDaemonProvider)> {
    let session_id = std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let url = daemon_url(repo_root);
    if !kin_daemon_available(repo_root) {
        eprintln!("warning: kin-daemon not reachable at {url}");
        eprintln!("         virtual projections will be unavailable until kin-daemon comes up");
    }
    let provider =
        KinDaemonProvider::with_auth(&url, session_id, Some(repo_root.to_path_buf()), None);
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
    let registry =
        WorkspaceRegistry::load(&config_path).with_context(|| "loading workspace registry")?;

    let entries = registry.list().to_vec();
    if entries.is_empty() {
        eprintln!("warning: no workspaces registered");
        eprintln!("         use `kin-vfs workspaces add --path /path/to/repo` to add one");
    }

    // Auto-start kin-daemon for each workspace that isn't already running.
    for entry in &entries {
        if is_daemon_reachable(&entry.daemon_url) {
            println!(
                "  {} daemon already running at {}",
                entry.name, entry.daemon_url
            );
        } else {
            match auto_start_daemon(entry) {
                Ok(()) => println!("  {} daemon started at {}", entry.name, entry.daemon_url),
                Err(e) => eprintln!("  {} daemon failed to start: {e}", entry.name),
            }
        }
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

/// Check if a kin-daemon is reachable AND has loaded its graph.
/// Just getting HTTP 200 from /health isn't enough — the daemon may be up
/// but still loading the graph, in which case /vfs/tree returns empty.
#[cfg(feature = "nfs")]
fn is_daemon_reachable(url: &str) -> bool {
    let health_url = format!("{url}/health");
    let output = std::process::Command::new("curl")
        .args(["-sf", "--connect-timeout", "2", &health_url])
        .stderr(std::process::Stdio::null())
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            body.contains("\"graph_loaded\":true")
        }
        _ => false,
    }
}

/// Auto-start a kin-daemon for a workspace if not already running.
///
/// Finds the kin-daemon binary and spawns it in the background. Waits
/// briefly for it to become healthy before returning.
#[cfg(feature = "nfs")]
fn auto_start_daemon(entry: &kin_vfs_nfs::registry::WorkspaceEntry) -> Result<()> {
    use anyhow::bail;

    // Find kin-daemon binary.
    let home = std::env::var("HOME").unwrap_or_default();
    let daemon_bin = [
        PathBuf::from(&home).join(".kin/bin/kin-daemon"),
        // Also check next to our own binary.
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("kin-daemon")))
            .unwrap_or_default(),
    ]
    .into_iter()
    .find(|p| p.exists())
    .ok_or_else(|| anyhow::anyhow!("kin-daemon binary not found"))?;

    // Extract port from daemon_url (e.g., "http://127.0.0.1:4221" -> "4221").
    let port = entry.daemon_url.rsplit(':').next().unwrap_or("4219");

    // Spawn daemon in background.
    let child = std::process::Command::new(&daemon_bin)
        .args(["--repo", entry.path.to_str().unwrap_or("."), "--port", port])
        .env_remove("DYLD_INSERT_LIBRARIES")
        .env_remove("LD_PRELOAD")
        .env("KIN_NO_VFS", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning kin-daemon for {}", entry.name))?;

    tracing::info!(
        name = %entry.name,
        pid = child.id(),
        port,
        "started kin-daemon"
    );

    // Wait up to 30 seconds for daemon to load graph.
    // Large repos (500+ files) can take 10-20s to hydrate.
    for _ in 0..150 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if is_daemon_reachable(&entry.daemon_url) {
            return Ok(());
        }
    }

    bail!(
        "daemon started but graph not loaded after 30s at {}",
        entry.daemon_url
    )
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
    let mut registry =
        WorkspaceRegistry::load(&config_path).with_context(|| "loading workspace registry")?;

    match action {
        None => {
            // Auto-discover then list.
            let discovered = registry.discover().unwrap_or_default();
            if !discovered.is_empty() {
                println!("Discovered {} new workspace(s):", discovered.len());
                for name in &discovered {
                    if let Some(entry) = registry.get(name) {
                        println!("  {} → {}", name, entry.path.display());
                    }
                }
                println!();
            }
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
        Some(WorkspacesAction::Discover) => {
            let discovered = registry.discover()?;
            if discovered.is_empty() {
                println!("No new workspaces found.");
            } else {
                println!("Discovered {} workspace(s):", discovered.len());
                for name in &discovered {
                    if let Some(entry) = registry.get(name) {
                        println!("  {} → {}", name, entry.path.display());
                    }
                }
            }
            println!("\n{} total workspace(s) registered.", registry.list().len());
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
    use kin_vfs_fuse::{mount_blocking, MountOptions};
    use std::sync::Arc;

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
    let url = daemon_url(&ws);
    if !kin_daemon_available(&ws) {
        eprintln!("warning: kin-daemon not reachable at {url}");
        eprintln!("         mounted reads will return backend errors until kin-daemon comes up");
    }
    let provider = Arc::new(KinDaemonProvider::with_auth(
        &url,
        session_id,
        Some(ws.clone()),
        None,
    ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that read/mutate `KIN_DAEMON_URL`.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_daemon_url_env_override_wins() {
        // Env override beats both the port file and the default.
        assert_eq!(
            resolve_daemon_url(Some("http://127.0.0.1:9999".to_string()), Some(5050)),
            "http://127.0.0.1:9999"
        );
    }

    #[test]
    fn resolve_daemon_url_uses_port_file_when_no_env() {
        assert_eq!(
            resolve_daemon_url(None, Some(5050)),
            "http://127.0.0.1:5050"
        );
    }

    #[test]
    fn resolve_daemon_url_falls_back_to_default() {
        assert_eq!(resolve_daemon_url(None, None), DEFAULT_DAEMON_URL);
    }

    #[test]
    fn resolve_daemon_url_blank_env_falls_through_to_port_file() {
        // A whitespace-only override is treated as absent.
        assert_eq!(
            resolve_daemon_url(Some("   ".to_string()), Some(5050)),
            "http://127.0.0.1:5050"
        );
        assert_eq!(
            resolve_daemon_url(Some(String::new()), None),
            DEFAULT_DAEMON_URL
        );
    }

    #[test]
    fn read_daemon_port_reads_and_trims() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file → None.
        assert_eq!(read_daemon_port(dir.path()), None);

        let kin = dir.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.port"), "5050\n").unwrap();
        assert_eq!(read_daemon_port(dir.path()), Some(5050));

        // Garbage → None (doesn't panic).
        std::fs::write(kin.join("daemon.port"), "not-a-port").unwrap();
        assert_eq!(read_daemon_port(dir.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_workspace_aliases_preserve_a_symlink_root() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real_root = parent.path().join("real-project");
        let alias_root = parent.path().join("project-link");
        std::fs::create_dir_all(real_root.join(".kin")).unwrap();
        std::fs::create_dir_all(real_root.join("src")).unwrap();
        symlink(&real_root, &alias_root).unwrap();

        let start = alias_root.join("src");
        let canonical = find_workspace(&start).unwrap();
        assert_eq!(canonical, std::fs::canonicalize(&real_root).unwrap());
        assert!(trusted_workspace_aliases(&start, &canonical).contains(&alias_root));
    }

    #[cfg(unix)]
    #[test]
    fn deep_subdirectory_symlink_cannot_widen_the_workspace_alias() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real_root = parent.path().join("real-project");
        let deep_target = real_root.join("a/b");
        let alias_root = parent.path().join("project-link");
        std::fs::create_dir_all(real_root.join(".kin")).unwrap();
        std::fs::create_dir_all(&deep_target).unwrap();
        symlink(&deep_target, &alias_root).unwrap();

        let canonical = find_workspace(&alias_root).unwrap();
        assert_eq!(canonical, std::fs::canonicalize(&real_root).unwrap());
        assert_eq!(lexical_workspace_alias(&alias_root, &canonical), None);

        let aliases = trusted_workspace_aliases(&alias_root, &canonical);
        assert!(!aliases.contains(&parent.path().to_path_buf()));
        assert!(!aliases.contains(&PathBuf::from("/")));
        for alias in aliases {
            assert_eq!(
                std::fs::canonicalize(&alias).unwrap(),
                canonical,
                "every emitted alias must resolve exactly to the repo root"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn shallow_deep_symlink_cannot_export_the_filesystem_root() {
        use std::os::unix::fs::symlink;

        // `/tmp/<temp>/project-link` has three lexical components below `/`.
        // Pointing it three levels below the repository root reproduces the
        // old algorithm's worst case: three suffix pops produced `/`.
        let parent = tempfile::tempdir_in("/tmp").unwrap();
        let real_root = parent.path().join("real-project");
        let deep_target = real_root.join("a/b/c");
        let alias_root = parent.path().join("project-link");
        std::fs::create_dir_all(real_root.join(".kin")).unwrap();
        std::fs::create_dir_all(&deep_target).unwrap();
        symlink(&deep_target, &alias_root).unwrap();

        let canonical = find_workspace(&alias_root).unwrap();
        assert_eq!(lexical_workspace_alias(&alias_root, &canonical), None);

        let aliases = trusted_workspace_aliases(&alias_root, &canonical);
        assert!(!aliases.contains(&PathBuf::from("/")));
        assert!(aliases.iter().all(|alias| {
            std::fs::canonicalize(alias).ok().as_deref() == Some(canonical.as_path())
        }));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_workspace_removes_an_inherited_alias_env() {
        let home = std::env::var_os("HOME").expect("HOME must be set for the test");
        let repo = tempfile::tempdir_in(home).unwrap();
        std::fs::create_dir_all(repo.path().join(".kin")).unwrap();

        let canonical = find_workspace(repo.path()).unwrap();
        let aliases = trusted_workspace_aliases(&canonical, &canonical);
        assert!(aliases.is_empty(), "canonical repo should need no aliases");

        let mut child = std::process::Command::new("unused-test-command");
        child.env("KIN_VFS_WORKSPACE_ALIASES", "/");
        set_verified_workspace_alias_env(&mut child, &aliases).unwrap();

        let aliases_env = child
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new("KIN_VFS_WORKSPACE_ALIASES"));
        assert!(
            matches!(aliases_env, Some((_, None))),
            "the command must explicitly remove any inherited alias value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_shell_hooks_clear_inherited_alias_on_switch_and_deactivation() {
        use std::os::unix::net::UnixListener;

        let root = tempfile::tempdir().unwrap();
        let repo_a = root.path().join("repo-a");
        let repo_b = root.path().join("repo-b");
        std::fs::create_dir_all(repo_a.join(".kin")).unwrap();
        std::fs::create_dir_all(repo_b.join(".kin")).unwrap();
        let repo_a = std::fs::canonicalize(repo_a).unwrap();
        let repo_b = std::fs::canonicalize(repo_b).unwrap();

        // Keep activation from starting a daemon while the shell hook is under
        // test. The hook only checks that this path is a Unix socket.
        let _listener = UnixListener::bind(repo_b.join(".kin/vfs.sock")).unwrap();
        let shell_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../shell");
        let probe = r#"
source "$1" || exit 10
[[ "${KIN_VFS_WORKSPACE:-}" == "$2" ]] || exit 11
[[ -z "${KIN_VFS_WORKSPACE_ALIASES+x}" ]] || exit 12
export KIN_VFS_WORKSPACE_ALIASES="$2"
"$3" || exit 13
[[ "${KIN_VFS_WORKSPACE_ALIASES:-}" == "$2" ]] || exit 14
export KIN_VFS_WORKSPACE_ALIASES=/
_kin_vfs_deactivate || exit 15
[[ -z "${KIN_VFS_WORKSPACE_ALIASES+x}" ]] || exit 16
"#;

        for (shell, hook, refresh, flags) in [
            (
                "/bin/bash",
                "kin-vfs.bash",
                "_kin_vfs_prompt_command",
                &["--noprofile", "--norc"][..],
            ),
            ("/bin/zsh", "kin-vfs.zsh", "_kin_vfs_chpwd", &["-f"][..]),
        ] {
            if !Path::new(shell).is_file() {
                continue;
            }
            let output = std::process::Command::new(shell)
                .args(flags)
                .arg("-c")
                .arg(probe)
                .arg("kin-vfs-shell-test")
                .arg(shell_dir.join(hook))
                .arg(&repo_b)
                .arg(refresh)
                .current_dir(&repo_b)
                .env("KIN_VFS_WORKSPACE", &repo_a)
                .env("KIN_VFS_WORKSPACE_ALIASES", "/")
                .env_remove("DYLD_INSERT_LIBRARIES")
                .env_remove("LD_PRELOAD")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{hook} retained a stale alias during switch/deactivation\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn every_shipped_shell_hook_clears_unverified_workspace_aliases() {
        fn function_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            let source = source
                .split_once(start)
                .unwrap_or_else(|| panic!("missing shell function: {start}"))
                .1;
            source.split_once(end).map_or(source, |(body, _)| body)
        }

        let shell_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../shell");
        let cases = [
            (
                "kin-vfs.bash",
                "_kin_vfs_activate() {",
                "_kin_vfs_deactivate() {",
                "_kin_vfs_prompt_command() {",
                "unset KIN_VFS_WORKSPACE_ALIASES",
            ),
            (
                "kin-vfs.zsh",
                "_kin_vfs_activate() {",
                "_kin_vfs_deactivate() {",
                "_kin_vfs_chpwd() {",
                "unset KIN_VFS_WORKSPACE_ALIASES",
            ),
            (
                "kin-vfs.fish",
                "function _kin_vfs_activate",
                "function _kin_vfs_deactivate",
                "function _kin_vfs_chpwd",
                "set -e KIN_VFS_WORKSPACE_ALIASES",
            ),
            (
                "kin-vfs.ps1",
                "function Enable-KinVfs {",
                "function Disable-KinVfs {",
                "function Invoke-KinVfsLocationCheck {",
                "Remove-Item Env:\\KIN_VFS_WORKSPACE_ALIASES",
            ),
        ];

        for (file, activate, deactivate, refresh, clear) in cases {
            let source = std::fs::read_to_string(shell_dir.join(file)).unwrap();
            for (path, end) in [(activate, deactivate), (deactivate, refresh)] {
                assert!(
                    function_body(&source, path, end).contains(clear),
                    "{file} {path} must clear unverified workspace aliases"
                );
            }
            assert!(
                !function_body(&source, refresh, "__kin_vfs_end_of_checked_functions__")
                    .contains(clear),
                "{file} {refresh} must preserve a verified same-workspace alias"
            );
        }
    }

    #[test]
    fn lexical_workspace_alias_rejects_parent_traversal() {
        assert_eq!(
            lexical_workspace_alias(Path::new("../project"), Path::new("/project")),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_var_root_gets_the_var_alias() {
        assert_eq!(
            macos_system_workspace_alias(Path::new(
                "/private/var/folders/xy/kin-vfs-real-daemon.abc"
            )),
            Some(PathBuf::from("/var/folders/xy/kin-vfs-real-daemon.abc"))
        );
        assert_eq!(
            macos_system_workspace_alias(Path::new("/private/Users/not-an-alias")),
            None
        );
    }

    // ── Interposition canary seams ───────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn minted_canary_token_is_valid_and_unique() {
        use kin_vfs_core::canary::is_valid_token;

        let a = mint_canary_token().expect("OS RNG available");
        let b = mint_canary_token().expect("OS RNG available");

        // Every minted token must pass the registry's own validity check, or the
        // expect/announce/verdict sides would silently disagree.
        assert!(is_valid_token(&a));
        assert!(is_valid_token(&b));

        // Shape: "kvfs-" + 32 hex chars (16 CSPRNG bytes).
        assert!(a.starts_with("kvfs-"));
        assert_eq!(a.len(), "kvfs-".len() + 32);
        assert!(a["kvfs-".len()..].bytes().all(|c| c.is_ascii_hexdigit()));

        // Two CSPRNG draws collide only with negligible (~2^-128) probability.
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn launch_outcome_proceeds_when_graph_native() {
        // Active and NotRequired are both trusted — proceed regardless of strict.
        assert_eq!(
            launch_outcome(InterposeStatus::Active, false),
            ExecVerdict::Proceed
        );
        assert_eq!(
            launch_outcome(InterposeStatus::Active, true),
            ExecVerdict::Proceed
        );
        assert_eq!(
            launch_outcome(InterposeStatus::NotRequired, true),
            ExecVerdict::Proceed
        );
    }

    #[cfg(unix)]
    #[test]
    fn launch_outcome_flags_or_refuses_when_stripped() {
        // Stripped: loud flag by default, hard refuse under strict mode.
        assert_eq!(
            launch_outcome(InterposeStatus::Stripped, false),
            ExecVerdict::Flag
        );
        assert_eq!(
            launch_outcome(InterposeStatus::Stripped, true),
            ExecVerdict::Refuse
        );
    }

    #[test]
    fn daemon_url_precedence_env_then_port_file_then_default() {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved = std::env::var("KIN_DAEMON_URL").ok();
        std::env::remove_var("KIN_DAEMON_URL");

        // No port file, no env → default.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(daemon_url(empty.path()), DEFAULT_DAEMON_URL);

        // Port file present, no env → derived from the file.
        let repo = tempfile::tempdir().unwrap();
        let kin = repo.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.port"), "5050").unwrap();
        assert_eq!(daemon_url(repo.path()), "http://127.0.0.1:5050");

        // Env override beats the port file.
        std::env::set_var("KIN_DAEMON_URL", "http://127.0.0.1:9999");
        assert_eq!(daemon_url(repo.path()), "http://127.0.0.1:9999");

        match saved {
            Some(value) => std::env::set_var("KIN_DAEMON_URL", value),
            None => std::env::remove_var("KIN_DAEMON_URL"),
        }
    }
}
