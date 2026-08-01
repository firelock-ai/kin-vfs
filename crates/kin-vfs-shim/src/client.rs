// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Synchronous VFS daemon client.
//!
//! On Unix (Linux/macOS), uses `std::os::unix::net::UnixStream`.
//! On Windows, uses named pipes (`\\.\pipe\kin-vfs-{hash}`).
//!
//! Uses std I/O (NOT tokio) because the shim runs inside arbitrary host
//! processes that may not have an async runtime.
//!
//! Each thread gets its own connection via `thread_local!` to avoid locking.

#[cfg(not(target_os = "windows"))]
use std::cell::Cell;
use std::cell::RefCell;
#[cfg(not(target_os = "windows"))]
use std::ffi::CString;
use std::io::{Read, Write};
#[cfg(not(target_os = "windows"))]
use std::os::raw::c_void;
#[cfg(not(target_os = "windows"))]
use std::os::unix::net::UnixStream;
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

static AUTHORITY_UNAVAILABLE_WARNED: AtomicBool = AtomicBool::new(false);

// ── Backoff constants ────────────────────────────────────────────────────

/// Initial delay before the first reconnection retry.
const BACKOFF_INITIAL_MS: u64 = 50;
/// Maximum delay between reconnection retries.
const BACKOFF_MAX_MS: u64 = 200;
/// Maximum number of reconnection attempts before giving up.
/// With 3 retries and 50/100/200ms backoff, total wall time is ~500ms max.
/// This prevents the shim from blocking indefinitely when the daemon is down.
const BACKOFF_MAX_RETRIES: u32 = 3;

/// Timeout for a single Unix socket connect attempt.
/// Prevents blocking indefinitely on stale socket files.
#[cfg(not(target_os = "windows"))]
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

use kin_vfs_core::{DirEntry, VfsPath, VirtualStat};

#[cfg(not(target_os = "windows"))]
use crate::protocol::ErrorCode;
use crate::protocol::{VfsRequest, VfsResponse};

/// Maximum frame payload: 16 MiB (must match daemon).
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Read/write timeout.
#[cfg(not(target_os = "windows"))]
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ── Unix socket client (Linux/macOS) ────────────────────────────────────

#[cfg(not(target_os = "windows"))]
thread_local! {
    static CLIENT: RefCell<Option<SyncVfsClient>> = const { RefCell::new(None) };
}

#[cfg(not(target_os = "windows"))]
thread_local! {
    static LAST_FAILURE: Cell<ClientCallFailure> = const { Cell::new(ClientCallFailure::None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCallFailure {
    None,
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    InvalidInput,
    /// The path names a nested-repository (gitlink) boundary with no child
    /// projection; its contents cannot be served without fabricating state.
    UnsupportedBoundary,
    Unreachable,
    Authority,
}

#[cfg(not(target_os = "windows"))]
#[inline]
fn set_last_failure(failure: ClientCallFailure) {
    LAST_FAILURE.with(|cell| cell.set(failure));
}

#[cfg(not(target_os = "windows"))]
#[inline]
pub fn last_call_failure() -> ClientCallFailure {
    LAST_FAILURE.with(Cell::get)
}

#[cfg(not(target_os = "windows"))]
fn response_failure<T>(response: VfsResponse) -> Option<T> {
    let failure = match response {
        VfsResponse::Error {
            code: ErrorCode::NotFound,
            ..
        } => ClientCallFailure::NotFound,
        VfsResponse::Error {
            code: ErrorCode::PermissionDenied,
            ..
        } => ClientCallFailure::PermissionDenied,
        VfsResponse::Error {
            code: ErrorCode::IsDirectory,
            ..
        } => ClientCallFailure::IsDirectory,
        VfsResponse::Error {
            code: ErrorCode::NotDirectory,
            ..
        } => ClientCallFailure::NotDirectory,
        VfsResponse::Error {
            code: ErrorCode::InvalidInput,
            ..
        } => ClientCallFailure::InvalidInput,
        VfsResponse::Error {
            code: ErrorCode::UnsupportedBoundary,
            ..
        } => ClientCallFailure::UnsupportedBoundary,
        _ => ClientCallFailure::Authority,
    };
    set_last_failure(failure);
    None
}

/// Compute a sleep duration with exponential backoff and +/-25% jitter.
///
/// Uses a simple xorshift64 seeded from the thread ID and attempt number
/// to avoid pulling in a PRNG crate (the shim must stay lightweight).
fn backoff_with_jitter(attempt: u32) -> Duration {
    let base_ms = BACKOFF_INITIAL_MS.saturating_mul(1u64 << attempt.min(16));
    let capped_ms = base_ms.min(BACKOFF_MAX_MS);

    // Cheap deterministic jitter: +/-25% of capped_ms.
    // Seed from thread id + attempt to get per-thread, per-attempt variation.
    let thread_id = {
        // std::thread::current().id() returns a ThreadId. We hash the
        // Debug repr as a quick-and-dirty u64 source.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut h);
        h.finish()
    };
    let mut seed = thread_id ^ (attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // xorshift64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;

    let jitter_range = capped_ms / 4; // 25%
    let jitter = if jitter_range > 0 {
        (seed % (jitter_range * 2 + 1)) as i64 - jitter_range as i64
    } else {
        0
    };

    let final_ms = (capped_ms as i64 + jitter).max(1) as u64;
    Duration::from_millis(final_ms)
}

/// Execute a closure with the thread-local client, initializing or
/// reconnecting as needed. Returns `None` if the daemon is unreachable
/// after exponential backoff retries.
#[cfg(not(target_os = "windows"))]
fn with_client<F, T>(sock_path: &Path, mut f: F) -> Option<T>
where
    F: FnMut(&mut SyncVfsClient) -> Option<T>,
{
    // First real daemon contact is the moment to fire the interposition canary:
    // the shim is provably loaded and running in normal (non-constructor)
    // context. Cheap atomic-guarded one-shot; no-op when no token was injected.
    announce_interpose_once(sock_path);

    // Assume reachable until a full reconnect cycle proves otherwise; any path
    // that returns after the daemon answered leaves this cleared.
    set_last_failure(ClientCallFailure::None);

    CLIENT.with(|cell| {
        let mut borrow = cell.borrow_mut();

        // Try existing connection first.
        if let Some(ref mut client) = *borrow {
            if client.sock_path == sock_path {
                if let Some(result) = f(client) {
                    return Some(result);
                }
                if last_call_failure() != ClientCallFailure::None {
                    return None;
                }
                // Request failed — reconnect below.
            }
            *borrow = None;
        }

        // (Re)connect with exponential backoff + jitter.
        for attempt in 0..BACKOFF_MAX_RETRIES {
            if let Some(mut client) = SyncVfsClient::connect(sock_path) {
                let result = f(&mut client);
                if result.is_some() {
                    *borrow = Some(client);
                    return result;
                }
                if last_call_failure() != ClientCallFailure::None {
                    return None;
                }
                // Transport failed after connect. Drop this client and retry.
            }
            std::thread::sleep(backoff_with_jitter(attempt));
        }

        // All retries exhausted — the daemon is genuinely unreachable. Record it
        // so authority callers fail loud instead of reading raw disk.
        set_last_failure(ClientCallFailure::Unreachable);
        if !AUTHORITY_UNAVAILABLE_WARNED.swap(true, AtomicOrdering::Relaxed) {
            eprintln!("kin-vfs-shim: graph authority unreachable after retries");
        }
        None
    })
}

// ── Interposition canary announce ────────────────────────────────────────

/// One-shot guard so the canary is announced at most once per process.
#[cfg(not(target_os = "windows"))]
static ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// Announce, exactly once per process, that the shim loaded with the launch
/// canary token — proving to the daemon that this process is graph-native
/// rather than reading raw disk through stripped interposition.
///
/// A no-op when no `KIN_VFS_CANARY` token was injected (the common case).
///
/// Sent synchronously, on its OWN short-lived connection. The connection must
/// be its own because the thread-local [`CLIENT`]'s `RefCell` may be borrowed by
/// the in-flight `with_client` call that triggered this; the send must be
/// synchronous because the alternative is a race the verdict cannot survive.
///
/// This used to spawn a detached thread to keep the announce off the caller's
/// first read. Nothing joins that thread, so a process that reads one file and
/// exits races its own announce and loses often enough to measure: the daemon
/// then reports `Stripped` for a run whose shim loaded and whose read came from
/// the graph, and under `KIN_VFS_STRICT=1` the launcher refuses that good run.
/// A verdict decided by thread scheduling rather than by evidence is not a
/// verdict. The cost of fixing it is one socket round trip, once per process, on
/// a call that is already doing blocking socket I/O.
#[cfg(not(target_os = "windows"))]
pub fn announce_interpose_once(sock_path: &Path) {
    if ANNOUNCED.swap(true, AtomicOrdering::Relaxed) {
        return;
    }

    let Some(state) = super::shim_state() else {
        return;
    };
    let Some(token) = state.canary_token.clone() else {
        return; // No canary expected for this process — nothing to announce.
    };

    let pid = unsafe { libc::getpid() } as u32;
    let _ = announce_interpose(sock_path, pid, &token);
}

/// Send a single interposition `Announce` handshake to the daemon over a fresh
/// connection. Returns `true` iff the daemon acknowledged with `Announced`.
#[cfg(not(target_os = "windows"))]
pub fn announce_interpose(sock_path: &Path, pid: u32, token: &str) -> bool {
    let Some(mut client) = SyncVfsClient::connect(sock_path) else {
        return false;
    };
    matches!(
        client.roundtrip(&VfsRequest::Announce {
            pid,
            token: token.to_string(),
        }),
        Some(VfsResponse::Announced)
    )
}

/// Tell the daemon that `surface` served a workspace-owned path from raw disk,
/// so the launch token's verdict reads back as bypassed rather than active.
///
/// The announce rides the same connection, ahead of the report. A process that
/// only ever reached the workspace through an uninterposed surface has made no
/// graph call, so the lazy announce in [`with_client`] has not fired; without
/// this the daemon would see a bypass for a token it never saw confirmed and
/// call the run stripped, which is the wrong diagnosis for a shim that loaded.
///
/// Sent synchronously, unlike the load announce: the reporting process may exit
/// immediately after, and a verdict that depends on a detached thread winning
/// that race is not a verdict. Callers gate this to one send per surface, so
/// the cost is one connection per bypass class per process.
///
/// Returns `true` iff the daemon acknowledged the report.
#[cfg(not(target_os = "windows"))]
pub fn report_interpose_bypass(sock_path: &Path, pid: u32, token: &str, surface: &str) -> bool {
    // Whatever happens on this connection, the lazy announce must not fire a
    // second time from another thread with the same token.
    ANNOUNCED.store(true, AtomicOrdering::Relaxed);

    let Some(mut client) = SyncVfsClient::connect(sock_path) else {
        return false;
    };
    let announced = matches!(
        client.roundtrip(&VfsRequest::Announce {
            pid,
            token: token.to_string(),
        }),
        Some(VfsResponse::Announced)
    );
    if !announced {
        return false;
    }
    matches!(
        client.roundtrip(&VfsRequest::CanaryBypass {
            token: token.to_string(),
            surface: surface.to_string(),
        }),
        Some(VfsResponse::Announced)
    )
}

/// Synchronous VFS daemon client over Unix sockets.
#[cfg(not(target_os = "windows"))]
pub struct SyncVfsClient {
    stream: UnixStream,
    sock_path: PathBuf,
}

#[cfg(not(target_os = "windows"))]
impl SyncVfsClient {
    /// Connect to the daemon socket with a timeout.
    ///
    /// Uses non-blocking connect + poll to avoid blocking indefinitely on
    /// stale socket files (which cause UE-state deadlocks on macOS when
    /// the shim runs inside a DYLD constructor).
    fn connect(sock_path: &Path) -> Option<Self> {
        // Non-blocking connect with timeout. If the socket doesn't exist or
        // the daemon isn't listening, connect will fail quickly.
        // NOTE: Do NOT call sock_path.exists() here — it triggers stat(),
        // which the shim intercepts, causing re-entrant RefCell borrow panic.
        let stream = connect_unix_with_timeout(sock_path, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
        let _ = stream.set_nonblocking(false);
        Some(Self {
            stream,
            sock_path: sock_path.to_path_buf(),
        })
    }

    /// Send a request and receive the response.
    fn roundtrip(&mut self, request: &VfsRequest) -> Option<VfsResponse> {
        self.send(request).ok()?;
        self.recv().ok()
    }

    /// Serialize and send a length-prefixed msgpack frame.
    fn send(&mut self, request: &VfsRequest) -> Result<(), ()> {
        let payload = rmp_serde::to_vec(request).map_err(|_| ())?;
        let len = payload.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).map_err(|_| ())?;
        self.stream.write_all(&payload).map_err(|_| ())?;
        self.stream.flush().map_err(|_| ())?;
        Ok(())
    }

    /// Read a length-prefixed msgpack frame and deserialize.
    fn recv(&mut self) -> Result<VfsResponse, ()> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).map_err(|_| ())?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_SIZE {
            return Err(());
        }
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf).map_err(|_| ())?;
        rmp_serde::from_slice(&buf).map_err(|_| ())
    }
}

/// Connect to a Unix socket with a timeout.
///
/// `std::os::unix::net::UnixStream` doesn't have `connect_timeout`, so we
/// use raw libc: create a socket, set non-blocking, connect (returns
/// EINPROGRESS), poll for writability, then switch back to blocking mode.
#[cfg(not(target_os = "windows"))]
fn connect_unix_with_timeout(path: &Path, timeout: Duration) -> Option<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let path_cstr = CString::new(path.to_str()?).ok()?;

    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return None;
        }

        // Set non-blocking for the connect call.
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            libc::close(fd);
            return None;
        }

        // Build sockaddr_un.
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path_cstr.as_bytes_with_nul();
        if path_bytes.len() > addr.sun_path.len() {
            libc::close(fd);
            return None;
        }
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr().cast::<libc::c_char>(),
            addr.sun_path.as_mut_ptr(),
            path_bytes.len(),
        );

        let ret = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        );

        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err != libc::EINPROGRESS && err != libc::EWOULDBLOCK {
                libc::close(fd);
                return None;
            }

            // Poll for writability with timeout.
            let timeout_ms = timeout.as_millis() as libc::c_int;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let poll_ret = libc::poll(&mut pfd, 1, timeout_ms);
            if poll_ret <= 0 {
                // Timeout or error — daemon not responding.
                libc::close(fd);
                return None;
            }

            // Check for connect error via SO_ERROR.
            let mut so_err: libc::c_int = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut _ as *mut c_void,
                &mut len,
            );
            if so_err != 0 {
                libc::close(fd);
                return None;
            }
        }

        // Restore blocking mode.
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);

        Some(UnixStream::from_raw_fd(fd))
    }
}

// ── Named pipe client (Windows) ─────────────────────────────────────────

/// Synchronous VFS daemon client over Windows named pipes.
///
/// Named pipes use the same length-prefixed MessagePack wire format as the
/// Unix socket client. The pipe name follows the convention:
/// `\\.\pipe\kin-vfs-{workspace-hash}`
///
/// # Daemon requirement
///
/// The VFS daemon must expose a named pipe listener on Windows. This module
/// only implements the client side; the daemon's `kin-vfs-daemon` crate
/// needs a corresponding `NamedPipeListener` transport.
#[cfg(target_os = "windows")]
pub struct NamedPipeClient {
    pipe: std::fs::File,
    pipe_name: String,
}

#[cfg(target_os = "windows")]
thread_local! {
    static PIPE_CLIENT: RefCell<Option<NamedPipeClient>> = const { RefCell::new(None) };
}

/// Connect to a named pipe, returning a `File` handle.
///
/// Named pipes on Windows can be opened with `CreateFile` / `std::fs::OpenOptions`.
/// The pipe path looks like `\\.\pipe\kin-vfs-abc123`.
#[cfg(target_os = "windows")]
fn connect_named_pipe(pipe_name: &str) -> Option<std::fs::File> {
    use std::fs::OpenOptions;
    // Named pipes on Windows are opened like regular files.
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)
        .ok()
}

/// Execute a closure with the thread-local named pipe client, initializing
/// or reconnecting as needed. Returns `None` if the daemon is unreachable
/// after exponential backoff retries.
#[cfg(target_os = "windows")]
fn with_pipe_client<F, T>(pipe_name: &str, mut f: F) -> Option<T>
where
    F: FnMut(&mut NamedPipeClient) -> Option<T>,
{
    PIPE_CLIENT.with(|cell| {
        let mut borrow = cell.borrow_mut();

        // Try existing connection first.
        if let Some(ref mut client) = *borrow {
            if client.pipe_name == pipe_name {
                if let Some(result) = f(client) {
                    return Some(result);
                }
                // Request failed — reconnect below.
            }
            *borrow = None;
        }

        // (Re)connect with exponential backoff + jitter.
        for attempt in 0..BACKOFF_MAX_RETRIES {
            if let Some(pipe) = connect_named_pipe(pipe_name) {
                let mut client = NamedPipeClient {
                    pipe,
                    pipe_name: pipe_name.to_string(),
                };
                let result = f(&mut client);
                if result.is_some() {
                    *borrow = Some(client);
                }
                return result;
            }
            std::thread::sleep(backoff_with_jitter(attempt));
        }

        // All retries exhausted — report unavailable graph authority.
        if !AUTHORITY_UNAVAILABLE_WARNED.swap(true, AtomicOrdering::Relaxed) {
            eprintln!("kin-vfs-shim: graph authority unreachable after retries");
        }
        None
    })
}

#[cfg(target_os = "windows")]
impl NamedPipeClient {
    /// Send a request and receive the response over the named pipe.
    fn roundtrip(&mut self, request: &VfsRequest) -> Option<VfsResponse> {
        self.send(request).ok()?;
        self.recv().ok()
    }

    /// Serialize and send a length-prefixed msgpack frame.
    fn send(&mut self, request: &VfsRequest) -> Result<(), ()> {
        let payload = rmp_serde::to_vec(request).map_err(|_| ())?;
        let len = payload.len() as u32;
        self.pipe.write_all(&len.to_be_bytes()).map_err(|_| ())?;
        self.pipe.write_all(&payload).map_err(|_| ())?;
        self.pipe.flush().map_err(|_| ())?;
        Ok(())
    }

    /// Read a length-prefixed msgpack frame and deserialize.
    fn recv(&mut self) -> Result<VfsResponse, ()> {
        let mut len_buf = [0u8; 4];
        self.pipe.read_exact(&mut len_buf).map_err(|_| ())?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_SIZE {
            return Err(());
        }
        let mut buf = vec![0u8; len as usize];
        self.pipe.read_exact(&mut buf).map_err(|_| ())?;
        rmp_serde::from_slice(&buf).map_err(|_| ())
    }
}

// ── Repo-aware daemon discovery + auth (write-notify) ───────────────
//
// The shim is a `cdylib` leaf crate (it depends only on `kin-vfs-core`), so it
// cannot import the discovery helper in `kin-vfs-cli` (`daemon_url`) or the
// token resolver in `kin-vfs-daemon` (`auth::resolve_token`). These functions
// mirror those semantics so the write-notify POST reaches the *correct*
// per-repo kin daemon (which binds an ephemeral port and records it in
// `<repo>/.kin/daemon.port`) and carries the bearer token the daemon expects
// once `KIN_DAEMON_REQUIRE_TOKEN` is enabled. The single source of truth for
// these conventions is the kin daemon (kin/crates/kin-daemon/src/api.rs); the
// long-term home for the shared logic is `kin-vfs-core`, which all three
// crates already depend on.

/// Default kin-daemon authority when no port file or env override is present.
const DEFAULT_DAEMON_HOST: &str = "127.0.0.1";
const DEFAULT_DAEMON_PORT: u16 = 4219;

/// Environment override for the kin-daemon URL (matches `kin-vfs-cli`).
const DAEMON_URL_ENV: &str = "KIN_DAEMON_URL";

/// Environment override for the daemon bearer token (matches the daemon's own
/// `auth::AUTH_TOKEN_ENV`, so client and server read the same variable).
const DAEMON_AUTH_TOKEN_ENV: &str = "KIN_DAEMON_AUTH_TOKEN";

/// Resolved daemon connection target for the write-notify POST: the loopback
/// authority to dial and the matching bearer token, if one is configured.
struct NotifyTarget {
    host: String,
    port: u16,
    token: Option<String>,
}

impl NotifyTarget {
    /// `host:port` authority, used for both the TCP connect and the `Host:`
    /// header (the daemon rejects non-public routes whose Host is not on its
    /// loopback allowlist, so this must carry the real authority it dialed).
    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Trim surrounding whitespace and discard an empty result.
fn trim_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Read the daemon's actual port from `<repo_root>/.kin/daemon.port`, the file
/// the kin daemon writes on startup. Mirrors `kin-vfs-cli::read_daemon_port`.
fn read_daemon_port(repo_root: &Path) -> Option<u16> {
    std::fs::read_to_string(repo_root.join(".kin").join("daemon.port"))
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
}

/// Parse the loopback `host:port` out of a `KIN_DAEMON_URL` override. Only the
/// authority is needed because the notify path speaks raw HTTP/1.1 over TCP
/// rather than going through a URL client. A missing port defaults to 4219.
fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.trim().strip_prefix("https://"))
        .unwrap_or_else(|| url.trim());
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let host = if host.is_empty() {
                DEFAULT_DAEMON_HOST.to_string()
            } else {
                host.to_string()
            };
            let port = port.parse().ok()?;
            Some((host, port))
        }
        None => Some((authority.to_string(), DEFAULT_DAEMON_PORT)),
    }
}

/// Pure authority precedence: `KIN_DAEMON_URL` env override > port file > the
/// `:4219` default. Each source is passed explicitly so the ordering is
/// unit-testable without touching the environment or filesystem.
fn resolve_host_port_from(env_url: Option<&str>, port_file: Option<u16>) -> (String, u16) {
    if let Some((host, port)) = env_url.and_then(parse_host_port) {
        return (host, port);
    }
    if let Some(port) = port_file {
        return (DEFAULT_DAEMON_HOST.to_string(), port);
    }
    (DEFAULT_DAEMON_HOST.to_string(), DEFAULT_DAEMON_PORT)
}

/// Resolve the daemon authority with the same precedence the rest of the VFS
/// uses: `KIN_DAEMON_URL` env override > `<repo>/.kin/daemon.port` > `:4219`.
fn resolve_daemon_host_port(repo_root: &Path) -> (String, u16) {
    resolve_host_port_from(
        std::env::var(DAEMON_URL_ENV).ok().as_deref(),
        read_daemon_port(repo_root),
    )
}

/// Pure token precedence (env override > file > none), mirroring the daemon's
/// `auth::resolve_from`. A `None` result means no `Authorization` header is
/// sent — which is correct: the daemon accepts tokenless requests while
/// enforcement is off, and a bare `Bearer ` with no secret must never be sent.
fn resolve_token_from(env_token: Option<&str>, file_token: Option<&str>) -> Option<String> {
    env_token
        .and_then(trim_non_empty)
        .or_else(|| file_token.and_then(trim_non_empty))
}

/// Read and trim `<repo_root>/.kin/daemon.token`, if present and non-empty.
/// Mirrors the daemon's `auth::read_token_file`.
fn read_token_file(repo_root: &Path) -> Option<String> {
    std::fs::read_to_string(repo_root.join(".kin").join("daemon.token"))
        .ok()
        .as_deref()
        .and_then(trim_non_empty)
}

/// Resolve the bearer token with the same precedence as the daemon's
/// `auth::resolve_token`: `KIN_DAEMON_AUTH_TOKEN` env > `<repo>/.kin/daemon.token`
/// > none.
fn resolve_daemon_token(repo_root: &Path) -> Option<String> {
    resolve_token_from(
        std::env::var(DAEMON_AUTH_TOKEN_ENV).ok().as_deref(),
        read_token_file(repo_root).as_deref(),
    )
}

/// Resolve the full notify target (authority + token) for the served repo root.
fn resolve_notify_target(repo_root: &Path) -> NotifyTarget {
    let (host, port) = resolve_daemon_host_port(repo_root);
    let token = resolve_daemon_token(repo_root);
    NotifyTarget { host, port, token }
}

// ── Write-back notification (non-blocking POST to daemon) ───────────

/// Rebuild a filesystem `PathBuf` from the workspace root's exact bytes.
///
/// Used only to locate `.kin/daemon.port` and `.kin/daemon.token` — explicit
/// config IO at the projection boundary, never a semantic answer path.
#[cfg(not(target_os = "windows"))]
fn workspace_root_path(root: &[u8]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    std::path::PathBuf::from(std::ffi::OsStr::from_bytes(root))
}

/// Windows has no byte-path constructor: a root that is not representable is
/// refused rather than coerced, so discovery fails loud instead of reading the
/// wrong repo's daemon config.
#[cfg(target_os = "windows")]
fn workspace_root_path(root: &[u8]) -> std::path::PathBuf {
    match std::str::from_utf8(root) {
        Ok(text) => std::path::PathBuf::from(text),
        Err(_) => std::path::PathBuf::new(),
    }
}

/// Timeout for the daemon TCP connection + request (keeps write path fast).
const NOTIFY_TIMEOUT: Duration = Duration::from_millis(100);

/// Warn-once guard so a persistently unreachable daemon surfaces a single
/// diagnostic line instead of either spamming the host process or failing
/// completely silently. Matches the `FALLBACK_WARNED` convention above.
static NOTIFY_WARNED: AtomicBool = AtomicBool::new(false);

/// Warn-once guard for a lost notification worker (channel send failed because
/// the receiver is gone). Distinct from an unreachable daemon: this means the
/// reconcile signal itself was dropped, which the graph-truth thesis treats as
/// a real fault — surfaced once rather than hidden.
static NOTIFY_WORKER_LOST: AtomicBool = AtomicBool::new(false);

/// Warn-once guard for a write-notify the daemon *received* but did not confirm
/// (a non-2xx status such as 401/409, or `200 {reindexed:false}`). Distinct from
/// an unreachable daemon: the reconcile was reachable but declined/failed, so the
/// graph did not converge on this write. Surfaced once rather than hidden.
static NOTIFY_REJECTED_WARNED: AtomicBool = AtomicBool::new(false);

use std::sync::{mpsc, OnceLock};

/// Singleton sender half of the notification channel.
///
/// The channel is **unbounded**: write-notify is the fast-path reconcile
/// signal that keeps graph truth converged with disk, and silently dropping it
/// (as an earlier bounded `try_send` did) let the graph diverge under write
/// storms while pretending success. An unbounded sender never blocks the write
/// path and never drops; the worker drains it continuously (each POST is capped
/// at [`NOTIFY_TIMEOUT`], so the queue does not grow without bound in practice).
///
/// Holds `None` when the background worker thread could not be spawned, in
/// which case notifications are disabled rather than panicking — a panic here
/// would unwind across the cdylib FFI boundary and abort the host.
static NOTIFY_TX: OnceLock<Option<mpsc::Sender<Vec<u8>>>> = OnceLock::new();

/// Return (or lazily create) the singleton notification sender.
///
/// On first call, spawns a background worker thread that drains the
/// channel and sends HTTP POSTs to the daemon's `/vfs/write-notify`
/// endpoint. The worker runs for the lifetime of the process. Returns
/// `None` if the worker thread cannot be spawned; notifications are then
/// disabled for the lifetime of the process.
pub fn get_notify_sender() -> Option<&'static mpsc::Sender<Vec<u8>>> {
    NOTIFY_TX
        .get_or_init(|| {
            let (tx, rx) = mpsc::channel::<Vec<u8>>();

            std::thread::Builder::new()
                .name("kin-vfs-notify".into())
                .spawn(move || {
                    notify_worker(rx);
                })
                .ok()
                .map(|_| tx)
        })
        .as_ref()
}

/// Background worker: drain the channel and POST each notification to the daemon.
fn notify_worker(rx: mpsc::Receiver<Vec<u8>>) {
    while let Ok(path) = rx.recv() {
        notify_write_sync(&path);
    }
}

/// Notify the daemon that a workspace file was written.
///
/// Enqueues a notification to the background worker thread which POSTs to the
/// repo's kin daemon `/vfs/write-notify` endpoint (authority resolved per repo,
/// not hardcoded). The enqueue is non-blocking and **lossless** (unbounded
/// channel): the reconcile signal is never silently dropped, so the graph stays
/// converged with disk even under write storms. The daemon's file watcher
/// remains a backstop, but correctness no longer depends on it catching up.
///
/// A send can only fail if the worker thread died (receiver dropped); that is a
/// genuine fault for graph truth, so it is surfaced once rather than hidden.
pub fn notify_file_changed(path: &VfsPath) {
    if let Some(tx) = get_notify_sender() {
        if tx.send(path.as_bytes().to_vec()).is_err() {
            warn_notify_worker_lost();
        }
    }
}

/// Build the raw HTTP/1.1 write-notify request for `path`, addressed to
/// `target`. Split out from the socket I/O so request shaping (authority,
/// bearer token, body) is unit-testable without a live daemon.
///
/// The path travels as **canonical bytes**, hex-encoded in the same
/// `{"bytes_hex": …}` envelope `kin_model::RepoPath` serializes to, so the
/// daemon decodes it straight into a `RepoPath`. A JSON string could not
/// represent a non-UTF8 Unix path without lossy replacement, which would
/// misattribute a write to a different (or nonexistent) artifact.
fn build_notify_request(path: &[u8], target: &NotifyTarget) -> String {
    let session_id = super::shim_state().and_then(|s| s.session_id.as_ref());
    let body = if let Some(sid) = session_id {
        format!(
            r#"{{"path":{{"bytes_hex":"{}"}},"session_id":"{}"}}"#,
            hex_encode(path),
            escape_json_string(sid)
        )
    } else {
        format!(r#"{{"path":{{"bytes_hex":"{}"}}}}"#, hex_encode(path))
    };

    // Attach the bearer token only when one resolves: the daemon accepts
    // tokenless requests while enforcement is off, and a bare `Bearer ` with no
    // secret would be rejected. When enforcement is on and no token is found,
    // the daemon answers 401 — observable, never a silent auth bypass.
    let auth_header = match &target.token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };

    format!(
        "POST /vfs/write-notify HTTP/1.1\r\n\
         Host: {host}\r\n\
         {auth}Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        host = target.authority(),
        auth = auth_header,
        len = body.len(),
    )
}

/// Lowercase-hex encode `bytes`.
///
/// Hand-rolled rather than pulling in the `hex` crate: the shim is a cdylib
/// injected into arbitrary host processes and deliberately keeps its
/// dependency surface minimal (same reason the backoff jitter avoids a PRNG
/// crate). Canonical lowercase output is required — the daemon rejects any
/// other encoding.
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Classified daemon reply to a write-notify POST.
///
/// The kin daemon's `/vfs/write-notify` endpoint confirms a reconcile only with
/// `200 {"reindexed":true,...}`. A soft-block or reconcile error is a `200
/// {"reindexed":false,...}`, and auth/veto failures are non-2xx (401/409). The
/// shim must therefore inspect BOTH the status line and the body, not merely the
/// fact that bytes came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyResponse {
    /// `200` with `"reindexed":true` — the daemon accepted and re-indexed.
    Acked,
    /// `2xx` without `"reindexed":true` — reachable, but the reconcile did not
    /// happen (soft-block / reconcile error). Graph did not converge.
    NotReindexed,
    /// Non-2xx status (e.g. 401 auth, 409 write-veto, 5xx). Carries the code.
    Rejected(u16),
    /// No HTTP status line could be parsed from the bytes read.
    Unparsable,
}

/// Transport-level outcome of one write-notify attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyAttempt {
    /// A response was received and classified.
    Responded(NotifyResponse),
    /// Could not connect to the daemon at all.
    Unreachable,
    /// Connected, but the exchange failed mid-flight (write error, or no bytes
    /// read back). Worth one bounded retry.
    Transient,
}

/// Parse a raw HTTP/1.1 response into a [`NotifyResponse`].
///
/// Split from the socket I/O so the status-line + body classification is
/// unit-testable without a live daemon.
fn parse_notify_response(raw: &[u8]) -> NotifyResponse {
    let text = String::from_utf8_lossy(raw);
    let Some(status_line) = text.lines().next() else {
        return NotifyResponse::Unparsable;
    };
    // "HTTP/1.1 200 OK" — the status code is the second whitespace-separated token.
    let Some(code) = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
    else {
        return NotifyResponse::Unparsable;
    };
    if !(200..300).contains(&code) {
        return NotifyResponse::Rejected(code);
    }
    // 2xx: the reconcile actually happened only when `reindexed` is true. The
    // daemon emits compact JSON; tolerate incidental spaces defensively.
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    if body.replace(' ', "").contains("\"reindexed\":true") {
        NotifyResponse::Acked
    } else {
        NotifyResponse::NotReindexed
    }
}

/// Whether an attempt is worth one bounded retry: a transient transport hiccup
/// or a 5xx (server-side, possibly momentary). Deterministic client rejections
/// (4xx: auth/veto/malformed) and definitive replies are never retried.
fn notify_is_retryable(attempt: NotifyAttempt) -> bool {
    match attempt {
        NotifyAttempt::Transient => true,
        NotifyAttempt::Responded(NotifyResponse::Rejected(code)) => (500..600).contains(&code),
        _ => false,
    }
}

/// Perform one write-notify POST and classify the outcome. The response body is
/// tiny (`{"reindexed":true,"entity_count":N}`) and the shim sends
/// `Connection: close`, so we read to EOF under the tight [`NOTIFY_TIMEOUT`],
/// capped so a misbehaving peer can never make the worker read unbounded bytes.
fn attempt_notify(request: &str, target: &NotifyTarget) -> NotifyAttempt {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    /// Upper bound on response bytes read: a valid reply is well under this.
    const MAX_NOTIFY_RESPONSE: usize = 2048;

    let addrs = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return NotifyAttempt::Unreachable,
    };

    let stream = addrs
        .into_iter()
        .find_map(|addr| TcpStream::connect_timeout(&addr, NOTIFY_TIMEOUT).ok());
    let mut stream = match stream {
        Some(s) => s,
        None => return NotifyAttempt::Unreachable,
    };

    let _ = stream.set_write_timeout(Some(NOTIFY_TIMEOUT));
    let _ = stream.set_read_timeout(Some(NOTIFY_TIMEOUT));

    if stream.write_all(request.as_bytes()).is_err() {
        return NotifyAttempt::Transient;
    }

    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= MAX_NOTIFY_RESPONSE {
                    break;
                }
            }
            // Timeout/partial read: classify whatever we have (below).
            Err(_) => break,
        }
    }

    if buf.is_empty() {
        // Wrote the request but the daemon never answered — treat as transient.
        return NotifyAttempt::Transient;
    }
    NotifyAttempt::Responded(parse_notify_response(&buf))
}

/// Synchronous POST to the daemon's write-notify endpoint with a tight timeout,
/// requiring and parsing a successful daemon acknowledgement.
///
/// Resolves the per-repo daemon authority and bearer token from the served
/// workspace root before connecting, so the notification reaches the correct
/// daemon and authenticates once enforcement is on. The outcome is then handled
/// per documented semantics rather than fire-and-forget:
///
/// - `200 {reindexed:true}` — acknowledged; the graph re-indexed the write.
/// - unreachable daemon — warned once; the already-landed projection write is
///   visibly unreconciled and the daemon's watcher remains a backstop.
/// - transient transport error or `5xx` — retried once, then surfaced.
/// - non-2xx (401/409/…) or `200 {reindexed:false}` — surfaced once: the daemon
///   was reached but did not confirm the reconcile, so this write is not known
///   to have converged into the graph.
fn notify_write_sync(path: &[u8]) {
    let Some(state) = super::shim_state() else {
        return;
    };
    let target = resolve_notify_target(&workspace_root_path(&state.workspace_root));
    let request = build_notify_request(path, &target);

    let mut attempt = attempt_notify(&request, &target);
    if notify_is_retryable(attempt) {
        attempt = attempt_notify(&request, &target);
    }

    match attempt {
        NotifyAttempt::Responded(NotifyResponse::Acked) => { /* acknowledged — success */ }
        NotifyAttempt::Unreachable => warn_notify_unreachable(),
        // Reached the daemon but it declined/failed (or a status we could not
        // parse): surface it — do not pretend success.
        NotifyAttempt::Responded(_) | NotifyAttempt::Transient => warn_notify_rejected(),
    }
}

/// Emit a single diagnostic line the first time the write-notify POST cannot
/// reach the daemon, so the failure is observable without spamming the host.
fn warn_notify_unreachable() {
    if !NOTIFY_WARNED.swap(true, AtomicOrdering::Relaxed) {
        eprintln!(
            "kin-vfs-shim: write-notify could not reach the kin daemon; \
             relying on its file watcher to re-index (this warning prints once)"
        );
    }
}

/// Emit a single diagnostic line the first time the daemon *received* a
/// write-notify but did not acknowledge the re-index (non-2xx status, or
/// `200 {reindexed:false}`). Unlike an unreachable daemon, the reconcile was
/// reachable and declined/failed — so this write is not known to have converged
/// into the graph. The daemon's file watcher remains the backstop.
fn warn_notify_rejected() {
    if !NOTIFY_REJECTED_WARNED.swap(true, AtomicOrdering::Relaxed) {
        eprintln!(
            "kin-vfs-shim: the kin daemon did not acknowledge a write-notify \
             (re-index not confirmed); relying on its file watcher to \
             re-index (this warning prints once)"
        );
    }
}

/// Emit a single diagnostic line the first time a write-notify cannot be
/// enqueued because the worker thread is gone. Unlike an unreachable daemon
/// (recoverable via the file watcher), a lost worker means reconcile signals
/// are being dropped for the rest of the process — a real graph-truth fault.
fn warn_notify_worker_lost() {
    if !NOTIFY_WORKER_LOST.swap(true, AtomicOrdering::Relaxed) {
        eprintln!(
            "kin-vfs-shim: write-notify worker is gone; file-change \
             notifications are being dropped (this warning prints once)"
        );
    }
}

/// Escape a string for JSON embedding (handles backslash and double-quote).
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

// ── Public API: Unix socket (called from intercept.rs on Linux/macOS) ───

/// Stat a path via the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_stat(sock_path: &Path, path: &VfsPath) -> Option<VirtualStat> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::Stat { path: path.clone() })?;
        match response {
            VfsResponse::Stat(s) => Some(s),
            other => response_failure(other),
        }
    })
}

/// Read full file content from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_file(sock_path: &Path, path: &VfsPath) -> Option<Vec<u8>> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::Read {
            path: path.clone(),
            offset: 0,
            len: 0, // 0 means "entire file"
        })?;
        match response {
            VfsResponse::Content { data, total_size }
                if usize::try_from(total_size).ok() == Some(data.len()) =>
            {
                Some(data)
            }
            VfsResponse::Content { .. } => {
                set_last_failure(ClientCallFailure::Authority);
                None
            }
            other => response_failure(other),
        }
    })
}

/// Read a byte range from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_range(
    sock_path: &Path,
    path: &VfsPath,
    offset: u64,
    len: u64,
    expected_total: u64,
) -> Option<Vec<u8>> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::Read {
            path: path.clone(),
            offset,
            len,
        })?;
        match response {
            VfsResponse::Content { data, total_size }
                if total_size == expected_total
                    && u64::try_from(data.len()).ok()
                        == Some(len.min(expected_total.saturating_sub(offset))) =>
            {
                Some(data)
            }
            VfsResponse::Content { .. } => {
                set_last_failure(ClientCallFailure::Authority);
                None
            }
            other => response_failure(other),
        }
    })
}

/// List directory entries from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_dir(sock_path: &Path, path: &VfsPath) -> Option<Vec<DirEntry>> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::ReadDir { path: path.clone() })?;
        match response {
            VfsResponse::DirEntries(entries) => Some(entries),
            other => response_failure(other),
        }
    })
}

/// Check if a path exists via the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_exists(sock_path: &Path, path: &VfsPath) -> Option<bool> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::Access {
            path: path.clone(),
            mode: 0, // F_OK
        })?;
        match response {
            VfsResponse::Accessible(b) => Some(b),
            other => response_failure(other),
        }
    })
}

/// Read a symbolic link target from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_link(sock_path: &Path, path: &VfsPath) -> Option<Vec<u8>> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::ReadLink { path: path.clone() })?;
        match response {
            VfsResponse::LinkTarget(target) => Some(target),
            other => response_failure(other),
        }
    })
}

/// Check access with a mode mask via the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_access(sock_path: &Path, path: &VfsPath, mode: u32) -> Option<bool> {
    with_client(sock_path, |c| {
        let response = c.roundtrip(&VfsRequest::Access {
            path: path.clone(),
            mode,
        })?;
        match response {
            VfsResponse::Accessible(b) => Some(b),
            other => response_failure(other),
        }
    })
}

// ── Public API: Named pipe (called from ProjFS callbacks on Windows) ────

/// Stat a path via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_stat_named_pipe(pipe_name: &str, path: &VfsPath) -> Option<VirtualStat> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Stat { path: path.clone() })? {
            VfsResponse::Stat(s) => Some(s),
            _ => None,
        }
    })
}

/// Read full file content from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_file_named_pipe(pipe_name: &str, path: &VfsPath) -> Option<Vec<u8>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.clone(),
            offset: 0,
            len: 0,
        })? {
            VfsResponse::Content { data, .. } => Some(data),
            _ => None,
        }
    })
}

/// Read a byte range from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_range_named_pipe(
    pipe_name: &str,
    path: &VfsPath,
    offset: u64,
    len: u64,
) -> Option<Vec<u8>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.clone(),
            offset,
            len,
        })? {
            VfsResponse::Content { data, .. } => Some(data),
            _ => None,
        }
    })
}

/// List directory entries from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_dir_named_pipe(pipe_name: &str, path: &VfsPath) -> Option<Vec<DirEntry>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::ReadDir { path: path.clone() })? {
            VfsResponse::DirEntries(entries) => Some(entries),
            _ => None,
        }
    })
}

/// Check if a path exists via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_exists_named_pipe(pipe_name: &str, path: &VfsPath) -> Option<bool> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.clone(),
            mode: 0,
        })? {
            VfsResponse::Accessible(b) => Some(b),
            _ => None,
        }
    })
}

/// Read a symbolic link target from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_link_named_pipe(pipe_name: &str, path: &VfsPath) -> Option<Vec<u8>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::ReadLink { path: path.clone() })? {
            VfsResponse::LinkTarget(target) => Some(target),
            _ => None,
        }
    })
}

/// Check access with a mode mask via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_access_named_pipe(pipe_name: &str, path: &VfsPath, mode: u32) -> Option<bool> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.clone(),
            mode,
        })? {
            VfsResponse::Accessible(b) => Some(b),
            _ => None,
        }
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

// Wire-format tests are platform-independent (no socket/pipe needed).
#[cfg(test)]
mod tests {
    use crate::protocol::{ErrorCode, VfsRequest, VfsResponse};
    use kin_vfs_core::{VfsPath, VirtualStat};

    /// Build a validated byte-exact graph path for test fixtures.
    ///
    /// Only the socket-backed tests use it, and those are Unix-only.
    #[cfg(not(target_os = "windows"))]
    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid test path")
    }
    use std::io::{Read, Write};
    #[cfg(not(target_os = "windows"))]
    use std::os::unix::net::UnixListener;
    #[cfg(not(target_os = "windows"))]
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;
    #[cfg(not(target_os = "windows"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(not(target_os = "windows"))]
    fn temp_socket_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(format!(
            "/tmp/kvfs-{}-{}.sock",
            std::process::id(),
            nanos % 1_000_000_000
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn spawn_single_response_server(
        socket_path: &Path,
        response: VfsResponse,
    ) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).expect("bind test socket");
        let socket_path = socket_path.to_path_buf();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).expect("read frame len");
            let len = u32::from_be_bytes(len_buf);
            let mut payload = vec![0u8; len as usize];
            stream.read_exact(&mut payload).expect("read frame payload");
            let _: VfsRequest = rmp_serde::from_slice(&payload).expect("decode request");
            let payload = rmp_serde::to_vec(&response).expect("encode response");
            stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .expect("write response len");
            stream.write_all(&payload).expect("write response payload");
            stream.flush().expect("flush response");
            drop(stream);
            drop(listener);
            let _ = std::fs::remove_file(&socket_path);
        })
    }

    #[test]
    fn request_serialization_roundtrip() {
        let vpath = |bytes: &[u8]| VfsPath::from_bytes(bytes.to_vec()).expect("valid path");
        let requests = vec![
            VfsRequest::Stat {
                path: vpath(b"a/b"),
            },
            VfsRequest::Read {
                path: vpath(b"c"),
                offset: 10,
                len: 100,
            },
            VfsRequest::ReadDir { path: vpath(b"d") },
            VfsRequest::ReadLink {
                path: vpath(b"link"),
            },
            VfsRequest::Access {
                path: vpath(b"e"),
                mode: 4,
            },
            // A non-UTF8 path must survive the wire byte-for-byte.
            VfsRequest::Stat {
                path: vpath(b"logs/x-\xff\xfe.log"),
            },
            VfsRequest::Ping,
        ];

        // Byte-exactness is the contract, not merely "no panic": decode the
        // non-UTF8 request back and compare its exact bytes.
        let raw = vpath(b"logs/x-\xff\xfe.log");
        let wire = rmp_serde::to_vec(&VfsRequest::Stat { path: raw.clone() }).unwrap();
        match rmp_serde::from_slice::<VfsRequest>(&wire).unwrap() {
            VfsRequest::Stat { path } => assert_eq!(path.as_bytes(), raw.as_bytes()),
            other => panic!("expected Stat, got {other:?}"),
        }

        // A malformed path on the wire must be rejected at decode, never
        // accepted as identity.
        for malformed in [&b"/absolute"[..], b"a/../b", b"a//b"] {
            let forged = rmp_serde::to_vec(&serde_bytes_request(malformed)).unwrap();
            assert!(
                rmp_serde::from_slice::<VfsRequest>(&forged).is_err(),
                "{malformed:?} must be rejected at decode"
            );
        }

        for req in &requests {
            let bytes = rmp_serde::to_vec(req).expect("serialize");
            let decoded: VfsRequest = rmp_serde::from_slice(&bytes).expect("deserialize");
            // Just ensure no panic
            let _ = format!("{decoded:?}");
        }
    }

    /// Encode a `VfsRequest::Stat` whose path is arbitrary raw bytes, matching
    /// `VfsPath`'s own `serialize_bytes` shape. Used to prove the decoder
    /// rejects malformed paths rather than trusting the peer.
    fn serde_bytes_request(path: &[u8]) -> impl serde::Serialize + '_ {
        struct Forged<'a>(&'a [u8]);
        impl serde::Serialize for Forged<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStructVariant;
                let mut variant =
                    serializer.serialize_struct_variant("VfsRequest", 0, "Stat", 1)?;
                variant.serialize_field("path", serde_bytes_field(self.0))?;
                variant.end()
            }
        }
        Forged(path)
    }

    /// Raw bytes serialized exactly as `VfsPath` does.
    fn serde_bytes_field(bytes: &[u8]) -> &RawBytes {
        // Safety-free transmute-less view: `RawBytes` is a `#[repr(transparent)]`
        // newtype over `[u8]`, so this is a plain unsizing cast.
        RawBytes::new(bytes)
    }

    #[repr(transparent)]
    struct RawBytes([u8]);

    impl RawBytes {
        fn new(bytes: &[u8]) -> &Self {
            // SAFETY: `RawBytes` is `#[repr(transparent)]` over `[u8]`, so the
            // reference cast is layout-identical.
            unsafe { &*(bytes as *const [u8] as *const RawBytes) }
        }
    }

    impl serde::Serialize for RawBytes {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&self.0)
        }
    }

    #[test]
    fn response_serialization_roundtrip() {
        let responses = vec![
            VfsResponse::Stat(VirtualStat::regular_file(42, [0u8; 32], false, 1000)),
            VfsResponse::Stat(VirtualStat::directory(2000)),
            VfsResponse::Content {
                data: b"hello".to_vec(),
                total_size: 5,
            },
            VfsResponse::LinkTarget(vec![b'.', b'.', b'/', 0xff]),
            VfsResponse::Accessible(true),
            VfsResponse::Pong,
            VfsResponse::Error {
                code: ErrorCode::NotFound,
                message: "gone".into(),
            },
        ];
        for resp in &responses {
            let bytes = rmp_serde::to_vec(resp).expect("serialize");
            let decoded: VfsResponse = rmp_serde::from_slice(&bytes).expect("deserialize");
            let _ = format!("{decoded:?}");
        }

        let target = vec![b'.', b'.', b'/', 0xff];
        let bytes = rmp_serde::to_vec(&VfsResponse::LinkTarget(target.clone())).unwrap();
        match rmp_serde::from_slice::<VfsResponse>(&bytes).unwrap() {
            VfsResponse::LinkTarget(decoded) => assert_eq!(decoded, target),
            other => panic!("expected byte-preserving link target, got {other:?}"),
        }
    }

    #[test]
    fn framing_encode_decode() {
        // Simulate the exact wire format: 4-byte BE length + msgpack payload.
        let req = VfsRequest::Ping;
        let payload = rmp_serde::to_vec(&req).unwrap();
        let len = payload.len() as u32;

        let mut wire = Vec::new();
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(&payload);

        // Decode
        let decoded_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        assert_eq!(decoded_len, len);
        let decoded: VfsRequest = rmp_serde::from_slice(&wire[4..]).unwrap();
        assert!(matches!(decoded, VfsRequest::Ping));
    }

    // ── Notification serialization tests ─────────────────────────────────

    #[test]
    fn escape_json_string_basic() {
        use super::escape_json_string;
        assert_eq!(escape_json_string("src/main.rs"), "src/main.rs");
    }

    #[test]
    fn escape_json_string_special_chars() {
        use super::escape_json_string;
        assert_eq!(
            escape_json_string(r#"path\with"quotes"#),
            r#"path\\with\"quotes"#
        );
        assert_eq!(escape_json_string("line\nnew"), r#"line\nnew"#);
    }

    #[test]
    fn notification_body_is_valid_json() {
        use super::escape_json_string;
        let path = "src/main.rs";
        let body = format!(r#"{{"path":"{}"}}"#, escape_json_string(path));
        assert_eq!(body, r#"{"path":"src/main.rs"}"#);
    }

    #[test]
    fn notification_body_with_special_path() {
        use super::escape_json_string;
        let path = r#"src/file "name".rs"#;
        let body = format!(r#"{{"path":"{}"}}"#, escape_json_string(path));
        // Quotes in path must be escaped.
        assert_eq!(body, r#"{"path":"src/file \"name\".rs"}"#);
    }

    // ── Write-notify discovery + auth tests ──────────────────────────────
    //
    // The precedence resolvers are split into pure functions that take each
    // candidate source as an argument (mirroring the daemon's `auth::resolve_from`)
    // so ordering can be exercised exhaustively without env or filesystem state —
    // the same testing seam the daemon's auth module uses.

    #[test]
    fn parse_host_port_handles_scheme_authority_and_path() {
        use super::parse_host_port;
        assert_eq!(
            parse_host_port("http://127.0.0.1:5050"),
            Some(("127.0.0.1".to_string(), 5050))
        );
        // Scheme is optional; trailing path/query are ignored.
        assert_eq!(
            parse_host_port("127.0.0.1:8080/vfs/write-notify?x=1"),
            Some(("127.0.0.1".to_string(), 8080))
        );
        // No explicit port falls back to the daemon default.
        assert_eq!(
            parse_host_port("http://localhost"),
            Some(("localhost".to_string(), super::DEFAULT_DAEMON_PORT))
        );
        // Empty/garbage authority yields None so the caller falls through.
        assert_eq!(parse_host_port("http://"), None);
        assert_eq!(parse_host_port("http://127.0.0.1:not-a-port"), None);
    }

    #[test]
    fn resolve_host_port_precedence_env_then_port_file_then_default() {
        use super::{resolve_host_port_from, DEFAULT_DAEMON_HOST, DEFAULT_DAEMON_PORT};

        // Env override wins over the port file.
        assert_eq!(
            resolve_host_port_from(Some("http://127.0.0.1:9999"), Some(5050)),
            ("127.0.0.1".to_string(), 9999)
        );
        // Port file is honored when there is no env override.
        assert_eq!(
            resolve_host_port_from(None, Some(5050)),
            ("127.0.0.1".to_string(), 5050)
        );
        // Neither source → the `:4219` default.
        assert_eq!(
            resolve_host_port_from(None, None),
            (DEFAULT_DAEMON_HOST.to_string(), DEFAULT_DAEMON_PORT)
        );
        // A malformed env override falls through to the port file rather than
        // dialing a bad authority.
        assert_eq!(
            resolve_host_port_from(Some("http://"), Some(5050)),
            ("127.0.0.1".to_string(), 5050)
        );
    }

    #[test]
    fn resolve_token_precedence_env_then_file_then_none() {
        use super::resolve_token_from;

        // Env override beats the file token.
        assert_eq!(
            resolve_token_from(Some("env-token"), Some("file-token")).as_deref(),
            Some("env-token")
        );
        // File token is used when there is no env override.
        assert_eq!(
            resolve_token_from(None, Some("file-token")).as_deref(),
            Some("file-token")
        );
        // Neither source → None, so no `Authorization` header is sent.
        assert_eq!(resolve_token_from(None, None), None);
        // Blank sources are treated as absent (never a bare `Bearer `), and the
        // resolved token is trimmed to match what the daemon parses.
        assert_eq!(
            resolve_token_from(Some("   "), Some("  file-token  ")).as_deref(),
            Some("file-token")
        );
        assert_eq!(resolve_token_from(Some(""), Some("   ")), None);
    }

    #[test]
    fn notify_request_omits_auth_header_when_no_token() {
        use super::{build_notify_request, NotifyTarget};
        let target = NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 4219,
            token: None,
        };
        let req = build_notify_request(b"src/main.rs", &target);

        assert!(req.starts_with("POST /vfs/write-notify HTTP/1.1\r\n"));
        // Host carries the resolved authority (the daemon's loopback allowlist
        // rejects non-public routes with a missing/foreign Host).
        assert!(req.contains("Host: 127.0.0.1:4219\r\n"));
        // No token configured → no Authorization header, never a bare Bearer.
        assert!(!req.contains("Authorization:"));
        assert!(req.contains(r#"{"path":{"bytes_hex":"7372632f6d61696e2e7273"}}"#));
    }

    /// The write-notify body must match the fixture the Kin daemon parses.
    /// A change here is a peer-contract change, not a local refactor.
    #[test]
    fn notify_body_matches_the_shared_golden_fixture() {
        use super::hex_encode;

        const FIXTURE: &str = include_str!("../../../tests/fixtures/write-notify.json");

        // The fixture is pretty-printed for review; the wire body is compact.
        // Compare the decoded fields rather than the whitespace.
        let fixture: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("fixture must be valid JSON");
        assert_eq!(
            fixture["path"]["bytes_hex"].as_str().unwrap(),
            hex_encode(b"src/main.rs"),
            "write-notify must carry canonical lowercase-hex path bytes"
        );
        assert_eq!(fixture["session_id"].as_str().unwrap(), "sess-42");

        // And the request the shim actually builds carries that same envelope.
        let target = super::NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 4219,
            token: None,
        };
        let request = super::build_notify_request(b"src/main.rs", &target);
        assert!(
            request.contains(&format!(
                r#""path":{{"bytes_hex":"{}"}}"#,
                hex_encode(b"src/main.rs")
            )),
            "emitted body must use the fixture's path envelope: {request}"
        );
    }

    #[test]
    fn notify_body_carries_non_utf8_paths_losslessly() {
        use super::hex_encode;

        // The whole point of bytes_hex: a JSON string could not carry this
        // path without lossy substitution, which would misattribute the write.
        let raw = b"logs/x-\xff\xfe.log";
        let target = super::NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 4219,
            token: None,
        };
        let request = super::build_notify_request(raw, &target);
        let encoded = hex_encode(raw);
        assert_eq!(encoded, "6c6f67732f782dfffe2e6c6f67");
        assert!(request.contains(&encoded), "{request}");
        // Round-trip proves no byte was replaced.
        assert_eq!(
            (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>(),
            raw
        );
    }

    #[test]
    fn notify_request_carries_bearer_token_and_resolved_authority() {
        use super::{build_notify_request, NotifyTarget};
        let target = NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 5050,
            token: Some("secret-token".to_string()),
        };
        let req = build_notify_request(b"src/lib.rs", &target);

        assert!(req.contains("Host: 127.0.0.1:5050\r\n"));
        assert!(req.contains("Authorization: Bearer secret-token\r\n"));
        // Content-Length must match the JSON body exactly.
        let body = r#"{"path":{"bytes_hex":"7372632f6c69622e7273"}}"#;
        assert!(req.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(req.ends_with(body));
    }

    // ── Backoff tests ───────────────────────────────────────────────────

    #[test]
    fn backoff_respects_bounds() {
        use super::{backoff_with_jitter, BACKOFF_MAX_MS};

        for attempt in 0..12 {
            let d = backoff_with_jitter(attempt);
            let ms = d.as_millis() as u64;

            // Must always be >= 1ms (the .max(1) floor).
            assert!(ms >= 1, "attempt {attempt}: duration {ms}ms < 1ms");

            // Must never exceed max + 25% jitter.
            let upper = BACKOFF_MAX_MS + BACKOFF_MAX_MS / 4;
            assert!(
                ms <= upper,
                "attempt {attempt}: duration {ms}ms > upper bound {upper}ms"
            );
        }
    }

    #[test]
    fn backoff_grows_exponentially() {
        // Median of the base (without jitter) should roughly double.
        // We check that attempt 3 base is larger than attempt 0 base.
        let base_0 = super::BACKOFF_INITIAL_MS; // 50
        let base_3 = super::BACKOFF_INITIAL_MS.saturating_mul(1u64 << 3); // 400
        assert!(base_3 > base_0);
        assert_eq!(base_3, 400);
    }

    // ── Notification channel tests ──────────────────────────────────────

    #[test]
    fn notify_channel_does_not_panic_on_rapid_sends() {
        // Write storm against the real (unbounded) singleton channel: far more
        // than the old 64-slot capacity. Must neither panic, deadlock, nor
        // block the caller. (Losslessness is asserted separately below, against
        // a controlled receiver, since the singleton worker drains over TCP.)
        for i in 0..10_000 {
            let path = VfsPath::from_utf8(format!("src/file_{i}.rs")).unwrap();
            super::notify_file_changed(&path);
        }
    }

    #[test]
    fn notify_channel_is_lossless_under_write_storm() {
        // The reconcile signal must never be silently dropped. An earlier
        // bounded `sync_channel(64)` + `try_send` dropped excess under a write
        // storm, letting graph truth diverge from disk. Model the new unbounded
        // channel and prove every enqueued notification is delivered.
        //
        // We exercise the same channel type `notify_file_changed` uses
        // (`mpsc::channel`), draining on a worker, and assert the received count
        // equals the sent count — i.e. zero drops, well past the old capacity.
        use std::sync::mpsc;

        const STORM: usize = 5_000; // >> old NOTIFY_CHANNEL_CAPACITY (64)
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let worker = std::thread::spawn(move || {
            let mut count = 0usize;
            while rx.recv().is_ok() {
                count += 1;
            }
            count
        });

        for i in 0..STORM {
            // Non-blocking, lossless send — never drops, never blocks.
            tx.send(format!("src/file_{i}.rs").into_bytes())
                .expect("send must succeed");
        }
        drop(tx); // close channel so the worker's recv loop ends

        let received = worker.join().expect("worker thread");
        assert_eq!(
            received, STORM,
            "every write-notify must be delivered (no silent drops)"
        );
    }

    #[test]
    fn notify_sender_is_singleton() {
        // Verify that get_notify_sender returns the same sender across calls
        // (i.e., only one worker thread is spawned).
        let s1 = super::get_notify_sender().map(|s| s as *const _);
        let s2 = super::get_notify_sender().map(|s| s as *const _);
        assert_eq!(s1, s2);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn client_recovers_after_daemon_restart() {
        let socket = temp_socket_path();
        super::CLIENT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        let first = spawn_single_response_server(
            &socket,
            VfsResponse::Content {
                data: b"v1".to_vec(),
                total_size: 2,
            },
        );
        assert_eq!(
            super::client_read_file(&socket, &vpath("virtual/file")).as_deref(),
            Some(&b"v1"[..])
        );
        first.join().expect("first daemon thread");

        for _ in 0..20 {
            if !socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let second = spawn_single_response_server(
            &socket,
            VfsResponse::Content {
                data: b"v2".to_vec(),
                total_size: 2,
            },
        );
        assert_eq!(
            super::client_read_file(&socket, &vpath("virtual/file")).as_deref(),
            Some(&b"v2"[..])
        );
        second.join().expect("second daemon thread");

        super::CLIENT.with(|cell| {
            *cell.borrow_mut() = None;
        });
        let _ = std::fs::remove_file(&socket);
    }

    // ── Write-notify acknowledgement tests (AC1) ─────────────────────────
    //
    // The shim must REQUIRE and PARSE a successful daemon reply, not fire and
    // forget. `parse_notify_response` classifies the status line + body; a
    // socket-level round trip proves `attempt_notify` maps real daemon replies
    // (ack / soft-block / auth / veto) to the right outcome.

    #[test]
    fn parse_notify_response_classifies_status_and_body() {
        use super::{parse_notify_response, NotifyResponse};

        // 200 + reindexed:true is the ONLY acknowledged success.
        assert_eq!(
            parse_notify_response(
                b"HTTP/1.1 200 OK\r\n\r\n{\"reindexed\":true,\"entity_count\":1}"
            ),
            NotifyResponse::Acked
        );
        // 200 with reindexed:false is a soft-block / reconcile failure — reached
        // but not converged, must NOT read as success.
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 200 OK\r\n\r\n{\"reindexed\":false,\"error\":\"x\"}"),
            NotifyResponse::NotReindexed
        );
        // A 2xx with no confirmation field is surfaced, never silently accepted.
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 204 No Content\r\n\r\n"),
            NotifyResponse::NotReindexed
        );
        // Non-2xx (auth / veto / server error) are rejections carrying the code.
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 401 Unauthorized\r\n\r\n"),
            NotifyResponse::Rejected(401)
        );
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 409 Conflict\r\n\r\n{\"error\":\"write_veto\"}"),
            NotifyResponse::Rejected(409)
        );
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 500 Internal Server Error\r\n\r\n"),
            NotifyResponse::Rejected(500)
        );
        // Non-HTTP garbage is unparsable (surfaced, not treated as success).
        assert_eq!(
            parse_notify_response(b"not-an-http-response"),
            NotifyResponse::Unparsable
        );
    }

    #[test]
    fn notify_retry_policy_only_retries_transient_and_5xx() {
        use super::{notify_is_retryable, NotifyAttempt, NotifyResponse};
        assert!(notify_is_retryable(NotifyAttempt::Transient));
        assert!(notify_is_retryable(NotifyAttempt::Responded(
            NotifyResponse::Rejected(503)
        )));
        // Deterministic client rejections are never retried.
        assert!(!notify_is_retryable(NotifyAttempt::Responded(
            NotifyResponse::Rejected(401)
        )));
        assert!(!notify_is_retryable(NotifyAttempt::Responded(
            NotifyResponse::Rejected(409)
        )));
        // Definitive replies are not retried.
        assert!(!notify_is_retryable(NotifyAttempt::Responded(
            NotifyResponse::Acked
        )));
        assert!(!notify_is_retryable(NotifyAttempt::Responded(
            NotifyResponse::NotReindexed
        )));
        assert!(!notify_is_retryable(NotifyAttempt::Unreachable));
    }

    /// Serve exactly one canned HTTP response on an ephemeral loopback port,
    /// then close so the client's read loop sees EOF.
    fn spawn_http_response(response: &'static str) -> std::net::SocketAddr {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                // Drain the request headers so the client's write completes.
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                // Dropping `stream` closes the connection (EOF for the client).
            }
        });
        addr
    }

    #[test]
    fn attempt_notify_maps_daemon_replies_over_a_socket() {
        use super::{attempt_notify, NotifyAttempt, NotifyResponse, NotifyTarget};

        let request = "POST /vfs/write-notify HTTP/1.1\r\nHost: x\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}";

        let cases: [(&'static str, NotifyAttempt); 3] = [
            (
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"reindexed\":true,\"entity_count\":2}",
                NotifyAttempt::Responded(NotifyResponse::Acked),
            ),
            (
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"reindexed\":false,\"entity_count\":0}",
                NotifyAttempt::Responded(NotifyResponse::NotReindexed),
            ),
            (
                "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n",
                NotifyAttempt::Responded(NotifyResponse::Rejected(401)),
            ),
        ];

        for (resp, expected) in cases {
            let addr = spawn_http_response(resp);
            let target = NotifyTarget {
                host: addr.ip().to_string(),
                port: addr.port(),
                token: None,
            };
            assert_eq!(attempt_notify(request, &target), expected, "for {resp:?}");
        }
    }

    #[test]
    fn attempt_notify_reports_unreachable_when_nothing_listens() {
        use super::{attempt_notify, NotifyAttempt, NotifyTarget};
        // Port 1 on loopback: connect refused → unreachable, not a false ack.
        let target = NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 1,
            token: None,
        };
        assert_eq!(
            attempt_notify("POST / HTTP/1.1\r\n\r\n", &target),
            NotifyAttempt::Unreachable
        );
    }

    // ── Graph-authority failure classification tests (AC3) ───────────────
    //
    // The failure side channel distinguishes graph absence (ENOENT) from
    // unavailable or internally inconsistent authority (EIO); none may
    // consult raw disk.

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn client_classifies_absence_unreachable_and_authority_failures() {
        // Down daemon: socket never bound → None AND flagged unreachable.
        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let missing = temp_socket_path();
        assert!(super::client_stat(&missing, &vpath("x")).is_none());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::Unreachable,
            "an unreachable daemon must be classified separately"
        );

        // Reachable + answers Stat: success clears the failure classification.
        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let ok_sock = temp_socket_path();
        let ok_server = spawn_single_response_server(
            &ok_sock,
            VfsResponse::Stat(VirtualStat::regular_file(3, [0u8; 32], false, 1)),
        );
        assert!(super::client_stat(&ok_sock, &vpath("x")).is_some());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::None,
            "a successful daemon answer must clear prior failures"
        );
        ok_server.join().expect("ok server");

        // Reachable but NOT-FOUND: absence is distinct from authority failure.
        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let nf_sock = temp_socket_path();
        let nf_server = spawn_single_response_server(
            &nf_sock,
            VfsResponse::Error {
                code: ErrorCode::NotFound,
                message: "nope".into(),
            },
        );
        assert!(super::client_stat(&nf_sock, &vpath("missing")).is_none());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::NotFound,
            "a reachable not-found must be classified as graph absence"
        );
        nf_server.join().expect("nf server");

        // A reachable daemon can also reject an internally inconsistent graph
        // answer (for example a blob size/hash mismatch). That is authority
        // failure, never absence and never permission to consult raw disk.
        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let integrity_sock = temp_socket_path();
        let integrity_server = spawn_single_response_server(
            &integrity_sock,
            VfsResponse::Error {
                code: ErrorCode::Internal,
                message: "graph blob hash mismatch".into(),
            },
        );
        assert!(super::client_stat(&integrity_sock, &vpath("corrupt.bin")).is_none());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::Authority,
            "daemon integrity errors must be classified as authority failures"
        );
        integrity_server.join().expect("integrity server");

        // Content frames are also checked at the shim boundary. The local VFS
        // daemon may not relabel a partial/mismatched body as exact content.
        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let body_sock = temp_socket_path();
        let body_server = spawn_single_response_server(
            &body_sock,
            VfsResponse::Content {
                data: b"abc".to_vec(),
                total_size: 4,
            },
        );
        assert!(super::client_read_file(&body_sock, &vpath("corrupt.bin")).is_none());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::Authority
        );
        body_server.join().expect("body server");

        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let range_sock = temp_socket_path();
        let range_server = spawn_single_response_server(
            &range_sock,
            VfsResponse::Content {
                data: b"abcd".to_vec(),
                total_size: 11,
            },
        );
        assert!(super::client_read_range(&range_sock, &vpath("corrupt.bin"), 0, 4, 10).is_none());
        assert_eq!(
            super::last_call_failure(),
            super::ClientCallFailure::Authority
        );
        range_server.join().expect("range server");

        super::CLIENT.with(|cell| *cell.borrow_mut() = None);
        let _ = std::fs::remove_file(&ok_sock);
        let _ = std::fs::remove_file(&nf_sock);
        let _ = std::fs::remove_file(&integrity_sock);
        let _ = std::fs::remove_file(&body_sock);
        let _ = std::fs::remove_file(&range_sock);
    }
}
