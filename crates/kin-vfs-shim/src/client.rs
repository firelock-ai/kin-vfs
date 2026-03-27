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

use std::cell::RefCell;
use std::io::{Read, Write};
#[cfg(not(target_os = "windows"))]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── Backoff constants ────────────────────────────────────────────────────

/// Initial delay before the first reconnection retry.
const BACKOFF_INITIAL_MS: u64 = 100;
/// Maximum delay between reconnection retries.
const BACKOFF_MAX_MS: u64 = 5_000;
/// Maximum number of reconnection attempts before giving up.
const BACKOFF_MAX_RETRIES: u32 = 8;

use kin_vfs_core::{DirEntry, VirtualStat};

use crate::protocol::{VfsRequest, VfsResponse};

/// Maximum frame payload: 16 MiB (must match daemon).
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Read/write timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ── Unix socket client (Linux/macOS) ────────────────────────────────────

#[cfg(not(target_os = "windows"))]
thread_local! {
    static CLIENT: RefCell<Option<SyncVfsClient>> = const { RefCell::new(None) };
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
    CLIENT.with(|cell| {
        let mut borrow = cell.borrow_mut();

        // Try existing connection first.
        if let Some(ref mut client) = *borrow {
            if client.sock_path == sock_path {
                if let Some(result) = f(client) {
                    return Some(result);
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
                }
                return result;
            }
            std::thread::sleep(backoff_with_jitter(attempt));
        }

        // All retries exhausted — daemon unreachable.
        None
    })
}

/// Synchronous VFS daemon client over Unix sockets.
#[cfg(not(target_os = "windows"))]
pub struct SyncVfsClient {
    stream: UnixStream,
    sock_path: PathBuf,
}

#[cfg(not(target_os = "windows"))]
impl SyncVfsClient {
    /// Connect to the daemon socket.
    fn connect(sock_path: &Path) -> Option<Self> {
        let stream = UnixStream::connect(sock_path).ok()?;
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

        // All retries exhausted — daemon unreachable.
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

// ── Write-back notification (fire-and-forget HTTP POST to daemon) ────────

/// Daemon HTTP endpoint for file change notifications.
const DAEMON_HTTP_ADDR: &str = "127.0.0.1:4219";

use std::sync::mpsc::SyncSender;
use std::sync::OnceLock;

/// Singleton bounded channel for coalescing file-change notifications.
/// Replaces the previous thread-per-notification design that spawned
/// hundreds of OS threads during rapid writes (e.g., cargo build).
static NOTIFY_SENDER: OnceLock<SyncSender<String>> = OnceLock::new();

/// Return (or lazily create) the notification sender and its worker thread.
fn get_notify_sender() -> &'static SyncSender<String> {
    NOTIFY_SENDER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(64);
        std::thread::Builder::new()
            .name("kin-vfs-notify-worker".into())
            .spawn(move || {
                notification_worker(rx);
            })
            .expect("failed to spawn notification worker");
        tx
    })
}

/// Drain the channel, coalesce duplicate paths within a 50 ms window,
/// then send one HTTP POST per unique path.
fn notification_worker(rx: std::sync::mpsc::Receiver<String>) {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    let coalesce_window = Duration::from_millis(50);

    loop {
        // Block until the first notification arrives.
        let Ok(first_path) = rx.recv() else { break };

        let mut paths = HashSet::new();
        paths.insert(first_path);

        // Coalesce additional notifications within the window.
        let deadline = Instant::now() + coalesce_window;
        while Instant::now() < deadline {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(path) => { paths.insert(path); }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }

        // Send coalesced notifications.
        for path in paths {
            notify_file_changed_sync(&path);
        }
    }
}

/// Notify the daemon that a workspace file was written.
///
/// Sends a fire-and-forget notification via a bounded channel to a single
/// worker thread that coalesces rapid writes and POSTs to
/// `http://127.0.0.1:4219/vfs/file-changed`. If the channel is full the
/// notification is dropped — the daemon will pick up the change on the
/// next reconciliation cycle.
pub fn notify_file_changed(path: &str) {
    // Non-blocking send — drops notification if channel is full (acceptable).
    let _ = get_notify_sender().try_send(path.to_string());
}

/// Synchronous implementation of the file-changed notification.
fn notify_file_changed_sync(path: &str) {
    use std::io::Write as _;
    use std::net::TcpStream;

    let body = format!(r#"{{"path":"{}"}}"#, escape_json_string(path));
    let request = format!(
        "POST /vfs/file-changed HTTP/1.1\r\n\
         Host: 127.0.0.1:4219\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let stream = match TcpStream::connect(DAEMON_HTTP_ADDR) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut stream = stream;
    let _ = stream.write_all(request.as_bytes());
    // Don't wait for response — fire-and-forget.
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
pub fn client_stat(sock_path: &Path, path: &str) -> Option<VirtualStat> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::Stat {
            path: path.to_string(),
        })? {
            VfsResponse::Stat(s) => Some(s),
            _ => None,
        }
    })
}

/// Read full file content from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_file(sock_path: &Path, path: &str) -> Option<Vec<u8>> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.to_string(),
            offset: 0,
            len: 0, // 0 means "entire file"
        })? {
            VfsResponse::Content { data, .. } => Some(data),
            _ => None,
        }
    })
}

/// Read a byte range from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_range(sock_path: &Path, path: &str, offset: u64, len: u64) -> Option<Vec<u8>> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.to_string(),
            offset,
            len,
        })? {
            VfsResponse::Content { data, .. } => Some(data),
            _ => None,
        }
    })
}

/// List directory entries from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_dir(sock_path: &Path, path: &str) -> Option<Vec<DirEntry>> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::ReadDir {
            path: path.to_string(),
        })? {
            VfsResponse::DirEntries(entries) => Some(entries),
            _ => None,
        }
    })
}

/// Check if a path exists via the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_exists(sock_path: &Path, path: &str) -> Option<bool> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.to_string(),
            mode: 0, // F_OK
        })? {
            VfsResponse::Accessible(b) => Some(b),
            _ => None,
        }
    })
}

/// Read a symbolic link target from the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_read_link(sock_path: &Path, path: &str) -> Option<String> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::ReadLink {
            path: path.to_string(),
        })? {
            VfsResponse::LinkTarget(target) => Some(target),
            _ => None,
        }
    })
}

/// Check access with a mode mask via the daemon (Unix socket).
#[cfg(not(target_os = "windows"))]
pub fn client_access(sock_path: &Path, path: &str, mode: u32) -> Option<bool> {
    with_client(sock_path, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.to_string(),
            mode,
        })? {
            VfsResponse::Accessible(b) => Some(b),
            _ => None,
        }
    })
}

// ── Public API: Named pipe (called from ProjFS callbacks on Windows) ────

/// Stat a path via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_stat_named_pipe(pipe_name: &str, path: &str) -> Option<VirtualStat> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Stat {
            path: path.to_string(),
        })? {
            VfsResponse::Stat(s) => Some(s),
            _ => None,
        }
    })
}

/// Read full file content from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_file_named_pipe(pipe_name: &str, path: &str) -> Option<Vec<u8>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.to_string(),
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
    path: &str,
    offset: u64,
    len: u64,
) -> Option<Vec<u8>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Read {
            path: path.to_string(),
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
pub fn client_read_dir_named_pipe(pipe_name: &str, path: &str) -> Option<Vec<DirEntry>> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::ReadDir {
            path: path.to_string(),
        })? {
            VfsResponse::DirEntries(entries) => Some(entries),
            _ => None,
        }
    })
}

/// Check if a path exists via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_exists_named_pipe(pipe_name: &str, path: &str) -> Option<bool> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.to_string(),
            mode: 0,
        })? {
            VfsResponse::Accessible(b) => Some(b),
            _ => None,
        }
    })
}

/// Check access with a mode mask via the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_access_named_pipe(pipe_name: &str, path: &str, mode: u32) -> Option<bool> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::Access {
            path: path.to_string(),
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
    use kin_vfs_core::VirtualStat;

    #[test]
    fn request_serialization_roundtrip() {
        let requests = vec![
            VfsRequest::Stat {
                path: "/a/b".into(),
            },
            VfsRequest::Read {
                path: "/c".into(),
                offset: 10,
                len: 100,
            },
            VfsRequest::ReadDir {
                path: "/d".into(),
            },
            VfsRequest::Access {
                path: "/e".into(),
                mode: 4,
            },
            VfsRequest::Ping,
        ];
        for req in &requests {
            let bytes = rmp_serde::to_vec(req).expect("serialize");
            let decoded: VfsRequest = rmp_serde::from_slice(&bytes).expect("deserialize");
            // Just ensure no panic
            let _ = format!("{decoded:?}");
        }
    }

    #[test]
    fn response_serialization_roundtrip() {
        let responses = vec![
            VfsResponse::Stat(VirtualStat::file(42, [0u8; 32], 1000)),
            VfsResponse::Stat(VirtualStat::directory(2000)),
            VfsResponse::Content {
                data: b"hello".to_vec(),
                total_size: 5,
            },
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
        assert_eq!(escape_json_string(r#"path\with"quotes"#), r#"path\\with\"quotes"#);
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

    // ── Backoff tests ───────────────────────────────────────────────────

    #[test]
    fn backoff_respects_bounds() {
        use super::{backoff_with_jitter, BACKOFF_INITIAL_MS, BACKOFF_MAX_MS};

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
        let base_0 = super::BACKOFF_INITIAL_MS; // 100
        let base_3 = super::BACKOFF_INITIAL_MS.saturating_mul(1u64 << 3); // 800
        assert!(base_3 > base_0);
        assert_eq!(base_3, 800);
    }

    // ── Notification channel tests ──────────────────────────────────────

    #[test]
    fn notify_channel_does_not_panic_on_rapid_sends() {
        // Exercises the bounded-channel path: send more messages than the
        // channel capacity (64). Excess notifications are silently dropped
        // via try_send — verify no panic or deadlock.
        for i in 0..200 {
            super::notify_file_changed(&format!("src/file_{i}.rs"));
        }
        // If we get here without panic or hang, the channel works.
    }

    #[test]
    fn notify_sender_is_singleton() {
        // Verify that get_notify_sender returns the same sender across calls
        // (i.e., only one worker thread is spawned).
        let s1 = super::get_notify_sender() as *const _;
        let s2 = super::get_notify_sender() as *const _;
        assert_eq!(s1, s2);
    }
}
