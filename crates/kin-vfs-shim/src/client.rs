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
#[cfg(not(target_os = "windows"))]
use std::ffi::CString;
use std::io::{Read, Write};
#[cfg(not(target_os = "windows"))]
use std::os::raw::c_void;
#[cfg(not(target_os = "windows"))]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

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
            path_bytes.as_ptr(),
            addr.sun_path.as_mut_ptr() as *mut u8,
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

// ── Write-back notification (non-blocking POST to daemon) ───────────

/// Channel capacity for the background notification worker. Excess
/// notifications are silently dropped via `try_send`.
const NOTIFY_CHANNEL_CAPACITY: usize = 64;

/// Timeout for the daemon TCP connection + request (keeps write path fast).
const NOTIFY_TIMEOUT: Duration = Duration::from_millis(100);

use std::sync::{mpsc, OnceLock};

/// Singleton sender half of the notification channel.
static NOTIFY_TX: OnceLock<mpsc::SyncSender<String>> = OnceLock::new();

/// Return (or lazily create) the singleton notification sender.
///
/// On first call, spawns a background worker thread that drains the
/// channel and sends HTTP POSTs to the daemon's `/vfs/write-notify`
/// endpoint. The worker runs for the lifetime of the process.
pub fn get_notify_sender() -> &'static mpsc::SyncSender<String> {
    NOTIFY_TX.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<String>(NOTIFY_CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("kin-vfs-notify".into())
            .spawn(move || {
                notify_worker(rx);
            })
            .expect("spawn notify worker");

        tx
    })
}

/// Background worker: drain the channel and POST each notification to the daemon.
fn notify_worker(rx: mpsc::Receiver<String>) {
    while let Ok(path) = rx.recv() {
        notify_write_sync(&path);
    }
}

/// Notify the daemon that a workspace file was written.
///
/// Enqueues a non-blocking notification to the background worker thread
/// which POSTs to `http://127.0.0.1:4219/vfs/write-notify`. If the
/// channel is full or the daemon is unreachable, the notification is
/// silently dropped — the daemon's file watcher will catch up.
pub fn notify_file_changed(path: &str) {
    let _ = get_notify_sender().try_send(path.to_string());
}

/// Synchronous POST to the daemon's write-notify endpoint with tight timeout.
fn notify_write_sync(path: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let body = format!(r#"{{"file_path":"{}"}}"#, escape_json_string(path));
    let request = format!(
        "POST /vfs/write-notify HTTP/1.1\r\n\
         Host: 127.0.0.1:4219\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let stream = match TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], 4219)),
        NOTIFY_TIMEOUT,
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = stream.set_write_timeout(Some(NOTIFY_TIMEOUT));
    let _ = stream.set_read_timeout(Some(NOTIFY_TIMEOUT));
    let mut stream = stream;

    if stream.write_all(request.as_bytes()).is_ok() {
        let mut resp_buf = [0u8; 12];
        let _ = stream.read(&mut resp_buf);
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

/// Read a symbolic link target from the daemon (named pipe).
#[cfg(target_os = "windows")]
pub fn client_read_link_named_pipe(pipe_name: &str, path: &str) -> Option<String> {
    with_pipe_client(pipe_name, |c| {
        match c.roundtrip(&VfsRequest::ReadLink {
            path: path.to_string(),
        })? {
            VfsResponse::LinkTarget(target) => Some(target),
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
    #[cfg(not(target_os = "windows"))]
    use std::io::{Read, Write};
    #[cfg(not(target_os = "windows"))]
    use std::os::unix::net::UnixListener;
    #[cfg(not(target_os = "windows"))]
    use std::path::{Path, PathBuf};
    #[cfg(not(target_os = "windows"))]
    use std::thread;
    #[cfg(not(target_os = "windows"))]
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            stream
                .write_all(&payload)
                .expect("write response payload");
            stream.flush().expect("flush response");
            drop(stream);
            drop(listener);
            let _ = std::fs::remove_file(&socket_path);
        })
    }

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
            super::client_read_file(&socket, "/virtual/file").as_deref(),
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
            super::client_read_file(&socket, "/virtual/file").as_deref(),
            Some(&b"v2"[..])
        );
        second.join().expect("second daemon thread");

        super::CLIENT.with(|cell| {
            *cell.borrow_mut() = None;
        });
        let _ = std::fs::remove_file(&socket);
    }
}
