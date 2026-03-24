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

/// Execute a closure with the thread-local client, initializing or
/// reconnecting as needed. Returns `None` if the daemon is unreachable.
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

        // (Re)connect.
        let mut client = SyncVfsClient::connect(sock_path)?;
        let result = f(&mut client);
        if result.is_some() {
            *borrow = Some(client);
        }
        result
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
/// or reconnecting as needed. Returns `None` if the daemon is unreachable.
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

        // (Re)connect.
        let pipe = connect_named_pipe(pipe_name)?;
        let mut client = NamedPipeClient {
            pipe,
            pipe_name: pipe_name.to_string(),
        };
        let result = f(&mut client);
        if result.is_some() {
            *borrow = Some(client);
        }
        result
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
}
