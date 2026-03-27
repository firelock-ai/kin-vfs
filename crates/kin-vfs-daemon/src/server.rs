// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! VFS daemon server.
//!
//! On Unix (Linux/macOS), listens on a Unix domain socket.
//! On Windows, listens on a named pipe (`\\.\pipe\kin-vfs-{hash}`).
//!
//! Connection handling is transport-agnostic: any `AsyncRead + AsyncWrite`
//! stream is accepted via the generic `handle_connection` function.

use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use kin_vfs_core::{ContentProvider, VfsError};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{broadcast, watch, Semaphore};

use crate::framing::{read_frame, write_frame};
use crate::protocol::{ErrorCode, VfsRequest, VfsResponse};
use crate::DaemonError;

/// Maximum number of concurrent client connections.
const MAX_CONNECTIONS: usize = 256;

/// Handle returned by `VfsDaemonServer::new` to trigger a graceful shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the server to stop accepting connections and shut down.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

/// Endpoint address for the daemon listener.
///
/// On Unix, this is a filesystem path to a Unix domain socket.
/// On Windows, this is a named pipe path (e.g., `\\.\pipe\kin-vfs-{hash}`).
#[derive(Clone, Debug)]
pub enum ListenAddress {
    /// Unix domain socket path (Linux/macOS).
    #[cfg(unix)]
    UnixSocket(std::path::PathBuf),
    /// Named pipe path (Windows), e.g. `\\.\pipe\kin-vfs-abc123`.
    #[cfg(windows)]
    NamedPipe(String),
}

pub struct VfsDaemonServer<P: ContentProvider> {
    provider: Arc<P>,
    address: ListenAddress,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

impl<P: ContentProvider + 'static> VfsDaemonServer<P> {
    /// Create a new daemon server listening on a Unix socket.
    #[cfg(unix)]
    pub fn new(provider: P, socket_path: impl AsRef<Path>) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            provider: Arc::new(provider),
            address: ListenAddress::UnixSocket(socket_path.as_ref().to_path_buf()),
            shutdown_rx,
            shutdown_tx,
        }
    }

    /// Create a new daemon server listening on a Windows named pipe.
    #[cfg(windows)]
    pub fn new_named_pipe(provider: P, pipe_name: String) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            provider: Arc::new(provider),
            address: ListenAddress::NamedPipe(pipe_name),
            shutdown_rx,
            shutdown_tx,
        }
    }

    /// Returns a handle that can be used to trigger graceful shutdown.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            tx: self.shutdown_tx.clone(),
        }
    }

    /// Run the server. Dispatches to the platform-specific listener.
    pub async fn run(&self) -> Result<(), DaemonError> {
        match &self.address {
            #[cfg(unix)]
            ListenAddress::UnixSocket(path) => self.run_unix(path.clone()).await,
            #[cfg(windows)]
            ListenAddress::NamedPipe(name) => self.run_named_pipe(name.clone()).await,
        }
    }

    /// Unix socket accept loop.
    #[cfg(unix)]
    async fn run_unix(&self, socket_path: std::path::PathBuf) -> Result<(), DaemonError> {
        // Remove stale socket file if it exists.
        if socket_path.exists() {
            tracing::warn!("removing stale socket file at {:?}", socket_path);
            std::fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;

        // Security: restrict socket to owner only — prevents unauthorized file reads
        std::fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(0o700),
        )?;

        tracing::info!("VFS daemon listening on {:?}", socket_path);

        let result = self.accept_loop(move |shutdown_rx, semaphore, provider, invalidation_tx| {
            let socket_path = socket_path.clone();
            async move {
                let mut shutdown_rx = shutdown_rx;
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                tracing::info!("VFS daemon shutting down");
                                break;
                            }
                        }
                        result = listener.accept() => {
                            match result {
                                Ok((stream, _addr)) => {
                                    accept_stream(
                                        stream,
                                        &semaphore,
                                        &provider,
                                        &invalidation_tx,
                                        shutdown_rx.clone(),
                                    );
                                }
                                Err(e) => {
                                    tracing::error!("failed to accept connection: {e}");
                                }
                            }
                        }
                    }
                }

                // Clean up socket file.
                if socket_path.exists() {
                    let _ = std::fs::remove_file(&socket_path);
                }
            }
        }).await;

        result
    }

    /// Named pipe accept loop (Windows).
    ///
    /// Uses `tokio::net::windows::named_pipe` for async named pipe I/O.
    /// Creates a new pipe instance for each connection (ProjFS + shim clients
    /// each get their own pipe). The pipe name must match the client's naming
    /// convention: `\\.\pipe\kin-vfs-{workspace-hash}`.
    #[cfg(windows)]
    async fn run_named_pipe(&self, pipe_name: String) -> Result<(), DaemonError> {
        use tokio::net::windows::named_pipe::ServerOptions;

        tracing::info!("VFS daemon listening on named pipe: {pipe_name}");

        // Windows named pipes: we create a new server instance, wait for a
        // client to connect, then create a fresh instance for the next client.
        // This is the standard pattern for multi-client named pipe servers.
        let result = self.accept_loop(move |shutdown_rx, semaphore, provider, invalidation_tx| {
            let pipe_name = pipe_name.clone();
            async move {
                let mut shutdown_rx = shutdown_rx;

                // Create the first pipe instance.
                let mut server = match ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&pipe_name)
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("failed to create named pipe {pipe_name}: {e}");
                        return;
                    }
                };

                loop {
                    // Wait for a client to connect or shutdown signal.
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                tracing::info!("VFS daemon shutting down");
                                break;
                            }
                        }
                        result = server.connect() => {
                            match result {
                                Ok(()) => {
                                    // Client connected. Hand off this pipe instance
                                    // and create a new one for the next client.
                                    let connected_pipe = server;

                                    server = match ServerOptions::new().create(&pipe_name) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::error!("failed to create next pipe instance: {e}");
                                            break;
                                        }
                                    };

                                    accept_stream(
                                        connected_pipe,
                                        &semaphore,
                                        &provider,
                                        &invalidation_tx,
                                        shutdown_rx.clone(),
                                    );
                                }
                                Err(e) => {
                                    tracing::error!("named pipe connect error: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }).await;

        result
    }

    /// Common server setup: version poller + semaphore + invalidation channel.
    /// The `accept_fn` closure receives these resources and runs the
    /// platform-specific accept loop.
    async fn accept_loop<F, Fut>(&self, accept_fn: F) -> Result<(), DaemonError>
    where
        F: FnOnce(
            watch::Receiver<bool>,
            Arc<Semaphore>,
            Arc<P>,
            broadcast::Sender<Vec<String>>,
        ) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // Broadcast channel for push invalidation events.
        let (invalidation_tx, _) = broadcast::channel::<Vec<String>>(64);

        // Spawn background version poller for cache invalidation.
        let poller_provider = Arc::clone(&self.provider);
        let poller_tx = invalidation_tx.clone();
        let mut poller_shutdown = self.shutdown_rx.clone();
        tokio::spawn(async move {
            version_poller(poller_provider, poller_tx, &mut poller_shutdown).await;
        });

        let shutdown_rx = self.shutdown_rx.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let provider = Arc::clone(&self.provider);

        accept_fn(shutdown_rx, semaphore, provider, invalidation_tx).await;

        Ok(())
    }

    /// Returns the listen address.
    pub fn address(&self) -> &ListenAddress {
        &self.address
    }

    /// Returns the socket path (Unix only, for backwards compatibility).
    #[cfg(unix)]
    pub fn socket_path(&self) -> &Path {
        match &self.address {
            ListenAddress::UnixSocket(path) => path,
        }
    }

    /// Returns the named pipe path (Windows only).
    #[cfg(windows)]
    pub fn pipe_name(&self) -> &str {
        match &self.address {
            ListenAddress::NamedPipe(name) => name,
        }
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(unix)]
impl<P: ContentProvider> Drop for VfsDaemonServer<P> {
    fn drop(&mut self) {
        // Best-effort cleanup of the socket file.
        let ListenAddress::UnixSocket(ref path) = self.address;
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Accept a connected stream and spawn a connection handler task.
///
/// Works with any `AsyncRead + AsyncWrite + Send + Unpin + 'static` stream,
/// making it transport-agnostic (Unix socket, named pipe, etc.).
fn accept_stream<S, P>(
    stream: S,
    semaphore: &Arc<Semaphore>,
    provider: &Arc<P>,
    invalidation_tx: &broadcast::Sender<Vec<String>>,
    shutdown_rx: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    P: ContentProvider + 'static,
{
    let permit = semaphore.clone().try_acquire_owned();
    match permit {
        Ok(permit) => {
            tracing::debug!("accepted new connection");
            let provider = Arc::clone(provider);
            let inv_tx = invalidation_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, provider, inv_tx, shutdown_rx).await {
                    tracing::debug!("connection closed: {e}");
                }
                drop(permit);
            });
        }
        Err(_) => {
            tracing::warn!(
                "connection limit reached ({MAX_CONNECTIONS}), dropping connection"
            );
            drop(stream);
        }
    }
}

/// Handle a single client connection over any async stream.
///
/// The stream is split into read/write halves via `tokio::io::split`,
/// making this function work identically for Unix sockets and named pipes.
async fn handle_connection<S, P>(
    stream: S,
    provider: Arc<P>,
    invalidation_tx: broadcast::Sender<Vec<String>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), DaemonError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    P: ContentProvider + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    loop {
        let request = tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = read_frame(&mut reader) => {
                match result {
                    Ok(req) => req,
                    Err(DaemonError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        tracing::debug!("client disconnected");
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        tracing::trace!("request: {request:?}");
        let response = dispatch_request(&request, &*provider);

        // Subscribe is special: after responding, we enter push mode.
        if matches!(request, VfsRequest::Subscribe) {
            write_frame(&mut writer, &VfsResponse::Pong).await?;
            return handle_subscription(&mut writer, invalidation_tx, shutdown_rx).await;
        }

        write_frame(&mut writer, &response).await?;
    }
}

/// Enter push-invalidation mode: forward broadcast events to this client.
async fn handle_subscription<W>(
    writer: &mut W,
    invalidation_tx: broadcast::Sender<Vec<String>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), DaemonError>
where
    W: AsyncWrite + Unpin,
{
    let mut rx = invalidation_tx.subscribe();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(paths) => {
                        let response = VfsResponse::Invalidate { paths };
                        write_frame(writer, &response).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("subscription lagged by {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Background task: poll the provider's version counter every 500ms.
/// When the version changes, broadcast an invalidation event to all subscribed
/// shim clients so they can flush their caches.
async fn version_poller<P: ContentProvider + 'static>(
    provider: Arc<P>,
    invalidation_tx: broadcast::Sender<Vec<String>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut last_version: u64 = 0;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("version poller shutting down");
                    return;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                // Poll version on a blocking thread since provider.version()
                // may perform synchronous HTTP I/O.
                let prov = Arc::clone(&provider);
                let current = tokio::task::spawn_blocking(move || prov.version())
                    .await
                    .unwrap_or(last_version);

                if current != last_version && last_version != 0 {
                    tracing::info!(
                        "VFS version changed: {} -> {}, broadcasting invalidation",
                        last_version,
                        current
                    );
                    // Broadcast empty paths = "everything may have changed".
                    let _ = invalidation_tx.send(vec![]);
                }
                last_version = current;
            }
        }
    }
}

fn dispatch_request<P: ContentProvider>(request: &VfsRequest, provider: &P) -> VfsResponse {
    match request {
        VfsRequest::Stat { path } => match provider.stat(path) {
            Ok(stat) => VfsResponse::Stat(stat),
            Err(e) => vfs_error_to_response(e),
        },
        VfsRequest::ReadDir { path } => match provider.read_dir(path) {
            Ok(entries) => VfsResponse::DirEntries(entries),
            Err(e) => vfs_error_to_response(e),
        },
        VfsRequest::Read { path, offset, len } => {
            if *offset == 0 && *len == 0 {
                // Full file read.
                match provider.read_file(path) {
                    Ok(data) => {
                        let total_size = data.len() as u64;
                        VfsResponse::Content { data, total_size }
                    }
                    Err(e) => vfs_error_to_response(e),
                }
            } else {
                match provider.read_range(path, *offset, *len) {
                    Ok(data) => {
                        // Get total size from stat for completeness.
                        let total_size = provider
                            .stat(path)
                            .map(|s| s.size)
                            .unwrap_or(data.len() as u64);
                        VfsResponse::Content { data, total_size }
                    }
                    Err(e) => vfs_error_to_response(e),
                }
            }
        }
        VfsRequest::ReadLink { path } => match provider.read_link(path) {
            Ok(target) => VfsResponse::LinkTarget(target),
            Err(e) => vfs_error_to_response(e),
        },
        VfsRequest::Access { path, .. } => match provider.exists(path) {
            Ok(accessible) => VfsResponse::Accessible(accessible),
            Err(e) => vfs_error_to_response(e),
        },
        VfsRequest::Ping => VfsResponse::Pong,
        VfsRequest::Subscribe => {
            // Handled in the connection loop; this branch should not be reached.
            VfsResponse::Pong
        }
    }
}

fn vfs_error_to_response(e: VfsError) -> VfsResponse {
    let (code, message) = match &e {
        VfsError::NotFound { .. } => (ErrorCode::NotFound, e.to_string()),
        VfsError::IsDirectory { .. } => (ErrorCode::IsDirectory, e.to_string()),
        VfsError::NotDirectory { .. } => (ErrorCode::NotDirectory, e.to_string()),
        VfsError::PermissionDenied { .. } => (ErrorCode::PermissionDenied, e.to_string()),
        VfsError::Io(_) => (ErrorCode::IoError, e.to_string()),
        VfsError::Provider(_) => (ErrorCode::Internal, e.to_string()),
    };
    VfsResponse::Error { code, message }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kin_vfs_core::{DirEntry, FileType, VfsResult, VirtualStat};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory content provider for tests.
    struct MemoryProvider {
        files: Mutex<HashMap<String, Vec<u8>>>,
        dirs: Mutex<HashMap<String, Vec<DirEntry>>>,
    }

    impl MemoryProvider {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                dirs: Mutex::new(HashMap::new()),
            }
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_string(), content.to_vec());
        }

        fn add_dir(&self, path: &str, entries: Vec<DirEntry>) {
            self.dirs
                .lock()
                .unwrap()
                .insert(path.to_string(), entries);
        }
    }

    impl ContentProvider for MemoryProvider {
        fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            let end = std::cmp::min(start + len as usize, data.len());
            if start >= data.len() {
                return Ok(vec![]);
            }
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
            let files = self.files.lock().unwrap();
            if let Some(data) = files.get(path) {
                let hash = [0u8; 32]; // placeholder
                Ok(VirtualStat::file(data.len() as u64, hash, 1000))
            } else {
                let dirs = self.dirs.lock().unwrap();
                if dirs.contains_key(path) {
                    Ok(VirtualStat::directory(1000))
                } else {
                    Err(VfsError::NotFound {
                        path: path.to_string(),
                    })
                }
            }
        }

        fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
            self.dirs
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn exists(&self, path: &str) -> VfsResult<bool> {
            let files = self.files.lock().unwrap();
            let dirs = self.dirs.lock().unwrap();
            Ok(files.contains_key(path) || dirs.contains_key(path))
        }
    }

    fn temp_socket_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap();
        // Leak the tempdir so it lives long enough for the test.
        let path = dir.path().join("test.sock");
        std::mem::forget(dir);
        path
    }

    async fn send_request(
        socket_path: &Path,
        request: &VfsRequest,
    ) -> Result<VfsResponse, DaemonError> {
        let stream = tokio::net::UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = stream.into_split();

        // Write request frame.
        let payload =
            rmp_serde::to_vec(request).map_err(|e| DaemonError::Serialization(e.to_string()))?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        writer.write_u32(payload.len() as u32).await?;
        writer.write_all(&payload).await?;
        writer.flush().await?;

        // Read response frame.
        let len = reader.read_u32().await?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;
        rmp_serde::from_slice(&buf).map_err(|e| DaemonError::Serialization(e.to_string()))
    }

    #[tokio::test]
    async fn server_ping_pong() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Give the server a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(&socket_path, &VfsRequest::Ping).await.unwrap();
        assert!(matches!(response, VfsResponse::Pong));

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_stat_file() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/hello.txt", b"Hello, world!");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: "/hello.txt".into(),
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::Stat(stat) => {
                assert!(stat.is_file);
                assert_eq!(stat.size, 13);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_read_file() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/data.bin", b"binary content here");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Full read (offset=0, len=0 means full).
        let response = send_request(
            &socket_path,
            &VfsRequest::Read {
                path: "/data.bin".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(data, b"binary content here");
                assert_eq!(total_size, 19);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_read_range() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/data.bin", b"0123456789");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Read {
                path: "/data.bin".into(),
                offset: 3,
                len: 4,
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(data, b"3456");
                assert_eq!(total_size, 10);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_read_dir() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_dir(
            "/mydir",
            vec![
                DirEntry {
                    name: "a.txt".into(),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "subdir".into(),
                    file_type: FileType::Directory,
                },
            ],
        );
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::ReadDir {
                path: "/mydir".into(),
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::DirEntries(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].name, "a.txt");
                assert_eq!(entries[1].name, "subdir");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_not_found_error() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: "/nonexistent".into(),
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::Error { code, .. } => {
                assert!(matches!(code, ErrorCode::NotFound));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_concurrent_connections() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/a.txt", b"aaa");
        provider.add_file("/b.txt", b"bbb");
        provider.add_file("/c.txt", b"ccc");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Spawn 3 concurrent clients.
        let mut handles = Vec::new();
        for (path, expected) in [("/a.txt", b"aaa"), ("/b.txt", b"bbb"), ("/c.txt", b"ccc")] {
            let sp = socket_path.clone();
            let path = path.to_string();
            let expected = expected.to_vec();
            handles.push(tokio::spawn(async move {
                let response = send_request(
                    &sp,
                    &VfsRequest::Read {
                        path,
                        offset: 0,
                        len: 0,
                    },
                )
                .await
                .unwrap();
                match response {
                    VfsResponse::Content { data, .. } => {
                        assert_eq!(data, expected);
                    }
                    other => panic!("unexpected: {other:?}"),
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_access_check() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/exists.txt", b"yes");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Access {
                path: "/exists.txt".into(),
                mode: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, VfsResponse::Accessible(true)));

        let response = send_request(
            &socket_path,
            &VfsRequest::Access {
                path: "/nope".into(),
                mode: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, VfsResponse::Accessible(false)));

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn stale_socket_cleanup() {
        let socket_path = temp_socket_path();

        // Create a stale socket file.
        std::fs::write(&socket_path, b"stale").unwrap();
        assert!(socket_path.exists());

        let provider = MemoryProvider::new();
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Server should have replaced the stale file. Verify it works.
        let response = send_request(&socket_path, &VfsRequest::Ping).await.unwrap();
        assert!(matches!(response, VfsResponse::Pong));

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_requests_single_connection() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("/x.txt", b"data");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Open a single connection and send multiple requests.
        let stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for _ in 0..5 {
            let payload = rmp_serde::to_vec(&VfsRequest::Ping).unwrap();
            writer.write_u32(payload.len() as u32).await.unwrap();
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();

            let len = reader.read_u32().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf).await.unwrap();
            let response: VfsResponse = rmp_serde::from_slice(&buf).unwrap();
            assert!(matches!(response, VfsResponse::Pong));
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }
}
