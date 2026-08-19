// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! VFS daemon server.
//!
//! On Unix (Linux/macOS), listens on a Unix domain socket.
//! On Windows, listens on a named pipe (`\\.\pipe\kin-vfs-{hash}`).
//!
//! Connection handling is transport-agnostic: any `AsyncRead + AsyncWrite`
//! stream is accepted via the generic `handle_connection` function.

// `Path` is used by the Unix-socket lib paths and the socket tests; on Windows
// the lib target has no use for it (named-pipe transport), so suppress the
// unused-import lint there without `#[cfg(unix)]`-gating (which would break the
// Windows test build that still references `&Path`).
#[cfg_attr(windows, allow(unused_imports))]
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use kin_vfs_core::protocol::MAX_PROJECTION_WRITE;
use kin_vfs_core::writer::{ContentWriter, NoWrites};
use kin_vfs_core::{CanaryRegistry, ContentProvider, InterposeStatus, VfsError, VfsPath};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{broadcast, watch, Semaphore};

use crate::framing::{read_frame, write_frame};
use crate::lookup_log::{LookupLog, LookupOutcome};
use crate::protocol::{ErrorCode, VfsRequest, VfsResponse};
use crate::DaemonError;

/// Maximum number of concurrent client connections.
const MAX_CONNECTIONS: usize = 256;

/// How often the admission task asks whether the write debounce has closed.
///
/// Shorter than the debounce itself so a window that closes is acted on within
/// one tick of closing, and long enough that a daemon with no write side (the
/// common case, where the writer is [`NoWrites`] and `admission_due` is a
/// constant `false`) spends nothing on it.
const ADMISSION_TICK: std::time::Duration = std::time::Duration::from_millis(200);

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
    /// Interposition canary ledger: records shim `Announce` handshakes so a
    /// launcher can tell graph-native processes from ones where the shim was
    /// stripped (and which are silently reading raw disk).
    canary: Arc<CanaryRegistry>,
    /// Per-lookup diagnostics. Owned per server rather than process-wide so a
    /// second daemon in one process announces its own outcomes.
    lookups: Arc<LookupLog>,
    /// The write side, when this daemon admits writes from a projection
    /// surface.
    ///
    /// [`NoWrites`] by default, which refuses every write request rather than
    /// accepting bytes nothing will ever admit. A surface whose writes are
    /// silently taken and never folded into the graph is the exact failure
    /// this seam exists to prevent, so the default has to be a refusal and not
    /// a no-op.
    writer: Arc<dyn ContentWriter>,
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
            canary: Arc::new(CanaryRegistry::new()),
            lookups: Arc::new(LookupLog::new()),
            writer: Arc::new(NoWrites),
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
            canary: Arc::new(CanaryRegistry::new()),
            lookups: Arc::new(LookupLog::new()),
            writer: Arc::new(NoWrites),
        }
    }

    /// Admit writes from projection surfaces through `writer`.
    ///
    /// Without this the server answers every [`VfsRequest::Write`],
    /// [`VfsRequest::Remove`] and [`VfsRequest::Rename`] with a permission
    /// refusal, which is what a read-only projection should do.
    ///
    /// The caller shares the handle: the same writer should back the
    /// `WriteThroughProvider` this server serves reads from, so what a surface
    /// reads back and what it has staged are the same set by construction
    /// rather than by agreement.
    pub fn with_writer(mut self, writer: Arc<dyn ContentWriter>) -> Self {
        self.writer = writer;
        self
    }

    /// The write side this server admits through.
    pub fn writer(&self) -> &Arc<dyn ContentWriter> {
        &self.writer
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
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700))?;

        tracing::info!("VFS daemon listening on {:?}", socket_path);

        let canary = Arc::clone(&self.canary);
        let lookups = Arc::clone(&self.lookups);
        let writer = Arc::clone(&self.writer);
        let result = self
            .accept_loop(move |shutdown_rx, semaphore, provider, invalidation_tx| {
                let socket_path = socket_path.clone();
                let canary = Arc::clone(&canary);
                let lookups = Arc::clone(&lookups);
                let writer = Arc::clone(&writer);
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
                                            &writer,
                                            &invalidation_tx,
                                            &canary,
                                            &lookups,
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
            })
            .await;

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
        let canary = Arc::clone(&self.canary);
        let lookups = Arc::clone(&self.lookups);
        let writer = Arc::clone(&self.writer);
        let result = self.accept_loop(move |shutdown_rx, semaphore, provider, invalidation_tx| {
            let pipe_name = pipe_name.clone();
            let canary = Arc::clone(&canary);
            let lookups = Arc::clone(&lookups);
            let writer = Arc::clone(&writer);
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
                                        &writer,
                                        &invalidation_tx,
                                        &canary,
                                        &lookups,
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
            broadcast::Sender<Vec<VfsPath>>,
        ) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // Broadcast channel for push invalidation events.
        let (invalidation_tx, _) = broadcast::channel::<Vec<VfsPath>>(64);

        // Spawn background version poller for cache invalidation.
        let poller_provider = Arc::clone(&self.provider);
        let poller_tx = invalidation_tx.clone();
        let mut poller_shutdown = self.shutdown_rx.clone();
        tokio::spawn(async move {
            version_poller(poller_provider, poller_tx, &mut poller_shutdown).await;
        });

        // Spawn the admission task. Without it a projection surface's writes
        // stage forever: the request path takes the bytes and nothing folds
        // them into graph truth, which reads to the surface exactly like a
        // write that worked.
        let admit_writer = Arc::clone(&self.writer);
        let mut admit_shutdown = self.shutdown_rx.clone();
        tokio::spawn(async move {
            admission_loop(admit_writer, &mut admit_shutdown).await;
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

    /// Shared interposition-canary ledger. A launcher injects a `KIN_VFS_CANARY`
    /// token per child and registers it with [`CanaryRegistry::expect`]; the
    /// shim's `Announce` handshake confirms it here. Query
    /// [`CanaryRegistry::verdict`] to fail loud on a stripped (never-confirmed)
    /// process instead of trusting its raw-disk reads as graph truth.
    pub fn canary(&self) -> Arc<CanaryRegistry> {
        Arc::clone(&self.canary)
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
#[allow(clippy::too_many_arguments)]
fn accept_stream<S, P>(
    stream: S,
    semaphore: &Arc<Semaphore>,
    provider: &Arc<P>,
    writer: &Arc<dyn ContentWriter>,
    invalidation_tx: &broadcast::Sender<Vec<VfsPath>>,
    canary: &Arc<CanaryRegistry>,
    lookups: &Arc<LookupLog>,
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
            let writer = Arc::clone(writer);
            let inv_tx = invalidation_tx.clone();
            let canary = Arc::clone(canary);
            let lookups = Arc::clone(lookups);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    provider,
                    writer,
                    inv_tx,
                    canary,
                    lookups,
                    shutdown_rx,
                )
                .await
                {
                    tracing::debug!("connection closed: {e}");
                }
                drop(permit);
            });
        }
        Err(_) => {
            tracing::warn!("connection limit reached ({MAX_CONNECTIONS}), dropping connection");
            drop(stream);
        }
    }
}

/// Handle a single client connection over any async stream.
///
/// The stream is split into read/write halves via `tokio::io::split`,
/// making this function work identically for Unix sockets and named pipes.
#[allow(clippy::too_many_arguments)]
async fn handle_connection<S, P>(
    stream: S,
    provider: Arc<P>,
    writer_side: Arc<dyn ContentWriter>,
    invalidation_tx: broadcast::Sender<Vec<VfsPath>>,
    canary: Arc<CanaryRegistry>,
    lookups: Arc<LookupLog>,
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

        // Canary handshake is stateful (it mutates the registry), so it is
        // handled here rather than in the stateless `dispatch_request`. The shim
        // sends it once on load; recording it lets a launcher distinguish a
        // graph-native process from one whose interposition was stripped.
        if let VfsRequest::Announce { pid, token } = &request {
            let confirmed = canary.confirm(token);
            tracing::info!(pid, confirmed, "VFS interposition canary announced");
            write_frame(&mut writer, &VfsResponse::Announced).await?;
            continue;
        }

        // A launcher (kin-vfs exec) registers the token it expects a child to
        // announce, then queries the verdict after the child runs. Both are
        // stateful (they touch the registry), so handled here like Announce.
        if let VfsRequest::CanaryExpect { token } = &request {
            let registered = canary.expect(token);
            tracing::debug!(registered, "VFS canary expectation registered");
            write_frame(&mut writer, &VfsResponse::Announced).await?;
            continue;
        }
        if let VfsRequest::CanaryVerdict { token } = &request {
            let status = canary.verdict(Some(token));
            tracing::info!(?status, "VFS canary verdict queried");
            write_frame(&mut writer, &VfsResponse::CanaryStatus(status)).await?;
            continue;
        }

        // A shim that loaded can still be routed around: a workspace path
        // reached through an uninterposed libc surface is answered by raw disk.
        // Recording it here is what lets the verdict contradict the load
        // handshake instead of certifying the run as graph-native.
        if let VfsRequest::CanaryBypass { token, surface } = &request {
            let recorded = canary.record_bypass(token, surface);
            if recorded {
                tracing::warn!(
                    surface,
                    "VFS interposition BYPASSED: a workspace path was served from raw disk"
                );
            } else {
                tracing::debug!(surface, "VFS canary bypass report rejected as malformed");
            }
            write_frame(&mut writer, &VfsResponse::Announced).await?;
            continue;
        }
        if let VfsRequest::CanaryBypassSurfaces { token } = &request {
            let surfaces = canary.bypassed_surfaces(token);
            write_frame(&mut writer, &VfsResponse::CanaryBypasses(surfaces)).await?;
            continue;
        }

        let response = dispatch_request(&request, &*provider, &writer_side, &lookups);

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
    invalidation_tx: broadcast::Sender<Vec<VfsPath>>,
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
    invalidation_tx: broadcast::Sender<Vec<VfsPath>>,
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

/// Answer one request, recording every path-bearing lookup.
///
/// The recording sits here rather than at each provider call because this is the
/// single funnel every request passes through, so a new request kind cannot ship
/// unlogged by forgetting a call site.
fn dispatch_request<P: ContentProvider>(
    request: &VfsRequest,
    provider: &P,
    writer: &Arc<dyn ContentWriter>,
    lookups: &LookupLog,
) -> VfsResponse {
    provider.begin_lookup_endpoint();
    let response = answer_request(request, provider, writer);
    let answered_by = provider.finish_lookup_endpoint();
    if let Some((op, path)) = lookup_subject(request) {
        // `answered_by` is request-local transport provenance. Moving it into
        // the lazy formatter is allocation-free, while rereading the
        // provider's shared endpoint here could attribute response A to a
        // concurrent request that already moved the cache to endpoint B.
        lookups.record(op, &path.to_string(), LookupOutcome::of(&response), || {
            answered_by
        });
    }
    response
}

/// The operation name and path a request is asking about, or `None` for the
/// control-plane requests (ping, subscribe, canary) that name no path.
fn lookup_subject(request: &VfsRequest) -> Option<(&'static str, &VfsPath)> {
    match request {
        VfsRequest::Stat { path } => Some(("stat", path)),
        VfsRequest::ReadDir { path } => Some(("read_dir", path)),
        VfsRequest::Read { path, .. } => Some(("read", path)),
        VfsRequest::ReadLink { path } => Some(("read_link", path)),
        VfsRequest::Access { path, .. } => Some(("access", path)),
        VfsRequest::Write { path, .. } => Some(("write", path)),
        VfsRequest::Remove { path } => Some(("remove", path)),
        // A rename is recorded under its destination: that is the path the
        // graph ends up holding, and the one an operator reading the log will
        // go looking for.
        VfsRequest::Rename { to, .. } => Some(("rename", to)),
        VfsRequest::Ping
        | VfsRequest::Subscribe
        | VfsRequest::Announce { .. }
        | VfsRequest::CanaryExpect { .. }
        | VfsRequest::CanaryVerdict { .. }
        | VfsRequest::CanaryBypass { .. }
        | VfsRequest::CanaryBypassSurfaces { .. } => None,
    }
}

fn answer_request<P: ContentProvider>(
    request: &VfsRequest,
    provider: &P,
    writer: &Arc<dyn ContentWriter>,
) -> VfsResponse {
    match request {
        VfsRequest::Stat { path } => match provider.stat_at(path) {
            (generation, Ok(stat)) => VfsResponse::Stat { stat, generation },
            (generation, Err(e)) => vfs_error_at(e, generation),
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
                    Ok(data) => match provider.stat(path) {
                        Ok(stat) => VfsResponse::Content {
                            data,
                            total_size: stat.size,
                        },
                        Err(error) => vfs_error_to_response(error),
                    },
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
        VfsRequest::Announce { .. }
        | VfsRequest::CanaryExpect { .. }
        | VfsRequest::CanaryBypass { .. } => {
            // Handled in the connection loop (needs the canary registry); this
            // branch is unreachable but keeps the match exhaustive.
            VfsResponse::Announced
        }
        VfsRequest::CanaryVerdict { .. } => {
            // Handled in the connection loop; unreachable. Exhaustiveness only.
            VfsResponse::CanaryStatus(InterposeStatus::NotRequired)
        }
        VfsRequest::CanaryBypassSurfaces { .. } => {
            // Handled in the connection loop; unreachable. Exhaustiveness only.
            VfsResponse::CanaryBypasses(Vec::new())
        }
        VfsRequest::Write { .. } | VfsRequest::Remove { .. } | VfsRequest::Rename { .. } => {
            admit_projection_write(request, writer)
        }
    }
}

/// Stage one projection write through the daemon's write side.
///
/// This is the seam a ProjFS callback reaches: the surface has the bytes a
/// separate process wrote, and this hands them to the same
/// [`ContentWriter`] the FUSE and NFS mounts stage through, so a projected
/// write is admitted by one code path rather than one per surface.
///
/// A server with no write side answers a permission refusal here, because
/// [`NoWrites`] refuses every mutation. That is deliberate: accepting a write
/// nothing will admit would report success for bytes the graph never takes.
fn admit_projection_write(request: &VfsRequest, writer: &Arc<dyn ContentWriter>) -> VfsResponse {
    match request {
        VfsRequest::Write { path, data } => {
            if data.len() > MAX_PROJECTION_WRITE {
                return vfs_error_to_response(VfsError::InvalidInput {
                    path: format!(
                        "{path}: a projection write of {} bytes is over the {MAX_PROJECTION_WRITE}-byte limit",
                        data.len()
                    ),
                });
            }
            // Write then truncate, in that order. `write_at` does not shorten
            // a file, so replacing a long file's contents with a short one
            // would otherwise leave the old tail behind and admit bytes no
            // process ever wrote. The truncate is what makes this a whole-file
            // replacement rather than a prefix overwrite.
            if let Err(error) = writer.write_at(path, 0, data) {
                return vfs_error_to_response(error);
            }
            match writer.set_len(path, data.len() as u64) {
                Ok(stat) => VfsResponse::Written { stat },
                Err(error) => vfs_error_to_response(error),
            }
        }
        VfsRequest::Remove { path } => match writer.remove(path) {
            Ok(()) => VfsResponse::WriteAccepted,
            Err(error) => vfs_error_to_response(error),
        },
        VfsRequest::Rename { from, to } => match writer.rename(from, to) {
            Ok(()) => VfsResponse::WriteAccepted,
            Err(error) => vfs_error_to_response(error),
        },
        // Every other request kind is answered by `answer_request` itself.
        _ => vfs_error_to_response(VfsError::InvalidInput {
            path: "not a projection write".to_string(),
        }),
    }
}

/// Background task: fold staged projection writes into graph truth once the
/// write debounce has closed.
///
/// The daemon's counterpart to the NFS router's admission loop. A surface's
/// write request stages bytes and answers; nothing about that answer means the
/// graph took them, and this is what makes it eventually true. An admission
/// that fails leaves its paths staged with the refusal attached, which is what
/// a status probe reads, so a failure here is visible rather than lost.
async fn admission_loop(writer: Arc<dyn ContentWriter>, shutdown_rx: &mut watch::Receiver<bool>) {
    let debounce = crate::kin_writer::configured_debounce();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("admission loop shutting down");
                    return;
                }
            }
            _ = tokio::time::sleep(ADMISSION_TICK) => {
                if !writer.admission_due(debounce) {
                    continue;
                }
                // Blocking: one synchronous daemon request per admission.
                let admitting = Arc::clone(&writer);
                match tokio::task::spawn_blocking(move || admitting.admit()).await {
                    Ok(Ok(Some(admission))) => tracing::info!(
                        change = %admission.change_id,
                        branch = %admission.branch,
                        files = admission.file_count,
                        "admitted a projection write into graph truth"
                    ),
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "a projection write could not be admitted")
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the admission task panicked")
                    }
                }
            }
        }
    }
}

/// Report a failure that names no snapshot. Every request kind but `Stat`
/// answers this way: nothing downstream keys a cache on their errors, so
/// carrying a generation they cannot source honestly would be worse than
/// carrying the sentinel.
fn vfs_error_to_response(e: VfsError) -> VfsResponse {
    vfs_error_at(e, 0)
}

/// Report a failure stamped with the generation of the snapshot that produced
/// it, so a definitive absence is as rememberable as a definitive presence.
fn vfs_error_at(e: VfsError, generation: u64) -> VfsResponse {
    let (code, message) = match &e {
        VfsError::NotFound { .. } => (ErrorCode::NotFound, e.to_string()),
        VfsError::IsDirectory { .. } => (ErrorCode::IsDirectory, e.to_string()),
        VfsError::NotDirectory { .. } => (ErrorCode::NotDirectory, e.to_string()),
        VfsError::PermissionDenied { .. } => (ErrorCode::PermissionDenied, e.to_string()),
        VfsError::InvalidInput { .. } => (ErrorCode::InvalidInput, e.to_string()),
        VfsError::UnsupportedRepositoryBoundary { .. } => {
            (ErrorCode::UnsupportedBoundary, e.to_string())
        }
        VfsError::Io(_) => (ErrorCode::IoError, e.to_string()),
        VfsError::Provider(_) => (ErrorCode::Internal, e.to_string()),
    };
    VfsResponse::Error {
        code,
        message,
        generation,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kin_vfs_core::{DirEntry, FileType, VfsResult, VirtualStat};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory content provider for tests, keyed by byte-exact paths.
    struct MemoryProvider {
        files: Mutex<HashMap<VfsPath, Vec<u8>>>,
        dirs: Mutex<HashMap<VfsPath, Vec<DirEntry>>>,
        version: u64,
    }

    impl MemoryProvider {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                dirs: Mutex::new(HashMap::new()),
                version: 0,
            }
        }

        fn at_version(version: u64) -> Self {
            Self {
                version,
                ..Self::new()
            }
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(vpath(path), content.to_vec());
        }

        fn add_dir(&self, path: &str, entries: Vec<DirEntry>) {
            self.dirs.lock().unwrap().insert(vpath(path), entries);
        }

        /// What this provider holds for a path right now, as the store itself
        /// sees it. Used by assertions, never by the serving path.
        fn holds(&self, path: &VfsPath) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(path).cloned()
        }

        fn publish(&self, path: &VfsPath, content: Vec<u8>) {
            self.files.lock().unwrap().insert(path.clone(), content);
        }

        fn retract(&self, path: &VfsPath) {
            self.files.lock().unwrap().remove(path);
        }
    }

    /// A shareable handle to one [`MemoryProvider`].
    ///
    /// A newtype rather than `impl ContentProvider for Arc<MemoryProvider>`,
    /// which the orphan rule forbids. Cloning shares the one store, so what
    /// the daemon answers from and what an admission publishes into are the
    /// same thing.
    #[derive(Clone)]
    struct SharedGraph(Arc<MemoryProvider>);

    impl SharedGraph {
        fn new() -> Self {
            Self(Arc::new(MemoryProvider::new()))
        }
    }

    impl std::ops::Deref for SharedGraph {
        type Target = MemoryProvider;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl ContentProvider for SharedGraph {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.0.read_file(path)
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            self.0.read_range(path, offset, len)
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            self.0.stat(path)
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            self.0.read_dir(path)
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            self.0.exists(path)
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.0.read_link(path)
        }

        fn version(&self) -> u64 {
            self.0.version()
        }
    }

    impl ContentProvider for MemoryProvider {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            let end = std::cmp::min(start + len as usize, data.len());
            if start >= data.len() {
                return Ok(vec![]);
            }
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            let files = self.files.lock().unwrap();
            if let Some(data) = files.get(path) {
                let hash = [0u8; 32]; // placeholder
                Ok(VirtualStat::regular_file(
                    data.len() as u64,
                    hash,
                    false,
                    1000,
                ))
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

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            self.dirs
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            let files = self.files.lock().unwrap();
            let dirs = self.dirs.lock().unwrap();
            Ok(files.contains_key(path) || dirs.contains_key(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn version(&self) -> u64 {
            self.version
        }
    }

    /// Build a validated byte-exact path for test fixtures.
    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid test path")
    }

    /// Build a validated byte-exact directory-entry name for test fixtures.
    fn vname(name: &str) -> kin_vfs_core::VfsName {
        kin_vfs_core::VfsName::from_utf8(name).expect("valid test name")
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
        provider.add_file("hello.txt", b"Hello, world!");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: vpath("hello.txt"),
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::Stat { stat, .. } => {
                assert!(stat.is_file);
                assert_eq!(stat.size, 13);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn stat_answers_carry_the_version_that_produced_them() {
        // A client that remembers a path fact keys it on this number. Both the
        // presence and the absence have to carry it, or absence is the one
        // answer nothing can remember — and absence is what a tool probing for
        // files that are not there asks about most.
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::at_version(41);
        provider.add_file("hello.txt", b"Hello, world!");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();
        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let present = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: vpath("hello.txt"),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(present, VfsResponse::Stat { generation: 41, .. }),
            "a present path must name the version that answered: {present:?}"
        );

        let absent = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: vpath("nope.txt"),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(
                absent,
                VfsResponse::Error {
                    code: ErrorCode::NotFound,
                    generation: 41,
                    ..
                }
            ),
            "a definitive absence must name it too: {absent:?}"
        );

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn a_provider_with_no_authority_stamps_the_unrememberable_sentinel() {
        let socket_path = temp_socket_path();
        let server = VfsDaemonServer::new(MemoryProvider::new(), &socket_path);
        let handle = server.shutdown_handle();
        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let absent = send_request(
            &socket_path,
            &VfsRequest::Stat {
                path: vpath("nope.txt"),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(absent, VfsResponse::Error { generation: 0, .. }),
            "a provider reporting no version must not look like a snapshot a \
             client can key on: {absent:?}"
        );

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_read_file() {
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        provider.add_file("data.bin", b"binary content here");
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
                path: vpath("data.bin"),
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
        provider.add_file("data.bin", b"0123456789");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Read {
                path: vpath("data.bin"),
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
            "mydir",
            vec![
                DirEntry {
                    name: vname("a.txt"),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: vname("subdir"),
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
                path: vpath("mydir"),
            },
        )
        .await
        .unwrap();

        match response {
            VfsResponse::DirEntries(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].name.as_bytes(), b"a.txt");
                assert_eq!(entries[1].name.as_bytes(), b"subdir");
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
                path: vpath("nonexistent"),
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
        provider.add_file("a.txt", b"aaa");
        provider.add_file("b.txt", b"bbb");
        provider.add_file("c.txt", b"ccc");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Spawn 3 concurrent clients.
        let mut handles = Vec::new();
        for (path, expected) in [("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")] {
            let sp = socket_path.clone();
            let path = vpath(path);
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
        provider.add_file("exists.txt", b"yes");
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Access {
                path: vpath("exists.txt"),
                mode: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, VfsResponse::Accessible(true)));

        let response = send_request(
            &socket_path,
            &VfsRequest::Access {
                path: vpath("nope"),
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
        provider.add_file("x.txt", b"data");
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

    #[tokio::test]
    async fn server_canary_announce_confirms_token() {
        use kin_vfs_core::InterposeStatus;

        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        let server = VfsDaemonServer::new(provider, &socket_path);
        // Grab the shared registry before the server is moved into the task.
        let canary = server.canary();
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The launcher records that it expects this token (it injected
        // KIN_VFS_CANARY into a child it launched under interposition).
        let token = "canary-tok-1";
        canary.expect(token);

        // Before the shim announces, the token is expected-but-unconfirmed:
        // the launcher would FAIL LOUD (Stripped).
        assert_eq!(canary.verdict(Some(token)), InterposeStatus::Stripped);

        // The shim (loaded successfully) announces over the socket.
        let response = send_request(
            &socket_path,
            &VfsRequest::Announce {
                pid: 4242,
                token: token.to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, VfsResponse::Announced));

        // The daemon recorded it → the process is now graph-native (Active).
        assert!(canary.is_confirmed(token));
        assert_eq!(canary.verdict(Some(token)), InterposeStatus::Active);

        // A token that was expected but never announced stays Stripped — this is
        // the silent-DYLD-strip case the canary exists to surface.
        canary.expect("stripped-tok");
        assert_eq!(
            canary.verdict(Some("stripped-tok")),
            InterposeStatus::Stripped
        );

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_canary_expect_verdict_roundtrip_over_socket() {
        // Exercises the full launcher protocol the way kin-vfs exec uses it:
        // CanaryExpect (before launch) → CanaryVerdict=Stripped (child not yet
        // announced) → Announce (shim loaded) → CanaryVerdict=Active.
        let socket_path = temp_socket_path();
        let provider = MemoryProvider::new();
        let server = VfsDaemonServer::new(provider, &socket_path);
        let handle = server.shutdown_handle();

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let token = "exec-tok-7";

        // Launcher registers the expectation.
        let resp = send_request(
            &socket_path,
            &VfsRequest::CanaryExpect {
                token: token.to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, VfsResponse::Announced));

        // Before the shim announces, the verdict is Stripped (fail loud).
        let resp = send_request(
            &socket_path,
            &VfsRequest::CanaryVerdict {
                token: token.to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            resp,
            VfsResponse::CanaryStatus(kin_vfs_core::InterposeStatus::Stripped)
        ));

        // The shim loaded and announces.
        let resp = send_request(
            &socket_path,
            &VfsRequest::Announce {
                pid: 99,
                token: token.to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, VfsResponse::Announced));

        // Now the verdict is Active — the process is graph-native.
        let resp = send_request(
            &socket_path,
            &VfsRequest::CanaryVerdict {
                token: token.to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            resp,
            VfsResponse::CanaryStatus(kin_vfs_core::InterposeStatus::Active)
        ));

        handle.shutdown();
        server_handle.await.unwrap();
    }

    #[test]
    fn every_path_bearing_request_names_its_lookup_subject() {
        // A request kind absent from `lookup_subject` is served with nothing
        // written down about it, which is the state the daemon was in when it
        // answered not-in-graph for a graph-owned path and left no trace.
        let path = vpath("src/lib.rs");
        let cases: Vec<(VfsRequest, &str)> = vec![
            (VfsRequest::Stat { path: path.clone() }, "stat"),
            (VfsRequest::ReadDir { path: path.clone() }, "read_dir"),
            (
                VfsRequest::Read {
                    path: path.clone(),
                    offset: 0,
                    len: 0,
                },
                "read",
            ),
            (VfsRequest::ReadLink { path: path.clone() }, "read_link"),
            (
                VfsRequest::Access {
                    path: path.clone(),
                    mode: 0,
                },
                "access",
            ),
        ];
        for (request, expected_op) in cases {
            let (op, subject) = lookup_subject(&request)
                .unwrap_or_else(|| panic!("{expected_op} request named no lookup subject"));
            assert_eq!(op, expected_op);
            assert_eq!(subject, &path);
        }

        // The write requests name a subject too. A projection write that
        // reached the graph and left no trace is the same operator problem as
        // a read that did, and worse: it changed something.
        let write_cases: Vec<(VfsRequest, &str)> = vec![
            (
                VfsRequest::Write {
                    path: path.clone(),
                    data: b"x".to_vec(),
                },
                "write",
            ),
            (VfsRequest::Remove { path: path.clone() }, "remove"),
            (
                VfsRequest::Rename {
                    from: vpath("other.rs"),
                    to: path.clone(),
                },
                "rename",
            ),
        ];
        for (request, expected_op) in write_cases {
            let (op, subject) = lookup_subject(&request)
                .unwrap_or_else(|| panic!("{expected_op} request named no lookup subject"));
            assert_eq!(op, expected_op);
            assert_eq!(
                subject, &path,
                "{expected_op} named the wrong path as its subject"
            );
        }

        // Control-plane requests carry no path and must not be logged as
        // lookups, or the first-of-class announcements would be spent on them.
        for request in [
            VfsRequest::Ping,
            VfsRequest::Subscribe,
            VfsRequest::Announce {
                pid: 1,
                token: "t".into(),
            },
            VfsRequest::CanaryExpect { token: "t".into() },
            VfsRequest::CanaryVerdict { token: "t".into() },
            VfsRequest::CanaryBypass {
                token: "t".into(),
                surface: "fopen".into(),
            },
            VfsRequest::CanaryBypassSurfaces { token: "t".into() },
        ] {
            assert!(
                lookup_subject(&request).is_none(),
                "control-plane request was treated as a lookup"
            );
        }
    }

    #[test]
    fn dispatch_records_lookups_and_classifies_a_miss_apart_from_a_hit() {
        let provider = MemoryProvider::new();
        provider.add_file("present.rs", b"graph truth");
        let log = LookupLog::new();

        let hit = dispatch_request(
            &VfsRequest::Read {
                path: vpath("present.rs"),
                offset: 0,
                len: 0,
            },
            &provider,
            &read_only_writer(),
            &log,
        );
        assert!(matches!(hit, VfsResponse::Content { .. }));
        assert_eq!(log.recorded(), 1, "a served lookup went unrecorded");

        let miss = dispatch_request(
            &VfsRequest::Read {
                path: vpath("absent.rs"),
                offset: 0,
                len: 0,
            },
            &provider,
            &read_only_writer(),
            &log,
        );
        assert_eq!(LookupOutcome::of(&miss), LookupOutcome::NotInGraph);
        assert_eq!(log.recorded(), 2, "a missed lookup went unrecorded");

        let access_miss = dispatch_request(
            &VfsRequest::Access {
                path: vpath("absent.rs"),
                mode: 0,
            },
            &provider,
            &read_only_writer(),
            &log,
        );
        assert!(matches!(access_miss, VfsResponse::Accessible(false)));
        assert_eq!(
            LookupOutcome::of(&access_miss),
            LookupOutcome::NotInGraph,
            "authority reached but absent tree membership is a graph miss"
        );
        assert_eq!(log.recorded(), 3, "an access miss went unrecorded");

        // Ping carries no path, so it must not consume a lookup record.
        dispatch_request(&VfsRequest::Ping, &provider, &read_only_writer(), &log);
        assert_eq!(log.recorded(), 3, "a control-plane request was recorded");
    }
    // ── Projection write admission ──────────────────────────────────────

    /// The default write side: refuses every mutation. Named rather than
    /// inlined so a test that means "read-only" says so.
    fn read_only_writer() -> Arc<dyn ContentWriter> {
        Arc::new(kin_vfs_core::writer::NoWrites)
    }

    /// A writer that records what it was asked to do and stages it in memory.
    ///
    /// Deliberately not a mock that returns canned answers: the tests below
    /// assert on what the writer was actually asked, so a handler that answers
    /// `Written` without touching the write side fails them.
    #[derive(Default)]
    struct RecordingWriter {
        staged: parking_lot::Mutex<std::collections::HashMap<VfsPath, Vec<u8>>>,
        removed: parking_lot::Mutex<Vec<VfsPath>>,
        calls: parking_lot::Mutex<Vec<String>>,
        /// Where an admission publishes, when this writer admits at all.
        graph: Option<SharedGraph>,
        touched: parking_lot::Mutex<Option<std::time::Instant>>,
    }

    impl RecordingWriter {
        /// A writer that stages and never admits. Enough for the tests that
        /// only ask what the handler asked the write side to do.
        fn staging_only() -> Self {
            Self::default()
        }

        /// A writer whose admission publishes the staged set into `graph`,
        /// the way `KinDaemonWriter`'s publishes into the repository.
        fn admitting_into(graph: SharedGraph) -> Self {
            Self {
                graph: Some(graph),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().clone()
        }

        fn bytes(&self, path: &VfsPath) -> Option<Vec<u8>> {
            self.staged.lock().get(path).cloned()
        }

        fn touch(&self) {
            *self.touched.lock() = Some(std::time::Instant::now());
        }
    }

    impl ContentWriter for RecordingWriter {
        fn write_at(
            &self,
            path: &VfsPath,
            offset: u64,
            data: &[u8],
        ) -> kin_vfs_core::VfsResult<kin_vfs_core::VirtualStat> {
            self.calls
                .lock()
                .push(format!("write_at({path}, {offset}, {})", data.len()));
            let mut staged = self.staged.lock();
            let entry = staged.entry(path.clone()).or_default();
            let end = offset as usize + data.len();
            if entry.len() < end {
                entry.resize(end, 0);
            }
            entry[offset as usize..end].copy_from_slice(data);
            let size = entry.len() as u64;
            drop(staged);
            self.touch();
            Ok(kin_vfs_core::VirtualStat::regular_file(
                size, [0u8; 32], false, 0,
            ))
        }

        fn create_file(
            &self,
            path: &VfsPath,
            _exclusive: bool,
        ) -> kin_vfs_core::VfsResult<kin_vfs_core::VirtualStat> {
            self.calls.lock().push(format!("create_file({path})"));
            self.staged.lock().insert(path.clone(), Vec::new());
            Ok(kin_vfs_core::VirtualStat::regular_file(
                0, [0u8; 32], false, 0,
            ))
        }

        fn set_len(
            &self,
            path: &VfsPath,
            size: u64,
        ) -> kin_vfs_core::VfsResult<kin_vfs_core::VirtualStat> {
            self.calls.lock().push(format!("set_len({path}, {size})"));
            let mut staged = self.staged.lock();
            let entry = staged.get_mut(path).ok_or_else(|| VfsError::NotFound {
                path: path.to_string(),
            })?;
            entry.resize(size as usize, 0);
            self.touch();
            Ok(kin_vfs_core::VirtualStat::regular_file(
                size, [0u8; 32], false, 0,
            ))
        }

        fn create_dir(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<kin_vfs_core::VirtualStat> {
            self.calls.lock().push(format!("create_dir({path})"));
            Ok(kin_vfs_core::VirtualStat::directory(0))
        }

        fn remove(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<()> {
            self.calls.lock().push(format!("remove({path})"));
            self.staged.lock().remove(path);
            self.removed.lock().push(path.clone());
            self.touch();
            Ok(())
        }

        fn rename(&self, from: &VfsPath, to: &VfsPath) -> kin_vfs_core::VfsResult<()> {
            self.calls.lock().push(format!("rename({from}, {to})"));
            let mut staged = self.staged.lock();
            if let Some(bytes) = staged.remove(from) {
                staged.insert(to.clone(), bytes);
            }
            drop(staged);
            self.removed.lock().push(from.clone());
            self.touch();
            Ok(())
        }

        fn staged(&self, path: &VfsPath) -> Option<kin_vfs_core::writer::Staged> {
            self.staged.lock().get(path).map(|bytes| {
                kin_vfs_core::writer::Staged::Present(kin_vfs_core::VirtualStat::regular_file(
                    bytes.len() as u64,
                    [0u8; 32],
                    false,
                    0,
                ))
            })
        }

        fn staged_children(&self, _dir: &VfsPath) -> (Vec<DirEntry>, Vec<kin_vfs_core::VfsName>) {
            (Vec::new(), Vec::new())
        }

        fn read_staged(
            &self,
            path: &VfsPath,
            offset: u64,
            len: u64,
        ) -> kin_vfs_core::VfsResult<Vec<u8>> {
            let staged = self.staged.lock();
            let bytes = staged.get(path).ok_or_else(|| VfsError::NotFound {
                path: path.to_string(),
            })?;
            let start = (offset as usize).min(bytes.len());
            let end = (start + len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }

        fn read_staged_link(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn admit(&self) -> kin_vfs_core::VfsResult<Option<kin_vfs_core::writer::Admission>> {
            let Some(graph) = self.graph.as_ref() else {
                return Ok(None);
            };
            let staged = std::mem::take(&mut *self.staged.lock());
            let removed = std::mem::take(&mut *self.removed.lock());
            if staged.is_empty() && removed.is_empty() {
                return Ok(None);
            }
            for path in &removed {
                if !staged.contains_key(path) {
                    graph.retract(path);
                }
            }
            let mut paths: Vec<VfsPath> = Vec::new();
            for (path, bytes) in staged {
                graph.publish(&path, bytes);
                paths.push(path);
            }
            *self.touched.lock() = None;
            self.calls.lock().push(format!("admit({})", paths.len()));
            Ok(Some(kin_vfs_core::writer::Admission {
                change_id: "recorded-change".to_string(),
                branch: "main".to_string(),
                file_count: paths.len(),
                paths,
            }))
        }

        fn admission_due(&self, debounce: std::time::Duration) -> bool {
            match *self.touched.lock() {
                Some(touched) => touched.elapsed() >= debounce,
                None => false,
            }
        }

        fn health(&self) -> kin_vfs_core::writer::WriteHealth {
            let staged: Vec<VfsPath> = self.staged.lock().keys().cloned().collect();
            if staged.is_empty() {
                kin_vfs_core::writer::WriteHealth::Settled { last: None }
            } else {
                kin_vfs_core::writer::WriteHealth::Pending { paths: staged }
            }
        }
    }

    #[test]
    fn a_write_request_reaches_the_writer_with_the_bytes_it_carried() {
        let writer = Arc::new(RecordingWriter::staging_only());
        let handle: Arc<dyn ContentWriter> = writer.clone();
        let response = answer_request(
            &VfsRequest::Write {
                path: vpath("src/main.rs"),
                data: b"projected bytes".to_vec(),
            },
            &MemoryProvider::new(),
            &handle,
        );
        match response {
            VfsResponse::Written { stat } => assert_eq!(stat.size, 15),
            other => panic!("a projection write answered {other:?}"),
        }
        assert_eq!(
            writer.bytes(&vpath("src/main.rs")).as_deref(),
            Some(&b"projected bytes"[..]),
            "the writer did not receive the bytes the request carried"
        );
    }

    /// The truncate is the whole point of the second call.
    ///
    /// `write_at` does not shorten a file, so a short save over a long file
    /// would leave the old tail in place and admit bytes no process wrote.
    /// Asserting on the final size is what catches a handler that drops the
    /// `set_len`; asserting only that the write happened would not.
    #[test]
    fn a_shorter_write_replaces_the_file_rather_than_its_prefix() {
        let writer = Arc::new(RecordingWriter::staging_only());
        let handle: Arc<dyn ContentWriter> = writer.clone();
        let path = vpath("notes.txt");
        let provider = MemoryProvider::new();

        answer_request(
            &VfsRequest::Write {
                path: path.clone(),
                data: b"a long first version of this file".to_vec(),
            },
            &provider,
            &handle,
        );
        let response = answer_request(
            &VfsRequest::Write {
                path: path.clone(),
                data: b"short".to_vec(),
            },
            &provider,
            &handle,
        );

        match response {
            VfsResponse::Written { stat } => assert_eq!(
                stat.size, 5,
                "the answer reported a size the file no longer has"
            ),
            other => panic!("a projection write answered {other:?}"),
        }
        assert_eq!(
            writer.bytes(&path).as_deref(),
            Some(&b"short"[..]),
            "the previous version's tail survived the overwrite"
        );
    }

    #[test]
    fn a_remove_and_a_rename_reach_the_writer() {
        let writer = Arc::new(RecordingWriter::staging_only());
        let handle: Arc<dyn ContentWriter> = writer.clone();
        let provider = MemoryProvider::new();

        answer_request(
            &VfsRequest::Write {
                path: vpath("a.rs"),
                data: b"x".to_vec(),
            },
            &provider,
            &handle,
        );
        assert!(matches!(
            answer_request(
                &VfsRequest::Rename {
                    from: vpath("a.rs"),
                    to: vpath("b.rs"),
                },
                &provider,
                &handle,
            ),
            VfsResponse::WriteAccepted
        ));
        assert!(matches!(
            answer_request(
                &VfsRequest::Remove {
                    path: vpath("b.rs")
                },
                &provider,
                &handle
            ),
            VfsResponse::WriteAccepted
        ));

        let calls = writer.calls();
        assert!(
            calls.iter().any(|call| call == "rename(a.rs, b.rs)"),
            "the rename never reached the writer: {calls:?}"
        );
        assert!(
            calls.iter().any(|call| call == "remove(b.rs)"),
            "the removal never reached the writer: {calls:?}"
        );
    }

    /// A daemon with no write side must refuse, not accept and drop.
    ///
    /// This is the failure the write path exists to prevent, in its smallest
    /// form: a surface told its write was taken by something that will never
    /// admit it.
    #[test]
    fn a_daemon_with_no_write_side_refuses_a_projection_write() {
        let provider = MemoryProvider::new();
        for request in [
            VfsRequest::Write {
                path: vpath("a.rs"),
                data: b"x".to_vec(),
            },
            VfsRequest::Remove {
                path: vpath("a.rs"),
            },
            VfsRequest::Rename {
                from: vpath("a.rs"),
                to: vpath("b.rs"),
            },
        ] {
            match answer_request(&request, &provider, &read_only_writer()) {
                VfsResponse::Error {
                    code: ErrorCode::PermissionDenied,
                    ..
                } => {}
                other => panic!("a read-only daemon answered {request:?} with {other:?}"),
            }
        }
    }

    /// An oversized write is refused by name rather than by frame decode.
    ///
    /// The frame cap would reject it too, as an opaque protocol error on a
    /// connection. Refusing it here names the path and the size, which is what
    /// an operator needs to see, because the bytes have already landed on the
    /// surface's own store and the graph is now behind.
    #[test]
    fn a_write_over_the_bound_is_refused_by_name() {
        let writer = Arc::new(RecordingWriter::staging_only());
        let handle: Arc<dyn ContentWriter> = writer.clone();
        let response = answer_request(
            &VfsRequest::Write {
                path: vpath("huge.bin"),
                data: vec![0u8; MAX_PROJECTION_WRITE + 1],
            },
            &MemoryProvider::new(),
            &handle,
        );
        match response {
            VfsResponse::Error {
                code: ErrorCode::InvalidInput,
                message,
                ..
            } => {
                assert!(
                    message.contains("huge.bin") && message.contains("over the"),
                    "the refusal did not name the path and the limit: {message}"
                );
            }
            other => panic!("an oversized write answered {other:?}"),
        }
        assert!(
            writer.calls().is_empty(),
            "an oversized write reached the writer anyway: {:?}",
            writer.calls()
        );
    }

    /// The whole path over a real socket: a write frame in, a `Written` frame
    /// back, and the bytes staged on the writer the server was built with.
    ///
    /// The unit tests above call `answer_request` directly, which cannot see a
    /// request that never gets past `handle_connection`. This one can.
    #[tokio::test]
    async fn a_write_frame_crosses_the_socket_and_stages() {
        let socket_path = temp_socket_path();
        let writer = Arc::new(RecordingWriter::staging_only());
        let server = VfsDaemonServer::new(MemoryProvider::new(), &socket_path)
            .with_writer(writer.clone() as Arc<dyn ContentWriter>);
        let handle = server.shutdown_handle();
        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = send_request(
            &socket_path,
            &VfsRequest::Write {
                path: vpath("src/lib.rs"),
                data: b"written through the pipe".to_vec(),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(response, VfsResponse::Written { .. }),
            "a write frame answered {response:?}"
        );
        assert_eq!(
            writer.bytes(&vpath("src/lib.rs")).as_deref(),
            Some(&b"written through the pipe"[..]),
            "the write crossed the socket but never reached the writer"
        );

        handle.shutdown();
        server_handle.await.unwrap();
    }

    /// The handler drives the shipping writer, not only the test double.
    ///
    /// `KinDaemonWriter` is what a real mount stages through, and its
    /// `write_at`/`set_len` pair behaves differently from the in-memory
    /// double: it touches the host filesystem and restats. A handler that
    /// works against the double and not against this one would pass every
    /// other test here.
    #[test]
    fn the_write_handler_drives_the_real_kin_daemon_writer() {
        let repo = tempfile::tempdir().expect("temp repo root");
        let writer = crate::kin_writer::KinDaemonWriter::new(
            "http://127.0.0.1:1",
            repo.path().to_path_buf(),
            None,
        )
        .expect("build the shipping writer");
        let handle: Arc<dyn ContentWriter> = Arc::new(writer);
        let provider = MemoryProvider::new();
        let path = vpath("src/main.rs");

        let response = answer_request(
            &VfsRequest::Write {
                path: path.clone(),
                data: b"fn main() {}\n".to_vec(),
            },
            &provider,
            &handle,
        );
        assert!(
            matches!(response, VfsResponse::Written { .. }),
            "the shipping writer answered {response:?}"
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/main.rs")).expect("staged file"),
            b"fn main() {}\n",
            "the shipping writer did not stage the bytes"
        );
        assert!(
            matches!(
                handle.staged(&path),
                Some(kin_vfs_core::writer::Staged::Present(_))
            ),
            "the write staged nothing, so nothing would be admitted"
        );

        // And a shorter second write really shortens the staged file.
        answer_request(
            &VfsRequest::Write {
                path: path.clone(),
                data: b"fn m() {}".to_vec(),
            },
            &provider,
            &handle,
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/main.rs")).expect("staged file"),
            b"fn m() {}",
            "the previous version's tail survived on the real writer"
        );
    }
    /// The whole path, end to end, on every platform: a write frame crosses the
    /// socket, the admission task folds it into the graph, and a later read
    /// over the same protocol is answered by the graph rather than by the
    /// staging overlay.
    ///
    /// This is the platform-independent twin of the ProjFS live proof's cold
    /// projection. Both exist to answer one question the `Written` answer
    /// cannot: did anything actually take the write. Nothing else in this
    /// suite drives `admission_loop`, so without this test the daemon could
    /// stage every projected write forever and every other test would pass.
    ///
    /// The read-back is only evidence because the staging area is empty by
    /// then. `WriteThroughProvider` serves a staged path from the overlay, so a
    /// read taken before the admission would return the same bytes with the
    /// graph still empty. The assertion waits for the graph itself to hold
    /// them, and then checks the overlay is not what answered.
    #[tokio::test]
    async fn a_projected_write_is_admitted_and_then_served_from_the_graph() {
        let socket_path = temp_socket_path();
        let graph = SharedGraph::new();
        graph.add_file("src/main.rs", b"the version the graph starts with");
        let writer = Arc::new(RecordingWriter::admitting_into(graph.clone()));
        let write_side: Arc<dyn ContentWriter> = writer.clone();

        let server = VfsDaemonServer::new(
            kin_vfs_core::writer::WriteThroughProvider::new(graph.clone(), Arc::clone(&write_side)),
            &socket_path,
        )
        .with_writer(Arc::clone(&write_side));
        let handle = server.shutdown_handle();
        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let path = vpath("src/main.rs");
        let response = send_request(
            &socket_path,
            &VfsRequest::Write {
                path: path.clone(),
                data: b"the version a separate process wrote".to_vec(),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(response, VfsResponse::Written { .. }),
            "the write frame answered {response:?}"
        );

        // The default debounce is 1.2s and the admission task ticks every
        // 200ms, so this is a real wait rather than a formality.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut admitted = false;
        while std::time::Instant::now() < deadline {
            if graph.holds(&path).as_deref() == Some(&b"the version a separate process wrote"[..]) {
                admitted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            admitted,
            "a write the daemon accepted never reached the graph. The graph still holds {:?} \
             and the write side reports {}.",
            graph
                .holds(&path)
                .map(|b| String::from_utf8_lossy(&b).into_owned()),
            write_side.health().label(),
        );
        assert!(
            writer.bytes(&path).is_none(),
            "the admission left the path staged, so the read below would be answered by the \
             overlay and would prove nothing"
        );

        // Now the read: answered by the graph, because there is nothing staged
        // left to answer it.
        let read = send_request(
            &socket_path,
            &VfsRequest::Read {
                path: path.clone(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();
        match read {
            VfsResponse::Content { data, .. } => assert_eq!(
                data, b"the version a separate process wrote",
                "the graph served the pre-write version after an admission"
            ),
            other => panic!("reading back the admitted path answered {other:?}"),
        }

        handle.shutdown();
        server_handle.await.unwrap();
    }

    /// A removal admits as a removal rather than as an empty file.
    ///
    /// The distinction matters: publishing zero bytes over a deleted path
    /// leaves the graph holding a file the user deleted, and every read of it
    /// succeeds, so nothing downstream can tell.
    #[tokio::test]
    async fn a_projected_removal_takes_the_path_out_of_the_graph() {
        let socket_path = temp_socket_path();
        let graph = SharedGraph::new();
        graph.add_file("doomed.txt", b"still here");
        let writer = Arc::new(RecordingWriter::admitting_into(graph.clone()));
        let write_side: Arc<dyn ContentWriter> = writer.clone();

        let server = VfsDaemonServer::new(
            kin_vfs_core::writer::WriteThroughProvider::new(graph.clone(), Arc::clone(&write_side)),
            &socket_path,
        )
        .with_writer(Arc::clone(&write_side));
        let handle = server.shutdown_handle();
        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let path = vpath("doomed.txt");
        let response = send_request(&socket_path, &VfsRequest::Remove { path: path.clone() })
            .await
            .unwrap();
        assert!(
            matches!(response, VfsResponse::WriteAccepted),
            "the removal frame answered {response:?}"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut gone = false;
        while std::time::Instant::now() < deadline {
            if graph.holds(&path).is_none() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            gone,
            "a removal the daemon accepted never reached the graph; it still holds {:?}",
            graph
                .holds(&path)
                .map(|b| String::from_utf8_lossy(&b).into_owned()),
        );

        handle.shutdown();
        server_handle.await.unwrap();
    }
}
