// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Hermetic in-process HTTP mock of the kin daemon's VFS surface.
//!
//! Serves the strict `/vfs/tree` ETag contract and content-addressed
//! `/vfs/blob/<hash>` reads over real TCP so both providers are exercised on
//! the actual wire format — no real daemon, no GPU. Adversarial overrides let
//! tests serve malformed documents, mismatched ETag headers, wrong range
//! metadata, and stale snapshots without touching the happy-path plumbing.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use kin_model::WorkspaceTreeSnapshot;
use sha2::{Digest, Sha256};

struct ResponseGate {
    arrived: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

/// Mutable mock state shared with the test body.
pub(crate) struct MockState {
    /// The tree document currently served by `/vfs/tree`.
    pub(crate) snapshot: Mutex<WorkspaceTreeSnapshot>,
    /// Content-addressed blob store: lowercase hex SHA-256 → bytes.
    pub(crate) blobs: Mutex<HashMap<String, Vec<u8>>>,
    /// Raw override for the `/vfs/tree` body (malformed-document tests).
    pub(crate) tree_body_override: Mutex<Option<Vec<u8>>>,
    /// Override for the `ETag` header (header/body binding tests).
    pub(crate) etag_header_override: Mutex<Option<String>>,
    /// Override for the `X-Kin-Blob-Hash` header on `206` answers.
    pub(crate) range_hash_override: Mutex<Option<String>>,
    /// Override for the `Content-Range` total on `206` answers.
    pub(crate) range_total_override: Mutex<Option<u64>>,
    /// When set, `/vfs/blob/*` ignores `Range` and answers `200` with the
    /// complete body (full-body fallback tests).
    pub(crate) ignore_range: AtomicBool,
    /// Number of `200` tree bodies served (`304`s excluded).
    pub(crate) tree_bodies_served: AtomicUsize,
    /// Number of `/vfs/blob/*` requests served.
    pub(crate) blob_requests: AtomicUsize,
    /// Expected bearer token for `/vfs/*`; `None` keeps auth disabled.
    pub(crate) required_token: Mutex<Option<String>>,
    /// Repository identity returned by `/health`.
    pub(crate) health_repo_id: Mutex<Option<String>>,
    /// Canonical repository root returned by `/health`.
    pub(crate) health_repo_root: Mutex<Option<String>>,
    /// One-shot barrier immediately before a `200 /vfs/tree` response is
    /// written. This makes concurrent endpoint-move tests deterministic: the
    /// test can move another request to endpoint B while endpoint A's exact
    /// workspace-bound tree response is in flight.
    tree_response_gate: Mutex<Option<ResponseGate>>,
    /// Total HTTP requests observed by this daemon.
    pub(crate) requests: AtomicUsize,
    /// Requests refused with `401` because the bearer token was stale.
    pub(crate) unauthorized_requests: AtomicUsize,
}

impl MockState {
    /// Register `content` in the blob store under its real SHA-256.
    pub(crate) fn insert_blob(&self, content: &[u8]) {
        let hash = hex::encode(Sha256::digest(content));
        self.blobs.lock().unwrap().insert(hash, content.to_vec());
    }

    /// Register `content` under an arbitrary hex key (hash-mismatch tests).
    pub(crate) fn insert_blob_at(&self, hex_key: &str, content: &[u8]) {
        self.blobs
            .lock()
            .unwrap()
            .insert(hex_key.to_string(), content.to_vec());
    }

    /// Replace the served snapshot.
    pub(crate) fn set_snapshot(&self, snapshot: WorkspaceTreeSnapshot) {
        *self.snapshot.lock().unwrap() = snapshot;
    }

    pub(crate) fn require_token(&self, token: impl Into<String>) {
        *self.required_token.lock().unwrap() = Some(token.into());
    }

    pub(crate) fn set_health_root(&self, root: impl Into<String>) {
        *self.health_repo_root.lock().unwrap() = Some(root.into());
    }

    pub(crate) fn gate_next_tree_response(&self) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (arrived_tx, arrived_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *self.tree_response_gate.lock().unwrap() = Some(ResponseGate {
            arrived: arrived_tx,
            release: release_rx,
        });
        (arrived_rx, release_tx)
    }
}

/// RAII mock daemon. Stops and joins its accept thread on drop, so each test
/// releases its ephemeral port deterministically.
pub(crate) struct MockDaemon {
    base: String,
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    pub(crate) state: Arc<MockState>,
}

impl MockDaemon {
    pub(crate) fn spawn(snapshot: WorkspaceTreeSnapshot) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{addr}");
        let health_repo_id = snapshot.binding.repository_id.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(MockState {
            snapshot: Mutex::new(snapshot),
            blobs: Mutex::new(HashMap::new()),
            tree_body_override: Mutex::new(None),
            etag_header_override: Mutex::new(None),
            range_hash_override: Mutex::new(None),
            range_total_override: Mutex::new(None),
            ignore_range: AtomicBool::new(false),
            tree_bodies_served: AtomicUsize::new(0),
            blob_requests: AtomicUsize::new(0),
            required_token: Mutex::new(None),
            health_repo_id: Mutex::new(Some(health_repo_id)),
            health_repo_root: Mutex::new(None),
            tree_response_gate: Mutex::new(None),
            requests: AtomicUsize::new(0),
            unauthorized_requests: AtomicUsize::new(0),
        });

        let stop_thread = Arc::clone(&stop);
        let state_thread = Arc::clone(&state);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // An accepted socket inherits the listener's
                        // O_NONBLOCK on macOS/BSD, which would make the read
                        // below return WouldBlock before the request bytes
                        // arrive and serve a bogus 404. Force blocking reads
                        // with a timeout instead.
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        // A single read() is not guaranteed to deliver a whole
                        // HTTP request: TCP may segment it. Read until the
                        // header terminator so a partially-arrived request is
                        // never mistaken for a malformed one (which showed up
                        // as a parallel-test flake, not a real protocol fault).
                        let mut raw = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                            match stream.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                                Err(_) => break,
                            }
                        }
                        let request = String::from_utf8_lossy(&raw).into_owned();
                        let response = respond(&state_thread, &request);
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base,
            port: addr.port(),
            stop,
            handle: Some(handle),
            state,
        }
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One-shot transport-race endpoint used to prove endpoint refresh composes
/// with subsequent authority and auth refreshes. The first connection
/// atomically advertises the replacement port/token, optionally replaces the
/// repository manifest, and closes without an HTTP response, forcing the
/// provider's transport retry to re-resolve every live input.
pub(crate) struct EndpointHandoff {
    base: String,
    port: u16,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EndpointHandoff {
    pub(crate) fn spawn(
        port_file: PathBuf,
        token_file: PathBuf,
        next_port: u16,
        next_token: impl Into<String>,
    ) -> Self {
        Self::spawn_inner(port_file, token_file, next_port, next_token.into(), None)
    }

    pub(crate) fn spawn_with_manifest_rewrite(
        port_file: PathBuf,
        token_file: PathBuf,
        next_port: u16,
        next_token: impl Into<String>,
        manifest_file: PathBuf,
        replacement_manifest: Vec<u8>,
    ) -> Self {
        Self::spawn_inner(
            port_file,
            token_file,
            next_port,
            next_token.into(),
            Some((manifest_file, replacement_manifest)),
        )
    }

    fn spawn_inner(
        port_file: PathBuf,
        token_file: PathBuf,
        next_port: u16,
        next_token: String,
        manifest_rewrite: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind handoff endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking handoff endpoint");
        let addr = listener.local_addr().expect("handoff address");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop_thread = Arc::clone(&stop);
        let requests_thread = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        requests_thread.fetch_add(1, Ordering::Relaxed);
                        std::fs::write(&port_file, next_port.to_string())
                            .expect("advertise replacement endpoint");
                        std::fs::write(&token_file, &next_token)
                            .expect("advertise replacement token");
                        if let Some((manifest_file, replacement_manifest)) = &manifest_rewrite {
                            std::fs::write(manifest_file, replacement_manifest)
                                .expect("replace repository manifest before retry");
                        }
                        let _ = stream.shutdown(Shutdown::Both);
                        break;
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base: format!("http://{addr}"),
            port: addr.port(),
            stop,
            requests,
            handle: Some(handle),
        }
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for EndpointHandoff {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn parse_range(request: &str) -> Option<(usize, usize)> {
    let value = header_value(request, "range")?;
    let range = value.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    Some((start.trim().parse().ok()?, end.trim().parse().ok()?))
}

fn http_response(status: &str, extra_headers: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut wire = header.into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn respond(state: &MockState, request: &str) -> Vec<u8> {
    state.requests.fetch_add(1, Ordering::Relaxed);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");

    if path == "/health" {
        let body = serde_json::to_vec(&serde_json::json!({
            "status": "ok",
            "repo_id": state.health_repo_id.lock().unwrap().clone(),
            "repo_root": state.health_repo_root.lock().unwrap().clone(),
        }))
        .expect("serialize health");
        return http_response("200 OK", "", &body);
    }

    if path.starts_with("/vfs/") {
        if let Some(expected) = state.required_token.lock().unwrap().as_deref() {
            let authorized = header_value(request, "authorization")
                .is_some_and(|value| value == format!("Bearer {expected}"));
            if !authorized {
                state.unauthorized_requests.fetch_add(1, Ordering::Relaxed);
                return http_response("401 Unauthorized", "", b"");
            }
        }
    }

    if path == "/vfs/tree" {
        let etag = state
            .etag_header_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| {
                let identity = state
                    .snapshot
                    .lock()
                    .unwrap()
                    .identity()
                    .expect("mock tree snapshot must validate");
                format!("\"{identity}\"")
            });
        if let Some(sent) = header_value(request, "if-none-match") {
            let overridden = state.tree_body_override.lock().unwrap().is_some();
            if !overridden && sent == etag {
                return http_response("304 Not Modified", &format!("ETag: {etag}\r\n"), b"");
            }
        }
        let body = match state.tree_body_override.lock().unwrap().clone() {
            Some(body) => body,
            None => serde_json::to_vec(&*state.snapshot.lock().unwrap()).expect("serialize tree"),
        };
        state.tree_bodies_served.fetch_add(1, Ordering::Relaxed);
        if let Some(gate) = state.tree_response_gate.lock().unwrap().take() {
            gate.arrived.send(()).expect("announce gated tree response");
            gate.release
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("release gated tree response");
        }
        return http_response("200 OK", &format!("ETag: {etag}\r\n"), &body);
    }

    if let Some(hash_hex) = path.strip_prefix("/vfs/blob/") {
        state.blob_requests.fetch_add(1, Ordering::Relaxed);
        let blob = state.blobs.lock().unwrap().get(hash_hex).cloned();
        let Some(blob) = blob else {
            return http_response("404 Not Found", "", b"");
        };
        if !state.ignore_range.load(Ordering::Relaxed) {
            if let Some((start, end)) = parse_range(request) {
                if start >= blob.len() || end >= blob.len() || start > end {
                    return http_response("416 Range Not Satisfiable", "", b"");
                }
                let served_hash = state
                    .range_hash_override
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| hash_hex.to_string());
                let total = state
                    .range_total_override
                    .lock()
                    .unwrap()
                    .unwrap_or(blob.len() as u64);
                let headers = format!(
                    "Content-Range: bytes {start}-{end}/{total}\r\nX-Kin-Blob-Hash: {served_hash}\r\n"
                );
                return http_response("206 Partial Content", &headers, &blob[start..=end]);
            }
        }
        return http_response("200 OK", "", &blob);
    }

    http_response("404 Not Found", "", b"")
}
