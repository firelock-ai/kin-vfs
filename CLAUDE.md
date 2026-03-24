# kin-vfs

Purpose-built virtual filesystem for the Kin ecosystem. kin-vfs serves files directly from a content-addressed blob store, eliminating file duplication. A daemon owns the blob store and serves content over a Unix socket; a shim library (loaded via LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS) intercepts libc file operations in any process and routes them to the daemon. On Windows, the planned path is ProjFS.

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## Crate Layout

- `crates/kin-vfs-core` -- ContentProvider trait, virtual file tree, LRU blob cache, shared message types (Request/Response enums serialized with MessagePack).
- `crates/kin-vfs-daemon` -- Tokio-based daemon that listens on a Unix socket (named pipe on Windows), resolves virtual paths to blob hashes, and streams content back.
- `crates/kin-vfs-shim` -- cdylib that intercepts `open`, `read`, `stat`, `close`, etc. via `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS). Synchronous client -- no tokio runtime; runs inside arbitrary host processes.
- `crates/kin-vfs-cli` -- CLI binary (`kin-vfs`): start/stop/status commands for the daemon.
- `tests/integration` -- End-to-end tests spanning daemon + shim.

## Key Design Decisions

- **LD_PRELOAD / DYLD on Linux and macOS, ProjFS on Windows.** The shim is a cdylib loaded into any process; it overrides libc symbols to intercept file I/O transparently.
- **Synchronous client in shim.** The shim cannot assume the host process has a tokio runtime. All daemon communication is blocking I/O over a Unix socket.
- **MessagePack over Unix socket.** Request/Response messages are serialized with `rmp-serde`. Named pipe on Windows.
- **Virtual file descriptors start at 10000.** Avoids collisions with real fds the host process may hold.
- **Materialize-on-write.** Reads are virtual (served from blob store). When a tool writes to a virtual file, the shim materializes it to disk so the write lands on a real fd.
- **Thread-local socket connections.** Each thread in the shimmed process gets its own connection to the daemon, avoiding lock contention.

## Platform Notes

- The shim crate uses `#[cfg(unix)]` and `#[cfg(windows)]` gates extensively. Linux and macOS share the LD_PRELOAD / DYLD path; Windows uses the `windows` crate for ProjFS.
- Cross-compilation: the shim must be compiled for the target platform (it is a native cdylib).
- macOS requires SIP to be disabled or the binary to be unsigned for DYLD injection to work.
