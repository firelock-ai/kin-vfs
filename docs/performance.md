# Performance Tuning

Guidelines for optimizing kin-vfs throughput and latency.

## LRU Cache Tuning

The VFS core uses an LRU cache (`VfsCache` in `kin-vfs-core/src/cache.rs`) to avoid redundant daemon round-trips. The cache stores both stat metadata and file content keyed by path.

**Default capacity:** Set at construction time by the caller. A capacity of 1 is the minimum (enforced by `NonZeroUsize`).

**Tuning guidance:**
- For typical development workspaces (< 10k files), a cache capacity of 4096-8192 entries works well.
- For monorepos or large generated codebases, increase to 16384+.
- Each cached entry holds a clone of the file content, so memory usage scales with the average file size multiplied by capacity.
- The cache invalidates on version changes broadcast by the daemon (500ms polling interval). Stale reads are bounded by this interval.

## Version Polling Interval

The daemon's `version_poller` checks the content provider's version counter every 500ms. When the version changes, it broadcasts an invalidation event to all subscribed shim clients.

**Trade-off:** A shorter interval reduces cache staleness but increases provider load. 500ms is a good default for local development. For CI environments where content changes less frequently, this interval could be increased.

## Thread-Local Connections

Each thread in a shimmed process gets its own `SyncVfsClient` connection to the daemon (via `thread_local!` in `client.rs`). This eliminates lock contention on the socket.

**Implications:**
- Highly parallel tools (e.g., `cargo build` with many codegen threads) will open many simultaneous connections. The daemon handles this via tokio's async accept loop.
- Connection count equals the number of threads that perform file I/O in the shimmed process.
- Connections are lazily established and reused. A failed request triggers reconnection with exponential backoff.

## Reconnection Backoff

When the daemon is temporarily unavailable, the shim uses exponential backoff with jitter on reconnect attempts: starting at 100ms, doubling each retry, capped at 5s, with +/-25% jitter. The backoff resets on successful connection. This prevents thundering herd problems when the daemon restarts under many shimmed processes.

## Native vs Compatibility Mode

Kin operates in two filesystem modes (configured via `kin mode`):

**Native mode** (`kin mode native`): All file reads are served from the blob store through the VFS. Files do not need to exist on disk. Maximum storage efficiency and instant branch switching.

**Compatibility mode** (`kin mode compat`): Files exist on disk as normal. The VFS shim is not required. Standard git workflows work unmodified.

**When to use native mode:**
- Large repos where disk usage matters
- Workflows that benefit from instant checkout (no file materialization)
- CI pipelines that only read source files (no writes to tracked paths)

**When to use compatibility mode:**
- Tools that bypass libc (direct syscalls, io_uring, Rust's `std::fs` in some configurations)
- Environments where `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` is restricted (SIP, SELinux)
- Debugging scenarios where you need real files on disk

## Reducing Latency

- **Keep the daemon local.** The Unix socket path should be on the same filesystem as the workspace. Network-mounted socket paths add latency.
- **Avoid unnecessary shim injection.** Only set `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` for processes that actually read workspace files. Global injection adds overhead to every process.
- **Monitor daemon load.** Use `lsof -p <daemon-pid> | wc -l` to check open connections. If connection count is persistently high, the daemon's tokio runtime may benefit from more threads.
