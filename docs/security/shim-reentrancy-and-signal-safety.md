# Interposition Shim: Re-entrancy and Signal Safety

This note documents how the `kin-vfs-shim` interposition layer handles
re-entrancy and signal safety, for a reviewer auditing the correctness of a
library that is injected into arbitrary host processes. It describes behavior as
implemented in
[`crates/kin-vfs-shim/src/`](../../crates/kin-vfs-shim/src/) — primarily
`intercept.rs`, `lib.rs`, `client.rs`, and the macOS C translation unit
`macos_interpose.c` — and states the limitations honestly, including the one
case (signals + held locks) that is an inherent constraint rather than a solved
problem.

For the ecosystem-level projection trust boundary see the `kin` threat model
(`kin/docs/security/threat-model.md`); for vulnerability reporting see
[SECURITY.md](../../SECURITY.md).

## Why This Is Hard

The shim is a `cdylib` loaded into a host process via `LD_PRELOAD` (Linux) or a
`__DATA,__interpose` table (macOS), and it exports the very libc symbols it
hooks (`open`, `read`, `close`, `stat`, `mmap`, …). Two structural hazards
follow directly from that:

1. **Self-re-entry.** Because the shim's exported `close`/`access`/`stat`/…
   shadow libc *even for calls the shim itself makes*, any hooked function that
   internally calls one of those symbols re-enters the shim. The shim's own
   intra-library libc calls (closing a socket fd, `std::fs::write` in the
   materialize path, `access` probes) would otherwise recurse through its own
   hooks.
2. **Signal re-entry.** A signal handler can run on a thread that is already
   inside a hook. If that handler calls a hooked I/O function while the
   interrupted frame holds shim state, the second entry collides with the first.

Re-entry is not merely slow; it is **fatal** in three specific ways the code
calls out:

- The fd-table `parking_lot::RwLock` is **not recursive**: a second acquisition
  on the same thread deadlocks.
- The per-thread daemon client is a `RefCell`; a second `borrow_mut` while one is
  live panics, and a panic unwinding across the `cdylib` FFI boundary **aborts
  the host process**.
- A signal handler that calls a hooked function while the interrupted frame holds
  either primitive deadlocks or panics the host.

## The Re-entry Guard

Every primary hook is made re-entry-safe by a thread-local guard
(`ReentryGuard` over the `IN_SHIM` thread-local `Cell<bool>` in `intercept.rs`):

- The **outermost** hook entry on a thread sets the flag and runs the real shim
  logic. Any **nested** entry observes the flag set, `ReentryGuard::enter()`
  returns `None`, and the hook passes **straight through to the real libc
  function**, touching no shim state (no lock, no `RefCell`). This is the same
  technique malloc-replacement shims (jemalloc, tcmalloc) use.
- This single mechanism covers both self-re-entry and the synchronous part of
  signal re-entry: a handler that calls a hooked function from a frame already
  marked in-shim is bounced to real libc rather than re-entering the lock or the
  `RefCell`.

The guard is built to be as signal-tolerant as the technique allows:

- The `IN_SHIM` flag is **`const`-initialized** (`const { Cell::new(false) }`),
  so its TLS slot needs no lazy allocation. Reads/writes are plain loads/stores —
  the most async-signal-safe TLS can be.
- The slot is materialized on the **outermost, normal-context** entry, so a
  signal handler re-entering only ever *loads* an already-allocated slot; it
  never triggers first-touch TLS allocation from signal context.
- On synthesized-success paths the guard restores the caller's entry `errno`
  (`ReentryGuard::ok`). The shim's own daemon socket I/O (connect/poll/read)
  clobbers `errno`; without restoration, host libc wrappers that inspect `errno`
  after a successful call (e.g. `readdir`/`read` EOF detection) would misread a
  stale value as failure.

A unit test (`reentry_guard_refuses_nested_entry`) asserts the outer entry
succeeds, a nested entry is refused, and a fresh entry succeeds again after the
outermost guard drops; another (`reentry_guard_ok_restores_entry_errno`) asserts
the `errno` save/restore behavior.

## Signal-Safety Limitation (stated, not hidden)

The shim's two core primitives — `parking_lot::RwLock` (fd table) and
thread-local `RefCell` (socket client) — are **not async-signal-safe**. The
re-entry guard prevents a signal handler from *re-entering* shim state, but it
**cannot** make the underlying lock safe if a signal interrupts a thread that is
**already holding the fd-table write lock** and the handler then calls a hooked
function. In that window, deadlock is possible.

This is an inherent limitation of any `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` shim
that intercepts low-level I/O syscalls; the same constraint exists in
jemalloc/tcmalloc. The code documents it rather than papering over it. The
mitigations available to an operator are:

- **The kill switch.** `KIN_VFS_DISABLE=1` disables all interception instantly;
  every hook checks `is_disabled()` at entry and passes through to real libc. A
  process known to do aggressive signal handling can opt out entirely.
- **Fail-open by construction.** Every hook's first action (before any
  thread-local or lock) is the `is_disabled()` check, and on any error a hook
  passes through to the real syscall — the code's standing rule is *never panic
  in a hook; on any error, passthrough.*

## Pre-Initialization Window (macOS)

On macOS the `__interpose` table is live as soon as the image loads, so dyld can
route libSystem calls through the shim's hooks **before** the
`__DATA,__mod_init_func` constructor (`shim_init`) has run — i.e. before the
global `STATE` exists. Two defenses make that window safe:

- The kill switch `DISABLED` **starts `true`** and is cleared only after `STATE`
  is successfully set. Every hook therefore passes straight through to real libc
  during the pre-constructor window instead of dereferencing unset state.
- `close` and `munmap` perform the `is_disabled()` fast-path check **before**
  touching any thread-local, because on macOS those fire during
  `libSystem_initializer` (malloc/feature-flag setup calls `close`) before TLS is
  bootstrapped; reaching the `ReentryGuard` thread-local there would abort with a
  TLS bootstrap error. While disabled there are no virtual fds to reclaim, so the
  passthrough is correct.

## Recursion-Free Real-Symbol Resolution (macOS)

A hook must call the genuine libc function to forward to. On Linux that is
`dlsym(RTLD_NEXT, sym)`. On macOS `dlsym` is **unsafe here**: with the interpose
table live, the first `dlsym` during early startup runs libc internals that are
themselves interposed, recursing into the hooks before init completes → stack
overflow (verified as a SIGSEGV/`EXC_BAD_ACCESS`). Instead, the C TU
`macos_interpose.c` exposes `kin_real_<name>()` accessors that return
`&<libSystem symbol>` via a plain load-time bind (never routed through
`__interpose`), so Rust gets the real pointer with **zero `dlsym` and zero
recursion**.

The same C TU carries the `__DATA,__interpose` table itself, because the
`replacee` slots must bind to the real libSystem symbols — something a pure-Rust
table cannot express (a Rust `libc::open` reference coalesces with the shim's own
`#[no_mangle] open`, leaving both interpose slots pointing at the hook, a
verified no-op). The table length is pinned by a `_Static_assert` against the
`KIN_INTERPOSE_EXPECTED` value `build.rs` passes in, and a Rust test
(`macos_interpose_table_covers_all_hooks`) cross-checks the entry count, so a
truncated or missing table fails the build rather than silently shipping a shim
that reads raw disk.

## Materialize-on-Write Path

Writes are not served virtually; they are **materialized to a real fd** so build
tools, editors, and VCS behave normally. The path is designed to avoid both
re-entrancy and silent filesystem-authority drift:

- On a write-flagged `open`/`openat`, `materialize_file()` consults **graph
  truth first** via the daemon. If the daemon has content for the path, it seeds
  an atomic temp file `{path}.kin_tmp_{pid}`, the tool writes to that temp fd,
  and on `close` the shim renames temp → target and notifies the daemon. If the
  graph has no record of the path (a genuinely new file, or the daemon is
  unreachable), the shim defers to the real filesystem so the tool can create the
  file. Authority semantics are explicit: **graph wins** where it has content;
  the disk is used only where the graph is silent.
- The atomic-write temp suffix is **excluded from interception**:
  `is_workspace_path()` returns `false` for any path containing `.kin_tmp_`.
  Because `materialize_file()` writes the temp via `std::fs::write` (which calls
  the hooked `open`), without this exclusion that write would re-enter the daemon
  for a path that does not exist in the tree. The exclusion removes both the
  wasted round-trip and a re-entrancy edge.
- Stale `.kin_tmp_*` files from previously crashed processes are cleaned up on
  open, so a crash mid-write does not strand temp files or corrupt the target
  (a failed rename leaves the temp on disk but never a partially written target).

## Thread-Local Daemon Client and Its Re-entry Hazards

Daemon communication uses **synchronous** `std` I/O (not tokio) because the host
process may have no async runtime, and **each thread gets its own connection**
via a thread-local `RefCell<Option<SyncVfsClient>>` (`client.rs`) to avoid lock
contention on the socket. Two re-entrancy hazards are handled explicitly in this
file:

- `SyncVfsClient::connect` **must not** call `Path::exists()` on the socket path,
  because `exists()` issues a `stat` the shim intercepts, causing a re-entrant
  `RefCell` borrow panic. The code uses a non-blocking `connect` + `poll` with a
  timeout instead, and a comment marks the hazard at the call site.
- The interposition-canary announcement runs on a **dedicated thread with its own
  short-lived connection** and must never touch the thread-local `CLIENT`, whose
  `RefCell` may already be borrowed by the in-flight `with_client` call that
  triggered the announce.

The synchronous client is also bounded so a hook can never block a host process
indefinitely: a single connect attempt times out (`CONNECT_TIMEOUT`), reads and
writes time out (`IO_TIMEOUT`), and reconnects are capped (`BACKOFF_MAX_RETRIES`
with bounded jittered backoff, ~500 ms total wall time) before the hook gives up
and falls through.

## Summary for a Reviewer

- Re-entrancy (self and synchronous-signal) is handled by a `const`-initialized,
  plain-load thread-local guard that bounces nested entries to real libc; it is
  tested.
- The fd-table lock and socket `RefCell` are **not** async-signal-safe, and the
  one residual hazard — a signal interrupting a thread that already holds the
  fd-table lock and then calling a hooked function — is documented, not claimed
  fixed. The kill switch (`KIN_VFS_DISABLE=1`) and the fail-open
  `is_disabled()`-first design are the operator mitigations.
- The macOS pre-init window, recursion-free real-symbol resolution, and the
  build-time interpose-table length assertion close the macOS-specific failure
  modes.
- The write path materializes from graph truth atomically and excludes its own
  temp files from interception to avoid both authority drift and a re-entrancy
  edge.
