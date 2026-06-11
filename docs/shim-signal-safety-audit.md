<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Firelock, LLC -->

# kin-vfs-shim signal-safety / re-entrancy audit

**Scope:** every interposed libc entry point in `crates/kin-vfs-shim` and the
shared infrastructure they all funnel through (`client.rs` thread-local daemon
client, `fd_table.rs` lock, `lib.rs` init, the `real_fn!` dlsym resolver).

**Why:** external diligence flagged async-signal-safety on the VFS interposer.
The specific path it cited did not exist, but the concern class is legitimate
for *any* `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` / fortified-symbol shim: the
symbols we export shadow libc even for the shim's own internal calls, and a
signal handler can run on a thread that is already mid-hook.

**Method:** read every `#[no_mangle]` hook end-to-end on both the macOS and
Linux code paths (the Linux-gated hooks were compile-verified with
`cargo check --target x86_64-unknown-linux-gnu`). Each entry point was assessed
against five risk classes:

1. **Async-signal-safety (ASS):** does work reachable from a signal handler
   allocate, take a non-async-signal-safe lock, or call non-ASS libc?
2. **Reentrancy:** is there a guard so a hooked function the shim itself calls
   (or a signal handler) does not re-enter shim state?
3. **Fork safety:** `pthread_atfork`; what state is inconsistent in the child
   after `fork()` from a threaded parent?
4. **Init races:** is `dlsym(RTLD_NEXT)` resolution thread-safe / what happens
   to a call that arrives during init?
5. **errno preservation:** does the shim clobber `errno` on success paths?

Line citations are against the post-fix tree on branch
`vfs-audit/shim-signal-safety`.

---

## Summary verdict

| Risk class | Pre-audit state | Post-fix state |
|---|---|---|
| Reentrancy | **No guard.** Re-entry relied on hand-proven "never call a hooked fn under a lock/borrow" invariant (see the `connect()` comment, `client.rs:157`). One real latent bug (`materialize_file` querying the daemon instead of disk). | **FIXED** — thread-local `ReentryGuard` on every primary hook; nested entry passes through to real libc. |
| errno preservation | **Clobbered on success.** Daemon socket I/O (connect/poll/read) leaves a stale `errno` that host libc wrappers checking errno-after-success (readdir EOF, read EOF) misread as failure. | **FIXED** for stat/access/read/readlink families via `ReentryGuard::ok()`. open/opendir noted as follow-up (low value). |
| Async-signal-safety | Documented inherent limitation (`intercept.rs` module header, `fd_table.rs:54`). A signal handler calling a hooked fn while a lock is held → deadlock. | **Materially mitigated** — the re-entry guard turns that deadlock into a safe passthrough for the common case. Residual first-touch-TLS window documented; full ASS remains architecturally out of reach (same as jemalloc/tcmalloc) — kill switch is the escape hatch. |
| Fork safety | **No `pthread_atfork`.** `fork()` without `exec()` from a threaded parent can inherit a held `fd_table` lock → child deadlock; shared socket fd → frame corruption. | **Open follow-up** (F1). Not a clear low-risk one-liner; fork+exec (the common case) is unaffected. |
| Init races | `dlsym` resolved lazily under `OnceLock`; abort on failure. Safe for normal calls; a signal in the *first-ever* resolution window is theoretically unsafe. | **Acceptable.** Documented (I1); pre-exists, astronomically unlikely, no regression. |

**Net:** the two clear low-risk wins named in the task (reentrancy guard, errno
save/restore) are **implemented and tested**. Fork safety is the one genuine
remaining gap and is written up as a scoped follow-up rather than rushed in
during the freeze.

---

## Shared infrastructure findings

These back every entry point, so they are assessed once here and referenced
from the table.

### S1 — `dlsym(RTLD_NEXT)` resolver — `real_fn!` macro, `intercept.rs:48`
Each real function is resolved lazily inside a `std::sync::OnceLock::get_or_init`
closure that calls `libc::dlsym`, and `std::process::abort()`s if it returns
null (`intercept.rs:61`).
- **Init race:** `OnceLock` serializes concurrent first-callers correctly. The
  closure runs at most once. **SAFE for normal calls.**
- **ASS caveat:** `dlsym` is **not** async-signal-safe, and `OnceLock` first-init
  takes an internal lock. A signal that interrupts the *very first* resolution of
  a given symbol on the process and then calls that same symbol could deadlock
  the `OnceLock`. This pre-exists and is not introduced or worsened here; in
  practice every symbol is resolved on its first normal call long before any
  signal-handler use. Logged as **I1 (follow-up, accepted risk)**.
- **abort-on-null:** correct — a missing libc symbol is unrecoverable. Not a
  silent failure.

### S2 — thread-local daemon client — `client.rs:56` (`CLIENT: RefCell<Option<SyncVfsClient>>`)
`with_client` (`client.rs:99`) holds `cell.borrow_mut()` for the whole closure,
including the socket round-trip.
- **Reentrancy (pre-fix):** **RISK.** If any call made while the borrow is live
  re-enters `with_client` on the same thread, `borrow_mut` panics; that panic
  unwinds across the `cdylib` FFI boundary and aborts the host. The code avoided
  this by hand (the `connect()` comment at `client.rs:157` documents removing a
  `sock_path.exists()` call precisely because it triggered the `stat` hook and
  re-entered). Robust only as long as nobody adds a hooked call under the borrow.
- **Post-fix:** the `ReentryGuard` on the hook boundary means any such nested
  hook entry now passes through to real libc *before* reaching `with_client`, so
  the double-borrow is structurally impossible, not just hand-avoided.
- **ASS:** the socket round-trip (`UnixStream` read/write, `connect`, `poll`)
  and `RefCell` are not async-signal-safe — inherent, mitigated by the guard +
  kill switch.

### S3 — fd table lock — `fd_table.rs:69`, wrapped `RwLock` in `lib.rs:79`
`parking_lot::RwLock`, **not recursive**.
- **Reentrancy (pre-fix):** **RISK.** A second acquisition on the same thread
  deadlocks. The hooks were careful to `drop()` the lock before any daemon call
  (e.g. `read` at `intercept.rs:899`), but, like S2, this was an unenforced
  invariant.
- **Post-fix:** guard converts a re-entrant hook call into a passthrough, so a
  second acquisition cannot originate from our own interposed symbols.
- **ASS:** `parking_lot::RwLock` is not async-signal-safe. Documented at
  `fd_table.rs:54`; mitigated by the guard for the re-entry case.

### S4 — write-notify worker thread — `client.rs:579` (`get_notify_sender`)
A background thread is spawned lazily (`std::thread::Builder`, `client.rs:584`)
and fed via a bounded `sync_channel` with `try_send` (drop-on-full).
- **ASS:** spawning a thread / channel send are not async-signal-safe, but this
  only runs on the write/close path, never from a signal handler in practice.
- **Fork:** after `fork()` the worker thread does not exist in the child, but the
  `OnceLock<SyncSender>` still holds a live sender whose receiver is gone →
  `try_send` fills and silently drops (bounded, non-blocking). **No deadlock;**
  notifications are simply lost in a forked child until `exec`. Acceptable;
  folded into **F1**.

### S5 — global init — `lib.rs:165` (`shim_init`) via `.init_array` / `__mod_init_func`
Runs before `main`. Reads env, sets `STATE: OnceLock` once. The kill switch
(`DISABLED: AtomicBool`, `lib.rs:59`) and `is_workspace_path` (`lib.rs:106`) are
atomic/read-only. **SAFE.** `STATE` is never mutated after init, so all hooks
read a stable `&'static ShimState`.

---

## Entry-point × risk table

Columns are the per-entry-point assessment **after** the fixes on this branch.
"Reentrancy" / "errno" call out what the guard does for that hook.
Fork (F1) and init-race (I1/S1) are process-global and apply uniformly — see the
follow-ups; they are not repeated per row.

### Primary file ops (shared Linux + macOS)

| Entry point | Line | ASS | Reentrancy | errno | Verdict |
|---|---|---|---|---|---|
| `open` | 584 | inherent (lock+socket) | guard → passthrough | success=fd; not restored (follow-up E1) | **SAFE** (guarded) |
| `openat` | 668 | inherent | guard; resolves `/proc/self/fd` readlink under guard → passthrough | as `open` | **SAFE** |
| `read` | 877 | inherent | guard → passthrough | **restored** on EOF + n (899: lock dropped before socket) | **SAFE** |
| `pread` | 951 | inherent | guard → passthrough | **restored** on EOF + n | **SAFE** |
| `close` | 1022 | inherent | guard → passthrough (covers shim's own `libc::close` of socket/temp fds) | n/a | **SAFE** |
| `lseek` | 1072 | local only (no socket) | guard → passthrough | local compute; no clobber | **SAFE** |
| `dup` | 755 | lock only | guard → passthrough | n/a | **SAFE** |
| `dup2` | 777 | lock only | guard → passthrough | n/a | **SAFE** |
| `dup3` (Linux) | 808 | lock only | guard → passthrough | explicit EINVAL on error | **SAFE** |
| `flock` | 844 | lock only | guard → passthrough | n/a | **SAFE** |

### stat family (shared)

| Entry point | Line | errno | Verdict |
|---|---|---|---|
| `stat` | 1100 | **restored** on success (`guard.ok(0)`) | **SAFE** (guarded) |
| `lstat` | 1136 | **restored** | **SAFE** |
| `fstat` | 1172 | **restored**; explicit EBADF on miss | **SAFE** |
| `fstatat` | 1211 | **restored** | **SAFE** |

### access / dir / mmap / symlink (shared)

| Entry point | Line | Notes | Verdict |
|---|---|---|---|
| `access` | 1254 | guard; errno **restored** on `Some(true)=>0`; explicit EACCES on false | **SAFE** |
| `faccessat` | 1292 | guard; errno **restored** | **SAFE** |
| `getdents64` (Linux) | 1395 | guard → passthrough; entries pre-fetched at open, no socket I/O here, so errno is naturally untouched (readdir-EOF-safe) | **SAFE** |
| `__getdirentries64` (macOS) | 1526 | guard → passthrough; same as above | **SAFE** |
| `mmap` | 1580 | guard; `mmap_via_tempfile`'s `libc::close(tmp_fd)` now passes through under guard; explicit EINVAL/EIO on error | **SAFE** |
| `munmap` | 1764 | guard → passthrough (runs even when disabled, preserved) | **SAFE** |
| `readlink` | 1787 | guard; errno **restored** on copy_len; out-of-workspace target → real passthrough | **SAFE** |
| `readlinkat` | 1836 | guard; errno **restored** | **SAFE** |

### Linux versioned + statx + LFS direct-fill stat

| Entry point | Line | errno | Verdict |
|---|---|---|---|
| `__xstat` | 1888 | **restored** | **SAFE** (guarded) |
| `__lxstat` | 1924 | **restored** | **SAFE** |
| `__fxstat` | 1960 | **restored**; EBADF on miss | **SAFE** |
| `statx` | 2044 | **restored**; AT_EMPTY_PATH virtual-fd lookup under guard | **SAFE** |
| `stat64` (Linux) | 2377 | **restored** | **SAFE** |
| `lstat64` (Linux) | 2409 | **restored** | **SAFE** |
| `fstat64` (Linux) | 2441 | **restored**; EBADF on miss | **SAFE** |
| `__xstat64` | 2477 | **restored** | **SAFE** |
| `__lxstat64` | 2513 | **restored** | **SAFE** |
| `__fxstat64` | 2549 | **restored**; EBADF on miss | **SAFE** |

### Thin delegating aliases — intentionally **not** guarded

These forward to a guarded primary (or, when fortified bounds are exceeded /
disabled, to the real `__*_chk`). Guarding them would be a *double* guard: the
outer alias would set the flag and the inner primary would then see it and
wrongly fall through to real libc, defeating the projection. So they are left
unguarded and inherit the primary's guard. The shim never calls these itself, so
they are never a re-entry source.

| Entry point | Line | Delegates to | Verdict |
|---|---|---|---|
| `pread64` (Linux) | 2001 | `pread` | **SAFE** (inherits) |
| `open64` (Linux) | 2315 | `open` | **SAFE** |
| `openat64` (Linux) | 2321 | `openat` | **SAFE** |
| `stat64`/`lstat64`/`fstat64` (macOS) | 2014/2020/2026 | `stat`/`lstat`/`fstat` | **SAFE** |
| `__open_2` / `__open64_2` | 2186/2196 | `open` | **SAFE** |
| `__openat_2` / `__openat64_2` | 2206/2216 | `openat` | **SAFE** |
| `__read_chk` | 2227 | `read` (or real `__read_chk` on overflow) | **SAFE** |
| `__pread_chk` / `__pread64_chk` | 2245/2264 | `pread` | **SAFE** |
| `__readlink_chk` | 2277 | `readlink` | **SAFE** |
| `__readlinkat_chk` | 2292 | `readlinkat` | **SAFE** |

---

## Fixes delivered on this branch

### Fix 1 — thread-local re-entry guard (primary)
- **What:** `IN_SHIM: Cell<bool>` thread-local (`intercept.rs:272`) +
  `ReentryGuard` RAII (`intercept.rs:281`). `ReentryGuard::enter()`
  (`intercept.rs:289`) returns `None` if the current thread is already in a hook;
  the caller then passes straight through to real libc. Wired into **every
  primary hook** right after the real-fn resolution / `is_disabled` check.
- **Why it matters (three deadlock/panic classes closed):**
  - non-recursive `fd_table` `RwLock` can no longer be re-acquired by our own
    interposed symbols (S3);
  - the client `RefCell` can no longer be double-borrowed → no FFI-unwinding
    abort (S2);
  - a **signal handler** that runs on a thread already inside a hook and calls a
    hooked I/O function now sees the flag and passes through to real libc instead
    of deadlocking on the held lock. This is the concrete, common-case mitigation
    of the documented ASS limitation.
- **Bonus correctness fix:** the shim's own intra-library libc calls now resolve
  to *real* libc instead of recursing through our hooks. In particular
  `materialize_file` (`intercept.rs:433`) calls `libc::access(target, F_OK)` to
  ask **"is this file already on real disk?"** — pre-fix that re-entered the
  `access` hook and asked the *daemon* (wrong question, latent write-path bug);
  under the guard it now hits real `access`. Likewise `cleanup_stale_temps`
  (`intercept.rs:413`) `read_dir` of the parent now reads the real directory.
- **Const-initialized TLS** (`const { Cell::new(false) }`) so the slot needs no
  lazy allocation — reads/writes are plain loads/stores, the most
  async-signal-safe TLS can be. The slot is materialized on the outermost
  normal-context entry, so a re-entering signal handler only ever loads an
  already-allocated slot.
- **Tests:** `reentry_guard_refuses_nested_entry`,
  `reentry_guard_ok_restores_entry_errno` (`intercept.rs`, tests module).

### Fix 2 — errno preservation on synthesized-success paths
- **What:** `errno()` reader (`intercept.rs:231`) mirrors `set_errno`
  (`intercept.rs:218`); `ReentryGuard` captures `errno` on entry and
  `ReentryGuard::ok(ret)` (`intercept.rs:309`) restores it before returning a
  synthesized success.
- **Where:** the stat family, `access`/`faccessat`, `read`/`pread`,
  `readlink`/`readlinkat` — i.e. the functions whose success return is commonly
  followed by an `errno` check inside host libc wrappers.
- **Why it matters:** real libc never sets `errno` on success, but the shim's
  daemon socket round-trip (`connect` → `EINPROGRESS`, `poll`/`read` → `EAGAIN`,
  …) clobbers it. A host `readdir` returning `NULL` at end-of-directory, or a
  `read` returning `0` at EOF, are distinguished from errors *by `errno`*; a
  stale leaked value would be misread as a hard error. Restoring the entry value
  keeps the success contract.
- Error paths keep their explicit `set_errno` (EIO/EBADF/EACCES/EINVAL);
  passthrough-to-real paths are untouched (real libc owns errno there).

### Non-functional hygiene
- Zero new clippy warnings and zero new `rustfmt` deviations introduced (the
  shim's 5 pre-existing fmt hunks in the `real_fn!`/fortify macro regions and the
  pre-existing clippy lints at `intercept.rs:1089`, `platform/macos.rs:40`,
  `should_open_as_dir` are untouched — out of scope for this audit, owned by the
  fmt/clippy burndown track).

---

## Follow-ups (not done here — scoped, with effort)

### F1 — fork-without-exec safety (`pthread_atfork`) — **MEDIUM (~0.5–1 day)**
**Gap:** there is no `pthread_atfork` handler. After `fork()` from a
*multithreaded* parent:
- another thread may hold the `fd_table` `RwLock` at fork time → the child
  inherits it locked forever → deadlock the first time the child touches the
  table (`parking_lot` locks are user-space atomics, not reset by fork);
- the calling thread's `CLIENT` socket fd is shared with the parent → if both
  use it, MessagePack frames interleave and corrupt;
- the notify worker thread (S4) is gone in the child but its sender lingers
  (drops silently — benign).

**Why not now:** the overwhelmingly common pattern for the tools we wrap is
`fork()` immediately followed by `exec()`, which re-loads the shim fresh and is
**unaffected**. Fork-without-exec (some test harnesses, pre-forking servers) is
the exposed case. A correct fix is a real design decision, not a one-liner.

**Recommended approach:** register `pthread_atfork` from `shim_init`
(`lib.rs:165`) with a **child** handler that sets `DISABLED = true` (the kill
switch, `lib.rs:59`) — the safest option: a forked child simply falls through to
the real filesystem instead of risking a half-initialized lock/socket. Optionally
also clear the thread-local `CLIENT` in the child. Re-initializing the
`OnceLock<ShimState>` is not possible, which is exactly why disabling (rather
than repairing) the child is the right call. Add a fork-without-exec integration
test under `tests/`.

### F2 — promote the S2/S3 "drop the lock before any hooked call" invariant to a lint/comment contract — **LOW (~1 hr)**
The guard now backstops re-entry, but the original hand-proven invariant
(`client.rs:157`) is still the first line of defense and easy to regress. Add a
module-level note and, ideally, a debug-assert that no `fd_table` lock is held
across a `client::*` call.

### E1 — errno preservation for `open`/`openat`/`opendir`-style success — **LOW (~1 hr)**
`open`/`openat` (and the directory-open path that calls `client_read_dir`) clobber
`errno` on the success fd return too. Left out because (a) callers rarely inspect
`errno` after a *successful* open, and (b) those functions have many return arms,
raising edit risk during the freeze. Mechanically identical to Fix 2 (`guard.ok`).

### I1 — `dlsym`/`OnceLock` first-resolution-during-signal window — **ACCEPTED RISK**
See S1. Pre-existing, astronomically unlikely, and not worsened. A defensive
option (eagerly resolving all `real_fn!`s from `shim_init` before `main`) would
shrink the window further but adds startup cost; not worth it now.

### Architectural note — full async-signal-safety is out of reach
A shim that serves file I/O over a socket fundamentally cannot be fully
async-signal-safe (it allocates, locks, and does blocking I/O). This is the same
constraint accepted by jemalloc/tcmalloc and is documented in the
`intercept.rs` module header and `fd_table.rs:54`. The re-entry guard closes the
**re-entry** subclass (the realistic failure mode); for processes with
genuinely hostile signal handlers the supported escape hatch remains
`KIN_VFS_DISABLE=1` (`lib.rs:167`), which makes every hook a one-atomic-load
passthrough.

---

## Test / build evidence

- `cargo test -p kin-vfs-shim` (macOS aarch64): **67 passed, 0 failed**,
  including the two new guard tests.
- `cargo check --target x86_64-unknown-linux-gnu -p kin-vfs-shim`: **clean** —
  all Linux-gated hooks (versioned `__*stat`, `statx`, LFS `*64`, fortify
  `__*_chk`) compile with the guard/errno wiring.
- `cargo clippy` (both targets): no new warnings.
- `rustfmt --check`: no new deviations (5 pre-existing hunks unchanged).
- The full inject-and-run path (`tests/shim-smoke.sh`) was **not** run — per the
  freeze policy the shim must not be activated against live processes on this
  machine; that harness is the home for the end-to-end errno/re-entry behavior
  this audit reasons about statically.
