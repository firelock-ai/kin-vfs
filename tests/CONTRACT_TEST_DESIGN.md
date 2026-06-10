<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Firelock, LLC -->

# VFS provider↔daemon contract test — design (post-freeze)

Status: **design only — not yet implemented.** Authored alongside the Linux
`statx`/`_FORTIFY_SOURCE`/LFS shim hooks (task #16). Building and running this
test is deferred to post-freeze because it boots a real daemon; the freeze
forbids spawning daemons. This document is precise enough to implement directly.

## Why this gap matters

Per `planning/kin-vfs-linux-statx-fortify-scope.md` §3, there is **no automated
test of the real provider↔daemon HTTP contract**. Today:

- `tests/conformance` exercises any `ContentProvider` in-process (in-memory
  `TestProvider`) — it never speaks the wire protocol.
- `tests/shim-smoke.sh` runs the shim daemon-less.
- The `KinDaemonProvider` ↔ kin-daemon (`:4219`) HTTP routes are verified **by
  hand only**: `/health`, `/vfs/version`, `/vfs/tree`, `/vfs/read/{path}`,
  `/vfs/write-notify`.

Without an automated contract test, the daemon and provider can drift out of
alignment silently even after the `statx`/fortified hooks land — the shim would
serve correct calls to a provider that no longer matches the daemon's wire shape.

## What the test must verify

Boot a real daemon (or a route-faithful HTTP stand-in) and assert the
`KinDaemonProvider` honors the contract end-to-end for each route:

| Route | Assertion |
|-------|-----------|
| `GET /health` | 200; body parses; provider treats daemon as reachable. |
| `GET /vfs/version` | Monotonic/stable version token; provider caches and invalidates on change. |
| `GET /vfs/tree` | Returns the virtual tree; provider maps paths→hashes correctly. |
| `GET /vfs/read/{path}` | Byte-exact content for a known blob; `read_range` honors offset/len and past-EOF returns empty. |
| `POST /vfs/write-notify` | Write notification is accepted; subsequent `stat`/`read` reflect the materialized change. |

Stat-shape assertions (the reason the shim hooks exist) must be covered too:
`VirtualStat` round-trips with correct `is_file`/`is_dir`/`is_symlink`, `size`,
`mode`, `mtime`/`ctime`, and `nlink` — these are exactly the fields
`platform::{fill_stat_buf, fill_stat64_buf, fill_statx_buf}` consume.

## Proposed shape

- **Home:** a new `tests/contract` crate (sibling of `tests/conformance`),
  depending on `kin-vfs-core`, `kin-vfs-daemon`, and a blocking HTTP client.
- **Harness:**
  1. Build a `VfsDaemonServer` over a `KinDaemonProvider` backed by a seeded
     in-process blob store (the conformance fixture: `src/main.rs`, `src/lib.rs`,
     `README.md`), bound to an ephemeral port.
  2. Point a `KinDaemonProvider` client at that port.
  3. Drive each route via the client and assert against the fixture.
  4. Tear the server down deterministically (no port/process leak).
- **Gating (freeze-safe):** mark each test `#[ignore]` and additionally gate on
  an env flag (e.g. `KIN_VFS_CONTRACT=1`) so it never runs in the default suite
  or under the freeze, only when explicitly invoked. It rides the **new Linux
  CI** lane, where the shim hooks below also get their first real runtime check.
- **No GPU, no kin-daemon-on-:4219 dependency in CI:** use the in-process
  `VfsDaemonServer` so the test is hermetic; a separate, manually-run smoke can
  target a real `:4219` daemon.

## Honesty matrix (tool-scope) — to publish alongside

Per spec §4, document exactly which tools the projection covers so users know the
real boundary. With the task #16 hooks landed, the Linux column is:

| Surface | macOS | Linux (post-#16) |
|---------|-------|------------------|
| `open`/`openat`, `read`/`pread` | ✅ | ✅ |
| `stat`/`lstat`/`fstat`, `fstatat` | ✅ | ✅ (+ `__xstat` family) |
| `statx(2)` (modern coreutils) | n/a | ✅ **(new)** |
| `_FORTIFY_SOURCE` `__open_2`/`__read_chk`/`__readlink_chk` | n/a | ✅ **(new)** |
| LFS `open64`/`openat64`, `stat64`/`__xstat64` family | n/a | ✅ **(new)** |
| SIP-protected system binaries (`/usr/bin/*`) | ❌ SIP strips `DYLD_*` | n/a |
| Static binaries (no libc dynamic link) | ❌ | ❌ (use FUSE mount) |

Unsupported cells are the honest boundary of the LD_PRELOAD/DYLD shim; the FUSE
mount mode (`--features fuse`) covers static binaries and SIP cases.

## Runtime-verification limits of the #16 hooks (state plainly)

The `statx`/fortified/LFS hooks are `#[cfg(target_os = "linux")]`. On the macOS
build host they were verified by:

- native `cargo build`/`test` (cross-platform `statfill` logic — mode bits,
  block counts, fortify bounds — runs and passes on the host), and
- `cargo check --target x86_64-unknown-linux-gnu` (compiles the full Linux hook
  set against real Linux libc, validating every `libc::statx`/`stat64` field and
  signature).

**Not yet verified, requires Linux CI runtime:** actual symbol interposition
(that a fortified `ls`/`stat` resolves to our hooks under `LD_PRELOAD`), the
`statx`/`stat64` struct byte-layout as consumed by real coreutils, and the
fortify overflow-abort delegation. This contract test plus a coreutils smoke
under the new Linux CI are what close that gap.
