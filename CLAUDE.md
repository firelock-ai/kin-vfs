> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-vfs`.

# kin-vfs

Purpose-built virtual filesystem for the Kin ecosystem. It serves files from a content-addressed blob store, so working trees look like ordinary directories: no extra disk, instant checkouts, transparent reads for any tool that opens a file. `kin-vfs-core` is standalone-valuable beyond Kin.

## Key Design Decisions

- **Byte-exact path identity.** Every path identity, including cache keys and protocol fields, is a validated `VfsPath`/`VfsName` of raw bytes, never a `String`. Unix paths are byte sequences: demanding UTF-8 would drop non-UTF8 workspace files through to raw disk, and decoding lossily would address the wrong artifact. Windows fails loud on a name it cannot represent.

- **Graph truth is versioned and content-addressed.** `GET /vfs/tree` returns one schema-versioned document carrying ref identity, monotonic version, etag and exact resolved artifacts, and freshness rides one conditional `If-None-Match`, so there is no version-then-tree window. Bytes come only from `/vfs/blob/<hash>` for the exact `Hash256` that tree advertises, verified before use, so a path reuse or ref race cannot return another artifact's bytes. Contract in `docs/authority-and-write-notify-contract.md` and `tests/fixtures/`.

- **LD_PRELOAD and DYLD on Linux and macOS, ProjFS on Windows.** The shim is a cdylib routing workspace-root paths to the daemon and its `ContentProvider`. Linux shadows libc symbols and resolves the real ones with `dlsym(RTLD_NEXT)`. macOS has a two-level namespace, so it ships a `__DATA,__interpose` table dyld applies at load time, with no `dlsym`. Windows ProjFS callbacks need a live process to service them where LD_PRELOAD piggybacks on the host, so `shim_init_windows()` needs a caller that stays alive.

- **Synchronous client in the shim.** It cannot assume the host has a tokio runtime, so every daemon exchange is blocking I/O over a Unix socket, or a named pipe on Windows, with `VfsRequest`/`VfsResponse` serialized by `rmp-serde` inside length-prefixed frames.

- **Virtual file descriptors start at 10,000,** clear of real kernel-assigned fds the host holds (Linux and macOS only), and each thread gets its own connection, so nothing contends on the socket.

- **Materialize on write.** Reads stay virtual, from the blob store; writes land on real disk fds, so build tools, editors and version control need no special handling.

- **A FUSE mount is writable only with a `WorkspaceWriter`.** Then `write`, `create`, `unlink`, `rename` and `truncate` land on the workspace path and block until `provider.stat(path)` reports the exact content hash now on disk, so a write is done only when the graph reports it. Without a writer every mutation returns `EROFS`. `mkdir` marks the new directory pending, because an empty directory is no graph artifact and there is nothing to reconcile.

- **Kill switch.** `KIN_VFS_DISABLE=1` stops all interception, and the shim disables itself silently when `KIN_VFS_WORKSPACE` is unset.

- **A projection root must be a repository, not a directory holding `.kin`.** The shim admits `KIN_VFS_WORKSPACE` only when the root carries `.kin/manifest.json`, and kin-vfs's own walk up from the given path applies the same test. `$KIN_HOME` (default `$HOME/.kin`) is a real `.kin` directory of binaries, so a walk that asks only whether `.kin` is a directory binds `$HOME` as a root, and every path under it then fails `EIO` whether it exists or not, since a workspace path must never be answered from raw disk. The daemon reads that manifest to bind identity anyway, so such a root was never servable.

- **Auto-init on library load.** `.init_array` on Linux, `__DATA,__mod_init_func` on macOS, so `shim_init()` runs before `main()`.

## Environment Variables

`KIN_VFS_WORKSPACE` is required, the absolute workspace root, subject to the manifest rule above. `KIN_VFS_SOCK` defaults to `$KIN_VFS_WORKSPACE/.kin/vfs.sock`, `KIN_VFS_PIPE` to `\\.\pipe\kin-vfs-{hash}` on Windows. `KIN_SESSION_ID` scopes a projection to a session. `KIN_VFS_STRICT=1` refuses (`EIO`) rather than reports absent (`ENOENT`) a path the graph does not hold, and makes the launcher refuse a stripped interposition. `KIN_VFS_LOG` sets the CLI log filter, default `info`.

## Build And Run

`cargo build --workspace` and `cargo test --workspace` cover the workspace, `cargo build --release -p kin-vfs-shim` produces the cdylib you inject, and `cargo run -p kin-vfs-cli -- start --workspace /repo` starts the daemon. Inject that library with `LD_PRELOAD` on Linux or `DYLD_INSERT_LIBRARIES` on macOS. `--features fuse` adds `mount`, `unmount` and `fuse-status` to the CLI.

FUSE is source build only on macOS, where it links through pkg-config, and available on Linux through the `fusermount3` helper, where it links no library. The shim is a native cdylib, built per target and never cross-compiled; it carries `#![allow(clippy::missing_safety_doc)]` because the `#[no_mangle]` libc hooks are inherently unsafe FFI.

Use the shim for write-through and per-process control, in-process and almost free. Use FUSE for a system-wide mount, for static binaries the shim cannot reach, and to escape macOS SIP, which strips `DYLD_INSERT_LIBRARIES` for system-protected binaries, leaving the shim Homebrew or unprotected targets only. FUSE costs kernel round-trips and an install: `fuse3` on Linux, and on macOS prefer FUSE-T (userspace, no kext, `brew install fuse-t`) to macFUSE.

## Debugging

**Nothing is intercepted, or the daemon will not start.** Check the projection root and `KIN_VFS_DISABLE` first, then `kin-vfs status --workspace <path>`. `start` cleans a stale `.kin/vfs.sock` itself and `.kin/vfs.pid` records the PID; remove either by hand only after confirming no live lane lock or process owns the daemon. `KinDaemonProvider` needs kin-daemon on 4219.

**FUSE mounts.** `kin-vfs fuse-status --workspace . --mount-point <dir>` reports capability and state: mounted, readable, writable, or degraded with the reason. Auto-unmount is on by default when the `kin-vfs mount` process exits; `--no-auto-unmount` turns it off. On Linux it needs `allow_other`, which `fusermount3` grants a non-root user only when `/etc/fuse.conf` carries an uncommented `user_allow_other`, and the mount degrades loudly rather than failing when it cannot arm it. A `--read-only` mount returns `EROFS` for every write, and a writable mount refuses a save the graph did not take, surfacing as `EIO`, its log naming the path that did not converge.

**Windows ProjFS is proven, not shipped.** The `ProjFS live proof (windows-latest)` CI job drives `shim_init_windows()` against a real daemon and named pipe, reading, listing and writing the projected root. Nothing else calls it and no crate here depends on `kin-vfs-shim`, so no installed binary starts a projection. Shipping one needs `"rlib"` beside the shim's `crate-type = ["cdylib"]`, a resident `kin-vfs-cli` command holding the provider, and that executable in the `kin` release archive. `Client-ProjFS` is already `Enabled` on the `windows-latest` image, no enable step and no restart. Only notifications named in `WRITE_THROUGH_NOTIFY_MASK` reach `notification_cb`, and the default mapping a provider gets when it supplies none carries neither the close-after-modify an editor save produces nor the rename, so a write-through that looks wired can deliver nothing.

## Relationship To The Ecosystem

`kin` consumes `kin-vfs-core` through the registry and release-clean path; local sibling patches are DEV-LOCAL iteration only, never proof. `kin-vfs-daemon` bridges to kin-daemon on 4219 through `KinDaemonProvider` for blob resolution. `kin setup` and the one-line installer install kin-vfs. In native mode (`kin mode native`) it serves every file read from the blob store, so the filesystem is fully virtual.
