<div align="center">
<a href="https://github.com/firelock-ai/kin"><picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/kin-logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="brand/kin-logo-light.svg">
  <img src="brand/kin-logo-light.svg" alt="Kin" width="260">
</picture></a>
</div>

# Kin VFS: Transparent Filesystem Projection

> **Software that remembers itself.**
>
> Exact context, not more.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

`kin-vfs` is the transparent filesystem projection for the Kin ecosystem. It serves graph-owned Kin repository state to existing file-first tools, including compilers, linters, editors, and build systems, as ordinary files through normal filesystem calls.

> Part of **[Kin](https://github.com/firelock-ai/kin)**, the semantic system of record for AI-written software. Learn more at **[kinlab.ai](https://kinlab.ai)**.

> [!IMPORTANT]
> The projection surface is not as portable as the core Kin CLI. The public
> macOS builds support Apple Silicon and Intel. The public Linux VFS builds are
> dynamically linked GNU/glibc binaries and currently require glibc 2.39.
> Alpine and other musl hosts are not supported for VFS projection, even though
> the static `kin` and `kin-daemon` binaries can run there. On Linux arm64, the
> public projection path is release-tested on Ubuntu 24.04; Debian 12 and other
> older-glibc arm64 distributions do not meet the current binary requirement.

## Install

`kin-vfs` ships inside the main Kin distribution. There is no separate `cargo install kin-vfs` package or standalone VFS binary release today.

### Recommended: Kin installer

On macOS or Linux:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the current Kin release, verifies its published SHA-256 checksum, and installs `kin`, `kin-daemon`, `kin-vfs`, and the platform shim under `~/.kin` when that release provides them for the host architecture. It then runs the guided `kin setup` flow, which installs the shell hook used to activate VFS projection inside Kin repositories. Installing the files does not override the libc and injection limits below.

### Homebrew

```sh
brew install firelock-ai/kin/kin
kin setup --intent local
```

The Kin formula installs `kin-vfs` and its shim from the same release archive when they are available for the host platform.

### npm

```sh
npm install -g @kinlab/kin
kin setup --intent local
```

`@kinlab/kin` is a native launcher. On first use it downloads and checksum-verifies the matching Kin release archive under `~/.kin`, including the VFS files on supported hosts.

## First run

Initialize a repository, make sure its Kin daemon is running, then reload the shell hook from inside that repository:

```sh
cd /path/to/repository
kin init
kin status
exec "$SHELL" -l
kin-vfs status --workspace .
```

The setup hook detects `.kin/` when the shell starts or changes directory, starts the per-repository VFS daemon in the background, and loads the platform shim. `kin-vfs status` should report a healthy VFS daemon and a reachable `kin-daemon` provider.

For a single explicit launch, without relying on automatic shell activation:

```sh
kin-vfs exec --workspace . -- your-command arg1 arg2
```

`kin-vfs exec` sets the required interposition environment for the child process. When the VFS daemon is reachable, it also checks whether the shim actually loaded. On macOS, System Integrity Protection or a hardened executable may strip `DYLD_INSERT_LIBRARIES`; the launcher reports that condition instead of silently treating a raw filesystem read as graph-backed.

## Current platform and package boundaries

| Platform or mode | Current public distribution |
| --- | --- |
| macOS, Apple Silicon and Intel | **Supported public projection path.** The Kin archive includes `kin-vfs` and `libkin_vfs_shim.dylib`, and release proof exercises both architectures. Projection uses `DYLD_INSERT_LIBRARIES`; SIP-protected or hardened programs may reject injection. |
| GNU/Linux x86_64 | **Supported on glibc 2.39 or newer.** The archive includes a dynamically linked `kin-vfs` and `libkin_vfs_shim.so`. The static core CLI is more portable than these projection files. Alpine/musl and older-glibc hosts are not supported. |
| GNU/Linux arm64 | **Supported on the release-tested Ubuntu 24.04 arm64 path.** The public VFS executable currently requires glibc 2.39. Debian 12 arm64, Alpine arm64, and other hosts that do not provide that ABI are outside the supported projection boundary. |
| Linux with musl, including Alpine | **Not supported for VFS projection.** The release archive's core `kin` and `kin-daemon` binaries are static musl builds, but `kin-vfs` and its preload shim are separate GNU/glibc artifacts. Core CLI success must not be treated as VFS success. |
| Native Windows | **Not shipped for VFS projection, though the ProjFS provider's read path is now proven against a live filesystem.** The Kin archive still carries no Windows projection files, and no shipped binary starts the provider, so a native Windows install has no projection today. What changed is the evidence behind the read path: the `ProjFS live proof (windows-latest)` CI job virtualizes a real directory over a real daemon on every run, then reads and lists it from a separate PowerShell process. A write through the projection emits a `/vfs/write-notify` notification, and a repository-v6 `kin-daemon` no longer serves that route, so the proof shows the notification was sent rather than that the graph took the write. Use WSL2 with a Linux distribution that provides glibc 2.39 or newer for the supported Windows-hosted path. |
| FUSE mount on GNU/Linux | **Shipped in the public Linux `kin-vfs` binaries.** Both x86_64 and arm64 release builds enable the `fuse` feature. The host needs the distribution's `fuse3` package at run time; the binary mounts through `fusermount3` and links no FUSE library. See [FUSE mount](docs/fuse-mount.md). |
| NFS mount on macOS | **Shipped in the public Apple Silicon and Intel `kin-vfs` binaries.** Both release builds enable the `nfs` feature. The NFS client is built into macOS. The write-side concurrency caveat below is separate from packaging. |
| Other mount combinations | macOS FUSE and Linux NFS remain source-build paths. Native Windows projection is not shipped. |

The core Kin CLI has a wider platform envelope than the projection shim. A successful `kin --version` does not prove that VFS projection is available. Use `kin setup status` and `kin-vfs status --workspace .` to check the installed projection files and live daemon, then run a real command through `kin-vfs exec`. The public [Install Proof workflow](https://github.com/firelock-ai/kin/actions/workflows/install-proof.yml) exercises graph-owned bytes through the installed shim rather than relying on setup metadata alone.

## How it works

Instead of forcing tools to call a graph API, `kin-vfs` projects Kin's semantic graph onto familiar filesystem operations.

- **Dynamic interception:** Linux loads the shim through `LD_PRELOAD`. macOS uses a `__DATA,__interpose` table loaded through `DYLD_INSERT_LIBRARIES`.
- **Graph-first serving:** A read under a Kin-managed workspace is resolved through the local VFS daemon and `kin-daemon` graph store, with content hashes checked on the way back.
- **Materialize on write:** Reads come from graph truth. When a tool writes to a virtual file, the shim first seeds a real file from graph truth, then lets the write land on a real file descriptor. Paths outside the workspace pass through to the host filesystem.
- **Fail-loud launcher:** When the VFS daemon is reachable, `kin-vfs exec` uses an interposition canary so a stripped shim is reported instead of being mistaken for a graph-backed run.

## Structure

- **`crates/kin-vfs-core`:** Shared primitives, including `ContentProvider`, path mapping, stat types, protocol types, errors, and the blob cache.
- **`crates/kin-vfs-daemon`:** The Unix socket or named-pipe server that resolves virtual paths and bridges to `kin-daemon`.
- **`crates/kin-vfs-shim`:** The injected `cdylib` interception layer for Linux and macOS, plus the Windows ProjFS provider. The provider's read path is exercised live in CI, no shipped binary starts it, and its write-through notification targets a daemon route that no longer exists, so it is not yet a Windows projection path a user can run.
- **`crates/kin-vfs-fuse`:** Optional FUSE mount mode behind the `fuse` feature. Public Linux binaries include it; macOS remains a source-build path.
- **`crates/kin-vfs-nfs`:** Optional NFSv3 mount mode behind the `nfs` feature. Public macOS binaries include it; Linux remains a source-build path.
- **`crates/kin-vfs-cli`:** The `kin-vfs` CLI. On every supported Unix platform where the binary ships, it includes `start`, `stop`, `status`, and `exec`. Public Linux binaries also include FUSE commands, and public macOS binaries also include NFS commands.
- **`shell/`:** Shell hooks that activate projection when entering a Kin workspace.
- **`tests/`:** Integration and regression coverage for host filesystem behavior.

## Build from source

The default source build exposes the shared shim command surface. Public Kin
archives add the platform mount feature at release time: FUSE on GNU/Linux and
NFS on macOS.

```sh
cargo build --release -p kin-vfs-cli -p kin-vfs-shim
cargo test --workspace
```

The outputs are:

- `target/release/kin-vfs`
- `target/release/libkin_vfs_shim.dylib` on macOS
- `target/release/libkin_vfs_shim.so` on Linux

Because the CLI looks for the shim beside its executable, you can exercise that build directly:

```sh
target/release/kin-vfs exec --workspace /path/to/kin-repository -- your-command
```

FUSE and NFS are optional and require their platform dependencies:

```sh
cargo build --release -p kin-vfs-cli --features fuse
cargo build --release -p kin-vfs-cli --features nfs
```

On Linux FUSE needs the `fuse3` package at run time and nothing at build time. On macOS it links FUSE-T or macFUSE through `pkg-config`, so it stays a source build there. [FUSE mount](docs/fuse-mount.md) covers both. `scripts/fuse-mount-proof.sh` proves mounted graph-backed reads and write reconciliation into current graph workspace state, then makes a separate explicit Kin commit.

NFS needs nothing installed on macOS, because the NFS client is built into the
system and the server runs in this process. That is what makes it the projection
with none of the shim's failure modes: the kernel does the interception, so a
hardened runtime, a SIP-protected binary, or a statically linked program reads
graph-backed files like any other.

The current public Kin archives build these same feature paths: FUSE on GNU/Linux
and NFS on macOS. The inverse platform combinations remain contributor and
advanced-user source builds. The public
[Kin release workflow](https://github.com/firelock-ai/kin/blob/main/.github/workflows/release.yml)
is the distribution authority for which feature is packaged on each platform.

## NFS mount

```sh
cargo build --release -p kin-vfs-cli --features nfs
target/release/kin-vfs nfs-start --repo /path/to/kin-repository
```

That registers the repository if it is new, starts its `kin-daemon` if one is
not already serving it, binds an NFSv3 listener on loopback, and mounts it. No
`sudo` is needed for the mount itself. The first run may ask for admin rights
once to add a `kin.local` line to `/etc/hosts`, which only decides the name
Finder shows; declining it falls back to `127.0.0.1`.

Writable mode stages mount writes in the served repository's working copy.
After `KIN_VFS_ADMIT_DEBOUNCE_MS` milliseconds of quiet (1200 by default), the
server requests admission through the daemon. Until that request completes, the
mount serves the staged bytes back.

Two commands cover the rest:

```sh
kin-vfs nfs-sync     # request admission of staged writes now
kin-vfs nfs-status   # report current mount and staging state
kin-vfs nfs-stop     # request admission, unmount, and stop
```

`nfs-status` reports the obligations the server currently tracks. A write that
updates a path while an older admission is in flight remains pending under its
own mutation identity, then receives the next admission. The older response can
clear only the exact mutation it snapped, so status does not report `writable`
while that newer same-path write is still owed.

Two limits are worth knowing before you rely on it. An admission publishes the
whole working copy, exactly as `kin commit` does, so unrelated edits already
sitting in that repository's working directory are carried by the same change.
And creating a symlink through the mount is refused, because the admission does
not build that tree entry kind yet.

Start it with `--read-only` to project the graph without admitting anything
back.

## License

[Apache-2.0](LICENSE).
