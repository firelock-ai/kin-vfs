# Kin VFS: Transparent Filesystem Projection

**AI writes code. Kin proves the change.**

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
> public projection path is release-proven on Ubuntu 24.04; Debian 12 and other
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
| GNU/Linux arm64 | **Supported on the release-proven Ubuntu 24.04 arm64 path.** The public VFS executable currently requires glibc 2.39. Debian 12 arm64, Alpine arm64, and other hosts that do not provide that ABI are outside the supported projection boundary. |
| Linux with musl, including Alpine | **Not supported for VFS projection.** The release archive's core `kin` and `kin-daemon` binaries are static musl builds, but `kin-vfs` and its preload shim are separate GNU/glibc artifacts. Core CLI success must not be treated as VFS success. |
| Native Windows | The current Kin archive does not include VFS projection. The ProjFS path is not complete. Use WSL2 with a Linux distribution that provides glibc 2.39 or newer for the supported Windows-hosted path. |
| FUSE and NFS mounts | Optional source-build features. They are not enabled in the prebuilt `kin-vfs` binary shipped with Kin today. |

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
- **`crates/kin-vfs-shim`:** The injected `cdylib` interception layer for Linux and macOS, plus the in-progress Windows boundary.
- **`crates/kin-vfs-fuse`:** Optional read-only FUSE mount mode behind the `fuse` feature.
- **`crates/kin-vfs-nfs`:** Optional NFSv3 mount mode behind the `nfs` feature.
- **`crates/kin-vfs-cli`:** The `kin-vfs` CLI. Prebuilt releases include `start`, `stop`, `status`, and `exec`; mount commands require their source-build features.
- **`shell/`:** Shell hooks that activate projection when entering a Kin workspace.
- **`tests/`:** Integration and regression coverage for host filesystem behavior.

## Build from source

The default source build matches the public binary's command surface:

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

FUSE is read-only. On macOS it requires FUSE-T or macFUSE; on Linux it requires libfuse. These feature builds are contributor and advanced-user paths, not files installed by the current public Kin release.

## License

[Apache-2.0](LICENSE).
