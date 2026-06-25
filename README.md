# Kin VFS: Transparent Virtual File System Projection

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

`kin-vfs` is the transparent virtual filesystem bridge for the Kin ecosystem. It is the "Trojan horse" that enables legacy, file-first development tools (compilers, linters, legacy text editors, build systems) to operate seamlessly on Kin's graph-first semantic repository.

> Part of **[Kin](https://github.com/firelock-ai/kin)** — the semantic system of record for AI-native software (code as a graph, not files and diffs). Learn more at **[kinlab.ai](https://kinlab.ai)**.

## How It Works

Instead of forcing you to rewrite your toolchain to interact with a graph database API, `kin-vfs` projects the semantic graph database onto the filesystem.

- **Dynamic Interception**: On Linux the shim is loaded via `LD_PRELOAD` and overrides libc symbols globally. On macOS, where the two-level namespace means a plain exported symbol does not shadow already-recorded bindings, the shim ships a `__DATA,__interpose` table (loaded via `DYLD_INSERT_LIBRARIES`) that dyld uses to redirect libc calls (`open`, `read`, `stat`, `readdir`, …) into the shim at load time.
- **Graph-First Serving**: When a tool requests a file under a Kin-managed workspace, `kin-vfs` routes the request to fetch the entity source and layout directly from the local `kin-daemon` graph store, verifying content hashes on the fly.
- **Materialize-on-write**: Reads are served virtually from graph truth. When a tool writes to a virtual file, the shim materializes it to disk — seeded from graph truth — so the write lands on a real file descriptor and version control, build tools, and editors work without special handling. Paths outside the workspace root are passed straight through to the underlying filesystem.

## Structure

- **`crates/kin-vfs-core`**: Shared primitives — the `ContentProvider` trait, path-to-content mapping, stat types, error types, and the LRU blob cache.
- **`crates/kin-vfs-daemon`**: Tokio daemon that resolves virtual paths to content over a Unix socket and bridges to `kin-daemon` for blob resolution.
- **`crates/kin-vfs-shim`**: The `cdylib` interception layer. Overrides libc calls via `LD_PRELOAD` (Linux) or a `__DATA,__interpose` table loaded through `DYLD_INSERT_LIBRARIES` (macOS).
- **`crates/kin-vfs-fuse`**: Optional FUSE mount mode (behind the `fuse` feature) — a real, system-wide mount point as an alternative to the per-process shim.
- **`crates/kin-vfs-nfs`**: Optional NFS mount mode (behind the `nfs` feature) — a pure-Rust NFSv3 server that exposes registered Kin workspaces under `~/.kin/mnt/`, so graph-backed trees are browsable in Finder/Explorer and by any tool without `LD_PRELOAD`/`DYLD`.
- **`crates/kin-vfs-cli`**: The `kin-vfs` CLI binary (`start` / `stop` / `status`, plus `mount` / `unmount` with the `fuse` feature and `nfs-start` / `nfs-stop` / `nfs-status` / `workspaces` with the `nfs` feature).
- **`shell/`**: Shell hook scripts that set the interception environment variables automatically when entering a Kin workspace.
- **`tests/`**: Integration and regression tests ensuring that virtual filesystem calls behave identically to native OS files under common tools (e.g. `gcc`, `clang`, `rustc`).

## Build and Setup

To build the VFS shim library:
```sh
cargo build --release -p kin-vfs-shim
```
This produces `libkin_vfs_shim.so` (Linux) or `libkin_vfs_shim.dylib` (macOS), which the installer copies into `~/.kin/lib`.

## License

[Apache-2.0](LICENSE).
