# Kin VFS: Transparent Virtual File System Projection

`kin-vfs` is the transparent virtual filesystem bridge for the Kin ecosystem. It is the "Trojan horse" that enables legacy, file-first development tools (compilers, linters, legacy text editors, build systems) to operate seamlessly on Kin's graph-first semantic repository.

## How It Works

Instead of forcing you to rewrite your toolchain to interact with a graph database API, `kin-vfs` projects the semantic graph database onto the filesystem.

- **Dynamic Interception**: By utilizing standard dynamic linking hooks (`LD_PRELOAD` on Linux or `DYLD_INSERT_LIBRARIES`/`DYLD_FORCE_FLAT_NAMESPACE` on macOS), `kin-vfs` intercepts standard library filesystem calls (`open`, `read`, `write`, `stat`, `readdir`).
- **Graph-First Serving**: When a tool requests a file under a Kin-managed workspace, `kin-vfs` redirects the request to fetch the entity source and layout directly from the local `kin-daemon` graph store, verifying content hashes on the fly.
- **Git/Local Fallback**: File reads that fall outside Kin-managed semantics or references that do not exist in the graph fall back transparently to the underlying physical filesystem.

## Structure

- **`crates/kin-vfs`**: Rust crate implementing the VFS lookup, filesystem virtualization logic, cache management, and communication client to `kin-daemon`.
- **`shell/`**: Shell hook scripts to set up the environment variables (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) automatically when entering a Kin workspace.
- **`tests/`**: Integration and regression tests ensuring that virtual filesystem calls behave identically to native OS files under compilers (e.g. `gcc`, `clang`, `rustc`).

## Build and Setup

To build the VFS shim library:
```sh
cargo build --release -p kin-vfs
```
This produces `libkin_vfs_shim.so` (Linux) or `libkin_vfs_shim.dylib` (macOS), which is copied into `~/.kin/lib` by the installer.
