# FUSE mount

A FUSE mount presents a Kin workspace as an ordinary directory. Reads come from
the graph, writes land on the workspace and reconcile back into the graph, and
any program can use it without being launched a particular way. That is the
difference from the `LD_PRELOAD`/`DYLD` shim, which only intercepts processes it
was injected into and which SIP strips on macOS for system binaries.

Linux is the supported path. It is where the mount needs no library at build or
run time, and where a CI container can use it.

```sh
cargo build --release -p kin-vfs-cli --features fuse
kin-vfs mount --workspace /path/to/repo --mount-point /tmp/kin
```

## What a write does

The governing rule is the same one the rest of Kin follows: the graph is the
authority and the filesystem is a projection of it. A write through the mount is
therefore two things happening in order.

The bytes land on the workspace's real path. Saving `/tmp/kin/src/main.rs` when
the workspace is `/path/to/repo` writes `/path/to/repo/src/main.rs`. Then the
mount waits for the graph to report that exact content back, polling
`provider.stat(path)` until the SHA-256 the graph holds for the path equals the
SHA-256 now on disk, or until the path is gone for a delete. Only then does the
write report success.

That wait is what makes the mount graph-authoritative rather than merely
graph-backed. A save that the graph did not take fails with `EIO`, and the
mount's log names the path that did not converge. Reads keep coming from the
graph throughout, so once a save succeeds, reading the file back through the
mount returns the reconciled artifact rather than the bytes that were handed to
it.

Convergence is measured against the content hash rather than the size, because a
one-character edit leaves the size unchanged and a size comparison would call
that converged the moment it was made. The daemon's watcher reconciles a local
edit in roughly a tenth of a second; the mount waits up to ten, overridable with
`KIN_VFS_FUSE_CONVERGE_MS` for a large repository under load.

`kin-vfs mount --read-only` turns all of this off: the mount carries
`MountOption::RO`, the kernel refuses writes before they reach the filesystem,
and every mutation returns `EROFS`.

### Why there is no write acknowledgement to trust

`docs/authority-and-write-notify-contract.md` describes a `POST /vfs/write-notify`
that the daemon answers with `200 {"reindexed":true}`. A repository-v6 daemon
does not serve that route. `kin-daemon` 0.5.39 answers `404` for both
`/vfs/write-notify` and `/vfs/file-changed`, while `/health` answers `200` and a
fabricated route also answers `404`, so the absence is real rather than a
misread. `api_routes()` in `kin/crates/kin-daemon/src/api.rs` says so directly:
those routes "represented pre-v6 authority and must not remain as compatibility
shims".

The mount still sends the notification, because a daemon that does serve it
reconciles immediately instead of on watcher latency. But the first `404` settles
it for the life of the mount and later writes skip the round trip, and nothing
depends on the answer either way. Reading the graph back is the gate.

This also means the shim's write path is running on its watcher backstop today
rather than on the acknowledged contract its own documentation describes.

## What the mount needs installed

On Linux, the `fuse3` package and nothing else. `fuser` is built with
`default-features = false`, so it mounts by handing the mount to the setuid
`fusermount3` helper and receiving the `/dev/fuse` descriptor back over a socket.
No library is linked, so no development headers are needed to build it and no
shared object is needed to run it.

That is what makes the feature shippable. Building the same tree with and
without `--features fuse` on Debian 12 arm64 produces binaries with an identical
shared-library set and an identical set of referenced `GLIBC_` symbol versions,
so the feature adds no runtime dependency and does not move the glibc floor that
`scripts/check-glibc-floor.mjs` in the Kin repository enforces.

On macOS there is no such path: `fuser`'s build script refuses the pure-Rust
mount off Linux, so macOS links macFUSE or FUSE-T through `pkg-config` and the
mount stays a source build there. macOS FUSE is out of scope for the shipped
binary.

Inside a container the mount also needs `--cap-add SYS_ADMIN` and
`--device /dev/fuse`; some hosts additionally need
`--security-opt apparmor:unconfined`.

## Auto-unmount and `/etc/fuse.conf`

Auto-unmount is what keeps a killed mount process from leaving a dead mount point
behind, and it is armed wherever the host allows it.

libfuse requires `allow_other` (or `allow_root`) whenever `auto_unmount` is
requested, and `fusermount3` grants `allow_other` to a non-root user only when
`/etc/fuse.conf` carries an uncommented `user_allow_other` line. Debian and
Ubuntu ship that line commented out. So on a default install, an ordinary user
asking for auto-unmount gets a mount failure whose message is
`No such file or directory`. That is an `ENOENT` naming neither the option nor
the file, and it reads as a missing path.

The mount now checks first and degrades rather than failing: it mounts without
auto-unmount, says so, names the reason, prints the one line that enables it, and
says what is lost until then.

```
echo user_allow_other | sudo tee -a /etc/fuse.conf
```

The check requires the option to stand alone on a line. The shipped
`/etc/fuse.conf` documents it inside a comment block, so a search for the word
anywhere in the file would report every default install as permitting it.

## Checking a mount

```sh
kin-vfs fuse-status --workspace /path/to/repo --mount-point /tmp/kin
```

```
FUSE:         available (fusermount3)
Auto-unmount: available
Workspace:    /path/to/repo
kin-daemon:   http://127.0.0.1:4219 (reachable)
Mount:        /tmp/kin (mounted, readable, writable)
```

The mount line is a probe rather than a lookup: it reads the mount point the way
a caller would, because the mount table says a filesystem is attached and never
that it answers. Those come apart exactly when the backing daemon is gone, which
reports as `DEGRADED` with the reason. A mount point with nothing on it reports
`not mounted`.

## Refusals

A mount point inside the workspace is refused. A write through the mount lands on
the workspace path underneath it, so mounting a workspace onto itself would fold
the projection back into its own source.

A missing FUSE helper is refused before anything else happens, with the command
that installs it on the host's own distribution rather than a generic
instruction to install fuse3.

## Proving it

`scripts/fuse-mount-proof.sh` runs the whole loop inside a container: it creates
a repository, runs `kin init`, mounts it, edits, creates and deletes through the
mount, and asserts against `kin log` and `kin graph status` rather than against
the mount. It then falsifies two guards, forcing the convergence deadline to zero
to show that an identical write is refused when the graph cannot be observed to
have taken it, and killing the daemon to show that a read with no graph authority
is refused rather than answered from the disk underneath the mount.

## Limits

The FUSE session is single-threaded, so a write that is waiting on the graph
blocks other operations on that mount until it converges or fails.

An empty directory is not a graph artifact. `mkdir` creates the directory on the
projection surface and the mount remembers it for the life of the session so a
shell can descend into it, but nothing about it reaches the graph until it holds
a real file.

`symlink`, `link` and `mknod` return `EROFS` on every mount.

The kernel is told not to cache pages for a writable mount, since a change
reconciled into the graph would otherwise be masked by a page cache the kernel
had no reason to drop.
