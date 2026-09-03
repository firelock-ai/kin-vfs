# The NFS export's security posture

`kin-vfs nfs-start` serves graph-backed workspaces to the machine's own NFS
client so Finder, Explorer and every ordinary tool read them as files. This is
what that export enforces, what it cannot enforce, and what is left over.

## What it enforces

**Loopback only, and refused otherwise.** The listener binds an IPv4 loopback
address and `NfsServer::start` refuses any other address before it binds or
writes anything (`crates/kin-vfs-nfs/src/server.rs`). A loopback bind means the
kernel drops every packet from off the machine, so nothing on the network can
reach the export even when the port is known.

**An ephemeral port by default.** `--port 0` is the default, so the export does
not sit on a predictable port between runs.

**Read-only unless asked.** Writes are refused with `NFS3ERR_ROFS` unless
`--writable` is passed. Without it the export cannot commit anything to a
repository, so the worst a local account can do is read.

**Write containment resolved rather than spelled.** When the export is
writable, a path is resolved with symlinks followed before anything opens, and
a destination outside the served repository root is refused
(`crates/kin-vfs-core/src/containment.rs`). A symlink already committed in the
working copy therefore cannot redirect a mount write onto the rest of the
machine. Remove and rename act on the entry rather than on what it points at,
so removing a symlink removes the link.

**The mount source must be loopback.** The mount is issued against `kin.local`
only when that name resolves to loopback and nothing else, and falls back to
the literal `127.0.0.1` otherwise. `kin.local` is an mDNS name and any machine
on a shared network can answer for it; mounting there would send every read and
write of the projection to that machine.

**System tools are named, not searched for.** `mount`, `umount`, `diskutil`,
`sudo`, `sh` and the daemon health probe's `curl` are resolved out of
`/usr/bin`, `/bin`, `/usr/sbin` and `/sbin` and refused when they are not
there, rather than resolved through `PATH`. A binary planted earlier in `PATH`
would otherwise run in their place, and the `sudo` case would harvest the
password the user is about to type into a prompt that looks exactly right.

## What it cannot enforce

**There is no client authentication.** NFSv3 offers AUTH_UNIX, which is a uid
and gid the client asserts about itself, so it is an identity claim and not a
credential. In this server it does not even reach the export: `nfsserve`
0.11's `NFSFileSystem` trait receives no RPC context, and the `auth_unix`
fields it parses are private to that crate, so nothing the client sends is
visible to the code answering the call.

**A per-start secret does not help through this stack.** Two things defeat it.
`MOUNTPROC3_EXPORT` answers any unauthenticated caller with the export path, so
a secret export name is disclosed on request. And an opaque NFS file handle here
is the server's startup time in milliseconds followed by the file id, so a
caller who never mounts can construct one by searching a small range.

**So the boundary is the machine account.** While a writable export runs, any
account on the machine can write the served repositories, and those writes are
admitted as changes attributed to the user who started the export. While a
read-only export runs, any account on the machine can read them. Both stop when
the export stops.

## What to do about it

On a single-user machine the loopback bind is a real boundary and the export is
fine to run. On a shared or multi-account host, treat a running export the way
you would treat a world-readable copy of the repository, keep it read-only, and
stop it when you are done.

The `fuse` mount is the projection with a real local boundary: a FUSE mount is
owner-only unless `--allow-other` is passed, and the kernel enforces that
without any cooperation from this code. Closing the gap for NFS needs a server
that can see its peer, which means a patched or forked `nfsserve` exposing the
peer address and per-connection credentials.

## The residual race in write containment

Resolving a path and opening it are two syscalls, so a symlink swapped between
them is resolved as it was rather than as it became. Closing that needs
`openat` with `O_NOFOLLOW` per component against a retained directory
descriptor, which is what kin-core's retained-directory writes do. The account
that can win that race can already write the served working copy directly,
which is what the race would buy.
