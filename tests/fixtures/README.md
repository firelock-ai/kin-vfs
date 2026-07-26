# Shared VFS wire fixtures

These files are the **byte-level contract** between `kin-vfs` and the Kin
daemon's `/vfs/*` surface. They are golden fixtures: the VFS side asserts that
its own types serialize to exactly these bytes and deserialize from them, so a
peer change on either side shows up as a fixture diff instead of a silent
runtime mismatch.

The Kin daemon should assert the same files from its side. Any change here is a
peer-contract change and must land on both sides together.

| File | Contract |
|---|---|
| `tree-snapshot.json` | A complete `GET /vfs/tree` document: schema version, head ref identity, monotonic version, snapshot etag, and one exact resolved artifact per tracked leaf. Covers every artifact kind: source, Compose config, an opaque lockfile, unsupported-language source, an executable blob, raw binary, a symlink, a non-UTF8 path, and a gitlink repository boundary. |
| `write-notify.json` | The body the shim POSTs to `/vfs/write-notify`, carrying canonical path bytes. |

## Encoding rules pinned by these fixtures

- **Paths are bytes.** `path` is `{"bytes_hex": "<lowercase hex>"}`, matching
  `kin_model::RepoPath`. A path is never a JSON string: UTF-8 is a presentation
  property, and a JSON string cannot carry a non-UTF8 Unix name without lossy
  substitution. Hex must be canonical lowercase; anything else is rejected.
- **Hashes are 32-byte arrays.** `Hash256` serializes as a JSON array of 32
  integers (its `serde` derive over `[u8; 32]`), not a hex string.
- **`entry` is internally tagged** on `type`: `blob` (with `hash` +
  `executable`), `symlink` (with `target_blob`), or `gitlink` (with `target`,
  itself tagged on `algorithm` with a `bytes` array).
- **Unknown fields are rejected** everywhere (`deny_unknown_fields`), so a peer
  that adds a field without a schema bump fails loud rather than being silently
  ignored.
- **`etag` also travels as the HTTP `ETag` header**, quoted (`"tree-7"`). The
  header and the document field must agree; the provider refuses the snapshot
  if they diverge.
- **Gitlink size is `0`.** A repository boundary has no blob content of its own.

## Routes pinned alongside these fixtures

- `GET /vfs/tree` — conditional via `If-None-Match: "<etag>"`; answers `304 Not
  Modified` or a complete new document. There is no separate version route: a
  version probe followed by a tree fetch would leave a window in which the tree
  changes under the check.
- `GET /vfs/blob/<hash>` — content-addressed by the lowercase-hex SHA-256 the
  tree advertises. Supports `Range`; a `206` must echo `X-Kin-Blob-Hash` and an
  exact `Content-Range: bytes <start>-<end>/<total>`. There is no path-addressed
  read route: addressing content by path would let a path reuse or ref race
  return another artifact's bytes.
- `POST /vfs/write-notify` — body per `write-notify.json`.
