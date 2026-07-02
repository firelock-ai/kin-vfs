# kin-vfs Release Metadata and Compatibility Policy

This note is the operator-facing contract for how `kin-vfs` releases: what is
published, from which version source, which checks gate a release, who consumes
it, and when a change must (or must not) move the version. It exists so the
cross-repo release orchestrator and human release engineers apply one consistent,
intent-aware rule instead of ad-hoc judgement.

## 1. Release metadata

| Facet | Value |
|---|---|
| **Version source** | `[workspace.package] version` in the root `Cargo.toml` (currently `0.1.0`). Every crate inherits it via `version.workspace = true`; the workspace moves as one unit. |
| **Publish target** | `kin-vfs-core` → the private `kin` cargo registry. It is the **only** published crate. |
| **Publish mechanism** | `.github/workflows/registry-publish.yml`, which calls the shared `firelock-ai/kin-actions/.github/workflows/cargo-registry-release.yml`. |
| **Smoke checks** | Registry Cutover Smoke (`registry-smoke.yml`: fresh-clone under the registry-only cargo config, asserting no private path patches or external Kin git-pins), plus the shared workflow's registry-only build, repo verification, and fresh-consumer smoke, plus the full-workspace `cargo test`. |
| **Downstream consumers** | The `kin` workspace consumes `kin-vfs-core` from the registry. The machine-readable list lives in `.kin-release/downstreams.json`; on publish the release workflow dispatches a rebuild to each entry. |

The other crates — `kin-vfs-shim`, `kin-vfs-daemon`, `kin-vfs-cli`, `kin-vfs-fuse`,
`kin-vfs-nfs` — are **internal**. They are not published to the registry; they
ship as binaries and as the injected shim library (`libkin_vfs_shim.{dylib,so}`)
delivered by `kin setup` and the one-line installer. They are still versioned
artifacts, which is why projection-behavior changes carry release intent even
though only `kin-vfs-core` reaches the registry (§3).

## 2. What the version-bump gate treats as release-affecting

The shared `Version bump gate` (`check-version-bump.py` in `kin-actions`) is
path- and intent-aware. It **requires** a workspace version bump when a change
touches:

- crate source trees — `src/**`, `crates/**/src/**`, `build.rs`; or
- `Cargo.toml` dependency / feature changes (what a consumer actually builds).

It **exempts** (no bump required): documentation and `*.md`, tests / benches /
examples, comments, and CI config under `.github/**`. It also enforces two
registry invariants independent of the change set: a version may never move
*below* the newest published version, and a release-affecting change may not land
on a version that is already published.

## 3. Compatibility and semver policy

1. **Published-surface changes** — a change to the `kin-vfs-core` public API bumps
   the workspace version per semver; consumers rebuild against the new version.
2. **Projection / runtime-behavior changes** — changes to shim interception, the
   daemon provider↔`kin-daemon` wire contract, or mount / native-mode semantics
   require explicit semver intent **and** an installer/channel impact assessment,
   because the shim and installer are versioned artifacts even though they do not
   publish to the registry. A behavior change that alters what a mounted tool
   observes is a compatibility event, not an internal detail.
3. **No incidental releases** — a dependency-only refresh or a downstream-consumer
   bump does **not** by itself release `kin-vfs`. `kin-vfs` releases only when the
   published `kin-vfs-core` API or the VFS artifact / compatibility surface
   actually changes.
4. **Known gate coarseness** — the gate keys on file *paths*, so it flags any
   `crates/**/src/**` edit as release-affecting, including changes to the internal
   (non-published) crates and test-only code that happens to live inside a `src`
   file. Until the gate is scoped to the published package's build inputs, such
   changes should ride the next intentional `kin-vfs-core` version bump rather than
   forcing a standalone release; a maintainer confirms the published surface is
   unchanged before deferring. This keeps §3.3 true in practice while the gate
   stays deliberately conservative (better a spurious bump prompt than a silent
   unreleased behavior change).

## 4. Practical flow

- **Docs / tests / CI only** → no bump; merges without a release.
- **Internal-crate code, published surface unchanged** → no standalone release;
  fold into the next `kin-vfs-core` bump (§3.4).
- **`kin-vfs-core` API change** → bump the workspace version, land, tag `v*.*.*`;
  the release workflow publishes `kin-vfs-core` and dispatches to the downstreams.
- **Projection/behavior change** → as above, with a recorded semver-intent and
  installer-impact note before tagging.

Registry-cutover and release-hardening changes are tracked with the related
registry-cutover-smoke and automatic-release-engineering work; keep this file in
sync with `registry-publish.yml` and `.kin-release/downstreams.json` when either
moves.
