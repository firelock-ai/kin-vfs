# Contributing to kin-vfs

Thanks for your interest in kin-vfs. This guide covers local development, the
conventions this repository follows, and how to get changes reviewed.

## Development Setup

kin-vfs is a Rust workspace. CI builds on **stable** Rust, so a current stable
toolchain via [rustup](https://rustup.rs/) is all you need:

```sh
rustup toolchain install stable
```

Build and test the workspace:

```sh
cargo build
cargo test
```

The interception shim is a `cdylib` and can be built on its own:

```sh
cargo build --release -p kin-vfs-shim
```

This produces `libkin_vfs_shim.so` (Linux) or `libkin_vfs_shim.dylib` (macOS).

Before opening a pull request, make sure the standard checks pass:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI treats clippy warnings as errors (`-D warnings`), so a clean clippy run
locally avoids surprises.

## DCO Sign-Off

This project uses the [Developer Certificate of Origin
(DCO)](https://developercertificate.org/). Every commit you push on a pull
request must carry a `Signed-off-by` trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Add it by passing `-s` to `git commit`:

```sh
git commit -s -m "fix(shim): handle readdir on materialized directories"
```

If you forgot to sign off earlier commits on your branch:

```sh
git commit -s --amend              # amend only the last commit
git rebase --signoff HEAD~N        # add sign-off to the last N commits
```

By signing off you certify that you wrote the code (or have the right to
submit it) and that it may be distributed under the Apache License 2.0 that
governs this repository. Bot-authored commits (Dependabot, GitHub Actions)
are exempt.

## AI-Assisted Contributions

kin-vfs is built with significant AI assistance, and we welcome AI-assisted
contributions from the community. A few requirements:

- **You are responsible for AI-generated code you submit.** Review every
  line before opening a PR. If the model hallucinated an API call, an
  unsound unsafe block, or a security hole, that is your bug to catch.
- **AI-generated code is your contribution.** By signing off your commits
  you assert that you have reviewed the generated code and are submitting it
  under your own name, not as a third-party work.
- **No raw model output in commit messages or comments.** Clean up generated
  prose before it lands in public history. Write durable, human-authored
  commit messages that describe the technical change.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/),
a `type(scope): summary` subject:

```
fix(shim): pass through paths outside the workspace root
feat(fuse): add an unmount-on-signal guard
docs(readme): document the interpose table on macOS
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and
`chore`. Scopes match the area you touched (`shim`, `daemon`, `fuse`, `cli`,
`core`). Write the summary in the imperative mood and keep it focused on what
changed and why.

## Branch Naming and Commit Hygiene

Public Git history is part of the product, so keep it clean and reviewable:

- **Keep branch names topical, not tracker-coded.** Prefer short, descriptive
  names like `fix/shim-readdir` or `docs/contributing`. A squash merge copies
  the branch name into the public commit subject, so anything in the branch
  name lands in history verbatim.
- **Write durable subjects and bodies.** Commit messages should describe the
  technical change and why it was made. Keep internal tracker IDs, session
  identifiers, and automated authorship trailers out of public commit
  metadata; link that context from the pull request instead.
- **Don't bypass the hooks.** Repository hooks normalize commit metadata for
  consistency — don't skip them with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR — this keeps review focused and
  history bisectable.
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.

## Reporting Issues

File issues on
[firelock-ai/kin-vfs](https://github.com/firelock-ai/kin-vfs/issues).

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

## Repository Boundaries

kin-vfs is the transparent filesystem projection within the larger Kin
ecosystem. Graph storage and retrieval internals live in `kin-db`; the CLI,
daemon, and MCP server live in `kin`. If your change targets one of those
concerns, open it against the repository that owns the code.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
