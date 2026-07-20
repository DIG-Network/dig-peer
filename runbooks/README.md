# dig-peer runbook

## Local running / development

`dig-peer` is a library crate — it is consumed, not run. To work on it:

- Prereqs: a stable Rust toolchain (`rustup`), `cargo-llvm-cov` + `cargo-nextest` for coverage.
- Build: `cargo build`
- Test (unit + loopback e2e + doctests): `cargo test`
- Lint gate: `cargo fmt --all --check && cargo clippy --all-targets -- -D warnings`
- Coverage gate (>=80% lines): `cargo llvm-cov nextest --all --fail-under-lines 80`

The loopback e2e tests stand up a real dig-tls mTLS server on `127.0.0.1` and connect a `DigPeer` to
it over `dig-nat`'s Direct tier — no external network, no secrets.

## Deployment / release

Tag-driven, per-merge (§3.6 group B — `modules/crates`). A merged PR that bumps the version triggers
`release.yml` (git-cliff changelog + `vX.Y.Z` tag via `RELEASE_TOKEN`), and the tag push fires
`publish.yml` (`cargo publish` to crates.io via `CARGO_REGISTRY_TOKEN` + a GitHub Release).

- Secrets required on the repo: `RELEASE_TOKEN` (classic PAT, pushes the changelog commit + tag past
  branch protection) and `CARGO_REGISTRY_TOKEN` (crates.io publish; org-inherited).
- First release: because the workflows land in the first PR, kick `publish.yml` manually via
  `workflow_dispatch` (the new-crate first-release race) or an empty commit to `main`.
- Verify live: `cargo search dig-peer` shows the new version; the GitHub Release exists.
- Release-first ordering: dig-peer's deps (dig-nat, dig-message, dig-rpc-protocol, dig-tls) are all
  already published; nothing blocks its publish.
