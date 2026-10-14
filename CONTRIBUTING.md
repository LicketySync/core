# Contributing

Lickety-Sync is built by one owner and a set of agents under the rules in the
plan's "Engineering practice" section. The short version:

- Every change is a pull request. The author never reviews their own change.
- A pull request carries tests that fail without it, and passes every check in
  `.github/workflows/ci.yml`.
- Anything touching keys, the protocol, file paths or the local API gets a
  second reviewer and a security-reviewer pass against `spec/threat-model.md`.
- No `unwrap`, `expect` or `panic` outside tests; no `unsafe` outside the
  platform-FFI crates; no `TODO` without an issue link.
- Dead code is removed in the same pull request that orphans it.
- Every bug fix lands with a regression test named after the bug.

## Local checks

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo doc --no-deps --document-private-items
cargo deny check
cargo machete
cargo llvm-cov nextest --all-features --fail-under-lines 90 -p licketysync-keys -p licketysync-protocol -p licketysync-engine
```

`bootstrap.sh` in the parent directory installs the tools these need.
