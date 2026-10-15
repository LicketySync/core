# Contributing

Lickety-Sync is built by one owner and a set of agents under the rules in the
plan's "Engineering practice" section. The short version:

- There are no pull requests for our own changes. Every change is written by one
  agent, reviewed by two other agents in fresh contexts that read every changed
  file in full, and then committed to `main`. The author never reviews their own
  change. Dependabot's weekly update pull requests are the one exception: CI runs
  on them, and an agent reviews the diff and the `supply-chain/` delta, then
  merges. Known cost: OpenSSF Scorecard scores Code-Review and Branch-Protection
  low by design; the review record is the commit message and `CHANGELOG.md`.
  Codecov's per-change comments go with pull requests too (its dashboard still
  tracks every push), and gitleaks runs after the push, so GitHub's push
  protection, enabled in the manual setup steps, is the pre-push control for
  secrets.
- A change carries tests that fail without it, passes `./gate.sh` before the
  commit, and keeps `.github/workflows/ci.yml` green on every push. A red `main`
  is fixed forward before any other work.
- Anything touching keys, the protocol, file paths or the local API also gets a
  security-reviewer pass against `spec/threat-model.md` (to be written in phase
  0; until then the plan's Security section is the threat model).
- Every review ends with a plain-language summary for the owner: what the
  change does, what it risks, how to try it by hand.
- No `unwrap`, `expect` or `panic` outside tests; no `unsafe` outside the
  platform-FFI crates; no `TODO` without an issue link.
- Dead code is removed in the same change that orphans it.
- Every bug fix lands with a regression test named after the bug.
- Every change updates `CHANGELOG.md` and names its reviewers there and in the
  commit message.

## Review checklist

Each reviewer works in a fresh context with only the diff, every changed file in
full, the tests, the threat model and the plan, and walks this list:

- Correct at the edges: empty, huge, concurrent, offline, clock skew.
- Idiomatic Rust: typed errors; no `unwrap`/`expect` outside tests; no panic
  reachable from untrusted input.
- Dead code gone, including branches no caller reaches and features that lost
  their last user.
- Tests exercise behaviour, cover failure paths as fully as success, are
  deterministic, and fail if the change is reverted.
- Security: checked against the threat model; every peer byte treated as
  untrusted; no host contacted that `spec/allowed-hosts.txt` does not list.
- Docs and `CHANGELOG.md` updated.
- Touches keys, protocol, paths or the API? The security-reviewer pass is
  recorded in the changelog entry.

A finding blocks the commit until it is fixed and re-reviewed, or the reviewer
agrees it is not one.

## Local checks

`./gate.sh` runs, in order, every CI check that can fail and fits on one machine
(it needs the network for the advisory database):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --doc
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
cargo deny check
cargo audit
cargo machete
cargo vet --locked
cargo +nightly udeps --workspace --all-targets
typos
ci/test-no-hostnames.sh
ci/no-hostnames.sh
cargo llvm-cov nextest --all-features --fail-under-lines 90 -p licketysync-<crate> --ignore-filename-regex 'crates/(<the others>)/'   # once each for keys, protocol, engine
```

The coverage threshold is per crate: only that crate's own files count, so a
well-tested neighbour cannot mask an under-tested one (`gate.sh` has the exact
loop).

CI adds the other operating systems, Semgrep, CodeQL, gitleaks, the cargo-geiger
report and, once configured, ClusterFuzzLite. `bootstrap.sh` in the parent
directory installs the tools the gate needs.

When `cargo vet --locked` fails after a dependency change: run `cargo vet` (it
refreshes `supply-chain/imports.lock` from the Mozilla and Google audits), then
`cargo vet suggest`, and either `cargo vet certify` after actually reading the
crate or `cargo vet add-exemption` with a reason; commit `supply-chain/` with the
change.
