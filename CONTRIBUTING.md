# Contributing

Lickety-Sync is built by one owner and a set of agents under the rules in the
plan's "Engineering practice" section. The short version:

- There are no pull requests for our own changes. Every change is written by one
  agent, reviewed by two other agents in fresh contexts that read every changed
  file in full, and then committed to `main`. The author never reviews their own
  change. Dependabot's weekly update pull requests are the one exception: CI runs
  on them, and an agent reviews the diff and the `supply-chain/` delta, then
  merges. When an update changes cargo-geiger's counts, the geiger job fails and
  prints the new lines; the reviewing agent reads the cause in the report, and
  only then commits those lines to `ci/geiger-baseline.txt` on the pull
  request's branch, so the change is in the merged diff. Known cost: OpenSSF
  Scorecard scores Code-Review and Branch-Protection low by design; the review
  record is the commit message and `CHANGELOG.md`.
  Codecov's per-change comments go with pull requests too (its dashboard still
  tracks every push). gitleaks scans the full history after the push, and the
  working tree in `gate.sh` when it is installed; GitHub's push protection,
  enabled in the manual setup steps, is the pre-push control for secrets.
- A change carries tests that fail without it, passes `./gate.sh` before the
  commit, and keeps `.github/workflows/ci.yml` green on every push. A red `main`
  is fixed forward before any other work.
- Anything touching keys, the protocol, file paths or the local API also gets a
  security-reviewer pass against `spec/threat-model.md`, citing the TM numbers it
  touches, and cryptography is checked against `spec/suites.md`.
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
- Security: checked against `spec/threat-model.md` (cite the TM numbers the diff
  touches); cryptography only as `spec/suites.md` allows; every peer byte treated
  as untrusted; no host contacted that `spec/allowed-hosts.txt` does not list.
- Docs and `CHANGELOG.md` updated.
- Touches keys, protocol, paths or the API? The security-reviewer pass is
  recorded in the changelog entry.

A finding blocks the commit until it is fixed and re-reviewed, or the reviewer
agrees it is not one.

## Local checks

`./gate.sh` runs, in order, every CI check that can fail and fits on one machine
(it needs the network for the advisory database and Semgrep's community rules):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --doc
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
cargo deny check
cargo deny --config deny-production.toml check bans
cargo audit
cargo machete
cargo vet --locked
cargo +nightly-2026-10-14 udeps --workspace --all-targets
typos
semgrep --test --metrics=off --config .semgrep/project.yml .semgrep/tests/project.rs
semgrep scan --metrics=off --timeout 60 --config p/rust --config .semgrep --exclude .semgrep --error
ci/gitleaks.sh tree   # only when gitleaks is installed
ci/test-geiger.sh
ci/geiger.sh
ci/test-no-hostnames.sh
ci/no-hostnames.sh
ci/test-pinned-actions.sh
ci/pinned-actions.sh
ci/test-mutants.sh
ci/test-fuzz-targets.sh
cargo llvm-cov nextest --all-features --fail-under-lines 90 -p licketysync-<crate> --ignore-filename-regex 'crates/(<the others>)/'   # once each for keys, protocol, index, engine
```

The coverage threshold is per crate: only that crate's own files count, so a
well-tested neighbour cannot mask an under-tested one (`gate.sh` has the exact
loop).

`ci/geiger.sh` prints the cargo-geiger report and fails when any of a crate's
five used unsafe counts differs from its line in `ci/geiger-baseline.txt`, up
or down, and prints the line to write. A change that moves them (usually a new
or updated dependency) writes that line in the same commit, so the reviewers
see the change; the baseline's header says how, and how to move to another
cargo-geiger.

The Rust toolchains are the ones CI pins: stable 1.99.0, which
`rust-toolchain.toml`'s `channel = "stable"` gives the checkout, and
nightly-2026-10-14 (`rustup toolchain install nightly-2026-10-14`), for
cargo-udeps and to reproduce what `nightly.yml`'s fuzzing, cargo-careful and
Miri jobs report. `gate.sh` stops unless `rustc --version` in the checkout is
1.99.0 and the dated nightly is installed, and prints what to run; it never
downloads a toolchain. When stable moves past 1.99.0, either the pin moves or
`rustup toolchain install 1.99.0` and `rustup override set 1.99.0` keep the
checkout on it.

The tools beyond cargo's: cargo-nextest 0.9.148, cargo-llvm-cov 0.9.1,
cargo-udeps 0.1.61, cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-machete
0.9.2 and cargo-vet 0.10.2, the versions CI pins, are required (`cargo
install --locked <tool> --version <version>`), and so are typos 1.51.1, the
release of `crate-ci/typos` that `ci.yml` pins (`cargo install --locked
typos-cli --version 1.51.1`), and semgrep 1.181.0, the version CI's image
pins (`pipx install semgrep==1.181.0`). So are cargo-mutants 27.1.0 (the
weekly `mutants.yml`), cargo-fuzz 0.13.2 and cargo-careful 0.4.10
(`nightly.yml`), so that a surviving mutant, a fuzz crash or a careful
finding reproduces locally with the same tool (`ci/mutants.sh <k>/<n>
<budget>` runs one shard of the mutants as the weekly job does). `gate.sh`
checks all twelve and both toolchains before its first step. It stops when
the workflow that installs one of the ten cargo tools (`ci.yml`,
`nightly.yml`, `mutants.yml`) installs it any other way, when `ci.yml` runs
typos other than as one `crate-ci/typos` step pinned by commit with
`# v1.51.1` after it, and when a workflow names any other Rust toolchain or a
`dtolnay/rust-toolchain` step installs another than the `RUSTUP_TOOLCHAIN`
its job runs with. gitleaks is
optional (`ci/gitleaks-install.sh ~/.local/bin` installs the release CI
pins). CI adds the full-history gitleaks scan, the other operating systems,
CodeQL and, once configured, ClusterFuzzLite.
`bootstrap.sh` in the parent directory installs the tools the gate needs, the
pinned versions included.

Every action in every workflow of core, site and web is pinned by full commit
SHA, with the release tag on that commit in a comment (the pinning rule in
`ci.yml`, the owner's decision of 2026-10-25). `ci/pinned-actions.sh` checks
the form here, and on site's or web's workflows when given their
`.github/workflows`; whether the tag names that commit is checked by hand
(`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, dereferencing an annotated
tag with `git/tags/<sha>`). Dependabot's weekly pull requests move these pins
and their comments together. When one moves `crate-ci/typos`, the reviewing
agent also moves `gate.sh`'s `typos_version`, `bootstrap.sh` and this file
to that release's typos on the pull request's branch, as for the geiger
baseline, so the merged diff carries both, and installs it locally.

Dependabot cannot see the following pins, so the agent at each weekly
Dependabot review checks them for new releases; a bump is one reviewed change:

- the ten cargo tools above, in the workflows that install them, `gate.sh`
  and `bootstrap.sh`;
- the Rust toolchains, stable 1.99.0 (a new stable every six weeks) and
  nightly-2026-10-14 (moved when a tool or a fix needs a newer nightly): a
  bump is one reviewed change to `gate.sh`'s `rust_stable` or `rust_nightly`
  and every workflow's `toolchain:`, `RUSTUP_TOOLCHAIN` and `+nightly-...`,
  with `bootstrap.sh` and this file, after the gate passes on the new
  toolchain;
- `release.yml`'s cargo-auditable 0.7.7 and cargo-cyclonedx 0.5.9;
- site's `pages.yml`'s zola 0.23.6;
- the Codecov CLI version that `ci.yml`'s `codecov` job pins (v11.3.1); the
  same review reads the result of the last `codecov` job on `main`, since that
  job may fail without turning the run red, so a broken upload shows only
  there;
- the commit pins of `dtolnay/rust-toolchain` (every job that installs Rust)
  and `google/clusterfuzzlite` (`clusterfuzzlite.yml`): each has a single
  tag, `v1`, and no version releases, so Dependabot has no newer release to
  move to; a bump pins the commit `v1` names that day.

One thing stays unpinned, as a residual: the container images that pinned
actions name by tag (scorecard-action's, ClusterFuzzLite's).

When `cargo vet --locked` fails after a dependency change: run `cargo vet` (it
refreshes `supply-chain/imports.lock` from the Mozilla and Google audits), then
`cargo vet suggest`, and either `cargo vet certify` after actually reading the
crate or `cargo vet add-exemption` with a reason; commit `supply-chain/` with the
change.
