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

`./gate.sh` first checks the pins (below) and runs `ci/toolchains.sh`, then
runs, in order, every CI check that can fail and fits on one machine (it needs
the network for the advisory database and Semgrep's community rules):

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
cargo +<RUST_NIGHTLY> udeps --workspace --all-targets
cargo fetch --locked --manifest-path fuzz/Cargo.toml
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
ci/test-toolchains.sh
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

When `cargo vet --locked` fails after a dependency change: run `cargo vet` (it
refreshes `supply-chain/imports.lock` from the Mozilla and Google audits), then
`cargo vet suggest`, and either `cargo vet certify` after actually reading the
crate or `cargo vet add-exemption` with a reason; commit `supply-chain/` with the
change.

## Pins and the weekly refresh

Every version a workflow here, `gate.sh` or `bootstrap.sh` uses is written once,
in `ci/pins.env`, under a key named after the tool (`CARGO_NEXTEST`, `TYPOS`,
`SEMGREP`, `GITLEAKS`, ...) or the toolchain (`RUST_STABLE`, `RUST_NIGHTLY`);
the pinning rule is in `.github/workflows/ci.yml`'s header. Each reader runs
`ci/check-pins.sh` before sourcing the file, which refuses any line but a
comment or `KEY=value` with a key it lists (once) and a plain value, so the file
can set no other variable, such as `PATH`; a new key goes into both files.
`gate.sh` stops before its first step when an installed tool or toolchain is
not its `pins.env` version, printing the command that installs it, or when a
copy in a workflow or in `ci/geiger-baseline.txt` differs, naming the file and
the line it expects; `bootstrap.sh` installs every version from the file.
Three tools that `bootstrap.sh` installs are not checked by the gate on this
machine: cargo-auditable and cargo-cyclonedx (the gate checks only
`release.yml`'s copies of their versions) and cargo-semver-checks; and
gitleaks, which `bootstrap.sh` does not install, only draws a warning from
`ci/gitleaks.sh` when it is another version than `GITLEAKS`.

The tools beyond cargo's, all required: the cargo tools of `pins.env`
(`cargo install --locked <crate> --version <version>`; cargo-geiger and
cargo-udeps with `--features vendored-openssl`), typos (crate `typos-cli`) and
semgrep (`pipx install semgrep==<SEMGREP>`). cargo-mutants (the weekly
`mutants.yml`), cargo-fuzz and cargo-careful (`nightly.yml`) are not run by
the gate but are pinned the same way, so that a surviving mutant, a fuzz crash
or a careful finding reproduces locally with the same tool (`ci/mutants.sh
<k>/<n> <budget>` runs one shard of the mutants as the weekly job does).
gitleaks is optional (`ci/gitleaks-install.sh ~/.local/bin` installs the
release CI pins). CI adds the full-history gitleaks scan, the other operating
systems, CodeQL and, once configured, ClusterFuzzLite.

The Rust toolchains: `RUST_STABLE`, which `rust-toolchain.toml`'s
`channel = "stable"` must give the checkout, and `RUST_NIGHTLY`, a dated
nightly installed by name with miri and rust-src, for cargo-udeps and to
reproduce what `nightly.yml`'s fuzzing, cargo-careful and Miri jobs report.
`gate.sh` never downloads a toolchain. When stable moves past `RUST_STABLE`,
either the pin moves or `rustup toolchain install <RUST_STABLE>` and
`rustup override set <RUST_STABLE>` keep a checkout on it; an override holds
for one directory, so each worktree needs its own.

Every action in every workflow of core, site and web is pinned by full commit
SHA, with the release tag on that commit in a comment, which Dependabot
rewrites when it moves the pin. `ci/pinned-actions.sh` checks the form here,
and on site's or web's workflows when given their `.github/workflows`; whether
the tag names that commit is checked by hand
(`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, an annotated tag then
`git/tags/<sha>`). Dependabot opens its weekly pull requests only for releases
at least 7 days old (`cooldown` in `.github/dependabot.yml`; security updates
come at once).

**Which release.** The owner's "Stay current" rule (the owner's messages of
2026-10-25, quoted in the project's CLAUDE.md): every pin is the newest
release that has been out for at least 7 days, or a newer one at once when it
fixes a critical or high vulnerability. A crate's date is its
crates.io publish date; an action's, tool's or image's, its GitHub release's
`published_at` (`gh api repos/<owner>/<repo>/releases/tags/<tag>`) or the
image tag's push date; a stable Rust's, its release day (`rustup check` shows
the newest); a nightly's, its date. Any request to these services carries a
User-Agent with no personal data, such as
`licketysync-ci-check (+https://github.com/LicketySync)`.

**Moving a pin**, the one procedure for every key: edit `ci/pins.env`; edit
the workflow copies, running `./gate.sh` until it no longer stops at one (each
stop names the file and the line it wants); then `git grep -n -F <old version>`
until only the CHANGELOG matches, apart from text about other software;
install the new version locally (the gate prints the command); and review it
as one change, with its CHANGELOG entry. Some keys need one more step:
`CARGO_GEIGER` moves only with `ci/geiger-baseline.txt`'s counts, re-measured
as the baseline's header says; `SEMGREP_IMAGE_DIGEST` is the new tag's index
digest on Docker Hub; `GITLEAKS_LINUX_X64_SHA256` is the linux_x64 line of the
release's checksums file (`ci/gitleaks-install.sh` says how to read it);
`RUST_NIGHTLY` must be a date whose nightly has miri and rust-src.

**The weekly refresh.** At each weekly Dependabot review the agent applies the
rule to what Dependabot cannot see, and lands what it finds as one reviewed
change:

- every key in `ci/pins.env`: the Rust stable and dated nightly, the cargo
  tools, typos, semgrep and its image digest, gitleaks and its SHA-256, and
  the Codecov CLI;
- cargo-geiger, which moves only with the baseline's counts;
- site's zola, in its `pages.yml` (site has no `pins.env`);
- the commit pins of `dtolnay/rust-toolchain` and `google/clusterfuzzlite`:
  each has a single tag, `v1`, and no version releases, so Dependabot has no
  newer release to move to; a bump pins the commit `v1` names that day;
- transitive crates, which Dependabot skips: `cargo update` here and in
  `fuzz/` (whose `Cargo.lock` the fuzz jobs build from with `--locked`
  checked), taking back with `cargo update --precise` any version younger than
  7 days, then `cargo deny`, `cargo audit` (and `cargo audit --file
  fuzz/Cargo.lock`), `cargo vet` and the geiger baseline as for any
  dependency change.

The same review reads the result of the last `codecov` job on `main`, since
that job may fail without turning the run red, so a broken upload shows only
there. Dependabot updates `fuzz/Cargo.lock` in pull requests of its own (the
`/fuzz` entry). A pull request for the root that changes a requirement in a
crate's `Cargo.toml` can leave `fuzz/Cargo.lock` behind; CI's deps job then
fails, and the reviewing agent updates `fuzz/Cargo.lock` on the pull request's
branch, as for the geiger baseline.

What stays unpinned, as residuals: the container images that pinned actions
name by tag (scorecard-action's on ghcr.io, ClusterFuzzLite's on gcr.io); the
toolchains that actions choose for themselves (CodeQL's Rust extractor sets its
own, which moves only with the codeql-action pin, and ClusterFuzzLite builds in
its own image); GitHub's runner images; and `fuzz/Cargo.lock` in part:
`fuzz/` is a workspace of its own, so cargo-deny and cargo-vet do not read its
lockfile, though `gate.sh` and `nightly.yml` audit it with `cargo audit --file`
and Dependabot updates it. `ci/pinned-actions.sh` and `ci/toolchains.sh` read
lines, not YAML; their headers list what they cannot see.
