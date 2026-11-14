# Contributing

LicketySync is built by one owner and a set of agents under the rules in the
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

`./gate.sh` is the list. It runs, in order and stopping at the first that
fails, every CI check that can fail and fits on one machine (it needs the
network for the advisory database and Semgrep's community rules), and prints
`== <command>` before each check after the first group (the pins and the
toolchains print no such line), so from there its output is the current list
and its comments say why each is there. This section names only the groups, in
`gate.sh`'s order, and not every command: when the two differ, `gate.sh` is
right. A check is added to `gate.sh` and to CI, and here only when it starts a
group. The groups:

1. **The pins**, before anything is built: `ci/check-pins.sh` on
   `ci/pins.env`; every tool and toolchain at its pinned version, and every
   copy of a version in a workflow or in `ci/geiger-baseline.txt` (below, "Pins
   and the weekly refresh"); `ci/toolchains.sh`.
2. **Rust**: `cargo fmt`, clippy pedantic with `-D warnings` (all targets, all
   features), nextest on every crate but the four of group 8, doc-tests,
   rustdoc with warnings denied.
3. **Dependencies**: `cargo deny` (and the production bans of
   `deny-production.toml`), `cargo audit` on core's lockfile and on `fuzz/`'s,
   `cargo machete`, `cargo vet --locked`.
4. **The browser test crate**, `browser-tests/webtransport` (spike B), a
   workspace of its own: its lockfile fetched `--locked`, audited,
   deny-checked and vetted against its own `supply-chain/`; its code formatted
   and clippy pedantic on wasm32; `ci/check-vendored.sh` (the vendored
   libp2p-webtransport-websys is the copy `vendor/SHA256SUMS` lists) and
   `ci/check-wasm-bindgen.sh` (its wasm-bindgen is the pinned
   wasm-bindgen-cli's).
5. **Unused dependencies and the fuzz lockfile**: `cargo udeps` on the pinned
   nightly; `fuzz/Cargo.lock` current (`cargo fetch --locked`).
6. **Scans**: typos; Semgrep, first the project rules' own cases, then the scan;
   gitleaks over the working tree (`ci/gitleaks.sh tree`), only when gitleaks
   is installed.
7. **The CI scripts**, each check with the test that runs it on made-up
   inputs: cargo-geiger's counts against the baseline (`ci/test-geiger.sh`,
   `ci/geiger.sh`); no hostname beyond `spec/allowed-hosts.txt`
   (`ci/test-no-hostnames.sh`, `ci/no-hostnames.sh`); every action in the
   workflows pinned by commit (`ci/test-pinned-actions.sh`,
   `ci/pinned-actions.sh`); the tests of group 1's two checks
   (`ci/test-toolchains.sh`, `ci/test-check-pins.sh`); the line-ending
   attributes of the test vectors and fuzz seeds
   (`ci/test-vector-line-endings.sh`); the scripts the weekly and nightly
   workflows run, on stand-ins for their tools or made-up logs
   (`ci/test-mutants.sh`, `ci/test-fuzz-targets.sh`,
   `ci/test-check-netlog.sh`); the tests of group 4's two checks
   (`ci/test-check-wasm-bindgen.sh`, `ci/test-check-vendored.sh`); and the
   download helper with the check that nothing downloads without it
   (`ci/test-download.sh`, `ci/check-downloads.sh`); the helper that picks
   sccache (`ci/test-rustc-wrapper.sh`).
8. **Coverage**, last: at least 90% of lines in each of the keys, protocol,
   index and engine crates, measured per crate, after
   `cargo llvm-cov clean --workspace`. These are the gate's only runs of those
   crates' tests; CI runs them under nextest too.

The coverage threshold is per crate: only that crate's own files count, so a
well-tested neighbour cannot mask an under-tested one (`gate.sh` has the exact
loop).

The clean comes first because `cargo llvm-cov` reports on every test binary
that belongs to a workspace crate in `target/llvm-cov-target`, but before a run
removes only the crate it measures. A binary of another crate left by an
earlier run, such as engine's, which links the index, then carries the index
code of that run, and its coverage map counts the old code against the new
files: the index measurement failed for no reason (twice, 2026-11-08).
`cargo llvm-cov clean --workspace` removes every workspace crate's artifacts
and the profile data there, and keeps the build of the dependencies. It takes
under a second and the four measurements take about as long after it as before
(124 s against 119 s on the development machine, half of it engine's tests); a
plain `cargo llvm-cov clean`, which removes the whole directory, adds about
30 s for the dependencies' rebuild. Run the clean first before a coverage command of
your own, too.

`ci/geiger.sh` prints the cargo-geiger report and fails when any of a crate's
five used unsafe counts differs from its line in `ci/geiger-baseline.txt`, up
or down, and prints the line to write. A change that moves them (usually a new
or updated dependency) writes that line in the same commit, so the reviewers
see the change; the baseline's header says how, and how to move to another
cargo-geiger. When its inputs are those of a scan that passed, it skips the
scan and says so; its header lists the inputs, and the stamp that records the
passing scan is in `$XDG_CACHE_HOME/licketysync/geiger` (else
`~/.cache/licketysync/geiger`). `LICKETYSYNC_GEIGER_FULL=1 ./gate.sh` scans
anyway; CI always scans.

Builds go through sccache when it is on `PATH` (`ci/rustc-wrapper.sh`, which
`gate.sh` and `ci/mutants.sh` source, says when and what it caches here). It
runs one server of its own, reached by the Unix socket `server.sock` in
`$XDG_CACHE_HOME/licketysync/sccache` (else `~/.cache/licketysync/sccache`; a
relative `XDG_CACHE_HOME` is ignored), with its cache in `cache/` there,
whatever `SCCACHE_DIR` says. The cache holds up to 10 GiB, or
`SCCACHE_CACHE_SIZE` (such as `2G`), and every cargo-mutants copy adds its own
entries. The server exits after an hour with nothing to do
(`SCCACHE_IDLE_TIMEOUT`, 3600 unless set). After an upgrade of sccache the
helper replaces a server of the old version when it can read the server's
report; otherwise it builds without sccache and prints the command that stops
the server. To see the server's statistics, to stop it (never while a gate or a
mutants run is building: its compilations would start servers of their own), to
clear the cache once it has stopped, and to find stray sccache servers, touching
neither any other sccache server nor your own `SCCACHE_DIR`:

```sh
case ${XDG_CACHE_HOME:-} in /*) d=$XDG_CACHE_HOME ;; *) d=$HOME/.cache ;; esac
d=$d/licketysync/sccache
SCCACHE_SERVER_UDS=$d/server.sock sccache --show-stats
SCCACHE_SERVER_UDS=$d/server.sock sccache --stop-server
rm -r -- "${d:?}/cache"
pgrep -a sccache
```

`LICKETYSYNC_SCCACHE=0` turns it off. CI uses none.

What worktrees share through this cache is in `ci/rustc-wrapper.sh`'s header.
One known limit: sccache 0.19.0 hashes a variable a crate reads as it compiles
the same whether it is unset or set to the empty string, so a crate that reads
one with `option_env!` can be given the other case's output. Nothing LicketySync
builds depends on that today, and CI builds without sccache. To rebuild past it:
stop the server and clear the cache as above, then run a plain `cargo clean` in
each workspace that built the crate (in this one it also empties
`target/llvm-cov-target` and `target/geiger`; `browser-tests/webtransport` is a
workspace of its own), or `cargo clean -p <crate>` with that build's
`--manifest-path`, `--target-dir`, `--target` and `--profile`, since cargo does
not rebuild a crate when only the cache or the wrapper changes. While such a
variable is set to the empty string, run `gate.sh` and `ci/mutants.sh` with
`LICKETYSYNC_SCCACHE=0`, so that the cache holds only the unset case: clearing
the cache alone only changes which case is given the other's output.

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
<k>/<n> <budget>` runs one shard of the mutants as the weekly job does: each
mutant's tests limited to twice the unmutated tree's test time, at least
300 s, and on Linux each test process under the job's caps on memory and file
size). Every cargo-mutants run in this tree, by hand too, caps rustc's lints
(`.cargo/mutants.toml` says why), so that a mutant that only leaves something
unused is tested, not counted unviable. `ci/test-mutants.sh` also needs
python3 (3.11 or later), prlimit and flock (util-linux), and
`ci/test-download.sh` python3, openssl and flock.
gitleaks is optional (`ci/gitleaks-install.sh ~/.local/bin` installs the
release CI pins). Every download in the CI scripts (gitleaks, and Chrome for
Testing in `nightly.yml`) goes through `ci/download.sh`, which retries any
failure for about four minutes, such as the HTTP 504 that failed CI run
42568260092 (so a failure no retry cures, such as a 404 from a wrong pin, is
reported only after those four minutes); a new script calls it, not curl or
wget, and `ci/check-downloads.sh` (in the gate and CI) fails one that does. CI
adds the full-history gitleaks scan, the other operating systems, CodeQL and,
once configured, ClusterFuzzLite.

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
`RUST_NIGHTLY` must be a date whose nightly has miri and rust-src;
`ANDROID_NDK` and `XCODE`, which only `ci.yml`'s `net-cross` job uses, must be
versions the runner images carry (ubuntu-latest's `$ANDROID_HOME/ndk/<version>`,
macos-latest's `/Applications/Xcode_<version>.app`; their README files in
actions/runner-images list them), the NDK named by its full version.

**The weekly refresh.** At each weekly Dependabot review the agent applies the
rule to what Dependabot cannot see, and lands what it finds as one reviewed
change:

- every key in `ci/pins.env`: the Rust stable and dated nightly, the cargo
  tools, typos, semgrep and its image digest, gitleaks and its SHA-256, the
  Codecov CLI, `net-cross`'s Android NDK and Xcode, and the nightly
  `webtransport-chrome` job's Chrome for Testing with the SHA-256 of its two
  zips and the size of the Chrome zip, which `ci/test-download.sh` checks
  (`ci/chrome-install.sh` says how to take them), and its
  wasm-bindgen-cli, which moves in the same change as
  `browser-tests/webtransport`'s `wasm-bindgen`, `wasm-bindgen-futures`,
  `wasm-bindgen-test`, `js-sys` and `web-sys`: Dependabot skips those crates
  there (`dependabot.yml`), since `wasm-bindgen-test-runner` refuses a module
  built against another wasm-bindgen, and `ci/check-wasm-bindgen.sh` (gate.sh
  and CI's `deps` job) fails unless the test crate's `Cargo.toml` requires
  exactly the CLI's version of `wasm-bindgen` and its `Cargo.lock` holds it;
- cargo-geiger, which moves only with the baseline's counts;
- site's zola, in its `pages.yml` (site has no `pins.env`);
- the commit pins of `dtolnay/rust-toolchain` and `google/clusterfuzzlite`:
  each has a single tag, `v1`, and no version releases, so Dependabot has no
  newer release to move to; a bump pins the commit `v1` names that day;
- transitive crates, which Dependabot skips: `cargo update` here, in
  `fuzz/` (whose `Cargo.lock` the fuzz jobs build from with `--locked`
  checked) and in `browser-tests/webtransport` (spike B's browser test crate,
  with its own `supply-chain/` store), taking back with `cargo update
  --precise` any version younger than 7 days, then `cargo deny`, `cargo audit`
  (and `cargo audit --file` on the other two lockfiles), `cargo vet` in both
  stores and the geiger baseline as for any dependency change. `cargo vet
  prune` runs in one store at a time: an exemption that only the other
  workspace's graph uses looks unused to it, so prune neither store from the
  other's workspace (the browser workspace's exemptions live in its own
  store, `browser-tests/webtransport/supply-chain/`, for that reason). One
  exception, which the owner approved on 2026-11-03: `idna_adapter`, idna's
  back end chosen by its version, stays on its 1.0 line, the ASCII-only one
  (`crates/net/Cargo.toml` requires `~1.0`, `deny.toml` bans the ICU4X back
  end of later lines, and `dependabot.yml` skips them); a 1.0.* release is
  taken as usual. One hold-back that is no
  one's choice: `libp2p-swarm` 0.48.0 requires `wasm-bindgen-futures`
  `=0.4.58` on wasm targets only, which holds `wasm-bindgen` and its macro
  and shared crates at 0.2.108 and `js-sys` and `web-sys` at 0.3.85 in
  `Cargo.lock` (no native build compiles them), so a refresh leaves them
  until `libp2p-swarm` moves. Phase 6's browser build must settle it: the
  app's web UI and the `wasm-bindgen-cli` the spikes use are on 0.2.129, and
  one wasm build holds one `wasm-bindgen`.

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
