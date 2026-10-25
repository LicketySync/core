#!/usr/bin/env bash
# The gate every change must pass before it is committed (the plan's Engineering
# practice). It runs every CI check that can fail and fits on one machine,
# with the tools and Rust toolchains at the versions ci/pins.env pins for CI
# (required; bootstrap.sh installs them): the cargo checks, typos, the Semgrep
# rule cases and scan, the cargo-geiger counts, which must equal
# ci/geiger-baseline.txt, and the checks that every action in the workflows is
# pinned by commit and every toolchain they name is pinned
# (ci/pinned-actions.sh, ci/toolchains.sh). gitleaks runs over the working tree
# when it is installed (the plan's local check; CI scans the full history). CI
# adds the other operating systems, CodeQL, and ClusterFuzzLite once it is
# configured. Needs the network: cargo-audit and cargo-deny fetch the advisory
# database, each into its own clone (see deny.toml), and the Semgrep scan
# fetches the community rules. Works from any directory and stops at the first
# failing step.
set -euo pipefail
cd "$(dirname "$0")"

step() { echo "== $*"; "$@"; }

# The pins first, so that a wrong version stops the gate before the long steps.
# Every version is ci/pins.env's (the pinning rule in .github/workflows/ci.yml's
# header): the gate stops when the tool or toolchain here is another, or when a
# workflow, or ci/geiger-baseline.txt, holds another copy than pins.env's. The
# cargo tools the gate runs are pinned so that the gate and CI judge alike (CI
# once took an older cargo-vet than the one that wrote supply-chain/imports.lock,
# and main went red, run 39160240196); cargo-mutants (mutants.yml), cargo-fuzz
# and cargo-careful (nightly.yml), which the gate does not run, so that a
# survivor, a crash or a finding they report reproduces here with the same tool.
# CONTRIBUTING.md ("Pins and the weekly refresh") says how to move a pin.
pins=ci/pins.env
# Only its listed keys, with plain values, so sourcing it sets nothing else.
ci/check-pins.sh "$pins"
# shellcheck source=ci/pins.env
. "$pins"
wf=.github/workflows
# The rule, for the messages below.
rule="ci/pins.env holds the version; the rule is in $wf/ci.yml's header"

# installs <workflow> <crate>: print each place the workflow installs the
# crate, one per line as written there: an item of an install-action `tool:`
# list, an install-action step named after the crate (`uses:
# taiki-e/install-action@<crate>`), or a `cargo install` command. install-action
# reads `nextest` as cargo-nextest and `typos` as typos-cli, so those names
# count as the crate too. Comments are not install lines.
installs() {
  awk -v crate="$2" '
    function canon(name) {
      if (name == "nextest") return "cargo-nextest"
      if (name == "typos") return "typos-cli"
      return name
    }
    {
      line = $0
      sub(/^[ \t]*(-[ \t]+)?/, "", line)
      sub(/[ \t]+#.*$/, "", line)
      sub(/[ \t]+$/, "", line)
    }
    line ~ /^tool:/ {
      sub(/^tool:[ \t]*/, "", line)
      gsub(/["\047]/, "", line)
      n = split(line, items, /[ \t,]+/)
      for (i = 1; i <= n; i++) {
        name = items[i]
        sub(/@.*/, "", name)
        if (canon(name) == crate) print items[i]
      }
      next
    }
    line ~ /^uses:[ \t]*taiki-e\/install-action@/ {
      name = line
      sub(/^uses:[ \t]*taiki-e\/install-action@/, "", name)
      if (canon(name) == crate) print line
      next
    }
    line ~ /^(run:[ \t]*)?cargo[ \t]+install[ \t]/ {
      sub(/^run:[ \t]*/, "", line)
      n = split(line, words, /[ \t]+/)
      for (i = 3; i <= n; i++) {
        name = words[i]
        sub(/@.*/, "", name)
        if (name == crate) { print line; break }
      }
    }
  ' "$1"
}
# first_version: the first X.Y.Z (or vX.Y.Z) on the first line of its input.
first_version() {
  awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+$/) { sub(/^v/, "", $i); print $i; break } }'
}
# need_installs <crate> <version> <the one install line> <workflow...>: stop
# unless each workflow installs the crate only by that line (an install-action
# item without @version is another line).
need_installs() {
  local crate=$1 version=$2 spelled=$3 file found
  shift 3
  for file in "$@"; do
    if ! found=$(installs "$file" "$crate"); then
      echo "cannot read $file" >&2
      exit 1
    fi
    if [ -z "$found" ] || printf '%s\n' "$found" | grep -qvxF -- "$spelled"; then
      echo "$file must install $crate $version only as \`$spelled\` ($rule)." >&2
      echo "It installs $crate as:" >&2
      printf '%s\n' "${found:-(nothing)}" | sed 's/^/  /' >&2
      exit 1
    fi
  done
}
# need_tool <crate> <version> <the one install line> <workflow...>: as
# need_installs, and stop unless the installed crate is that version. The
# version is the first X.Y.Z of `cargo <tool> --version`, else of
# `<crate without -cli> --version` (typos-cli installs `typos`), else what cargo
# install recorded (cargo-careful has no --version).
need_tool() {
  local crate=$1 version=$2 have extra=
  have=$(cargo "${crate#cargo-}" --version 2> /dev/null | first_version) || true
  if [ -z "$have" ] && [ "${crate%-cli}" != "$crate" ] && command -v "${crate%-cli}" > /dev/null; then
    have=$("${crate%-cli}" --version 2> /dev/null | first_version) || true
  fi
  if [ -z "$have" ] && command -v "$crate" > /dev/null; then
    have=$(cargo install --list | awk -v c="$crate" '$1 == c { v = $2; sub(/^v/, "", v); sub(/:$/, "", v); print v }') || true
  fi
  if [ "$have" != "$version" ]; then
    case $crate in cargo-geiger | cargo-udeps) extra=' --features vendored-openssl' ;; esac
    echo "$crate $version is needed (found: ${have:-none}; $rule); install it for this user:" >&2
    echo "  cargo install --locked $crate --version $version$extra" >&2
    exit 1
  fi
  need_installs "$@"
}
# need_line <file> <ERE selecting the lines> <the one line>: stop unless the
# file has exactly that one line among those selected (indentation and a list
# dash aside).
need_line() {
  local file=$1 select=$2 want=$3 found
  found=$(grep -E "$select" "$file" | sed -E 's/^[[:space:]]*(-[[:space:]]+)?//; s/[[:space:]]+$//') || [ $? -eq 1 ]
  if [ "$found" != "$want" ]; then
    echo "$file must have exactly one line \`$want\` ($rule). It has:" >&2
    printf '%s\n' "${found:-(nothing)}" | sed 's/^/  /' >&2
    exit 1
  fi
}
need_tool cargo-nextest "$CARGO_NEXTEST" "cargo-nextest@$CARGO_NEXTEST" $wf/ci.yml
need_tool cargo-llvm-cov "$CARGO_LLVM_COV" "cargo-llvm-cov@$CARGO_LLVM_COV" $wf/ci.yml
need_tool cargo-udeps "$CARGO_UDEPS" "cargo-udeps@$CARGO_UDEPS" $wf/ci.yml
need_tool cargo-deny "$CARGO_DENY" "cargo-deny@$CARGO_DENY" $wf/ci.yml
need_tool cargo-audit "$CARGO_AUDIT" "cargo-audit@$CARGO_AUDIT" $wf/ci.yml $wf/nightly.yml
need_tool cargo-machete "$CARGO_MACHETE" "cargo-machete@$CARGO_MACHETE" $wf/ci.yml
need_tool cargo-vet "$CARGO_VET" "cargo install cargo-vet --version $CARGO_VET --locked" $wf/ci.yml
need_tool cargo-geiger "$CARGO_GEIGER" \
  "cargo install cargo-geiger --version $CARGO_GEIGER --locked --features vendored-openssl" $wf/ci.yml
need_tool typos-cli "$TYPOS" "typos@$TYPOS" $wf/ci.yml
need_tool cargo-mutants "$CARGO_MUTANTS" "cargo-mutants@$CARGO_MUTANTS" $wf/mutants.yml
need_tool cargo-fuzz "$CARGO_FUZZ" "cargo install cargo-fuzz --version $CARGO_FUZZ --locked" $wf/nightly.yml
need_tool cargo-careful "$CARGO_CAREFUL" "cargo-careful@$CARGO_CAREFUL" $wf/nightly.yml
# release.yml's tools, which the gate does not run.
need_installs cargo-auditable "$CARGO_AUDITABLE" "cargo-auditable@$CARGO_AUDITABLE" $wf/release.yml
need_installs cargo-cyclonedx "$CARGO_CYCLONEDX" "cargo-cyclonedx@$CARGO_CYCLONEDX" $wf/release.yml
# The other copies: cargo-geiger's in the baseline it measured, semgrep's image
# by version and digest, and the Codecov CLI's.
need_line ci/geiger-baseline.txt '^cargo-geiger ' "cargo-geiger $CARGO_GEIGER"
need_line $wf/ci.yml '^[[:space:]]*image:[[:space:]]*semgrep/' "image: semgrep/semgrep:$SEMGREP@$SEMGREP_IMAGE_DIGEST"
need_line $wf/ci.yml '^[[:space:]]*version:' "version: v$CODECOV_CLI"
# semgrep, at the version of CI's image.
if ! have=$(semgrep --version 2> /dev/null) || [ "$have" != "$SEMGREP" ]; then
  echo "semgrep $SEMGREP is needed (found: ${have:-none}; $rule); install it for this user:" >&2
  echo "  pipx install --force semgrep==$SEMGREP" >&2
  exit 1
fi
# The Rust toolchains: RUST_STABLE, which rust-toolchain.toml's `channel =
# "stable"` must give this checkout, and RUST_NIGHTLY, installed by its dated
# name. Neither check downloads anything (RUSTUP_AUTO_INSTALL=0); then
# ci/toolchains.sh checks the workflows.
have=$(RUSTUP_AUTO_INSTALL=0 rustc --version 2> /dev/null | awk 'NR == 1 { print $2 }') || true
if [ "$have" != "$RUST_STABLE" ]; then
  echo "rustc $RUST_STABLE is needed in this checkout (found: ${have:-none}; $rule)." >&2
  echo "rust-toolchain.toml names stable: when stable is older, run \`rustup update stable\`;" >&2
  echo "when it is newer, move the pin, or install $RUST_STABLE and set it for this" >&2
  echo "directory (an override holds for one directory, so each worktree needs its own):" >&2
  echo "  rustup toolchain install $RUST_STABLE --profile minimal --component rustfmt,clippy,llvm-tools-preview" >&2
  echo "  rustup override set $RUST_STABLE" >&2
  exit 1
fi
installed=$(rustup toolchain list)
if ! grep -q "^$RUST_NIGHTLY-" <<< "$installed"; then
  echo "Rust $RUST_NIGHTLY is needed (found: none; $rule); install it for this user:" >&2
  echo "  rustup toolchain install $RUST_NIGHTLY --profile minimal --component miri,rust-src" >&2
  exit 1
fi
ci/toolchains.sh

step cargo fmt --all --check
step cargo clippy --workspace --all-targets --all-features -- -D warnings
step cargo nextest run --workspace --all-features
step cargo test --workspace --doc
step env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
step cargo deny check
step cargo deny --config deny-production.toml check bans
step cargo audit
# fuzz/ is a workspace of its own, so its lockfile is audited on its own.
step cargo audit --file fuzz/Cargo.lock
step cargo machete
step cargo vet --locked
step cargo "+$RUST_NIGHTLY" udeps --workspace --all-targets
# fuzz/Cargo.lock, which nightly.yml's fuzz jobs build from, is current (fuzz/ is
# a workspace of its own).
step cargo fetch --locked --manifest-path fuzz/Cargo.toml
step typos
# Semgrep as CI runs it. The scan covers the files git tracks, so `git add` (or
# `git add -N`) a new file first.
step semgrep --test --metrics=off --config .semgrep/project.yml .semgrep/tests/project.rs
step semgrep scan --metrics=off --timeout 60 --config p/rust --config .semgrep --exclude .semgrep --error
# gitleaks, the gate's one optional step: bootstrap.sh does not install it.
if command -v gitleaks > /dev/null; then
  step ci/gitleaks.sh tree
else
  echo "== skipped: gitleaks (not installed; CI runs it). Install: ci/gitleaks-install.sh ~/.local/bin"
fi
step ci/test-geiger.sh
step ci/geiger.sh
step ci/test-no-hostnames.sh
step ci/no-hostnames.sh
# Every action in the workflows pinned by commit, and the workflows' Rust
# toolchains (the pinning rule in ci.yml's header); ci/toolchains.sh itself ran
# with the pins above.
step ci/test-pinned-actions.sh
step ci/pinned-actions.sh
step ci/test-toolchains.sh
step ci/test-check-pins.sh
# The line-ending attributes of the test vectors and fuzz seeds (.gitattributes).
step ci/test-vector-line-endings.sh
# The scripts mutants.yml and nightly.yml's fuzz jobs run, on stand-ins for the tools.
step ci/test-mutants.sh
step ci/test-fuzz-targets.sh
# 90% line coverage on each of the crates the plan names, and on the index
# crate, which TM-17, TM-40 and TM-41 name as their enforcer (review ruling of
# 2026-10-22), measured per crate: only that crate's own files count, so a
# well-tested neighbour cannot mask it.
for c in keys protocol index engine; do
  others=$(ls crates | grep -vx "$c" | paste -sd'|' -)
  step cargo llvm-cov nextest --all-features --fail-under-lines 90 \
    -p "licketysync-$c" --ignore-filename-regex "crates/($others)/"
done
echo "== gate passed"
