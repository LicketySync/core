#!/usr/bin/env bash
# The gate every change must pass before it is committed (the plan's Engineering
# practice). It runs every CI check that can fail and fits on one machine:
# cargo-deny, cargo-audit, cargo-machete and cargo-vet at the versions CI pins
# (required; bootstrap.sh installs them), the Semgrep rule cases and scan with
# the semgrep version CI's image pins (required; bootstrap.sh installs it), and
# the cargo-geiger counts, which must equal ci/geiger-baseline.txt. gitleaks
# runs over the working tree when it is installed (the plan's local check; CI
# scans the full history). CI adds the other operating systems, CodeQL, and
# ClusterFuzzLite once it is configured. Needs the network: cargo-audit and
# cargo-deny fetch the advisory database, each into its own clone (see
# deny.toml), and the Semgrep scan fetches the community rules. Works from any
# directory and stops at the first failing step.
set -euo pipefail
cd "$(dirname "$0")"

step() { echo "== $*"; "$@"; }

# The pinned tools first, so that a wrong version stops the gate before the
# long steps. cargo-deny, cargo-audit, cargo-machete and cargo-vet at the exact
# versions CI installs, so that the gate and CI judge alike: CI once took the
# newest cargo-vet it found, 0.10.0, whose formatter rejects the
# supply-chain/imports.lock that 0.10.2 writes, and main went red (run
# 39160240196). A bump is one reviewed change to these lines, ci.yml,
# nightly.yml and bootstrap.sh; Dependabot cannot see the pins, so the weekly
# Dependabot review checks them for new releases.
# installs <workflow> <crate>: print each place the workflow installs the
# crate, one per line as written there: an item of an install-action `tool:`
# list, an install-action step named after the crate (`uses:
# taiki-e/install-action@<crate>`), or a `cargo install` command. Comments are
# not install lines.
installs() {
  awk -v crate="$2" '
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
        if (name == crate) print items[i]
      }
      next
    }
    line ~ /^uses:[ \t]*taiki-e\/install-action@/ {
      name = line
      sub(/^uses:[ \t]*taiki-e\/install-action@/, "", name)
      if (name == crate) print line
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
# need_tool <crate> <version> <the one install line> <workflow...>: stop unless
# the installed crate is that version and each workflow installs the crate only
# by that line (an install-action item without @version is another line).
need_tool() {
  local crate=$1 version=$2 spelled=$3 have file found
  shift 3
  have=$(cargo "${crate#cargo-}" --version 2> /dev/null | awk 'NR == 1 { print $NF }') || true
  if [ "$have" != "$version" ]; then
    echo "$crate $version is needed (found: ${have:-none}); install it for this user:" >&2
    echo "  cargo install --locked $crate --version $version" >&2
    exit 1
  fi
  for file in "$@"; do
    if ! found=$(installs "$file" "$crate"); then
      echo "cannot read $file" >&2
      exit 1
    fi
    if [ -z "$found" ] || printf '%s\n' "$found" | grep -qvxF -- "$spelled"; then
      echo "$file must install $crate $version only as \`$spelled\`; the gate and CI" >&2
      echo "must pin one version. It installs $crate as:" >&2
      printf '%s\n' "${found:-(nothing)}" | sed 's/^/  /' >&2
      exit 1
    fi
  done
}
wf=.github/workflows
need_tool cargo-deny 0.20.2 cargo-deny@0.20.2 $wf/ci.yml
need_tool cargo-audit 0.22.2 cargo-audit@0.22.2 $wf/ci.yml $wf/nightly.yml
need_tool cargo-machete 0.9.2 cargo-machete@0.9.2 $wf/ci.yml
need_tool cargo-vet 0.10.2 'cargo install cargo-vet --version 0.10.2 --locked' $wf/ci.yml
# Semgrep with CI's version (its image tag in ci.yml).
semgrep_version=1.181.0
if ! have=$(semgrep --version 2> /dev/null) || [ "$have" != "$semgrep_version" ]; then
  echo "semgrep $semgrep_version is needed (found: ${have:-none}); install it for this user:" >&2
  echo "  pipx install --force semgrep==$semgrep_version" >&2
  exit 1
fi

step cargo fmt --all --check
step cargo clippy --workspace --all-targets --all-features -- -D warnings
step cargo nextest run --workspace --all-features
step cargo test --workspace --doc
step env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
step cargo deny check
step cargo deny --config deny-production.toml check bans
step cargo audit
step cargo machete
step cargo vet --locked
step cargo +nightly udeps --workspace --all-targets
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
step ci/test-no-test-vectors.sh
step ci/no-test-vectors.sh
# 90% line coverage on each of the crates the plan names, measured per crate:
# only that crate's own files count, so a well-tested neighbour cannot mask it.
for c in keys protocol engine; do
  others=$(ls crates | grep -vx "$c" | paste -sd'|' -)
  step cargo llvm-cov nextest --all-features --fail-under-lines 90 \
    -p "licketysync-$c" --ignore-filename-regex "crates/($others)/"
done
echo "== gate passed"
