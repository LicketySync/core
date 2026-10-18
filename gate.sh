#!/usr/bin/env bash
# The gate every change must pass before it is committed (the plan's Engineering
# practice). It runs every CI check that can fail and fits on one machine: the
# Semgrep rule cases and scan with the semgrep version CI's image pins (required;
# bootstrap.sh installs it), and the cargo-geiger counts, which must equal
# ci/geiger-baseline.txt. gitleaks runs over the working tree when it is
# installed (the plan's local check; CI scans the full history). CI adds the
# other operating systems, CodeQL, and ClusterFuzzLite once it is configured.
# Needs the network: cargo-audit and cargo-deny fetch the advisory database,
# each into its own clone (see deny.toml), and the Semgrep scan fetches the
# community rules. Works from any directory and stops at the first failing step.
set -euo pipefail
cd "$(dirname "$0")"

step() { echo "== $*"; "$@"; }

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
# Semgrep as CI runs it, with CI's version (its image tag in ci.yml). The scan
# covers the files git tracks, so `git add` (or `git add -N`) a new file first.
semgrep_version=1.181.0
if ! have=$(semgrep --version 2> /dev/null) || [ "$have" != "$semgrep_version" ]; then
  echo "semgrep $semgrep_version is needed (found: ${have:-none}); install it for this user:" >&2
  echo "  pipx install --force semgrep==$semgrep_version" >&2
  exit 1
fi
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
