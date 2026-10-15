#!/usr/bin/env bash
# The gate every change must pass before it is committed (the plan's Engineering
# practice). It runs every CI check that can fail and fits on one machine. CI adds
# the other operating systems, Semgrep, CodeQL and gitleaks (tools of their own),
# ClusterFuzzLite once it is configured, and the cargo-geiger report, which cannot
# fail (first-party unsafe is forbidden by the workspace lint). Needs the network:
# cargo-audit and cargo-deny fetch the advisory database. Works from any directory
# and stops at the first failing step.
set -euo pipefail
cd "$(dirname "$0")"

step() { echo "== $*"; "$@"; }

step cargo fmt --all --check
step cargo clippy --workspace --all-targets --all-features -- -D warnings
step cargo nextest run --workspace --all-features
step cargo test --workspace --doc
step env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
step cargo deny check
step cargo audit
step cargo machete
step cargo vet --locked
step cargo +nightly udeps --workspace --all-targets
step typos
step ci/test-no-hostnames.sh
step ci/no-hostnames.sh
# 90% line coverage on each of the crates the plan names, measured per crate:
# only that crate's own files count, so a well-tested neighbour cannot mask it.
for c in keys protocol engine; do
  others=$(ls crates | grep -vx "$c" | paste -sd'|' -)
  step cargo llvm-cov nextest --all-features --fail-under-lines 90 \
    -p "licketysync-$c" --ignore-filename-regex "crates/($others)/"
done
echo "== gate passed"
