#!/usr/bin/env bash
# Tests for ci/toolchains.sh. Each case is a repository in a temporary
# directory with its own ci/pins.env (stable 1.2.3, nightly-2000-01-02), one
# workflow and, for some, a ci/ script; the expected exit code is the assertion.
# Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/toolchains.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
n=0
fails=0
pins=$'# test pins\nRUST_STABLE=1.2.3\nRUST_NIGHTLY=nightly-2000-01-02'
sha=0123456789abcdef0123456789abcdef01234567
tc="uses: dtolnay/rust-toolchain@$sha # v1"
run_case() { # run_case <name> <expected exit> <repo>
  local rc=0
  "$check" "$3" > "$3.out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$3.out"
    fails=$((fails + 1))
  fi
}
case_() { # case_ <name> <expected exit> <workflow> [<ci script body>]
  n=$((n + 1))
  local repo="$tmp/$n"
  mkdir -p "$repo/.github/workflows" "$repo/ci"
  printf '%s\n' "$pins" > "$repo/ci/pins.env"
  printf '%s\n' "$3" > "$repo/.github/workflows/w.yml"
  if [ -n "${4:-}" ]; then printf '%s\n' "$4" > "$repo/ci/s.sh"; fi
  run_case "$1" "$2" "$repo"
}
head_env=$'on: push\nenv:\n  RUSTUP_TOOLCHAIN: 1.2.3\njobs:'
head_bare=$'on: push\njobs:'
job() { # job <name> <job-level lines> <step lines...>: one job, steps indented
  local name=$1 extra=$2
  shift 2
  printf '  %s:\n    runs-on: ubuntu-latest\n' "$name"
  if [ -n "$extra" ]; then printf '%s\n' "$extra"; fi
  printf '    steps:\n'
  printf '      %s\n' "$@"
}
nightly_env=$'    env:\n      RUSTUP_TOOLCHAIN: nightly-2000-01-02'

case_ "passes: stable step and run under the workflow's RUSTUP_TOOLCHAIN" 0 \
  "$head_env"$'\n'"$(job a "" "- $tc" "  with:" "    toolchain: 1.2.3" "- run: cargo test")"
case_ "passes: nightly job overriding the workflow's RUSTUP_TOOLCHAIN" 0 \
  "$head_env"$'\n'"$(job a "$nightly_env" "- $tc" "  with:" "    toolchain: nightly-2000-01-02" "- run: cargo +nightly-2000-01-02 udeps")"
case_ "passes: a job with no Rust needs no RUSTUP_TOOLCHAIN" 0 \
  "$head_bare"$'\n'"$(job a "" "- run: echo hello" "- run: ci/s.sh")" 'echo "no tools here"'
case_ "passes: a ci/ script that only mentions cargo in a comment" 0 \
  "$head_bare"$'\n'"$(job a "" "- run: ci/s.sh")" $'# cargo is not called here\necho hi'
case_ "passes: a path under .cargo is not a call" 0 \
  "$head_bare"$'\n'"$(job a "" "- run: ls ~/.cargo/bin")"
case_ "passes: a commented-out YAML line is not read" 0 \
  "$head_env"$'\n'"$(job a "" "# toolchain: stable" "- run: cargo test")"
case_ "passes: a key after an inline run is not part of it" 0 \
  "$head_env"$'\n'"$(job a "" "- run: cargo test" "  env:" "    X: toolchain-free")"
case_ "refused: a step on stable" 1 \
  "$head_env"$'\n'"$(job a "" "- $tc" "  with:" "    toolchain: stable")"
case_ "refused: a step on the undated nightly" 1 \
  "$head_env"$'\n'"$(job a "$nightly_env" "- $tc" "  with:" "    toolchain: nightly")"
case_ "refused: another version" 1 \
  "$head_env"$'\n'"$(job a "" "- $tc" "  with:" "    toolchain: 1.2.4")"
case_ "refused: a step with no toolchain input" 1 \
  "$head_env"$'\n'"$(job a "" "- $tc")"
case_ "refused: a pinned step in a workflow with no RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "" "- $tc" "  with:" "    toolchain: 1.2.3")"
case_ "refused: a job RUSTUP_TOOLCHAIN that differs from its step" 1 \
  "$head_env"$'\n'"$(job a "$nightly_env" "- $tc" "  with:" "    toolchain: 1.2.3")"
case_ "refused: an inline run calling cargo with no RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "" "- run: cargo build")"
case_ "refused: a block run calling rustc with no RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "" "- name: x" "  run: |" "    set -e" "    rustc --version")"
case_ "refused: a run calling rustup with no RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "" "- run: rustup show")"
case_ "refused: a run calling a ci/ script that calls cargo, with no RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "" "- run: ci/s.sh x")" $'set -e\ncargo test "$@"'
case_ "refused: RUSTUP_TOOLCHAIN for one step only" 1 \
  "$head_bare"$'\n'"$(job a "" "- run: cargo test" "  env:" "    RUSTUP_TOOLCHAIN: 1.2.3")"
case_ "refused: cargo +nightly in an inline run" 1 \
  "$head_env"$'\n'"$(job a "" "- run: cargo +nightly udeps")"
case_ "refused: cargo +stable in a block run" 1 \
  "$head_env"$'\n'"$(job a "" "- run: |" "    cd fuzz" "    cargo +stable fuzz run x")"
case_ "refused: a shell comment naming another toolchain (read, fails closed)" 1 \
  "$head_env"$'\n'"$(job a "" "- run: |" "    # cargo +nightly test" "    cargo test")"
case_ "refused: a workflow RUSTUP_TOOLCHAIN of stable" 1 \
  $'on: push\nenv:\n  RUSTUP_TOOLCHAIN: stable\njobs:\n'"$(job a "" "- run: cargo test")"
case_ "refused: the second job of two lacks RUSTUP_TOOLCHAIN" 1 \
  "$head_bare"$'\n'"$(job a "$nightly_env" "- run: cargo test")"$'\n'"$(job b "" "- run: cargo test")"
# Built by hand: case_ always writes the pins file and one workflow.
n=$((n + 1)); repo="$tmp/$n"; mkdir -p "$repo/.github/workflows" "$repo/ci"
printf '%s\n' "$head_env" > "$repo/.github/workflows/w.yml"
run_case "refused: a missing ci/pins.env (fails closed)" 1 "$repo"
n=$((n + 1)); repo="$tmp/$n"; mkdir -p "$repo/.github/workflows" "$repo/ci"
printf '%s\nX=$(touch %s/ran)\n' "$pins" "$repo" > "$repo/ci/pins.env"
printf '%s\n' "$head_env" > "$repo/.github/workflows/w.yml"
run_case "refused: a pins line that would run a command" 1 "$repo"
if [ -e "$repo/ran" ]; then echo "FAIL the pins line ran"; fails=$((fails + 1)); fi
n=$((n + 1)); repo="$tmp/$n"; mkdir -p "$repo/.github/workflows" "$repo/ci"
printf '%s\n' "$pins" > "$repo/ci/pins.env"
run_case "refused: no workflow (fails closed)" 1 "$repo"
if [ "$fails" -ne 0 ]; then
  echo "$fails of the cases failed" >&2
  exit 1
fi
echo "test-toolchains: all cases passed"
