#!/usr/bin/env bash
# The tests that race, run <runs> times in a row with no retries, stopping at
# the first failing run. A race that fails one run in three, or one in
# twenty-five, passes a single run: the store's open race on Windows passed CI
# at aaa2d90 and failed it in run 43753618314, and the forked child that held
# the store's open lock failed 6 of 150 runs of the nightly's cargo careful
# (f427bca fixed both), after the gate had passed each change once.
#
# The tests, named here and nowhere else (one line each: the package, where the
# filter must select at least one test, `any` or `linux`, and libtest's filter):
# - the daemon store's: every one opens a store and takes its open lock, and
#   some open one from eight threads at once, or spawn processes that open it,
#   hold it or are killed while writing;
# - the fs resolver's symlink swap race (TM-4), which only Linux and Android
#   build.
# A filter that selects no test where it must select one, or only ignored
# tests, fails the script, so that a renamed test cannot drop out of the loop
# unnoticed; elsewhere it says so and runs nothing.
#
# Each run is `cargo test` of each package's library tests, the selected tests
# on threads of one process, as `cargo test` and the nightly's `cargo careful
# test` run them, rather than nextest's process per test: a child that one test
# spawns holds a copy of every descriptor of the process until it starts its
# program, so an open lock that another test let go by closing its file stayed
# held through that copy. A process per test never shows it: on the store
# before f427bca's fix, 7 of 8 loops of 50 runs here failed so, while nextest's
# --stress-count 50 passed every iteration.
# Usage: ci/repeat-races.sh <runs> [repo-root] (defaults to this repository).
# Run by gate.sh (50 runs); it runs on Windows and macOS too; tested by
# ci/test-repeat-races.sh, on a stand-in cargo. Exit 1 when a build or a run
# fails or a filter selects no test where it must; 2 on a wrong argument.
set -euo pipefail
races=(
  'licketysync-daemon any store::tests::'
  'licketysync-fs linux resolver::tests::tm_4_symlink_then_directory_race'
)
if [ $# -lt 1 ] || [ $# -gt 2 ] || ! [[ $1 =~ ^[1-9][0-9]{0,3}$ ]]; then
  echo "usage: $0 <runs, 1 to 9999> [repo-root]" >&2
  exit 2
fi
runs=$1
cd "${2:-$(dirname "$0")/..}"
case $(uname -s) in
  Linux) os=linux ;;
  *) os=other ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The entries that select a test here, as "<package> <filter>".
selected=()
total=0
for entry in "${races[@]}"; do
  read -r package where filter <<< "$entry"
  cmd=(cargo test -p "$package" --lib --all-features)
  "${cmd[@]}" --no-run
  # libtest lists each selected test as `<name>: test`; a CR is dropped, for
  # Windows.
  "${cmd[@]}" -- --list "$filter" > "$tmp/list" 2> "$tmp/list.err" || {
    cat "$tmp/list.err" >&2
    echo "cannot list the tests of $package" >&2
    exit 1
  }
  count=$(tr -d '\r' < "$tmp/list" | grep -c ': test$' || true)
  # `--list` shows an ignored test too, but `cargo test` runs none of it, and
  # `--list --ignored` shows only those: a filter whose tests are all ignored
  # selects none.
  "${cmd[@]}" -- --list --ignored "$filter" > "$tmp/ignored" 2> "$tmp/list.err" || {
    cat "$tmp/list.err" >&2
    echo "cannot list the ignored tests of $package" >&2
    exit 1
  }
  count=$((count - $(tr -d '\r' < "$tmp/ignored" | grep -c ': test$' || true)))
  if [ "$count" -gt 0 ]; then
    echo "== $package: \`$filter\` selects $count"
    selected+=("$package $filter")
    total=$((total + count))
  elif [ "$where" = any ] || [ "$where" = "$os" ]; then
    echo "$package: \`$filter\` selects no test; ci/repeat-races.sh must name tests that exist" >&2
    exit 1
  else
    echo "== $package: \`$filter\` selects no test here ($where only)"
  fi
done
start=$SECONDS
for ((run = 1; run <= runs; run++)); do
  for entry in "${selected[@]}"; do
    read -r package filter <<< "$entry"
    if ! cargo test -p "$package" --lib --all-features -q -- "$filter" > "$tmp/run" 2>&1; then
      cat "$tmp/run"
      echo "run $run of $runs failed: $package, $filter" >&2
      exit 1
    fi
  done
done
echo "== $runs runs of the $total passed ($((SECONDS - start)) s)"
