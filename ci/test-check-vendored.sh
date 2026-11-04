#!/usr/bin/env bash
# Tests for ci/check-vendored.sh. Each case copies this repository's vendored
# crate and its SHA256SUMS into a temporary tree, changes one thing, and runs
# the check there; the expected exit code is the assertion. Run by gate.sh and
# CI. Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
vendor="$here/../browser-tests/webtransport/vendor"
crate=libp2p-webtransport-websys-0.6.0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
n=0
fails=0
case_() { # case_ <name> <expected exit> <shell command run in the copied crate directory>
  n=$((n + 1))
  local dir="$tmp/$n" rc=0
  mkdir -p "$dir/browser-tests/webtransport/vendor"
  cp -R "$vendor/$crate" "$vendor/SHA256SUMS" "$dir/browser-tests/webtransport/vendor/"
  (cd "$dir/browser-tests/webtransport/vendor/$crate" && eval "$3")
  "$here/check-vendored.sh" "$dir" > "$dir/out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
case_ "the copy as committed"           0 ':'
case_ "an edited source file"           1 'echo "// edit" >> src/lib.rs'
case_ "an extra file"                   1 'touch src/extra.rs'
case_ "a missing file"                  1 'rm src/utils.rs'
case_ "a symbolic link added"           1 'ln -s lib.rs src/link.rs'
case_ "a listed file made a link"       1 'mv src/utils.rs ../utils.rs && ln -s ../../utils.rs src/utils.rs'
if [ "$fails" -ne 0 ]; then
  echo "$fails of $n cases failed"
  exit 1
fi
echo "all $n cases passed"
