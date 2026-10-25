#!/usr/bin/env bash
# Tests for ci/check-pins.sh. Each case is a pins file in a temporary directory;
# the expected exit code is the assertion, and each name says the result. The
# real ci/pins.env is the first case. Run by gate.sh and CI. Exit 1 if any case
# fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-pins.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
n=0
fails=0
run_case() { # run_case <name> <expected exit> <file>
  local rc=0
  "$check" "$3" > "$tmp/out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$tmp/out"
    fails=$((fails + 1))
  fi
}
case_() { # case_ <name> <expected exit> <file body>
  n=$((n + 1))
  printf '%s\n' "$3" > "$tmp/$n.env"
  run_case "$1" "$2" "$tmp/$n.env"
}
good=$'# a comment\n\nRUST_STABLE=1.2.3\nRUST_NIGHTLY=nightly-2000-01-02\nSEMGREP_IMAGE_DIGEST=sha256:0123abcd'
run_case "passes: this repository's ci/pins.env"  0 "$here/pins.env"
case_ "passes: comments, blank lines and known keys" 0 "$good"
case_ "passes: an indented comment"              0 $'   # indented\nTYPOS=1.2.3'
case_ "refused: PATH"                            1 "$good"$'\nPATH=bin'
case_ "refused: HOME"                            1 "$good"$'\nHOME=tmp'
case_ "refused: IFS"                             1 "$good"$'\nIFS=x'
case_ "refused: LC_ALL"                          1 "$good"$'\nLC_ALL=C'
case_ "refused: a cargo setting"                 1 "$good"$'\nCARGO_HOME=tmp'
case_ "refused: RUSTUP_TOOLCHAIN"                1 "$good"$'\nRUSTUP_TOOLCHAIN=stable'
case_ "refused: an unknown key"                  1 "$good"$'\nCARGO_NEW_TOOL=1.0.0'
case_ "refused: a lowercase key"                 1 "$good"$'\nrust_stable=1.2.3'
case_ "refused: a key set twice"                 1 "$good"$'\nRUST_STABLE=1.2.4'
case_ "refused: export"                          1 $'export RUST_STABLE=1.2.3'
case_ "refused: a space before the key"          1 $' RUST_STABLE=1.2.3'
case_ "refused: spaces around ="                 1 $'RUST_STABLE = 1.2.3'
case_ "refused: a command substitution"          1 $'RUST_STABLE=$(touch x)'
case_ "refused: a backtick"                      1 $'RUST_STABLE=`id`'
case_ "refused: a second command after ;"        1 $'RUST_STABLE=1.2.3;id'
case_ "refused: a trailing comment"              1 $'RUST_STABLE=1.2.3 # pinned'
case_ "refused: a quoted value"                  1 $'RUST_STABLE="1.2.3"'
case_ "refused: an empty value"                  1 $'RUST_STABLE='
case_ "refused: a tilde"                         1 $'RUST_STABLE=~'
case_ "refused: a carriage return"               1 $'RUST_STABLE=1.2.3\r'
case_ "refused: a line with no ="                1 $'RUST_STABLE'
n=$((n + 1))
run_case "refused: a missing file (fails closed)" 1 "$tmp/$n.env"
if [ "$fails" -ne 0 ]; then
  echo "$fails of the cases failed" >&2
  exit 1
fi
echo "test-check-pins: all cases passed"
