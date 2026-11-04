#!/usr/bin/env bash
# Tests for ci/check-wasm-bindgen.sh. Each case is a tree in a temporary
# directory with this repository's ci/check-pins.sh, a pins.env, and the
# browser test crate's Cargo.toml and Cargo.lock lines that matter; the
# expected exit code is the assertion. Run by gate.sh and CI. Exit 1 if any
# case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
n=0
fails=0
case_() { # case_ <name> <expected exit> <WASM_BINDGEN_CLI> <Cargo.toml requirement> <Cargo.lock version>
  n=$((n + 1))
  local dir="$tmp/$n" rc=0
  mkdir -p "$dir/ci" "$dir/browser-tests/webtransport"
  cp "$here/check-pins.sh" "$here/check-wasm-bindgen.sh" "$dir/ci/"
  printf 'WASM_BINDGEN_CLI=%s\n' "$3" > "$dir/ci/pins.env"
  printf '[target.x.dependencies]\nwasm-bindgen = "%s"\nwasm-bindgen-test = "=0.3.79"\n' "$4" \
    > "$dir/browser-tests/webtransport/Cargo.toml"
  printf '[[package]]\nname = "wasm-bindgen"\nversion = "%s"\n\n[[package]]\nname = "wasm-bindgen-test"\nversion = "0.3.80"\n' "$5" \
    > "$dir/browser-tests/webtransport/Cargo.lock"
  "$dir/ci/check-wasm-bindgen.sh" "$dir" > "$dir/out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
case_ "all three agree"                         0 0.2.129 "=0.2.129" 0.2.129
case_ "a bumped requirement and lock"           1 0.2.129 "=0.2.130" 0.2.130
case_ "a bumped lock under a caret requirement" 1 0.2.129 "0.2.129" 0.2.130
case_ "a requirement that is not exact"         1 0.2.129 "0.2.129" 0.2.129
case_ "the pin moved without the crate"         1 0.2.130 "=0.2.129" 0.2.129
if [ "$fails" -ne 0 ]; then
  echo "$fails of $n cases failed"
  exit 1
fi
echo "all $n cases passed"
