#!/usr/bin/env bash
# The browser test crate's wasm-bindgen is the version of the wasm-bindgen-cli
# that nightly.yml's webtransport-chrome job installs (WASM_BINDGEN_CLI in
# ci/pins.env): its Cargo.toml requires exactly that version and its
# Cargo.lock holds it, since wasm-bindgen-test-runner refuses a wasm module
# built against another wasm-bindgen. Run by gate.sh and CI's deps job on every
# push, so that no change (a Dependabot pull request among them) can turn the
# nightly red this way. Tested by ci/test-check-wasm-bindgen.sh.
# Usage: ci/check-wasm-bindgen.sh [repo-root]. Exit 1 on a mismatch.
set -euo pipefail
root=${1:-$(dirname "$0")/..}
"$root/ci/check-pins.sh" "$root/ci/pins.env"
# shellcheck source=pins.env
. "$root/ci/pins.env"
want=${WASM_BINDGEN_CLI:?ci/pins.env sets no WASM_BINDGEN_CLI}
manifest=$root/browser-tests/webtransport/Cargo.toml
lock=$root/browser-tests/webtransport/Cargo.lock
required=$(sed -nE 's/^wasm-bindgen[[:space:]]*=[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "$manifest")
locked=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/^version = "|"$/, ""); print }' "$lock")
status=0
if [ "$required" != "=$want" ]; then
  echo "$manifest requires wasm-bindgen \"${required:-(none)}\"; WASM_BINDGEN_CLI is $want, so it must be \"=$want\"" >&2
  status=1
fi
if [ "$locked" != "$want" ]; then
  echo "$lock holds wasm-bindgen ${locked:-(none)}; WASM_BINDGEN_CLI is $want" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "wasm-bindgen $want in the browser test crate, as WASM_BINDGEN_CLI"
exit "$status"
