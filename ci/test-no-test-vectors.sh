#!/usr/bin/env bash
# Tests for ci/no-test-vectors.sh on a throwaway two-crate workspace with path
# dependencies only (no registry, no network): `a` has a `test-vectors`
# feature and `b` depends on `a`. Enabling the feature from b's
# dev-dependencies must pass; from its dependencies, directly, through a
# default feature of b's own, or on another target, or among a's own default
# features, must fail. Run by gate.sh and CI.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/no-test-vectors.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

manifest() { # name, extra sections
  printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n%s\n' "$1" "$2"
}
mkdir -p "$work/a/src" "$work/b/src"
printf '[workspace]\nmembers = ["a", "b"]\nresolver = "2"\n' > "$work/Cargo.toml"
manifest a '[features]
test-vectors = []' > "$work/a/Cargo.toml"
touch "$work/a/src/lib.rs" "$work/b/src/lib.rs"

expect() { # pass|fail, b's extra sections, description
  manifest b "$2" > "$work/b/Cargo.toml"
  if "$check" "$work" > /dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$1" ]; then
    echo "FAIL: $3: expected $1, got $got" >&2
    exit 1
  fi
}

expect pass '[dependencies]
a = { path = "../a" }' "a plain dependency"
expect pass '[dev-dependencies]
a = { path = "../a", features = ["test-vectors"] }' "the feature through dev-dependencies"
expect fail '[dependencies]
a = { path = "../a", features = ["test-vectors"] }' "the feature through dependencies"
expect fail '[dependencies]
a = { path = "../a" }

[features]
default = ["vectors"]
vectors = ["a/test-vectors"]' "the feature through a default feature of the dependent"
expect fail '[target.wasm32-unknown-unknown.dependencies]
a = { path = "../a", features = ["test-vectors"] }' "the feature on another target"
manifest a '[features]
default = ["test-vectors"]
test-vectors = []' > "$work/a/Cargo.toml"
expect fail '' "the feature among the crate's own default features"
echo "no-test-vectors check: all cases pass"
