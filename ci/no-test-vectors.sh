#!/usr/bin/env bash
# No build that ships enables a `test-vectors` feature (deterministic signing,
# for test vectors only; see crates/keys/Cargo.toml): a crate may enable it in
# its dev-dependencies and nowhere else. `cargo tree` without dev-dependency
# edges resolves features as a build of every workspace member does, on every
# target, and `{f}` prints each package's resolved features (`-e features`
# would miss one a member turns on through its own features); a package with
# `test-vectors` among them is a hit.
# Usage: ci/no-test-vectors.sh [workspace-root] (defaults to this repository).
# Exit 1 on a hit. Run by gate.sh and CI; tested by ci/test-no-test-vectors.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

tree=$(cargo tree --workspace --target all -e no-dev --prefix none -f '{p} [{f}]')
if hits=$(printf '%s\n' "$tree" | grep -E '\[([^]]*,)?test-vectors(,[^]]*)?\]$'); then
  echo "test-vectors is enabled outside dev-dependencies:" >&2
  printf '%s\n' "$hits" | sort -u >&2
  echo "find who enables it: cargo tree -e features,no-dev -i <crate>" >&2
  exit 1
fi
echo "no test-vectors feature outside dev-dependencies"
