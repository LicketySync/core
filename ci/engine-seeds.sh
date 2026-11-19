#!/usr/bin/env bash
# The engine scenarios over seeds 0 to 39: crates/engine/tests/converge.rs,
# which runs seeds 0 to 4 unless LICKETYSYNC_ENGINE_SEEDS names another count.
# A scenario can fail one seed in ten and pass the first five: after 0747475,
# engine-partition failed seeds 20 and 29 of the nightly long runs while every
# gate passed (73a0240 fixed it). The test profile's debug assertions stay on,
# and every failing scenario and seed is reported (--no-fail-fast). The seed
# count is named here and nowhere else.
# Usage: ci/engine-seeds.sh [repo-root] (defaults to this repository). Run by
# gate.sh and by ci.yml's Linux test job; tested by ci/test-engine-seeds.sh, on
# a stand-in cargo. Exits with cargo's status.
set -euo pipefail
seeds=40
cd "${1:-$(dirname "$0")/..}"
echo "== the engine scenarios over seeds 0 to $((seeds - 1))"
LICKETYSYNC_ENGINE_SEEDS=$seeds exec cargo nextest run -p licketysync-engine --all-features \
  --test converge --no-fail-fast
