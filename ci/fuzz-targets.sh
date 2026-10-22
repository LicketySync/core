#!/usr/bin/env bash
# The fuzz targets for nightly.yml's fuzz matrix: appends `targets=<JSON array
# of the names cargo-fuzz lists in fuzz/>` to <output file> ($GITHUB_OUTPUT in
# CI). With no fuzz/Cargo.toml, or no target in it, the array is empty and a
# notice says that nothing is fuzzed: the fuzz jobs are then skipped, and the
# run says why instead of passing as if it had fuzzed. A failing `cargo fuzz
# list` fails the script, as does a name that is not plain (letters, digits,
# `_` and `-`, ASCII only; the names become job and artifact names). Until 2026-10-22 the
# job ran `for t in $(cargo fuzz list)`, which ignores the command's failure,
# and cargo-fuzz was never installed (install-action has no cargo-fuzz), so the
# job passed in 17 s without fuzzing (runs 39576345810 and 39755196041).
# Usage: ci/fuzz-targets.sh <output file> [repo-root] (defaults to this
# repository). Tested by ci/test-fuzz-targets.sh, which gate.sh runs.
set -euo pipefail
# Byte-wise matching, so that the name check below admits ASCII only.
export LC_ALL=C
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <output file> [repo-root]" >&2
  exit 1
fi
out=$1
case $out in /*) ;; *) out=$PWD/$out ;; esac
cd "${2:-$(dirname "$0")/..}"
targets=
if [ -f fuzz/Cargo.toml ]; then
  targets=$(cd fuzz && cargo fuzz list)
fi
names=()
while IFS= read -r t; do
  [ -n "$t" ] || continue
  if ! [[ $t =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "cargo fuzz list printed a target name that is not plain: $t" >&2
    exit 1
  fi
  names+=("\"$t\"")
done <<< "$targets"
if [ ${#names[@]} -eq 0 ]; then
  echo "::notice title=cargo-fuzz::no fuzz targets in fuzz/Cargo.toml; nothing is fuzzed"
fi
json=$(IFS=,; echo "[${names[*]}]")
echo "fuzz targets: $json"
echo "targets=$json" >> "$out"
