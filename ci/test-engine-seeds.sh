#!/usr/bin/env bash
# Tests for ci/engine-seeds.sh with a stand-in `cargo` first on PATH, which
# records its arguments and the LICKETYSYNC_ENGINE_SEEDS it was given, and
# exits as the case says; then that the variable is the one
# crates/engine/tests/converge.rs reads, so that renaming it there cannot turn
# the slice back into seeds 0 to 4 unnoticed. Run by gate.sh and CI. Exit 1 if
# any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/engine-seeds.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/cargo" << 'STUB'
#!/usr/bin/env bash
printf '%s\n' "seeds=${LICKETYSYNC_ENGINE_SEEDS-unset} dir=$PWD $*" > "$FAKE_CALL"
exit "${FAKE_EXIT:-0}"
STUB
chmod +x "$tmp/bin/cargo"
PATH="$tmp/bin:$PATH"
want="nextest run -p licketysync-engine --all-features --test converge --no-fail-fast"
n=0
fails=0
# case_ <name> <expected exit> <expected call, or ""> [VAR=value ... for the
# script and the stand-in]
case_() {
  n=$((n + 1))
  local name=$1 code=$2 call=$3 dir="$tmp/$n" rc=0
  shift 3
  mkdir "$dir"
  env FAKE_CALL="$dir/call" "$@" "$script" "$dir" > "$dir/log" 2>&1 || rc=$?
  if [ "$rc" = "$code" ] && [ "$(cat "$dir/call" 2> /dev/null)" = "$call" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $code; cargo was called as:"
    sed 's/^/  > /' "$dir/call" 2> /dev/null || echo "  (not called)"
    sed 's/^/  | /' "$dir/log"
    fails=$((fails + 1))
  fi
}
case_ "converge runs over seeds 0 to 39, in the given tree" 0 "seeds=40 dir=$tmp/1 $want"
case_ "a failing run fails with cargo's status" 100 "seeds=40 dir=$tmp/2 $want" FAKE_EXIT=100
case_ "a count in the caller's environment is replaced" 0 "seeds=40 dir=$tmp/3 $want" \
  LICKETYSYNC_ENGINE_SEEDS=5
# The variable the script sets must be the one converge.rs reads.
n=$((n + 1))
name="converge.rs reads LICKETYSYNC_ENGINE_SEEDS"
if grep -qF 'std::env::var("LICKETYSYNC_ENGINE_SEEDS")' "$here/../crates/engine/tests/converge.rs"; then
  echo "ok   $name"
else
  echo "FAIL $name: crates/engine/tests/converge.rs no longer reads it; ci/engine-seeds.sh sets it"
  fails=$((fails + 1))
fi
if [ "$fails" -gt 0 ]; then
  echo "engine-seeds: $fails failing case(s)"
  exit 1
fi
echo "engine-seeds: all $n cases pass"
