#!/usr/bin/env bash
# Tests for ci/mutants.sh with a stand-in `cargo` first on PATH: it records its
# arguments, writes the outcome files the case gives it into mutants.out/ and
# exits with the case's code, or blocks until a signal comes and records
# SIGINT. The expected exit code and the expected lines of output are the
# assertions. Run by gate.sh, ci.yml and mutants.yml. Exit 1 if any case fails.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/mutants.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/cargo" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > args
mkdir -p mutants.out
printf '%b' "${FAKE_CAUGHT:-}" > mutants.out/caught.txt
printf '%b' "${FAKE_MISSED:-}" > mutants.out/missed.txt
printf '%b' "${FAKE_TIMEOUT:-}" > mutants.out/timeout.txt
printf '%b' "${FAKE_UNVIABLE:-}" > mutants.out/unviable.txt
if [ -n "${FAKE_HANG:-}" ]; then
  # Block until a signal comes; record SIGINT and stop as cargo-mutants does.
  trap 'echo INT > signal; kill "$pid" 2> /dev/null; exit 130' INT
  tail -f /dev/null &
  pid=$!
  wait "$pid"
  exit 1
fi
exit "${FAKE_EXIT:-0}"
EOF
chmod +x "$tmp/bin/cargo"
PATH="$tmp/bin:$PATH"
tmo=/usr/bin/timeout # as ci/mutants.sh finds it
[ -x "$tmo" ] || tmo=timeout
n=0
fails=0
# case_ <name> <expected exit> <shard> <budget> <expected output lines, one
# per line> [VAR=value ... for the stand-in]. An outer timeout(1) stops a case
# whose budget is not enforced.
case_() {
  n=$((n + 1))
  local name=$1 want=$2 shard=$3 budget=$4 lines=$5 dir="$tmp/$n" rc=0 line
  shift 5
  mkdir "$dir"
  (cd "$dir" && env GITHUB_STEP_SUMMARY="$dir/summary" "$@" \
    "$tmo" 60 "$script" "$shard" "$budget" "$dir") > "$dir/out" 2>&1 || rc=$?
  local ok=1
  [ "$rc" = "$want" ] || ok=0
  while IFS= read -r line; do
    [ -z "$line" ] || grep -qxF -- "$line" "$dir/out" || { ok=0; echo "  missing line: $line"; }
  done <<< "$lines"
  if [ "$ok" = 1 ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want"
    sed 's/^/  | /' "$dir/out"
    fails=$((fails + 1))
  fi
}
m1='crates/keys/src/chunk.rs:42:12: replace < with <= in padme'
m2='crates/keys/src/phrase.rs:104:18: replace > with >= in Phrase::parse'
t1='crates/keys/src/records/groups.rs:198:36: replace + with - in WalkLevels::add'

case_ "every mutant caught" 0 3/16 180m \
  "== cargo-mutants shard 3/16: 3 caught, 0 missed, 0 timed out, 1 unviable
== every mutant of this shard was caught" \
  FAKE_CAUGHT='a\nb\nc\n' FAKE_UNVIABLE='d\n'
case_ "survivors are reported, not failing (phase 0)" 0 0/16 180m \
  "== cargo-mutants shard 0/16: 1 caught, 2 missed, 0 timed out, 0 unviable
== Surviving mutants (missed: the tests still pass with this change):
  $m1
  $m2
::notice title=cargo-mutants shard 0/16::2 missed, 0 timed out; reported, not failing, until the end of phase 0 (decision 2026-10-22)" \
  FAKE_EXIT=2 FAKE_CAUGHT='a\n' FAKE_MISSED="$m1\n$m2\n"
case_ "timeouts and survivors are reported, not failing (exit 3)" 0 15/16 180m \
  "== cargo-mutants shard 15/16: 0 caught, 1 missed, 1 timed out, 0 unviable
  $m1
== Mutants whose tests ran past 300 s (timeout):
  $t1" \
  FAKE_EXIT=3 FAKE_MISSED="$m1\n" FAKE_TIMEOUT="$t1\n"
case_ "the unmutated tree fails to build or test" 1 1/16 180m \
  "::error title=cargo-mutants shard 1/16::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log)" \
  FAKE_EXIT=4
case_ "a cargo-mutants usage error" 1 1/16 180m "" FAKE_EXIT=1
case_ "a cargo-mutants internal error" 1 1/16 180m \
  "::error title=cargo-mutants shard 1/16::cargo-mutants failed with exit 70" FAKE_EXIT=70
case_ "killed by a signal" 1 1/16 180m "" FAKE_EXIT=137
# The run of 2026-10-22 (39755196041) was cancelled at GitHub's 6 h job limit
# with nothing to say why; a shard past its budget fails with its findings so far.
case_ "the shard runs past its budget (run 39755196041)" 1 2/16 1s \
  "  $m1
::error title=cargo-mutants shard 2/16::stopped after 1s, before the shard finished: give mutants.yml more shards, or see the timeouts listed above" \
  FAKE_HANG=1 FAKE_MISSED="$m1\n"
case_ "k must be below n" 1 16/16 180m ""
case_ "a shard without n" 1 3 180m ""
case_ "a budget without a unit" 1 3/16 180 ""

# What reaches cargo-mutants, and what reaches the job summary.
if [ "$(cat "$tmp/1/args")" = "mutants --package licketysync-keys --package licketysync-protocol --package licketysync-index --package licketysync-engine --timeout 300 --no-shuffle --sharding round-robin --shard 3/16" ]; then
  echo "ok   cargo-mutants gets the four crates, the 300 s limit and the shard"
else
  echo "FAIL cargo-mutants arguments: $(cat "$tmp/1/args")"
  fails=$((fails + 1))
fi
if grep -qxF "### cargo-mutants shard 0/16" "$tmp/2/summary" && grep -qxF "$m2" "$tmp/2/summary"; then
  echo "ok   the job summary lists the survivors"
else
  echo "FAIL the job summary of case 2:"
  sed 's/^/  | /' "$tmp/2/summary" 2> /dev/null || true
  fails=$((fails + 1))
fi
# The budget stops cargo-mutants with SIGINT, which it handles by writing
# what it has; another signal would kill it without.
if [ "$(cat "$tmp/8/signal" 2> /dev/null)" = INT ]; then
  echo "ok   the budget stops cargo-mutants with SIGINT"
else
  echo "FAIL the budget did not stop cargo-mutants with SIGINT"
  fails=$((fails + 1))
fi
for c in 9 10 11; do
  if [ -e "$tmp/$c/args" ]; then
    echo "FAIL case $c ran cargo-mutants despite a bad argument"
    fails=$((fails + 1))
  fi
done

if [ "$fails" -gt 0 ]; then
  echo "mutants: $fails failing case(s)"
  exit 1
fi
echo "mutants: all $n cases and the argument checks pass"
