#!/usr/bin/env bash
# Tests for ci/mutants.sh with a stand-in `cargo` and `rustc` first on PATH.
# The stand-in rustc names the case's host. The stand-in cargo records its
# arguments and, for the run, the runner variables it is given; it prints the
# case's list for `--list`; for the run it writes the outcome files the case
# gives it into mutants.out/ and exits with the case's code, or blocks until a
# signal comes and records SIGINT, or, as cargo-mutants does, times the
# unmutated tree's tests by its arguments, or runs the unmutated tree's tests
# and then each mutant's (a stand-in test process, `hog`, that asks for a
# little less or a little more than a cap; a test binary's or a doc-test's)
# through the host's runner, logs them as cargo-mutants, cargo and rustdoc do,
# and counts the mutant caught or missed. The expected exit code and the
# expected lines of output are the assertions. Needs python3 and prlimit
# (util-linux). Run by gate.sh, ci.yml and mutants.yml. Exit 1 if any case
# fails.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/mutants.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
# The runner variables come only from ci/mutants.sh.
unset "${!CARGO_TARGET_@}"
cat > "$tmp/bin/rustc" << 'EOF'
#!/usr/bin/env bash
[ -z "${FAKE_RUSTC_EXIT:-}" ] || exit "$FAKE_RUSTC_EXIT"
printf 'rustc 1.99.1 (stand-in)\nhost: %s\n' "${FAKE_HOST:-x86_64-unknown-linux-gnu}"
EOF
cat > "$tmp/bin/cargo" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> args
if [ "$2" = --list ]; then
  printf '%b' "${FAKE_LIST:-}"
  exit "${FAKE_LIST_EXIT:-0}"
fi
# The runner cargo starts test binaries through: the variable of its host's
# target (the stand-in rustc's host), as cargo reads it. Every runner
# variable set is recorded.
host=${FAKE_HOST:-x86_64-unknown-linux-gnu}
var=${host^^}
var=CARGO_TARGET_${var//[-.]/_}_RUNNER
runner=${!var-}
env | grep -E '^CARGO_TARGET_[A-Z0-9_]+_RUNNER=' > runner
mkdir -p mutants.out/log
printf '%b' "${FAKE_CAUGHT:-}" > mutants.out/caught.txt
printf '%b' "${FAKE_MISSED:-}" > mutants.out/missed.txt
printf '%b' "${FAKE_TIMEOUT:-}" > mutants.out/timeout.txt
printf '%b' "${FAKE_UNVIABLE:-}" > mutants.out/unviable.txt
if [ -n "${FAKE_BASELINE:-}" ]; then
  # The unmutated tree's tests take FAKE_BASELINE seconds (none pass: the
  # stand-in reckons). As cargo-mutants 27.1.0 times them (src/timeouts.rs):
  # an explicit --timeout limits them too, and when they run past it no mutant
  # is tested (exit 4); each mutant's limit is that --timeout, or else their
  # time times --timeout-multiplier (5 by default), rounded up, at least
  # --minimum-test-timeout (20 s by default), which cargo-mutants logs.
  explicit='' multiplier=5 floor=20
  while [ $# -gt 0 ]; do
    case $1 in
      --timeout) explicit=$2 ;;
      --timeout-multiplier) multiplier=$2 ;;
      --minimum-test-timeout) floor=$2 ;;
    esac
    shift
  done
  if [ -n "$explicit" ] && [ "$FAKE_BASELINE" -gt "$explicit" ]; then
    echo "ERROR cargo test failed in an unmutated tree, so no mutants were tested"
    exit 4
  fi
  [ -n "$explicit" ] || awk -v b="$FAKE_BASELINE" -v m="$multiplier" -v f="$floor" \
    'BEGIN { t = b * m; if (t > int(t)) t = int(t) + 1; if (t < f) t = f; print "INFO Auto-set test timeout to " t "s" }'
fi
if [ -n "${FAKE_HANG:-}" ]; then
  # Block until a signal comes; record SIGINT and stop as cargo-mutants does.
  trap 'echo INT > signal; kill "$pid" 2> /dev/null; exit 130' INT
  tail -f /dev/null &
  pid=$!
  wait "$pid"
  exit 1
fi
# A module named as Python's mmap, which would let every mapping pass, where
# the tests run.
[ -z "${FAKE_PLANT:-}" ] || printf 'MAP_PRIVATE = MAP_NORESERVE = 0\ndef mmap(*args, **kwargs):\n    pass\n' > mmap.py
# run_tests <log> <test command>: append to the log a test command's output
# and, when it fails, the failure, and return its status. It runs through the
# runner, as cargo test starts a test binary and rustdoc a doc-test (the runner
# split on whitespace, as cargo splits it; nothing when unset). A failure ends
# the log as cargo 1.99 reports a test binary's: the signal (a shell's status
# 128 + n), named for SIGABRT but not for SIGXFSZ, or the exit status; or, for
# a command that starts with "doc ", as rustdoc 1.99 reports a doc-test's,
# the signal by number and name.
run_tests() {
  local log=$1 test=$2 doc='' rc=0 why
  if [ "${test%% *}" = doc ]; then
    doc=1
    test=${test#doc }
  fi
  # shellcheck disable=SC2086 # split on purpose, as cargo splits them
  $runner $test >> "$log" 2>&1 || rc=$?
  if [ "$rc" = 0 ]; then
    return 0
  elif [ -n "$doc" ]; then
    why="exit status: $rc"
    [ "$rc" -le 128 ] || why="signal: $((rc - 128)) (SIG$(kill -l "$rc"))"
    echo "Test executable failed ($why)." >> "$log"
  else
    if [ "$rc" = 134 ]; then
      why="signal: 6, SIGABRT: process abort signal"
    elif [ "$rc" -gt 128 ]; then
      why="signal: $((rc - 128))"
    else
      why="exit status: $rc"
    fi
    echo "  process didn't exit successfully: \`$runner $test\` ($why)" >> "$log"
  fi
  return "$rc"
}
if [ -n "${FAKE_BASELINE_TESTS:-}" ]; then
  # The unmutated tree's tests, a test command a line, each run whether or not
  # the one before failed (as rustdoc runs every doc-test), logged as
  # cargo-mutants does (baseline.log, its first line "*** baseline"); when any
  # fails, no mutant is tested.
  printf '\n*** baseline\n' > mutants.out/log/baseline.log
  failed=0
  while IFS= read -r test; do
    run_tests mutants.out/log/baseline.log "$test" || failed=1
  done <<< "$FAKE_BASELINE_TESTS"
  if [ "$failed" = 1 ]; then
    echo "ERROR cargo test failed in an unmutated tree, so no mutants were tested"
    exit 4
  fi
fi
if [ -n "${FAKE_TESTS:-}" ]; then
  # Each line is <mutant>|<its test command>. As cargo-mutants does: start the
  # mutant's log (mutants.out/log/, its first line "*** <mutant>"), run the
  # mutant's tests into it, and count the mutant caught when they fail, missed
  # when they pass.
  code=0
  n=0
  while IFS='|' read -r mutant test; do
    n=$((n + 1))
    log=mutants.out/log/$n.log
    printf '\n*** %s\n' "$mutant" > "$log"
    if run_tests "$log" "$test"; then
      echo "$mutant" >> mutants.out/missed.txt
      code=2
    else
      echo "$mutant" >> mutants.out/caught.txt
    fi
  done <<< "$FAKE_TESTS"
  exit "$code"
fi
exit "${FAKE_EXIT:-0}"
EOF
# A stand-in test process, its Python run with -I (as ci/check-netlog.py is):
# `hog memory <bytes>` maps that much private writable memory, which counts
# against the data cap, without touching it (MAP_NORESERVE: no memory is used;
# by its value on x86_64 and aarch64 Linux, 0x4000, where Python lacks the
# name, as 3.12 does); `hog file <bytes>` makes a sparse file of that size (no
# disk is used), which the file-size cap bounds. Past a cap it fails as a Rust
# test binary does: for memory, Rust's message and an abort (SIGABRT, status
# 134 to a shell); for the file, the status of a death by SIGXFSZ (153), which
# Python ignores, getting EFBIG instead.
cat > "$tmp/bin/hog" << 'EOF'
#!/usr/bin/env bash
exec python3 -I - "$@" << 'PY'
import mmap
import os
import sys

kind, size = sys.argv[1], int(sys.argv[2])
if kind == "memory":
    try:
        mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | getattr(mmap, "MAP_NORESERVE", 0x4000))
    except OSError:
        print(f"memory allocation of {size} bytes failed", file=sys.stderr)
        sys.exit(134)
else:
    code = 0
    with open("sparse", "wb") as f:
        try:
            f.truncate(size)
        except OSError:
            code = 153
    os.remove("sparse")
    sys.exit(code)
PY
EOF
chmod +x "$tmp/bin/cargo" "$tmp/bin/rustc" "$tmp/bin/hog"
PATH="$tmp/bin:$PATH"
tmo=/usr/bin/timeout # as ci/mutants.sh finds it
[ -x "$tmo" ] || tmo=timeout
n=0
fails=0
# case_ <name> <expected exit> <shard> <budget> <expected output lines, one
# per line> [VAR=value ... for the stand-ins]. An outer timeout(1) stops a case
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
== Mutants whose tests ran past their limit (timeout):
  $t1" \
  FAKE_EXIT=3 FAKE_MISSED="$m1\n" FAKE_TIMEOUT="$t1\n"
case_ "the unmutated tree fails to build or test" 1 1/16 180m \
  "::error title=cargo-mutants shard 1/16::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log)" \
  FAKE_BASELINE_TESTS=false
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
# Runs 40112234775, 41225873013 and 42399213062 lost 3 to 5 shards each to a
# mutant whose tests allocated until the runner died. Under the caps such a
# test process fails, and its mutant is caught and counted as stopped by a
# cap; one just under a cap passes; one that fails an assertion is caught but
# not by a cap.
caps="prlimit --data=6442450944 --fsize=1073741824 --core=0 --"
r1='crates/protocol/src/connection/mod.rs:934:13: replace < with > in Connection::has_room'
r2='crates/engine/src/stand_in.rs:1:1: a mutant whose tests write a file of 1 GiB and 1 byte'
c1='crates/index/src/trie.rs:80:9: replace Trie::len -> usize with 0'
case_ "a test process past a cap fails, its mutant caught by a cap (run 42399213062)" 0 7/16 180m \
  "== each test process runs under: $caps
== cargo-mutants shard 7/16: 3 caught, 2 missed, 0 timed out, 0 unviable
== 2 of the caught were stopped by a cap (memory or file size)
== Surviving mutants (missed: the tests still pass with this change):
  $m1
  $m2
::notice title=cargo-mutants shard 7/16::2 missed, 0 timed out; reported, not failing, until the end of phase 0 (decision 2026-10-22)" \
  FAKE_TESTS="$r1|hog memory $((6442450944 + (64 << 20)))
$m1|hog memory $((6442450944 - (256 << 20)))
$r2|hog file 1073741825
$m2|hog file 1073741824
$c1|false"
case_ "the shard's mutants are listed, numbered, before the run" 0 4/16 180m \
  "::group::The mutants of shard 4/16, in the order they are tested
    1  $m1
    2  $t1
::endgroup::
== every mutant of this shard was caught" \
  FAKE_LIST="$m1\n$t1\n"
case_ "cargo-mutants cannot list the mutants" 1 4/16 180m \
  "::error title=cargo-mutants shard 4/16::cargo-mutants could not list the mutants (exit 1)" \
  FAKE_LIST_EXIT=1
# The caps follow the host's target, on any Linux; elsewhere there is no
# prlimit, and the log says the tests run uncapped.
case_ "an aarch64 Linux host has the caps too" 0 5/16 180m \
  "== each test process runs under: $caps
== cargo-mutants shard 5/16: 1 caught, 0 missed, 0 timed out, 0 unviable
== 1 of the caught were stopped by a cap (memory or file size)
== every mutant of this shard was caught" \
  FAKE_HOST=aarch64-unknown-linux-gnu FAKE_TESTS="$r1|hog memory $((6442450944 + (64 << 20)))"
case_ "a macOS host runs the tests uncapped, and says so" 0 5/16 180m \
  "== the test processes run uncapped: prlimit is Linux only, and the host is aarch64-apple-darwin
== every mutant of this shard was caught" \
  FAKE_HOST=aarch64-apple-darwin
case_ "rustc cannot name the host" 1 5/16 180m \
  "::error title=cargo-mutants shard 5/16::rustc -vV did not name the host, so the test processes cannot be capped" \
  FAKE_RUSTC_EXIT=1
# cargo-mutants gives an explicit --timeout to the unmutated tree's tests too;
# those of 2026-11-07 took 143 to 295 s against the 300 s it was then.
case_ "the unmutated tree's tests may take longer than 300 s" 0 6/16 180m \
  "INFO Auto-set test timeout to 800s
== every mutant of this shard was caught" \
  FAKE_BASELINE=400
case_ "a mutant's tests still have at least 300 s" 0 6/16 180m \
  "INFO Auto-set test timeout to 300s
== every mutant of this shard was caught" \
  FAKE_BASELINE=143
case_ "the budget runs out before any mutant is tested" 1 2/16 1s \
  "== cargo-mutants shard 2/16: 0 caught, 0 missed, 0 timed out, 0 unviable
::error title=cargo-mutants shard 2/16::stopped after 1s before any mutant was tested: the unmutated tree's build and tests, which have no time limit but this budget, took it all, or all but what the first mutant used (mutants.out/log/)" \
  FAKE_HANG=1
case_ "a module where the tests run cannot replace Python's own (python3 -I)" 0 8/16 180m \
  "== cargo-mutants shard 8/16: 1 caught, 0 missed, 0 timed out, 0 unviable
== 1 of the caught were stopped by a cap (memory or file size)" \
  FAKE_PLANT=1 FAKE_TESTS="$r1|hog memory $((6442450944 + (64 << 20)))"
# rustdoc reports a doc-test killed by SIGXFSZ by the signal's name as well
# as its number (cargo, by the number only); both count.
r3='crates/keys/src/stand_in.rs:1:1: a mutant whose doc-test writes a file of 1 GiB and 1 byte'
case_ "a doc-test past a cap: its mutant caught by a cap" 0 9/16 180m \
  "== cargo-mutants shard 9/16: 2 caught, 0 missed, 0 timed out, 0 unviable
== 2 of the caught were stopped by a cap (memory or file size)" \
  FAKE_TESTS="$r3|doc hog file 1073741825
$r1|doc hog memory $((6442450944 + (64 << 20)))"
# Only caught mutants count: a passing test process can print the sign (a
# test of the message itself), and the baseline's log can carry it (below).
case_ "a missed mutant whose log carries a cap's sign is not counted" 0 10/16 180m \
  "== cargo-mutants shard 10/16: 1 caught, 1 missed, 0 timed out, 0 unviable
== 0 of the caught were stopped by a cap (memory or file size)" \
  FAKE_TESTS="$m1|echo memory allocation of 8 bytes failed
$c1|false"
# A test process of the unmutated tree past a cap fails it like any failing
# test; the error names the cap.
case_ "the unmutated tree's tests past the data cap: the error names it" 1 11/16 180m \
  "== cargo-mutants shard 11/16: 0 caught, 0 missed, 0 timed out, 0 unviable
== 0 of the caught were stopped by a cap (memory or file size)
::error title=cargo-mutants shard 11/16::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log); a test process of the unmutated tree went past the data cap (6 GiB), set in ci/mutants.sh" \
  FAKE_BASELINE_TESTS="hog memory $((6442450944 + (64 << 20)))"
case_ "the unmutated tree's tests past the file cap: the error names it" 1 12/16 180m \
  "::error title=cargo-mutants shard 12/16::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log); a test process of the unmutated tree went past the file-size cap (1 GiB), set in ci/mutants.sh" \
  FAKE_BASELINE_TESTS="hog file 1073741825"
case_ "the unmutated tree's doc-tests past both caps: the error names both" 1 13/16 180m \
  "::error title=cargo-mutants shard 13/16::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log); a test process of the unmutated tree went past the data cap (6 GiB) and the file-size cap (1 GiB), set in ci/mutants.sh" \
  FAKE_BASELINE_TESTS="doc hog memory $((6442450944 + (64 << 20)))
doc hog file 1073741825"

# What reaches cargo-mutants, and what reaches the job summary.
picked="--package licketysync-keys --package licketysync-protocol --package licketysync-index --package licketysync-engine --no-shuffle --sharding round-robin --shard 3/16"
if [ "$(cat "$tmp/1/args")" = "mutants --list $picked"$'\n'"mutants $picked --timeout-multiplier 2 --minimum-test-timeout 300 --caught --unviable" ]; then
  echo "ok   cargo-mutants lists, then tests, the four crates' shard, each mutant's limit twice the baseline's, at least 300 s, and every outcome printed"
else
  echo "FAIL cargo-mutants arguments:"
  sed 's/^/  | /' "$tmp/1/args"
  fails=$((fails + 1))
fi
if [ "$(cat "$tmp/1/runner")" = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=$caps" ]; then
  echo "ok   cargo runs the test processes under the caps"
else
  echo "FAIL the runner cargo gets: $(cat "$tmp/1/runner")"
  fails=$((fails + 1))
fi
if [ "$(cat "$tmp/12/mutants.out/caught.txt")" = "$r1"$'\n'"$r2"$'\n'"$c1" ]; then
  echo "ok   the mutants caught are the two whose test processes went past a cap and the one that failed"
else
  echo "FAIL the mutants caught in case 12:"
  sed 's/^/  | /' "$tmp/12/mutants.out/caught.txt"
  fails=$((fails + 1))
fi
if grep -qxF "3 caught, 2 missed, 0 timed out, 0 unviable (exit 2); 2 of the caught were stopped by a cap (memory or file size)." "$tmp/12/summary"; then
  echo "ok   the job summary counts the mutants stopped by a cap"
else
  echo "FAIL the job summary of case 12:"
  sed 's/^/  | /' "$tmp/12/summary" 2> /dev/null || true
  fails=$((fails + 1))
fi
if [ "$(grep -c . "$tmp/14/args")" = 1 ] && [ ! -e "$tmp/14/runner" ]; then
  echo "ok   no run when the listing fails"
else
  echo "FAIL case 14 ran cargo-mutants after the listing failed"
  fails=$((fails + 1))
fi
if [ "$(cat "$tmp/15/runner")" = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=$caps" ]; then
  echo "ok   on aarch64 Linux the caps are that target's runner"
else
  echo "FAIL the runner cargo gets on aarch64 Linux: $(cat "$tmp/15/runner")"
  fails=$((fails + 1))
fi
if [ ! -s "$tmp/16/runner" ] && ! grep -q "runs under\|by a cap" "$tmp/16/out" \
  && grep -qxF "0 caught, 0 missed, 0 timed out, 0 unviable (exit 0)." "$tmp/16/summary"; then
  echo "ok   on macOS no runner is set and nothing is said of caps"
else
  echo "FAIL case 16 set a runner or spoke of caps:"
  sed 's/^/  | /' "$tmp/16/runner" "$tmp/16/out" "$tmp/16/summary" 2> /dev/null || true
  fails=$((fails + 1))
fi
if [ ! -e "$tmp/17/args" ]; then
  echo "ok   no listing or run when rustc cannot name the host"
else
  echo "FAIL case 17 ran cargo-mutants without knowing the host"
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
