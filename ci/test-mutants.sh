#!/usr/bin/env bash
# Tests for ci/mutants.sh with a stand-in `cargo` and `rustc` first on PATH.
# The stand-in rustc names the case's host. The stand-in cargo records its
# arguments, the rustc wrapper it is given (ci/rustc-wrapper.sh's) and, for
# the run, the runner variables it is given; it prints the case's list for
# `--list`; for the run it writes the outcome files the case
# gives it into mutants.out/ and exits with the case's code, or blocks until a
# signal comes and records SIGINT, or, as cargo-mutants does, times the
# unmutated tree's tests by its arguments, or runs the unmutated tree's tests
# and then each mutant's (a stand-in test process, `hog`, that asks for a
# little less or a little more than a cap; a test binary's or a doc-test's)
# through the host's runner, logs them as cargo-mutants, cargo and rustdoc do,
# and counts the mutant caught or missed. For the listing and the run alike it
# records whether cargo-mutants 27.1.0 would cap the lints, by its rules: a
# --cap-lints on its command line, else cap_lints in its config file (the
# workspace root's .cargo/mutants.toml, where ci/mutants.sh runs it, unless
# --no-config or --config says otherwise). Each case's repository root gets a
# copy of this repository's .cargo/mutants.toml, as the real one has it. The
# expected exit code and the expected lines of output are the assertions.
#
# Each case starts ci/mutants.sh as a CI step does, whatever this suite
# inherited: no signal ignored or blocked, no descriptor open but stdin,
# stdout and stderr (as_ci, below). When it ends, any process it started that
# is still running is killed and fails the case; the EXIT trap kills those of
# the case running when the suite stops. Last, the suite runs itself: once
# with SIGINT ignored, SIGTERM blocked and under two locks, to check that it
# still passes, leaves no process running and frees both locks; and three
# times stopped by a signal while a case blocks.
# Needs python3 (3.11 or later, for tomllib), prlimit and flock (util-linux),
# and Linux's /proc. Run by gate.sh, ci.yml and mutants.yml. Exit 1 if any
# case fails.
set -euo pipefail
# The stand-in cargo reads TOML with Python's tomllib, new in 3.11.
if ! python3 -I -c 'import tomllib' 2> /dev/null; then
  echo "ci/test-mutants.sh needs python3 3.11 or later, for tomllib;" \
    "python3 --version says: $(python3 --version 2>&1 || true)" >&2
  exit 1
fi
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
script="$(cd "$(dirname "$0")" && pwd)/mutants.sh"
# The configuration ci/mutants.sh's cargo-mutants reads, which each case gets.
config="$(cd "$(dirname "$0")/.." && pwd)/.cargo/mutants.toml"

# survivors <NAME=value>: kill every process of this user whose environment
# holds that variable, and print each once, as "  <pid> <command line>". Each
# case's processes carry a variable of their own (case_ below), which they keep
# whatever process group they move to: timeout(1) moves to one of its own, so
# the outer timeout's signal to its group never reaches the inner timeout of
# ci/mutants.sh or the stand-ins. Each pass stops (SIGSTOP) every process it
# finds, so that none forks again, then kills them (SIGKILL); neither signal
# can be caught, blocked or ignored. A child forked before its parent stopped
# is found by the next pass. Passes repeat until one finds none, at most 50;
# past that, a last line says so.
survivors() {
  local file pid pass
  local -a found
  local -A seen=()
  for ((pass = 1; pass <= 50; pass++)); do
    found=()
    while IFS= read -r file; do
      pid=${file#/proc/}
      found+=("${pid%/environ}")
    done < <(grep -lxzF -- "$1" /proc/[0-9]*/environ 2> /dev/null || true)
    [ "${#found[@]}" -gt 0 ] || return 0
    kill -STOP "${found[@]}" 2> /dev/null || true
    for pid in "${found[@]}"; do
      [ -n "${seen[$pid]:-}" ] || echo "  $pid $(tr '\0' ' ' 2> /dev/null < "/proc/$pid/cmdline")"
      seen[$pid]=1
    done
    kill -KILL "${found[@]}" 2> /dev/null || true
  done
  echo "  (still finding processes after 50 passes)"
}
tmp=$(mktemp -d)
# The variable (NAME=value) that marks the processes running now, a case's or
# those of a test below, which the cleanup kills.
running=
cleanup() {
  [ -z "$running" ] || survivors "$running" > /dev/null
  running=
  rm -rf "$tmp"
}
# Stopped by SIGHUP, SIGINT or SIGTERM, bash (5.2 and 5.3, measured) runs this
# EXIT trap too, then ends by that signal, so that its caller sees why; a
# signal ignored on entry stays ignored. The stop tests below check it.
trap cleanup EXIT
mkdir "$tmp/bin"
# The runner variables come only from ci/mutants.sh, and so does the rustc
# wrapper (ci/rustc-wrapper.sh, which it sources): each case runs with
# LICKETYSYNC_SCCACHE=0, but for the two of sccache's.
unset "${!CARGO_TARGET_@}" "${!SCCACHE_@}" RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER LICKETYSYNC_SCCACHE \
  CARGO_INCREMENTAL CI
cat > "$tmp/bin/rustc" << 'EOF'
#!/usr/bin/env bash
[ -z "${FAKE_RUSTC_EXIT:-}" ] || exit "$FAKE_RUSTC_EXIT"
printf 'rustc 1.99.1 (stand-in)\nhost: %s\n' "${FAKE_HOST:-x86_64-unknown-linux-gnu}"
EOF
cat > "$tmp/bin/cargo" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> args
printf '%s\n' "${RUSTC_WRAPPER-unset}" >> wrapper
# Whether cargo-mutants 27.1.0 caps the lints (src/main.rs, src/options.rs,
# src/config.rs). It reads its config file first, whatever the command line
# says of the cap: the file --config names, none with --no-config, or else
# .cargo/mutants.toml of the workspace root (here, the directory it runs in),
# which may be absent. A --config file that is missing stops it (exit 1),
# recorded here as "error"; so does a file that is not TOML, holds a key it
# does not know (its Config is deny_unknown_fields) or a cap_lints that is not
# a boolean, recorded as "invalid". The types of its other keys are not
# checked here. Then --cap-lints <bool> or --cap-lints=<bool> on its command
# line wins over cap_lints in the file, which is false when absent.
cap='' file=.cargo/mutants.toml named=''
for ((i = 1; i <= $#; i++)); do
  a=${!i} j=$((i + 1))
  case $a in
    --cap-lints) cap=${!j-} ;;
    --cap-lints=*) cap=${a#*=} ;;
    --no-config) file='' ;;
    --config) file=${!j-} named=1 ;;
    --config=*) file=${a#*=} named=1 ;;
  esac
done
in_file=false
if [ -n "$named" ] && [ ! -f "$file" ]; then
  in_file=error
elif [ -n "$file" ] && [ -e "$file" ]; then
  # Config's fields (src/config.rs) and those serde reads of the Common it
  # flattens (src/options.rs), in cargo-mutants 27.1.0.
  in_file=$(python3 -I -c '
import sys, tomllib
known = {
    "additional_cargo_args", "additional_cargo_test_args", "all_features",
    "build_timeout_multiplier", "cap_lints", "copy_vcs", "copy_target",
    "error_values", "examine_globs", "examine_re", "exclude_globs", "exclude_re",
    "gitignore", "features", "minimum_test_timeout", "no_default_features",
    "output", "profile", "skip_calls", "skip_calls_defaults", "test_package",
    "test_workspace", "timeout_multiplier", "test_tool", "sharding",
}
try:
    with open(sys.argv[1], "rb") as f:
        c = tomllib.load(f)
except (OSError, ValueError):
    c = None
v = None if c is None or set(c) - known else c.get("cap_lints", False)
print(("false", "true")[v] if isinstance(v, bool) else "invalid")
' "$file")
fi
case $in_file in
  true | false) ;;
  *)
    echo "cap_lints=$in_file" >> lints
    echo "Error: the config file $file: $in_file" >&2
    exit 1
    ;;
esac
cap=${cap:-$in_file}
echo "cap_lints=$cap" >> lints
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
  # What it inherited: the signals ignored and blocked, and the descriptors
  # open, read by grep and ls (bash's own status would show its own traps);
  # 3 is ls's own, open on /proc/self/fd.
  grep -E '^Sig(Blk|Ign):' /proc/self/status > inherited
  ls /proc/self/fd >> inherited
  # Block until a signal comes; record SIGINT and stop as cargo-mutants does,
  # its child ended first (its status recorded). bash cannot trap a signal
  # that was ignored when it started, while cargo-mutants handles SIGINT
  # whatever it inherited, so as_ci starts each case with no signal ignored.
  trap 'echo INT > signal; kill "$pid" 2> /dev/null; wait "$pid"; echo "$?" > child; exit 130' INT
  tail -f /dev/null &
  pid=$!
  # Say where it blocks, on the fifo FAKE_READY names (the stop tests below).
  [ -z "${FAKE_READY:-}" ] || echo "$PWD" > "$FAKE_READY"
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
# python3 -I -c "$as_ci" <command>: run the command as a CI step starts one,
# with no signal ignored or blocked and no descriptor open but stdin, stdout
# and stderr, whatever this suite inherited (Python's own ignored SIGPIPE and
# SIGXFSZ included). A caller that ignores SIGINT (a background job of a
# script does, and passes it on) would leave the budget's SIGINT to a stand-in
# that cannot trap it; a descriptor inherited from a plain flock holds its lock
# while any process of the case is alive.
as_ci='
import os, signal, sys
for s in signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP}:
    if signal.getsignal(s) == signal.SIG_IGN:
        signal.signal(s, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_SETMASK, ())
os.closerange(3, os.sysconf("SC_OPEN_MAX"))
os.execvp(sys.argv[1], sys.argv[1:])
'
# python3 -I -c "$caller" <command>: run the command as the caller of
# 2026-11-14 below: SIGINT ignored (a background job of a script ignores it)
# and SIGTERM blocked, Python's own ignored SIGPIPE and SIGXFSZ back to their
# defaults. The check of as_ci and the run of this suite by itself use it.
caller='
import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_IGN)
for s in signal.SIGPIPE, signal.SIGXFSZ:
    signal.signal(s, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.execvp(sys.argv[1], sys.argv[1:])
'
n=0
fails=0
# case_ <name> <expected exit> <shard> <budget> <expected output lines, one
# per line> [VAR=value ... for the stand-ins]. An outer timeout(1) stops a case
# whose budget is not enforced. The case's repository root gets a copy of
# this repository's .cargo/mutants.toml, when there is one. Its processes
# carry LICKETYSYNC_TEST_MUTANTS_CASE=<its directory>; those still running
# when it ends are killed and fail it. It runs in the background so that a
# signal to the suite interrupts the wait at once, and the cleanup ends it.
case_() {
  n=$((n + 1))
  local name=$1 want=$2 shard=$3 budget=$4 lines=$5 dir="$tmp/$n" rc=0 line left
  shift 5
  mkdir "$dir"
  if [ -f "$config" ]; then
    mkdir "$dir/.cargo"
    cp "$config" "$dir/.cargo/mutants.toml"
  fi
  running="LICKETYSYNC_TEST_MUTANTS_CASE=$dir"
  (cd "$dir" && exec env GITHUB_STEP_SUMMARY="$dir/summary" LICKETYSYNC_SCCACHE=0 "$@" \
    LICKETYSYNC_TEST_MUTANTS_CASE="$dir" python3 -I -c "$as_ci" \
    "$tmo" 60 "$script" "$shard" "$budget" "$dir") > "$dir/out" 2>&1 &
  wait "$!" || rc=$?
  left=$(survivors "$running")
  running=
  local ok=1
  [ "$rc" = "$want" ] || ok=0
  while IFS= read -r line; do
    [ -z "$line" ] || grep -qxF -- "$line" "$dir/out" || { ok=0; echo "  missing line: $line"; }
  done <<< "$lines"
  if [ -n "$left" ]; then
    ok=0
    printf '  still running after ci/mutants.sh ended (now killed):\n%s\n' "$left"
  fi
  if [ "$ok" = 1 ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want"
    sed 's/^/  | /' "$dir/out"
    fails=$((fails + 1))
  fi
}
# LICKETYSYNC_TEST_MUTANTS_STOP=<fifo>: run one case only, whose stand-in
# blocks (its budget 30 m, the outer timeout 60 s) after naming its directory
# on the fifo; the stop tests below then stop this suite by a signal.
if [ -n "${LICKETYSYNC_TEST_MUTANTS_STOP:-}" ]; then
  case_ "a case that blocks until the suite is stopped" 1 2/16 30m "" \
    FAKE_HANG=1 FAKE_READY="$LICKETYSYNC_TEST_MUTANTS_STOP"
  exit 1
fi
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

# Builds go through sccache when it is installed, the listing's and the run's
# (ci/rustc-wrapper.sh), unless LICKETYSYNC_SCCACHE=0; a stand-in sccache is
# first on PATH, and its socket's directory under $tmp/xdg.
mkdir "$tmp/sccache-bin" "$tmp/cargo-home"
# The stand-in answers as a running server of its own version and cache would.
cat > "$tmp/sccache-bin/sccache" << 'EOF'
#!/bin/sh
case $1 in
  --version) echo "sccache 0.19.0" ;;
  --dist-status) echo '{"Disabled":"disabled"}' ;;
  --show-stats) printf '{"cache_location":"Local disk: \\"%s\\"","version":"0.19.0"}\n' "$SCCACHE_DIR" ;;
esac
EOF
chmod +x "$tmp/sccache-bin/sccache"
private="$tmp/xdg/licketysync/sccache"
case_ "with sccache installed, cargo-mutants builds through it" 0 1/16 180m \
  "== rustc wrapper: $tmp/sccache-bin/sccache, on its own server at $private/server.sock, its cache in $private/cache (LICKETYSYNC_SCCACHE=0 turns it off)" \
  PATH="$tmp/sccache-bin:$PATH" XDG_CACHE_HOME="$tmp/xdg" CARGO_HOME="$tmp/cargo-home" LICKETYSYNC_SCCACHE=
sccache_case=$n
case_ "LICKETYSYNC_SCCACHE=0: no wrapper" 0 1/16 180m "== rustc wrapper: none (LICKETYSYNC_SCCACHE=0)" \
  PATH="$tmp/sccache-bin:$PATH" XDG_CACHE_HOME="$tmp/xdg" CARGO_HOME="$tmp/cargo-home"

# The stand-in decides the lint cap as cargo-mutants 27.1.0 does, so that the
# check of case 1 below is not vacuous. Each row: what .cargo/mutants.toml
# holds (- for no file; \n between lines), the arguments after --list, and the
# cap expected; "invalid" and "error" also expect cargo-mutants to stop.
# other.toml sets cap_lints = true, empty.toml nothing, and missing.toml is
# not there.
lint_rows='-||false
cap_lints = true||true
cap_lints = false||false
cap_lints = true|--cap-lints false|false
cap_lints = true|--cap-lints=false|false
-|--cap-lints true|true
cap_lints = true|--no-config|false
-|--config other.toml|true
-|--config=other.toml|true
cap_lints = true|--config empty.toml|false
cap_lints = false|--config other.toml|true
cap_lints = true\ntest_tool = "cargo"\nsharding = "round-robin"||true
cap_lints = true\nbogus = 1||invalid
cap_lints = "yes"||invalid
cap_lints = "yes"|--cap-lints true|invalid
cap_lints = [||invalid
-|--config missing.toml|error'
k=0
lint_fails=$fails
while IFS='|' read -r content flags want; do
  k=$((k + 1))
  d="$tmp/lints-$k"
  mkdir -p "$d/.cargo"
  [ "$content" = - ] || printf '%b\n' "$content" > "$d/.cargo/mutants.toml"
  printf 'cap_lints = true\n' > "$d/other.toml"
  : > "$d/empty.toml"
  rc=0
  # shellcheck disable=SC2086 # the row's arguments, split on purpose
  (cd "$d" && cargo mutants --list $flags > /dev/null 2>&1) || rc=$?
  stops=0
  case $want in invalid | error) stops=1 ;; esac
  if [ "$(cat "$d/lints")" != "cap_lints=$want" ] || [ "$((rc != 0))" != "$stops" ]; then
    echo "FAIL the stand-in with [$content] and [$flags]: $(cat "$d/lints"), exit $rc;" \
      "expected cap_lints=$want"
    fails=$((fails + 1))
  fi
done <<< "$lint_rows"
if [ "$fails" = "$lint_fails" ]; then
  echo "ok   the stand-in decides the lint cap as cargo-mutants 27.1.0 does ($k rows)"
fi

# What reaches cargo-mutants, and what reaches the job summary.
picked="--package licketysync-keys --package licketysync-protocol --package licketysync-index --package licketysync-engine --no-shuffle --sharding round-robin --shard 3/16"
if [ "$(cat "$tmp/1/args")" = "mutants --list $picked"$'\n'"mutants $picked --timeout-multiplier 2 --minimum-test-timeout 300 --caught --unviable" ]; then
  echo "ok   cargo-mutants lists, then tests, the four crates' shard, each mutant's limit twice the baseline's, at least 300 s, and every outcome printed"
else
  echo "FAIL cargo-mutants arguments:"
  sed 's/^/  | /' "$tmp/1/args"
  fails=$((fails + 1))
fi
# Cargo.toml denies the dead_code and unused lints: without the cap, a mutant
# that only leaves something unused does not build and is counted unviable,
# never tested (.cargo/mutants.toml says more).
if [ "$(cat "$tmp/1/lints")" = "cap_lints=true"$'\n'"cap_lints=true" ]; then
  echo "ok   cargo-mutants caps the lints, for the listing and the run"
else
  echo "FAIL cargo-mutants does not cap the lints (cap_lints = true in .cargo/mutants.toml," \
    "or --cap-lints true from ci/mutants.sh):"
  sed 's/^/  | /' "$tmp/1/lints"
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
# The stand-in ends its child and waits for it before it stops, as
# cargo-mutants does; one that did not would leave its child running.
if [ "$(cat "$tmp/8/child" 2> /dev/null)" = 143 ]; then
  echo "ok   the stand-in cargo-mutants ends its child (SIGTERM, status 143) before it stops"
else
  echo "FAIL the stand-in cargo-mutants did not wait for its child: $(cat "$tmp/8/child" 2> /dev/null)"
  fails=$((fails + 1))
fi
# Each case starts as a CI step does (as_ci), whatever this suite inherited:
# no signal ignored or blocked, and no descriptor open but 0 to 2 (3 is ls's).
# The run of the suite with SIGINT ignored, SIGTERM blocked and a lock's
# descriptor inherited (below) checks this under all three.
inherited=$'SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n0\n1\n2\n3'
if [ "$(cat "$tmp/8/inherited" 2> /dev/null)" = "$inherited" ]; then
  echo "ok   the stand-in cargo-mutants inherits no signal ignored or blocked, and no descriptor but 0 to 2"
else
  echo "FAIL the stand-in cargo-mutants inherited signals ignored or blocked (masks in hex) or descriptors:"
  sed 's/^/  | /' "$tmp/8/inherited" 2> /dev/null || true
  fails=$((fails + 1))
fi
for c in 9 10 11; do
  if [ -e "$tmp/$c/args" ]; then
    echo "FAIL case $c ran cargo-mutants despite a bad argument"
    fails=$((fails + 1))
  fi
done

if [ "$(cat "$tmp/$sccache_case/wrapper")" = "$tmp/sccache-bin/sccache"$'\n'"$tmp/sccache-bin/sccache" ] &&
  [ "$(cat "$tmp/$((sccache_case + 1))/wrapper")" = $'unset\nunset' ] &&
  [ "$(cat "$tmp/1/wrapper")" = $'unset\nunset' ]; then
  echo "ok   the listing and the run build through sccache when it is installed, and not when LICKETYSYNC_SCCACHE=0" \
    "(as in every other case)"
else
  echo "FAIL the rustc wrapper cargo-mutants got, with sccache and then with LICKETYSYNC_SCCACHE=0:"
  cat "$tmp/$sccache_case/wrapper" "$tmp/$((sccache_case + 1))/wrapper" | sed 's/^/  | /'
  fails=$((fails + 1))
fi

# as_ci itself, under the caller with descriptor 7 open as well: what grep
# and ls see without it (SIGINT ignored, SIGTERM blocked, 7 open) and through
# it (nothing; 3 is ls's own). uutils' timeout clears the blocked signals of
# its child, GNU's does not, so the stand-in's check above sees a mask that
# as_ci left only where timeout(1) is GNU's, as in CI.
sees() { # sees <launcher...>: the masks and descriptors a command sees through it
  (exec 7< /dev/null && python3 -I -c "$caller" "$@" grep -E '^Sig(Blk|Ign):' /proc/self/status)
  (exec 7< /dev/null && python3 -I -c "$caller" "$@" ls /proc/self/fd)
}
bare=$(sees env)
clean=$(sees python3 -I -c "$as_ci")
blocked=$(sed -n 's/^SigBlk:\t//p' <<< "$bare")
ignored=$(sed -n 's/^SigIgn:\t//p' <<< "$bare")
if ! (((0x${blocked:-0} & 0x4000) && (0x${ignored:-0} & 0x2))) || ! grep -qx 7 <<< "$bare"; then
  echo "FAIL the caller did not ignore SIGINT, block SIGTERM and pass descriptor 7 on:"
  sed 's/^/  | /' <<< "$bare"
  fails=$((fails + 1))
elif [ "$clean" != "$inherited" ]; then
  echo "FAIL as_ci left signals ignored or blocked (masks in hex) or descriptors:"
  sed 's/^/  | /' <<< "$clean"
  fails=$((fails + 1))
else
  echo "ok   as_ci starts its command with no signal ignored or blocked and no descriptor but 0 to 2," \
    "under a caller that ignores SIGINT, blocks SIGTERM and passes a descriptor on"
fi

# survivors ends a marked tree that keeps forking: a bash that starts up to
# 1000 children as fast as it can, each blocked reading a fifo that no one
# writes, and has started the first when survivors begins. One scan misses the
# children started while it reads /proc; the passes, each stopping what it
# finds before it kills, leave none.
mark="LICKETYSYNC_TEST_MUTANTS_FORKS=$tmp"
mkfifo "$tmp/forking" "$tmp/blocked"
exec {forking}<> "$tmp/forking"
running=$mark
env "$mark" bash -c 'for ((i = 0; i < 1000; i++)); do
    cat <> "$2" &
    [ "$i" != 0 ] || echo started > "$1"
  done
  wait' _ "$tmp/forking" "$tmp/blocked" > /dev/null 2>&1 &
# Not a job of this shell, which would report its SIGKILL.
disown "$!"
started=
read -r -t 30 -u "$forking" started || true
exec {forking}<&-
survivors "$mark" > /dev/null
left=$(grep -lxzF -- "$mark" /proc/[0-9]*/environ 2> /dev/null || true)
survivors "$mark" > /dev/null
running=
if [ "$started" != started ]; then
  echo "FAIL the tree that keeps forking did not start within 30 s"
  fails=$((fails + 1))
elif [ -n "$left" ]; then
  echo "FAIL the kill of a case's processes left $(grep -c . <<< "$left") of a tree that keeps forking"
  fails=$((fails + 1))
else
  echo "ok   the kill of a case's processes ends a tree that keeps forking"
fi

if [ -n "${LICKETYSYNC_TEST_MUTANTS_NESTED:-}" ]; then
  echo "skipped: the runs of this suite by itself (LICKETYSYNC_TEST_MUTANTS_NESTED is set: this is one)"
else
  # The stand-ins left running on 2026-11-14: a run of this suite whose caller
  # ignored SIGINT left, in each case that waits for the budget's SIGINT,
  # timeout(1), the stand-in cargo-mutants and its child blocked for good, and
  # their inherited descriptor of the cargo lock kept it held for about 15
  # minutes. So the suite runs itself again as gate.sh runs it (a
  # non-interactive bash under `flock -o` on a lock), with SIGINT ignored and
  # SIGTERM blocked, inside a plain flock on a second lock whose descriptor its
  # processes inherit, as the cargo lock's was. It must pass, leave no process
  # running (its processes all carry LICKETYSYNC_TEST_MUTANTS_NESTED) and leave
  # both locks free. It runs in the background, so that the cleanup ends it
  # when this suite is stopped.
  running="LICKETYSYNC_TEST_MUTANTS_NESTED=$tmp"
  env "$running" python3 -I -c "$caller" \
    flock "$tmp/inherited.lock" flock -o "$tmp/gate.lock" "$self" > "$tmp/nested" 2>&1 &
  nested=0
  wait "$!" || nested=$?
  held=
  for lock in gate inherited; do
    flock -n "$tmp/$lock.lock" true || held="$held $lock.lock"
  done
  left=$(survivors "$running")
  running=
  bug="the stand-ins left running on 2026-11-14"
  if [ "$nested" = 0 ] && [ -z "$held" ] && [ -z "$left" ]; then
    echo "ok   run with SIGINT ignored, SIGTERM blocked and under two locks, the suite passes, leaves no" \
      "process running and frees both locks ($bug)"
  else
    echo "FAIL the suite run with SIGINT ignored, SIGTERM blocked and under two locks ($bug):" \
      "exit $nested${held:+; still held:$held}"
    [ -z "$left" ] || printf '  still running after it ended (now killed):\n%s\n' "$left"
    sed 's/^/  | /' "$tmp/nested"
    fails=$((fails + 1))
  fi

  # Stopped by SIGHUP, SIGINT or SIGTERM while a case blocks, the suite kills
  # that case's processes, removes its directory and ends by the signal (its
  # status 128 + the signal's number). Each run (in the stop mode above)
  # starts as a CI step does, so that no signal is ignored.
  for sig in HUP INT TERM; do
    mkfifo "$tmp/ready-$sig"
    exec {ready}<> "$tmp/ready-$sig"
    running="LICKETYSYNC_TEST_MUTANTS_NESTED=$tmp/stop-$sig"
    env "$running" LICKETYSYNC_TEST_MUTANTS_STOP="$tmp/ready-$sig" python3 -I -c "$as_ci" "$self" \
      > "$tmp/stop-$sig" 2>&1 &
    pid=$!
    dir=
    read -r -t 30 -u "$ready" dir || true
    exec {ready}<&-
    kill "-$sig" "$pid" 2> /dev/null || true
    rc=0
    # (bash reports on stderr a job that a signal ended)
    wait "$pid" 2> /dev/null || rc=$?
    left=$(survivors "$running")
    running=
    want=$((128 + $(kill -l "$sig")))
    if [ -n "$dir" ] && [ "$rc" = "$want" ] && [ -z "$left" ] && [ ! -e "$dir" ]; then
      echo "ok   stopped by SIG$sig while a case blocks, the suite ends that case's processes, removes its" \
        "files and ends by SIG$sig"
    else
      echo "FAIL stopped by SIG$sig while a case blocks (${dir:-none blocked within 30 s}): exit $rc," \
        "expected $want"
      [ -z "$left" ] || printf '  still running after it ended (now killed):\n%s\n' "$left"
      [ -z "$dir" ] || [ ! -e "$dir" ] || echo "  its case's directory is still there"
      sed 's/^/  | /' "$tmp/stop-$sig"
      fails=$((fails + 1))
    fi
  done
fi

if [ "$fails" -gt 0 ]; then
  echo "mutants: $fails failing case(s)"
  exit 1
fi
echo "mutants: all $n cases and the argument checks pass"
