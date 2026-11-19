#!/usr/bin/env bash
# Tests for ci/repeat-races.sh with a stand-in `cargo` and `uname` first on
# PATH. The stand-in cargo builds nothing, lists the case's tests for each
# package (`-- --list`), and passes each run but the one the case makes fail,
# recording every run it is asked for; the exit code, the runs asked for and
# the output are the assertions. Run by gate.sh and CI. Exit 1 if any case
# fails.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/repeat-races.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/cargo" << 'STUB'
#!/usr/bin/env bash
# FAKE_TESTS_DAEMON, FAKE_TESTS_FS: the test names each package's filter
# selects, space-separated; FAKE_CRLF: list them with CRLF line ends;
# FAKE_BUILD_FAILS, FAKE_LIST_FAILS: the package whose build or list fails;
# FAKE_FAIL_AT: the run (counted over every package) that fails; FAKE_RUNS:
# the file each run is recorded in, as "<package> <filter>".
args="$*"
pkg=$3
case $pkg in
  licketysync-daemon) tests=${FAKE_TESTS_DAEMON:-} ;;
  licketysync-fs) tests=${FAKE_TESTS_FS:-} ;;
  *) echo "stand-in cargo: unexpected package: $args" >&2; exit 99 ;;
esac
case $args in
  "test -p $pkg --lib --all-features --no-run")
    [ "${FAKE_BUILD_FAILS:-}" != "$pkg" ] || { echo "error: could not compile \`$pkg\`" >&2; exit 101; }
    ;;
  "test -p $pkg --lib --all-features -- --list "*)
    [ "${FAKE_LIST_FAILS:-}" != "$pkg" ] || { echo "error: test failed to list" >&2; exit 101; }
    echo "     Running unittests src/lib.rs" >&2
    end=$'\n'
    [ -z "${FAKE_CRLF:-}" ] || end=$'\r\n'
    case $args in
      *" --ignored "*)
        if [ "$pkg" = licketysync-daemon ]; then tests=${FAKE_IGNORED_DAEMON:-}; else tests=${FAKE_IGNORED_FS:-}; fi
        ;;
    esac
    n=0
    for t in $tests; do
      printf '%s: test%s' "$t" "$end"
      n=$((n + 1))
    done
    printf '%s%s tests, 0 benchmarks%s' "$end" "$n" "$end"
    ;;
  "test -p $pkg --lib --all-features -q -- "*)
    echo "$pkg ${args##* -- }" >> "$FAKE_RUNS"
    if [ "$(wc -l < "$FAKE_RUNS")" -eq "${FAKE_FAIL_AT:-0}" ]; then
      echo "test ${tests%% *} ... FAILED (stand-in)"
      exit 101
    fi
    echo "test result: ok."
    ;;
  *) echo "stand-in cargo: unexpected arguments: $args" >&2; exit 99 ;;
esac
STUB
cat > "$tmp/bin/uname" << 'STUB'
#!/usr/bin/env bash
[ "$*" = -s ] || { echo "stand-in uname: unexpected arguments: $*" >&2; exit 99; }
echo "${FAKE_UNAME:-Linux}"
STUB
chmod +x "$tmp/bin/cargo" "$tmp/bin/uname"
PATH="$tmp/bin:$PATH"
daemon='store::tests::'
fs='resolver::tests::tm_4_symlink_then_directory_race'
store_tests='store::tests::a store::tests::b store::tests::crash::c'
race_test=$fs
n=0
fails=0
# case_ <name> <expected exit> <expected runs, "<package> <filter>" each, one
# per line, or ""> <text the output must hold, or ""> <runs argument...> --
# [VAR=value ... for the stand-ins]
case_() {
  n=$((n + 1))
  local name=$1 want=$2 runs=$3 says=$4 dir="$tmp/$n" rc=0 ok=1 args=()
  shift 4
  while [ "$1" != -- ]; do
    args+=("$1")
    shift
  done
  shift
  mkdir "$dir"
  : > "$dir/runs"
  env FAKE_RUNS="$dir/runs" FAKE_TESTS_DAEMON="$store_tests" FAKE_TESTS_FS="$race_test" "$@" \
    "$script" ${args[@]+"${args[@]}"} > "$dir/log" 2>&1 || rc=$?
  [ "$rc" = "$want" ] || ok=0
  [ "$(cat "$dir/runs")" = "$runs" ] || ok=0
  [ -z "$says" ] || grep -qF -- "$says" "$dir/log" || ok=0
  if [ "$ok" = 1 ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want; runs asked for:"
    sed 's/^/  > /' "$dir/runs"
    sed 's/^/  | /' "$dir/log"
    fails=$((fails + 1))
  fi
}
both="licketysync-daemon $daemon
licketysync-fs $fs"
case_ "every run passes" 0 "$both
$both
$both" "== 3 runs of the 4 passed (" 3 --
# CI run 43753618314 (Windows) and the nightly's 6 of 150 (bf95139): a race
# fails some runs, and a retry or one more pass would hide it.
case_ "the first failing run stops the loop, with no retry" 1 "$both
$both" "run 2 of 5 failed: licketysync-fs, $fs" 5 -- FAKE_FAIL_AT=4
case_ "the failing run's output is shown" 1 "licketysync-daemon $daemon" \
  "test store::tests::a ... FAILED (stand-in)" 5 -- FAKE_FAIL_AT=1
case_ "a build that fails stops before any run" 101 "" "" 5 -- FAKE_BUILD_FAILS=licketysync-fs
case_ "a list that fails stops before any run" 1 "" "cannot list the tests of licketysync-daemon" 5 -- \
  FAKE_LIST_FAILS=licketysync-daemon
# A renamed test must not drop out of the loop unnoticed.
case_ "the store's filter selecting no test fails" 1 "" \
  "licketysync-daemon: \`$daemon\` selects no test; ci/repeat-races.sh must name tests that exist" 5 -- \
  FAKE_TESTS_DAEMON=
case_ "the fs race selecting no test on Linux fails" 1 "" \
  "licketysync-fs: \`$fs\` selects no test; ci/repeat-races.sh must name tests that exist" 5 -- \
  FAKE_TESTS_FS=
# `--list` shows an ignored test as it does any other; `cargo test` runs none.
case_ "a filter whose tests are all ignored fails" 1 "" \
  "licketysync-daemon: \`$daemon\` selects no test; ci/repeat-races.sh must name tests that exist" 5 -- \
  FAKE_IGNORED_DAEMON="$store_tests"
case_ "ignored tests are not counted, the others are" 0 "$both" \
  "== licketysync-daemon: \`$daemon\` selects 2" 1 -- FAKE_IGNORED_DAEMON=store::tests::c
case_ "on macOS, the Linux-only race is left out and the store's run" 0 "licketysync-daemon $daemon
licketysync-daemon $daemon" "== licketysync-fs: \`$fs\` selects no test here (linux only)" 2 -- \
  FAKE_TESTS_FS= FAKE_UNAME=Darwin
case_ "on Windows (Git Bash), likewise" 0 "licketysync-daemon $daemon" \
  "== 1 runs of the 3 passed (" 1 -- FAKE_TESTS_FS= FAKE_UNAME=MINGW64_NT-10.0-20348
case_ "a list with CRLF line ends, as on Windows, counts its tests" 0 "$both" \
  "== licketysync-daemon: \`$daemon\` selects 3" 1 -- FAKE_CRLF=1
case_ "the store's filter selecting none on macOS still fails" 1 "" \
  "licketysync-daemon: \`$daemon\` selects no test; ci/repeat-races.sh must name tests that exist" 1 -- \
  FAKE_TESTS_DAEMON= FAKE_UNAME=Darwin
case_ "no runs argument" 2 "" "" --
case_ "zero runs" 2 "" "" 0 --
case_ "a runs argument that is not a number" 2 "" "" 5x --
case_ "10000 runs" 2 "" "" 10000 --
case_ "three arguments" 2 "" "" 5 . . --
if [ "$fails" -gt 0 ]; then
  echo "repeat-races: $fails failing case(s)"
  exit 1
fi
echo "repeat-races: all $n cases pass"
