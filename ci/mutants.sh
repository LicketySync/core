#!/usr/bin/env bash
# One shard of the weekly mutation test (mutants.yml):
# cargo-mutants over the crates the plan names (keys, protocol, engine) and the
# index crate, which TM-17, TM-40 and TM-41 name as their enforcer, shard
# <k>/<n> of their mutants dealt round-robin, stopped after <budget> (a
# duration as timeout(1) reads it, such as 180m). cargo-mutants first builds and
# tests the unmutated tree (its baseline), with no time limit but the budget,
# then each mutant of the shard with a limit on its tests of twice the
# baseline's test time, at least 300 s (below), and leaves mutants.out/ in the
# repository root, which the job uploads. Every build it runs, the unmutated
# tree's and each mutant's, caps rustc's lints at warn: cap_lints in
# .cargo/mutants.toml, which cargo-mutants reads from the repository root, here
# and in any run by hand, and which says why (a mutant that only leaves
# something unused is tested, not counted unviable). ci/test-mutants.sh checks
# that the listing and the run both get it. They build through sccache when it
# is installed (ci/rustc-wrapper.sh, sourced before the listing; CI installs
# none).
#
# On Linux every test process runs under caps on its memory and on the files
# it writes (below), so that a mutant whose tests grow without bound fails its
# own tests (caught) instead of taking the runner down. Before the run the log
# lists the shard's mutants, numbered in the order they are tested; during it,
# the outcome of each mutant as it ends, caught and unviable ones included. If
# a runner dies anyway, the mutant it was testing is the one after the last
# outcome in its log.
#
# Decision 2026-10-22 (phase 0): surviving mutants (missed: the tests still
# pass with the code broken) and mutants whose tests ran past their limit
# (timeout) are reported, not failing, until the end of phase 0, while the keys
# crate is reworked to the shared-key model; the rule is revisited then. A
# mutant killed by a cap is caught, like any whose tests fail, and the counts
# say about how many of the caught were. The script fails (exit 1) when rustc
# cannot name the host, when cargo-mutants cannot list the shard's mutants,
# when the unmutated tree does not build or its tests fail (cargo-mutants exit
# 4; naming the cap when a test process went past one), when the shard runs
# past <budget> (saying so apart when no mutant was tested yet), or when
# cargo-mutants stops on any other error (a usage or internal error, a
# signal). Every case after the listing first prints the counts and the
# surviving and timed-out mutants found so far, to the log and, on GitHub, to
# the job summary.
# Usage: ci/mutants.sh <k>/<n> <budget> [repo-root] (defaults to this
# repository). Tested by ci/test-mutants.sh, which gate.sh, ci.yml and
# mutants.yml run.
set -euo pipefail
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "usage: $0 <k>/<n> <budget, e.g. 180m> [repo-root]" >&2
  exit 1
fi
shard=$1
budget=$2
if ! [[ $shard =~ ^(0|[1-9][0-9]*)/([1-9][0-9]*)$ ]] || [ "${BASH_REMATCH[1]}" -ge "${BASH_REMATCH[2]}" ]; then
  echo "the shard must be k/n with 0 <= k < n; got: $shard" >&2
  exit 1
fi
if ! [[ $budget =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "the budget must be a whole number of s, m or h, such as 180m; got: $budget" >&2
  exit 1
fi
# This script's directory, for ci/rustc-wrapper.sh below.
ci_dir=$(cd "$(dirname "$0")" && pwd)
cd "${3:-$(dirname "$0")/..}"

# timeout(1) by its path where it is there: a `timeout` earlier on PATH can be
# another program (the dev machine has one without options). It sends SIGINT,
# which cargo-mutants handles by stopping its build or test and writing what it
# has, even when its caller ignored SIGINT (ctrlc's set_handler, which it
# calls, replaces an ignored disposition). No --kill-after: uutils' timeout
# (the dev machine's /usr/bin/timeout) sends the SIGKILL at once with it; the
# job's timeout-minutes is the backstop.
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout

title="title=cargo-mutants shard $shard"

# The caps, set by prlimit(1) (util-linux, so Linux only) as cargo's runner for
# the host's target (CARGO_TARGET_<TRIPLE>_RUNNER, the triple from rustc -vV, as
# cargo reads it): cargo starts every test binary and doc-test through it,
# never rustc or a build script. On another host the tests run uncapped, and
# the log says so. Runs 40112234775, 41225873013 and 42399213062 each lost 3
# to 5 shards to "The runner has received a shutdown signal". Each of those
# traced (the five of 2026-11-07, two of 2026-10-31) died one to three minutes
# into a mutant whose tests allocate without end (such as `replace < with > in
# Connection::has_room` in the protocol crate, or `replace <= with > in build`
# in the index crate's trie) until the 16 GiB runner died, before the 300 s
# limit on their tests could stop them; the others were not traced.
# - data, 6 GiB: the heap and every other private writable mapping. The
#   unmutated tests peak at 1.85 GiB (engine's converge test, measured
#   2026-11-08 with 4, 8 and all 20 of its tests at once), so 6 GiB is three
#   times that and leaves 10 GiB of the runner's 16 to the rest. Not the
#   address space (--as): it also counts the malloc arenas each test thread
#   reserves without using, so it grows with the core count (converge: 2.8 GiB
#   with 4 test threads, 5.3 GiB with 20).
# - fsize, 1 GiB: the largest file a test process may write, its own output
#   included, which cargo-mutants sends straight into the mutant's log in
#   mutants.out. The tests write no file but the test vectors, under 200 kB,
#   and only when told to regenerate them.
# - core, 0: no core dump of a capped process (up to 6 GiB) on the disk.
# A test process past a cap dies: Rust aborts the process when an allocation
# is refused, and a write past fsize raises SIGXFSZ. cargo test then fails, and
# cargo-mutants counts the mutant caught: run so on 2026-11-08, each of the
# five mutants that killed the runners of 2026-11-07 was caught within 70 s.
# The baseline runs under the same caps, so tests that outgrow them fail it
# (exit 4 below) instead of having every mutant counted caught.
data_cap=$((6 << 30))
file_cap=$((1 << 30))
host=$(rustc -vV | sed -n 's/^host: //p') || host=
if [ -z "$host" ]; then
  echo "::error $title::rustc -vV did not name the host, so the test processes cannot be capped"
  exit 1
fi
caps=
case $host in
  *-linux-*)
    runner=${host^^}
    runner=CARGO_TARGET_${runner//[-.]/_}_RUNNER
    caps="prlimit --data=$data_cap --fsize=$file_cap --core=0 --"
    export "$runner=$caps"
    echo "== each test process runs under: $caps"
    ;;
  *) echo "== the test processes run uncapped: prlimit is Linux only, and the host is $host" ;;
esac

# sccache as rustc's wrapper, when it is installed (the helper says why).
# shellcheck source=ci/rustc-wrapper.sh
. "$ci_dir/rustc-wrapper.sh"

picked=(--package licketysync-keys --package licketysync-protocol --package licketysync-index
  --package licketysync-engine --no-shuffle --sharding round-robin --shard "$shard")
# The shard's mutants, numbered in the order the run below tests them (the
# same selection, unshuffled), folded on GitHub.
echo "::group::The mutants of shard $shard, in the order they are tested"
listed=0
cargo mutants --list "${picked[@]}" | awk '{ printf "%5d  %s\n", NR, $0 }' || listed=$?
echo "::endgroup::"
if [ "$listed" != 0 ]; then
  echo "::error $title::cargo-mutants could not list the mutants (exit $listed)"
  exit 1
fi

# Each mutant's time limit. cargo-mutants 27.1.0 (src/timeouts.rs) gives an
# explicit --timeout to the baseline's tests as well as to each mutant's, and
# ends the run with exit 4, as if they had failed, when the baseline's pass it:
# with the 300 s of the runs to 2026-11-07, whose baselines tested for 143 to
# 295 s, a slower runner or a few more tests would have failed the shard. So
# no --timeout: the baseline's tests have no limit but <budget>, and each
# mutant's limit is their time times --timeout-multiplier, rounded up, at least
# --minimum-test-timeout (the log says "Auto-set test timeout to <n>s").
# - 2 times: a mutant's tests are its own crate's, and the engine crate's, the
#   slowest, took 89 to 98 % of each shard's baseline on 2026-11-07 (its
#   surviving mutants), so an engine mutant may run its tests about twice as
#   slowly as unmutated before it counts as timed out; the fixed 300 s gave
#   them 1.13 times on the slowest runner (265 s in a baseline of 295). A
#   mutant that hangs costs twice the baseline's test time (up to 590 s on
#   2026-11-07, about 30 such mutants in the 16 shards).
# - at least 300 s, the limit until 2026-11-08: no mutant times out sooner on
#   a fast runner than it did then.
# --caught and --unviable print those outcomes too, as each mutant ends, the
# way cargo-mutants prints the missed and timed-out ones.
status=0
"$tmo" --signal=INT "$budget" cargo mutants "${picked[@]}" \
  --timeout-multiplier 2 --minimum-test-timeout 300 --caught --unviable || status=$?

count() { # count <outcome>: the lines of mutants.out/<outcome>.txt, 0 when absent
  if [ -f "mutants.out/$1.txt" ]; then grep -c . "mutants.out/$1.txt" || true; else echo 0; fi
}
caught=$(count caught)
missed=$(count missed)
timeouts=$(count timeout)
unviable=$(count unviable)
counts="$caught caught, $missed missed, $timeouts timed out, $unviable unviable"
echo "== cargo-mutants shard $shard: $counts"
# The sign each cap leaves in a log of mutants.out/log/ (a mutant's, or the
# unmutated tree's baseline.log): past the data cap, Rust's "memory allocation
# of <n> bytes failed", printed before it aborts; past the file cap, SIGXFSZ,
# which cargo gives by its number only, "process didn't exit successfully:
# `<runner> <test binary>` (signal: 25)" (cargo 1.99 names some signals, not
# this one), and rustdoc by its name as well, "Test executable failed
# (signal: 25 (SIGXFSZ))." for a doc-test. Checked with cargo and rustdoc
# 1.99.1 on 2026-11-08, on a toy crate of the workspace's edition (2021: each
# doc-test its own process).
mem_sign="memory allocation of [0-9]+ bytes failed"
file_sign="process didn't exit successfully: .*\(signal: 25\)$|\(SIGXFSZ\)"
# Of the caught mutants, those stopped by a cap: those whose log (its first
# "*** " line names the mutant as caught.txt does; the logs of missed,
# timed-out and unviable mutants and the baseline's are not counted) carries a
# sign. Approximate both ways: Rust prints the same message for any refused
# allocation, cap or not, and a test process past a cap that fails some other
# way (a thread refused its stack, a library that handles the refusal) leaves
# no sign. A rising count means tests drifting toward a cap.
if [ -n "$caps" ]; then
  capped=0
  while IFS= read -r log; do
    name=$(awk '/^\*\*\* / { sub(/^\*\*\* /, ""); print; exit }' "$log")
    if [ -n "$name" ] && grep -qxF -- "$name" mutants.out/caught.txt 2> /dev/null; then
      capped=$((capped + 1))
    fi
  done < <(grep -lE -- "$mem_sign|$file_sign" mutants.out/log/*.log 2> /dev/null || true)
  counts_capped="$capped of the caught were stopped by a cap (memory or file size)"
  echo "== $counts_capped"
fi
list() { # list <outcome> <heading>: print the mutants of that outcome, if any
  if [ -s "mutants.out/$1.txt" ]; then
    echo "== $2:"
    sed 's/^/  /' "mutants.out/$1.txt"
  fi
}
list missed "Surviving mutants (missed: the tests still pass with this change)"
list timeout "Mutants whose tests ran past their limit (timeout)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### cargo-mutants shard $shard"
    echo
    echo "$counts (exit $status)${caps:+; $counts_capped}."
    for o in missed timeout; do
      if [ -s "mutants.out/$o.txt" ]; then
        printf '\n%s:\n\n```\n' "$o"
        cat "mutants.out/$o.txt"
        printf '```\n'
      fi
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

case $status in
  0) echo "== every mutant of this shard was caught" ;;
  2 | 3)
    echo "::notice $title::$missed missed, $timeouts timed out; reported, not failing, until the end of phase 0 (decision 2026-10-22)"
    ;;
  # Never a time-out since 2026-11-08: the unmutated tree's tests have no
  # limit but <budget> (124 below). When the baseline's log carries a cap's
  # sign, the message names the cap: the tests have outgrown it, or one runs
  # away unmutated.
  4)
    past=
    if [ -n "$caps" ]; then
      if grep -qE -- "$mem_sign" mutants.out/log/baseline.log 2> /dev/null; then
        past="the data cap ($((data_cap >> 30)) GiB)"
      fi
      if grep -qE -- "$file_sign" mutants.out/log/baseline.log 2> /dev/null; then
        past="${past:+$past and }the file-size cap ($((file_cap >> 30)) GiB)"
      fi
    fi
    echo "::error $title::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log)${past:+; a test process of the unmutated tree went past $past, set in ci/mutants.sh}"
    exit 1
    ;;
  124)
    # Nothing tested: the unmutated tree took the budget, or so much of it
    # that the first mutant used the rest (its build has no limit either).
    if [ "$((caught + missed + timeouts + unviable))" = 0 ]; then
      echo "::error $title::stopped after $budget before any mutant was tested: the unmutated tree's build and tests, which have no time limit but this budget, took it all, or all but what the first mutant used (mutants.out/log/)"
    else
      echo "::error $title::stopped after $budget, before the shard finished: give mutants.yml more shards, or see the timeouts listed above"
    fi
    exit 1
    ;;
  *)
    echo "::error $title::cargo-mutants failed with exit $status"
    exit 1
    ;;
esac
