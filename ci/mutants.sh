#!/usr/bin/env bash
# One shard of the weekly mutation test (mutants.yml):
# cargo-mutants over the crates the plan names (keys, protocol, engine) and the
# index crate, which TM-17, TM-40 and TM-41 name as their enforcer, shard
# <k>/<n> of their mutants dealt round-robin, stopped after <budget> (a
# duration as timeout(1) reads it, such as 180m). cargo-mutants first builds and
# tests the unmutated tree (its baseline), then each mutant of the shard with a
# 300 s limit on its tests, and leaves mutants.out/ in the repository root,
# which the job uploads.
#
# Decision 2026-10-22 (phase 0): surviving mutants (missed: the tests still
# pass with the code broken) and mutants whose tests ran past the 300 s limit
# (timeout) are reported, not failing, until the end of phase 0, while the keys
# crate is reworked to the shared-key model; the rule is revisited then. The
# script fails (exit 1) when the unmutated tree does not build or its tests
# fail (cargo-mutants exit 4), when the shard runs past <budget>, or when
# cargo-mutants stops on any other error (a usage or internal error, a
# signal). Every case first prints the counts and the surviving and timed-out
# mutants found so far, to the log and, on GitHub, to the job summary.
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
cd "${3:-$(dirname "$0")/..}"

# timeout(1) by its path where it is there: a `timeout` earlier on PATH can be
# another program (the dev machine has one without options). It sends SIGINT,
# which cargo-mutants handles by stopping its build or test and writing what it
# has. No --kill-after: uutils' timeout (the dev machine's /usr/bin/timeout)
# sends the SIGKILL at once with it; the job's timeout-minutes is the backstop.
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout
status=0
"$tmo" --signal=INT "$budget" \
  cargo mutants --package licketysync-keys --package licketysync-protocol \
  --package licketysync-index --package licketysync-engine --timeout 300 --no-shuffle --sharding round-robin \
  --shard "$shard" || status=$?

count() { # count <outcome>: the lines of mutants.out/<outcome>.txt, 0 when absent
  if [ -f "mutants.out/$1.txt" ]; then grep -c . "mutants.out/$1.txt" || true; else echo 0; fi
}
caught=$(count caught)
missed=$(count missed)
timeouts=$(count timeout)
unviable=$(count unviable)
counts="$caught caught, $missed missed, $timeouts timed out, $unviable unviable"
echo "== cargo-mutants shard $shard: $counts"
list() { # list <outcome> <heading>: print the mutants of that outcome, if any
  if [ -s "mutants.out/$1.txt" ]; then
    echo "== $2:"
    sed 's/^/  /' "mutants.out/$1.txt"
  fi
}
list missed "Surviving mutants (missed: the tests still pass with this change)"
list timeout "Mutants whose tests ran past 300 s (timeout)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### cargo-mutants shard $shard"
    echo
    echo "$counts (exit $status)."
    for o in missed timeout; do
      if [ -s "mutants.out/$o.txt" ]; then
        printf '\n%s:\n\n```\n' "$o"
        cat "mutants.out/$o.txt"
        printf '```\n'
      fi
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

title="title=cargo-mutants shard $shard"
case $status in
  0) echo "== every mutant of this shard was caught" ;;
  2 | 3)
    echo "::notice $title::$missed missed, $timeouts timed out; reported, not failing, until the end of phase 0 (decision 2026-10-22)"
    ;;
  4)
    echo "::error $title::the unmutated tree does not build or its tests fail (mutants.out/log/baseline.log)"
    exit 1
    ;;
  124)
    echo "::error $title::stopped after $budget, before the shard finished: give mutants.yml more shards, or see the timeouts listed above"
    exit 1
    ;;
  *)
    echo "::error $title::cargo-mutants failed with exit $status"
    exit 1
    ;;
esac
