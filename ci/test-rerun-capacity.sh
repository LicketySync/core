#!/usr/bin/env bash
# Tests for ci/rerun-capacity.sh on a stand-in gh that answers from
# ci/rerun-fixtures/: GitHub's answers for three CI runs of 2026-11-17 whose
# macOS jobs were cancelled for runner capacity (44110056167, which also had a
# real Windows test failure, 44113762557 and 44119568108, attempts 1 to 3).
# They keep, of each run, its id, event, status, conclusion, attempt, branch
# and head repository's name; of each job, its id, name, status, conclusion,
# attempt, labels, runner id and each step's conclusion; of each annotation,
# its level and message. Cases that no recorded run covers are made from
# those answers with jq (marked "made up"). The assertion is whether the
# stand-in saw `run rerun`, and for which run. Run by gate.sh and CI. Exit 1
# if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fx=$here/rerun-fixtures
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
# The stand-in: `gh api <path>` prints $DATA/<path without its query, with / as _>.json,
# every requested path goes to $DATA/requests, `gh run rerun <id> ...` appends the id to $DATA/reruns (and fails when
# $DATA/rerun-fails exists), anything else fails.
cat > "$tmp/bin/gh" <<'STANDIN'
#!/usr/bin/env bash
case $1 in
  api)
    echo "$2" >> "$DATA/requests"
    p=${2%%\?*}
    p=${p#repos/*/*/}
    f=$DATA/${p//\//_}.json
    [ -f "$f" ] || { echo "stand-in gh: no answer for $2" >&2; exit 1; }
    cat "$f" ;;
  run)
    [ "$2" = rerun ] && [ "$4" = --failed ] || { echo "stand-in gh: unexpected: $*" >&2; exit 1; }
    [ ! -f "$DATA/rerun-fails" ] || { printf 'run 1 cannot be rerun\033[31m\r\n::error::forged\n'; exit 1; }
    echo "$3" >> "$DATA/reruns" ;;
  *) echo "stand-in gh: unexpected: $*" >&2; exit 1 ;;
esac
STANDIN
chmod +x "$tmp/bin/gh"

n=0
fails=0
# data <dir>: the recorded answers for every run in the stand-in's names.
data() {
  local d=$1 f id a
  mkdir -p "$d"
  for f in "$fx"/run-*-*.json; do
    f=${f##*/run-}; f=${f%.json}; id=${f%-*}; a=${f#*-}
    cp "$fx/run-$id-$a.json" "$d/actions_runs_${id}_attempts_${a}.json"
    cp "$fx/jobs-$id-$a.json" "$d/actions_runs_${id}_attempts_${a}_jobs.json"
  done
  for f in "$fx"/annotations-*.json; do
    f=${f##*/annotations-}
    cp "$fx/annotations-$f" "$d/check-runs_${f%.json}_annotations.json"
  done
}
case_() { # case_ <name> <expected: rerun|none|error> <run id> <attempt> [<jq filter on the run>] [<data dir>]
  n=$((n + 1))
  local d=${6:-$tmp/$n} rc=0 got=none want=$2
  [ -n "${6:-}" ] || data "$d"
  if [ -n "${5:-}" ]; then
    local r=$d/actions_runs_$3_attempts_$4.json
    jq "$5" "$r" > "$r.new" && mv "$r.new" "$r"
  fi
  # What the script reads again before it reruns: the run itself, and the newest CI run of its branch.
  if [ ! -f "$d/actions_runs_$3.json" ] && [ -f "$d/actions_runs_$3_attempts_$4.json" ]; then
    cp "$d/actions_runs_$3_attempts_$4.json" "$d/actions_runs_$3.json"
  fi
  [ -f "$d/actions_workflows_ci.yml_runs.json" ] \
    || printf '{"workflow_runs":[{"id":%s}]}\n' "$3" > "$d/actions_workflows_ci.yml_runs.json"
  rm -f "$d/reruns"
  DATA=$d GITHUB_REPOSITORY=LicketySync/core PATH="$tmp/bin:$PATH" \
    "$here/rerun-capacity.sh" "$3" "$4" > "$d/out" 2>&1 || rc=$?
  if [ -f "$d/reruns" ]; then got="rerun $(tr '\n' ' ' < "$d/reruns")"; fi
  [ "$rc" -eq 0 ] || got=error
  [ "$want" != rerun ] || want="rerun $3 "
  if [ "$got" = "$want" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$got', expected '$want'"
    cat "$d/out"
    fails=$((fails + 1))
  fi
}
# A copy of the recorded data with jobs of one run changed (made up).
variant() { # variant <dir> <run id> <attempt> <jq filter on the jobs answer>
  data "$1"
  local j=$1/actions_runs_$2_attempts_$3_jobs.json
  jq "$4" "$j" > "$j.new" && mv "$j.new" "$j"
}

case_ "recorded: one iOS job and one macOS job cancelled for capacity" rerun 44113762557 1
case_ "recorded: the same run's attempt 1 of the third run"            rerun 44119568108 1
case_ "recorded: attempt 2, a macOS job cancelled again"               rerun 44119568108 2
case_ "recorded: attempt 3 succeeded"                                  none  44119568108 3
case_ "recorded: a capacity cancellation beside a real test failure"   none  44110056167 1
d=$tmp/lastattempt
data "$d"
# Attempt 2's jobs, a capacity-cancelled macOS job among them, as attempt 3's: only the limit stops it.
cp "$d/actions_runs_44119568108_attempts_2_jobs.json" "$d/actions_runs_44119568108_attempts_3_jobs.json"
jq '.conclusion="cancelled"' "$d/actions_runs_44119568108_attempts_3.json" > "$d/x" && mv "$d/x" "$d/actions_runs_44119568108_attempts_3.json"
case_ "made up: attempt 3 cancelled for capacity again (the last attempt)" none 44119568108 3 "" "$d"
case_ "made up: a scheduled run"                                       none  44113762557 1 '.event="schedule"'
case_ "made up: a fork's pull request"                                 none  44113762557 1 \
  '.event="pull_request" | .head_repository.full_name="Someone/core"'
d=$tmp/ownpr
variant "$d" 44113762557 1 '.jobs += [{"id":1,"name":"codecov","status":"completed","conclusion":"skipped","steps":[]}]'
jq '.event="pull_request" | .head_repository.full_name="licketysync/CORE"' "$d/actions_runs_44113762557_attempts_1.json" > "$d/x" \
  && mv "$d/x" "$d/actions_runs_44113762557_attempts_1.json"
case_ "made up: own pull request (other case), a skipped job with no steps" rerun 44113762557 1 "" "$d"
case_ "made up: a run that succeeded"                                  none  44113762557 1 '.conclusion="success"'
case_ "made up: the answer is for another attempt"                     none  44113762557 1 '.run_attempt=2'
d=$tmp/concurrency
variant "$d" 44113762557 1 '.'
for f in "$d"/check-runs_*_annotations.json; do
  echo '[{"annotation_level":"failure","message":"Canceling since a higher priority waiting request for CI exists"}]' > "$f"
done
case_ "made up: cancelled by a newer push (concurrency), no steps"     none  44113762557 1 "" "$d"
d=$tmp/noannotation
variant "$d" 44113762557 1 '.'
for f in "$d"/check-runs_*_annotations.json; do echo '[]' > "$f"; done
case_ "made up: cancelled with no annotation"                          none  44113762557 1 "" "$d"
d=$tmp/onenotcapacity
variant "$d" 44113762557 1 '.'
f=$d/check-runs_134146076556_annotations.json
echo '[{"annotation_level":"notice","message":"The job was not acquired by Runner of type hosted"}]' > "$f"
case_ "made up: one of two cancelled jobs without the failure note"    none  44113762557 1 "" "$d"
d=$tmp/stepsran
variant "$d" 44113762557 1 '.jobs |= map(if .conclusion == "cancelled" then .steps = [{"conclusion":"cancelled"}] else . end)'
case_ "made up: cancelled after a step ran (a person cancelled it)"    none  44113762557 1 "" "$d"
d=$tmp/timedout
variant "$d" 44113762557 1 '.jobs[0].conclusion = "timed_out"'
case_ "made up: a job timed out"                                       none  44113762557 1 "" "$d"
d=$tmp/stepless-failure
variant "$d" 44113762557 1 '(.jobs[] | select(.id == 134146076556)) |= (.conclusion = "failure")'
case_ "made up: a job with no steps that failed, with the capacity note" none 44113762557 1 "" "$d"
d=$tmp/stepless-timeout
variant "$d" 44113762557 1 '(.jobs[] | select(.id == 134146076556)) |= (.conclusion = "timed_out")'
case_ "made up: a job with no steps that timed out, with the capacity note" none 44113762557 1 "" "$d"
d=$tmp/newer-attempt
variant "$d" 44113762557 1 '.'
jq '.run_attempt=2' "$d/actions_runs_44113762557_attempts_1.json" > "$d/actions_runs_44113762557.json"
case_ "made up: the run is on attempt 2 by the time of the rerun"      none  44113762557 1 "" "$d"
d=$tmp/running
variant "$d" 44113762557 1 '.'
jq '.status="in_progress"' "$d/actions_runs_44113762557_attempts_1.json" > "$d/actions_runs_44113762557.json"
case_ "made up: the run is in progress by the time of the rerun"       none  44113762557 1 "" "$d"
d=$tmp/newerrun
variant "$d" 44113762557 1 '.'
echo '{"workflow_runs":[{"id":44113762558},{"id":44113762557}]}' > "$d/actions_workflows_ci.yml_runs.json"
case_ "made up: a newer CI run on the same branch and event"           none  44113762557 1 "" "$d"
d=$tmp/refused
variant "$d" 44113762557 1 '.'
touch "$d/rerun-fails"
case_ "made up: GitHub refuses the rerun"                              error 44113762557 1 "" "$d"
if grep -q "already have been rerun, or still be running" "$d/out" && ! grep -q '^::' "$d/out" \
  && ! grep -q "$(printf '\033')" "$d/out"; then
  echo "ok   the refusal is said plainly, with its control characters stripped"
else
  echo "FAIL the refusal is not said plainly or keeps control characters"; cat -v "$d/out"; fails=$((fails + 1))
fi
d=$tmp/branchname
variant "$d" 44113762557 1 '.'
jq '.head_branch="a&b=c d"' "$d/actions_runs_44113762557_attempts_1.json" > "$d/x" \
  && mv "$d/x" "$d/actions_runs_44113762557_attempts_1.json"
case_ "made up: a branch name with & = and a space" rerun 44113762557 1 "" "$d"
if grep -qx 'repos/LicketySync/core/actions/workflows/ci.yml/runs?branch=a%26b%3Dc%20d&event=push&per_page=1' "$d/requests"; then
  echo "ok   the branch name was percent-encoded"
else
  echo "FAIL the branch name was not percent-encoded"; cat "$d/requests"; fails=$((fails + 1))
fi
d=$tmp/morejobs
variant "$d" 44113762557 1 '.total_count = 101'
case_ "made up: more jobs than the page holds"                         error 44113762557 1 "" "$d"
case_ "a run with no recorded answer"                                  error 1 1
n=$((n + 1))
for bad in "1 x" "x 1" "1;id 1"; do
  rc=0
  # shellcheck disable=SC2086
  DATA=$tmp PATH="$tmp/bin:$PATH" GITHUB_REPOSITORY=LicketySync/core "$here/rerun-capacity.sh" $bad > /dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 2 ]; then echo "ok   arguments '$bad' refused"; else echo "FAIL arguments '$bad': exit $rc"; fails=$((fails + 1)); fi
done
if [ "$fails" -ne 0 ]; then
  echo "$fails cases failed"
  exit 1
fi
echo "all cases passed"
