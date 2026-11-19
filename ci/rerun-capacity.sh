#!/usr/bin/env bash
# Reruns the jobs of a CI run that GitHub cancelled for lack of runner capacity
# (macOS runners: "The job was not acquired by Runner of type hosted even after
# multiple attempts", after 15 minutes of waiting), and nothing else. Run by
# .github/workflows/ci-rerun.yml when CI completes; tested by
# ci/test-rerun-capacity.sh on recorded GitHub API answers.
# Usage: ci/rerun-capacity.sh <run id> <run attempt>, with GITHUB_REPOSITORY set
# and gh signed in (GH_TOKEN). It reruns (`gh run rerun --failed`) only when all
# of these hold, and says which does not:
#   - the attempt was a push or a pull request of this repository (a fork's
#     pull request is never rerun) and ended failed or cancelled;
#   - it is attempt 1 or 2, so a run has at most 3 attempts in all;
#   - every job that did not succeed or skip was cancelled before any step ran
#     (a job with steps that failed or was cancelled is a real result, and a
#     rerun would rerun it too) and carries GitHub's capacity annotation. A job
#     that a newer push cancelled through the concurrency group has no steps
#     either, but its annotation is another, so it is not rerun;
#   - just before the rerun, the run is read again: it is completed, still on
#     that attempt, and the newest CI run of its branch and event, since
#     rerunning an outdated run joins ci.yml's concurrency group and can cancel
#     the newer commit's run.
# Fails closed: an answer it cannot read, or a list of jobs longer than one
# page, ends it with exit 1 and no rerun.
set -euo pipefail
id=${1:?usage: ci/rerun-capacity.sh <run id> <run attempt>}
attempt=${2:?usage: ci/rerun-capacity.sh <run id> <run attempt>}
[[ $id =~ ^[0-9]+$ && $attempt =~ ^[0-9]+$ ]] || { echo "run id and attempt must be numbers" >&2; exit 2; }
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
max_attempt=2
message='The job was not acquired by Runner of type hosted'

skip() { echo "no rerun: $1"; exit 0; }

run=$(gh api "repos/$repo/actions/runs/$id/attempts/$attempt")
reason=$(jq -r --arg repo "$repo" --argjson attempt "$attempt" --argjson max "$max_attempt" '
  if .run_attempt != $attempt then "the answer is for attempt \(.run_attempt), not \($attempt)"
  elif (.event | IN("push", "pull_request") | not) then "event \(.event) is not a push or a pull request"
  elif ((.head_repository.full_name // "") | ascii_downcase) != ($repo | ascii_downcase)
    then "the run is from another repository"
  elif (.conclusion | IN("failure", "cancelled") | not) then "the run ended \(.conclusion)"
  elif .run_attempt > $max then "attempt \(.run_attempt) is the last (\($max + 1) in all)"
  else empty end' <<< "$run")
[ -z "$reason" ] || skip "$reason"

jobs=$(gh api "repos/$repo/actions/runs/$id/attempts/$attempt/jobs?per_page=100")
if [ "$(jq '.total_count > (.jobs | length)' <<< "$jobs")" != false ]; then
  echo "the run has more jobs than one page holds, or the answer is unreadable" >&2
  exit 1
fi
# Jobs that neither succeeded nor were skipped.
bad=$(jq -c '[.jobs[] | select(.conclusion | IN("success", "skipped") | not)]' <<< "$jobs")
[ "$bad" != '[]' ] || skip "no job failed or was cancelled"
# A job's id, not its name, goes in the log: a name is the workflow author's text.
real=$(jq -r '.[] | select(.conclusion != "cancelled" or (.steps | length) > 0) | .id' <<< "$bad")
[ -z "$real" ] || skip "a job that ran did not succeed (job $(head -n 1 <<< "$real"))"
for job in $(jq -r '.[].id' <<< "$bad"); do
  [[ $job =~ ^[0-9]+$ ]] || { echo "unreadable job id" >&2; exit 1; }
  notes=$(gh api "repos/$repo/check-runs/$job/annotations")
  [ "$(jq --arg m "$message" '[.[] | select(.annotation_level == "failure" and (.message | startswith($m)))] | length > 0' <<< "$notes")" = true ] \
    || skip "job $job was cancelled, but not for runner capacity"
done
# Read the run again: a newer push or someone's rerun may have come meanwhile.
now=$(gh api "repos/$repo/actions/runs/$id")
reason=$(jq -r --argjson attempt "$attempt" '
  if .run_attempt != $attempt then "the run is on attempt \(.run_attempt) now"
  elif .status != "completed" then "the run is \(.status) now"
  else empty end' <<< "$now")
[ -z "$reason" ] || skip "$reason"
branch=$(jq -r '.head_branch | @uri' <<< "$run")
event=$(jq -r '.event' <<< "$run")
newest=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?branch=$branch&event=$event&per_page=1" \
  | jq -r '.workflow_runs[0].id // empty')
[ "$newest" = "$id" ] || skip "run ${newest:-?} is newer on this branch"
echo "rerunning run $id after attempt $attempt: runner capacity cancelled $(jq length <<< "$bad") job(s) before any step"
if ! out=$(gh run rerun "$id" --failed --repo "$repo" 2>&1); then
  echo "gh run rerun failed (the run may already have been rerun, or still be running): $(tr -d '[:cntrl:]' <<< "$out" | head -c 300)" >&2
  exit 1
fi
