#!/usr/bin/env bash
# Downloads one file over HTTPS into a named file, retrying what is transient.
# The one place for the curl options every download in this repository's CI
# scripts uses (ci/check-downloads.sh fails when a script, gate.sh or a
# workflow calls curl or wget on its own), so that a short outage at a download
# host, such as the HTTP 504s of GitHub's release downloads that turned main
# red in CI run 42568260092 (2026-11-09), does not fail a job, and a future
# download script gets the same behaviour by calling this one. It checks
# nothing about the file but that there is one: the caller checks the file's
# SHA-256 afterwards.
# The options:
# - --proto '=https' --tlsv1.2: HTTPS only, TLS 1.2 or newer.
# - -fSL --no-progress-meter: an HTTP error is a failure (no error page in the
#   output file), errors are shown, redirects are followed, and there is no
#   progress meter. Not -s: it would hide the notice of each retry (curl 8.18.0
#   words it "Will retry in N seconds", 8.21.0 "Retrying in N seconds"), and the
#   CI log should show each retry.
# - --retry 8 --retry-all-errors: after any failure curl waits 1 s, then 2, 4
#   and so on up to 128 (its own backoff; 255 s in all over the 8 retries) and
#   tries again, so an outage of about four minutes is ridden out. Any failure
#   means a timeout, an HTTP error (408, 429, 5xx, and also 404 and the other
#   client errors), a connection refused or reset, a reply that never came, a
#   failed TLS handshake and a body cut off in the middle: the signatures of a
#   download host in trouble. The cost: curl cannot tell a failure that no retry
#   cures from an outage (a host in trouble answers 404 and refuses connections
#   too), so every permanent failure is reported after those 255 s (about four
#   minutes), not at once: a 404 from a wrong pin, a connection refused for
#   good, an output file that cannot be written (curl's exit status 23, retried
#   all the same: measured with curl 8.18.0 and 8.21.0). That is acceptable: the
#   job fails either way, so what is lost is four minutes of a run that was
#   going to be red, and the 878 s bound below still holds (with curl 7.79.0 or
#   later, as below); a wrong pin comes only with a commit that changes a pin,
#   and such a commit is reviewed anyway.
#   --retry-all-errors needs curl 7.71.0; the plain --retry would retry only a
#   timeout and an HTTP 408, 429, 500, 502, 503 or 504.
#   --retry-connrefused (curl 7.52.0) is implied by it (measured with curl
#   8.18.0: a refused connection is retried without it), and stays so that a
#   refused connection is retried whatever the curl.
# - --connect-timeout 30 --max-time 300 --retry-max-time 450: a connection
#   that does not open in 30 s, or a transfer that takes more than 300 s,
#   counts as a timeout and is retried. The largest file, Chrome for Testing's
#   chrome-linux64.zip at the version in ci/pins.env, is 201,329,937 bytes (a
#   HEAD request, 2026-11-09), which needs 0.67 MB/s (5.4 Mbit/s) to arrive in
#   300 s; chromedriver's zip is 11,898,387 bytes. curl starts a retry only if
#   less than 450 s have passed since the first try began when a try fails; the
#   wait before the retry is not counted (measured with curl 8.18.0: with a
#   window of 5 s the tries began at 0, 1, 3 and 7 s). The window is longer than
#   one try so that a first try that times out is not the last. So, with curl
#   7.79.0 or later, a stuck download ends in 878 s (14.6 minutes) at most: the
#   window, the longest wait (128 s) and one more try. The two downloads of
#   nightly.yml's webtransport-chrome job take 29.3 minutes of its 45, and the
#   gitleaks job of ci.yml, whose one download takes 14.6, has timeout-minutes
#   25. ci/test-download.sh checks both. A Retry-After header (429, 503) is
#   honoured by curl as the wait, but not past the window: if it would end
#   after the window, curl 8.15.0, 8.18.0 and 8.21.0 give up with exit status 0
#   and no file (measured with a 503: "The Retry-After: time would make this
#   command line exceed the maximum allowed time for retries", exit 0), which
#   is why this script checks for the file. That check against the window came
#   with curl 7.79.0. Before it curl honours a Retry-After all the same and
#   waits out a long one whole (curl 7.74.0 sleeps the 100000 s of
#   ci/test-download.sh's `late` case), so the 878 s bound does not hold on a
#   curl older than 7.79.0.
# Every option is in curl 7.71.0 (2020) and later, which is the minimum for the
# options themselves; the 878 s bound needs 7.79.0 or later. Ubuntu 22.04 has
# curl 7.81.0 and 24.04 has 8.5.0 (neither was run); CI's curl (8.5.0 on
# ubuntu-latest) and the development machine's (8.18.0) are both past 7.79.0,
# and ci/test-download.sh also passed with 8.15.0 and 8.21.0 (2026-11-09).
# A retry never leaves a partial or appended file behind. The output is the one
# file given to -o, and curl truncates it before it tries again (checked with
# curl 8.18.0: a try cut off after 5946 of 11892 bytes, then a complete one,
# left the 11892-byte file, not 17838); there is no -C, which would continue a
# partial file instead. This script removes the file before curl runs, so that
# a file from before is never taken for this download, and again when curl
# gives up (curl leaves the part it got). And whatever the file holds, the
# caller's SHA-256 check passes only for the exact file pinned.
# Usage: ci/download.sh <https URL> <output file>
# Exit status: curl's when it gave up (non-zero, no output file), 1 when curl
# reported success but there is no file or an empty one (no output file), 2 for
# a bad call.
set -euo pipefail
usage="usage: ci/download.sh <https URL> <output file>"
if [ $# -ne 2 ]; then
  echo "$usage" >&2
  exit 2
fi
url=$1
out=$2
case $url in
  https://*) ;;
  *)
    echo "ci/download.sh: not an https:// URL: $url" >&2
    exit 2
    ;;
esac
rm -f -- "$out"
rc=0
curl --proto '=https' --tlsv1.2 -fSL --no-progress-meter \
  --retry 8 --retry-all-errors --retry-connrefused --retry-max-time 450 \
  --connect-timeout 30 --max-time 300 \
  -o "$out" "$url" || rc=$?
if [ "$rc" -ne 0 ]; then
  rm -f -- "$out"
  exit "$rc"
fi
if [ ! -s "$out" ]; then
  rm -f -- "$out"
  echo "ci/download.sh: curl succeeded but left no file, or an empty one, for $url" >&2
  exit 1
fi
