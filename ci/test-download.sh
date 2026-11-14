#!/usr/bin/env bash
# Tests for ci/download.sh and ci/check-downloads.sh. Four groups:
# - the options download.sh hands to curl, seen by a stand-in `curl` first on
#   PATH that records its arguments: the safety options the scripts always had
#   (HTTPS only, TLS 1.2, -fSL, the output file), the retry options (all
#   errors, a window, a time limit on each try), no resuming, the longest a
#   stuck download can take against the timeouts of the jobs that run it, and
#   the call refused when it is not `<https URL> <file>`; and what it leaves
#   behind when the stand-in succeeds without a file, with an empty file, or
#   fails after writing part of one (a failure or nothing: no file), also when
#   the output file's name begins with a dash;
# - ci/gitleaks-install.sh and ci/chrome-install.sh on the same stand-in: they
#   download their pinned URLs through it, with retries, and still refuse a
#   download that is not the pinned file (the SHA-256 check);
# - the real curl against a server on 127.0.0.1 (HTTPS with a certificate made
#   here, trusted through CURL_CA_BUNDLE) that answers each path by a plan: a
#   504, a 404, a body cut off half way and a connection closed with no reply,
#   each and then the file; and a 503 with a Retry-After that ends after the
#   retry window. Each of the first four is retried and the file arrives whole,
#   not appended to the part (a plain curl is shown to leave that part), and the
#   retry is announced in the log (curl words it "Will retry in" or "Retrying
#   in", by version); the 503 is a failure with no file, not curl's exit status
#   0. The cases run at the same time, so the one retry each costs, about a
#   second, curl's own first wait before a retry, is spent once (nothing here
#   sleeps, and curl has no shorter wait). Each runs under timeout(1)
#   (/usr/bin/timeout where there is one, else the first `timeout` on PATH, as
#   ci/mutants.sh finds it), so that a helper or a curl that hangs fails the
#   case and ends the test instead of holding the CI job for hours; the 503
#   must fail by itself, not by that timeout's kill (status 124) and not by a
#   timeout that is not there (status 127). The `late` case needs a curl that
#   honours a Retry-After by giving up when it would end after
#   --retry-max-time, a check curl has had since 7.79.0 (Ubuntu 22.04's 7.81.0,
#   24.04's 8.5.0 and 8.15.0 to 8.21.0 have it); curl 7.74.0 (Debian 11) has
#   no such check, so it waits out the whole 100000 s, the timeout kills it and
#   the case fails. The dump of a failed run names the curl for that reason. A
#   failure that no retry cures, and the 404 of a wrong pin, which curl retries
#   for 255 s, are tested on the stand-in;
# - ci/check-downloads.sh on this repository, and on trees made for each case:
#   a direct curl or wget fails it, comments and other words do not.
# The expected exit code or file is the assertion.
#
# The server and the downloads of the third group start as a CI step does,
# whatever this suite inherited (ci/as_ci.py): no signal ignored or blocked
# and no descriptor open but stdin, stdout and stderr, so that none can hold a
# caller's lock; and each gets SIGTERM when the suite ends, however it ends,
# SIGKILL included. They carry a variable of their own: the group fails if any
# is still running at its end, and the EXIT trap kills them before the suite
# ends. Last, the suite runs itself: under two locks with SIGINT ignored, and
# through ci/reaper.py, which kills that run when the suite ends, however it
# ends, it is stopped mid-download by SIGTERM and by SIGKILL, and must leave
# nothing running and both locks free, and it is killed while it runs itself,
# when nothing of that run may be left either; and sent SIGINT during a
# foreground command, it must end by SIGINT.
# Needs python3, openssl, flock (util-linux) and Linux's /proc. Run by gate.sh
# and CI. Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
self="$here/$(basename "$0")"
download="$here/download.sh"
check="$here/check-downloads.sh"
# survivors <NAME=value>: kill every process of this user whose environment
# holds that variable, and print each once, as "  <pid> <command line>"; as
# ci/test-mutants.sh's. Each pass prints what it finds, then stops (SIGSTOP)
# every process it found, so that none forks again, and at once kills them
# (SIGKILL); a child forked before its parent stopped is found by the next
# pass. Passes repeat until one finds none, at most 50; past that, a last
# line says so.
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
    for pid in "${found[@]}"; do
      [ -n "${seen[$pid]:-}" ] || echo "  $pid $(tr '\0' ' ' 2> /dev/null < "/proc/$pid/cmdline")"
      seen[$pid]=1
    done
    kill -STOP "${found[@]}" 2> /dev/null || true
    kill -KILL "${found[@]}" 2> /dev/null || true
  done
  echo "  (still finding processes after 50 passes)"
}
tmp=$(mktemp -d)
# The variable that marks the processes of the third group, the server and the
# downloads; and the one that marks those of the run of this suite by itself
# under way (empty when there is none).
mark="LICKETYSYNC_TEST_DOWNLOAD_RUN=$tmp"
nested=
# Stopped by SIGHUP, SIGINT or SIGTERM, bash (5.2 and 5.3) runs this EXIT trap
# too, then ends by that signal; a signal ignored on entry stays ignored. The
# kills come first, so that nothing is left running or writing in $tmp when it
# is removed, or when the suite has ended. A SIGINT that comes while a
# foreground command runs, bash holds until the command ends, then drops,
# taking it for the command's own; trapped, it runs the INT trap then instead,
# which restores bash's own handling and sends the signal again (as in
# ci/test-mutants.sh).
cleanup() {
  survivors "$mark" > /dev/null
  [ -z "$nested" ] || survivors "$nested" > /dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'trap - INT; kill -INT $$' INT

# --- the server of the third group, and the runs of this suite by itself ----
# They come first, so that a run in a stop mode (below) skips the other groups.
# Needs python3 and openssl. The server answers each path by a plan of steps, one
# a request, the last repeating: 200 is the file; another number is that status
# with a small page, and N/S adds Retry-After: S; cut is the status 200 and half
# the file, then the connection closed with no end to the TLS session; empty is
# the connection closed with no reply; hold is no reply until the server ends.
# It prints its port when it listens and "held <path>" for each request it
# holds, and logs a line a request: the path, the number of the request and its
# step.
cat > "$tmp/server.py" << 'EOF'
import http.server
import socket
import ssl
import sys
import threading

cert, key, body_path, plan, log_path = sys.argv[1:6]
plans = {}
for entry in plan.split():
    name, steps = entry.split("=")
    plans["/" + name] = steps.split(",")
body = open(body_path, "rb").read()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def hang_up(self):
        self.close_connection = True
        self.request.shutdown(socket.SHUT_RDWR)

    def do_GET(self):
        steps = plans[self.path]
        count = self.server.counts.get(self.path, 0)
        self.server.counts[self.path] = count + 1
        step = steps[min(count, len(steps) - 1)]
        with open(log_path, "a") as log:
            log.write("%s %d %s\n" % (self.path[1:], count + 1, step))
        if step == "empty":
            self.hang_up()
            return
        if step == "hold":
            sys.stdout.write("held %s\n" % self.path[1:])
            sys.stdout.flush()
            threading.Event().wait()
        if step == "cut":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[: len(body) // 2])
            self.wfile.flush()
            self.hang_up()
            return
        status, _, after = step.partition("/")
        data = body if status == "200" else b"<html>an error page</html>\n"
        self.send_response(int(status))
        if after:
            self.send_header("Retry-After", after)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.counts = {}
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
EOF
if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -subj /CN=localhost \
  -addext subjectAltName=IP:127.0.0.1 > "$tmp/openssl.out" 2>&1; then
  cat "$tmp/openssl.out"
  echo "FAIL: openssl could not make the test certificate"
  exit 1
fi
mkdir "$tmp/home" "$tmp/f"
awk 'BEGIN { for (i = 1; i <= 400; i++) print "the pretend tarball, line " i }' > "$tmp/body"
port=''
# ci/as_ci.py starts the server and each download as a CI step starts a
# command (no signal ignored or blocked, no descriptor but 0 to 2), and has the
# kernel send it SIGTERM when this suite ends, however it ends: the server ends
# at it, and timeout(1) passes it on to download.sh and curl. It refuses
# (status 125) a command whose parent is not this suite.
as_ci="$here/as_ci.py"
serve() { # serve <plan>: starts the server (a coprocess, through as_ci and with the mark) and sets port
  : > "$tmp/requests"
  coproc SERVER { exec env "$mark" python3 -I "$as_ci" "$$" \
    python3 -I "$tmp/server.py" "$tmp/cert.pem" "$tmp/key.pem" "$tmp/body" "$1" "$tmp/requests"; }
  if ! read -r -u "${SERVER[0]}" port; then
    echo "FAIL: the test server did not start"
    exit 1
  fi
}
stop() {
  kill "$SERVER_PID"
  wait "$SERVER_PID" 2> /dev/null || true
}
# as a machine with no proxy and no curl settings of its own would run it
clean_env=(env -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u CURL_HOME -u XDG_CONFIG_HOME
  HOME="$tmp/home" NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
  CURL_CA_BUNDLE="$tmp/cert.pem" SSL_CERT_FILE="$tmp/cert.pem")
pids=()
paths=()
# timeout(1) by its path where it is there, else the first on PATH, as
# ci/mutants.sh and ci/test-mutants.sh find it: a `timeout` earlier on PATH may
# not kill grandchildren (ci/webtransport-chrome.sh also names the path).
# timeout_for <preferred path>: the program to run the cases under.
timeout_for() { if [ -x "$1" ]; then echo "$1"; else echo timeout; fi; }
tmo=$(timeout_for /usr/bin/timeout)
# Each case ends in this many seconds (the cases need about two): the status 124
# is a kill by that timeout. Without a limit a curl that sleeps a Retry-After of
# 100000 s (28 hours; a curl before 7.79.0 does, as its source reads; 8.15.0,
# 8.18.0 and 8.21.0 do not, measured) would hold this test, and the ci-scripts
# job with its default of 6 hours, until the job is cancelled.
fetch_seconds=60
# job <path> <command...>: the command under that timeout, in the background
# (pids), through as_ci and with the mark, as clean_env runs it; its output in
# $tmp/f/<path>.out, and its status in .rc once collect has waited for it. A
# simple command, so that this suite is its parent, as as_ci requires (in a
# subshell, the subshell would be).
job() {
  local path=$1
  shift
  "${clean_env[@]}" "$mark" python3 -I "$as_ci" "$$" "$tmo" "$fetch_seconds" "$@" > "$tmp/f/$path.out" 2>&1 &
  pids+=("$!")
  paths+=("$path")
}
fetch() { job "$1" "$download" "https://127.0.0.1:$port/$1" "$tmp/f/$1.got"; } # fetch <path>: download.sh; $tmp/f/<path>.got
probe() { # probe <path>: a plain curl, with the options of download.sh but no retry
  job "$1" curl --proto '=https' --tlsv1.2 -fSL --no-progress-meter -o "$tmp/f/$1.got" "https://127.0.0.1:$port/$1"
}
collect() { # collect: waits for each job, and writes its status to $tmp/f/<path>.rc
  local i rc
  for i in "${!pids[@]}"; do
    rc=0
    wait "${pids[i]}" || rc=$?
    echo "$rc" > "$tmp/f/${paths[i]}.rc"
  done
  pids=()
  paths=()
}
# ci/reaper.py runs this suite's runs of itself: it waits for every process
# a run leaves, and kills them all when this suite ends, however it ends.
reaper="$here/reaper.py"
# nest <NAME=value> <dir> <VAR=value>...: start this suite again in the
# background ($pid) as gate.sh runs it (a non-interactive bash under `flock -o`
# on <dir>/gate.lock), inside a plain flock on <dir>/inherited.lock whose
# descriptor its processes inherit, through the reaper (30 s), with the
# variables given and its TMPDIR $tmp/t, which the cleanup removes whatever the
# run leaves; its output in <dir>/out. Its processes carry the first variable.
nest() {
  local marked=$1 dir=$2
  shift 2
  mkdir -p "$dir" "$tmp/t"
  env "$marked" TMPDIR="$tmp/t" "$@" python3 -I "$reaper" "$$" 30 \
    flock "$dir/inherited.lock" flock -o "$dir/gate.lock" "$self" > "$dir/out" 2>&1 &
  pid=$!
}
# LICKETYSYNC_TEST_DOWNLOAD_STOP=<fifo>: a download and a plain curl that the
# server holds; once it holds both, this suite names its PID and its directory
# on the fifo and waits for them. With LICKETYSYNC_TEST_DOWNLOAD_RELEASE=<fifo>
# as well, a foreground command names them instead, and ends when a line comes
# on the second fifo. The runs of this suite by itself, at the end, then stop
# it by a signal.
if [ -n "${LICKETYSYNC_TEST_DOWNLOAD_STOP:-}" ]; then
  serve "fetched=hold probed=hold"
  fetch fetched
  probe probed
  for _ in 1 2; do
    if ! read -r -t 30 -u "${SERVER[0]}" _; then
      echo "FAIL: the server did not hold both requests within 30 s"
      exit 1
    fi
  done
  if [ -n "${LICKETYSYNC_TEST_DOWNLOAD_RELEASE:-}" ]; then
    bash -c '{ echo "$1" > "$2" && read -r _; } < "$3"' _ "$$ $tmp" "$LICKETYSYNC_TEST_DOWNLOAD_STOP" \
      "$LICKETYSYNC_TEST_DOWNLOAD_RELEASE"
  else
    echo "$$ $tmp" > "$LICKETYSYNC_TEST_DOWNLOAD_STOP"
    collect
  fi
  exit 1
fi
# LICKETYSYNC_TEST_DOWNLOAD_NEST=<fifo>: start a run of this suite by itself in
# the stop mode, as the tests at the end do, and once that run's server holds
# both requests, name this suite's PID on the fifo and wait for the run; the
# last test then kills this suite.
if [ -n "${LICKETYSYNC_TEST_DOWNLOAD_NEST:-}" ]; then
  mkfifo "$tmp/ready"
  exec {ready}<> "$tmp/ready"
  nested="LICKETYSYNC_TEST_DOWNLOAD_STOPPED=$tmp/run"
  nest "$nested" "$tmp/run" LICKETYSYNC_TEST_DOWNLOAD_STOP="$tmp/ready"
  if ! read -r -t 30 -u "$ready" _ _; then
    echo "FAIL: the run of this suite by itself did not say within 30 s that its server held both requests"
    exit 1
  fi
  echo "$$" > "$LICKETYSYNC_TEST_DOWNLOAD_NEST"
  wait "$pid"
  exit 1
fi

n=0
fails=0
check_() { # check_ <name> <command...>: ok when the command succeeds
  local name=$1
  shift
  n=$((n + 1))
  if "$@"; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    fails=$((fails + 1))
  fi
}

# --- the options download.sh passes to curl ---------------------------------
mkdir "$tmp/bin"
cat > "$tmp/bin/curl" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${STUB_ARGS:-/dev/null}"
printf '%s\n' "$*" >> "${STUB_CALLS:-/dev/null}"
# What is in the file named by -o when it exits: STUB_FILE=body (the default)
# STUB_BODY, or a made-up line; empty, an empty file; none, no file.
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then
    case ${STUB_FILE:-body} in
      body) printf '%s\n' "${STUB_BODY-a file from the stand-in curl}" > "$2" ;;
      empty) : > "$2" ;;
    esac
  fi
  shift
done
exit "${STUB_EXIT:-0}"
EOF
chmod +x "$tmp/bin/curl"
url=https://example.invalid/dir/file.tar.gz
out="$tmp/file.tar.gz"
rc=0
# run_stub <curl's exit status> <download.sh arguments...>: sets rc; the
# arguments curl got, one a line, are in $tmp/args (gone when curl did not run).
# STUB_FILE=none or empty, set before the call, says what the stand-in leaves in
# the output file.
run_stub() {
  local code=$1
  shift
  rm -f "$tmp/args"
  rc=0
  STUB_ARGS="$tmp/args" STUB_EXIT=$code PATH="$tmp/bin:$PATH" "$download" "$@" \
    > "$tmp/stub.out" 2>&1 || rc=$?
}
has_arg() { grep -qxF -- "$1" "$tmp/args"; }
no_arg() { ! has_arg "$1"; }
arg_after() { awk -v flag="$1" 'prev == flag { print; exit } { prev = $0 }' "$tmp/args"; }
arg_is() { [ "$(arg_after "$1")" = "$2" ]; } # arg_is <flag> <value>
arg_count() { # arg_count <flag>: the flag is there once, with a whole number of at least 1 after it
  [ "$(grep -cxF -- "$1" "$tmp/args")" = 1 ] && [[ $(arg_after "$1") =~ ^[1-9][0-9]*$ ]]
}
last_arg_is() { [ "$(tail -n 1 "$tmp/args")" = "$1" ]; }
curl_not_run() { [ ! -e "$tmp/args" ]; }
exit_is() { [ "$rc" = "$1" ]; }
# The longest a stuck download can take: curl starts a retry when a try fails
# less than --retry-max-time after the first began, and waits first, not
# counting the wait (1 s before the first retry, doubling: 2^(N-1) s before the
# last of N), and the try that follows takes at most --max-time. The window
# must outlast one try (or a try that times out would end the retries). That
# bound must fit the jobs that run the downloads, whose timeout-minutes are read
# from the workflows: the gitleaks job (ci.yml) runs one, and leaves 10 minutes
# for its checkout and scans; the webtransport-chrome job (nightly.yml) runs
# two, and leaves 15 of its minutes for the rest.
workflows="$here/../.github/workflows"
job_timeout() { # job_timeout <workflow file> <job>: the job's timeout-minutes, nothing when it has none
  awk -v job="$2" '
    $0 ~ "^  " job ":[[:space:]]*$" { in_job = 1; next }
    in_job && /^  [A-Za-z0-9_-]+:/ { exit }
    in_job && /^    timeout-minutes: [0-9]+[[:space:]]*$/ { print $2; exit }
  ' "$1"
}
stuck_bound() { # the bound in seconds, printed
  echo $(($(arg_after --retry-max-time) + (1 << ($(arg_after --retry) - 1)) + $(arg_after --max-time)))
}
retry_window_outlasts_a_try() { [ "$(arg_after --retry-max-time)" -gt "$(arg_after --max-time)" ]; }
retries_within_curls_backoff_cap() { [ "$(arg_after --retry)" -le 10 ]; } # 2^9 s is under curl's 10-minute cap on a wait
job_allows() { # job_allows <workflow file> <job> <seconds>: the job's timeout-minutes is a number that allows that long
  local minutes
  minutes=$(job_timeout "$workflows/$1" "$2")
  [[ $minutes =~ ^[1-9][0-9]*$ ]] && [ $((minutes * 60)) -ge "$3" ]
}
gitleaks_job_allows_the_bound() { job_allows ci.yml gitleaks $(($(stuck_bound) + 600)); }
job_ends_within_an_hour() { # job_ends_within_an_hour <workflow file> <job>: not hours: the default is 6
  local minutes
  minutes=$(job_timeout "$workflows/$1" "$2")
  [[ $minutes =~ ^[1-9][0-9]*$ ]] && [ "$minutes" -le 60 ]
}
chrome_job_allows_two_downloads() { job_allows nightly.yml webtransport-chrome $((2 * $(stuck_bound) + 900)); }
# The largest file is Chrome for Testing's chrome-linux64.zip at the version in
# ci/pins.env: 201,329,937 bytes (a HEAD request, 2026-11-09). A try must let it
# arrive at 1 MB/s or less (curl would otherwise cut a slow download that
# progresses, and start again). A bump of CHROME_FOR_TESTING changes the size:
# set it to `wc -c chrome-linux64.zip` of the new zip (the steps are in
# ci/chrome-install.sh).
chrome_zip_bytes=201329937
try_fits_chrome() { [ $(($(arg_after --max-time) * 1000000)) -ge "$chrome_zip_bytes" ]; }

run_stub 0 "$url" "$out"
check_ "curl is run, and succeeds when curl does" exit_is 0
check_ "HTTPS only (--proto =https)" arg_is --proto '=https'
check_ "TLS 1.2 or newer" has_arg --tlsv1.2
check_ "HTTP errors fail the download, errors shown, redirects followed (-fSL)" has_arg -fSL
check_ "no progress meter, but not silent (curl's notice of each retry stays in the log)" has_arg --no-progress-meter
check_ "not silent (-s would hide the notice of each retry)" no_arg -s
check_ "not silent (-fsSL would hide the notice of each retry)" no_arg -fsSL
check_ "not silent (--silent would hide the notice of each retry)" no_arg --silent
check_ "the output file is the second argument (-o)" arg_is -o "$out"
check_ "the URL is the last argument" last_arg_is "$url"
check_ "retries failures (--retry N)" arg_count --retry
check_ "retries every error, not only the transient HTTP ones (--retry-all-errors)" has_arg --retry-all-errors
check_ "retries a refused connection" has_arg --retry-connrefused
check_ "limits the retries in time (--retry-max-time N)" arg_count --retry-max-time
check_ "limits each try (--max-time N)" arg_count --max-time
check_ "limits opening a connection (--connect-timeout N)" arg_count --connect-timeout
check_ "the retry window is longer than one try" retry_window_outlasts_a_try
check_ "at most 10 retries (the doubling wait stays under curl's cap)" retries_within_curls_backoff_cap
check_ "a try is long enough for the largest download (Chrome, 201 MB) at 1 MB/s" try_fits_chrome
check_ "a stuck download ends inside the gitleaks job's timeout-minutes (ci.yml), with 10 minutes to spare" \
  gitleaks_job_allows_the_bound
check_ "the gitleaks job's timeout-minutes is at most an hour (not the 6 hours of the default)" \
  job_ends_within_an_hour ci.yml gitleaks
check_ "two stuck downloads end inside the Chrome job's timeout-minutes (nightly.yml), with 15 minutes to spare" \
  chrome_job_allows_two_downloads
check_ "does not resume a partial file (no -C, which would append)" no_arg -C
check_ "does not resume a partial file (no --continue-at)" no_arg --continue-at
check_ "does not skip the certificate check (-k)" no_arg -k
check_ "does not skip the certificate check (--insecure)" no_arg --insecure
check_ "does not write the file under its remote name (-O)" no_arg -O
out_missing() { [ ! -e "$out" ]; }
out_has_the_body() { [ "$(cat "$out")" = "a file from the stand-in curl" ]; }
said_the_url() { grep -qF "$url" "$tmp/stub.out"; }
rm -f "$out"
run_stub 0 "$url" "$out"
check_ "success: the file curl wrote is kept" out_has_the_body
rm -f "$out"
run_stub 22 "$url" "$out"
check_ "gives curl's exit status when it gives up" exit_is 22
check_ "curl gave up after writing part of a file: no file is left" out_missing
rm -f "$out"
STUB_FILE=none run_stub 0 "$url" "$out"
check_ "curl succeeds and writes no file (as curl 8.18.0 does after a Retry-After past the window): fails" exit_is 1
check_ "curl succeeds and writes no file: the message names the URL" said_the_url
check_ "curl succeeds and writes no file: no file is left" out_missing
rm -f "$out"
STUB_FILE=empty run_stub 0 "$url" "$out"
check_ "curl succeeds and writes an empty file: fails" exit_is 1
check_ "curl succeeds and writes an empty file: the message names the URL" said_the_url
check_ "curl succeeds and writes an empty file: no file is left" out_missing
echo 'a file from before' > "$out"
STUB_FILE=none run_stub 0 "$url" "$out"
check_ "a file from before is not taken for the download: fails" exit_is 1
check_ "a file from before is not taken for the download: no file is left" out_missing
# An output file whose name begins with a dash: rm needs -- to remove it, at
# each of the three places the helper removes the file (before curl runs, when
# curl fails, when curl leaves nothing).
mkdir "$tmp/dash"
start=$PWD
cd "$tmp/dash"
dash_out="$tmp/dash/-out"
dash_out_missing() { [ ! -e "$dash_out" ]; }
dash_out_has_the_body() { [ "$(cat "$dash_out")" = "a file from the stand-in curl" ]; }
echo 'a file from before' > ./-out
run_stub 0 "$url" -out
check_ "an output file named -out: a file from before is removed, the download kept" exit_is 0
check_ "an output file named -out: the file is the stand-in's body" dash_out_has_the_body
run_stub 22 "$url" -out
check_ "an output file named -out: curl gave up, curl's exit status" exit_is 22
check_ "an output file named -out: curl gave up after writing part of a file, no file is left" dash_out_missing
STUB_FILE=empty run_stub 0 "$url" -out
check_ "an output file named -out: curl wrote an empty file, fails" exit_is 1
check_ "an output file named -out: curl wrote an empty file, the message names the URL" said_the_url
check_ "an output file named -out: curl wrote an empty file, no file is left" dash_out_missing
cd "$start"
run_stub 0
check_ "refused: no arguments" exit_is 2
check_ "refused: no arguments, curl not run" curl_not_run
run_stub 0 "$url"
check_ "refused: no output file" exit_is 2
check_ "refused: no output file, curl not run" curl_not_run
run_stub 0 "$url" "$out" extra
check_ "refused: a third argument" exit_is 2
check_ "refused: a third argument, curl not run" curl_not_run
run_stub 0 http://example.invalid/file "$out"
check_ "refused: an http:// URL" exit_is 2
check_ "refused: an http:// URL, curl not run" curl_not_run
run_stub 0 file:///etc/hostname "$out"
check_ "refused: a file:// URL" exit_is 2
check_ "refused: a file:// URL, curl not run" curl_not_run
run_stub 0 --config=/etc/hostname "$out"
check_ "refused: a URL that is an option" exit_is 2
check_ "refused: a URL that is an option, curl not run" curl_not_run
run_stub 0 "" "$out"
check_ "refused: an empty URL" exit_is 2
check_ "refused: an empty URL, curl not run" curl_not_run
check_ "the script is executable" test -x "$download"

# The two install scripts call it, with the URL and then the file they check.
# The stand-in curl delivers a made-up file, not the pinned one, so each script
# fails at its SHA-256 check, after the calls this looks at (one line a call,
# the arguments in it).
pin() { sed -n "s/^$1=//p" "$here/pins.env"; }
run_install() { # run_install <script>: sets rc; the calls curl got are in $tmp/calls
  rm -f "$tmp/calls"
  rc=0
  STUB_CALLS="$tmp/calls" PATH="$tmp/bin:$PATH" "$here/$1" "$tmp/dest" > "$tmp/install.out" 2>&1 || rc=$?
}
called_with() { # called_with <file name> <URL>: a call has -o <path>/<file name>, then the URL, last
  local line
  while IFS= read -r line; do
    [[ $line == *" -o /"*"/$1 $2" ]] && return 0
  done < "$tmp/calls"
  return 1
}
ncalls_are() { [ "$(wc -l < "$tmp/calls")" -eq "$1" ]; }
all_retry() { ! grep -qv -- ' --retry [1-9]' "$tmp/calls"; } # no call lacks --retry N
v=$(pin GITLEAKS)
run_install gitleaks-install.sh
check_ "gitleaks-install.sh downloads once" ncalls_are 1
check_ "gitleaks-install.sh's download retries" all_retry
check_ "gitleaks-install.sh downloads the pinned release to a file named for it" \
  called_with "gitleaks_${v}_linux_x64.tar.gz" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_linux_x64.tar.gz"
v=$(pin CHROME_FOR_TESTING)
run_install chrome-install.sh
check_ "chrome-install.sh downloads twice" ncalls_are 2
check_ "chrome-install.sh's downloads retry" all_retry
check_ "chrome-install.sh downloads the pinned Chrome" called_with chrome-linux64.zip \
  "https://storage.googleapis.com/chrome-for-testing-public/$v/linux64/chrome-linux64.zip"
check_ "chrome-install.sh downloads the pinned chromedriver" called_with chromedriver-linux64.zip \
  "https://storage.googleapis.com/chrome-for-testing-public/$v/linux64/chromedriver-linux64.zip"

# The SHA-256 checks still follow the downloads. The stand-in delivers a file of
# a body chosen here; scripts copied beside a pins.env whose hash is that file's
# get past the check (and fail at the next step, not a real archive), and with
# the hash of another file they are refused and install nothing. The two Chrome
# zips are tried one at a time.
body='the file the stand-in delivers'
good=$(printf '%s\n' "$body" | sha256sum | cut -d ' ' -f 1)
bad=$(printf '%s' "$good" | tr '0-9a-f' '1-9a-f0')
mkdir "$tmp/ci2"
cp "$here/download.sh" "$here/check-pins.sh" "$here/gitleaks-install.sh" "$here/chrome-install.sh" "$tmp/ci2/"
install_with_pins() { # install_with_pins <script> <KEY=value>...: sets rc; $tmp/ci2/pins.env has those values
  local script=$1 kv
  shift
  cp "$here/pins.env" "$tmp/ci2/pins.env"
  for kv; do sed -i "s/^${kv%%=*}=.*/$kv/" "$tmp/ci2/pins.env"; done
  rm -rf "$tmp/dest"
  rc=0
  STUB_BODY="$body" PATH="$tmp/bin:$PATH" "$tmp/ci2/$script" "$tmp/dest" > "$tmp/install.out" 2>&1 || rc=$?
}
passed_sha256() { grep -q ': OK$' "$tmp/install.out" && ! grep -q 'FAILED' "$tmp/install.out"; }
refused_by_sha256() { # refused_by_sha256 <file name>: that file failed, the script stopped, nothing was installed
  grep -q "$1: FAILED$" "$tmp/install.out" && [ "$rc" != 0 ] && [ ! -e "$tmp/dest" ]
}
install_with_pins gitleaks-install.sh "GITLEAKS_LINUX_X64_SHA256=$good"
check_ "gitleaks-install.sh: the tarball with the pinned hash passes the SHA-256 check" passed_sha256
install_with_pins gitleaks-install.sh "GITLEAKS_LINUX_X64_SHA256=$bad"
check_ "gitleaks-install.sh: a tarball with another hash is refused" refused_by_sha256 _linux_x64.tar.gz
install_with_pins chrome-install.sh "CHROME_LINUX64_SHA256=$good" "CHROMEDRIVER_LINUX64_SHA256=$good"
check_ "chrome-install.sh: both zips with their pinned hashes pass the SHA-256 checks" passed_sha256
install_with_pins chrome-install.sh "CHROME_LINUX64_SHA256=$bad" "CHROMEDRIVER_LINUX64_SHA256=$good"
check_ "chrome-install.sh: a Chrome zip with another hash is refused" refused_by_sha256 chrome-linux64.zip
install_with_pins chrome-install.sh "CHROME_LINUX64_SHA256=$good" "CHROMEDRIVER_LINUX64_SHA256=$bad"
check_ "chrome-install.sh: a chromedriver zip with another hash is refused" refused_by_sha256 chromedriver-linux64.zip

# --- the real curl against a server that fails, then answers the file -------
exit_of() { [ "$(cat "$tmp/f/$1.rc")" = "$2" ]; }                  # exit_of <path> <status>
failed_by_itself() { # failed_by_itself <path>: a failure of download.sh or curl, not of the timeout around them
  local status
  status=$(cat "$tmp/f/$1.rc")
  # timeout(1)'s own statuses: 124 it killed the command, 125 it failed itself, 126 the
  # command could not be run, 127 it was not found (also env's, when timeout is not
  # there), 137 it was killed. None is a status of download.sh (curl's, 1 or 2) or of curl.
  case $status in
    0 | 124 | 125 | 126 | 127 | 137) return 1 ;;
    *) return 0 ;;
  esac
}
got_the_file() { cmp -s "$tmp/f/$1.got" "$tmp/body"; }              # got_the_file <path>: the file, whole and nothing else
got_no_file() { [ ! -e "$tmp/f/$1.got" ]; }                         # got_no_file <path>
got_part_of_the_file() { # got_part_of_the_file <path>: something, but less than the file
  [ -s "$tmp/f/$1.got" ] && [ "$(wc -c < "$tmp/f/$1.got")" -lt "$(wc -c < "$tmp/body")" ]
}
requests_are() { [ "$(grep -c "^$1 " "$tmp/requests")" -eq "$2" ]; } # requests_are <path> <number>
said() { grep -q "$2" "$tmp/f/$1.out"; }                             # said <path> <text in the log>

not() { ! "$@"; }
for status in 0 1 2 22 28 124 125 126 127 137; do echo "$status" > "$tmp/f/status-$status.rc"; done
check_ "a status of 0 is not a failure by itself" not failed_by_itself status-0
check_ "the status 1 is a failure by itself" failed_by_itself status-1
check_ "the status 2 is a failure by itself" failed_by_itself status-2
check_ "curl's status 22 is a failure by itself" failed_by_itself status-22
check_ "curl's status 28 is a failure by itself" failed_by_itself status-28
check_ "the status 124, the kill of the timeout, is not a failure by itself" not failed_by_itself status-124
check_ "the status 125, the failure of the timeout itself, is not a failure by itself" not failed_by_itself status-125
check_ "the status 126, a command that could not be run, is not a failure by itself" not failed_by_itself status-126
check_ "the status 127, a timeout or a command that is not there, is not a failure by itself" not failed_by_itself status-127
check_ "the status 137, a kill by SIGKILL, is not a failure by itself" not failed_by_itself status-137
check_ "timeout(1) is its path when that is there" test "$(timeout_for /bin/sh)" = /bin/sh
check_ "timeout(1) is the one on PATH when its path is not there" test "$(timeout_for "$tmp/no/such/timeout")" = timeout
check_ "the timeout the cases run under can be run" "$tmo" 5 true

# as_ci itself, under a caller that ignores SIGINT, blocks SIGTERM and passes
# descriptor 7 on: the signals ignored and blocked (masks in hex) and the
# descriptors that grep and ls see without it and through it (3 is ls's own),
# and the parent-death signal a command gets through it (15, SIGTERM).
caller='
import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_IGN)
for s in signal.SIGPIPE, signal.SIGXFSZ:
    signal.signal(s, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.execvp(sys.argv[1], sys.argv[1:])
'
pdeathsig='
import ctypes
s = ctypes.c_int()
ctypes.CDLL(None).prctl(2, ctypes.byref(s), 0, 0, 0)  # PR_GET_PDEATHSIG
print("parent-death signal", s.value)
'
sees() { # sees <launcher...>: what a command sees through it, printed
  python3 -I -c "$caller" "$@" grep -E '^Sig(Blk|Ign):' /proc/self/status 7< /dev/null
  python3 -I -c "$caller" "$@" ls /proc/self/fd 7< /dev/null
  python3 -I -c "$caller" "$@" python3 -I -c "$pdeathsig" 7< /dev/null
}
# (in files, not $(...): as_ci's parent must be this suite, not a subshell)
sees env > "$tmp/bare" || true
sees python3 -I "$as_ci" "$$" > "$tmp/clean" 2>&1 || true
blocked=$(sed -n 's/^SigBlk:\t//p' "$tmp/bare")
ignored=$(sed -n 's/^SigIgn:\t//p' "$tmp/bare")
caller_as_meant() { (((0x${blocked:-0} & 0x4000) && (0x${ignored:-0} & 0x2))) && grep -qx 7 "$tmp/bare"; }
check_ "the caller of the next check ignores SIGINT, blocks SIGTERM and passes descriptor 7 on" caller_as_meant
clean_start() {
  [ "$(cat "$tmp/clean")" = $'SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n0\n1\n2\n3\nparent-death signal 15' ] ||
    { sed 's/^/  | /' "$tmp/clean" && false; }
}
check_ "as_ci starts its command with no signal ignored or blocked, no descriptor but 0 to 2, and SIGTERM when the suite ends" \
  clean_start
# A subshell is not this suite: as_ci refuses, and runs nothing.
(
  rc=0
  python3 -I "$as_ci" "$$" touch "$tmp/ran" 2> "$tmp/refused" || rc=$?
  echo "$rc" > "$tmp/refused.rc"
)
refused() { [ "$(cat "$tmp/refused.rc")" = 125 ] && [ ! -e "$tmp/ran" ] && grep -q 'its parent is not the suite' "$tmp/refused"; }
check_ "as_ci refuses a command whose parent is not the suite (status 125), and runs nothing" refused
# So does ci/reaper.py.
(
  rc=0
  python3 -I "$reaper" "$$" 5 touch "$tmp/reaped" 2> "$tmp/reaper-refused" || rc=$?
  echo "$rc" > "$tmp/reaper-refused.rc"
)
reaper_refused() {
  [ "$(cat "$tmp/reaper-refused.rc")" = 125 ] && [ ! -e "$tmp/reaped" ] &&
    grep -q "its parent is not the suite" "$tmp/reaper-refused"
}
check_ "ci/reaper.py refuses a command whose parent is not the suite (status 125), and runs nothing" reaper_refused
# Under a caller that ignores SIGHUP, SIGINT, SIGQUIT, SIGALRM and SIGTERM and
# blocks SIGTERM, ci/reaper.py starts its command with every signal the caller
# ignored still ignored but four, back at their defaults: Python's own SIGPIPE
# and SIGXFSZ, and SIGALRM and SIGTERM, which the reaper handles itself; and no
# signal blocked (masks in hex). What the caller ignores is read through it
# alone (Python's SIGPIPE and SIGXFSZ included).
ignoring='
import os, signal, sys
for s in signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGALRM, signal.SIGTERM:
    signal.signal(s, signal.SIG_IGN)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.execvp(sys.argv[1], sys.argv[1:])
'
python3 -I -c "$ignoring" grep -E '^SigIgn:' /proc/self/status > "$tmp/ignoring" 2>&1 || true
python3 -I -c "$ignoring" python3 -I "$reaper" "$$" 30 grep -E '^Sig(Blk|Ign):' /proc/self/status \
  > "$tmp/reaped-signals" 2>&1 || true
caller_ignores=$(sed -n 's/^SigIgn:\t//p' "$tmp/ignoring")
# SIGHUP, SIGINT and SIGQUIT are bits 0 to 2 (0x7), SIGALRM bit 13 (0x2000)
# and SIGTERM bit 14 (0x4000).
ignoring_as_meant() { (((0x${caller_ignores:-0} & 0x6007) == 0x6007)); }
check_ "the caller of the next check ignores SIGHUP, SIGINT, SIGQUIT, SIGALRM and SIGTERM" ignoring_as_meant
reaper_signals() { # the four it resets: SIGPIPE 0x1000, SIGALRM 0x2000, SIGTERM 0x4000, SIGXFSZ 0x1000000
  local want
  want=$(printf '%016x' $((0x${caller_ignores:-0} & ~0x1007000)))
  [ "$(cat "$tmp/reaped-signals")" = "$(printf 'SigBlk:\t%016x\nSigIgn:\t%s' 0 "$want")" ] ||
    { echo "  expected SigIgn $want:" && sed 's/^/  | /' "$tmp/reaped-signals" && false; }
}
check_ "ci/reaper.py passes on its caller's ignored signals but SIGPIPE, SIGXFSZ, SIGALRM and SIGTERM; blocks none" \
  reaper_signals
# At its time limit (SIGALRM, sent here rather than waited for) ci/reaper.py
# stops and kills every process of its run, as at SIGTERM, and ends with
# status 142: here a bash and the child it forked, which never end by
# themselves. It first writes a line for each to its standard error.
nested="LICKETYSYNC_TEST_DOWNLOAD_ALARM=$tmp"
mkfifo "$tmp/alarm-ready" "$tmp/alarm-blocked"
exec {ready}<> "$tmp/alarm-ready"
env "$nested" python3 -I "$reaper" "$$" 300 bash -c 'cat <> "$1" & echo started > "$2"; wait' _ \
  "$tmp/alarm-blocked" "$tmp/alarm-ready" > "$tmp/alarm-out" 2>&1 &
pid=$!
started=''
read -r -t 30 -u "$ready" started || true
exec {ready}<&-
kill -ALRM "$pid" 2> /dev/null || true
rc=0
wait "$pid" 2> /dev/null || rc=$?
left=$(survivors "$nested")
nested=
alarm_ends_the_run() {
  [ "$started" = started ] && [ "$rc" = 142 ] &&
    { [ -z "$left" ] || { printf '  still running after it ended (now killed):\n%s\n' "$left" && false; }; }
}
check_ "at its time limit ci/reaper.py kills every process of its run, and ends with status 142" alarm_ends_the_run
alarm_names_them() { # a line for the bash, and one for its child
  [ "$(grep -c '^reaper: still running 300 s after it started, now killed: [0-9]* .' "$tmp/alarm-out")" = 2 ] &&
    grep -q '^reaper: still running 300 s after it started, now killed: [0-9]* bash -c ' "$tmp/alarm-out" ||
    { sed 's/^/  | /' "$tmp/alarm-out" && false; }
}
check_ "at its time limit ci/reaper.py names each process it kills, by PID and command line" alarm_names_them

before=$fails
serve "err504=504,200 err404=404,200 cut=cut,200 hangup=empty,200 late=503/100000 part=cut"
fetch err504
fetch err404
fetch cut
fetch hangup
fetch late
probe part
collect
stop
left=$(survivors "$mark")
nothing_left() { [ -z "$left" ] || { printf '  still running (now killed):\n%s\n' "$left" && false; }; }
check_ "the server and the downloads leave no process running" nothing_left
check_ "a 504 is retried: exit 0" exit_of err504 0
check_ "a 504 is retried: the file arrives whole" got_the_file err504
check_ "a 504 is retried: two requests, the 504 and the file" requests_are err504 2
check_ "a 504 is retried: the log shows curl's notice of the retry" said err504 'Will retry\|Retrying in'
check_ "a 404 is retried (--retry-all-errors): exit 0" exit_of err404 0
check_ "a 404 is retried: the file arrives whole" got_the_file err404
check_ "a 404 is retried: two requests" requests_are err404 2
check_ "a plain curl keeps the part of a body cut off (so the next case shows what a retry does with it)" got_part_of_the_file part
check_ "a body cut off is retried: exit 0" exit_of cut 0
check_ "a body cut off is retried: the file is the whole file, not the part and the file" got_the_file cut
check_ "a body cut off is retried: two requests" requests_are cut 2
check_ "a connection closed with no reply is retried: exit 0" exit_of hangup 0
check_ "a connection closed with no reply is retried: the file arrives whole" got_the_file hangup
check_ "a connection closed with no reply is retried: two requests" requests_are hangup 2
check_ "a Retry-After past the retry window is a failure (curl 8.18.0 exits 0), not a timeout's kill" \
  failed_by_itself late
check_ "a Retry-After past the retry window leaves no file" got_no_file late
check_ "a Retry-After past the retry window is not waited out: one request" requests_are late 1
check_ "the ci-scripts job (ci.yml) has a timeout-minutes of at most an hour (not the 6 hours of the default)" \
  job_ends_within_an_hour ci.yml ci-scripts
check_ "the ci-scripts job's timeout-minutes allows these cases their $fetch_seconds seconds, with 5 minutes to spare" \
  job_allows ci.yml ci-scripts $((fetch_seconds + 300))
# What a failed run shows: whatever each case's helper or curl said, what the server was
# asked, and the curl that ran (the `late` case needs one with the Retry-After check).
failure_dump() {
  local f
  for f in "$tmp"/f/*.out; do
    echo "--- ${f##*/} (download.sh or curl said):"
    cat "$f"
  done
  echo "--- the server was asked:"
  cat "$tmp/requests"
  echo "--- the curl that ran:"
  curl --version | head -n 1 || true
}
dump_names_the_curl() { # the dump is taken whole first: grep -q on a pipe could end the dump with SIGPIPE
  local dump
  dump=$(failure_dump) && grep -qxF -- "$(curl --version | head -n 1)" <<< "$dump"
}
check_ "the dump of a failed run names the curl (its first line of --version)" dump_names_the_curl
if [ "$fails" != "$before" ]; then
  failure_dump
fi

# --- ci/check-downloads.sh ---------------------------------------------------
# case_ <name> <expected exit> <path>=<body>...: a tree with ci/download.sh
# (an empty file) and the files given, and the check run on it.
case_() {
  local name=$1 want=$2 dir="$tmp/tree/$((n + 1))" rc=0 spec
  shift 2
  mkdir -p "$dir/ci"
  : > "$dir/ci/download.sh"
  for spec in "$@"; do
    mkdir -p "$dir/$(dirname "${spec%%=*}")"
    printf '%s\n' "${spec#*=}" > "$dir/${spec%%=*}"
  done
  "$check" "$dir" > "$dir/out" 2>&1 || rc=$?
  n=$((n + 1))
  # a failure counts only when it is the finding (its message), not some other error
  if [ "$rc" = "$want" ] && { [ "$want" = 0 ] || grep -q 'call curl or wget on their own' "$dir/out"; }; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
this_repository() {
  "$check" > "$tmp/out" 2>&1 || {
    cat "$tmp/out"
    return 1
  }
}
check_ "passes: this repository (every download goes through ci/download.sh)" this_repository
case_ "passes: a script that calls ci/download.sh" 0 \
  'ci/a.sh=ci/download.sh "https://example.invalid/x" "$tmp/x"'
case_ "passes: curl in a comment" 0 \
  'ci/a.sh=# curl -fsSLO https://example.invalid/x'
case_ "passes: curl in an indented comment" 0 \
  'ci/a.sh=    # wget https://example.invalid/x'
case_ "passes: curl in a comment in a workflow" 0 \
  '.github/workflows/w.yml=      # curl is not run here'
case_ "passes: curl in ci/test-*.sh (stand-ins)" 0 \
  'ci/test-a.sh=curl https://example.invalid/x' 'ci/a.sh=true'
case_ "passes: curl in ci/download.sh itself" 0 \
  'ci/download.sh=curl --retry 8 -o "$2" "$1" || rc=$?' 'ci/a.sh=true'
case_ "passes: libcurl, curl-config and wgetrc are other words" 0 \
  'ci/a.sh=libcurl-dev libcurl curl-config wgetrc ci/curl-note.txt x.curl'
case_ "fails: a script that calls curl" 1 \
  'ci/a.sh=curl --proto "=https" -fsSL -o "$tmp/x" https://example.invalid/x'
case_ "fails: a script that calls wget" 1 \
  'ci/a.sh=wget -O "$tmp/x" https://example.invalid/x'
case_ "fails: curl indented in a function" 1 \
  $'ci/a.sh=f() {\n  curl -fsSL https://example.invalid/x\n}'
case_ "fails: curl by its path" 1 \
  'ci/a.sh=/usr/bin/curl -fsSL https://example.invalid/x'
case_ "fails: curl after command" 1 \
  'ci/a.sh=command curl -fsSL https://example.invalid/x'
case_ "fails: curl in a command substitution" 1 \
  'ci/a.sh=x=$(curl -fsSL https://example.invalid/x)'
case_ "fails: curl piped into" 1 \
  'ci/a.sh=echo x | curl -d @- https://example.invalid/x'
case_ "fails: curl after a semicolon" 1 \
  'ci/a.sh=true; curl https://example.invalid/x'
case_ "fails: curl quoted" 1 \
  'ci/a.sh="curl" https://example.invalid/x'
case_ "fails: curl on the line after a comment" 1 \
  $'ci/a.sh=# fetch it\ncurl https://example.invalid/x'
case_ "fails: curl in gate.sh" 1 \
  'gate.sh=curl https://example.invalid/x'
case_ "fails: curl in a workflow run step" 1 \
  '.github/workflows/w.yml=      - run: curl -fsSL https://example.invalid/x | sh'
case_ "fails: curl in a .yaml workflow" 1 \
  '.github/workflows/w.yaml=        curl https://example.invalid/x'
case_ "fails: curl in a comment after code (fails closed)" 1 \
  'ci/a.sh=true # curl'
case_ "fails: a script that calls curl, beside one that does not" 1 \
  'ci/a.sh=ci/download.sh u f' 'ci/b.sh=curl u'
# built by hand: case_ always makes ci/download.sh and a file to scan
n=$((n + 1))
dir="$tmp/tree/helper-missing"
mkdir -p "$dir/ci"
echo true > "$dir/ci/a.sh"
if ! "$check" "$dir" > "$dir/out" 2>&1 && grep -q 'ci/download.sh is missing' "$dir/out"; then
  echo "ok   fails: a tree with no ci/download.sh"
else
  echo "FAIL a tree with no ci/download.sh: passed or failed for another reason"
  cat "$dir/out"
  fails=$((fails + 1))
fi
n=$((n + 1))
dir="$tmp/tree/nothing-to-scan"
mkdir -p "$dir/ci"
: > "$dir/ci/download.sh"
if ! "$check" "$dir" > "$dir/out" 2>&1 && grep -q 'no script or workflow to check' "$dir/out"; then
  echo "ok   fails: a tree with nothing to check"
else
  echo "FAIL a tree with nothing to check: passed or failed for another reason"
  cat "$dir/out"
  fails=$((fails + 1))
fi
# a file grep cannot read stops the check: it is not "no match"
n=$((n + 1))
dir="$tmp/tree/unreadable"
mkdir -p "$dir/ci"
: > "$dir/ci/download.sh"
echo true > "$dir/ci/a.sh"
chmod 000 "$dir/ci/a.sh"
rc=0
"$check" "$dir" > "$dir/out" 2>&1 || rc=$?
if [ -r "$dir/ci/a.sh" ]; then
  echo "ok   (skipped: this user can read a file with mode 000, so there is no unreadable one)"
elif [ "$rc" != 0 ] && grep -q 'Permission denied' "$dir/out"; then
  echo "ok   fails: a script it cannot read"
else
  echo "FAIL a script it cannot read: exit $rc, expected a failure that says why"
  cat "$dir/out"
  fails=$((fails + 1))
fi
n=$((n + 1))
if "$check" "$tmp/no-such-directory" > "$tmp/out" 2>&1; then
  echo "FAIL a missing directory: passed"
  fails=$((fails + 1))
else
  echo "ok   fails: a missing directory"
fi

# The server and the downloads left running by a stopped suite: stopped while
# it downloaded, by SIGKILL the suite left the server running for good, and by
# SIGTERM the downloads for up to a minute, and they held every descriptor it
# had inherited, a caller's lock among them. So the suite runs itself (nest,
# above, with SIGINT ignored and under two locks), and once the server holds a
# download and a plain curl (the stop mode), it is stopped by SIGTERM, then by
# SIGKILL. The run must end by that signal, leave no process running and both
# locks free, run none of the other groups' cases (so that it holds the
# requests within seconds, however loaded the machine) and make its directory
# under its TMPDIR; stopped by SIGTERM, remove it. Before the SIGTERM the test
# stops (SIGSTOP) the server and the downloads, so that the EXIT trap's kill
# must end them before the suite ends: a stopped process ends at SIGKILL only,
# and the SIGTERM it gets once the suite has ended waits until something
# continues it. The processes of each run carry a variable of their own, so
# that the cleanup ends them when this suite is stopped.
bug="the server and the downloads left running by a stopped suite"
for sig in TERM KILL; do
  n=$((n + 1))
  mkfifo "$tmp/ready-$sig"
  exec {ready}<> "$tmp/ready-$sig"
  nested="LICKETYSYNC_TEST_DOWNLOAD_STOPPED=$tmp/$sig"
  nest "$nested" "$tmp/$sig" LICKETYSYNC_TEST_DOWNLOAD_STOP="$tmp/ready-$sig"
  suite='' dir='' stopped=()
  read -r -t 30 -u "$ready" suite dir || true
  exec {ready}<&-
  if [ -n "$suite" ]; then
    if [ "$sig" = TERM ]; then
      while IFS= read -r file; do
        file=${file#/proc/}
        stopped+=("${file%/environ}")
      done < <(grep -lxzF -- "LICKETYSYNC_TEST_DOWNLOAD_RUN=$dir" /proc/[0-9]*/environ 2> /dev/null || true)
      [ "${#stopped[@]}" = 0 ] || kill -STOP "${stopped[@]}" 2> /dev/null || true
    fi
    kill "-$sig" "$suite" 2> /dev/null || true
  fi
  rc=0
  wait "$pid" 2> /dev/null || rc=$?
  held=''
  for lock in gate inherited; do
    flock -n "$tmp/$sig/$lock.lock" true || held="$held $lock.lock"
  done
  left=$(survivors "$nested")
  nested=
  want=$((128 + $(kill -l "$sig")))
  why=''
  [ -n "$suite" ] || why="; it did not say within 30 s that the server held both requests"
  [ "$sig" != TERM ] || [ "${#stopped[@]}" != 0 ] || [ -z "$suite" ] || why="$why; nothing of its third group to stop"
  [ "$sig" != TERM ] || [ -z "$dir" ] || [ ! -e "$dir" ] || why="$why; its directory is still there"
  [ -z "$dir" ] || [[ $dir == "$tmp/t/"* ]] || why="$why; its directory is not under its TMPDIR, $tmp/t"
  [ "$rc" != 142 ] || why="$why; still running 30 s after it started"
  ! grep -q "^ok " "$tmp/$sig/out" || why="$why; it ran the other groups' cases first"
  if [ -z "$why" ] && [ "$rc" = "$want" ] && [ -z "$held" ] && [ -z "$left" ]; then
    echo "ok   stopped by SIG$sig mid-download under two locks with SIGINT ignored, the suite leaves no process" \
      "running and frees both locks ($bug)"
  else
    echo "FAIL stopped by SIG$sig mid-download under two locks with SIGINT ignored ($bug): exit $rc, expected" \
      "$want${held:+; still held:$held}$why"
    [ -z "$left" ] || printf '  still running after it ended (now killed):\n%s\n' "$left"
    { grep -v '^ok ' "$tmp/$sig/out" || true; } | sed 's/^/  | /'
    fails=$((fails + 1))
  fi
done

# SIGINT while a foreground command runs (the stop mode's other form): bash
# holds it until the command ends, which this test brings about after the
# signal, and then the INT trap ends the suite by SIGINT, its processes killed
# and its directory removed; without the trap, bash would drop the signal and
# go on. The run starts through as_ci, so that SIGINT is not ignored.
n=$((n + 1))
mkdir -p "$tmp/INT" "$tmp/t"
mkfifo "$tmp/ready-INT" "$tmp/release-INT"
exec {ready}<> "$tmp/ready-INT" {release}<> "$tmp/release-INT"
nested="LICKETYSYNC_TEST_DOWNLOAD_STOPPED=$tmp/INT"
env "$nested" LICKETYSYNC_TEST_DOWNLOAD_STOP="$tmp/ready-INT" LICKETYSYNC_TEST_DOWNLOAD_RELEASE="$tmp/release-INT" \
  TMPDIR="$tmp/t" python3 -I "$as_ci" "$$" "$self" > "$tmp/INT/out" 2>&1 &
pid=$!
suite='' dir=''
read -r -t 30 -u "$ready" suite dir || true
if [ -n "$suite" ]; then
  kill -INT "$suite" 2> /dev/null || true
else
  kill -KILL "$pid" 2> /dev/null || true
fi
echo >&"$release"
exec {ready}<&- {release}>&-
rc=0
wait "$pid" 2> /dev/null || rc=$?
left=$(survivors "$nested")
nested=
if [[ $dir == "$tmp/t/"* ]] && [ "$rc" = 130 ] && [ ! -e "$dir" ] && [ -z "$left" ]; then
  echo "ok   sent SIGINT while a foreground command runs, the suite ends by SIGINT once the command has ended," \
    "its processes killed and its files removed"
else
  echo "FAIL sent SIGINT while a foreground command runs (${dir:-none started within 30 s}): exit $rc, expected 130"
  [ -z "$left" ] || printf '  still running after it ended (now killed):\n%s\n' "$left"
  [ -z "$dir" ] || [ ! -e "$dir" ] || echo "  its directory is still there"
  { grep -v '^ok ' "$tmp/INT/out" || true; } | sed 's/^/  | /'
  fails=$((fails + 1))
fi

# A run of this suite by itself, left running when the suite was killed during
# it: the run went on until its downloads' minute was up, and held every
# descriptor the suite had, its caller's lock among them. So the suite runs
# itself (nest) in a mode where it starts such a run (the stop mode), and once
# that run's server holds its requests, it is killed (SIGKILL). The inner run's
# reaper gets SIGTERM when the suite ends and kills every process under it, so
# that nothing may be left and both locks of the outer run must be free.
n=$((n + 1))
bug="a run of this suite by itself left running when the suite was killed"
mkfifo "$tmp/ready-NEST"
exec {ready}<> "$tmp/ready-NEST"
nested="LICKETYSYNC_TEST_DOWNLOAD_NESTED=$tmp/NEST"
nest "$nested" "$tmp/NEST" LICKETYSYNC_TEST_DOWNLOAD_NEST="$tmp/ready-NEST"
outer=''
read -r -t 30 -u "$ready" outer || true
exec {ready}<&-
[ -z "$outer" ] || kill -KILL "$outer" 2> /dev/null || true
rc=0
wait "$pid" 2> /dev/null || rc=$?
held=''
for lock in gate inherited; do
  flock -n "$tmp/NEST/$lock.lock" true || held="$held $lock.lock"
done
left=$(survivors "$nested")
nested=
if [ -n "$outer" ] && [ "$rc" = 137 ] && [ -z "$held" ] && [ -z "$left" ]; then
  echo "ok   killed while it runs itself, the suite leaves no process of that run running and frees both locks ($bug)"
else
  echo "FAIL killed while it runs itself ($bug; ${outer:-its run did not start within 30 s}): exit $rc," \
    "expected 137${held:+; still held:$held}"
  [ -z "$left" ] || printf '  still running after it ended (now killed):\n%s\n' "$left"
  { grep -v '^ok ' "$tmp/NEST/out" || true; } | sed 's/^/  | /'
  fails=$((fails + 1))
fi
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
