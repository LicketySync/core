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
# The expected exit code or file is the assertion. Needs python3 and openssl.
# Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
download="$here/download.sh"
check="$here/check-downloads.sh"
tmp=$(mktemp -d)
# The server of the third group runs as a coprocess ($SERVER_PID is set while it does).
cleanup() {
  [ -z "${SERVER_PID:-}" ] || kill "$SERVER_PID" 2> /dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
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
# Needs python3 and openssl. The server answers each path by a plan of steps, one
# a request, the last repeating: 200 is the file; another number is that status
# with a small page, and N/S adds Retry-After: S; cut is the status 200 and half
# the file, then the connection closed with no end to the TLS session; empty is
# the connection closed with no reply. It prints its port when it listens and
# logs a line a request: the path, the number of the request and its step.
cat > "$tmp/server.py" << 'EOF'
import http.server
import socket
import ssl
import sys

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
serve() { # serve <plan>: starts the server (a coprocess) and sets port
  : > "$tmp/requests"
  coproc SERVER { exec python3 -I "$tmp/server.py" "$tmp/cert.pem" "$tmp/key.pem" "$tmp/body" "$1" "$tmp/requests"; }
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
clean_env() { env -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u CURL_HOME -u XDG_CONFIG_HOME \
  HOME="$tmp/home" NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 \
  CURL_CA_BUNDLE="$tmp/cert.pem" SSL_CERT_FILE="$tmp/cert.pem" "$@"; }
pids=()
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
fetch() { # fetch <path>: download.sh from the server, in the background (pids); $tmp/f/<path>.got, .out and .rc
  (
    rc=0
    clean_env "$tmo" "$fetch_seconds" "$download" "https://127.0.0.1:$port/$1" "$tmp/f/$1.got" \
      > "$tmp/f/$1.out" 2>&1 || rc=$?
    echo "$rc" > "$tmp/f/$1.rc"
  ) &
  pids+=("$!")
}
probe() { # probe <path>: a plain curl, with the options of download.sh but no retry, in the background
  (
    rc=0
    clean_env "$tmo" "$fetch_seconds" curl --proto '=https' --tlsv1.2 -fSL --no-progress-meter \
      -o "$tmp/f/$1.got" "https://127.0.0.1:$port/$1" > "$tmp/f/$1.out" 2>&1 || rc=$?
    echo "$rc" > "$tmp/f/$1.rc"
  ) &
  pids+=("$!")
}
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

before=$fails
serve "err504=504,200 err404=404,200 cut=cut,200 hangup=empty,200 late=503/100000 part=cut"
fetch err504
fetch err404
fetch cut
fetch hangup
fetch late
probe part
wait "${pids[@]}"
stop
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
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
