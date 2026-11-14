#!/usr/bin/env bash
# Tests for ci/rustc-wrapper.sh, without sccache: each case sources it in a
# fresh bash under `set -euo pipefail`, in a directory of its own, with only
# the case's variables, HOME and XDG_CACHE_HOME under a temporary directory,
# and a PATH of the case's directories: one with a stand-in `sccache`, one with
# none, one with a file of that name that is not executable, one with a
# directory of that name; then one with the tools the helper runs (grep, stat,
# mkdir, chmod, wc, flock), or a variant of it. The stand-in logs each run. Its
# server is the file at SCCACHE_SERVER_UDS, holding the server's version and
# cache: `--dist-status`, when there is none, pauses as a real start does, then
# logs a start and makes it; `--show-stats --stats-format=json` reports it as
# sccache does (else the stand-in's own version and SCCACHE_DIR, as for no
# server); `--stop-server` logs a stop and removes it (not with STUB_KEEP, a
# server that answers the stop and stays); `--version` prints
# STUB_VERSION (default 0.19.0), and `--dist-status` STUB_DIST if set, else
# what sccache prints with distributed compilation off. STUB_FAIL names a
# command that fails and STUB_HANG one that never ends. A child process then
# prints the five variables the helper exports, as it inherits them. The
# assertions: the line the helper prints, what the child sees, the stand-in's
# runs ($runs_want, or by default the three of a server reached when sccache is
# used and none otherwise), and the modes, starts and stops the case names.
# Last, the helper sourced in several shells at once starts one server. Each
# case is bounded by timeout(1). Run by gate.sh and CI.
# Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -P)"
helper=$here/rustc-wrapper.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/with" "$tmp/without" "$tmp/not-executable" "$tmp/directory" "$tmp/directory/sccache" \
  "$tmp/tools" "$tmp/tools-no-flock" "$tmp/tools-no-chmod"
for t in grep stat mkdir chmod wc flock; do
  ln -s "$(type -P "$t")" "$tmp/tools/$t"
  [ "$t" = flock ] || ln -s "$(type -P "$t")" "$tmp/tools-no-flock/$t"
  [ "$t" = chmod ] || ln -s "$(type -P "$t")" "$tmp/tools-no-chmod/$t"
done
printf '#!/bin/sh\nexit 0\n' > "$tmp/tools-no-chmod/chmod"
cat > "$tmp/with/sccache" << EOF
#!/bin/sh
echo "\$*" >> "\${STUB_LOG:?}"
v=\${STUB_VERSION:-0.19.0}
[ "\${STUB_HANG:-}" != "\$1" ] || exec $(type -P tail) -f /dev/null
[ "\${STUB_FAIL:-}" != "\$1" ] || exit 1
case \$1 in
  --version) echo "sccache \$v" ;;
  --dist-status)
    if [ ! -e "\${SCCACHE_SERVER_UDS:?}" ]; then
      $(type -P sleep) 0.3
      echo start >> "\${STUB_LOG}.starts"
      echo "\$v|\$SCCACHE_DIR" > "\$SCCACHE_SERVER_UDS"
    fi
    if [ -n "\${STUB_DIST:-}" ]; then echo "\$STUB_DIST"; else echo '{"Disabled":"disabled"}'; fi ;;
  --show-stats)
    sv=\$v sd=\${SCCACHE_DIR:-}
    [ ! -e "\$SCCACHE_SERVER_UDS" ] || IFS='|' read -r sv sd < "\$SCCACHE_SERVER_UDS"
    printf '{"stats":{},"cache_location":"Local disk: \\\\"%s\\\\"","version":"%s"}\n' "\$sd" "\$sv" ;;
  --stop-server)
    [ -n "\${STUB_KEEP:-}" ] || $(type -P rm) -f "\$SCCACHE_SERVER_UDS"
    echo stop >> "\${STUB_LOG}.stops" ;;
esac
EOF
chmod +x "$tmp/with/sccache" "$tmp/tools-no-chmod/chmod"
: > "$tmp/not-executable/sccache"
reached=$'--version\n--dist-status\n--show-stats --stats-format=json'
# Each case is bounded, so a hang fails it.
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout
n=0
fails=0
# case_ <name> <PATH, under $tmp> <expected line> <expected child line, "off"
# for none of the five set> [NAME=value ...]. The helper runs in $tmp/<n>/work,
# with HOME=$tmp/<n>/home and XDG_CACHE_HOME=$tmp/<n>/xdg unless the case sets
# them, and $tools (default tools) last on PATH; $setup, when set, runs first in
# $tmp/<n>.
case_() {
  n=$((n + 1))
  local name=$1 dirs=$2 line=$3 want=$4 rc=0 out d="$tmp/$n" runs= expect_runs
  shift 4
  mkdir -p "$d/work" "$d/home"
  if [ -n "${setup:-}" ]; then
    (cd "$d" && eval "$setup")
  fi
  [ "$want" != off ] || want='unset|unset|unset|unset|unset'
  out=$(cd "$d/work" && "$tmo" 30 env -i PATH="$tmp/$dirs:$tmp/${tools:-tools}" HOME="$d/home" XDG_CACHE_HOME="$d/xdg" \
    STUB_LOG="$d/runs" "$@" "$BASH" -c '
    set -euo pipefail
    . "$1"
    "$BASH" -c '\''printf "child: %s|%s|%s|%s|%s\n" "${RUSTC_WRAPPER-unset}" "${SCCACHE_SERVER_UDS-unset}" \
      "${SCCACHE_CONF-unset}" "${SCCACHE_DIR-unset}" "${SCCACHE_IDLE_TIMEOUT-unset}"'\''
  ' _ "$helper" 2>&1) || rc=$?
  want=${want//@d/$d}
  line=${line//@d/$d}
  [ ! -f "$d/runs" ] || runs=$(cat "$d/runs")
  if [ -n "${runs_want+set}" ]; then
    expect_runs=$runs_want
  elif [[ $want == "$tmp/with/sccache|"* ]]; then
    expect_runs=$reached
  else
    expect_runs=
  fi
  if [ "$rc" = 0 ] && [ "$out" = "$line"$'\n'"child: $want" ] && [ "$runs" = "$expect_runs" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc; the stand-in ran: [${runs//$'\n'/, }], expected [${expect_runs//$'\n'/, }]; output:"
    printf '%s\n' "$out" | sed 's/^/  | /'
    echo "  expected:"
    printf '%s\n' "$line" "child: $want" | sed 's/^/  | /'
    fails=$((fails + 1))
  fi
}
# count_ <name> <file under the case's directory> <lines>: the last case left
# that many lines there (starts, stops).
count_() {
  local got
  got=$(grep -c . "$tmp/$n/$2" 2> /dev/null) || got=0
  if [ "$got" = "$3" ]; then
    echo "ok     and $1"
  else
    echo "FAIL   $1: $got, expected $3"
    fails=$((fails + 1))
  fi
}
# mode_ <name> <path> <mode>: the last case left that path with that mode.
mode_() {
  local got
  got=$(stat -c %a -- "$tmp/$n/$2" 2> /dev/null) || got=none
  if [ "$got" = "$3" ]; then
    echo "ok     and $1"
  else
    echo "FAIL   $1: mode $got, expected $3"
    fails=$((fails + 1))
  fi
}
private=@d/xdg/licketysync/sccache
on="== rustc wrapper: $tmp/with/sccache, on its own server at $private/server.sock, its cache in $private/cache"
on+=" (LICKETYSYNC_SCCACHE=0 turns it off)"
uses="$tmp/with/sccache|$private/server.sock|$here/sccache.toml|$private/cache|3600"
not_on_path="== rustc wrapper: none (sccache is not on PATH)"
not_mine() { echo "== rustc wrapper: none (@d/xdg/licketysync$1 is not a directory of this user's)"; }

# sccache found, or not
case_ "sccache on PATH: the wrapper, on a socket of its own" with "$on" "$uses"
mode_ "the socket's directory has mode 700" xdg/licketysync/sccache 700
mode_ "and so has its parent" xdg/licketysync 700
count_ "one server started" runs.starts 1
case_ "no sccache on PATH: none"                    without "$not_on_path" off
case_ "a sccache that is not executable: none"      not-executable "$not_on_path" off
case_ "a sccache directory: none"                   directory "$not_on_path" off
case_ "one not executable, then one that is: the wrapper" "not-executable:$tmp/with" "$on" "$uses"
# the server: started or reached under the lock, then its version and cache
# checked; each step bounded
stop_it="if a server stays, stop it: SCCACHE_SERVER_UDS=$private/server.sock $tmp/with/sccache --stop-server"
failed() { echo "== rustc wrapper: none (sccache: $1; $stop_it)"; }
# The setups that leave a server running, with a version and a cache.
setup="mkdir -p -m 700 xdg/licketysync/sccache && echo \"0.19.0|\$PWD/xdg/licketysync/sccache/cache\" > xdg/licketysync/sccache/server.sock"
case_ "a server of this version with this cache running (another worktree's, say): reached" with "$on" "$uses"
count_ "none started" runs.starts 0
count_ "none stopped" runs.stops 0
setup="mkdir -p -m 700 xdg/licketysync/sccache && echo \"0.18.0|\$PWD/xdg/licketysync/sccache/cache\" > xdg/licketysync/sccache/server.sock"
runs_want=$reached$'\n--stop-server\n--dist-status\n--show-stats --stats-format=json'
case_ "a server of another version (sccache upgraded): stopped, a new one started" with "$on" "$uses"
count_ "one stopped" runs.stops 1
count_ "one started" runs.starts 1
check_server() { # check_server <name> <expected first line of the server file>
  if [ "$(cut -d'|' -f1 "$tmp/$n/xdg/licketysync/sccache/server.sock" 2> /dev/null)" = "$2" ]; then
    echo "ok     and $1"
  else
    echo "FAIL   $1"
    fails=$((fails + 1))
  fi
}
check_server "the server running is of this version" 0.19.0
runs_want=$reached$'\n--stop-server\n--dist-status\n--show-stats --stats-format=json'
case_ "a server of another version that stays after its stop: none" with \
  "$(failed "its server is sccache 0.18.0, not 0.19.0")" off STUB_KEEP=1
runs_want=$reached$'\n--stop-server'
case_ "a server of another version that will not stop: none" with "$(failed "could not stop its server of sccache 0.18.0")" \
  off STUB_FAIL=--stop-server
setup="mkdir -p -m 700 xdg/licketysync/sccache && echo '0.19.0|/elsewhere' > xdg/licketysync/sccache/server.sock"
runs_want=$reached
case_ "a server on the socket with another cache: none" with "$(failed "its server keeps its cache elsewhere")" off
unset setup
runs_want='--version'
case_ "sccache --version fails: none"               with "$(failed "sccache --version failed or took over 60 s")" \
  off STUB_FAIL=--version
runs_want=$'--version\n--dist-status'
case_ "the server cannot be reached or started: none" with \
  "$(failed "could not reach or start its server within 60 s")" off STUB_FAIL=--dist-status
runs_want=$reached
case_ "its statistics cannot be read: none"         with \
  "$(failed "could not read the statistics of its server within 60 s")" off STUB_FAIL=--show-stats
case_ "the statistics never come (a hang), bounded: none" with \
  "$(failed "could not read the statistics of its server within 1 s")" off STUB_HANG=--show-stats \
  LICKETYSYNC_SCCACHE_WAIT=1
runs_want=$'--version\n--dist-status'
case_ "the start never ends (a hang), bounded: none" with \
  "$(failed "could not reach or start its server within 1 s")" off STUB_HANG=--dist-status LICKETYSYNC_SCCACHE_WAIT=1
runs_want=$'--version\n--dist-status'
case_ "a server with distributed compilation on: none" with \
  "$(failed "its server has distributed compilation on")" off STUB_DIST='{"SchedulerStatus":["http://127.0.0.1/",{}]}'
unset runs_want
# LICKETYSYNC_SCCACHE_WAIT: a positive whole number of seconds, else 60
for w in 0 -5 abc 1.5 ''; do
  case_ "LICKETYSYNC_SCCACHE_WAIT=$w: 60 instead, the wrapper" with \
    "$(printf '== rustc wrapper: LICKETYSYNC_SCCACHE_WAIT=%q is not a positive whole number of seconds; 60 instead' "$w")"$'\n'"$on" \
    "$uses" LICKETYSYNC_SCCACHE_WAIT="$w"
done
# start.lock held by another caller for longer than the wait
mkdir -p -m 700 "$tmp/$((n + 1))/xdg/licketysync" "$tmp/$((n + 1))/xdg/licketysync/sccache"
exec {held}> "$tmp/$((n + 1))/xdg/licketysync/sccache/start.lock"
flock "$held"
runs_want=
case_ "start.lock held past the wait: none"         with \
  "$(failed "another caller held @d/xdg/licketysync/sccache/start.lock for over 1 s")" off LICKETYSYNC_SCCACHE_WAIT=1
unset runs_want
exec {held}>&-
tools=tools-no-flock
case_ "no flock on PATH: none"                      with \
  "== rustc wrapper: none (flock is not on PATH, to start one sccache server)" off
unset tools
# a wrapper chosen already is kept
case_ "RUSTC_WRAPPER set: kept"                     with "== rustc wrapper: /x/w (RUSTC_WRAPPER was set)" \
  '/x/w|unset|unset|unset|unset' RUSTC_WRAPPER=/x/w
case_ "RUSTC_WRAPPER set empty (no wrapper): kept"  with "== rustc wrapper: none (RUSTC_WRAPPER was set)" \
  '|unset|unset|unset|unset' RUSTC_WRAPPER=
case_ "RUSTC_WRAPPER set, and CI: kept"             with "== rustc wrapper: /x/w (RUSTC_WRAPPER was set)" \
  '/x/w|unset|unset|unset|unset' RUSTC_WRAPPER=/x/w CI=true
case_ "CARGO_BUILD_RUSTC_WRAPPER set: no RUSTC_WRAPPER" with \
  "== rustc wrapper: /x/w (CARGO_BUILD_RUSTC_WRAPPER was set)" off CARGO_BUILD_RUSTC_WRAPPER=/x/w
case_ "CARGO_BUILD_RUSTC_WRAPPER set empty: none"   with \
  "== rustc wrapper: none (CARGO_BUILD_RUSTC_WRAPPER was set)" off CARGO_BUILD_RUSTC_WRAPPER=
# a wrapper a cargo configuration file names, or may name, is kept: cargo uses it
config() { # config <file> <its text>: the setup that writes it
  setup="mkdir -p '$(dirname "$1")' && printf '$2\\n' > '$1'"
}
own() { echo "== rustc wrapper: cargo's own (@d/$1 may name one, or include a file that does)"; }
config work/.cargo/config.toml '[build]\nrustc-wrapper = "/x/w"'
case_ "a configuration file here names rustc-wrapper: cargo's own" with "$(own work/.cargo/config.toml)" off
config .cargo/config '[build]\nrustc-wrapper = "/x/w"'
case_ "one in a directory above, the old name: cargo's own" with "$(own .cargo/config)" off
config home/.cargo/config.toml 'build.rustc-wrapper = "/x/w"'
case_ "one in CARGO_HOME, a dotted key: cargo's own" with "$(own home/.cargo/config.toml)" off
config work/.cargo/config.toml '[build]\n"rustc-wrapper" = "/x/w"'
case_ "a quoted key: cargo's own" with "$(own work/.cargo/config.toml)" off
config work/.cargo/config.toml '[build]\n"rustc\\\\u002dwrapper" = "/x/w"'
case_ "a key with an escape: cargo's own" with "$(own work/.cargo/config.toml)" off
config work/.cargo/config.toml 'include = ["more.toml"]'
case_ "an include, the list form: cargo's own" with "$(own work/.cargo/config.toml)" off
config work/.cargo/config.toml '[[include]]\npath = "more.toml"'
case_ "an include, the table form: cargo's own" with "$(own work/.cargo/config.toml)" off
config work/.cargo/config.toml '[build]\nrustc-workspace-wrapper = "/x/w"\njobs = 2'
case_ "rustc-workspace-wrapper only (cargo chains the two): the wrapper" with "$on" "$uses"
unset setup
# not in CI, and not when turned off
case_ "CI set: none"                                with "== rustc wrapper: none (CI is set)" off CI=true
case_ "CI set but empty: none"                      with "== rustc wrapper: none (CI is set)" off CI=
case_ "LICKETYSYNC_SCCACHE=0: none"                 with "== rustc wrapper: none (LICKETYSYNC_SCCACHE=0)" off \
  LICKETYSYNC_SCCACHE=0
case_ "LICKETYSYNC_SCCACHE=1: the wrapper"          with "$on" "$uses" LICKETYSYNC_SCCACHE=1
case_ "LICKETYSYNC_SCCACHE empty: the wrapper"      with "$on" "$uses" LICKETYSYNC_SCCACHE=
# sccache's own variables: three kept, SCCACHE_DIR ignored, any other turns it off
only="of sccache's variables only SCCACHE_CACHE_SIZE, SCCACHE_IDLE_TIMEOUT, SCCACHE_LOG and SCCACHE_DIR, which is ignored, may be"
case_ "SCCACHE_BUCKET (a remote cache): none"       with "== rustc wrapper: none (set: SCCACHE_BUCKET; $only)" off \
  SCCACHE_BUCKET=b
case_ "SCCACHE_SERVER_PORT (a TCP server): none"    with \
  "== rustc wrapper: none (set: SCCACHE_SERVER_PORT; $only)" off SCCACHE_SERVER_PORT=4226
case_ "SCCACHE_SERVER_UDS set before: none"         with "== rustc wrapper: none (set: SCCACHE_SERVER_UDS; $only)" \
  'unset|/x.sock|unset|unset|unset' SCCACHE_SERVER_UDS=/x.sock
case_ "SCCACHE_CONF (another config): none"         with "== rustc wrapper: none (set: SCCACHE_CONF; $only)" \
  'unset|unset|/x.toml|unset|unset' SCCACHE_CONF=/x.toml
case_ "SCCACHE_DIR set: ignored, the wrapper with its own cache" with "$on" "$uses" SCCACHE_DIR=/d
case_ "SCCACHE_CACHE_SIZE and SCCACHE_LOG: the wrapper" with "$on" "$uses" SCCACHE_CACHE_SIZE=1G SCCACHE_LOG=debug
case_ "SCCACHE_IDLE_TIMEOUT set: kept"              with "$on" "${uses%|3600}|60" SCCACHE_IDLE_TIMEOUT=60
# incremental compilation
case_ "CARGO_INCREMENTAL=1 (sccache refuses it): none" with \
  "== rustc wrapper: none (CARGO_INCREMENTAL=1, with which sccache refuses to compile)" off CARGO_INCREMENTAL=1
case_ "CARGO_INCREMENTAL=0: the wrapper"            with "$on" "$uses" CARGO_INCREMENTAL=0
case_ "CARGO_BUILD_INCREMENTAL=true: the wrapper"   with "$on" "$uses" CARGO_BUILD_INCREMENTAL=true
# the socket's directory and its parent: this user's alone, or no wrapper
case_ "a relative XDG_CACHE_HOME: ~/.cache instead" with "${on//@d\/xdg/@d\/home\/.cache}" \
  "${uses//@d\/xdg/@d\/home\/.cache}" XDG_CACHE_HOME=rel
case_ "neither XDG_CACHE_HOME nor HOME absolute: none" with \
  "== rustc wrapper: none (neither XDG_CACHE_HOME nor HOME is an absolute path, for sccache's socket)" off \
  XDG_CACHE_HOME=rel HOME=rel
setup='mkdir -p -m 755 xdg/licketysync/sccache && chmod 755 xdg/licketysync'
case_ "both directories there with mode 755: made 700, the wrapper" with "$on" "$uses"
mode_ "the socket's directory has mode 700" xdg/licketysync/sccache 700
mode_ "and its parent, too" xdg/licketysync 700
setup='mkdir -p -m 755 xdg/licketysync/sccache && chmod 755 xdg/licketysync'
tools=tools-no-chmod
case_ "a chmod that does nothing: the mode checked again, none" with \
  "== rustc wrapper: none (@d/xdg/licketysync has mode 755, not 700)" off
unset tools
setup='mkdir -p xdg/licketysync elsewhere && chmod 700 elsewhere && ln -s ../../elsewhere xdg/licketysync/sccache'
case_ "the socket's directory a symbolic link: none" with "$(not_mine /sccache)" off
setup='mkdir -p xdg elsewhere && chmod 700 elsewhere && ln -s ../elsewhere xdg/licketysync'
case_ "its parent a symbolic link: none"            with "$(not_mine '')" off
setup='mkdir -p xdg/licketysync && : > xdg/licketysync/sccache'
case_ "a file where the socket's directory goes: none" with "$(not_mine /sccache)" off
setup='mkdir -p xdg && : > xdg/licketysync'
case_ "a file where its parent goes: none"          with "$(not_mine '')" off
unset setup
long=$(printf 'd%.0s' {1..80})
case_ "a socket path too long for a Unix socket: none" with \
  "== rustc wrapper: none (@d/$long/licketysync/sccache/server.sock is too long for a Unix socket)" off \
  XDG_CACHE_HOME="$tmp/$((n + 1))/$long"
# sourced in several shells at once, with one socket's directory: one server
n=$((n + 1))
d="$tmp/$n"
mkdir -p "$d/work"
for i in 1 2 3 4 5 6; do
  (cd "$d/work" && "$tmo" 30 env -i PATH="$tmp/with:$tmp/tools" HOME="$d/home" XDG_CACHE_HOME="$d/xdg" STUB_LOG="$d/runs" \
    "$BASH" -c 'set -euo pipefail; . "$1"' _ "$helper" > "$d/out$i" 2>&1) &
done
wait
starts=$(grep -c . "$d/runs.starts" 2> /dev/null || echo 0)
if [ "$starts" = 1 ] && [ "$(grep -c -- --dist-status "$d/runs")" = 6 ] &&
  [ "$(cat "$d"/out* | grep -cxF "${on//@d/$d}")" = 6 ]; then
  echo "ok   six shells at once: each uses the wrapper, and one server starts"
else
  echo "FAIL six shells at once: $starts servers started; the stand-in ran:"
  sed 's/^/  | /' "$d/runs" "$d"/out*
  fails=$((fails + 1))
fi
if [ "$fails" -gt 0 ]; then
  echo "rustc-wrapper: $fails of $n cases failed"
  exit 1
fi
echo "rustc-wrapper: all $n cases pass"
