# shellcheck shell=bash
# Sourced by gate.sh and ci/mutants.sh, never run: sccache as cargo's rustc
# wrapper when it is installed, on one server of its own that only this user can
# reach. sccache 0.19.0 keys a Rust compilation on its arguments other than
# paths (--out-dir, -L and --extern are left out), the contents of its sources
# and of the crates it links, every CARGO_* variable, and the working directory.
# Two trees, or two target directories set by CARGO_TARGET_DIR, so share only
# what does not hash those: the C and assembly that build scripts compile
# through the wrapper too (cc-rs), such as aws-lc-sys's; Rust only within one
# tree and target directory (cargo-geiger's rebuilds, a coverage target
# emptied). It caches no incremental compilation (the workspace's own crates in
# dev and test builds), binary or proc-macro.
#
# Kept as they are, with no sccache exported: a wrapper already chosen by
# RUSTC_WRAPPER or CARGO_BUILD_RUSTC_WRAPPER (set empty, none), or one a cargo
# configuration file may name: `rustc-wrapper`, an `include` of another file,
# or a backslash this script does not decode, in the files ci/cargo-configs.sh
# lists. Otherwise sccache is not used when CI is set, when
# LICKETYSYNC_SCCACHE=0 (the opt-out), when any SCCACHE_* variable other than
# SCCACHE_CACHE_SIZE, SCCACHE_IDLE_TIMEOUT, SCCACHE_LOG and SCCACHE_DIR is set,
# since those can name a remote cache, a TCP server or another config (a
# SCCACHE_DIR is ignored), when CARGO_INCREMENTAL=1, with which sccache 0.19.0
# refuses to compile, or when flock or timeout is missing.
# When an executable sccache is on PATH, this exports:
# - RUSTC_WRAPPER, its absolute path;
# - SCCACHE_SERVER_UDS, a Unix socket (a file, not an abstract name) in
#   $XDG_CACHE_HOME/licketysync/sccache (else ~/.cache/licketysync/sccache),
#   that directory and licketysync/ above it this user's with mode 700, so no
#   other account and no TCP port reaches the server. Without such directories,
#   or with a socket path too long for a Unix socket, sccache is not used;
# - SCCACHE_CONF, ci/sccache.toml, which names no remote cache;
# - SCCACHE_DIR, always cache/ in that directory: sccache's local cache takes
#   one server at a time (its docs/Local.md), and ~/.cache/sccache, or a user's
#   own SCCACHE_DIR, may have another, such as one on the default TCP port;
# - SCCACHE_IDLE_TIMEOUT, 3600 unless set: a server with nothing to do for an
#   hour, longer than any quiet stretch of a gate or a mutants run, exits.
# Then, holding start.lock in that directory (flock, waiting at most 60 s), it
# runs `sccache --dist-status`, which connects to the server or starts it
# (`--show-stats` starts none, and `--start-server` would start a second one
# beside a running server: it replaces the socket), so that callers at once, in
# any worktree, start one server; then reads the server's statistics, which must
# name cache/ above as a local disk cache and the version `sccache --version`
# prints; `--dist-status` must report distributed compilation disabled. A server
# of another version (an sccache upgraded since it started) is stopped and a new
# one started, still under the lock; builds of another gate that are compiling
# at that moment may then fail, never pass wrongly. Each sccache command is
# bounded to 60 s by timeout(1) (LICKETYSYNC_SCCACHE_WAIT, a positive whole
# number of seconds, else 60, shortens both for tests). When any of it fails or
# times out, or the server keeps its cache elsewhere or compiles elsewhere,
# sccache is not used, and the line printed says why and how to stop a stray
# server. sccache 0.19.0 has no way to keep a compiling client from starting a
# server of its own when none answers, so a server can start outside the lock:
# after a crash of the server, after a stop mid-build, or after it exited when
# idle (at our 3600 s, or at a SCCACHE_IDLE_TIMEOUT of the user's). Builds may
# then start more than one, and those builds may fail, never pass wrongly; each
# stray server exits after its idle timeout, and the next sourcing starts one
# under the lock again.
# It prints the wrapper in use and why, and sets nothing else. CI installs no
# sccache and sets CI. Tested by ci/test-rustc-wrapper.sh.
_licketysync_rustc_wrapper() {
  local here sccache flock base dir sock v f mode idle wait tmo why bad= configs=()
  here=${BASH_SOURCE[0]%/*}
  [ "$here" != "${BASH_SOURCE[0]}" ] || here=.
  here=$(cd "$here" && pwd -P)
  if [ -n "${RUSTC_WRAPPER+set}" ]; then
    echo "== rustc wrapper: ${RUSTC_WRAPPER:-none} (RUSTC_WRAPPER was set)"
    return
  fi
  if [ -n "${CARGO_BUILD_RUSTC_WRAPPER+set}" ]; then
    echo "== rustc wrapper: ${CARGO_BUILD_RUSTC_WRAPPER:-none} (CARGO_BUILD_RUSTC_WRAPPER was set)"
    return
  fi
  # shellcheck source=ci/cargo-configs.sh
  . "$here/cargo-configs.sh"
  cargo_configs "$(pwd -P)"
  for f in "${configs[@]}"; do
    if grep -qF '\' "$f" || grep -qE "(^|[^A-Za-z0-9_-])[\"']?(rustc-wrapper|include)[\"']?[[:space:]]*=" "$f" ||
      grep -qE "^[[:space:]]*\[+[[:space:]]*[\"']?include\b" "$f"; then
      echo "== rustc wrapper: cargo's own ($f may name one, or include a file that does)"
      return
    fi
  done
  if [ -n "${CI+set}" ]; then
    echo "== rustc wrapper: none (CI is set)"
    return
  fi
  if [ "${LICKETYSYNC_SCCACHE:-}" = 0 ]; then
    echo "== rustc wrapper: none (LICKETYSYNC_SCCACHE=0)"
    return
  fi
  for v in $(compgen -e); do
    case $v in
      SCCACHE_CACHE_SIZE | SCCACHE_IDLE_TIMEOUT | SCCACHE_LOG | SCCACHE_DIR) ;;
      SCCACHE_*) bad+=" $v" ;;
    esac
  done
  if [ -n "$bad" ]; then
    echo "== rustc wrapper: none (set:$bad; of sccache's variables only SCCACHE_CACHE_SIZE," \
      "SCCACHE_IDLE_TIMEOUT, SCCACHE_LOG and SCCACHE_DIR, which is ignored, may be)"
    return
  fi
  # sccache 0.19.0 stops every compilation when CARGO_INCREMENTAL=1
  # ("incremental compilation is prohibited"). With 0, or with
  # CARGO_BUILD_INCREMENTAL=true or false, it compiles; CARGO_BUILD_INCREMENTAL=1
  # cargo itself refuses, with or without sccache.
  if [ "${CARGO_INCREMENTAL:-}" = 1 ]; then
    echo "== rustc wrapper: none (CARGO_INCREMENTAL=1, with which sccache refuses to compile)"
    return
  fi
  sccache=$(type -P sccache) || sccache=
  if [ ! -f "$sccache" ] || [ ! -x "$sccache" ]; then
    echo "== rustc wrapper: none (sccache is not on PATH)"
    return
  fi
  flock=$(type -P flock) || flock=
  if [ -z "$flock" ]; then
    echo "== rustc wrapper: none (flock is not on PATH, to start one sccache server)"
    return
  fi
  if [[ ${XDG_CACHE_HOME:-} == /* ]]; then
    base=$XDG_CACHE_HOME
  elif [[ ${HOME:-} == /* ]]; then
    base=$HOME/.cache
  else
    echo "== rustc wrapper: none (neither XDG_CACHE_HOME nor HOME is an absolute path, for sccache's socket)"
    return
  fi
  for dir in "$base/licketysync" "$base/licketysync/sccache"; do
    mkdir -p -m 700 -- "$dir" 2> /dev/null || true
    if [ -L "$dir" ] || [ ! -d "$dir" ] || [ ! -O "$dir" ]; then
      echo "== rustc wrapper: none ($dir is not a directory of this user's)"
      return
    fi
    mode=$(stat -c %a -- "$dir" 2> /dev/null) || mode=
    [ "$mode" = 700 ] || chmod 700 -- "$dir" 2> /dev/null || true
    mode=$(stat -c %a -- "$dir" 2> /dev/null) || mode=
    if [ "$mode" != 700 ]; then
      echo "== rustc wrapper: none ($dir has mode ${mode:-unknown}, not 700)"
      return
    fi
  done
  sock=$dir/server.sock
  # A Unix socket's path holds at most 107 bytes.
  if [ "$(printf '%s' "$sock" | wc -c)" -gt 107 ]; then
    echo "== rustc wrapper: none ($sock is too long for a Unix socket)"
    return
  fi
  idle=${SCCACHE_IDLE_TIMEOUT:-3600}
  wait=60
  if [ -n "${LICKETYSYNC_SCCACHE_WAIT+set}" ]; then
    if [[ $LICKETYSYNC_SCCACHE_WAIT =~ ^[1-9][0-9]*$ ]]; then
      wait=$LICKETYSYNC_SCCACHE_WAIT
    else
      printf '== rustc wrapper: LICKETYSYNC_SCCACHE_WAIT=%q is not a positive whole number of seconds; 60 instead\n' \
        "$LICKETYSYNC_SCCACHE_WAIT"
    fi
  fi
  tmo=/usr/bin/timeout
  [ -x "$tmo" ] || tmo=$(type -P timeout) || tmo=
  if [ -z "$tmo" ]; then
    echo "== rustc wrapper: none (timeout is not on PATH, to bound the server's start)"
    return
  fi
  # The server: reached, or started, by one caller at a time (-o: the server
  # does not keep the lock), each step bounded; then its version and cache
  # checked, and a server of another sccache version replaced.
  why=$(SCCACHE_SERVER_UDS=$sock SCCACHE_CONF=$here/sccache.toml SCCACHE_DIR=$dir/cache SCCACHE_IDLE_TIMEOUT=$idle \
    "$flock" -o -w "$wait" -E 75 "$dir/start.lock" "$BASH" -c '
    tmo=$1 wait=$2 sccache=$3 cache=$4
    run() { "$tmo" "$wait" "$sccache" "$@"; }
    start() { # start: reach or start the server, which must not compile elsewhere
      local dist
      dist=$(run --dist-status 2> /dev/null) || { echo "could not reach or start its server within $wait s"; exit 1; }
      [[ $dist == "{\"Disabled\""* ]] || { echo "its server has distributed compilation on"; exit 1; }
    }
    check() { # check: set version and location from the server statistics
      local stats
      stats=$(run --show-stats --stats-format=json 2> /dev/null) || return 1
      [[ $stats =~ \"version\":\"([^\"]*)\" ]] || return 1
      version=${BASH_REMATCH[1]}
      location=other
      [[ $stats != *"\"cache_location\":\"Local disk: \\\"$cache\\\"\""* ]] || location=ours
    }
    want=$(run --version 2> /dev/null) || { echo "sccache --version failed or took over $wait s"; exit 1; }
    want=${want#sccache }
    start
    check || { echo "could not read the statistics of its server within $wait s"; exit 1; }
    if [ "$version" != "$want" ]; then
      run --stop-server > /dev/null 2>&1 || { echo "could not stop its server of sccache $version"; exit 1; }
      start
      check || { echo "could not read the statistics of its server within $wait s"; exit 1; }
      [ "$version" = "$want" ] || { echo "its server is sccache $version, not $want"; exit 1; }
    fi
    [ "$location" = ours ] || { echo "its server keeps its cache elsewhere"; exit 1; }
  ' _ "$tmo" "$wait" "$sccache" "$dir/cache" 2>&1) || {
    [ "$?" != 75 ] || why="another caller held $dir/start.lock for over $wait s"
    echo "== rustc wrapper: none (sccache: ${why:-its server could not be checked}; if a server stays," \
      "stop it: SCCACHE_SERVER_UDS=$sock $sccache --stop-server)"
    return
  }
  export RUSTC_WRAPPER=$sccache SCCACHE_SERVER_UDS=$sock SCCACHE_CONF=$here/sccache.toml
  export SCCACHE_DIR=$dir/cache SCCACHE_IDLE_TIMEOUT=$idle
  echo "== rustc wrapper: $sccache, on its own server at $sock, its cache in $SCCACHE_DIR" \
    "(LICKETYSYNC_SCCACHE=0 turns it off)"
}
_licketysync_rustc_wrapper
unset -f _licketysync_rustc_wrapper cargo_configs
