#!/usr/bin/env bash
# The cargo-geiger report, held to ci/geiger-baseline.txt: every crate's five
# used unsafe counts (functions, expressions, impls, traits, methods) must equal
# its line there, and the baseline's header says why and how to change it.
# cargo-geiger runs once per crate under crates/, because it has no --workspace
# flag, refuses the virtual workspace manifest and rejects relative paths, and
# in its own target directory ($CARGO_TARGET_DIR/geiger, or target/geiger),
# because it cleans the crate it scans and would otherwise throw away the build
# the other checks use.
#
# cargo-geiger exits 1 after any warning. It warns about every file a
# dependency compiles in that it does not scan; that exit is accepted when the
# count it prints last matches the warnings and each of them names either a
# file with a known non-Rust extension (below: documentation such as a
# README.md through include_str!, or a C or C++ source for a build script), a
# DER file of ring, rustls-webpki or rustls-pki-types in that package's own
# directory in the registry, $CARGO_HOME/registry/src/<index>/<package>-<version>/
# with <version> a semver version (the algorithm identifiers and key templates
# they embed with include_bytes!; another package's .der fails, and so does one
# in a directory of that name anywhere else, nested inside another package for
# one, or under a name that only begins like one, ring-0x-1.0.0 for one), or
# a generated Rust file the baseline accepts by producing package and file
# name. Any other unscanned file fails, Rust or not (an .rs.in, an .inc or an
# assembly file can hide code), as do a package with no metrics, any other exit
# code, and an exit without the count (a build error). cargo-geiger's other
# diagnostics are printed and not judged: cargo's progress lines, and "Failed to
# match (ignoring source) package: ..." for each lockfile package outside the
# scanned graph (the dev-dependencies, for one).
#
# Also fails: a report without its totals line, a count that differs from the
# baseline (the line to write is printed), a crate with no line, a line for a
# crate that is gone, a malformed baseline, or a cargo-geiger that is missing or
# another version than the baseline names (the install command is printed).
# Every crate is reported before the script exits.
#
# A scan is skipped, saying so, when its inputs are those of one that passed.
# A passing run writes a stamp: a file named by the SHA-256 of a listing of its
# inputs that holds the listing, which ends with a fixed line, in
# $XDG_CACHE_HOME/licketysync/geiger (else ~/.cache/licketysync/geiger), a
# directory of mode 700; whole or not at all (a temporary file, then mv); and
# only when the listing after the scan equals the one before. A run skips only
# on a stamp that holds exactly its listing, when the stamp and its directory
# are this user's and no one else may write them, and when no file in cargo's
# registry sources or git checkouts is newer than the stamp, which bears the
# time its scan began: those sources are not inputs (Cargo.lock names their
# versions), and the check catches an edit by hand, one made during the scan
# included. Two runs at once at worst both scan.
# The inputs: Cargo.lock, Cargo.toml, crates/*/Cargo.toml and every build.rs
# under crates/; this script and the baseline; `rustc -vV` and `cargo geiger
# --version`; every exported variable named CARGO_* (but CARGO_TARGET_DIR),
# RUSTC*, RUSTUP_* or *RUSTFLAGS, by value (by name alone when the name says
# token, credential, secret or password); the cargo configuration files in this
# directory, in each above it and in CARGO_HOME (ci/cargo-configs.sh; one that
# includes another file means a full run, below); and the files of some
# crates. Other variables, such as those build scripts read (CC, CFLAGS), are
# not inputs. The files under crates/ that belong to no crate are listed.
# A crate's own files are listed when it may use unsafe code; when one of them
# names unsafe (cargo-geiger counts unsafe code that cfg leaves out, which the
# lint never sees), no_mangle, export_name, link_section or
# debugger_visualizer, holds a word that begins with include (but included,
# includes and including), assigns to something named path (a path attribute,
# alone or in cfg_attr; but `let path =` and `let mut path =`), lets a macro
# build an attribute (#[$, a $ in cfg_attr) or a name (paste's [<), or holds a
# NUL byte, comments, line breaks or Unicode spaces between the tokens or not:
# these fail closed, so prose or code that only looks like one lists the crate;
# or when it has a file other than Rust (its Cargo.toml aside), which compiled
# in can change the counts or fail the scan. Not covered: the files another
# crate's macro compiles in (sqlx::migrate!, say); the content of a file
# outside crates/ that a crate compiles in (a trigger lists the crate's own
# files, not that one), or one compiled in by means no trigger names; and unsafe
# code that another crate's macro expands into a crate that forbids it (a
# Semgrep rule's to cover). Deliberate obfuscation beyond the triggers is left
# to CI's full scan and to review.
# A crate may not use unsafe code when its [lints] holds only
# `workspace = true` and Cargo.toml's [workspace.lints.rust] has the line
# `unsafe_code = "forbid"`, unless an exported *RUSTFLAGS or a configuration
# file names --cap-lints, which outranks forbid, or RUSTC, RUSTC_WRAPPER,
# RUSTC_WORKSPACE_WRAPPER or their CARGO_BUILD_ forms name a compiler or a
# wrapper other than the sccache on PATH. When any crate may use unsafe code,
# every file under crates/ is listed, since it can compile another crate's.
# Every run scans when CI is set (it reads and writes no stamp) or
# LICKETYSYNC_GEIGER_FULL is (it still writes its stamp); when there is no
# absolute cache directory; and when the layout is not the simple one the
# listing covers: a Cargo.toml under crates/ other than crates/*/Cargo.toml; a
# manifest that holds a backslash or a multi-line string; a dependency path
# that is not a crate under crates/; a target or build path that is not a file
# in its own crate; a configuration file that holds a backslash, a [source]
# or [[include]] table, or a key named directory, local-registry, registry,
# index, replace-with, rustc, rustc-wrapper, rustc-workspace-wrapper, rustdoc,
# path, paths or include.
# Usage: ci/geiger.sh [repo-root] (defaults to this repository). Exit 1 on any
# failure. Run by gate.sh and CI; tested by ci/test-geiger.sh.
set -euo pipefail
# This script, for the listing.
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "${1:-$(dirname "$0")/..}"
root=$PWD
baseline=ci/geiger-baseline.txt
# The extensions of files cargo-geiger may leave unscanned without a line in the
# baseline. Not Rust, and not assembly.
known_ext=' md markdown txt html svg c cc cpp cxx h hpp '
# The packages whose .der files are accepted, by registry directory name (the
# package, a dash and a semver version: three numbers, then an optional
# pre-release or build suffix), and the registry's source directory they must
# sit in, as cargo names it:
# $CARGO_HOME (else ~/.cargo) and registry/src, with no doubled slash. A
# relative CARGO_HOME matches no path, so its .der files fail.
der_packages='ring|rustls-webpki|rustls-pki-types'
registry=$(printf '%s/registry/src' "${CARGO_HOME:-$HOME/.cargo}" | tr -s /)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/geiger"
tmp=$(mktemp -d)
# part: a stamp being written, removed if the run stops before it is in place.
part=
trap 'rm -rf "$tmp"; [ -z "$part" ] || rm -f "$part"' EXIT

if [ ! -f "$baseline" ]; then
  echo "$baseline is missing" >&2
  exit 1
fi
lines=$(grep -vE '^(#|$)' "$baseline" || true)
want=$(printf '%s\n' "$lines" | grep -E '^cargo-geiger ' || true)
counts=$(printf '%s\n' "$lines" | grep -E '^[a-z0-9_-]+( [0-9]+){5}$' | grep -v '^generated ' || true)
generated=$(printf '%s\n' "$lines" | grep -E '^generated [A-Za-z0-9_-]+ [A-Za-z0-9_.-]+\.rs$' || true)
if bad=$(printf '%s\n' "$lines" | grep -vxF -e "$want" -e '' | grep -vxF -f <(printf '%s\n' "$counts" "$generated" | grep .)); then
  echo "$baseline: not \`<crate> <functions> <expressions> <impls> <traits> <methods>\`" >&2
  echo "nor \`generated <package> <file>.rs\`:" >&2
  printf '%s\n' "$bad" >&2
  exit 1
fi
if dups=$(printf '%s\n' "$counts" | awk 'NF { print $1 }' | sort | uniq -d | grep .); then
  echo "$baseline: crate listed twice: $dups" >&2
  exit 1
fi
if [ "$(printf '%s\n' "$want" | grep -c .)" != 1 ]; then
  echo "$baseline: needs exactly one \`cargo-geiger <version>\` line" >&2
  exit 1
fi
install="cargo install cargo-geiger --version ${want#cargo-geiger } --locked --features vendored-openssl"
if ! have=$(cargo geiger --version 2> /dev/null); then
  echo "cargo-geiger is not installed; install the version the baseline names:" >&2
  echo "  $install" >&2
  exit 1
fi
if [ "$have" != "$want" ]; then
  echo "the baseline was measured with $want, this is $have; counts differ between" >&2
  echo "versions, so install that one:" >&2
  echo "  $install" >&2
  echo "or move the baseline to $have as its header says, as a reviewed change" >&2
  exit 1
fi

# The stamp (the header says what it lists, and when none is used).
# shellcheck source=ci/cargo-configs.sh
. "$(dirname "$self")/cargo-configs.sh"
# The listing's last line: a listing without it was cut short.
sentinel='end of the listing'
# What makes a crate's own files inputs although it forbids unsafe_code: code
# cargo-geiger counts that the lint does not see (unsafe in code cfg leaves
# out), the attributes the lint covers, a file compiled in from elsewhere. They
# fail closed, matched as Perl patterns on each file whole (grep -zP), so that
# nothing between tokens, a comment or a line break, hides them; a word that
# only looks like one lists the crate, which costs a scan and nothing more:
# - any word that begins with include (include!, include_str!, an alias, an
#   identifier passed to a macro, a bare include, the verb in prose), but the
#   words included, includes and including;
# - path, then only whitespace, bytes other than ASCII (Unicode spaces) or
#   comments, then = but not == (#[path], #![path], a path in cfg_attr, any
#   other assignment to something named path), but `let path =` and
#   `let mut path =` with one space;
# - an attribute a macro builds: `#[$`, or a `$` inside cfg_attr(...) at any
#   depth of parentheses (a named group: `(?1)` would be include's (d|s|ing));
# - debugger_visualizer, whose attribute names a file;
# - `[<`, as paste! builds a name from pieces;
# - a NUL byte, which grep -z would split the file at (checked apart).
triggers='\bunsafe\b|no_mangle|export_name|link_section|debugger_visualizer|\[<|\binclude(?!(d|s|ing)\b)|(?<!\blet )(?<!\bmut )\bpath\b(?:\s|[\x80-\xff]|/\*[\s\S]*?\*/|//[^\n]*\n)*=(?!=)|#\s*!?\s*\[\s*\$|cfg_attr\s*\((?:[^()]|(?<paren>\((?:[^()]|(?&paren))*\)))*\$'
# workspace_forbids: [workspace.lints.rust] in Cargo.toml has the line
# `unsafe_code = "forbid"` (a trailing comment aside).
workspace_forbids() {
  awk '
    /^[[:space:]]*\[/ { h = $0; sub(/#.*/, "", h); gsub(/[[:space:]]/, "", h); cur = h; next }
    cur == "[workspace.lints.rust]" {
      l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+#[^"]*$/, "", l); sub(/[[:space:]]+$/, "", l)
      if (l ~ /^unsafe_code[[:space:]]*=[[:space:]]*"forbid"$/) ok = 1
    }
    END { exit !ok }
  ' Cargo.toml 2> /dev/null
}
# takes_workspace_lints <manifest>...: each manifest whose [lints] holds only
# `workspace = true` and in which no other table header or key names lints.
takes_workspace_lints() {
  awk '
    function done_() { if (file != "" && ok && !bad) print file }
    FNR == 1 { done_(); file = FILENAME; cur = ""; ok = 0; bad = 0 }
    /^[[:space:]]*\[/ {
      h = $0; sub(/#.*/, "", h); gsub(/[[:space:]"\047]/, "", h); cur = h
      if (h ~ /lints/ && h != "[lints]") bad = 1
      next
    }
    /^[[:space:]]*(#|$)/ { next }
    { l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+#[^"\047]*$/, "", l); sub(/[[:space:]]+$/, "", l) }
    cur == "[lints]" { if (l == "workspace = true") ok = 1; else bad = 1; next }
    l ~ /^["\047]?lints/ { bad = 1 }
    END { done_() }
  ' "$@"
}
# string_paths <manifest>...: `<manifest><tab><kind><tab><value>` for each
# string value of a `path` or `build` key, comment lines aside. The kind is
# `target` for the line `path = ...` in [lib], [[bin]], [[example]], [[test]]
# or [[bench]] of a crate's manifest, `build` for the line `build = ...` in its
# [package], and `dependency` for any other.
string_paths() {
  awk '
    FNR == 1 { cur = "" }
    /^[[:space:]]*\[/ { h = $0; sub(/#.*/, "", h); gsub(/[[:space:]"\047]/, "", h); cur = h }
    /^[[:space:]]*#/ { next }
    {
      t = $0; sub(/^[[:space:]]+/, "", t)
      first = "dependency"
      if (FILENAME != "Cargo.toml") {
        if (cur ~ /^\[(lib|\[bin\]|\[example\]|\[test\]|\[bench\])\]$/ && t ~ /^path[[:space:]]*=/) first = "target"
        else if (cur == "[package]" && t ~ /^build[[:space:]]*=/) first = "build"
      }
      l = $0; n = 0
      while (match(l, /(^|[^A-Za-z0-9_-])["\047]?(path|build)["\047]?[[:space:]]*=[[:space:]]*("[^"]*"|\047[^\047]*\047)/)) {
        v = substr(l, RSTART, RLENGTH); sub(/^[^=]*=[[:space:]]*/, "", v)
        print FILENAME "\t" (n++ == 0 ? first : "dependency") "\t" substr(v, 2, length(v) - 2)
        l = substr(l, RSTART + RLENGTH)
      }
    }
  ' "$@"
}
# private <path>: owned by this user, and neither group nor others may write it.
private() {
  local mode
  [ -O "$1" ] && mode=$(stat -c %a -- "$1" 2> /dev/null) && [ $((8#$mode & 8#022)) -eq 0 ]
}
# inputs: print the listing, ending with the sentinel, and return 0; or, when
# the listing would miss files, print why and return 1; or return 2 when a
# command it needs fails. Called before the scan and again after it, so that a
# stamp lists only what was scanned.
inputs() {
  local root_p members=() manifests configs=() f m c v p abs i h why all= taking any=
  local named=() kinds=() values=() resolved=() files=() present=() crates_files=() listed=() rs=() outside=
  local -A has_trigger=() has_other=()
  root_p=$(pwd -P)
  for m in crates/*/Cargo.toml; do
    [ ! -f "$m" ] || members+=("$m")
  done
  manifests=("${members[@]}")
  [ ! -f Cargo.toml ] || manifests=(Cargo.toml "${members[@]}")
  cargo_configs "$root_p"
  # Every file under crates/ outside the target directories.
  find -L crates -path 'crates/*/target' -prune -o -type f -print0 > "$tmp/crates" || return 2
  mapfile -t -d '' crates_files < "$tmp/crates"
  # The layouts the listing does not cover.
  for f in "${crates_files[@]}"; do
    if [[ ${f##*/} == Cargo.toml && ! $f =~ ^crates/[^/]+/Cargo\.toml$ ]]; then
      outside="$f is a manifest below a crate"
      break
    fi
  done
  if [ -z "$outside" ] && [ "${#manifests[@]}" -gt 0 ]; then
    if m=$(grep -lF '\' "${manifests[@]}"); then
      outside="$(head -n 1 <<< "$m") holds a backslash"
    elif m=$(grep -lE "\"\"\"|'''" "${manifests[@]}"); then
      outside="$(head -n 1 <<< "$m") holds a multi-line string"
    fi
  fi
  if [ -z "$outside" ] && [ "${#manifests[@]}" -gt 0 ]; then
    while IFS=$'\t' read -r m c v; do
      named+=("$m")
      kinds+=("$c")
      values+=("$v")
      p=$v
      [[ $p == /* ]] || p=${m%Cargo.toml}$p
      resolved+=("$p")
    done < <(string_paths "${manifests[@]}")
    if [ "${#resolved[@]}" -gt 0 ]; then
      mapfile -t -d '' resolved < <(realpath -m -z -- "${resolved[@]}")
      [ "${#resolved[@]}" = "${#values[@]}" ] || return 2
    fi
    for i in "${!values[@]}"; do
      m=${named[i]} c=${kinds[i]} v=${values[i]} abs=${resolved[i]}
      if [ "$c" = dependency ]; then
        p=${abs#"$root_p"/crates/}
        if [ "$p" = "$abs" ] || [ -z "$p" ] || [[ $p == */* ]] || [ ! -f "$abs/Cargo.toml" ]; then
          outside="$m names $v, not a crate under crates/"
          break
        fi
      elif [ "$m" = Cargo.toml ] || [[ $abs != "$root_p/${m%/Cargo.toml}"/* ]] || [ ! -f "$abs" ]; then
        outside="$m names $v, not a file in its own crate"
        break
      fi
    done
  fi
  for f in "${configs[@]}"; do
    [ -z "$outside" ] || break
    if grep -qF '\' "$f"; then
      outside="$f holds a backslash"
    elif grep -qE "^[[:space:]]*\[+[[:space:]]*[\"']?(source|include)\b" "$f" ||
      grep -qE "(^|[^A-Za-z0-9_-])[\"']?(directory|local-registry|registry|index|replace-with|rustc|rustc-wrapper|rustc-workspace-wrapper|rustdoc|path|paths|include)[\"']?[[:space:]]*=" "$f"; then
      outside="$f names a source, a registry, a compiler, a wrapper, a path or an include"
    fi
  done
  if [ -n "$outside" ]; then
    echo "$outside"
    return 1
  fi
  # Why every crate may use unsafe code, if so.
  for v in $(compgen -e); do
    [[ $v != *RUSTFLAGS || ${!v} != *cap-lints* ]] || all="$v names --cap-lints"
  done
  for f in "${configs[@]}"; do
    ! grep -q 'cap-lints' "$f" || all="$f names --cap-lints"
  done
  for v in RUSTC RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
    [ -z "${!v:-}" ] || all="$v names another compiler or wrapper"
  done
  if [ -n "${RUSTC_WRAPPER:-}" ] && { [[ ${RUSTC_WRAPPER##*/} != sccache ]] || [ "$RUSTC_WRAPPER" != "$(type -P sccache)" ]; }; then
    all="RUSTC_WRAPPER is not the sccache on PATH"
  fi
  if [ -z "$all" ] && ! workspace_forbids; then
    all='[workspace.lints.rust] does not set unsafe_code = "forbid"'
  fi
  taking=
  if [ -z "$all" ] && [ "${#members[@]}" -gt 0 ]; then
    taking=$(takes_workspace_lints "${members[@]}") || return 2
    for m in "${members[@]}"; do
      [[ $'\n'$taking$'\n' == *$'\n'$m$'\n'* ]] || all="${m%/Cargo.toml} does not take the workspace's lints alone"
    done
  fi
  # The crates whose own files hold a trigger or a file other than Rust.
  for f in "${crates_files[@]}"; do
    c=${f#crates/}
    c=${c%%/*}
    [[ $f == *.rs || $f == "crates/$c/Cargo.toml" ]] || has_other[$c]=1
  done
  rs=()
  for f in "${crates_files[@]}"; do
    [[ $f != *.rs ]] || rs+=("$f")
  done
  if [ "${#rs[@]}" -gt 0 ]; then
    LC_ALL=C grep -lzZP -- "$triggers" "${rs[@]}" > "$tmp/triggered" || [ $? = 1 ] || return 2
    LC_ALL=C grep -laZP -- '\x00' "${rs[@]}" >> "$tmp/triggered" || [ $? = 1 ] || return 2
    while IFS= read -r -d '' f; do
      c=${f#crates/}
      has_trigger[${c%%/*}]=1
    done < "$tmp/triggered"
  fi
  files=(Cargo.lock Cargo.toml "$baseline" crates/*/Cargo.toml)
  for f in "${crates_files[@]}"; do
    [[ ${f##*/} != build.rs ]] || files+=("$f")
  done
  [ ! -e build.rs ] || files+=(build.rs)
  printf 'cargo geiger --version: %s\n' "$have"
  h=$("${RUSTC:-rustc}" -vV) || return 2
  while IFS= read -r v; do
    printf 'rustc -vV: %s\n' "$v"
  done <<< "$h"
  for v in $(compgen -e | LC_ALL=C sort); do
    if [[ $v == CARGO_TARGET_DIR || ! ($v == CARGO_* || $v == RUSTC* || $v == RUSTUP_* || $v == *RUSTFLAGS) ]]; then
      continue
    elif [[ $v =~ TOKEN|CREDENTIAL|SECRET|PASSWORD ]]; then
      echo "$v set"
    else
      h=$(printf '%s' "${!v}" | sha256sum) || return 2
      printf '%s %s\n' "$v" "${h%% *}"
    fi
  done
  h=$(sha256sum < "$self") || return 2
  printf 'script %s\n' "${h%% *}"
  for m in "${members[@]}"; do
    c=${m#crates/}
    c=${c%/Cargo.toml}
    if [ -n "$all" ]; then
      echo "crate $c may use unsafe code: every file under crates/ is listed"
    else
      why=
      [ -z "${has_trigger[$c]:-}" ] || why="a file names unsafe, an unsafe attribute, include or path"
      [ -z "${has_other[$c]:-}" ] || why="${why:+$why; }it has files other than Rust"
      if [ -n "$why" ]; then
        echo "crate $c forbids unsafe_code; its files are listed ($why)"
        listed+=("$c")
      else
        echo "crate $c forbids unsafe_code"
      fi
    fi
  done
  [ -z "$all" ] || echo "every crate may use unsafe code: $all"
  for f in "${crates_files[@]}"; do
    c=${f#crates/}
    c=${c%%/*}
    if [ -n "$all" ] || [[ " ${listed[*]} " == *" $c "* ]] || [ ! -f "crates/$c/Cargo.toml" ]; then
      files+=("$f")
    fi
  done
  for f in "${configs[@]}"; do
    h=$(sha256sum < "$f") || return 2
    printf 'config %q %s\n' "${f#"$root_p"/}" "${h%% *}"
  done
  while IFS= read -r -d '' f; do
    if [ -f "$f" ]; then present+=("$f"); else printf 'missing %q\n' "$f"; fi
  done < <(printf '%s\0' "${files[@]}" | LC_ALL=C sort -zu)
  if [ "${#present[@]}" -gt 0 ]; then
    sha256sum -- "${present[@]}" || return 2
  fi
  echo "$sentinel"
}
# The registry's and git checkouts' sources are not inputs: a file there newer
# than the stamp (an edit by hand) means a full run.
registry_changed() {
  local home=${CARGO_HOME:-${HOME:-}/.cargo} d dirs=() found
  for d in "$home/registry/src" "$home/git/checkouts"; do
    [ ! -d "$d" ] || dirs+=("$d")
  done
  [ "${#dirs[@]}" -gt 0 ] || return 1
  found=$(find "${dirs[@]}" -newer "$1" -type f -print -quit 2> /dev/null) || return 0
  [ -n "$found" ]
}
stamp=
if [[ ${XDG_CACHE_HOME:-} == /* ]]; then
  cache=$XDG_CACHE_HOME/licketysync/geiger
elif [[ ${HOME:-} == /* ]]; then
  cache=$HOME/.cache/licketysync/geiger
else
  cache=
fi
if [ -n "${CI+set}" ]; then
  echo "== cargo-geiger: a full run: CI is set"
elif [ -z "$cache" ]; then
  echo "== cargo-geiger: a full run: neither XDG_CACHE_HOME nor HOME is an absolute path, for the stamp"
else
  rc=0
  inputs > "$tmp/inputs" || rc=$?
  [ "$rc" != 0 ] || [ "$(tail -n 1 "$tmp/inputs")" = "$sentinel" ] || rc=2
  case $rc in
    0)
      key=$(sha256sum < "$tmp/inputs")
      key=${key%% *}
      stamp=$cache/$key
      if [ -n "${LICKETYSYNC_GEIGER_FULL:-}" ]; then
        echo "== cargo-geiger: a full run: LICKETYSYNC_GEIGER_FULL is set"
      elif [ ! -e "$stamp" ]; then
        echo "== cargo-geiger: a full run: no stamp for these inputs ($stamp)"
      elif ! cmp -s "$tmp/inputs" "$stamp"; then
        echo "== cargo-geiger: a full run: the stamp $stamp does not hold these inputs whole"
      elif ! private "$cache" || ! private "$stamp"; then
        echo "== cargo-geiger: a full run: the stamp or its directory is not this user's alone ($stamp)"
      elif registry_changed "$stamp"; then
        echo "== cargo-geiger: a full run: a file in cargo's registry or git checkouts is newer than the stamp"
      else
        echo "== cargo-geiger: skipped: a run with the same inputs passed (they are listed in $stamp);"
        echo "LICKETYSYNC_GEIGER_FULL=1 runs it anyway"
        exit 0
      fi
      ;;
    1) echo "== cargo-geiger: a full run: a layout the stamp does not cover: $(head -n 1 "$tmp/inputs")" ;;
    *)
      echo "ci/geiger.sh: could not list the inputs for the stamp" >&2
      exit 1
      ;;
  esac
fi
# The scan's start, which the stamp's time will be: a file in the registry or a
# git checkout changed during the scan is then newer than the stamp.
: > "$tmp/started"

fails=0
for manifest in crates/*/Cargo.toml; do
  crate=$(basename "$(dirname "$manifest")")
  echo "== cargo geiger: $manifest"
  rc=0
  cargo geiger --manifest-path "$root/$manifest" --output-format Ascii > "$tmp/out" 2> "$tmp/err" || rc=$?
  cat "$tmp/out"
  cat "$tmp/err" >&2
  # The same output without colour codes, for matching.
  sed $'s/\e\\[[0-9;]*m//g' "$tmp/out" > "$tmp/out.plain"
  sed $'s/\e\\[[0-9;]*m//g' "$tmp/err" > "$tmp/err.plain"
  if [ "$rc" -ne 0 ]; then
    count=0
    refused=()
    while IFS= read -r line; do
      count=$((count + 1))
      path=${line#WARNING: Dependency file was never scanned: }
      if [ "$path" = "$line" ]; then
        refused+=("$line")
        continue
      fi
      base=${path##*/}
      if [[ $base == *.* && $known_ext == *" ${base##*.} "* ]]; then
        continue
      fi
      if [[ $base == *.der && $path =~ ^"$registry"/[^/]+/($der_packages)-[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?/ ]]; then
        continue
      fi
      if [[ $path =~ /build/([A-Za-z0-9_-]+)-[0-9a-f]{16}/out/([A-Za-z0-9_.-]+)$ ]] &&
        printf '%s\n' "$generated" | grep -qxF "generated ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"; then
        echo "== $crate: accepted by the baseline: ${BASH_REMATCH[2]} generated by ${BASH_REMATCH[1]}"
        continue
      fi
      refused+=("$line")
    done < <(grep '^WARNING: ' "$tmp/err.plain" || true)
    last=$(grep -v '^[[:space:]]*$' "$tmp/err.plain" | tail -n 1 || true)
    if [ "$rc" -ne 1 ] || [ "$count" -eq 0 ] || [ "${#refused[@]}" -gt 0 ] ||
      [ "$last" != "error: Found $count warnings" ]; then
      echo "$crate: cargo-geiger failed (exit $rc; last line: ${last:-none})" >&2
      if [ "${#refused[@]}" -gt 0 ]; then
        echo "warnings that leave the count incomplete (see ci/geiger-baseline.txt on generated files):" >&2
        printf '%s\n' "${refused[@]}" >&2
      fi
      fails=$((fails + 1))
      continue
    fi
    echo "== $crate: exit 1 accepted: its $count warnings name files cargo-geiger need not scan"
  fi
  # The totals line: five used/total pairs and nothing else.
  totals=$(grep -E '^ *[0-9]+/[0-9]+( +[0-9]+/[0-9]+){4} *$' "$tmp/out.plain" | tail -n 1 || true)
  if [ -z "$totals" ]; then
    echo "$crate: cargo-geiger's report has no totals line" >&2
    fails=$((fails + 1))
    continue
  fi
  used=()
  for pair in $totals; do used+=("${pair%%/*}"); done
  now="$crate ${used[*]}"
  was=$(printf '%s\n' "$counts" | awk -v c="$crate" '$1 == c')
  if [ -z "$was" ]; then
    echo "$crate: not in $baseline; a reviewed change adds the line:" >&2
    echo "$now" >&2
    fails=$((fails + 1))
  elif [ "$was" != "$now" ]; then
    echo "$crate: used unsafe counts (functions expressions impls traits methods) differ" >&2
    echo "from $baseline. Find the cause in the report above; a reviewed change that" >&2
    echo "accepts them replaces the line" >&2
    echo "$was" >&2
    echo "with" >&2
    echo "$now" >&2
    fails=$((fails + 1))
  else
    echo "== $crate: at the baseline ($now)"
  fi
done
for listed in $(printf '%s\n' "$counts" | awk 'NF { print $1 }'); do
  if [ ! -f "crates/$listed/Cargo.toml" ]; then
    echo "$baseline lists $listed, which is not a crate under crates/; remove the line" >&2
    fails=$((fails + 1))
  fi
done
if [ "$fails" -gt 0 ]; then
  echo "ci/geiger.sh: $fails failure(s)" >&2
  exit 1
fi
echo "== cargo-geiger: every crate matches $baseline"
# The stamp, whole or not at all, and only when the inputs are still those
# listed before the scan: a failure to write it fails nothing, and the next run
# scans again.
if [ -n "$stamp" ]; then
  if ! inputs > "$tmp/after" || ! cmp -s "$tmp/inputs" "$tmp/after"; then
    echo "== cargo-geiger: no stamp written: the inputs changed during the scan" >&2
  elif mkdir -p -m 700 "$cache" && [ -O "$cache" ] && chmod 700 "$cache" &&
    part=$(mktemp "$cache/.$key.XXXXXX") && cat "$tmp/inputs" > "$part" && touch -r "$tmp/started" "$part" &&
    mv -f "$part" "$stamp"; then
    part=
    echo "== cargo-geiger: stamp written: $stamp"
  else
    echo "== cargo-geiger: could not write the stamp $stamp; the next run scans again" >&2
  fi
fi
