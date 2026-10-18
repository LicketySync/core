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
# README.md through include_str!, or a C or C++ source for a build script) or
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
# Usage: ci/geiger.sh [repo-root] (defaults to this repository). Exit 1 on any
# failure. Run by gate.sh and CI; tested by ci/test-geiger.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
root=$PWD
baseline=ci/geiger-baseline.txt
# The extensions of files cargo-geiger may leave unscanned without a line in the
# baseline. Not Rust, and not assembly.
known_ext=' md markdown txt html svg c cc cpp cxx h hpp '
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/geiger"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

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
