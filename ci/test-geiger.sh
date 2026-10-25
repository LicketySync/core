#!/usr/bin/env bash
# Tests for ci/geiger.sh, without cargo-geiger: a stub `cargo` first on PATH
# plays `cargo geiger` for each crate of a throwaway tree, printing the report
# (a totals line) and the stderr the case gives that crate and exiting with its
# code. It answers --version with $GEIGER_STUB_VERSION (or fails as a missing
# subcommand does when that is "missing"), refuses a relative --manifest-path
# as cargo-geiger does, and refuses a CARGO_TARGET_DIR that is not ci/geiger.sh's
# own. Each case asserts the exit code of ci/geiger.sh, and some also a line of
# its output. Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/geiger.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = geiger ] || { echo "stub: unexpected cargo $*" >&2; exit 98; }
if [ "${2:-}" = --version ]; then
  [ "$GEIGER_STUB_VERSION" = missing ] && { echo "error: no such command: \`geiger\`" >&2; exit 101; }
  echo "$GEIGER_STUB_VERSION"
  exit 0
fi
case ${CARGO_TARGET_DIR:-} in */geiger) ;; *) echo "stub: CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-unset}" >&2; exit 97 ;; esac
manifest=
while [ $# -gt 0 ]; do
  [ "$1" = --manifest-path ] && manifest=$2
  shift
done
case $manifest in /*) ;; *) echo "stub: relative manifest path: $manifest" >&2; exit 99 ;; esac
crate=$(basename "$(dirname "$manifest")")
echo "report for $crate"
cat "$GEIGER_STUB/$crate.out"
cat "$GEIGER_STUB/$crate.err" >&2
exit "$(cat "$GEIGER_STUB/$crate.rc")"
STUB
chmod +x "$tmp/bin/cargo"

never='WARNING: Dependency file was never scanned:'
readme="$never /reg/aead-0.6.1/README.md"
csrc="$never /reg/cc-1.8.0/src/detect_compiler_family.c"
cppsrc="$never /reg/cc-1.8.0/src/detect_cpp_stdlib.cpp"
gen_serde="$never /t/geiger/debug/build/serde_core-0123456789abcdef/out/private.rs"
rsfile="$never /t/geiger/debug/build/x-0123456789abcdef/out/generated.rs"
nometrics='WARNING: No metrics found for package: foo 1.0.0'
version='cargo-geiger 9.8.7'
keys='a 95 4352 23 2 63'
t() { # totals line: t <functions> <expressions> <impls> <traits> <methods> (used)
  printf '%s/309     %s/11699   %s/36  %s/2     %s/216' "$@"
}
at=$(t 95 4352 23 2 63)
n=0
fails=0
# case_ <name> <expected exit> <baseline lines> then, per crate:
#   <crate> <exit code> <stderr> <report lines>
# The baseline is a comment, "$base_version" (default the stub's version) and
# the lines given; the stub reports "$stub_version" (default the same).
case_() {
  n=$((n + 1))
  local name=$1 want=$2 rc=0
  dir="$tmp/$n"
  mkdir -p "$dir/stub" "$dir/repo/ci"
  printf '# a comment\n\n%s\n%s\n' "${base_version-$version}" "$3" > "$dir/repo/ci/geiger-baseline.txt"
  shift 3
  while [ $# -gt 0 ]; do
    mkdir -p "$dir/repo/crates/$1"
    touch "$dir/repo/crates/$1/Cargo.toml"
    echo "$2" > "$dir/stub/$1.rc"
    printf '%s\n' "$3" > "$dir/stub/$1.err"
    printf '%s\n' "$4" > "$dir/stub/$1.out"
    shift 4
  done
  GEIGER_STUB="$dir/stub" GEIGER_STUB_VERSION="${stub_version:-$version}" PATH="$tmp/bin:$PATH" \
    "$script" "$dir/repo" > "$dir/stdout" 2> "$dir/stderr" || rc=$?
  cat "$dir/stdout" "$dir/stderr" > "$dir/out"
  if [ "$rc" = "$want" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
# has_ <stdout|stderr> <exact line>: the last case printed that line there.
has_() {
  if grep -qxF -- "$2" "$dir/$1"; then
    echo "ok     and its $1 has: $2"
  else
    echo "FAIL   its $1 lacks: $2"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}

# cargo-geiger's exit code and warnings
case_ "clean run at the baseline"               0 "$keys" a 0 "    Checking a v0.0.1" "$at"
has_ stdout "== a: at the baseline ($keys)"
case_ "README, C and C++ files, count matches"  0 "$keys" a 1 "$readme"$'\n'"$csrc"$'\n'"$cppsrc"$'\n'"error: Found 3 warnings" "$at"
case_ "coloured count line"                     0 "$keys" a 1 "$readme"$'\n\e[1m\e[91merror\e[0m: Found 1 warnings' "$at"
# what cargo-geiger printed for the keys crate on 2026-10-18, abridged
case_ "real noise around the warnings"          0 "$keys" a 1 '    Blocking waiting for file lock on package cache
     Removed 6 files, 741B total
    Checking licketysync-keys v0.0.1 (/w/crates/keys)
{"$message_type":"artifact","artifact":"/t/geiger/debug/deps/libx.rmeta","emit":"metadata"}
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.57s
    Scanning done
Failed to match (ignoring source) package: registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229
Failed to match (ignoring source) package: registry+https://github.com/rust-lang/crates.io-index#const-oid@0.10.2 '"
$readme"$'\n'"$cppsrc"$'\n\n'"error: Found 2 warnings" "$at"
has_ stderr "Failed to match (ignoring source) package: registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229"
case_ "a Rust file never scanned"               1 "$keys" a 1 "$readme"$'\n'"$rsfile"$'\n'"error: Found 2 warnings" "$at"
has_ stderr "$rsfile"
case_ "an .rs.in file never scanned"            1 "$keys" a 1 "$never /reg/x-1.0.0/src/table.rs.in"$'\n'"error: Found 1 warnings" "$at"
case_ "an .inc file never scanned"              1 "$keys" a 1 "$never /reg/x-1.0.0/src/consts.inc"$'\n'"error: Found 1 warnings" "$at"
case_ "an assembly file never scanned"          1 "$keys" a 1 "$never /reg/x-1.0.0/src/aesni.S"$'\n'"error: Found 1 warnings" "$at"
case_ "a file without an extension"             1 "$keys" a 1 "$never /reg/x-1.0.0/src/LICENSE"$'\n'"error: Found 1 warnings" "$at"
case_ "a package with no metrics"               1 "$keys" a 1 "$nometrics"$'\n'"error: Found 1 warnings" "$at"
case_ "count above the warnings shown"          1 "$keys" a 1 "$readme"$'\n'"error: Found 2 warnings" "$at"
case_ "count line missing"                      1 "$keys" a 1 "$readme" "$at"
case_ "build error"                             1 "$keys" a 101 "error: could not compile \`a\`" ""
case_ "warnings but exit 2"                     1 "$keys" a 2 "$readme"$'\n'"error: Found 1 warnings" "$at"
case_ "exit 1 with no warnings"                 1 "$keys" a 1 "error: Found 0 warnings" "$at"
# generated Rust accepted by producing package and file name
case_ "generated file the baseline accepts"     0 "$keys"$'\ngenerated serde_core private.rs' a 1 "$gen_serde"$'\n'"error: Found 1 warnings" "$at"
has_ stdout "== a: accepted by the baseline: private.rs generated by serde_core"
case_ "generated file, no baseline line"        1 "$keys" a 1 "$gen_serde"$'\n'"error: Found 1 warnings" "$at"
case_ "accepted file name, another package"     1 "$keys"$'\ngenerated serde private.rs' a 1 "$gen_serde"$'\n'"error: Found 1 warnings" "$at"
case_ "accepted package, another file"          1 "$keys"$'\ngenerated serde_core other.rs' a 1 "$gen_serde"$'\n'"error: Found 1 warnings" "$at"
case_ "accepted name as a package suffix"       1 "$keys"$'\ngenerated core private.rs' a 1 "$gen_serde"$'\n'"error: Found 1 warnings" "$at"
case_ "accepted file in a subdirectory of out"  1 "$keys"$'\ngenerated serde_core private.rs' a 1 "$never /t/debug/build/serde_core-0123456789abcdef/out/sub/private.rs"$'\n'"error: Found 1 warnings" "$at"
case_ "generated line that is not Rust"         1 "$keys"$'\ngenerated serde_core private.txt' a 0 "" "$at"
# the five counts against the baseline, every difference failing
case_ "functions above"                         1 "$keys" a 0 "" "$(t 96 4352 23 2 63)"
has_ stderr "a 96 4352 23 2 63"
case_ "functions below"                         1 "$keys" a 0 "" "$(t 94 4352 23 2 63)"
has_ stderr "a 94 4352 23 2 63"
case_ "expressions above"                       1 "$keys" a 0 "" "$(t 95 4353 23 2 63)"
case_ "expressions below"                       1 "$keys" a 0 "" "$(t 95 4351 23 2 63)"
case_ "impls above"                             1 "$keys" a 0 "" "$(t 95 4352 24 2 63)"
case_ "impls below"                             1 "$keys" a 0 "" "$(t 95 4352 22 2 63)"
case_ "traits above"                            1 "$keys" a 0 "" "$(t 95 4352 23 3 63)"
case_ "traits below"                            1 "$keys" a 0 "" "$(t 95 4352 23 1 63)"
case_ "methods above"                           1 "$keys" a 0 "" "$(t 95 4352 23 2 64)"
case_ "methods below"                           1 "$keys" a 0 "" "$(t 95 4352 23 2 62)"
has_ stderr "$keys"
has_ stderr "a 95 4352 23 2 62"
case_ "every count lower"                       1 "$keys" a 0 "" "$(t 0 0 0 0 0)"
has_ stderr "a 0 0 0 0 0"
case_ "a difference in a second crate"          1 $'a 0 0 0 0 0\nb 95 4352 23 2 63' a 0 "" "$(t 0 0 0 0 0)" b 0 "" "$(t 95 4400 23 2 63)"
# every crate is reported after a failure, its stderr passed through
case_ "the crates after a failure still run"    1 $'a 0 0 0 0 0\nb 0 0 0 0 0\nc 0 0 0 0 0' a 1 "$rsfile"$'\n'"error: Found 1 warnings" "$(t 0 0 0 0 0)" b 0 "stub stderr of b" "$(t 0 0 0 0 0)" c 0 "" "$(t 9 0 0 0 0)"
has_ stdout "== cargo geiger: crates/b/Cargo.toml"
has_ stdout "== b: at the baseline (b 0 0 0 0 0)"
has_ stdout "== cargo geiger: crates/c/Cargo.toml"
has_ stderr "stub stderr of b"
has_ stderr "c 9 0 0 0 0"
has_ stderr "ci/geiger.sh: 2 failure(s)"
case_ "coloured totals line"                    0 "$keys" a 0 "" $'\e[1;31m'"$at"$'\e[0m'
case_ "totals of a package row are not totals"  1 "$keys" a 0 "" "$at      !  \`-- zeroize 1.9.1"
case_ "no totals line"                          1 "$keys" a 0 "" ""
case_ "a crate the baseline does not list"      1 "a 0 0 0 0 0" a 0 "" "$(t 0 0 0 0 0)" b 0 "" "$(t 1 2 3 4 5)"
has_ stderr "b 1 2 3 4 5"
case_ "a listed crate that is gone"             1 $'a 0 0 0 0 0\ngone 0 0 0 0 0' a 0 "" "$(t 0 0 0 0 0)"
case_ "baseline line with two counts"           1 "a 95 4352" a 0 "" "$(t 0 0 0 0 0)"
case_ "crate listed twice"                      1 $'a 0 0 0 0 0\na 5 5 5 5 5' a 0 "" "$(t 0 0 0 0 0)"
# the tool itself
stub_version='cargo-geiger 9.9.0'
case_ "another cargo-geiger version"            1 "a 0 0 0 0 0" a 0 "" "$(t 0 0 0 0 0)"
has_ stderr "  cargo install cargo-geiger --version 9.8.7 --locked --features vendored-openssl"
stub_version=missing
case_ "cargo-geiger not installed"              1 "a 0 0 0 0 0" a 0 "" "$(t 0 0 0 0 0)"
has_ stderr "  cargo install cargo-geiger --version 9.8.7 --locked --features vendored-openssl"
unset stub_version
base_version='# no version line'
case_ "baseline without a version line"         1 "a 0 0 0 0 0" a 0 "" "$(t 0 0 0 0 0)"
base_version=$'cargo-geiger 9.8.7\ncargo-geiger 9.8.6'
case_ "two version lines"                       1 "a 0 0 0 0 0" a 0 "" "$(t 0 0 0 0 0)"
unset base_version
# a missing baseline fails closed: built by hand because case_ always writes one
n=$((n + 1)); dir="$tmp/$n"; mkdir -p "$dir/repo/crates/a"; touch "$dir/repo/crates/a/Cargo.toml"
if GEIGER_STUB_VERSION="$version" PATH="$tmp/bin:$PATH" "$script" "$dir/repo" > "$dir/out" 2>&1; then
  echo "FAIL missing baseline: passed"; fails=$((fails + 1))
else
  echo "ok   missing baseline fails closed"
fi
# the report itself reaches stdout, for every crate
case_ "report printed for every crate"          0 $'a 0 0 0 0 0\nb 0 0 0 0 0' a 0 "" "$(t 0 0 0 0 0)" b 0 "" "$(t 0 0 0 0 0)"
has_ stdout "report for a"
has_ stdout "report for b"
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
