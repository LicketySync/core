#!/usr/bin/env bash
# Tests for ci/geiger.sh, without cargo-geiger: a stub `cargo` first on PATH
# plays `cargo geiger` for each crate of a throwaway tree, printing the report
# (a totals line) and the stderr the case gives that crate and exiting with its
# code. It answers --version with $GEIGER_STUB_VERSION (or fails as a missing
# subcommand does when that is "missing"), refuses a relative --manifest-path
# as cargo-geiger does, and refuses a CARGO_TARGET_DIR that is not ci/geiger.sh's
# own. ci/geiger.sh runs with CARGO_HOME=/cargo, so the registry's packages are
# under $reg, unless a case sets $cargo_home (and $home). Each case asserts the
# exit code of ci/geiger.sh, and some also a line of its output. Those cases
# run with CI set, as CI runs the script, so each scans and none reads or
# writes a stamp. The stamp's cases, last, share one tree and one cache
# directory and say whether the stub scanned; a stub `rustc` answers -vV with
# $RUSTC_STUB_VV, or a fixed text. Run by gate.sh and CI. Exit 1 if any case
# fails.
set -euo pipefail
# The stamp's variables come only from the cases.
unset CI LICKETYSYNC_GEIGER_FULL XDG_CACHE_HOME
for v in $(compgen -e); do
  case $v in CARGO_* | RUSTC* | RUSTUP_* | *RUSTFLAGS | SCCACHE_*) unset "$v" ;; esac
done
script="$(cd "$(dirname "$0")" && pwd)/geiger.sh"
# Every run of the script is bounded, so a hang fails its case.
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout
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
echo "$crate" >> "$GEIGER_STUB/scans"
[ -z "${GEIGER_STUB_TOUCH:-}" ] || echo "# changed during the scan" >> "$GEIGER_STUB_TOUCH"
echo "report for $crate"
cat "$GEIGER_STUB/$crate.out"
cat "$GEIGER_STUB/$crate.err" >&2
exit "$(cat "$GEIGER_STUB/$crate.rc")"
STUB
cat > "$tmp/bin/rustc" <<'STUB'
#!/usr/bin/env bash
[ "$*" = -vV ] || { echo "stub: unexpected rustc $*" >&2; exit 98; }
[ -z "${RUSTC_STUB_FAIL:-}" ] || { echo "stub: rustc fails" >&2; exit 1; }
printf '%b\n' "${RUSTC_STUB_VV:-rustc 1.99.1 (stub)\nhost: x86_64-unknown-linux-gnu}"
STUB
chmod +x "$tmp/bin/cargo" "$tmp/bin/rustc"

never='WARNING: Dependency file was never scanned:'
reg=/cargo/registry/src/index.crates.io-1949cf8c6b5b557f
readme="$never /reg/aead-0.6.1/README.md"
csrc="$never /reg/cc-1.8.0/src/detect_compiler_family.c"
cppsrc="$never /reg/cc-1.8.0/src/detect_cpp_stdlib.cpp"
dersrc="$never $reg/ring-0.17.14/src/data/alg-rsa-encryption.der"
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
  "$tmo" 60 env GEIGER_STUB="$dir/stub" GEIGER_STUB_VERSION="${stub_version:-$version}" PATH="$tmp/bin:$PATH" \
    CARGO_HOME="${cargo_home-/cargo}" HOME="${home-$HOME}" CI=true \
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
case_ "DER data of ring, rustls-webpki, rustls-pki-types" 0 "$keys" a 1 "$readme"$'\n'"$dersrc"$'\n'"$never $reg/rustls-webpki-0.103.16/src/data/alg-ed25519.der"$'\n'"$never $reg/rustls-pki-types-1.15.1/src/data/alg-rsa-encryption.der"$'\n'"error: Found 4 warnings" "$at"
cargo_home='' home=/h/
case_ "ring's DER data under the default ~/.cargo" 0 "$keys" a 1 "$never /h/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ring-0.17.14/src/data/alg-rsa-encryption.der"$'\n'"error: Found 1 warnings" "$at"
unset cargo_home home
case_ "another package's DER file never scanned" 1 "$keys" a 1 "$never $reg/x509-cert-0.2.5/tests/examples/cert.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a ring look-alike's DER file"            1 "$keys" a 1 "$never $reg/ring-compat-0.8.0/src/key.der"$'\n'"error: Found 1 warnings" "$at"
# the version after the package name must be semver: three numbers, then an
# optional pre-release or build suffix
case_ "a ring look-alike with a version, ring-0x" 1 "$keys" a 1 "$never $reg/ring-0x-1.0.0/x.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a ring look-alike with a version, ring-0" 1 "$keys" a 1 "$never $reg/ring-0-1.0.0/x.der"$'\n'"error: Found 1 warnings" "$at"
case_ "ring's own directory, ring-0.17.14"      0 "$keys" a 1 "$never $reg/ring-0.17.14/x.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a pre-release, rustls-webpki-0.103.0-alpha.1" 0 "$keys" a 1 "$never $reg/rustls-webpki-0.103.0-alpha.1/x.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a ring directory nested in another package" 1 "$keys" a 1 "$never $reg/x-1.0.0/vendor/ring-0.17.14/src/key.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a ring directory outside the registry"   1 "$keys" a 1 "$never /src/ring-0.17.14/src/data/alg-rsa-encryption.der"$'\n'"error: Found 1 warnings" "$at"
case_ "a .data file never scanned (ICU4X's baked Rust)" 1 "$keys" a 1 "$never /reg/icu_properties_data-2.4.0/data/property_binary_blank_v1.rs.data"$'\n'"error: Found 1 warnings" "$at"
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
rc=0
"$tmo" 60 env GEIGER_STUB_VERSION="$version" PATH="$tmp/bin:$PATH" CI=true "$script" "$dir/repo" > "$dir/out" 2>&1 || rc=$?
if [ "$rc" = 0 ] || [ "$rc" = 124 ]; then
  echo "FAIL missing baseline: exit $rc"; fails=$((fails + 1))
else
  echo "ok   missing baseline fails closed"
fi
# the report itself reaches stdout, for every crate
case_ "report printed for every crate"          0 $'a 0 0 0 0 0\nb 0 0 0 0 0' a 0 "" "$(t 0 0 0 0 0)" b 0 "" "$(t 0 0 0 0 0)"
has_ stdout "report for a"
has_ stdout "report for b"
# The stamp: one tree, changed and changed back between runs, and one cache
# directory. Crates a and b take the workspace's lints, which forbid
# unsafe_code; a depends on b. Each run_ asserts the exit code and whether the
# stub scanned; the variables in env_ and those given reach ci/geiger.sh.
s=$tmp/stamp
repo=$s/repo
cache=$s/cache/licketysync/geiger
mkdir -p "$s/stub" "$s/home" "$s/ci2" "$s/ci3" "$repo/ci" "$repo/crates/a/src" "$repo/crates/b/src"
cat > "$repo/Cargo.toml" << 'EOF'
[workspace]
members = ["crates/*"]

[workspace.lints.rust]
unsafe_code = "forbid"          # crates that need it opt out
EOF
cat > "$repo/crates/a/Cargo.toml" << 'EOF'
[package]
name = "a"

[dependencies]
b = { path = "../b" }

[lints]
workspace = true
EOF
printf '[package]\nname = "b"\n\n[lints]\nworkspace = true\n' > "$repo/crates/b/Cargo.toml"
echo 'version = 4' > "$repo/Cargo.lock"
echo 'pub fn a() {}' > "$repo/crates/a/src/lib.rs"
echo 'pub fn b() {}' > "$repo/crates/b/src/lib.rs"
printf '%s\na 0 0 0 0 0\nb 0 0 0 0 0\n' "$version" > "$repo/ci/geiger-baseline.txt"
for c in a b; do
  echo 0 > "$s/stub/$c.rc"
  : > "$s/stub/$c.err"
  t 0 0 0 0 0 > "$s/stub/$c.out"
done
: > "$s/stub/scans"
# Two copies of the script beside the file it sources: one changed by a
# comment, one that never writes the listing's last line.
cp "$(dirname "$script")/cargo-configs.sh" "$s/ci2/"
cp "$(dirname "$script")/cargo-configs.sh" "$s/ci3/"
{ cat "$script"; echo '# changed'; } > "$s/ci2/geiger.sh"
grep -vxF '  echo "$sentinel"' "$script" > "$s/ci3/geiger.sh"
chmod +x "$s/ci2/geiger.sh" "$s/ci3/geiger.sh"
printf '#!/usr/bin/env bash\nprintf "rustc 1.99.1 (another)\\nhost: x86_64-unknown-linux-gnu\\n"\n' > "$tmp/bin/rustc2"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/sccache"
chmod +x "$tmp/bin/rustc2" "$tmp/bin/sccache"
env_=()
# run_ <name> <expected exit> <scan|skip> [NAME=value ...]: ci/geiger.sh (or
# $script_) on the tree.
run_() {
  n=$((n + 1))
  local name=$1 want=$2 scan=$3 rc=0 before got=skip
  shift 3
  dir="$tmp/$n"
  mkdir -p "$dir"
  before=$(wc -l < "$s/stub/scans")
  "$tmo" 60 env GEIGER_STUB="$s/stub" GEIGER_STUB_VERSION="${stub_version:-$version}" PATH="$tmp/bin:$PATH" \
    CARGO_HOME=/cargo HOME="$s/home" XDG_CACHE_HOME="$s/cache" "${env_[@]}" "$@" "${script_:-$script}" "$repo" \
    > "$dir/stdout" 2> "$dir/stderr" || rc=$?
  cat "$dir/stdout" "$dir/stderr" > "$dir/out"
  [ "$(wc -l < "$s/stub/scans")" = "$before" ] || got=scan
  if [ "$rc" = "$want" ] && [ "$got" = "$scan" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, $got; expected exit $want, $scan"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
# check_ <name> <command>: a check of its own, passing when the command does.
check_() {
  if eval "$2"; then
    echo "ok     and $1"
  else
    echo "FAIL   not so: $1"
    fails=$((fails + 1))
  fi
}
hash_() { # hash_ <text>: its SHA-256
  local h
  h=$(printf '%s' "$1" | sha256sum)
  echo "${h%% *}"
}
run_ "no stamp: a full run, which writes one" 0 scan
first=$(ls -A "$cache")
check_ "the cache directory holds one stamp, named by a SHA-256" '[[ $first =~ ^[0-9a-f]{64}$ ]]'
check_ "the cache directory has mode 700" '[ "$(stat -c %a "$cache")" = 700 ]'
has_ stdout "== cargo-geiger: a full run: no stamp for these inputs ($cache/$first)"
has_ stdout "== cargo-geiger: stamp written: $cache/$first"
cp "$cache/$first" "$s/listing"
run_ "the same inputs: skipped" 0 skip
has_ stdout "== cargo-geiger: skipped: a run with the same inputs passed (they are listed in $cache/$first);"
has_ stdout "LICKETYSYNC_GEIGER_FULL=1 runs it anyway"
check_ "the stamp's name is the SHA-256 of what it holds" \
  '[ "$(sha256sum < "$cache/$first" | cut -c1-64)" = "$first" ]'
# what the stamp lists
lists_() {
  line=$1
  check_ "the stamp lists: $1" 'grep -qxF -- "$line" "$s/listing"'
}
lists_ "cargo geiger --version: $version"
lists_ 'rustc -vV: rustc 1.99.1 (stub)'
lists_ 'rustc -vV: host: x86_64-unknown-linux-gnu'
lists_ "CARGO_HOME $(hash_ /cargo)"
lists_ "script $(sha256sum < "$script" | cut -c1-64)"
lists_ 'crate a forbids unsafe_code'
lists_ 'crate b forbids unsafe_code'
for f in Cargo.lock Cargo.toml ci/geiger-baseline.txt crates/a/Cargo.toml crates/b/Cargo.toml; do
  lists_ "$(cd "$repo" && sha256sum "$f")"
done
check_ "the stamp lists no source of a or b" '! grep -q "crates/./src" "$s/listing"'
check_ "the stamp ends with the listing's last line" '[ "$(tail -n 1 "$s/listing")" = "end of the listing" ]'
# when every run scans
run_ "LICKETYSYNC_GEIGER_FULL=1: a full run"     0 scan LICKETYSYNC_GEIGER_FULL=1
has_ stdout "== cargo-geiger: a full run: LICKETYSYNC_GEIGER_FULL is set"
run_ "LICKETYSYNC_GEIGER_FULL empty: skipped"    0 skip LICKETYSYNC_GEIGER_FULL=
run_ "CI set: a full run"                        0 scan CI=true
has_ stdout "== cargo-geiger: a full run: CI is set"
run_ "CI set but empty: a full run"              0 scan CI=
rm -r "${s:?}/cache"
run_ "CI set, no stamp: a full run"              0 scan CI=true
check_ "a run with CI set writes no stamp" '[ ! -e "$s/cache" ]'
run_ "LICKETYSYNC_GEIGER_FULL=1, no stamp: a full run" 0 scan LICKETYSYNC_GEIGER_FULL=1
check_ "a run forced in full writes its stamp" '[ "$(ls -A "$cache")" = "$first" ] && cmp -s "$cache/$first" "$s/listing"'
run_ "after it: skipped"                         0 skip
# changed_ <what> <change> <change back> [NAME=value ...]: a full run with the
# change, given the variables; skipped once it is changed back, by the stamp
# of before.
changed_() {
  local what=$1 change=$2 back=$3
  shift 3
  eval "$change"
  run_ "$what changed: a full run" 0 scan "$@"
  eval "$back"
  run_ "$what changed back: skipped" 0 skip
}
changed_ "Cargo.lock" 'echo "# x" >> "$repo/Cargo.lock"' 'sed -i "\$d" "$repo/Cargo.lock"'
changed_ "Cargo.toml" 'echo "# x" >> "$repo/Cargo.toml"' 'sed -i "\$d" "$repo/Cargo.toml"'
changed_ "a crate's Cargo.toml" 'echo "# x" >> "$repo/crates/a/Cargo.toml"' 'sed -i "\$d" "$repo/crates/a/Cargo.toml"'
changed_ "a build.rs, added," 'echo "fn main() {}" > "$repo/crates/a/build.rs"' 'rm "${repo:?}/crates/a/build.rs"'
echo 'fn main() {}' > "$repo/crates/a/build.rs"
run_ "that build.rs again: skipped, by its stamp" 0 skip
changed_ "the build.rs" 'echo "// x" >> "$repo/crates/a/build.rs"' 'sed -i "\$d" "$repo/crates/a/build.rs"'
rm "${repo:?}/crates/a/build.rs"
changed_ "ci/geiger.sh" 'script_=$s/ci2/geiger.sh' 'unset script_'
changed_ "the baseline" 'echo "# x" >> "$repo/ci/geiger-baseline.txt"' 'sed -i "\$d" "$repo/ci/geiger-baseline.txt"'
changed_ "rustc -vV" '' '' RUSTC_STUB_VV='rustc 1.99.2 (stub)\nhost: x86_64-unknown-linux-gnu'
# cargo-geiger's version must be the baseline's, so they change together
changed_ "cargo geiger --version, with the baseline's line," \
  'stub_version="cargo-geiger 9.8.8"; sed -i "s/^$version\$/cargo-geiger 9.8.8/" "$repo/ci/geiger-baseline.txt"' \
  'unset stub_version; sed -i "s/^cargo-geiger 9.8.8\$/$version/" "$repo/ci/geiger-baseline.txt"'
changed_ "RUSTFLAGS" '' '' RUSTFLAGS='-C debuginfo=0'
changed_ "RUSTFLAGS, set but empty," '' '' RUSTFLAGS=
changed_ "CARGO_ENCODED_RUSTFLAGS" '' '' CARGO_ENCODED_RUSTFLAGS=$'-C\x1fdebuginfo=0'
changed_ "CARGO_BUILD_RUSTFLAGS" '' '' CARGO_BUILD_RUSTFLAGS='-C debuginfo=0'
changed_ "CARGO_HOME" '' '' CARGO_HOME=/other
changed_ "CARGO_PROFILE_DEV_OPT_LEVEL" '' '' CARGO_PROFILE_DEV_OPT_LEVEL=1
changed_ "CARGO_BUILD_TARGET" '' '' CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu
changed_ "RUSTC_BOOTSTRAP" '' '' RUSTC_BOOTSTRAP=1
changed_ "RUSTUP_TOOLCHAIN" '' '' RUSTUP_TOOLCHAIN=nightly
run_ "CARGO_TARGET_DIR, not an input: skipped"  0 skip CARGO_TARGET_DIR=/elsewhere
tok=a-token-0123456789
changed_ "CARGO_REGISTRY_TOKEN, keyed by name alone," '' '' CARGO_REGISTRY_TOKEN=$tok
check_ "no stamp holds the token or its hash" \
  '! grep -qF "$tok" "$cache"/* && ! grep -qF "$(hash_ "$tok")" "$cache"/* && grep -qxF "CARGO_REGISTRY_TOKEN set" "$cache"/*'
run_ "the token changed, by name the same: skipped" 0 skip CARGO_REGISTRY_TOKEN=another
changed_ "a cargo configuration file" \
  'mkdir "$repo/.cargo"; printf "[build]\njobs = 2\n" > "$repo/.cargo/config.toml"' 'rm -r "${repo:?}/.cargo"'
mkdir -p "$s/cargo-home"
env_=(CARGO_HOME="$s/cargo-home")
run_ "another CARGO_HOME: a full run"            0 scan
changed_ "the configuration file in CARGO_HOME" \
  'printf "[build]\njobs = 2\n" > "$s/cargo-home/config.toml"' 'rm "${s:?}/cargo-home/config.toml"'
# an edit in cargo's registry sources, newer than the stamp
mkdir -p "$s/cargo-home/registry/src/index/x-1.0.0/src"
echo 'pub fn x() {}' > "$s/cargo-home/registry/src/index/x-1.0.0/src/lib.rs"
touch -d '2000-01-01' "$s/cargo-home/registry/src/index/x-1.0.0/src/lib.rs"
run_ "a registry source older than the stamps: skipped" 0 skip
echo '// edited' >> "$s/cargo-home/registry/src/index/x-1.0.0/src/lib.rs"
run_ "a registry source edited after the stamp: a full run" 0 scan
has_ stdout "== cargo-geiger: a full run: a file in cargo's registry or git checkouts is newer than the stamp"
run_ "then skipped, by the stamp it wrote"       0 skip
mkdir -p "$s/cargo-home/git/checkouts/y-0123/abc/src"
echo 'pub fn y() {}' > "$s/cargo-home/git/checkouts/y-0123/abc/src/lib.rs"
run_ "a git checkout's file newer than the stamp: a full run" 0 scan
# an edit during a scan: the stamp bears the scan's start, so the edit is newer
run_ "a registry source edited during the scan (forced): a full run" 0 scan \
  GEIGER_STUB_TOUCH="$s/cargo-home/registry/src/index/x-1.0.0/src/lib.rs" LICKETYSYNC_GEIGER_FULL=1
has_ stdout "== cargo-geiger: stamp written: $cache/$(ls -t "$cache" | head -n 1)"
run_ "the next run: a full run, the edit newer than the stamp" 0 scan
has_ stdout "== cargo-geiger: a full run: a file in cargo's registry or git checkouts is newer than the stamp"
run_ "then skipped"                              0 skip
env_=()
# a crate's own files: inputs when it may use unsafe code, holds a trigger, or
# has a file other than Rust
echo '// x' >> "$repo/crates/a/src/lib.rs"
run_ "a source of a, which forbids unsafe_code, with no trigger, changed: skipped" 0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
# words and code that only look like a trigger
echo '/// What a holds is included here, what it includes, including more; nothing to uninclude.' \
  >> "$repo/crates/a/src/lib.rs"
run_ "prose saying included, includes, including and uninclude: skipped" 0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
echo 'pub fn p() -> &'"'"'static str { let path = "x"; path }' >> "$repo/crates/a/src/lib.rs"
run_ "let path = \"x\": skipped"                0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
echo 'pub fn q() -> String { let mut path = String::new(); path.push('"'"'x'"'"'); path }' >> "$repo/crates/a/src/lib.rs"
run_ "let mut path = …: skipped"                0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
printf '#[cfg_attr(test, derive(Debug))]\npub struct S;\npub fn p() -> &'"'"'static str { let path = "x"; path }\n' \
  >> "$repo/crates/a/src/lib.rs"
run_ "a cfg_attr, and later let path = \"x\": skipped" 0 skip
sed -i '2,$d' "$repo/crates/a/src/lib.rs"
echo 'pub fn f(path: &str, n: [u8; 1], m: (u8, u8)) -> bool { path == "x" || n.len() + m.0 as usize > 1 }' \
  >> "$repo/crates/a/src/lib.rs"
run_ "a parameter named path, and path == \"x\": skipped" 0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
echo 'pub fn g() -> &'"'"'static str { let mut filepath = "x"; filepath = "y"; filepath }' >> "$repo/crates/a/src/lib.rs"
run_ "a name that ends in path, assigned: skipped" 0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
changed_ "a file under crates/ in no crate" 'mkdir "$repo/crates/common"; echo "pub fn c() {}" > "$repo/crates/common/c.rs"' \
  'rm -r "${repo:?}/crates/common"'
mkdir "$repo/crates/common"
echo 'pub fn c() {}' > "$repo/crates/common/c.rs"
run_ "that file again: skipped, by its stamp"   0 skip
changed_ "that file" 'echo "// x" >> "$repo/crates/common/c.rs"' 'sed -i "\$d" "$repo/crates/common/c.rs"'
rm -r "${repo:?}/crates/common"
mkdir "$repo/crates/b/target"
echo x > "$repo/crates/b/target/x.json"
run_ "a file under b's target/: skipped"         0 skip
rm -r "${repo:?}/crates/b/target"
# listed_ <how> <change> <change back>: with the change, a's own files are
# inputs.
listed_() {
  local how=$1 change=$2 back=$3
  eval "$change"
  run_ "$how: a full run" 0 scan
  echo '// x' >> "$repo/crates/a/src/lib.rs"
  run_ "$how, a's source changed: a full run" 0 scan
  sed -i '$d' "$repo/crates/a/src/lib.rs"
  run_ "$how, a's source changed back: skipped" 0 skip
  eval "$back"
  run_ "$how, changed back: skipped" 0 skip
}
cp "$repo/crates/a/Cargo.toml" "$s/a.toml"
cp "$repo/crates/b/Cargo.toml" "$s/b.toml"
cp "$repo/Cargo.toml" "$s/root.toml"
a_back='cp "$s/a.toml" "$repo/crates/a/Cargo.toml"'
b_back='cp "$s/b.toml" "$repo/crates/b/Cargo.toml"'
root_back='cp "$s/root.toml" "$repo/Cargo.toml"'
src_back='rm -f "${repo:?}/crates/a/src/more.rs" "${repo:?}/crates/a/src/data.sql"; sed -i "2,\$d" "$repo/crates/a/src/lib.rs"'
# unsafe code that cfg leaves out: cargo-geiger 0.14.0 counts it, the lint never sees it
listed_ "unsafe code cfg leaves out, in a" 'echo "#[cfg(any())] unsafe fn f() {}" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "include_str! of a file other than Rust, in a" \
  'echo "pub const Q: &str = include_str!(\"data.sql\");" >> "$repo/crates/a/src/lib.rs"; echo x > "$repo/crates/a/src/data.sql"' \
  "$src_back"
listed_ "include! of a Rust file, in a" \
  'echo "include!(\"more.rs\");" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a path attribute, in a" \
  'echo "#[path = \"more.rs\"] mod m;" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a path in cfg_attr, in a" \
  'echo "#[cfg_attr(unix, path = \"more.rs\")] mod m;" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a path attribute split over lines, in a" \
  'printf "#[\n    path = \"more.rs\"\n]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a path in cfg_attr split over lines, in a" \
  'printf "#[cfg_attr(\n    unix,\n    path = \"more.rs\"\n)]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
# a file outside a, compiled in, with no new file in a
listed_ "include_str! of b's source, in a" \
  'echo "pub const S: &str = include_str!(\"../../b/src/lib.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "include_bytes! of b's source, in a" \
  'echo "pub const S: &[u8] = include_bytes!(\"../../b/src/lib.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "include_str! with a space before the !, in a" \
  'echo "pub const S: &str = include_str !(\"../../b/src/lib.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "include_str! by an alias in a use list, in a" \
  'printf "use std::{include_str as inc};\npub const S: &str = inc!(\"../../b/src/lib.rs\");\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "include_bytes! by an alias after a comma in a use list, in a" \
  'printf "use std::{concat, include_bytes as bytes};\npub const S: &[u8] = bytes!(concat!(\"../../b/src/\", \"lib.rs\"));\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "an inner path attribute, in a" \
  'printf "mod m {\n    #![path = \"more.rs\"]\n}\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
# what hides the narrower patterns of before: a comment between the tokens, a
# name passed to a macro without its !
listed_ "a comment between include_str and its !, in a" \
  'echo "pub const S: &str = include_str /* x */ !(\"../../b/src/lib.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "a comment in the attribute before path, in a" \
  'echo "#[/**/path = \"more.rs\"] mod m;" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a block comment before the =, in a" \
  'echo "#[path /* c */ = \"more.rs\"] mod m;" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a line comment before the =, in a" \
  'printf "#[path // c\n= \"more.rs\"]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
echo 'macro_rules! call { ($m:ident) => { $m!("../../b/src/lib.rs") } }' > "$s/call.rs"
listed_ "include_str passed to a macro, with no ! after it, in a" \
  'cat "$s/call.rs" >> "$repo/crates/a/src/lib.rs"; echo "pub const S: &str = call!(include_str);" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "a bare include passed to a macro, in a" \
  'cat "$s/call.rs" >> "$repo/crates/a/src/lib.rs"; echo "call!(include);" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "a macro named included_files, in a" 'echo "x::included_files!(\"d\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "path = after a word that ends in let, in a" \
  'echo "m!(outlet path = \"more.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "path = after a word that ends in mut, in a" \
  'echo "m!(immut path = \"more.rs\");" >> "$repo/crates/a/src/lib.rs"' "$src_back"
# Unicode spaces between path and =, and a NUL byte (grep -z splits a file
# there)
listed_ "U+200E between path and =, in a" \
  'printf "#[path\342\200\216= \"more.rs\"]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "U+2028 between path and =, in a" \
  'printf "#[path\342\200\250= \"more.rs\"]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "U+0085 between path and =, in a" \
  'printf "#[path\302\205= \"more.rs\"]\nmod m;\n" >> "$repo/crates/a/src/lib.rs"; echo "pub fn m() {}" > "$repo/crates/a/src/more.rs"' \
  "$src_back"
listed_ "a NUL byte inside a comment, in a" 'printf "// a\000b\n" >> "$repo/crates/a/src/lib.rs"' "$src_back"
# an attribute or a name a macro builds
listed_ "#[\$p = \$f] in a macro, m!(path \"…\") (a file from outside), in a" \
  'printf "macro_rules! m { (\$p:ident \$f:literal) => { #[\$p = \$f] mod x; } }\nm!(path \"../../../outside/x.rs\");\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "#[\$p = \$f] in a macro, m!(let path = \"…\"), in a" \
  'printf "macro_rules! m { (let \$p:ident = \$f:literal) => { #[\$p = \$f] mod x; } }\nm!(let path = \"more.rs\");\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "cfg_attr(all(), \$a = \"…\") in a macro, m!(path), in a" \
  'printf "macro_rules! m { (\$a:ident) => { #[cfg_attr(all(), \$a = \"../../../outside/x.rs\")] mod x; } }\nm!(path);\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "cfg_attr(all(unix, not(windows)), \$a = \$f) in a macro, at!(path, \"…\"), in a" \
  'printf "macro_rules! at { (\$a:ident, \$f:literal) => { #[cfg_attr(all(unix, not(windows)), \$a = \$f)] mod x; } }\nat!(path, \"../../outside.rs\");\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "paste builds include_str from pieces ([<), in a" \
  'echo "paste::paste! { const S: &str = [<inc lude_str>]!(\"../../b/src/lib.rs\"); }" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "debugger_visualizer with gdb_script_file, in a" \
  'echo "#![debugger_visualizer(gdb_script_file = \"../../../outside/x.py\")]" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "debugger_visualizer with natvis_file, in a" \
  'echo "#![debugger_visualizer(natvis_file = \"../../../outside/x.natvis\")]" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "include_str! by an alias, in a" \
  'printf "use std::include_str as inc;\npub const S: &str = inc!(\"../../b/src/lib.rs\");\n" >> "$repo/crates/a/src/lib.rs"' \
  "$src_back"
listed_ "another crate's include macro (include_proto!), in a" \
  'echo "pub mod p { x::include_proto!(\"p\"); }" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "no_mangle, in a" 'echo "#[no_mangle] pub extern \"C\" fn f() {}" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "export_name, in a" 'echo "#[export_name = \"g\"] pub extern \"C\" fn f() {}" >> "$repo/crates/a/src/lib.rs"' "$src_back"
listed_ "a file other than Rust, in a" 'echo x > "$repo/crates/a/src/data.sql"' "$src_back"
# every crate may use unsafe code, so every file under crates/ is listed: a's
# own, though a forbids it (another crate can compile a's files)
no_lints='sed -i "/^\[lints\]/,\$d" "$repo/crates/a/Cargo.toml"'
listed_ "a without [lints]" "$no_lints" "$a_back"
listed_ "b without [lints] (b can compile a's files)" 'sed -i "/^\[lints\]/,\$d" "$repo/crates/b/Cargo.toml"' "$b_back"
listed_ "a allowing unsafe_code in [lints.rust]" \
  "$no_lints"'; printf "[lints.rust]\nunsafe_code = \"allow\"\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
listed_ "a with lints.workspace = true, a dotted key" \
  "$no_lints"'; sed -i "1i lints.workspace = true" "$repo/crates/a/Cargo.toml"' "$a_back"
listed_ "a with another key in [lints]" \
  'echo "rust = { unsafe_code = \"allow\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
listed_ "a with [lints.rust] as well" \
  'printf "[lints.rust]\nunsafe_code = \"allow\"\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
listed_ "the workspace denying unsafe_code, not forbidding it" \
  'sed -i "s/^unsafe_code = \"forbid\"/unsafe_code = \"deny\"/" "$repo/Cargo.toml"' "$root_back"
listed_ "the workspace forbidding it in an inline table" \
  'sed -i "s/^unsafe_code = \"forbid\".*/unsafe_code = { level = \"forbid\", priority = 0 }/" "$repo/Cargo.toml"' "$root_back"
listed_ "the workspace forbidding it by a dotted key" \
  'sed -i "s/^\[workspace.lints.rust\]/[workspace.lints]/; s/^unsafe_code = /rust.unsafe_code = /" "$repo/Cargo.toml"' "$root_back"
listed_ "RUSTFLAGS capping the lints" 'env_=(RUSTFLAGS="--cap-lints warn")' 'env_=()'
listed_ "CARGO_ENCODED_RUSTFLAGS capping the lints" \
  'env_=(CARGO_ENCODED_RUSTFLAGS=$'"'"'--cap-lints\x1fwarn'"'"')' 'env_=()'
listed_ "a configuration file capping the lints" \
  'mkdir "$repo/.cargo"; printf "[build]\nrustflags = [\"--cap-lints\", \"warn\"]\n" > "$repo/.cargo/config.toml"' \
  'rm -r "${repo:?}/.cargo"'
listed_ "RUSTC_WRAPPER another wrapper" 'env_=(RUSTC_WRAPPER=/x/wrapper)' 'env_=()'
listed_ "RUSTC_WRAPPER a sccache not on PATH" 'env_=(RUSTC_WRAPPER=/elsewhere/sccache)' 'env_=()'
listed_ "RUSTC_WORKSPACE_WRAPPER" 'env_=(RUSTC_WORKSPACE_WRAPPER=/x/wrapper)' 'env_=()'
listed_ "CARGO_BUILD_RUSTC_WRAPPER" 'env_=(CARGO_BUILD_RUSTC_WRAPPER=/x/wrapper)' 'env_=()'
listed_ "RUSTC another compiler" 'env_=(RUSTC=rustc2)' 'env_=()'
env_=(RUSTC_WRAPPER="$tmp/bin/sccache")
run_ "RUSTC_WRAPPER the sccache on PATH: a full run (the variable changed)" 0 scan
echo '// x' >> "$repo/crates/a/src/lib.rs"
run_ "with it, a's source changed: skipped (a still forbids unsafe_code)" 0 skip
sed -i '$d' "$repo/crates/a/src/lib.rs"
env_=()
# outside_ <how> <the reason printed> <change> <change back>: with the change,
# every run scans, and none writes a stamp.
outside_() {
  local how=$1 why=$2 change=$3 back=$4
  eval "$change"
  run_ "$how: a full run" 0 scan
  has_ stdout "== cargo-geiger: a full run: a layout the stamp does not cover: $why"
  run_ "$how: a full run again" 0 scan
  eval "$back"
  run_ "$how, changed back: skipped" 0 skip
}
not_crate=', not a crate under crates/'
not_own=', not a file in its own crate'
outside_ "a path dependency outside crates/" "crates/a/Cargo.toml names ../../vendor/x$not_crate" \
  'echo "x = { path = \"../../vendor/x\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "an absolute path dependency" "crates/a/Cargo.toml names /vendor/x$not_crate" \
  'echo "x = { path = \"/vendor/x\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a path in single quotes" "crates/a/Cargo.toml names ../../vendor/x$not_crate" \
  "echo \"x = { path = '../../vendor/x' }\" >> \"\$repo/crates/a/Cargo.toml\"" "$a_back"
outside_ "a path under a quoted key" "crates/a/Cargo.toml names ../../vendor/x$not_crate" \
  'echo "x = { \"path\" = \"../../vendor/x\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a path into crates/ but no crate" "crates/a/Cargo.toml names ../c$not_crate" \
  'echo "c = { path = \"../c\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a path into another crate's folder (vendored there)" "crates/a/Cargo.toml names ../b/vendor/x$not_crate" \
  'echo "x = { path = \"../b/vendor/x\" }" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a nested crate" "crates/a/vendored/Cargo.toml is a manifest below a crate" \
  'mkdir -p "$repo/crates/a/vendored"; printf "[package]\nname = \"v\"\n" > "$repo/crates/a/vendored/Cargo.toml"' \
  'rm -r "${repo:?}/crates/a/vendored"'
outside_ "a backslash in a manifest (a path with a TOML escape)" "crates/a/Cargo.toml holds a backslash" \
  'printf "x = { path = \"\\\\u002e\\\\u002e/x\" }\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "an escaped TOML key" "crates/a/Cargo.toml holds a backslash" \
  'printf "x = { \"pat\\\\u0068\" = \"../../x\" }\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a build script outside crates/" "crates/a/Cargo.toml names ../../build.rs$not_own" \
  'sed -i "s/^name = \"a\"\$/&\nbuild = \"..\/..\/build.rs\"/" "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a crate compiling another crate's file ([lib] path)" "crates/a/Cargo.toml names ../b/src/lib.rs$not_own" \
  'printf "\n[lib]\npath = \"../b/src/lib.rs\"\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a target path to no file" "crates/a/Cargo.toml names src/none.rs$not_own" \
  'printf "\n[[bin]]\nname = \"x\"\npath = \"src/none.rs\"\n" >> "$repo/crates/a/Cargo.toml"' "$a_back"
outside_ "a [patch] in Cargo.toml" "Cargo.toml names vendor/x$not_crate" \
  'printf "\n[patch.crates-io]\nx = { path = \"vendor/x\" }\n" >> "$repo/Cargo.toml"' "$root_back"
outside_ "a multi-line string" "crates/a/Cargo.toml holds a multi-line string" \
  "sed -i 's/^name = \"a\"\$/&\ndescription = \"\"\"\nx\n\"\"\"/' \"\$repo/crates/a/Cargo.toml\"" "$a_back"
cfg=$(cd "$repo" && pwd -P)/.cargo/config.toml
names="$cfg names a source, a registry, a compiler, a wrapper, a path or an include"
# config_ <how> <its text>: a configuration file with that text
config_() {
  outside_ "$1" "$names" "mkdir \"\$repo/.cargo\"; printf '$2\\n' > \"\$repo/.cargo/config.toml\"" \
    'rm -r "${repo:?}/.cargo"'
}
config_ "vendored sources, a directory source" '[source.crates-io]\nreplace-with = "vendored"\n\n[source.vendored]\ndirectory = "vendor"'
config_ "vendored sources, a local registry" '[source.local]\nlocal-registry = "/x/registry"'
config_ "a dotted replace-with" 'source.crates-io.replace-with = "x"'
config_ "an include, the list form" 'include = ["more.toml"]'
config_ "an include, the table form" '[[include]]\npath = "more.toml"\noptional = true'
config_ "a dotted directory" 'source.vendored.directory = "vendor"'
config_ "a dotted local-registry" 'source.local.local-registry = "/x/registry"'
config_ "a [source] table with a git source" '[source.mine]\ngit = "file:///x/repo"\nbranch = "main"'
config_ "a registry's index" '[registries.x]\nindex = "sparse+https://x/"'
config_ "a dotted registry key" 'source.mirror.registry = "sparse+https://mirror/"'
config_ "a wrapper" '[build]\nrustc-wrapper = "/x/wrapper"'
config_ "a workspace wrapper" '[build]\nrustc-workspace-wrapper = "/x/wrapper"'
config_ "a compiler" '[build]\nrustc = "/x/rustc"'
config_ "rustdoc" '[build]\nrustdoc = "/x/rustdoc"'
config_ "a [patch] path" '[patch.crates-io]\nx = { path = "v" }'
config_ "paths" 'paths = ["v"]'
outside_ "a backslash in a configuration file" "$cfg holds a backslash" \
  'mkdir "$repo/.cargo"; printf "[build]\n\"rustc\\\\u002dwrapper\" = \"x\"\n" > "$repo/.cargo/config.toml"' \
  'rm -r "${repo:?}/.cargo"'
printf '\n[[bin]]\nname = "x"\npath = "src/main.rs"\n' >> "$repo/crates/a/Cargo.toml"
echo 'fn main() {}' > "$repo/crates/a/src/main.rs"
run_ "a target path to a file in a's own folder: a full run" 0 scan
run_ "a target path to a file in a's own folder: skipped" 0 skip
cp "$s/a.toml" "$repo/crates/a/Cargo.toml"
rm "${repo:?}/crates/a/src/main.rs"
run_ "back as before: skipped"                   0 skip
# a stamp that does not hold the whole listing is no stamp
head -c 100 "$s/listing" > "$cache/$first"
run_ "a stamp cut short: a full run"             0 scan
has_ stdout "== cargo-geiger: a full run: the stamp $cache/$first does not hold these inputs whole"
check_ "the stamp is whole again" 'cmp -s "$cache/$first" "$s/listing"'
: > "$cache/$first"
run_ "an empty stamp: a full run"                0 scan
run_ "the stamp written again: skipped"          0 skip
rm "${cache:?}/${first:?}"
cp "$s/listing" "$cache/.$first.AbC123"
run_ "a temporary file left before its mv: a full run" 0 scan
check_ "the stamp is in place, the temporary file left alone" \
  'cmp -s "$cache/$first" "$s/listing" && [ -f "$cache/.$first.AbC123" ]'
rm "${cache:?}/.${first:?}.AbC123"
# a stamp, or its directory, that others may write is not trusted (one owned
# by another user cannot be made here without root)
chmod g+w "$cache/$first"
run_ "a stamp others may write: a full run"      0 scan
has_ stdout "== cargo-geiger: a full run: the stamp or its directory is not this user's alone ($cache/$first)"
check_ "the stamp written again has mode 600" '[ "$(stat -c %a "$cache/$first")" = 600 ]'
run_ "then skipped"                              0 skip
chmod 775 "$cache"
run_ "a stamp directory others may write: a full run" 0 scan
check_ "the directory has mode 700 again" '[ "$(stat -c %a "$cache")" = 700 ]'
run_ "then skipped, too"                         0 skip
# a listing without its last line is an error, never a skip
script_=$s/ci3/geiger.sh
run_ "a listing cut short (no last line): exit 1, no scan" 1 skip
unset script_
has_ stderr "ci/geiger.sh: could not list the inputs for the stamp"
# an input that changes during the scan (forced, since a stamp holds): no
# stamp, for the inputs before it or after it
rm -r "${s:?}/cache"
cp "$repo/Cargo.lock" "$s/Cargo.lock"
run_ "Cargo.lock changed during the scan: no stamp" 0 scan GEIGER_STUB_TOUCH="$repo/Cargo.lock"
has_ stderr "== cargo-geiger: no stamp written: the inputs changed during the scan"
check_ "the cache directory holds no stamp" '[ ! -e "$cache" ] || [ -z "$(ls -A "$cache")" ]'
cp "$s/Cargo.lock" "$repo/Cargo.lock"
run_ "Cargo.lock as before the scan: a full run, no stamp being there" 0 scan
run_ "then skipped"                              0 skip
# a command the listing needs that fails stops the script, before any scan
run_ "rustc -vV fails: exit 1, no scan"          1 skip RUSTC_STUB_FAIL=1
has_ stderr "ci/geiger.sh: could not list the inputs for the stamp"
run_ "rustc -vV fails, CI set: not run, a full run" 0 scan RUSTC_STUB_FAIL=1 CI=true
# a run that fails writes no stamp
rm -r "${s:?}/cache"
t 1 0 0 0 0 > "$s/stub/b.out"
run_ "a failing run"                             1 scan
check_ "it wrote no stamp" '[ ! -e "$cache" ] || [ -z "$(ls -A "$cache")" ]'
run_ "a failing run again: a full run"           1 scan
t 0 0 0 0 0 > "$s/stub/b.out"
run_ "passing again: a full run"                 0 scan
run_ "and then skipped"                          0 skip
# where the stamp goes
: > "$s/blocked"
run_ "a cache directory that cannot be made: a full run, passing" 0 scan XDG_CACHE_HOME="$s/blocked"
has_ stderr "== cargo-geiger: could not write the stamp $s/blocked/licketysync/geiger/$first; the next run scans again"
run_ "the same again: a full run"                0 scan XDG_CACHE_HOME="$s/blocked"
run_ "a relative XDG_CACHE_HOME: ~/.cache instead" 0 scan XDG_CACHE_HOME=rel
check_ "the stamp is in ~/.cache, nothing in ./rel" \
  '[ -f "$s/home/.cache/licketysync/geiger/$first" ] && [ ! -e "$repo/rel" ]'
run_ "XDG_CACHE_HOME empty: ~/.cache, skipped"   0 skip XDG_CACHE_HOME=
run_ "neither XDG_CACHE_HOME nor HOME absolute: a full run" 0 scan XDG_CACHE_HOME=rel HOME=home
has_ stdout "== cargo-geiger: a full run: neither XDG_CACHE_HOME nor HOME is an absolute path, for the stamp"
run_ "the same again: a full run"                0 scan XDG_CACHE_HOME=rel HOME=home
# two runs at once, with no stamp: both pass, and one whole stamp is left
rm -r "${s:?}/cache"
for i in 1 2; do
  "$tmo" 60 env GEIGER_STUB="$s/stub" GEIGER_STUB_VERSION="$version" PATH="$tmp/bin:$PATH" CARGO_HOME=/cargo \
    HOME="$s/home" XDG_CACHE_HOME="$s/cache" "$script" "$repo" > "$s/both$i" 2>&1 &
  eval "pid$i=\$!"
done
rc1=0 rc2=0
wait "$pid1" || rc1=$?
wait "$pid2" || rc2=$?
n=$((n + 1))
if [ "$rc1$rc2" = 00 ] && [ "$(ls -A "$cache")" = "$first" ] && cmp -s "$cache/$first" "$s/listing"; then
  echo "ok   two runs at once: both pass, and one whole stamp is left"
else
  echo "FAIL two runs at once: exits $rc1 and $rc2; the cache holds: $(ls -A "$cache" | tr '\n' ' ')"
  cat "$s/both1" "$s/both2"
  fails=$((fails + 1))
fi
run_ "after them: skipped"                       0 skip
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
