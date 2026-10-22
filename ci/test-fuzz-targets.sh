#!/usr/bin/env bash
# Tests for ci/fuzz-targets.sh with a stand-in `cargo` first on PATH, which
# prints the case's target list for `cargo fuzz list` or fails as cargo does
# without cargo-fuzz. Each case is a tree in a temporary directory; the exit
# code, the output line and the notice are the assertions. Run by gate.sh,
# ci.yml and nightly.yml. Exit 1 if any case fails.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/fuzz-targets.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/cargo" << 'STUB'
#!/usr/bin/env bash
if [ "$*" != "fuzz list" ]; then
  echo "stand-in cargo: unexpected arguments: $*" >&2
  exit 101
fi
if [ -n "${FAKE_NO_FUZZ:-}" ]; then
  echo "error: no such command: \`fuzz\`" >&2
  exit 101
fi
printf '%b' "${FAKE_LIST:-}"
STUB
chmod +x "$tmp/bin/cargo"
PATH="$tmp/bin:$PATH"
notice='::notice title=cargo-fuzz::no fuzz targets in fuzz/Cargo.toml; nothing is fuzzed'
n=0
fails=0
# case_ <name> <expected exit> <expected output line, or "" for none> <notice:
# yes|no> <manifest: yes|no> [VAR=value ... for the stand-in]
case_() {
  n=$((n + 1))
  local name=$1 want=$2 line=$3 says=$4 manifest=$5 dir="$tmp/$n" rc=0 ok=1
  shift 5
  mkdir -p "$dir/fuzz"
  [ "$manifest" = no ] || : > "$dir/fuzz/Cargo.toml"
  env "$@" "$script" "$dir/output" "$dir" > "$dir/log" 2>&1 || rc=$?
  [ "$rc" = "$want" ] || ok=0
  if [ -n "$line" ]; then
    [ "$(cat "$dir/output" 2> /dev/null)" = "$line" ] || ok=0
  elif [ -s "$dir/output" ]; then
    ok=0
  fi
  if grep -qxF -- "$notice" "$dir/log"; then
    [ "$says" = yes ] || ok=0
  else
    [ "$says" = no ] || ok=0
  fi
  if [ "$ok" = 1 ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want; output: $(cat "$dir/output" 2> /dev/null)"
    sed 's/^/  | /' "$dir/log"
    fails=$((fails + 1))
  fi
}
case_ "two targets" 0 'targets=["chunk_open","frame-decode"]' no yes \
  FAKE_LIST='chunk_open\nframe-decode\n'
case_ "one target, no trailing newline" 0 'targets=["phrase_parse"]' no yes FAKE_LIST='phrase_parse'
case_ "no targets: an empty list and a notice" 0 'targets=[]' yes yes FAKE_LIST=''
case_ "no fuzz/Cargo.toml: an empty list and a notice" 0 'targets=[]' yes no FAKE_NO_FUZZ=1
# Runs 39576345810 and 39755196041: cargo-fuzz was not installed and the
# job's for loop hid the error, so it passed without fuzzing.
case_ "cargo-fuzz missing fails (runs 39576345810, 39755196041)" 101 "" no yes FAKE_NO_FUZZ=1
case_ "a target name with a space fails" 1 "" no yes FAKE_LIST='good\nnot plain\n'
case_ "a target name with a quote fails" 1 "" no yes FAKE_LIST='a"b\n'
case_ "a glob is a name, not a pattern" 1 "" no yes FAKE_LIST='*\n'
# Under en_US.UTF-8, bash's [a-z] takes an e with an acute accent, so the
# name check holds only because the script sets LC_ALL=C. Where that locale
# is missing or does not do so, the case cannot show it and is skipped.
name='a non-ASCII target name fails in a locale whose [a-z] takes it'
if LC_ALL=en_US.UTF-8 bash -c '[[ $(printf "\xc3\xa9") =~ ^[a-z]$ ]]' 2> /dev/null; then
  case_ "$name" 1 "" no yes LC_ALL=en_US.UTF-8 FAKE_LIST='target_\xc3\xa9\n'
else
  echo "skip $name: en_US.UTF-8 is not installed, or its [a-z] does not take it"
fi
if [ "$fails" -gt 0 ]; then
  echo "fuzz-targets: $fails failing case(s)"
  exit 1
fi
echo "fuzz-targets: all $n cases pass"
