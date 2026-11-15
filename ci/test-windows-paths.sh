#!/usr/bin/env bash
# Tests for ci/windows-paths.py. Each case is a git repository in a temporary
# directory that tracks one file at the case's path; the expected exit code,
# and the path named in the output when it is refused, are the assertion.
# Git's global and system configuration are left out, so that the cases do
# not depend on this machine's. Run by gate.sh and CI. Exit 1 if any case
# fails.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/windows-paths.py"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
n=0
fails=0
# judge <name> <expected exit> <dir> [path the output must name]
judge() {
  local rc=0
  python3 -I "$check" "$3" > "$3.out" 2>&1 || rc=$?
  if [ "$rc" != "$2" ]; then
    echo "FAIL $1: exit $rc, expected $2"
    cat "$3.out"
    fails=$((fails + 1))
  elif [ -n "${4-}" ] && ! grep -qF -- "$4" "$3.out"; then
    echo "FAIL $1: the output does not name $4"
    cat "$3.out"
    fails=$((fails + 1))
  else
    echo "ok   $1"
  fi
}
# case_ <name> <expected exit> <path> [shown]: a repository tracking one file
# there; a refused path must be in the output, as [shown] when the output
# escapes it.
case_() {
  n=$((n + 1))
  local dir="$tmp/$n"
  git init -q "$dir"
  mkdir -p "$(dirname "$dir/$3")"
  : > "$dir/$3"
  git -C "$dir" add -- "$3"
  if [ "$2" = 1 ]; then judge "$1" "$2" "$dir" "${4-$3}"; else judge "$1" "$2" "$dir"; fi
}
case_ "passes: a plain path"                         0 "src/lib.rs"
case_ "passes: a dot file and dots inside"           0 "a/.gitattributes.b.c"
case_ "passes: a leading space"                      0 " a"
case_ "passes: the renamed seed"                     0 "fuzz/seeds/disk_names/nul-byte"
case_ "passes: a device name inside a longer name"   0 "console/nulx/xnul/auxiliary"
case_ "passes: COM with two digits"                  0 "com10"
case_ "passes: LPT with a letter"                    0 "LPTa"
case_ "passes: COM alone"                            0 "com"
case_ "passes: a dotless i, which is not ASCII"      0 $'con\xc4\xb1n$'
case_ "passes: non-ASCII UTF-8"                      0 'été/€'
case_ "refused: nul"                                 1 "nul"
case_ "refused: NUL in upper case"                   1 "NUL"
case_ "refused: Nul with an extension"               1 "Nul.txt"
case_ "refused: nul with spaces before the extension" 1 "nul  .txt"
case_ "refused: a device name as a directory"        1 "dir/con/file"
case_ "refused: aux with two extensions"             1 "aux.tar.gz"
case_ "refused: prn"                                 1 "prn"
case_ "refused: com1"                                1 "com1"
case_ "refused: COM0"                                1 "COM0"
case_ "refused: lpt9 with an extension"              1 "lpt9.log"
case_ "refused: com with a superscript one"          1 $'com\xc2\xb9'
case_ "refused: LPT with a superscript three"        1 $'LPT\xc2\xb3.x'
case_ "refused: CONIN\$"                             1 'CONIN$'
case_ "refused: conout\$ with an extension"          1 'conout$.x'
case_ "refused: <"                                   1 "a<b"
case_ "refused: >"                                   1 "a>b"
case_ "refused: :"                                   1 "a:b"
case_ "refused: \""                                  1 'a"b'
case_ "refused: |"                                   1 "a|b"
case_ "refused: ?"                                   1 "a?b"
case_ "refused: *"                                   1 "a*b"
case_ "refused: a backslash"                         1 'a\b' 'a\\b'
case_ "refused: U+0001"                              1 $'a\x01b' 'a\x01b'
case_ "refused: U+001F"                              1 $'a\x1fb' 'a\x1fb'
case_ "refused: a tab"                               1 $'a\tb' 'a\tb'
case_ "refused: a trailing dot"                      1 "a."
case_ "refused: a trailing space"                    1 "a "
case_ "refused: a directory with a trailing dot"     1 "d./x"
# Not UTF-8: the output shows the byte escaped.
n=$((n + 1)); dir="$tmp/$n"; git init -q "$dir"; : > "$dir/"$'a\xffb'; git -C "$dir" add -A
judge "refused: not UTF-8" 1 "$dir" 'a\\xffb'
# Several paths: each refused one is named, and an empty repository passes.
n=$((n + 1)); dir="$tmp/$n"; git init -q "$dir"; mkdir -p "$dir/x"
: > "$dir/x/ok"; : > "$dir/x/aux"; : > "$dir/con.md"; git -C "$dir" add -A
judge "refused: two of three, the first named" 1 "$dir" "x/aux"
judge "refused: two of three, the second named" 1 "$dir" "con.md"
n=$((n + 1)); dir="$tmp/$n"; git init -q "$dir"
judge "passes: no file at all" 0 "$dir"
# Fails closed: a directory that is not a repository.
n=$((n + 1)); dir="$tmp/$n"; mkdir -p "$dir"
judge "fails closed: not a repository" 2 "$dir"
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
