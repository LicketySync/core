#!/usr/bin/env bash
# Tests for ci/pinned-actions.sh. Each case is a workflow directory in a
# temporary directory with one workflow file; the expected exit code is the
# assertion. Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
lint="$(cd "$(dirname "$0")" && pwd)/pinned-actions.sh"
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT
n=0
fails=0
sha=0123456789abcdef0123456789abcdef01234567
check() { # check <name> <expected exit> <dir>
  local rc=0
  "$lint" "$3" > "$3.out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$3.out"
    fails=$((fails + 1))
  fi
}
case_() { # case_ <name> <expected exit> <workflow body> [file name]
  n=$((n + 1))
  mkdir -p "$tmp/$n"
  printf '%s\n' "$3" > "$tmp/$n/${4:-ci.yml}"
  check "$1" "$2" "$tmp/$n"
}
steps() { # steps <step line...>: a workflow with one job holding these steps
  printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n'
  printf '      %s\n' "$@"
}
case_ "pinned, full version"                0 "$(steps "- uses: actions/checkout@$sha # v7.0.1")"
case_ "pinned, major version only"          0 "$(steps "- uses: dtolnay/rust-toolchain@$sha # v1")"
case_ "pinned, action in a subdirectory"    0 "$(steps "- uses: github/codeql-action/init@$sha # v4.39.1")"
case_ "pinned, uses after another key"      0 "$(steps "- id: pages" "  uses: actions/configure-pages@$sha # v6.0.0")"
case_ "pinned, quoted"                      0 "$(steps "- uses: \"actions/checkout@$sha\" # v7.0.1")"
case_ "local action"                        0 "$(steps "- uses: ./.github/actions/setup")"
case_ "Docker image by digest"              0 "$(steps "- uses: docker://alpine@sha256:${sha}0123456789abcdef01234567")"
case_ "reusable workflow, pinned"           0 $'on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@'"$sha"' # v1.2.3'
case_ "unpinned uses in a comment line"     0 "$(steps "# - uses: actions/checkout@v7" "- run: true")"
case_ "no uses at all"                      0 "$(steps "- run: true")"
case_ "tag"                                 1 "$(steps "- uses: actions/checkout@v7")"
case_ "branch"                              1 "$(steps "- uses: crate-ci/typos@master")"
case_ "short SHA"                           1 "$(steps "- uses: actions/checkout@${sha:0:7} # v7.0.1")"
case_ "41 hex digits"                       1 "$(steps "- uses: actions/checkout@${sha}a # v7.0.1")"
case_ "uppercase SHA"                       1 "$(steps "- uses: actions/checkout@${sha^^} # v7.0.1")"
case_ "SHA with no comment"                 1 "$(steps "- uses: actions/checkout@$sha")"
case_ "SHA with a branch in the comment"    1 "$(steps "- uses: actions/checkout@$sha # main")"
case_ "SHA with a four-part version"        1 "$(steps "- uses: actions/checkout@$sha # v1.2.3.4")"
case_ "comment with no space before it"     1 "$(steps "- uses: actions/checkout@$sha# v7.0.1")"
case_ "no ref at all"                       1 "$(steps "- uses: actions/checkout # v7.0.1")"
case_ "Docker image by tag"                 1 "$(steps "- uses: docker://alpine:3.20")"
case_ "Docker image with a short digest"    1 "$(steps "- uses: docker://alpine@sha256:$sha")"
case_ "reusable workflow by tag"            1 $'on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@v1'
case_ "value on the next line"              1 "$(steps "- uses:" "    actions/checkout@$sha # v7.0.1")"
case_ "one unpinned among pinned"           1 "$(steps "- uses: actions/checkout@$sha # v7.0.1" "- uses: Swatinem/rust-cache@v2" "- uses: taiki-e/install-action@$sha # v2.87.31")"
case_ "a .yaml workflow is checked"         1 "$(steps "- uses: actions/checkout@v7")" pages.yaml
# Built by hand: case_ always writes one workflow file.
n=$((n + 1)); mkdir -p "$tmp/$n"
check "no workflow fails closed" 1 "$tmp/$n"
n=$((n + 1)); mkdir -p "$tmp/$n"; echo 'on: push' > "$tmp/$n/notes.txt"
check "only other files fails closed" 1 "$tmp/$n"
n=$((n + 1))
check "missing directory fails closed" 1 "$tmp/$n"
# An unreadable workflow fails the check rather than passing (skipped when the
# user can read it anyway, as root can).
n=$((n + 1)); mkdir -p "$tmp/$n"; steps "- uses: actions/checkout@$sha # v7.0.1" > "$tmp/$n/ci.yml"
chmod 000 "$tmp/$n/ci.yml"
if [ -r "$tmp/$n/ci.yml" ]; then
  echo "skip unreadable workflow (readable as this user)"
else
  check "unreadable workflow fails closed" 1 "$tmp/$n"
fi
if [ "$fails" -ne 0 ]; then
  echo "$fails of the cases failed" >&2
  exit 1
fi
echo "test-pinned-actions: all cases passed"
