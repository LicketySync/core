#!/usr/bin/env bash
# Tests for ci/pinned-actions.sh. Each case is a workflow directory in a
# temporary directory with one workflow file; the expected exit code is the
# assertion, and each name says the result. Run by gate.sh and CI. Exit 1 if
# any case fails.
set -euo pipefail
lint="$(cd "$(dirname "$0")" && pwd)/pinned-actions.sh"
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT
n=0
fails=0
sha=0123456789abcdef0123456789abcdef01234567
digest=${sha}0123456789abcdef01234567
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
case_ "passes: pinned, three-part version"            0 "$(steps "- uses: actions/checkout@$sha # v1.2.3")"
case_ "passes: pinned, major version only"            0 "$(steps "- uses: dtolnay/rust-toolchain@$sha # v1")"
case_ "passes: pinned action in a subdirectory"       0 "$(steps "- uses: github/codeql-action/init@$sha # v1.2.3")"
case_ "passes: pinned, uses after another key"        0 "$(steps "- id: pages" "  uses: actions/configure-pages@$sha # v1.2.3")"
case_ "passes: pinned, quoted value"                  0 "$(steps "- uses: \"actions/checkout@$sha\" # v1.2.3")"
case_ "passes: Docker image by digest"                0 "$(steps "- uses: docker://alpine@sha256:$digest")"
case_ "passes: reusable workflow, pinned"             0 $'on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@'"$sha"' # v1.2.3'
case_ "passes: unpinned uses in a comment line"       0 "$(steps "# - uses: actions/checkout@v1" "- run: true")"
case_ "passes: a longer key ending in uses"           0 "$(steps "- run: true" "  env:" "    runs-uses: x" "    reuses: y")"
case_ "passes: no uses at all"                        0 "$(steps "- run: true")"
case_ "refused: tag"                                  1 "$(steps "- uses: actions/checkout@v1")"
case_ "refused: branch"                               1 "$(steps "- uses: crate-ci/typos@master")"
case_ "refused: short SHA"                            1 "$(steps "- uses: actions/checkout@${sha:0:7} # v1.2.3")"
case_ "refused: 41 hex digits"                        1 "$(steps "- uses: actions/checkout@${sha}a # v1.2.3")"
case_ "refused: uppercase SHA"                        1 "$(steps "- uses: actions/checkout@${sha^^} # v1.2.3")"
case_ "refused: SHA with no comment"                  1 "$(steps "- uses: actions/checkout@$sha")"
case_ "refused: SHA with a branch in the comment"     1 "$(steps "- uses: actions/checkout@$sha # main")"
case_ "refused: SHA with a four-part version"         1 "$(steps "- uses: actions/checkout@$sha # v1.2.3.4")"
case_ "refused: comment with no space before it"      1 "$(steps "- uses: actions/checkout@$sha# v1.2.3")"
case_ "refused: no ref at all"                        1 "$(steps "- uses: actions/checkout # v1.2.3")"
case_ "refused: local action"                         1 "$(steps "- uses: ./.github/actions/setup")"
case_ "refused: local reusable workflow"              1 $'on: push\njobs:\n  a:\n    uses: ./.github/workflows/w.yml'
case_ "refused: Docker image by tag"                  1 "$(steps "- uses: docker://alpine:3.20")"
case_ "refused: Docker image with a short digest"     1 "$(steps "- uses: docker://alpine@sha256:$sha")"
case_ "refused: reusable workflow by tag"             1 $'on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@v1'
case_ "refused: value on the next line"               1 "$(steps "- uses:" "    actions/checkout@$sha # v1.2.3")"
case_ "refused: one unpinned among pinned"            1 "$(steps "- uses: actions/checkout@$sha # v1.2.3" "- uses: Swatinem/rust-cache@v2" "- uses: taiki-e/install-action@$sha # v1.2.3")"
case_ "refused: a .yaml workflow, checked too"        1 "$(steps "- uses: actions/checkout@v1")" pages.yaml
# Other spellings of the key, refused even when the value is pinned.
case_ "refused: space before the colon"               1 "$(steps "- uses : actions/checkout@v1")"
case_ "refused: space before the colon, pinned"       1 "$(steps "- uses : actions/checkout@$sha # v1.2.3")"
case_ "refused: double-quoted key"                    1 "$(steps "- \"uses\": actions/checkout@v1")"
case_ "refused: single-quoted key"                    1 "$(steps "- 'uses': actions/checkout@v1")"
case_ "refused: key with an escape"                   1 "$(steps "- \"\\x75ses\": actions/checkout@v1")"
case_ "refused: flow mapping"                         1 "$(steps "- {uses: actions/checkout@v1}")"
case_ "refused: flow mapping, pinned"                 1 "$(steps "- {name: x, uses: actions/checkout@$sha}")"
case_ "refused: explicit ? key"                       1 "$(steps "- ? uses" "  : actions/checkout@v1")"
case_ "refused: explicit ? key on its own line"       1 "$(steps "-" "  ?" "    uses" "  : actions/checkout@v1")"
case_ "refused: explicit ? key in a flow mapping"     1 "$(steps "- {? uses : actions/checkout@v1}")"
case_ "refused: tagged key"                           1 "$(steps "- !!str uses: actions/checkout@v1")"
case_ "refused: anchored key"                         1 "$(steps "- &k uses: actions/checkout@v1")"
case_ "refused: anchored value"                       1 "$(steps "- uses: &v actions/checkout@$sha # v1.2.3")"
case_ "refused: uses-like text in a run script"       1 "$(steps "- run: echo 'uses: x'")"
# Built by hand: case_ always writes one workflow file.
n=$((n + 1)); mkdir -p "$tmp/$n"
check "refused: no workflow (fails closed)" 1 "$tmp/$n"
n=$((n + 1)); mkdir -p "$tmp/$n"; echo 'on: push' > "$tmp/$n/notes.txt"
check "refused: only other files (fails closed)" 1 "$tmp/$n"
n=$((n + 1))
check "refused: missing directory (fails closed)" 1 "$tmp/$n"
# An unreadable workflow fails the check rather than passing (skipped when the
# user can read it anyway, as root can).
n=$((n + 1)); mkdir -p "$tmp/$n"; steps "- uses: actions/checkout@$sha # v1.2.3" > "$tmp/$n/ci.yml"
chmod 000 "$tmp/$n/ci.yml"
if [ -r "$tmp/$n/ci.yml" ]; then
  echo "skip unreadable workflow (readable as this user)"
else
  check "refused: unreadable workflow (fails closed)" 1 "$tmp/$n"
fi
if [ "$fails" -ne 0 ]; then
  echo "$fails of the cases failed" >&2
  exit 1
fi
echo "test-pinned-actions: all cases passed"
