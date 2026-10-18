#!/usr/bin/env bash
# gitleaks with this repository's settings: .gitleaks.toml, inline
# `gitleaks:allow` comments ignored, secrets redacted, and on a finding only the
# rule, file, line and commit printed (from a JSON report), never the match.
# Usage: ci/gitleaks.sh history|tree [gitleaks-binary]
#   history  every commit of every ref (CI, after a full-depth checkout)
#   tree     the files a commit would hold now: tracked and untracked files that
#            .gitignore does not exclude, copied out and scanned as a directory
#            (gate.sh, so that a change is checked before it is committed)
# The binary defaults to `gitleaks` on PATH; CI passes the release
# ci/gitleaks-install.sh verified. Another version than that script pins still
# runs, with a warning that says how to install the pinned one. Exit 1 on a
# finding or an error.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-}
bin=${2:-gitleaks}
pinned=$(sed -n 's/^version=//p' ci/gitleaks-install.sh)
if ! have=$("$bin" version 2> /dev/null); then
  echo "gitleaks is not installed; install the pinned release: ci/gitleaks-install.sh ~/.local/bin" >&2
  exit 1
fi
if [ "$have" != "$pinned" ]; then
  echo "warning: gitleaks $have is not the pinned $pinned that CI runs;" >&2
  echo "install that one: ci/gitleaks-install.sh ~/.local/bin" >&2
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
common=(--config "$PWD/.gitleaks.toml" --ignore-gitleaks-allow --redact --no-banner
  --log-level warn --report-format json --report-path "$tmp/report.json" --exit-code 1)
rc=0
case $mode in
  history)
    "$bin" git "${common[@]}" . || rc=$?
    ;;
  tree)
    mkdir "$tmp/tree"
    # A tracked file deleted in the working tree is listed too, and skipped.
    git ls-files -z --cached --others --exclude-standard |
      while IFS= read -r -d '' f; do
        if [ -e "$f" ] || [ -L "$f" ]; then cp --parents --no-dereference -t "$tmp/tree" -- "$f"; fi
      done
    (cd "$tmp/tree" && "$bin" dir "${common[@]}" .) || rc=$?
    ;;
  *)
    echo "usage: ci/gitleaks.sh history|tree [gitleaks-binary]" >&2
    exit 2
    ;;
esac
if [ "$rc" -ne 0 ]; then
  if [ -s "$tmp/report.json" ]; then
    echo "gitleaks findings (rule, file:line, commit; the values are not printed):" >&2
    jq -r '.[] | "\(.RuleID)\t\(.File):\(.StartLine)\t\(if .Commit == "" then "(working tree)" else .Commit end)"' \
      "$tmp/report.json" >&2
  fi
  echo "gitleaks failed (exit $rc)" >&2
  exit 1
fi
echo "gitleaks ($mode): no leaks found"
