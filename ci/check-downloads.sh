#!/usr/bin/env bash
# Every download in the CI scripts goes through ci/download.sh, the one place
# for the curl options that retry a transient failure (an HTTP 504 from a
# download host turned main red in CI run 42568260092, 2026-11-09). This fails
# on a line that calls curl or wget on its own, in ci/*.sh, gate.sh or a
# workflow, and says to call ci/download.sh <https URL> <output file> instead.
# Skipped: ci/download.sh, which holds the options; this script; ci/test-*.sh,
# whose stand-ins for the tools are the one place their names are code; and
# comment lines (the first character that is not a blank is #), which hold
# example commands. A comment after code counts as code, and so does a line that
# only prints the tool's name (reword it): the check fails closed. Known
# limits: a command built from pieces (c=curl; "$c" ...), a download by another
# tool (gh, git, python), and a script outside these files, such as bootstrap.sh
# in the parent directory. Other downloads are not this check's to see: cargo
# retries its own, and so does taiki-e/install-action, and the Codecov upload
# has continue-on-error. It catches accidents, not adversaries; the two
# reviewers do the latter.
# Usage: ci/check-downloads.sh [repo-root] (defaults to this repository, not the
# current directory). Exit 1 on a hit. Run by gate.sh and CI; tested by
# ci/test-download.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

# grep, where finding nothing (exit 1) is an answer and anything else, such as an
# unreadable file or a bad pattern (exit 2), stops the check.
g() { grep "$@" || [ $? -eq 1 ]; }

if [ ! -f ci/download.sh ]; then
  echo "ci/download.sh is missing: the download scripts need it" >&2
  exit 1
fi
shopt -s nullglob
files=()
for f in ci/*.sh gate.sh .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$f" ] || continue # gate.sh is no pattern: nullglob leaves it when absent
  case $f in
    ci/download.sh | ci/check-downloads.sh | ci/test-*.sh) ;;
    *) files+=("$f") ;;
  esac
done
if [ ${#files[@]} -eq 0 ]; then
  echo "no script or workflow to check in $PWD" >&2
  exit 1
fi
# The tool's name as a word: not preceded by a letter, digit, _ . or - and not
# followed by a letter, digit, _ or -: curl, /usr/bin/curl, $(curl and "curl"
# hit; libcurl, curl-config, wgetrc and x.curl do not.
words='(^|[^A-Za-z0-9_.-])(curl|wget)([^A-Za-z0-9_-]|$)'
found=$(g -nHE "$words" "${files[@]}" | g -vE '^[^:]+:[0-9]+:[[:space:]]*#')
if [ -n "$found" ]; then
  printf '%s\n' "$found"
  echo "The lines above call curl or wget on their own. Call ci/download.sh <https URL> <output file> instead: it retries a transient failure such as an HTTP 504, and a script that checks the file's SHA-256 afterwards stays as safe as before." >&2
  exit 1
fi
echo "check-downloads: ok"
