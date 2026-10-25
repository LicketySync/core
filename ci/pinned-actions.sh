#!/usr/bin/env bash
# The pinning rule (ci.yml's header; the owner's decision of 2026-10-25): every
# `uses:` in a workflow names its action, or reusable workflow, by full commit
# SHA, 40 lowercase hex digits, followed by a comment that names a release tag
# (`# v1`, `# v2.9` or `# v7.0.1`), which Dependabot reads to keep the pin
# current. A local action (`./path`) passes, and so does a Docker image named
# by its digest (`docker://<image>@sha256:<64 hex digits>`). It checks the form
# only: that the tag is on that commit needs the network (`gh api
# repos/<owner>/<repo>/git/ref/tags/<tag>`), so the reviewers of a change that
# moves a pin check it. Known limits: a `uses:` in YAML flow style (`- {uses:
# ...}`) or with a quoted key is not seen; one whose value is on the next line
# fails; a line inside a block scalar (a `run: |` script) that looks like a
# `uses:` is checked like one. It fails closed: only grep's "no match" counts
# as an answer.
# Usage: ci/pinned-actions.sh [workflow directory] (defaults to this
# repository's .github/workflows, not the current directory). Exit 1 on an
# action that is not pinned, or when the directory holds no workflow. Run by
# gate.sh and CI; tested by ci/test-pinned-actions.sh.
set -euo pipefail
dir=${1:-$(dirname "$0")/../.github/workflows}

# grep, where finding nothing (exit 1) is an answer and anything else, such as an
# unreadable file (exit 2), stops the check.
g() { grep "$@" || [ $? -eq 1 ]; }

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
if [ ${#files[@]} -eq 0 ]; then
  echo "no workflow (*.yml or *.yaml) in $dir" >&2
  exit 1
fi
q="[\"']?"
key='[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*'
remote="$q[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@[:space:]\"']+)?@[0-9a-f]{40}$q[[:space:]]+#[[:space:]]*v[0-9]+(\.[0-9]+){0,2}[[:space:]]*"
local="$q(\./[^[:space:]\"']*|docker://[^@[:space:]\"']+@sha256:[0-9a-f]{64})$q([[:space:]]+#.*)?"
# Each `uses:` line as file:line:text, then the ones that are not pinned.
bad=$(g -nHE "^$key" "${files[@]}" | g -vE "^[^:]+:[0-9]+:$key($remote|$local)\$")
if [ -n "$bad" ]; then
  printf '%s\n' "$bad"
  echo "the actions above are not pinned by full commit SHA with a \`# v<version>\` comment" >&2
  exit 1
fi
echo "pinned-actions: ok"
