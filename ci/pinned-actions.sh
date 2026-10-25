#!/usr/bin/env bash
# The pinning rule (.github/workflows/ci.yml's header): every `uses:` in a
# workflow names its action, or reusable workflow, by full commit SHA, 40
# lowercase hex digits, followed by a comment that names the release tag on
# that commit (`# v1`, `# v2.9` or `# v7.0.1`), which Dependabot rewrites when
# it moves the pin. A Docker image named by its digest
# (`docker://<image>@sha256:<64 hex digits>`) also passes. A local action
# (`./path`) is refused: its own action.yml could use anything, and none is
# needed. So that no other spelling of the key slips past, any line that writes
# a `uses` key in another form is refused whole: a space before the colon, a
# quoted key, a key with escapes, a flow mapping (`{uses: ...}`), an explicit
# `?` key, an anchored or tagged key (`&a uses:`, `!!str uses:`), or an alias
# as a key (`*a : ...`, where the anchor could hold `uses`).
# It checks the form only: that the tag names that commit needs the network
# (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, an annotated tag then
# `git/tags/<sha>`), so the reviewers of a change that moves a pin check it.
# Known limits: it reads lines, not YAML, so text that looks like a `uses`
# key inside a `run:` script or after a `#` on a line is refused too (fails
# closed), and a value on the next line is refused. It fails closed: only
# grep's "no match" counts as an answer.
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
# The one form read: a block-style `uses:` key, with or without a list dash.
key='[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*'
remote="$q[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@[:space:]\"']+)?@[0-9a-f]{40}$q[[:space:]]+#[[:space:]]*v[0-9]+(\.[0-9]+){0,2}[[:space:]]*"
docker="${q}docker://[^@[:space:]\"']+@sha256:[0-9a-f]{64}$q([[:space:]]+#.*)?"
# Any other way to write the key: `uses` as a whole word (not part of a longer
# key) followed by optional quote and space and a colon; an explicit-key line;
# a double-quoted key with a backslash escape in it; an alias followed by a
# colon, that is an alias as a key.
other="(^|[^A-Za-z0-9_-])[\"']?uses[\"']?[[:space:]]*:|^[[:space:]]*(-[[:space:]]+)?\?([[:space:]]|\$)|\"[^\"]*\\\\[^\"]*\"[[:space:]]*:|(^|[[:space:]{,?])\*[^][:space:],{}[]+[[:space:]]*:"
# Each `uses:` line as file:line:text whose value is not pinned, then each other
# line (not a comment line) that writes the key some other way.
unpinned=$(g -nHE "^$key" "${files[@]}" | g -vE "^[^:]+:[0-9]+:$key($remote|$docker)\$")
unread=$(g -nHE "$other" "${files[@]}" | g -vE "^[^:]+:[0-9]+:([[:space:]]*#|$key)")
if [ -n "$unpinned$unread" ]; then
  printf '%s\n' "$unpinned" "$unread" | g -v '^$' | sort -t: -k1,1 -k2,2n
  cat >&2 <<'EOF'
The lines above break the pinning rule in .github/workflows/ci.yml's header.
Write each action as a block-style key, pinned by commit with its release tag:
  - uses: <owner>/<repo>[/<path>]@<40-hex commit> # v<release>
and find the commit a release tag names with
  gh api repos/<owner>/<repo>/git/ref/tags/<tag>
(for an annotated tag, whose object.type is "tag", then git/tags/<object.sha>).
A local action (./...) is not allowed; a Docker image needs its @sha256: digest.
EOF
  exit 1
fi
echo "pinned-actions: ok"
