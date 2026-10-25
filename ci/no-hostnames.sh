#!/usr/bin/env bash
# No host the user did not turn on: every hostname or IPv4 address inside a string
# literal under crates/ must be listed in spec/allowed-hosts.txt (empty in phase 0,
# when the binaries contact nothing). Comment lines, the join-link prefix (below),
# loopback, unspecified and the RFC 5737 documentation addresses are skipped; no
# other URL on the project's own domains is. This catches accidents, not
# adversaries; the two reviewers do the latter. Known limits: names ending in one
# of six top-level domains; string literals on one line in .rs files, so not
# Cargo.toml, included data files, IPv6 or hosts assembled from pieces; a line that
# starts with a block comment is skipped whole; a version string with four numbers
# looks like an address. It fails closed: a stage that breaks fails the check, and
# only grep's "no match" counts as an answer.
# Usage: ci/no-hostnames.sh [repo-root] (defaults to this repository, not the
# current directory). Exit 1 on a hit. Run by gate.sh and CI; tested by
# ci/test-no-hostnames.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

# grep, where finding nothing (exit 1) is an answer and anything else, such as an
# unreadable file or a bad pattern (exit 2), stops the check.
g() { grep "$@" || [ $? -eq 1 ]; }

list=spec/allowed-hosts.txt
if [ ! -f "$list" ]; then
  echo "$list is missing" >&2
  exit 1
fi
host='([a-z0-9-]+\.)+(com|net|org|io|dev|app)\b'
ip='\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
never_remote='^(127\.|0\.0\.0\.0$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'
# The join-link prefix is the one own-domain URL a string literal may hold without
# a list entry (TM-31). The check removes the exact text
# `https://licketysync.app/join#` and checks the rest of the string, so a URL that
# begins with it passes; the reviewers confirm that the binaries, which parse and
# write join links, never request it. Any other URL on licketysync.app or
# licketysync.com, the query form `/join?` included, another scheme, a port or a
# subdomain is a host like any other and needs its line in the list.
join_prefix='https://licketysync\.app/join#'
allowed=$(g -vE '^(#|$)' "$list")
malformed=$(printf '%s\n' "$allowed" \
            | g -vE '^(([a-z0-9-]+\.)+[a-z]+|([0-9]{1,3}\.){3}[0-9]{1,3})$|^$')
if [ -n "$malformed" ]; then
  printf '%s\n' "$malformed"
  echo "$list: the line above is not a bare hostname or IPv4 address (lowercase, nothing else on the line)" >&2
  exit 1
fi
lines=$(g -rniE --include='*.rs' "$host|$ip" crates/ \
        | g -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*([[:space:]]|$))')
# Blank out escaped quotes and the '"' char literal, so they cannot pair up
# wrongly in the string-literal extraction that follows.
bad=$(printf '%s\n' "$lines" | cut -d: -f3- \
      | sed -E "s/'\"'/ /g; s/\\\\\"/ /g" \
      | g -oE '"[^"]*"' | tr 'A-Z' 'a-z' \
      | sed -E "s,$join_prefix,,g" \
      | g -oE "$host|$ip" | g -vE "$never_remote" | sort -u \
      | g -vxF -f <(printf '%s\n' "$allowed"))
if [ -n "$bad" ]; then
  for h in $bad; do printf '%s\n' "$lines" | g -iF "$h"; done | sort -u
  echo "Hosts in code that are not on $list: $bad" >&2
  exit 1
fi
echo "no-hostnames: ok"
