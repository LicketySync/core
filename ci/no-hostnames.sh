#!/usr/bin/env bash
# No host the user did not turn on: every hostname or IPv4 address inside a string
# literal under crates/ must be listed in spec/allowed-hosts.txt (empty in phase 0,
# when the binaries contact nothing). Comment lines, the project's own domains,
# loopback, unspecified and the RFC 5737 documentation addresses are skipped. This
# catches accidents, not adversaries; the two reviewers do the latter. Known
# limits: names ending in one of six top-level domains; string literals on one
# line in .rs files, so not Cargo.toml, included data files, IPv6 or hosts
# assembled from pieces; a line that starts with a block comment is skipped whole;
# a version string with four numbers looks like an address.
# Usage: ci/no-hostnames.sh [repo-root] (defaults to this repository, not the
# current directory). Exit 1 on a hit. Run by gate.sh and CI; tested by
# ci/test-no-hostnames.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

list=spec/allowed-hosts.txt
if [ ! -f "$list" ]; then
  echo "$list is missing" >&2
  exit 1
fi
host='([a-z0-9-]+\.)+(com|net|org|io|dev|app)\b'
ip='\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
never_remote='^(127\.|0\.0\.0\.0$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'
allowed=$(grep -vE '^(#|$)' "$list" || true)
if printf '%s\n' "$allowed" | grep -vE '^(([a-z0-9-]+\.)+[a-z]+|([0-9]{1,3}\.){3}[0-9]{1,3})$|^$'; then
  echo "$list: the line above is not a bare hostname or IPv4 address (lowercase, nothing else on the line)" >&2
  exit 1
fi
lines=$(grep -rniE --include='*.rs' "$host|$ip" crates/ \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*([[:space:]]|$))' || true)
# Blank out escaped quotes and the '"' char literal, so they cannot pair up
# wrongly in the string-literal extraction that follows.
bad=$(printf '%s\n' "$lines" | cut -d: -f3- \
      | sed -E "s/'\"'/ /g; s/\\\\\"/ /g" \
      | grep -oE '"[^"]*"' | tr 'A-Z' 'a-z' \
      | sed -E 's/(^|[^a-z0-9.-])licketysync\.(com|dev)\b/\1/g' \
      | grep -oE "$host|$ip" | grep -vE "$never_remote" | sort -u \
      | grep -vxF -f <(printf '%s\n' "$allowed") || true)
if [ -n "$bad" ]; then
  for h in $bad; do printf '%s\n' "$lines" | grep -iF "$h"; done | sort -u
  echo "Hosts in code that are not on $list: $bad" >&2
  exit 1
fi
echo "no-hostnames: ok"
