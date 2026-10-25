#!/usr/bin/env bash
# Tests for ci/no-hostnames.sh. Each case is a one-crate tree in a temporary
# directory with its own allow-list and lib.rs; the expected exit code is the
# assertion. Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
lint="$(cd "$(dirname "$0")" && pwd)/no-hostnames.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
n=0
fails=0
case_() { # case_ <name> <expected exit> <allow-list body> <lib.rs body>
  n=$((n + 1))
  local dir="$tmp/$n" rc=0
  mkdir -p "$dir/crates/x/src" "$dir/spec"
  printf '%s\n' "$3" > "$dir/spec/allowed-hosts.txt"
  printf '%s\n' "$4" > "$dir/crates/x/src/lib.rs"
  "$lint" "$dir" > "$dir/out" 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit $rc, expected $2"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
case_ "empty list, no hosts"                       0 "# none" 'pub fn f() {}'
case_ "licence header in a comment"                0 "# none" '// at https://mozilla.org/MPL/2.0/.'
case_ "doc link in a comment"                      0 "# none" '/// see docs.rs/foo and https://datatracker.ietf.org/doc/rfc9000'
case_ "stray host, empty list"                     1 "# none" 'const U: &str = "https://tracker.example.com/announce";'
case_ "host on the list"                           0 "tracker.example.com" 'const U: &str = "https://tracker.example.com/announce";'
case_ "subdomain of a listed host"                 1 "example.com" 'const U: &str = "https://tracker.example.com";'
case_ "join-link prefix"                           0 "# none" 'pub const P: &str = "https://licketysync.app/join#";'
case_ "query form of the prefix"                   1 "# none" 'fn q(k: &str) -> String { format!("https://licketysync.app/join?k={k}") }'
case_ "prefix does not clear what follows it"      1 "# none" 'const U: &str = "https://licketysync.app/join#a=evil.net";'
case_ "prefix beside a stray host"                 1 "# none" 'const A: &str = "https://licketysync.app/join#"; const B: &str = "https://evil.net";'
case_ "join path without # or ?"                   1 "# none" 'const U: &str = "https://licketysync.app/join";'
case_ "other path on the client domain"            1 "# none" 'const U: &str = "https://licketysync.app/latest.json";'
case_ "other scheme on the client domain"          1 "# none" 'const U: &str = "wss://licketysync.app/relay";'
case_ "port on the client domain"                  1 "# none" 'const U: &str = "https://licketysync.app:8443/join#";'
case_ "documentation domain"                       1 "# none" 'const U: &str = "https://licketysync.com/docs";'
case_ "subdomain of the client domain"             1 "# none" 'const U: &str = "https://relay.licketysync.app/join#";'
case_ "client domain as first labels of a host"    1 "# none" 'const U: &str = "https://licketysync.app.evil.net/join#";'
case_ "look-alike of the client domain"            1 "# none" 'const U: &str = "https://evil-licketysync.app/join#";'
case_ "retired client domain"                      1 "# none" 'const U: &str = "https://licketysync.dev/join#";'
case_ "own-domain host on the list"                0 "updates.licketysync.app" 'const U: &str = "https://updates.licketysync.app/latest.json";'
case_ "field access is not a host"                 0 "# none" 'fn f(m: &M, s: &S) -> u64 { m.dev() + s.net + s.app }'
case_ "malformed allow-list line fails closed"     1 "[.example.com" 'pub fn f() {}'
case_ "listed host does not clear a stray one"     1 "relay.example.com" 'const L: [&str; 2] = ["relay.example.com", "evil.net"];'
case_ "blank lines and comments in the list"       0 $'# relays\n\ntracker.example.com\n' 'const U: &str = "tracker.example.com";'
case_ "deref assignment is not a comment"          1 "# none" '*slot = "evil.com".into();'
case_ "block comment continuation line"            0 "# none" ' * see evil.com for details'
case_ "uppercase host"                             1 "# none" 'const U: &str = "TRACKER.EXAMPLE.COM";'
case_ "uppercase host on the list"                 0 "tracker.example.com" 'const U: &str = "Tracker.Example.com";'
case_ "public IPv4 address"                        1 "# none" 'const B: &str = "104.131.131.82:4001";'
case_ "multiaddr with a public IPv4 address"       1 "# none" 'const B: &str = "/ip4/104.131.131.82/tcp/4001";'
case_ "IPv4 address on the list"                   0 "104.131.131.82" 'const B: &str = "104.131.131.82:4001";'
case_ "loopback and unspecified addresses"         0 "# none" 'const L: [&str; 2] = ["127.0.0.1:8384", "0.0.0.0:0"];'
case_ "documentation-range address in a test"      0 "# none" 'const T: &str = "203.0.113.5:4001";'
case_ "IPv4 address in a comment"                  0 "# none" '// bootstrap was 104.131.131.82 once'
case_ "bad entry: not a hostname or address"       1 "relay example com" 'pub fn f() {}'
case_ "escaped quote before a host"                1 "# none" 'const S: &str = "a\"evil.com\"b";'
case_ "quote char literal before a host"           1 "# none" "const Q: char = '\"'; const S: &str = \"evil.com\";"
# a missing allow-list fails closed: built by hand because case_ always writes one
n=$((n + 1)); dir="$tmp/$n"; mkdir -p "$dir/crates/x/src"; echo 'pub fn f() {}' > "$dir/crates/x/src/lib.rs"
if "$lint" "$dir" > "$dir/out" 2>&1; then echo "FAIL missing allow-list: passed"; fails=$((fails + 1)); else echo "ok   missing allow-list fails closed"; fi
# a broken stage fails the check rather than printing ok (built by hand: each
# needs a tree case_ does not make, or a different PATH)
fails_closed() { # fails_closed <name> <dir> [env assignment...]
  local name=$1 dir=$2 rc=0
  shift 2
  env "$@" "$lint" "$dir" > "$dir/out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] && ! grep -q 'no-hostnames: ok' "$dir/out"; then
    echo "ok   $name fails closed"
  else
    echo "FAIL $name: exit $rc"
    cat "$dir/out"
    fails=$((fails + 1))
  fi
}
n=$((n + 1)); dir="$tmp/$n"; mkdir -p "$dir/spec"; echo '# none' > "$dir/spec/allowed-hosts.txt"
fails_closed "missing crates/ directory" "$dir"
n=$((n + 1)); dir="$tmp/$n"; mkdir -p "$dir/crates/x/src" "$dir/spec" "$tmp/broken-sed"
echo '# none' > "$dir/spec/allowed-hosts.txt"; echo 'pub fn f() {}' > "$dir/crates/x/src/lib.rs"
printf '#!/bin/sh\nexit 2\n' > "$tmp/broken-sed/sed"; chmod +x "$tmp/broken-sed/sed"
fails_closed "a sed that fails" "$dir" PATH="$tmp/broken-sed:$PATH"
echo "$n cases, $fails failed"
[ "$fails" -eq 0 ]
