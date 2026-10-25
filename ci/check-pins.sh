#!/usr/bin/env bash
# Checks ci/pins.env before anything sources it: every line is blank, a comment,
# or KEY=value with KEY one of the keys below, each at most once, and a value of
# letters, digits and `._:+-` only. So sourcing it can set no other variable
# (not PATH, HOME, IFS, LC_ALL or any CARGO_ or RUSTUP_ setting that a tool
# reads) and run nothing. A new pin adds its key here and in pins.env, in one
# reviewed change. gate.sh, ci/toolchains.sh, ci/gitleaks-install.sh and the
# parent directory's bootstrap.sh run it; tested by ci/test-check-pins.sh.
# Usage: ci/check-pins.sh [pins file] (defaults to this directory's pins.env).
# Exit 1, printing the lines at fault, when the file breaks a rule or is missing.
set -euo pipefail
pins=${1:-$(dirname "$0")/pins.env}
keys='RUST_STABLE RUST_NIGHTLY
CARGO_NEXTEST CARGO_LLVM_COV CARGO_UDEPS CARGO_DENY CARGO_AUDIT CARGO_MACHETE
CARGO_VET CARGO_MUTANTS CARGO_FUZZ CARGO_CAREFUL CARGO_GEIGER CARGO_AUDITABLE
CARGO_CYCLONEDX CARGO_SEMVER_CHECKS
TYPOS SEMGREP SEMGREP_IMAGE_DIGEST GITLEAKS GITLEAKS_LINUX_X64_SHA256 CODECOV_CLI'
if [ ! -f "$pins" ]; then
  echo "$pins is missing" >&2
  exit 1
fi
if ! bad=$(awk -v keys="$keys" '
    BEGIN { n = split(keys, list, /[ \n]+/); for (i = 1; i <= n; i++) allowed[list[i]] = 1 }
    /^[ \t]*(#.*)?$/ { next }
    {
      eq = index($0, "=")
      key = substr($0, 1, eq - 1)
      value = substr($0, eq + 1)
      if (eq == 0 || !(key in allowed) || value !~ /^[A-Za-z0-9._:+-]+$/) {
        print FILENAME ":" NR ": " $0
      } else if (key in seen) {
        print FILENAME ":" NR ": " $0 "   (" key " is set twice)"
      }
      seen[key] = 1
    }
  ' "$pins"); then
  echo "cannot read $pins" >&2
  exit 1
fi
if [ -n "$bad" ]; then
  printf '%s\n' "$bad" >&2
  echo "$pins: each line must be blank, a comment, or KEY=value with a key that" >&2
  echo "ci/check-pins.sh lists (once) and a value of letters, digits and ._:+- only." >&2
  exit 1
fi
