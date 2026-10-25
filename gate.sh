#!/usr/bin/env bash
# The gate every change must pass before it is committed (the plan's Engineering
# practice). It runs every CI check that can fail and fits on one machine:
# cargo-nextest, cargo-llvm-cov, cargo-udeps, cargo-deny, cargo-audit,
# cargo-machete, cargo-vet and typos at the versions CI pins, on the Rust
# toolchains CI pins (required; bootstrap.sh installs them), the Semgrep rule
# cases and scan with the semgrep version CI's image pins (required;
# bootstrap.sh installs it), the cargo-geiger counts, which must equal
# ci/geiger-baseline.txt, and the check that every action in the workflows is
# pinned by commit (ci/pinned-actions.sh). gitleaks
# runs over the working tree when it is installed (the plan's local check; CI
# scans the full history). CI adds the other operating systems, CodeQL, and
# ClusterFuzzLite once it is configured. Needs the network: cargo-audit and
# cargo-deny fetch the advisory database, each into its own clone (see
# deny.toml), and the Semgrep scan fetches the community rules. Works from any
# directory and stops at the first failing step.
set -euo pipefail
cd "$(dirname "$0")"

step() { echo "== $*"; "$@"; }

# The pinned tools first, so that a wrong version stops the gate before the
# long steps. cargo-nextest, cargo-llvm-cov, cargo-udeps, cargo-deny,
# cargo-audit, cargo-machete and cargo-vet at the exact versions CI installs,
# so that the gate and CI judge alike: CI once took the newest cargo-vet it
# found, 0.10.0, whose formatter rejects the supply-chain/imports.lock that
# 0.10.2 writes, and main went red (run 39160240196). cargo-mutants
# (mutants.yml), cargo-fuzz and cargo-careful (nightly.yml), which the gate
# does not run, at the versions those workflows install, so that a survivor, a
# crash or a finding they report reproduces here with the same tool (a
# cargo-mutants release can make other mutants). need_tool reads the first
# X.Y.Z on the first line of the tool's --version (cargo-nextest prints its
# commit and date after it); cargo-careful has no --version, so need_tool
# takes the version cargo install recorded. A bump is one reviewed change to
# these lines, the workflow and bootstrap.sh; Dependabot cannot see the pins,
# so the weekly Dependabot review checks them for new releases.
# installs <workflow> <crate>: print each place the workflow installs the
# crate, one per line as written there: an item of an install-action `tool:`
# list, an install-action step named after the crate (`uses:
# taiki-e/install-action@<crate>`), or a `cargo install` command. Comments are
# not install lines.
installs() {
  awk -v crate="$2" '
    {
      line = $0
      sub(/^[ \t]*(-[ \t]+)?/, "", line)
      sub(/[ \t]+#.*$/, "", line)
      sub(/[ \t]+$/, "", line)
    }
    line ~ /^tool:/ {
      sub(/^tool:[ \t]*/, "", line)
      gsub(/["\047]/, "", line)
      n = split(line, items, /[ \t,]+/)
      for (i = 1; i <= n; i++) {
        name = items[i]
        sub(/@.*/, "", name)
        if (name == crate) print items[i]
      }
      next
    }
    line ~ /^uses:[ \t]*taiki-e\/install-action@/ {
      name = line
      sub(/^uses:[ \t]*taiki-e\/install-action@/, "", name)
      if (name == crate) print line
      next
    }
    line ~ /^(run:[ \t]*)?cargo[ \t]+install[ \t]/ {
      sub(/^run:[ \t]*/, "", line)
      n = split(line, words, /[ \t]+/)
      for (i = 3; i <= n; i++) {
        name = words[i]
        sub(/@.*/, "", name)
        if (name == crate) { print line; break }
      }
    }
  ' "$1"
}
# need_tool <crate> <version> <the one install line> <workflow...>: stop unless
# the installed crate is that version and each workflow installs the crate only
# by that line (an install-action item without @version is another line).
need_tool() {
  local crate=$1 version=$2 spelled=$3 have file found
  shift 3
  have=$(cargo "${crate#cargo-}" --version 2> /dev/null | awk '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+$/) { sub(/^v/, "", $i); print $i; break }
      }
    }') || true
  if [ -z "$have" ] && command -v "$crate" > /dev/null; then
    have=$(cargo install --list | awk -v c="$crate" '$1 == c { v = $2; sub(/^v/, "", v); sub(/:$/, "", v); print v }') || true
  fi
  if [ "$have" != "$version" ]; then
    echo "$crate $version is needed (found: ${have:-none}); install it for this user:" >&2
    echo "  cargo install --locked $crate --version $version" >&2
    exit 1
  fi
  for file in "$@"; do
    if ! found=$(installs "$file" "$crate"); then
      echo "cannot read $file" >&2
      exit 1
    fi
    if [ -z "$found" ] || printf '%s\n' "$found" | grep -qvxF -- "$spelled"; then
      echo "$file must install $crate $version only as \`$spelled\`; the gate and CI" >&2
      echo "must pin one version. It installs $crate as:" >&2
      printf '%s\n' "${found:-(nothing)}" | sed 's/^/  /' >&2
      exit 1
    fi
  done
}
wf=.github/workflows
need_tool cargo-nextest 0.9.148 cargo-nextest@0.9.148 $wf/ci.yml
need_tool cargo-llvm-cov 0.9.1 cargo-llvm-cov@0.9.1 $wf/ci.yml
need_tool cargo-udeps 0.1.61 cargo-udeps@0.1.61 $wf/ci.yml
need_tool cargo-deny 0.20.2 cargo-deny@0.20.2 $wf/ci.yml
need_tool cargo-audit 0.22.2 cargo-audit@0.22.2 $wf/ci.yml $wf/nightly.yml
need_tool cargo-machete 0.9.2 cargo-machete@0.9.2 $wf/ci.yml
need_tool cargo-vet 0.10.2 'cargo install cargo-vet --version 0.10.2 --locked' $wf/ci.yml
need_tool cargo-mutants 27.1.0 cargo-mutants@27.1.0 $wf/mutants.yml
need_tool cargo-fuzz 0.13.2 'cargo install cargo-fuzz --version 0.13.2 --locked' $wf/nightly.yml
need_tool cargo-careful 0.4.10 cargo-careful@0.4.10 $wf/nightly.yml
# Semgrep with CI's version (its image tag in ci.yml).
semgrep_version=1.181.0
if ! have=$(semgrep --version 2> /dev/null) || [ "$have" != "$semgrep_version" ]; then
  echo "semgrep $semgrep_version is needed (found: ${have:-none}); install it for this user:" >&2
  echo "  pipx install --force semgrep==$semgrep_version" >&2
  exit 1
fi
# typos with CI's version: ci.yml runs the crate-ci/typos action, whose release
# commit names the typos it downloads, so its one step must be pinned by commit
# with this version in the comment (Dependabot moves both together).
typos_version=1.51.1
if ! have=$(typos --version 2> /dev/null) || [ "$have" != "typos-cli $typos_version" ]; then
  echo "typos $typos_version is needed (found: ${have:-none}); install it for this user:" >&2
  echo "  cargo install --locked typos-cli --version $typos_version" >&2
  exit 1
fi
found=$(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*crate-ci/typos' $wf/ci.yml \
        | sed -E 's/^[[:space:]]*(-[[:space:]]+)?//') || [ $? -eq 1 ]
re="^uses: crate-ci/typos@[0-9a-f]{40} # v${typos_version//./\\.}\$"
if [[ $found == *$'\n'* || ! $found =~ $re ]]; then
  echo "$wf/ci.yml must run typos $typos_version as one step," >&2
  echo "\`uses: crate-ci/typos@<release commit> # v$typos_version\`. It has:" >&2
  printf '%s\n' "${found:-(nothing)}" | sed 's/^/  /' >&2
  exit 1
fi
# The Rust toolchains CI pins (ci.yml's header says how): stable 1.99.0, which
# rust-toolchain.toml's `channel = "stable"` gives this checkout, and
# nightly-2026-10-14 for cargo-udeps below and nightly.yml's jobs. Neither check
# downloads anything (RUSTUP_AUTO_INSTALL=0). A bump is one reviewed change to
# these two lines and the workflows, with bootstrap.sh and CONTRIBUTING.md.
rust_stable=1.99.0
rust_nightly=nightly-2026-10-14
have=$(RUSTUP_AUTO_INSTALL=0 rustc --version 2> /dev/null | awk 'NR == 1 { print $2 }') || true
if [ "$have" != "$rust_stable" ]; then
  echo "rustc $rust_stable is needed in this checkout (found: ${have:-none}), whose" >&2
  echo "rust-toolchain.toml names stable. An older stable: rustup update stable. A newer" >&2
  echo "one: move the pin (gate.sh and the workflows), or use $rust_stable here:" >&2
  echo "  rustup toolchain install $rust_stable --profile minimal --component rustfmt,clippy,llvm-tools-preview" >&2
  echo "  rustup override set $rust_stable" >&2
  exit 1
fi
installed=$(rustup toolchain list)
if ! grep -q "^$rust_nightly-" <<< "$installed"; then
  echo "Rust $rust_nightly is needed (found: none); install it for this user:" >&2
  echo "  rustup toolchain install $rust_nightly --profile minimal" >&2
  exit 1
fi
# toolchains <workflow>: print what the workflow says about Rust toolchains, one
# per line: `value <name>` for each `toolchain:` input, each RUSTUP_TOOLCHAIN
# and each `+<name>` after cargo, rustc or rustup; and `job <job> <installs>
# <runs>` for each dtolnay/rust-toolchain step: the toolchain it installs and
# the RUSTUP_TOOLCHAIN its job runs with, the job's own or else the workflow's
# (`-` for none, and for a step with no `toolchain:`). Comments are skipped.
toolchains() {
  awk '
    {
      line = $0
      if (line ~ /^[ \t]*#/) next
      sub(/[ \t]+#.*$/, "", line)
      sub(/[ \t]+$/, "", line)
      if (line == "") next
      match(line, /^ */)
      indent = RLENGTH
      key = line
      sub(/^[ \t]*(-[ \t]+)?/, "", key)
    }
    indent == 0 { section = key; sub(/:.*/, "", section) }
    section == "jobs" && indent == 2 { job = key; sub(/:.*/, "", job); want = 0 }
    section == "jobs" && indent == 4 { in_job_env = (key == "env:") }
    line ~ /^[ \t]*- / { want = 0 }
    key ~ /^uses:[ \t]*dtolnay\/rust-toolchain@/ { n++; step_job[n] = job; step_tc[n] = "-"; want = 1 }
    key ~ /^toolchain:/ {
      v = key
      sub(/^toolchain:[ \t]*/, "", v)
      print "value " v
      if (want) { step_tc[n] = v; want = 0 }
    }
    key ~ /^RUSTUP_TOOLCHAIN:/ {
      v = key
      sub(/^RUSTUP_TOOLCHAIN:[ \t]*/, "", v)
      print "value " v
      if (section == "env" && indent == 2) wf_env = v
      if (section == "jobs" && indent == 6 && in_job_env) job_env[job] = v
    }
    {
      s = line
      while (match(s, /(cargo|rustc|rustup)[ \t]+\+[^ \t"\047;|&)]+/)) {
        t = substr(s, RSTART, RLENGTH)
        sub(/^[^+]*\+/, "", t)
        print "value " t
        s = substr(s, RSTART + RLENGTH)
      }
    }
    END {
      for (i = 1; i <= n; i++) {
        e = (step_job[i] in job_env) ? job_env[step_job[i]] : wf_env
        print "job " step_job[i] " " step_tc[i] " " (e == "" ? "-" : e)
      }
    }
  ' "$1"
}
for file in $wf/*.yml; do
  if ! found=$(toolchains "$file"); then
    echo "cannot read $file" >&2
    exit 1
  fi
  bad=$(printf '%s\n' "$found" | awk -v s="$rust_stable" -v n="$rust_nightly" '
    $1 == "value" && $2 != s && $2 != n
    $1 == "job" && ($3 != $4 || ($3 != s && $3 != n))')
  if [ -n "$bad" ]; then
    echo "$file must name only the Rust toolchains $rust_stable and $rust_nightly, and" >&2
    echo "each rust-toolchain step must install the RUSTUP_TOOLCHAIN its job runs with." >&2
    echo "It has:" >&2
    printf '%s\n' "$bad" | sed 's/^/  /' >&2
    exit 1
  fi
done

step cargo fmt --all --check
step cargo clippy --workspace --all-targets --all-features -- -D warnings
step cargo nextest run --workspace --all-features
step cargo test --workspace --doc
step env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items
step cargo deny check
step cargo deny --config deny-production.toml check bans
step cargo audit
step cargo machete
step cargo vet --locked
step cargo "+$rust_nightly" udeps --workspace --all-targets
step typos
# Semgrep as CI runs it. The scan covers the files git tracks, so `git add` (or
# `git add -N`) a new file first.
step semgrep --test --metrics=off --config .semgrep/project.yml .semgrep/tests/project.rs
step semgrep scan --metrics=off --timeout 60 --config p/rust --config .semgrep --exclude .semgrep --error
# gitleaks, the gate's one optional step: bootstrap.sh does not install it.
if command -v gitleaks > /dev/null; then
  step ci/gitleaks.sh tree
else
  echo "== skipped: gitleaks (not installed; CI runs it). Install: ci/gitleaks-install.sh ~/.local/bin"
fi
step ci/test-geiger.sh
step ci/geiger.sh
step ci/test-no-hostnames.sh
step ci/no-hostnames.sh
# Every action in the workflows pinned by commit (the pinning rule in ci.yml).
step ci/test-pinned-actions.sh
step ci/pinned-actions.sh
# The line-ending attributes of the test vectors and fuzz seeds (.gitattributes).
step ci/test-vector-line-endings.sh
# The scripts mutants.yml and nightly.yml's fuzz jobs run, on stand-ins for the tools.
step ci/test-mutants.sh
step ci/test-fuzz-targets.sh
# 90% line coverage on each of the crates the plan names, and on the index
# crate, which TM-17, TM-40 and TM-41 name as their enforcer (review ruling of
# 2026-10-22), measured per crate: only that crate's own files count, so a
# well-tested neighbour cannot mask it.
for c in keys protocol index engine; do
  others=$(ls crates | grep -vx "$c" | paste -sd'|' -)
  step cargo llvm-cov nextest --all-features --fail-under-lines 90 \
    -p "licketysync-$c" --ignore-filename-regex "crates/($others)/"
done
echo "== gate passed"
