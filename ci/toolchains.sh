#!/usr/bin/env bash
# The Rust toolchains the workflows use, checked against ci/pins.env (the
# pinning rule in .github/workflows/ci.yml's header). In every workflow:
# - every `toolchain:` input, every RUSTUP_TOOLCHAIN value and every `+<name>`
#   after cargo, rustc or rustup names RUST_STABLE or RUST_NIGHTLY;
# - each job whose `run:` steps call cargo, rustc or rustup, or a ci/ script
#   that does, runs with RUSTUP_TOOLCHAIN set, for the job or for the workflow
#   (rust-toolchain.toml's `channel = "stable"` would otherwise choose the
#   runner's stable of the day: ci.yml's header says why);
# - each dtolnay/rust-toolchain step installs the RUSTUP_TOOLCHAIN its job runs
#   with.
# What this cannot see, so does not pin: toolchains an action chooses for
# itself (CodeQL's Rust extractor sets its own RUSTUP_TOOLCHAIN, and
# ClusterFuzzLite builds in its own image), cargo called by a script that a
# ci/ script calls, and RUSTUP_TOOLCHAIN set for one step only (checked as a
# value, but it does not count for the job). It reads lines, not YAML: a `run:`
# is its inline value and the lines indented under it, so shell comments count
# too, and keys are read only in the block style the workflows use.
# Usage: ci/toolchains.sh [repo-root] (defaults to this repository). Exit 1 on
# a finding. Run by gate.sh and CI; tested by ci/test-toolchains.sh.
set -euo pipefail
root=${1:-$(dirname "$0")/..}
pins=$root/ci/pins.env
if [ ! -f "$pins" ]; then
  echo "$pins is missing" >&2
  exit 1
fi
if grep -nvE '^([[:space:]]*(#.*)?|[A-Z][A-Z0-9_]*=[A-Za-z0-9._:+-]+)$' "$pins" >&2; then
  echo "$pins: the lines above are not comments or KEY=value" >&2
  exit 1
fi
# shellcheck source=pins.env
. "$pins"
: "${RUST_STABLE:?$pins sets no RUST_STABLE}" "${RUST_NIGHTLY:?$pins sets no RUST_NIGHTLY}"

shopt -s nullglob
files=("$root"/.github/workflows/*.yml "$root"/.github/workflows/*.yaml)
if [ ${#files[@]} -eq 0 ]; then
  echo "no workflow in $root/.github/workflows" >&2
  exit 1
fi
words='(^|[^A-Za-z0-9_./-])(cargo|rustc|rustup)([^A-Za-z0-9_-]|$)'
# The ci/ scripts that call cargo, rustc or rustup on a line that is not a comment.
rust_scripts=
for script in "$root"/ci/*.sh; do
  if grep -vE '^[[:space:]]*#' "$script" | grep -qE "$words"; then
    rust_scripts="$rust_scripts ${script##*/}"
  fi
done

# toolchains <workflow>: one line per finding input: `value <name>` for each
# toolchain named; `step <job> <installs> <runs>` for each rust-toolchain step;
# `job <job> <runs>` for each job whose run: steps call Rust tools. <runs> is
# the job's RUSTUP_TOOLCHAIN, else the workflow's, else `-`; <installs> is `-`
# for a step with no `toolchain:`.
toolchains() {
  awk -v words="$words" -v scripts="$rust_scripts" '
    BEGIN { n_scripts = split(scripts, list, " "); for (i = 1; i <= n_scripts; i++) rust_script[list[i]] = 1 }
    function rust_text(s,    t) {
      if (s ~ words) return 1
      while (match(s, /ci\/[A-Za-z0-9_.-]+\.sh/)) {
        t = substr(s, RSTART + 3, RLENGTH - 3)
        if (t in rust_script) return 1
        s = substr(s, RSTART + RLENGTH)
      }
      return 0
    }
    function plus(s,    t) {
      while (match(s, /(cargo|rustc|rustup)[ \t]+\+[^ \t"\047;|&)]+/)) {
        t = substr(s, RSTART, RLENGTH)
        sub(/^[^+]*\+/, "", t)
        print "value " t
        s = substr(s, RSTART + RLENGTH)
      }
    }
    {
      raw = $0
      match(raw, /^ */)
      indent = RLENGTH
    }
    # The lines of a run: block scalar, comments and blank lines included.
    in_run && (raw ~ /^[ \t]*$/ || indent > run_col) {
      if (rust_text(raw)) uses_rust[job] = 1
      plus(raw)
      next
    }
    { in_run = 0 }
    raw ~ /^[ \t]*(#|$)/ { next }
    {
      line = raw
      sub(/[ \t]+#.*$/, "", line)
      sub(/[ \t]+$/, "", line)
      key = line
      sub(/^[ \t]*(-[ \t]+)?/, "", key)
      col = length(line) - length(key)
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
    key ~ /^run:/ {
      v = raw
      sub(/^[^:]*:[ \t]*/, "", v)
      if (v !~ /^[|>]/ && rust_text(v)) uses_rust[job] = 1
      plus(v)
      in_run = 1
      run_col = col
    }
    END {
      for (i = 1; i <= n; i++) {
        e = (step_job[i] in job_env) ? job_env[step_job[i]] : wf_env
        print "step " step_job[i] " " step_tc[i] " " (e == "" ? "-" : e)
      }
      for (j in uses_rust) {
        e = (j in job_env) ? job_env[j] : wf_env
        print "job " j " " (e == "" ? "-" : e)
      }
    }
  ' "$1"
}

status=0
for file in "${files[@]}"; do
  found=$(toolchains "$file")
  bad=$(printf '%s\n' "$found" | awk -v s="$RUST_STABLE" -v n="$RUST_NIGHTLY" '
    $1 == "value" && $2 != s && $2 != n
    $1 == "step" && ($3 != $4 || ($3 != s && $3 != n))
    $1 == "job" && $3 != s && $3 != n' | sort)
  if [ -n "$bad" ]; then
    printf '%s:\n' "$file"
    printf '%s\n' "$bad" | sed 's/^/  /'
    status=1
  fi
done
if [ "$status" -ne 0 ]; then
  cat >&2 <<EOF
The workflows above use a Rust toolchain other than ci/pins.env's RUST_STABLE
($RUST_STABLE) or RUST_NIGHTLY ($RUST_NIGHTLY), as the pinning rule in
.github/workflows/ci.yml's header requires. \`value <name>\` is a toolchain named
anywhere; \`job <job> <runs>\` a job that calls cargo, rustc or rustup with that
RUSTUP_TOOLCHAIN (\`-\`: none; set it for the workflow or the job); \`step <job>
<installs> <runs>\` a rust-toolchain step, which must install the job's
RUSTUP_TOOLCHAIN.
EOF
  exit 1
fi
echo "toolchains: ok"
