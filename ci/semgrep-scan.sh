#!/usr/bin/env bash
# The Semgrep checks of gate.sh and CI, in one place so that both run the same
# commands, and the layout checks that keep a file from escaping them
# (threat-model.md TM-7, TM-14, TM-23). ci/test-semgrep-scan.sh tests them on
# made-up trees, since `semgrep --test` ignores a rule's paths.
# 1. The project rules' cases: `semgrep --test` on each rules file with its
#    cases file.
# 2. The root's .semgrepignore and no other, in any case, among the files git
#    tracks or sees untracked: a deeper one would hide its directory from
#    every rule, and without the root's, Semgrep skips its default list
#    (directories named tests, vendor, build and others).
# 3. The project rules (.semgrep/*.yml) over every file git tracks and every
#    untracked file it does not ignore, but the two cases files, with
#    nosemgrep comments ignored (--disable-nosem). Semgrep skips no file for
#    its size (--max-target-bytes=0), for looking like an image or other
#    binary (--no-exclude-binary-files), or once three rules time out on it
#    (--timeout-threshold=0); --timeout 60 is per rule and file (default 5 s;
#    the community unsafe-usage rule once took longer on two keys test
#    modules on a CI runner). Fails on any finding; on any error but a parse
#    error, which only the Rust-language rules meet (a timeout skips a rule on
#    a file); and on any file in the word rule's scope (ci/scope.py) that the
#    scan did not scan.
# 4. The layout, over the same files: no name with a control character (a line
#    break can split an entry in a .d file); no symbolic link anywhere
#    (Semgrep skips them, and rustc follows them); no .cargo/config or
#    .cargo/config.toml, which could add rustflags, environment or a linker;
#    and every path in
#    every Cargo.toml resolved: a target's (lib, bin, test, bench, example)
#    must be a .rs file git lists, and any other must be a directory with a
#    Cargo.toml git lists. Needs Python 3.11 or later (tomllib).
# 5. The community Rust rules (p/rust, fetched from Semgrep's registry), in a
#    scan of their own, where nosemgrep comments still silence them.
# Every check runs, then the script exits 1 if any failed.
# Usage: ci/semgrep-scan.sh [--project-only] [repo-root]. --project-only leaves
# out step 5, which needs the network (the tests use that). Needs semgrep, git
# and python3.
set -euo pipefail
community=1
if [ "${1:-}" = --project-only ]; then
  community=0
  shift
fi
here="$(cd "$(dirname "$0")" && pwd)"
cd "${1:-$here/..}"
if ! command -v python3 > /dev/null; then
  echo "ci/semgrep-scan.sh needs python3" >&2
  exit 1
fi
# The cases files, from ci/scope.py, which defines the word rule's scope.
mapfile -t cases < <(python3 -I -c 'import importlib.util, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("scope", os.path.join(sys.argv[1], "scope.py"))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
print("\n".join(scope.CASES))' "$here")
flags=(--metrics=off --disable-version-check --timeout 60 --timeout-threshold=0
  --max-target-bytes=0 --no-exclude-binary-files)
excludes=()
for c in "${cases[@]}"; do
  excludes+=(--exclude "/$c")
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

echo "== semgrep --test: the project rules' cases"
semgrep --test --metrics=off --config .semgrep/project.yml .semgrep/tests/project.rs || failed=1
semgrep --test --metrics=off --config .semgrep/manifests.yml .semgrep/tests/manifests.toml || failed=1

ignores=$(git ls-files -co --exclude-standard -- ':(glob,icase)**/.semgrepignore')
if [ "$ignores" != .semgrepignore ]; then
  echo "== the root's .semgrepignore must be the only one; git lists:"
  printf '%s\n' "${ignores:-(none)}" | sed 's/^/  /'
  failed=1
fi

echo "== semgrep scan: the project rules, nosemgrep off"
git ls-files -z -co --exclude-standard > "$tmp/files"
rc=0
semgrep scan "${flags[@]}" --disable-nosem --config .semgrep "${excludes[@]}" \
  --json --output "$tmp/scan.json" > "$tmp/scan.log" 2>&1 || rc=$?
if [ "$rc" != 0 ]; then
  cat "$tmp/scan.log"
  echo "== semgrep exited $rc"
  failed=1
else
  python3 -I - "$here" "$tmp/scan.json" "$tmp/files" <<'PY' || failed=1
import importlib.util, json, os, re, sys

sys.dont_write_bytecode = True
# ci/scope.py, loaded by its path: no directory joins the import path, so no
# file beside it (a tomllib.py, say) can stand in for a standard module.
spec = importlib.util.spec_from_file_location("scope", os.path.join(sys.argv[1], "scope.py"))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
in_scope = scope.in_scope

try:
    import tomllib
except ImportError:
    print("== ci/semgrep-scan.sh needs Python 3.11 or later (tomllib)")
    sys.exit(1)

report, listing = sys.argv[2], sys.argv[3]
with open(report, encoding="utf-8") as f:
    data = json.load(f)
with open(listing, "rb") as f:
    files = sorted({p.decode("utf-8", "surrogateescape") for p in f.read().split(b"\0") if p})
present = [p for p in files if os.path.lexists(p)]
listed = set(present)
bad = False

for p in files:
    if re.search(r"[\x00-\x1f\x7f]", p):
        print(f"== a name with a control character: {p!r}")
        bad = True

for r in data.get("results", []):
    rule = r["check_id"].rsplit(".", 1)[-1]
    print(f"== finding: {rule} at {r['path']}:{r['start']['line']}")
    bad = True
parse = ("PartialParsing", "Syntax error", "Lexical error", "Other syntax error")
for e in data.get("errors", []):
    kind = e.get("type")
    kind = kind[0] if isinstance(kind, list) else str(kind)
    if not kind.startswith(parse):
        print(f"== semgrep error: {kind}: {e.get('path', '')}: {str(e.get('message', ''))[:300]}")
        bad = True

scanned = {os.path.normpath(p) for p in data.get("paths", {}).get("scanned", [])}
for p in present:
    if in_scope(p) and os.path.normpath(p) not in scanned:
        print(f"== not scanned: {p}")
        bad = True

for p in present:
    if os.path.islink(p):
        print(f"== a symbolic link: {p}")
        bad = True
    parts = [part.lower() for part in p.split("/")]
    if len(parts) >= 2 and parts[-2] == ".cargo" and parts[-1] in ("config", "config.toml"):
        print(f"== a cargo configuration file: {p}")
        bad = True


def is_listed_file(p):
    return p in listed and os.path.isfile(p) and not os.path.islink(p)


targets = ("lib", "bin", "test", "bench", "example")
for m in present:
    if os.path.basename(m).lower() != "cargo.toml":
        continue
    try:
        with open(m, "rb") as f:
            manifest = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"== a manifest that does not parse: {m}: {e}")
        bad = True
        continue
    base = os.path.dirname(m)

    def resolve(value):
        return os.path.normpath(os.path.join(base, value)) if isinstance(value, str) else None

    for kind in targets:
        entries = manifest.get(kind)
        entries = [entries] if isinstance(entries, dict) else entries if isinstance(entries, list) else []
        for entry in entries:
            if isinstance(entry, dict) and "path" in entry:
                r = resolve(entry["path"])
                if r is None or not r.endswith(".rs") or not is_listed_file(r):
                    print(f"== a target path that is not a .rs file git lists: {m}: {entry['path']!r}")
                    bad = True

    def walk(node, top):
        global bad
        if isinstance(node, dict):
            if not top and "path" in node:
                r = resolve(node["path"])
                if r is None or not is_listed_file(os.path.join(r, "Cargo.toml")):
                    print(f"== a path that is not a directory with a Cargo.toml git lists: {m}: {node['path']!r}")
                    bad = True
            for k, v in node.items():
                if not (top and k in targets):
                    walk(v, False)
        elif isinstance(node, list):
            for v in node:
                walk(v, False)

    walk(manifest, True)

if not bad:
    print(f"== the project rules: no finding; {len(scanned)} files scanned; the layout holds")
sys.exit(1 if bad else 0)
PY
fi

if [ "$community" = 1 ]; then
  echo "== semgrep scan: the community Rust rules"
  semgrep scan "${flags[@]}" --config p/rust "${excludes[@]}" --error || failed=1
fi
if [ "$failed" != 0 ]; then
  echo "== ci/semgrep-scan.sh failed"
  exit 1
fi
