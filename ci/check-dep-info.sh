#!/usr/bin/env bash
# What rustc read for each workspace crate, from the dep-info files a build
# left (threat-model.md TM-7). The text rules in .semgrep/ cannot see a path
# attribute that a macro assembles from tokens passed one at a time
# (m!(#, path, =, "...")); rustc lists every file it read in the crate's .d
# file, and this check reads those lists. A .d file reflects the cfg of the
# build that wrote it, so the check runs after each build that matters:
# gate.sh at its end; in CI, clippy and a release `cargo check` on Linux,
# nextest on Linux, Windows and macOS, and net's builds for Android and iOS;
# and release.yml after its release build.
# It reads every .d file under the target directory but in build scripts'
# output directories, which hold other tools' depfiles (the workspace has no
# build script). A .d file is a workspace crate's when it names, read loosely,
# a file in this repository outside the target directory; then it is read
# strictly: a comment, `target: deps` or `path:` and nothing else (a name with
# a line break or other control character fails), escaped spaces unescaped.
# Every file it names must be, resolved as rustc resolved it (from the
# repository's root, symbolic links followed, no lexical shortcut):
# - one the word rule scans (ci/scope.py's trusted: not under the vendored
#   tree, part of which the extern rule leaves out), not a symbolic link;
# - under the target directory, not listed by git (in any case), and a
#   compiled artifact by its name and signature together: an rlib, an rmeta,
#   or a proc-macro library (.so ELF, .dylib Mach-O, .dll PE with its PE
#   header). The workspace has no build script, so no generated source there
#   is allowed, and git may list no file under the target directory at all;
# - or, outside the repository, a compiled crate (.rlib or .rmeta, by name and
#   signature), the toolchain's.
# A compiled artifact must also not be UTF-8, which rustc reads every source
# as; real ones stop decoding within their first 12 KB.
# A source in cargo's registry, a git checkout or the toolchain fails. Other
# crates' .d files are not judged. A file a workspace crate's
# .d names that no longer exists fails, in CI (CI set) in every .d; locally
# only in the newest .d of each crate and kind (by modification time, per
# directory and file name before its hash), since older ones are stale .d
# files of earlier builds, which are skipped and counted. CI's rust-cache
# keeps no workspace crate's build (cache-workspace-crates: false), so its .d
# files are all this run's.
# Usage: ci/check-dep-info.sh [repo-root] [target-dir]. The target directory
# defaults to $CARGO_TARGET_DIR, else <repo-root>/target. Exit 1 on any file
# outside, a missing file as above, a malformed line, or when no workspace
# crate's .d is found (nothing was built there). Needs git and Python 3
# (python3, else python, as on Windows).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "${1:-$here/..}"
target=${2:-${CARGO_TARGET_DIR:-$PWD/target}}
# The first of python3 and python that runs Python 3 (on Windows, python3 can
# be a stand-in that only offers to install it).
py=
for c in python3 python; do
  if command -v "$c" > /dev/null && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2> /dev/null; then
    py=$c
    break
  fi
done
if [ -z "$py" ]; then
  echo "ci/check-dep-info.sh needs Python 3" >&2
  exit 1
fi
"$py" -I - "$here" "$PWD" "$target" <<'PY'
import codecs, importlib.util, os, re, subprocess, sys

sys.dont_write_bytecode = True
# ci/scope.py, loaded by its path: no directory joins the import path, so no
# file beside it can stand in for a standard module.
spec = importlib.util.spec_from_file_location("scope", os.path.join(sys.argv[1], "scope.py"))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)

root, target = (os.path.realpath(a) for a in sys.argv[2:4])
strict = bool(os.environ.get("CI"))
control = re.compile(r"[\x00-\x1f\x7f]")

listing = subprocess.run(["git", "ls-files", "-z", "-co", "--exclude-standard"],
                         check=True, capture_output=True).stdout
listed = {p.decode("utf-8", "surrogateescape") for p in listing.split(b"\0") if p}
scanned = {p for p in listed if scope.trusted(p)}
# Compared in any case, as macOS and Windows open them.
listed_any_case = {p.lower() for p in listed}


def under(path, base):
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def shown(path):
    """The path relative to the root, or whole when it is on another drive."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    return path if rel.startswith("..") else rel.replace(os.sep, "/")


def head(path, n, at=0):
    try:
        with open(path, "rb") as f:
            f.seek(at)
            return f.read(n)
    except OSError:
        return b""


def pe(path):
    """A PE image: MZ, and the PE signature where the DOS header's e_lfanew points."""
    dos = head(path, 64)
    if len(dos) < 64 or dos[:2] != b"MZ":
        return False
    return head(path, 4, int.from_bytes(dos[60:64], "little")) == b"PE\0\0"


macho = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
# A compiled crate (rlib, rmeta), and a proc-macro library on each system, by
# its name and its signature together.
signature = {
    ".rlib": lambda p: head(p, 8) == b"!<arch>\n",
    ".rmeta": lambda p: head(p, 7) == b"rust\0\0\0",
    ".so": lambda p: head(p, 4) == b"\x7fELF",
    ".dylib": lambda p: head(p, 4) in macho,
    ".dll": pe,
}


def binary(path):
    """Not UTF-8, which rustc reads every source as: decoded a chunk at a time,
    up to the first byte that is not."""
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                decoder.decode(chunk)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return True
    except OSError:
        return False
    return False


def compiled(real, kinds):
    ext = os.path.splitext(real)[1].lower()
    return ext in kinds and os.path.isfile(real) and signature[ext](real) and binary(real)


def allowed(raw, real):
    if under(real, target):
        return shown(real).lower() not in listed_any_case and compiled(real, signature)
    if under(real, root):
        return not os.path.islink(raw) and shown(real) in scanned
    return compiled(real, (".rlib", ".rmeta"))


class Malformed(Exception):
    pass


def deps(text, strict_form):
    """The files a rustc dep-info file names: the prerequisites of each rule,
    with escaped spaces unescaped. In the strict form any other line, and any
    entry with a control character, raises Malformed; otherwise they are
    passed over."""
    found = []
    for line in text.split("\n"):
        if line == "" or line.startswith("#"):
            continue
        if line.endswith(":") and ": " not in line:
            found.append(line[:-1].replace("\\ ", " "))
            continue
        cut = line.find(": ")
        if cut <= 0:
            if strict_form:
                raise Malformed(line)
            continue
        tokens = [t.replace("\0", " ") for t in line[cut + 2:].replace("\\ ", "\0").split(" ") if t]
        # A lone backslash continues a line in other tools' depfiles; rustc
        # writes none.
        if "\\" in tokens and strict_form:
            raise Malformed(line)
        found.extend(t for t in tokens if t != "\\")
    for p in found:
        if control.search(p) and strict_form:
            raise Malformed(p)
    return [p for p in found if not control.search(p)]


crates = []
bad = False
# git tracks nothing under the target directory, in any case.
if under(target, root):
    prefix = shown(target).lower() + "/"
    for p in sorted(listed):
        if p.lower().startswith(prefix):
            print(f"== git lists a file under the target directory: {p}")
            bad = True
def ours(text):
    """Whether a .d file names a file in this repository outside the target
    directory: a workspace crate's, read loosely, so that another tool's
    depfile is told apart before it is held to rustc's form."""
    for p in deps(text, False):
        real = os.path.realpath(os.path.join(root, p))
        if under(real, root) and not under(real, target):
            return True
    return False


for d, _, names in os.walk(target):
    # A build script's output directory holds other tools' depfiles; no
    # workspace crate has a build script, so none of its .d files is there.
    if re.search(r"(^|/)build/[^/]+/out(/|$)", shown(d)):
        continue
    for n in sorted(names):
        if not n.endswith(".d"):
            continue
        dfile = os.path.join(d, n)
        with open(dfile, encoding="utf-8", errors="surrogateescape") as f:
            text = f.read()
        if not ours(text):
            continue
        try:
            listed_deps = deps(text, True)
        except Malformed as e:
            print(f"== {shown(dfile)}: a line that is not dep-info: {str(e)!r}")
            bad = True
            continue
        entries = []
        for p in dict.fromkeys(listed_deps):
            raw = os.path.join(root, p)
            entries.append((p, raw, os.path.realpath(raw)))
        key = (d, re.sub(r"-[0-9a-f]{16}$", "", n[:-2]))
        crates.append((key, os.path.getmtime(dfile), dfile, entries))

newest = {}
for key, mtime, dfile, _ in crates:
    if key not in newest or mtime > newest[key][0]:
        newest[key] = (mtime, dfile)
stale_files = stale_entries = 0
for key, _, dfile, entries in crates:
    missing = 0
    for p, raw, real in entries:
        if not os.path.lexists(raw):
            missing += 1
            if strict or newest[key][1] == dfile:
                print(f"== {shown(dfile)}: names {p}, which does not exist")
                bad = True
            continue
        if not allowed(raw, real):
            print(f"== {shown(dfile)}: read {p}, which the project rules do not scan")
            bad = True
    if missing and not strict and newest[key][1] != dfile:
        stale_files += 1
        stale_entries += missing
if not crates:
    print(f"== no workspace crate's dep-info under {target}: build first")
    sys.exit(1)
if stale_files:
    print(f"== skipped {stale_entries} missing files named by {stale_files} older .d files")
if not bad:
    print(f"== dep-info: the {len(crates)} files of workspace crates name only scanned files")
sys.exit(1 if bad else 0)
PY
