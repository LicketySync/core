#!/usr/bin/env bash
# Tests for ci/semgrep-scan.sh and for the project rules' paths, which
# `semgrep --test` ignores (threat-model.md TM-7). Each tree is a made-up git
# repository holding this repository's .semgrep/ and .semgrepignore and a crate
# with nothing to flag; ci/semgrep-scan.sh --project-only (no network) runs on
# it, bounded by timeout(1).
# - A clean tree passes.
# - One tree holds the probes, each a file the project rules must flag or a
#   layout the script must refuse, and asserts its line in the output: files in
#   directories Semgrep skips by default (tests/, build/, a crate's own
#   .semgrep/), a file that is not Rust, one over 1 MB, a Rust file outside
#   crates/, each banned word in a macro, a nosemgrep comment in code and in a
#   manifest, a nested .semgrepignore, a file that starts like an image, a
#   symbolic link, files under .semgrep/ but the cases files, a build.rs and a
#   Build.rs, the build and links keys, proc-macro manifests named Cargo.toml
#   and CARGO.TOML, a manifest path to a file that is not Rust, include!,
#   include_proto!, the path attribute (and one in cfg_attr with a
#   left-to-right mark before its =), and path attributes macros build from
#   parts, and the keyword extern (empty, linking and unsafe blocks, and the
#   keyword passed to a macro, and in a new file of the vendored tree); and
#   four files that must not be flagged (the vendored bindings.rs among them);
#   a read of the disk by a path in fs and engine, flagged in each but in
#   the resolver's files (resolver.rs and resolver/), and not in another crate;
#   a re-export of std::fs, flagged in a resolver file (where its own
#   types' re-export is not) and, as a renamed module, outside it; a read in
#   a macro's arguments, flagged in engine and not in the resolver; a
#   re-export written across a line break in a resolver file; std::os
#   re-exported in engine, flagged; and an IP address and an enum named
#   Command in engine, not flagged.
# - A copy of the script beside a stand-in tomllib.py must still use the
#   standard module.
# - Each other tree holds one fault and asserts exit 1 and its line, one per
#   way the script fails: a finding, a Semgrep error, a file the scan skipped,
#   a symbolic link, a cargo configuration file, a manifest that does not
#   parse, a target path and a dependency path that resolve to nothing git
#   lists, a failing case, a nested .semgrepignore, a name with a line break,
#   and Semgrep exiting with an error. A stand-in semgrep plays the two
#   Semgrep faults.
# The scans run at once, half as many as the machine has processors, and the
# assertions follow. Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
word=unsafe

# The stand-in semgrep: --test passes; a scan exits $STUB_EXIT when it is set,
# else writes a report that names every file git lists as scanned and holds
# one error of type $STUB_ERROR.
mkdir -p "$tmp/stub"
cat > "$tmp/stub/semgrep" <<'STUB'
#!/usr/bin/env bash
[ "$1" = --test ] && exit 0
[ -z "${STUB_EXIT:-}" ] || exit "$STUB_EXIT"
out=
while [ $# -gt 0 ]; do
  [ "$1" = --output ] && out=$2
  shift
done
git ls-files -co --exclude-standard | python3 -I -c '
import json, sys
files = [l for l in sys.stdin.read().splitlines() if l]
report = {"results": [], "paths": {"scanned": files},
          "errors": [{"type": sys.argv[2], "path": "crates/a/src/lib.rs", "message": "stand-in"}]}
with open(sys.argv[1], "w") as f:
    json.dump(report, f)
' "$out" "$STUB_ERROR"
STUB
chmod +x "$tmp/stub/semgrep"

# tree <dir>: a git repository with the rules, their cases, the root's
# .semgrepignore and a clean crate a.
tree() {
  mkdir -p "$1/crates/a/src"
  cp -R "$root/.semgrep" "$1/"
  cp "$root/.semgrepignore" "$1/"
  printf '[package]\nname = "a"\nversion = "0.0.1"\n' > "$1/crates/a/Cargo.toml"
  printf 'pub fn a() -> u8 {\n    1\n}\n' > "$1/crates/a/src/lib.rs"
  git -C "$1" init -q
}
# launch <dir> [env...]: ci/semgrep-scan.sh --project-only on it (or the copy
# $scanner names), in the background, at most $par at once; its output in
# <dir>.out, its exit code in <dir>.rc. use <dir>: the scan to assert on,
# after `wait`.
par=$(($(nproc 2> /dev/null || echo 2) / 2))
[ "$par" -ge 1 ] || par=1
launch() {
  local dir=$1
  shift
  git -C "$dir" add -A
  while [ "$(jobs -rp | wc -l)" -ge "$par" ]; do
    wait -n || true
  done
  (
    code=0
    "$tmo" 600 env "$@" "${scanner:-$here/semgrep-scan.sh}" --project-only "$dir" > "$dir.out" 2>&1 || code=$?
    echo "$code" > "$dir.rc"
  ) &
}
use() {
  out="$1.out"
  rc=$(cat "$1.rc")
}
# has <line> <case>: the scan in use printed that line.
has() {
  if grep -qxF -- "$1" "$out"; then
    echo "ok   $2"
  else
    echo "FAIL $2: no line \`$1\`"
    fails=$((fails + 1))
  fi
}
# lacks <text> <case>: the last scan printed no line holding that text.
lacks() {
  if grep -qF -- "$1" "$out"; then
    echo "FAIL $2: a line holds \`$1\`"
    grep -F -- "$1" "$out" | sed 's/^/  /'
    fails=$((fails + 1))
  else
    echo "ok   $2"
  fi
}
# starts <prefix> <case>: the last scan printed a line that starts so.
starts() {
  if PREFIX=$1 awk 'index($0, ENVIRON["PREFIX"]) == 1 { found = 1 } END { exit !found }' "$out"; then
    echo "ok   $2"
  else
    echo "FAIL $2: no line that starts \`$1\`"
    fails=$((fails + 1))
  fi
}
# exits <code> <case>: the last scan exited so.
exits() {
  if [ "$rc" = "$1" ]; then
    echo "ok   $2"
  else
    echo "FAIL $2: exit $rc, expected $1"
    sed 's/^/  /' "$out"
    fails=$((fails + 1))
  fi
}
flag() { echo "== finding: $1 at $2"; }
u=unsafe_code-only-in-ffi-crates
o=other_files-only-as-data
d=disk_by_path-only-in-resolver
r=resolver_re-exports-only-its-own-types

# A clean tree.
tree "$tmp/clean"
launch "$tmp/clean"

# The probes, in one tree.
t="$tmp/probes"
tree "$t"
mkdir -p "$t/crates/a/src/tests" "$t/crates/a/src/build" "$t/crates/a/src/.semgrep" "$t/fuzz" \
  "$t/crates/h/src" "$t/.semgrep/x" "$t/crates/b" "$t/crates/c" "$t/crates/d" "$t/crates/e" "$t/crates/n" \
  "$t/crates/k" "$t/crates/f" "$t/docs"
probe='macro_rules! sneak { ($p:expr) => { '"$word"' { *$p } } }'
printf '%s\n' "$probe" > "$t/crates/a/src/tests/m.rs"
printf '%s\n' "$probe" > "$t/crates/a/src/build/m.rs"
printf '%s\n' "$probe" > "$t/crates/a/src/.semgrep/m.rs"
printf '%s\n' "$probe" > "$t/crates/a/src/notes.in"
awk -v last="$probe" 'BEGIN {
  for (i = 0; i < 20000; i++) print "// padding past the 1 MB that Semgrep scans by default"
  print last
}' > "$t/crates/a/src/big.rs"
printf '%s\n' "$probe" > "$t/fuzz/x.rs"
printf 'macro_rules! words {\n    () => {\n        %s {}\n        #[no_mangle]\n        #[export_name = "malloc"]\n        #[link_section = ".init_array"]\n        core::arch::global_asm!("nop");\n    };\n}\n' \
  "$word" > "$t/crates/a/src/words.rs"
printf 'pub fn n() { %s {} } // nosemgrep\n' "$word" > "$t/crates/a/src/nosem.rs"
printf '[package]\nname = "n"\n\n[lib]\nproc-macro = true # nosemgrep\n' > "$t/crates/n/Cargo.toml"
printf '*\n' > "$t/crates/h/.semgrepignore"
printf '%s\n' "$probe" > "$t/crates/h/src/lib.rs"
printf 'GIF89a\n%s\n' "$probe" > "$t/crates/a/src/logo.gif"
printf '%s\n' "$probe" > "$t/docs/elsewhere.txt"
ln -s ../../../docs/elsewhere.txt "$t/crates/a/src/link.rs"
printf '%s\n' "$probe" > "$t/.semgrep/x/m.rs"
printf '%s\n' "$probe" > "$t/.semgrep/tests/extra.rs"
printf '[package]\nname = "b"\n' > "$t/crates/b/Cargo.toml"
printf 'fn main() {}\n' > "$t/crates/b/build.rs"
printf 'fn main() {}\n' > "$t/crates/b/Build.rs"
printf '[package]\nname = "c"\nbuild = "gen.rs"\nlinks = "z"\n' > "$t/crates/c/Cargo.toml"
printf '[package]\nname = "d"\n\n[lib]\nproc-macro = true\n' > "$t/crates/d/Cargo.toml"
printf '[package]\nname = "k"\n\n[lib]\nproc-macro = true\n' > "$t/crates/k/CARGO.TOML"
printf '[package]\nname = "e"\n\n[lib]\npath = "lib.txt"\n' > "$t/crates/e/Cargo.toml"
printf 'include!("notes.txt");\n#[path = "notes.txt"]\nmod notes;\ninclude_proto!("notes");\n#[cfg_attr(all(), path\xe2\x80\x8e= "notes.txt")]\nmod marked;\n' \
  > "$t/crates/a/src/other.rs"
# The two macros that built a path attribute through the old #[$doc]
# exception and through #[path $e $f]; both compile with rustc.
cat > "$t/crates/f/relay.rs" <<'RS'
macro_rules! outer {
    ($doc:meta) => {
        #[$doc]
        pub mod hidden;
    };
}
macro_rules! inner {
    ($k:ident) => {
        outer!($k = "notes.txt");
    };
}
inner!(path);
macro_rules! spelled {
    ($e:tt, $f:tt) => {
        #[path $e $f]
        pub mod spelled_out;
    };
}
spelled!(=, "notes.txt");
RS
# Extern blocks: empty, of either form, linking a file of the repository,
# and unsafe.
printf 'extern "C" {}\nextern {}\n%s extern "C" {}\n#[link(name = "../../notes.o", kind = "static", modifiers = "+verbatim")]\nextern "C" {}\nrelocate!(extern fn);\n' \
  "$word" > "$t/crates/a/src/blocks.rs"
# The vendored tree: the one file the extern rule leaves out, and a new one.
v="$t/browser-tests/webtransport/vendor/libp2p-webtransport-websys-0.6.0/src"
mkdir -p "$v"
printf 'extern "C" {}\n' > "$v/bindings.rs"
printf 'extern "C" {}\n' > "$v/new.rs"
printf 'The word %s, outside the scope.\n' "$word" > "$t/docs/notes.md"
# A read of the disk by a path: in fs and engine but the resolver's files.
read='pub fn r(p: &std::path::Path) -> bool { std::fs::read(p).is_ok() }'
mkdir -p "$t/crates/fs/src/resolver" "$t/crates/fs/tests" "$t/crates/engine/src" "$t/crates/net/src"
for f in fs/src/scan.rs fs/src/resolvers.rs fs/tests/disk.rs engine/src/disk.rs fs/src/resolver.rs \
  fs/src/resolver/unix.rs net/src/disk.rs; do
  printf '%s\n' "$read" > "$t/crates/$f"
done
# A re-export from a resolver file: flagged there; its own types are not.
printf 'pub use unix::{Dir, Root};\npub use std::fs as g;\n' > "$t/crates/fs/src/resolver/other.rs"
printf 'pub use std::fs as g;\n' > "$t/crates/fs/src/lib.rs"
# A read in a macro's arguments, which only the text backstop sees, and a
# re-export written across a line break.
printf 'pub fn m(p: &std::path::Path) {\n    assert!(std::fs::read(p).is_ok());\n}\n' > "$t/crates/engine/src/check.rs"
# What the rule leaves alone in engine (an IP address, its own enum), and
# std::os re-exported, which it does not.
printf 'use std::net::IpAddr;\npub enum Command {\n    A,\n}\npub fn c(_: IpAddr) -> Command {\n    Command::A\n}\n' \
  > "$t/crates/engine/src/own.rs"
printf 'pub use std::os::unix;\n' > "$t/crates/engine/src/os.rs"
printf 'pub fn m(p: &std::path::Path) {\n    assert!(std::fs::read(p).is_ok());\n}\npub\nuse crate::name::Name;\n' \
  > "$t/crates/fs/src/resolver/walk.rs"
launch "$t"

# One fault per tree: exit 1, and the fault's own line.
# fault <case> <line> <setup> [env...]: a clean tree, the setup function run
# with the tree's directory, a scan launched with the env given; the line is
# the start of one the scan prints.
n=0
faults=()
fault() {
  local name=$1 line=$2 setup=$3
  shift 3
  n=$((n + 1))
  tree "$tmp/fault-$n"
  "$setup" "$tmp/fault-$n"
  launch "$tmp/fault-$n" "$@"
  faults+=("$name" "$line")
}
f_finding() { printf 'pub fn f() { %s {} }\n' "$word" > "$1/crates/a/src/f.rs"; }
f_error() { :; }
f_skipped() {
  printf 'pub fn hid() {}\n' > "$1/crates/a/src/hid.rs"
  printf 'crates/a/src/hid.rs\n' >> "$1/.semgrepignore"
}
f_link() {
  mkdir -p "$1/docs"
  printf 'notes\n' > "$1/docs/notes.md"
  ln -s notes.md "$1/docs/link.md"
}
f_config() {
  mkdir -p "$1/.cargo"
  printf '[build]\nrustflags = []\n' > "$1/.cargo/config.toml"
}
f_unparsed() { printf '[package\nname = "a"\n' > "$1/crates/a/Cargo.toml"; }
f_target() {
  printf 'fn main() {}\n' > "$1/crates/notes"
  printf '[package]\nname = "a"\n\n[[bin]]\nname = "a"\npath = "../notes"\n' > "$1/crates/a/Cargo.toml"
}
f_dependency() { printf '[package]\nname = "a"\n\n[dependencies]\nm = { path = "../missing" }\n' > "$1/crates/a/Cargo.toml"; }
f_case() { printf '// the word %s, on a line no case names\n' "$word" >> "$1/.semgrep/tests/project.rs"; }
f_control() {
  mkdir -p "$1/docs"
  printf 'notes\n' > "$1/docs/a
b.md"
}
f_nested() {
  mkdir -p "$1/docs"
  printf '# hides nothing\n' > "$1/docs/.semgrepignore"
}
fault "a finding" "$(flag $u crates/a/src/f.rs:1)" f_finding
fault "a Semgrep error" "== semgrep error: Timeout: crates/a/src/lib.rs: stand-in" f_error \
  PATH="$tmp/stub:$PATH" STUB_ERROR=Timeout
fault "a file the scan skipped" "== not scanned: crates/a/src/hid.rs" f_skipped
fault "a symbolic link outside the rules' scope" "== a symbolic link: docs/link.md" f_link
fault "a cargo configuration file" "== a cargo configuration file: .cargo/config.toml" f_config
fault "a manifest that does not parse" "== a manifest that does not parse: crates/a/Cargo.toml: " f_unparsed
fault "a target path to a file that is not Rust" \
  "== a target path that is not a .rs file git lists: crates/a/Cargo.toml: '../notes'" f_target
fault "a dependency path to nothing" \
  "== a path that is not a directory with a Cargo.toml git lists: crates/a/Cargo.toml: '../missing'" f_dependency
fault "a failing case" "$(printf '\t')✖ unsafe_code-only-in-ffi-crates" f_case
fault "a nested .semgrepignore alone" "  docs/.semgrepignore" f_nested
fault "a name with a line break" "== a name with a control character: 'docs/a\\nb.md'" f_control
fault "Semgrep exiting with an error" "== semgrep exited 2" f_error PATH="$tmp/stub:$PATH" STUB_EXIT=2
# A copy of the script beside a tomllib.py, as if one were committed to ci/:
# the manifest check must still use the standard module, and so still fail on
# a target path to nothing.
mkdir -p "$tmp/ci-copy"
cp "$here/semgrep-scan.sh" "$here/scope.py" "$tmp/ci-copy/"
cat > "$tmp/ci-copy/tomllib.py" <<'PY'
print("== the stand-in tomllib.py was used")
TOMLDecodeError = ValueError


def load(f):
    return {}
PY
tree "$tmp/shadow"
f_target "$tmp/shadow"
scanner="$tmp/ci-copy/semgrep-scan.sh" launch "$tmp/shadow"
wait

use "$tmp/clean"
exits 0 "a clean tree passes"
use "$tmp/probes"
exits 1 "the probes fail the scan"
has "$(flag $u crates/a/src/tests/m.rs:1)" "a file in src/tests/ (Semgrep's default skips)"
has "$(flag $u crates/a/src/build/m.rs:1)" "a file in src/build/ (Semgrep's default skips)"
has "$(flag $u crates/a/src/.semgrep/m.rs:1)" "a file in a crate's own .semgrep/"
has "$(flag $u crates/a/src/notes.in:1)" "a file under crates/ that is not Rust"
has "$(flag $u crates/a/src/big.rs:20001)" "a file over 1 MB"
has "$(flag $u fuzz/x.rs:1)" "a Rust file outside crates/"
has "$(flag $u crates/a/src/words.rs:3)" "the word $word in a macro"
has "$(flag $u crates/a/src/words.rs:4)" "no_mangle in a macro"
has "$(flag $u crates/a/src/words.rs:5)" "export_name in a macro"
has "$(flag $u crates/a/src/words.rs:6)" "link_section in a macro"
has "$(flag $u crates/a/src/words.rs:7)" "global_asm in a macro"
has "$(flag $u crates/a/src/nosem.rs:1)" "a nosemgrep comment in code"
has "$(flag proc_macros-only-by-allow-list crates/n/Cargo.toml:5)" "a nosemgrep comment in a manifest"
has "== the root's .semgrepignore must be the only one; git lists:" "a nested .semgrepignore"
has "  crates/h/.semgrepignore" "a nested .semgrepignore, named"
has "== not scanned: crates/h/src/lib.rs" "the file a nested .semgrepignore hides"
has "$(flag $u crates/a/src/logo.gif:2)" "a file that starts like an image"
has "== a symbolic link: crates/a/src/link.rs" "a symbolic link"
has "== not scanned: crates/a/src/link.rs" "a symbolic link, not scanned"
has "$(flag $u .semgrep/x/m.rs:1)" "a file under .semgrep/x/"
has "$(flag $u .semgrep/tests/extra.rs:1)" "a file beside the cases files"
has "$(flag build_rs-only-by-allow-list crates/b/build.rs:1)" "a build.rs"
has "$(flag build_rs-only-by-allow-list crates/b/Build.rs:1)" "a Build.rs, read for build.rs on macOS and Windows"
has "$(flag build_scripts-only-by-allow-list crates/c/Cargo.toml:3)" "a build key"
has "$(flag build_scripts-only-by-allow-list crates/c/Cargo.toml:4)" "a links key"
has "$(flag proc_macros-only-by-allow-list crates/d/Cargo.toml:5)" "a proc-macro manifest"
has "$(flag proc_macros-only-by-allow-list crates/k/CARGO.TOML:5)" "a proc-macro manifest named CARGO.TOML"
has "$(flag manifest_paths-name-crates-or-rust_files crates/e/Cargo.toml:5)" "a manifest path to a file that is not Rust"
has "== a target path that is not a .rs file git lists: crates/e/Cargo.toml: 'lib.txt'" \
  "the same path, resolved"
has "$(flag $o crates/a/src/other.rs:1)" "include!"
has "$(flag $o crates/a/src/other.rs:2)" "a path attribute"
has "$(flag $o crates/a/src/other.rs:4)" "include_proto!"
has "$(flag $o crates/a/src/other.rs:5)" "a left-to-right mark between path and = in cfg_attr"
has "$(flag $o crates/f/relay.rs:2)" "a meta fragment"
has "$(flag $o crates/f/relay.rs:3)" "an attribute that starts with a metavariable"
has "$(flag $o crates/f/relay.rs:15)" "an attribute named path, built from what follows"
lacks "docs/notes.md" "a file outside the scope is not flagged"
lacks "crates/a/src/lib.rs" "a clean file is not flagged"
lacks "crates/a/Cargo.toml" "a clean manifest is not flagged"
has "$(flag extern_keyword-only-in-ffi-crates crates/a/src/blocks.rs:1)" "an empty extern \"C\" block"
has "$(flag extern_keyword-only-in-ffi-crates crates/a/src/blocks.rs:2)" "an empty extern block"
has "$(flag extern_keyword-only-in-ffi-crates crates/a/src/blocks.rs:3)" "an unsafe extern block"
has "$(flag $u crates/a/src/blocks.rs:3)" "an unsafe extern block, by its word"
has "$(flag extern_keyword-only-in-ffi-crates crates/a/src/blocks.rs:5)" "a linking extern block"
has "$(flag extern_keyword-only-in-ffi-crates crates/a/src/blocks.rs:6)" "the keyword passed to a macro that builds a block"
has "$(flag extern_keyword-only-in-ffi-crates browser-tests/webtransport/vendor/libp2p-webtransport-websys-0.6.0/src/new.rs:1)" \
  "a new file in the vendored tree"
lacks "/src/bindings.rs" "the vendored bindings.rs, left out"
has "$(flag $d crates/fs/src/scan.rs:1)" "a read by a path in fs"
has "$(flag $d crates/fs/src/resolvers.rs:1)" "a read by a path in fs, in a file only named like the resolver's"
has "$(flag $d crates/fs/tests/disk.rs:1)" "a read by a path in fs's tests"
has "$(flag $d crates/engine/src/disk.rs:1)" "a read by a path in engine"
lacks "crates/fs/src/resolver.rs" "a read by a path in the resolver, left out"
lacks "crates/fs/src/resolver/unix.rs" "a read by a path beneath the resolver, left out"
lacks "crates/net/src/disk.rs" "a read by a path in another crate, out of scope"
has "$(flag $r crates/fs/src/resolver/other.rs:2)" "a re-export of std::fs from a resolver file"
lacks "$(flag $r crates/fs/src/resolver/other.rs:1)" "a re-export of the resolver's own types"
lacks "$(flag $r crates/fs/src/lib.rs:1)" "a re-export outside the resolver, not this rule's"
has "$(flag $d crates/fs/src/lib.rs:1)" "a renamed std::fs outside the resolver"
has "$(flag $d crates/engine/src/check.rs:2)" "a read in a macro's arguments in engine"
lacks "== finding: $d at crates/fs/src/resolver/walk.rs" "a read in a macro's arguments in the resolver, left out"
has "$(flag $r crates/fs/src/resolver/walk.rs:4)" "a re-export across a line break in a resolver file"
lacks "crates/engine/src/own.rs" "an IP address and an enum named Command in engine, left alone"
has "$(flag $d crates/engine/src/os.rs:1)" "std::os re-exported in engine"

use "$tmp/shadow"
exits 1 "a tomllib.py beside the script: exit 1"
has "== a target path that is not a .rs file git lists: crates/a/Cargo.toml: '../notes'" \
  "a tomllib.py beside the script: the standard module still parses"
lacks "stand-in" "a tomllib.py beside the script: not used"

i=0
while [ "$i" -lt "${#faults[@]}" ]; do
  use "$tmp/fault-$((i / 2 + 1))"
  exits 1 "${faults[i]}: exit 1"
  starts "${faults[i + 1]}" "${faults[i]}: its line"
  i=$((i + 2))
done


if [ "$fails" != 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
