#!/usr/bin/env bash
# Tests for ci/check-dep-info.sh on made-up repositories (threat-model.md
# TM-7). The probes are toy crates that rustc compiles into the toy's own
# target directory, each with a module whose path attribute a macro assembles
# from tokens passed one at a time, which no text rule sees; the check must
# fail on the file each reads: one outside crates/, a registry source, a Rust
# source named .rmeta, one reached through /proc/self/cwd/.. (resolved as
# rustc resolved it), a name with a line break, a new file in the vendored
# tree, and, in a release build only, a module under
# #[cfg(not(debug_assertions))]; and must pass a name with a space. Other
# cases feed the check made-up .d files: what a workspace crate may name
# (untracked compiled artifacts under the target directory, the toolchain's
# compiled crates) beside a registry crate's .d and other tools' gcc-style
# depfiles; another tool's depfile in deps/ naming relative files that do not
# exist; a deleted crate's .d naming its missing root and a file elsewhere, in
# CI; a stale entry in an older .d, skipped locally and failing in CI; a
# missing entry in the newest; a malformed line; under the target directory a
# generated source, a tracked file (also in another case), a bare MZ named
# .dll, rustc's metadata named .so and a Rust source dressed as a .dll; outside
# the repository a toolchain source, a git checkout's source, Rust sources
# named .rlib and .rmeta and a UTF-8 file with rustc's metadata header; a file
# elsewhere; a symbolic link; a .d under examples/; and no .d at all. Each case
# asserts the exit code and a line. Run by gate.sh and CI's clippy job; needs
# rustc, git and python3.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmo=/usr/bin/timeout
[ -x "$tmo" ] || tmo=timeout
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unset CARGO_TARGET_DIR
fails=0

# repo <dir>: a git repository holding the toy crate's directory; git
# ignores its target directory.
repo() {
  mkdir -p "$1/crates/toy/src" "$1/target/debug/deps"
  printf '/target/\n' > "$1/.gitignore"
  git -C "$1" init -q
}
# build <dir> [rustc flags...]: rustc on the toy crate, from the repository's
# root as cargo runs it, its dep-info and metadata in target/debug/deps.
build() {
  local dir=$1
  shift
  git -C "$dir" add -A
  (cd "$dir" && "$tmo" 120 rustc --edition 2021 --crate-type lib --crate-name toy "$@" \
    --emit dep-info=target/debug/deps/toy-0000000000000000.d,metadata=target/debug/deps/libtoy-0000000000000000.rmeta \
    crates/toy/src/lib.rs)
}
# check <case> <dir> <expected exit> <line> [env...]: the check's exit code
# and one line of its output; CI is unset unless the env sets it.
check() {
  local name=$1 dir=$2 want=$3 line=$4 rc=0
  shift 4
  git -C "$dir" add -A
  "$tmo" 120 env -u CI "$@" "$here/check-dep-info.sh" "$dir" > "$dir.out" 2>&1 || rc=$?
  if [ "$rc" = "$want" ] && grep -qxF -- "$line" "$dir.out"; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc (expected $want), or no line \`$line\`; it printed:"
    sed 's/^/  /' "$dir.out"
    fails=$((fails + 1))
  fi
}
# assembled <dir> <path> [cfg]: the toy's lib.rs, a module whose path
# attribute a macro assembles from tokens passed one at a time.
assembled() {
  cat > "$1/crates/toy/src/lib.rs" <<RS
macro_rules! assemble {
    (\$h:tt, \$p:tt, \$e:tt, \$f:tt) => {
        \$h[\$p \$e \$f]
        ${3:-}
        pub mod hidden;
    };
}
assemble!(#, path, =, "$2");
RS
}
d=target/debug/deps/toy-0000000000000000.d
read_line() { echo "== $d: read $1, which the project rules do not scan"; }
ok_line() { echo "== dep-info: the $1 files of workspace crates name only scanned files"; }
hidden='pub fn hidden() -> u8 {
    2
}'

# A clean toy: a module and data under crates/.
t="$tmp/clean"
repo "$t"
printf 'mod inner;\npub const DATA: &[u8] = include_bytes!("data.bin");\npub fn f() -> u8 {\n    inner::g()\n}\n' \
  > "$t/crates/toy/src/lib.rs"
printf 'pub fn g() -> u8 {\n    1\n}\n' > "$t/crates/toy/src/inner.rs"
printf 'data\n' > "$t/crates/toy/src/data.bin"
build "$t"
check "a clean toy" "$t" 0 "$(ok_line 1)"

# The probes.
t="$tmp/outside"
repo "$t"
assembled "$t" "../../../notes.txt"
printf '%s\n' "$hidden" > "$t/notes.txt"
build "$t"
check "a path attribute built from tokens one at a time" "$t" 1 "$(read_line crates/toy/src/../../../notes.txt)"
t="$tmp/registry"
reg="$tmp/cargo/registry/src/index.crates.io-0000000000000000/x-1.0.0/src"
mkdir -p "$reg"
printf '%s\n' "$hidden" > "$reg/lib.rs"
repo "$t"
assembled "$t" "$reg/lib.rs"
build "$t"
check "a registry source compiled in as a module" "$t" 1 "$(read_line "$reg/lib.rs")"
t="$tmp/named"
repo "$t"
assembled "$t" "../../../notes.rmeta"
printf '%s\n' "$hidden" > "$t/notes.rmeta"
build "$t"
check "a Rust source in the repository named .rmeta" "$t" 1 "$(read_line crates/toy/src/../../../notes.rmeta)"
if [ -d /proc/self ]; then
  t="$tmp/proc"
  repo "$t"
  assembled "$t" "/proc/self/cwd/../proc/notes.txt"
  printf '%s\n' "$hidden" > "$t/notes.txt"
  build "$t"
  check "a path through /proc/self/cwd/.., resolved as rustc resolved it" "$t" 1 \
    "$(read_line /proc/self/cwd/../proc/notes.txt)"
fi
t="$tmp/line-break"
repo "$t"
assembled "$t" 'x:\nz'
printf '%s\n' "$hidden" > "$t/crates/toy/src/x:
z"
build "$t"
check "a name with a line break" "$t" 1 "== $d: a line that is not dep-info: 'z'"
t="$tmp/release"
repo "$t"
assembled "$t" "../../../notes.txt" '#[cfg(not(debug_assertions))]'
printf '%s\n' "$hidden" > "$t/notes.txt"
build "$t"
check "a release-only module, in a debug build" "$t" 0 "$(ok_line 1)"
build "$t" -C debug-assertions=off
check "a release-only module, in a release build" "$t" 1 "$(read_line crates/toy/src/../../../notes.txt)"

# A file under crates/ that git ignores, read as data: the scan never saw it.
t="$tmp/ignored"
repo "$t"
printf 'pub const DATA: &[u8] = include_bytes!("ignored.bin");\n' > "$t/crates/toy/src/lib.rs"
printf 'data\n' > "$t/crates/toy/src/ignored.bin"
printf 'crates/toy/src/ignored.bin\n' >> "$t/.gitignore"
build "$t"
check "an ignored file under crates/" "$t" 1 "$(read_line crates/toy/src/ignored.bin)"

# Made-up .d files. made_up <dir> <file>: the toy's lib.rs and a .d (at
# <dir>/<file>, under target/) that names it and the rest of the arguments.
made_up() {
  local dir=$1 file=$2
  shift 2
  mkdir -p "$(dirname "$dir/$file")"
  printf 'pub fn f() {}\n' > "$dir/crates/toy/src/lib.rs"
  printf '%s: crates/toy/src/lib.rs%s\n\ncrates/toy/src/lib.rs:\n' "$dir/$file" "$(printf ' %s' "$@")" \
    > "$dir/$file"
}
sys="$tmp/toolchain/lib/rustlib"
git_src="$tmp/cargo/git/checkouts/y/src"
mkdir -p "$sys/x86_64-unknown-linux-gnu/lib" "$sys/src/rust/library/core/src" "$git_src" "$tmp/elsewhere"
for f in "$sys/src/rust/library/core/src/lib.rs" "$git_src/lib.rs" "$tmp/elsewhere/x.rs" \
  "$tmp/elsewhere/x.rlib" "$tmp/elsewhere/x.rmeta"; do
  printf 'pub fn f() {}\n' > "$f"
done
# Compiled artifacts: their first bytes (an ar archive, rustc's metadata; and
# pe_image, a PE header: MZ, e_lfanew at 60 pointing at 64, and the PE
# signature there), then a byte that is not UTF-8, as in every real one.
pe_image() {
  printf 'MZ'
  head -c 58 /dev/zero
  printf '\100\0\0\0PE\0\0\377'
}
printf 'rust\0\0\0\n\377' > "$sys/x86_64-unknown-linux-gnu/lib/libcore.rmeta"
printf '!<arch>\n\377' > "$sys/x86_64-unknown-linux-gnu/lib/libstd.rlib"

# What a workspace crate may name, beside a registry crate's .d naming
# sources anywhere; and an older .d of the same crate naming a file that is
# gone, which is skipped locally and fails in CI.
t="$tmp/allowed"
repo "$t"
dep="$t/target/debug/deps"
printf 'rust\0\0\0\n\377' > "$dep/libdep-1111111111111111.rmeta"
printf '\177ELF\n\377' > "$dep/libpm-1111111111111111.so"
printf '\317\372\355\376\n' > "$dep/libpm-1111111111111111.dylib"
pe_image > "$dep/pm-1111111111111111.dll"
made_up "$t" "$d" "$sys/x86_64-unknown-linux-gnu/lib/libcore.rmeta" \
  "$sys/x86_64-unknown-linux-gnu/lib/libstd.rlib" "$dep/libdep-1111111111111111.rmeta" \
  "$dep/libpm-1111111111111111.so" "$dep/libpm-1111111111111111.dylib" "$dep/pm-1111111111111111.dll"
printf '%s: %s %s %s\n' "$t/target/debug/deps/x-1111111111111111.d" "$reg/lib.rs" \
  "$sys/src/rust/library/core/src/lib.rs" "$tmp/elsewhere/x.rs" > "$t/target/debug/deps/x-1111111111111111.d"
printf '%s: crates/toy/src/lib.rs crates/toy/src/gone.rs\n' "$t/target/debug/deps/toy-2222222222222222.d" \
  > "$t/target/debug/deps/toy-2222222222222222.d"
touch -d '2000-01-01' "$t/target/debug/deps/toy-2222222222222222.d"
# Other tools' depfiles, in gcc's form with continued lines: one in a build
# script's output directory naming files of the repository, one elsewhere.
mkdir -p "$t/target/debug/build/x-1111111111111111/out"
printf 'foo.o: %s \\\n  %s\n' "$t/crates/toy/src/lib.rs" "$t/notes.h" \
  > "$t/target/debug/build/x-1111111111111111/out/foo.d"
printf 'bar.o: %s \\\n  %s\n' "$reg/lib.rs" "$tmp/elsewhere/x.rs" > "$t/target/debug/deps/bar.d"
check "compiled artifacts, a registry crate's .d, other tools' depfiles, a stale older .d" "$t" 0 "$(ok_line 2)"
check "the stale older .d, counted" "$t" 0 "== skipped 1 missing files named by 1 older .d files"
check "the stale older .d, in CI" "$t" 1 \
  "== target/debug/deps/toy-2222222222222222.d: names crates/toy/src/gone.rs, which does not exist" CI=true

# Another tool's depfile in deps/, in gcc's form, naming relative files that
# do not exist from the repository's root: not a workspace crate's, skipped.
t="$tmp/relative"
repo "$t"
made_up "$t" "$d"
printf 'foo.o: foo.c \\\n  foo.h\n' > "$t/target/debug/deps/foo.d"
check "another tool's depfile in deps/ naming relative files that do not exist" "$t" 0 "$(ok_line 1)"

# A deleted crate's .d, rustc's (its rule's target is the .d itself), naming
# its missing root and a file outside the repository: still judged.
t="$tmp/deleted"
repo "$t"
made_up "$t" "$d"
gone=target/debug/deps/gone-1111111111111111.d
printf '%s: crates/gone/src/lib.rs %s\n\ncrates/gone/src/lib.rs:\n%s:\n' "$t/$gone" "$tmp/elsewhere/x.rs" \
  "$tmp/elsewhere/x.rs" > "$t/$gone"
check "a deleted crate's .d naming a file outside the repository, in CI" "$t" 1 \
  "== $gone: read $tmp/elsewhere/x.rs, which the project rules do not scan" CI=true
check "a deleted crate's .d naming its missing root, in CI" "$t" 1 \
  "== $gone: names crates/gone/src/lib.rs, which does not exist" CI=true

# fails <case> <expected line> <file>...: a workspace crate's .d (its newest)
# naming the files; the check must fail with the line.
n=0
fails_on() {
  local name=$1 line=$2
  shift 2
  n=$((n + 1))
  t="$tmp/made-up-$n"
  repo "$t"
  made_up "$t" "$d" "$@"
  check "$name" "$t" 1 "$line"
}
fails_on "a missing file in the newest .d" \
  "== $d: names crates/toy/src/gone.rs, which does not exist" crates/toy/src/gone.rs
fails_on "a toolchain source" "$(read_line "$sys/src/rust/library/core/src/lib.rs")" \
  "$sys/src/rust/library/core/src/lib.rs"
fails_on "a git checkout's source" "$(read_line "$git_src/lib.rs")" "$git_src/lib.rs"
fails_on "a Rust source named .rlib outside the repository" "$(read_line "$tmp/elsewhere/x.rlib")" \
  "$tmp/elsewhere/x.rlib"
fails_on "a Rust source named .rmeta outside the repository" "$(read_line "$tmp/elsewhere/x.rmeta")" \
  "$tmp/elsewhere/x.rmeta"
fails_on "a file outside the repository" "$(read_line "$tmp/elsewhere/x.rs")" "$tmp/elsewhere/x.rs"

# Under the target directory: an untracked generated source, and a tracked
# file (git add -f).
t="$tmp/generated"
repo "$t"
printf 'pub fn g() {}\n' > "$t/target/x.rs"
made_up "$t" "$d" target/x.rs
check "a generated source under the target directory" "$t" 1 "$(read_line target/x.rs)"
t="$tmp/forced"
repo "$t"
printf 'rust\0\0\0 notes\n' > "$t/target/notes.txt"
git -C "$t" add -f target/notes.txt
made_up "$t" "$d" target/notes.txt
check "a tracked file under the target directory" "$t" 1 "$(read_line target/notes.txt)"

# Under the target directory, a file named as a library whose signature is
# not its kind's, or is only the start of one: a bare MZ named .dll, and
# rustc's metadata named .so.
t="$tmp/bare-mz"
repo "$t"
printf 'MZ pub fn f() {}\n' > "$t/target/debug/deps/pm-1111111111111111.dll"
made_up "$t" "$d" target/debug/deps/pm-1111111111111111.dll
check "a bare MZ named .dll under the target directory" "$t" 1 \
  "$(read_line target/debug/deps/pm-1111111111111111.dll)"
t="$tmp/misnamed"
repo "$t"
printf 'rust\0\0\0\n' > "$t/target/debug/deps/libpm-1111111111111111.so"
made_up "$t" "$d" target/debug/deps/libpm-1111111111111111.so
check "rustc's metadata named .so under the target directory" "$t" 1 \
  "$(read_line target/debug/deps/libpm-1111111111111111.so)"
# git tracks a file under the target directory, in another case.
t="$tmp/cased"
repo "$t"
mkdir -p "$t/TARGET"
printf 'pub fn g() {}\n' > "$t/TARGET/notes.rs"
git -C "$t" add -f TARGET/notes.rs
made_up "$t" "$d"
check "a tracked file under the target directory, in another case" "$t" 1 \
  "== git lists a file under the target directory: TARGET/notes.rs"

# A Rust source dressed as a library: MZ, a PE header inside a comment, all of
# it UTF-8, named .dll under the target directory; and rustc's metadata header
# on a UTF-8 file named .rmeta outside the repository.
t="$tmp/dressed"
repo "$t"
{
  printf 'MZ!{/*'
  head -c 54 /dev/zero
  printf '\100\0\0\0PE\0\0*/}\n'
} > "$t/target/debug/deps/pm-1111111111111111.dll"
made_up "$t" "$d" target/debug/deps/pm-1111111111111111.dll
check "a Rust source dressed as a .dll under the target directory" "$t" 1 \
  "$(read_line target/debug/deps/pm-1111111111111111.dll)"
printf 'rust\0\0\0 pub fn f() {}\n' > "$tmp/elsewhere/dressed.rmeta"
fails_on "a UTF-8 file with rustc's metadata header outside the repository" \
  "$(read_line "$tmp/elsewhere/dressed.rmeta")" "$tmp/elsewhere/dressed.rmeta"

# The vendored tree, which the rules scan only in part: a new Rust file there,
# read by a workspace crate through an assembled path.
t="$tmp/vendor"
repo "$t"
v="browser-tests/webtransport/vendor/x-1.0.0/src"
mkdir -p "$t/$v"
printf '#[link(name = "x", modifiers = "+verbatim")]\nextern "C" {}\n%s\n' "$hidden" > "$t/$v/new.rs"
assembled "$t" "../../../$v/new.rs"
build "$t"
check "a workspace crate reading a file of the vendored tree" "$t" 1 \
  "$(read_line "crates/toy/src/../../../$v/new.rs")"

# A file whose name holds a space, which the .d escapes.
t="$tmp/spaced"
repo "$t"
assembled "$t" "with space.rs"
printf '%s\n' "$hidden" > "$t/crates/toy/src/with space.rs"
build "$t"
check "a name with a space" "$t" 0 "$(ok_line 1)"

# A .d outside deps/: an example's.
t="$tmp/example"
repo "$t"
made_up "$t" target/debug/examples/toy-0000000000000000.d "$tmp/elsewhere/x.rs"
check "an example's .d" "$t" 1 \
  "== target/debug/examples/toy-0000000000000000.d: read $tmp/elsewhere/x.rs, which the project rules do not scan"

# A malformed line, and a symbolic link under crates/.
t="$tmp/malformed"
repo "$t"
made_up "$t" "$d"
printf 'crates/toy/src/lib.rs\n' >> "$t/$d"
check "a line that is not dep-info" "$t" 1 "== $d: a line that is not dep-info: 'crates/toy/src/lib.rs'"
t="$tmp/link"
repo "$t"
ln -s lib.rs "$t/crates/toy/src/link.rs"
made_up "$t" "$d" crates/toy/src/link.rs
check "a symbolic link" "$t" 1 "$(read_line crates/toy/src/link.rs)"

# Nothing built: no workspace crate's .d.
t="$tmp/empty"
repo "$t"
printf 'pub fn f() {}\n' > "$t/crates/toy/src/lib.rs"
check "no build" "$t" 1 "== no workspace crate's dep-info under $t/target: build first"

if [ "$fails" != 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
