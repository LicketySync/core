#!/usr/bin/env bash
# Regression test for CI run 39869811485 on ab8b0f8, where the keys crate's
# vector tests failed on Windows: Git for Windows sets core.autocrlf=true, which
# turned the LF of the committed test vectors into CRLF on checkout, and the
# tests compare each file byte for byte. The same setting turns a fuzz seed's
# LF into CRLF on checkout (link_parse/link-01) and drops the CR of a seed's
# CRLF on commit (words_parse/words-03). .gitattributes unsets `text` under
# every crate's tests/vectors/ and under fuzz/seeds/. With core.autocrlf=true,
# as on Windows, this checks that every such file git tracks checks out exactly
# as staged, and that every such file in the working tree (untracked ones that
# .gitignore does not exclude included) would be committed exactly as it is;
# then that the patterns reach paths that do not exist yet and nothing else.
# Run by gate.sh and CI. Exit 1 if any check fails.
set -euo pipefail
cd "$(dirname "$0")/.."
windows=(git -c core.autocrlf=true)
spec=(':(glob)crates/*/tests/vectors/**' ':(glob)fuzz/seeds/**')
fails=0
fail() {
  echo "FAIL $*"
  fails=$((fails + 1))
}

checked_out=0
while IFS= read -r -d '' entry; do
  path=${entry#*$'\t'}
  blob=$(printf '%s\n' "${entry%%$'\t'*}" | cut -d' ' -f2)
  checked_out=$((checked_out + 1))
  if ! cmp -s <(git cat-file blob "$blob") \
    <("${windows[@]}" cat-file --filters --path="$path" "$blob"); then
    fail "$path: a checkout with core.autocrlf=true changes its bytes"
  fi
done < <(git ls-files -z --stage -- "${spec[@]}")

committed=0
while IFS= read -r -d '' path; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then continue; fi
  committed=$((committed + 1))
  if [ "$("${windows[@]}" hash-object -- "$path")" != "$(git hash-object --no-filters -- "$path")" ]; then
    fail "$path: a commit with core.autocrlf=true changes its bytes"
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- "${spec[@]}")

if [ "$checked_out" -eq 0 ] || [ "$committed" -eq 0 ]; then
  fail "no test vectors or fuzz seeds found (tracked: $checked_out, in the tree: $committed)"
else
  echo "ok   $checked_out tracked vectors and seeds check out unchanged, $committed would commit unchanged"
fi

# attr <unset|set-or-unspecified> <path>...: the `text` attribute of each path,
# which need not exist.
attr() {
  local want=$1 path name value
  shift
  while IFS= read -r -d '' path && IFS= read -r -d '' name && IFS= read -r -d '' value; do
    if [ "$want" = unset ] && [ "$value" != unset ]; then
      fail "$path: $name is $value, not unset"
    elif [ "$want" != unset ] && [ "$value" = unset ]; then
      fail "$path: $name is unset, but it is neither a test vector nor a fuzz seed"
    else
      echo "ok   $path: $name $value"
    fi
  done < <(git check-attr -z text -- "$@")
}
attr unset crates/protocol/tests/vectors/frames.json \
  crates/engine/tests/vectors/nested/case.bin fuzz/seeds/new_target/seed-00
attr set-or-unspecified crates/keys/src/test_vectors.rs crates/protocol/src/vectors/mod.rs \
  crates/keys/tests/kat.rs crates/keys/tests/vectors.json fuzz/fuzz_targets/chunk_open.rs \
  Cargo.toml ci/gitleaks.sh
if [ "$fails" -ne 0 ]; then
  echo "$fails line-ending checks failed" >&2
  exit 1
fi
