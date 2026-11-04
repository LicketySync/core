#!/usr/bin/env bash
# The vendored libp2p-webtransport-websys (browser-tests/webtransport/vendor)
# is exactly the copy its README describes: every file listed in SHA256SUMS
# with that SHA-256, and no file that is not listed. cargo-vet vets it as the
# crates.io release it copies (`audit-as-crates-io`), which keys on the
# version and does not see an edit to the source, so this check does.
# Every entry that is not a directory counts, so a symbolic link (or any
# other special file) is refused: the copy holds regular files only.
# Usage: ci/check-vendored.sh [repo-root]. Exit 1 on any difference. Run by
# gate.sh and CI's deps job; tested by ci/test-check-vendored.sh.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}/browser-tests/webtransport/vendor"
crate=libp2p-webtransport-websys-0.6.0
special=$(cd "$crate" && find . ! -type d ! -type f | sed 's|^\./||' | LC_ALL=C sort)
if [ -n "$special" ]; then
  echo "vendor/$crate holds entries that are not regular files:" >&2
  printf '%s\n' "$special" >&2
  exit 1
fi
listed=$(awk '{ print $2 }' SHA256SUMS | LC_ALL=C sort)
present=$(cd "$crate" && find . ! -type d | sed 's|^\./||' | LC_ALL=C sort)
if [ "$listed" != "$present" ]; then
  echo "vendor/$crate: its files differ from SHA256SUMS:" >&2
  diff <(printf '%s\n' "$listed") <(printf '%s\n' "$present") >&2 || true
  exit 1
fi
(cd "$crate" && sha256sum --check --strict --quiet ../SHA256SUMS)
echo "vendor/$crate matches SHA256SUMS"
