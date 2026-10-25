#!/usr/bin/env bash
# Installs the pinned gitleaks release (the MIT-licensed command-line tool) into
# a directory, after checking the tarball against the SHA-256 its release
# publishes. CI's gitleaks job runs it; locally, `ci/gitleaks-install.sh
# ~/.local/bin` makes gate.sh run gitleaks too. Linux x86_64 only.
# The release and its SHA-256 are GITLEAKS and GITLEAKS_LINUX_X64_SHA256 in
# ci/pins.env; Dependabot cannot see them. To move to release <v>: take the
# linux_x64 line of its checksums,
#   gh release download v<v> -R gitleaks/gitleaks -p 'gitleaks_<v>_checksums.txt' -O - | grep linux_x64
# and change both values in one reviewed commit (CONTRIBUTING.md, "Pins and the
# weekly refresh").
# Usage: ci/gitleaks-install.sh <directory>
set -euo pipefail
pins=$(dirname "$0")/pins.env
# Only its listed keys, with plain values, so sourcing it sets nothing else.
"$(dirname "$0")/check-pins.sh" "$pins"
# shellcheck source=pins.env
. "$pins"
version=${GITLEAKS:?$pins sets no GITLEAKS}
sha256=${GITLEAKS_LINUX_X64_SHA256:?$pins sets no GITLEAKS_LINUX_X64_SHA256}
dest=${1:?usage: ci/gitleaks-install.sh <directory>}
tarball="gitleaks_${version}_linux_x64.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$tarball" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/$tarball"
echo "$sha256  $tmp/$tarball" | sha256sum --check --strict
tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks
mkdir -p "$dest"
install -m 0755 "$tmp/gitleaks" "$dest/gitleaks"
echo "gitleaks $("$dest/gitleaks" version) installed in $dest"
