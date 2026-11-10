#!/usr/bin/env bash
# Installs the pinned Chrome for Testing and its matching chromedriver (Linux
# x86_64) into a directory, after checking each zip against its SHA-256 in
# ci/pins.env. Google publishes no SHA-256 for these downloads, so the pinned
# values are the ones computed when the pin was taken, after the download's
# MD5 matched the `x-goog-hash` that Google's storage reports for it. nightly.yml's
# webtransport-chrome job runs it; locally, the installed Chrome works as well
# (ci/webtransport-chrome.sh). The downloads are ci/download.sh's, which retries
# a transient failure such as an HTTP 504; the SHA-256 checks follow them. The
# release is CHROME_FOR_TESTING; Dependabot cannot see it. To move to release
# <v> (the newest Stable at googlechromelabs.github.io/chrome-for-testing that
# has been out 7 days, its date the zip's Last-Modified):
#   curl -fsSLO https://storage.googleapis.com/chrome-for-testing-public/<v>/linux64/chrome-linux64.zip
#   curl -fsSLO https://storage.googleapis.com/chrome-for-testing-public/<v>/linux64/chromedriver-linux64.zip
#   curl -fsSI <each URL> | grep -i x-goog-hash; openssl md5 -binary <zip> | base64   # must agree
#   sha256sum chrome-linux64.zip chromedriver-linux64.zip
#   wc -c chrome-linux64.zip   # chrome_zip_bytes in ci/test-download.sh
# and change the three values, and chrome_zip_bytes in ci/test-download.sh (the
# largest download, which a try of ci/download.sh must let arrive: that test
# checks it), in one reviewed commit (CONTRIBUTING.md, "Pins and the weekly
# refresh").
# Usage: ci/chrome-install.sh <directory>
set -euo pipefail
pins=$(dirname "$0")/pins.env
# Only its listed keys, with plain values, so sourcing it sets nothing else.
"$(dirname "$0")/check-pins.sh" "$pins"
# shellcheck source=pins.env
. "$pins"
version=${CHROME_FOR_TESTING:?$pins sets no CHROME_FOR_TESTING}
chrome_sha256=${CHROME_LINUX64_SHA256:?$pins sets no CHROME_LINUX64_SHA256}
driver_sha256=${CHROMEDRIVER_LINUX64_SHA256:?$pins sets no CHROMEDRIVER_LINUX64_SHA256}
dest=${1:?usage: ci/chrome-install.sh <directory>}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
base="https://storage.googleapis.com/chrome-for-testing-public/$version/linux64"
for zip in chrome-linux64.zip chromedriver-linux64.zip; do
  "$(dirname "$0")/download.sh" "$base/$zip" "$tmp/$zip"
done
echo "$chrome_sha256  $tmp/chrome-linux64.zip" | sha256sum --check --strict
echo "$driver_sha256  $tmp/chromedriver-linux64.zip" | sha256sum --check --strict
mkdir -p "$dest"
rm -rf "$dest/chrome-linux64" "$dest/chromedriver-linux64"
unzip -q "$tmp/chrome-linux64.zip" -d "$dest"
unzip -q "$tmp/chromedriver-linux64.zip" -d "$dest"
"$dest/chrome-linux64/chrome" --version
"$dest/chromedriver-linux64/chromedriver" --version
echo "Chrome for Testing $version and its chromedriver installed in $dest"
