#!/usr/bin/env bash
# Spike B: the headless-Chrome WebTransport test. Starts
# net's example listeners on 127.0.0.1, runs browser-tests/webtransport in
# headless Chrome against them (wasm-bindgen-test-runner + chromedriver), and
# checks Chrome's net log: no packet off loopback, and the outer TLS facts
# (the key-exchange group, TM-33). Every step is bounded; the listener exits
# by itself after its deadline. Needs CHROMEDRIVER (or chromedriver on PATH)
# and wasm-bindgen-test-runner at WASM_BINDGEN_CLI (ci/pins.env) on PATH;
# CHROME, if set, is the Chrome binary to drive (nightly.yml sets it to the
# pinned Chrome for Testing that ci/chrome-install.sh installs), else
# chromedriver finds the installed Chrome. OUT is where the logs and the net
# log go. Usage: ci/webtransport-chrome.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
# One target directory for both workspaces (core's and browser-tests/webtransport).
export CARGO_TARGET_DIR="$target"
out=${OUT:-$target/webtransport-chrome}
rm -rf "$out"
mkdir -p "$out"
export CHROMEDRIVER=${CHROMEDRIVER:-$(command -v chromedriver)}

cd "$root"
# /usr/bin/timeout by full path: a `timeout` earlier on PATH may not kill grandchildren.
/usr/bin/timeout 900 cargo build -q -p licketysync-net --features webtransport --example webtransport_listen
# The browser test crate and its dependencies, built before the listener
# starts (a cold build took over 4 minutes), so the listener's deadline counts
# only the test run; the run below rebuilds just the test crate, with the
# addresses in its environment.
/usr/bin/timeout 1200 cargo test -q --no-run --manifest-path browser-tests/webtransport/Cargo.toml \
	--target wasm32-unknown-unknown --test web
# $! is the listener itself, so the trap kills it; its deadline, 600 s, is a
# backstop.
"$target/debug/examples/webtransport_listen" 600 >"$out/listener.log" 2>&1 &
lpid=$!
trap 'kill "$lpid" 2>/dev/null || true' EXIT
for _ in $(seq 1 200); do
	grep -q '^READY$' "$out/listener.log" && break
	sleep 0.05
done
grep -q '^READY$' "$out/listener.log" || { echo "listener did not start"; cat "$out/listener.log"; exit 1; }
for n in OK PQ CLASSICAL LIAR LONG STRICT; do
	export "WT_PROBE_$n=$(awk -v n="$n" '$1 == "ADDR" && $2 == n { print $3 }' "$out/listener.log")"
done

# Chrome's own background traffic (component updater, new-tab page, accounts,
# network time, secure-DNS probes) is switched off, anything left goes to a
# dead loopback proxy and resolves no name, so only loopback is used;
# check-netlog.py verifies it.
binary=
if [ -n "${CHROME:-}" ]; then
	binary="\"binary\": \"$CHROME\", "
fi
cat >"$out/webdriver.json" <<JSON
{"goog:chromeOptions": {${binary}"args": [
  "--log-net-log=$out/netlog.json", "--net-log-capture-mode=Everything",
  "--user-data-dir=$out/profile", "--no-first-run", "--disable-background-networking",
  "--disable-component-update", "--disable-sync", "--disable-default-apps",
  "--disable-domain-reliability", "--disable-client-side-phishing-detection",
  "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater,NetworkTimeServiceQuerying,DnsOverHttps",
  "--proxy-server=http://127.0.0.1:9", "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
]}}
JSON
export WASM_BINDGEN_TEST_WEBDRIVER_JSON="$out/webdriver.json"
export WASM_BINDGEN_TEST_TIMEOUT=180
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner

status=0
/usr/bin/timeout 1200 cargo test --manifest-path browser-tests/webtransport/Cargo.toml \
	--target wasm32-unknown-unknown --test web 2>&1 | tee "$out/browser.log" || status=$?
kill "$lpid" 2>/dev/null || true
wait "$lpid" 2>/dev/null || true
echo "---- listener"
cat "$out/listener.log"
# What the listeners saw, for each test that needs the native side's word:
# the echo on X25519MLKEM768, the classical-only listener on X25519, the
# browser that was not the expected one refused, and Chrome refusing the
# wrong certificate hash and the 15-day certificate itself.
expect() { # expect <pattern> <what failed>
	grep -qE -- "$1" "$out/listener.log" || { echo "FAIL: $2"; status=1; }
}
expect '^REPORT OK ok .*kx=Some\(X25519MLKEM768\) ' "no X25519MLKEM768 echo on OK"
expect '^REPORT CLASSICAL ok .*kx=Some\(X25519\) ' "CLASSICAL did not record X25519"
expect '^REPORT STRICT refused unexpected peer' "STRICT did not refuse"
expect '^REPORT OK refused .*CERTIFICATE_VERIFY_FAILED' "Chrome did not refuse the wrong certhash"
expect '^REPORT LONG refused .*CERTIFICATE_VERIFY_FAILED' "Chrome did not refuse the 15-day certificate"
echo "---- Chrome's net log"
python3 -I "$root/ci/check-netlog.py" --expect-pq "$out/netlog.json" | tee "$out/netlog-check.log" || status=1
# The suite the listener's order chose, as Chrome saw it.
grep -qF 'group=X25519MLKEM768 version=TLS1.3 suite=TLS13_CHACHA20_POLY1305_SHA256' "$out/netlog-check.log" ||
	{ echo "FAIL: no session on X25519MLKEM768 with TLS13_CHACHA20_POLY1305_SHA256"; status=1; }
exit "$status"
