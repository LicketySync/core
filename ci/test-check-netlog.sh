#!/usr/bin/env bash
# Tests for ci/check-netlog.py. Each case writes a small Chrome net log (the
# constants table and the events the checker reads) to a temporary directory
# and runs the checker on it; the expected exit code, and for some a line of
# its output, is the assertion. The ServerHello bytes are built here as TLS 1.3
# lays them out. Run by gate.sh and CI. Exit 1 if any case fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-netlog.py"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# make <file> <spec...>: writes a net log. Each spec is one of
#   wt:<group hex>      a WebTransport session whose ServerHello names that group
#   wt-short            a WebTransport session with a truncated ServerHello
#   tcp:<address>       a TCP connect attempt to that address
#   udp:<address>       a UDP socket connected to that address that sends a packet
#   probe:<address>     a UDP socket connected to that address that sends nothing
#   sendto:<address>    an unconnected UDP socket that sends a packet to that address
#   dns                 a system resolver task (a real lookup)
make() {
  python3 -I - "$@" <<'PY'
import base64, json, sys
out, specs = sys.argv[1], sys.argv[2:]
names = ["QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE", "QUIC_SESSION_CRYPTO_FRAME_RECEIVED",
         "QUIC_SESSION_WEBTRANSPORT_SESSION_READY", "QUIC_SESSION_CLOSED", "TCP_CONNECT_ATTEMPT",
         "UDP_CONNECT", "UDP_BYTES_SENT", "HOST_RESOLVER_SYSTEM_TASK"]
types = {n: i + 1 for i, n in enumerate(names)}
sources = {"WEB_TRANSPORT_CLIENT": 1, "UDP_SOCKET": 2, "TCP_SOCKET": 3, "HOST_RESOLVER_IMPL_JOB": 4}
def server_hello(group):
    ext = (0x0033).to_bytes(2, "big") + (36).to_bytes(2, "big") + group.to_bytes(2, "big") \
        + (32).to_bytes(2, "big") + bytes(32)
    ext += (0x002B).to_bytes(2, "big") + (2).to_bytes(2, "big") + (0x0304).to_bytes(2, "big")
    body = (0x0303).to_bytes(2, "big") + bytes(32) + b"\x00" + (0x1303).to_bytes(2, "big") + b"\x00"
    body += len(ext).to_bytes(2, "big") + ext
    return b"\x02" + len(body).to_bytes(3, "big") + body
events = []
def ev(name, source, sid, params):
    events.append({"type": types[name], "source": {"type": sources[source], "id": sid}, "phase": 0, "params": params})
sid = 10
for spec in specs:
    sid += 1
    kind, _, arg = spec.partition(":")
    if kind in ("wt", "wt-short"):
        hello = server_hello(int(arg or "11ec", 16))
        if kind == "wt-short":
            hello = hello[:30]
        ev("QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE", "WEB_TRANSPORT_CLIENT", sid, {"url": "https://127.0.0.1:4433/.well-known/libp2p-webtransport?type=noise"})
        ev("QUIC_SESSION_CRYPTO_FRAME_RECEIVED", "WEB_TRANSPORT_CLIENT", sid, {"encryption_level": "ENCRYPTION_INITIAL", "offset": 0, "bytes": base64.b64encode(hello[:50]).decode()})
        if len(hello) > 50:
            ev("QUIC_SESSION_CRYPTO_FRAME_RECEIVED", "WEB_TRANSPORT_CLIENT", sid, {"encryption_level": "ENCRYPTION_INITIAL", "offset": 50, "bytes": base64.b64encode(hello[50:]).decode()})
        ev("QUIC_SESSION_WEBTRANSPORT_SESSION_READY", "WEB_TRANSPORT_CLIENT", sid, {})
    elif kind == "tcp":
        ev("TCP_CONNECT_ATTEMPT", "TCP_SOCKET", sid, {"address": arg})
    elif kind in ("udp", "probe"):
        ev("UDP_CONNECT", "UDP_SOCKET", sid, {"address": arg})
        if kind == "udp":
            ev("UDP_BYTES_SENT", "UDP_SOCKET", sid, {"byte_count": 1200})
    elif kind == "sendto":
        ev("UDP_BYTES_SENT", "UDP_SOCKET", sid, {"address": arg, "byte_count": 60})
    elif kind == "dns":
        ev("HOST_RESOLVER_SYSTEM_TASK", "HOST_RESOLVER_IMPL_JOB", sid, {"hostname": "example.com"})
    else:
        sys.exit("unknown spec " + spec)
json.dump({"constants": {"logEventTypes": types, "logSourceType": sources}, "events": events}, open(out, "w"))
PY
}
n=0
fails=0
case_() { # case_ <name> <expected exit> <expected output line or ""> <checker flags> -- <spec...>
  n=$((n + 1))
  local name=$1 want=$2 line=$3 flags=$4 rc=0
  shift 5
  make "$tmp/$n.json" "$@"
  # shellcheck disable=SC2086
  python3 -I "$check" $flags "$tmp/$n.json" > "$tmp/$n.out" 2>&1 || rc=$?
  if [ "$rc" = "$want" ] && { [ -z "$line" ] || grep -qF -- "$line" "$tmp/$n.out"; }; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $rc, expected $want${line:+ and a line with \"$line\"}"
    cat "$tmp/$n.out"
    fails=$((fails + 1))
  fi
}
case_ "loopback session, X25519MLKEM768" 0 "1 session(s) negotiated X25519MLKEM768" "" -- wt:11ec
case_ "the group is read from the ServerHello" 0 "group=X25519MLKEM768 version=TLS1.3 suite=TLS13_CHACHA20_POLY1305_SHA256" "" -- wt:11ec
case_ "classical session counts no PQ" 0 "0 session(s) negotiated X25519MLKEM768" "" -- wt:001d
case_ "--expect-pq passes with one PQ session" 0 "" --expect-pq -- wt:001d wt:11ec
case_ "--expect-pq fails with none" 1 "no session negotiated X25519MLKEM768" --expect-pq -- wt:001d
case_ "truncated ServerHello is no crash" 0 "no ServerHello" "" -- wt-short
case_ "TCP to a public address fails" 1 "tcp 192.0.2.1:443" "" -- wt:11ec tcp:192.0.2.1:443
case_ "TCP to loopback passes" 0 "" "" -- tcp:127.0.0.1:9
case_ "UDP packet to a public address fails" 1 "udp [2001:db8::1]:443" "" -- udp:[2001:db8::1]:443
case_ "UDP routing probe without a packet passes" 0 "routing probes" "" -- probe:[2001:db8::8888]:443
case_ "a real DNS lookup fails" 1 "dns " "" -- dns
case_ "unconnected UDP send to a multicast address fails" 1 "udp 224.0.0.251:5353" "" -- sendto:224.0.0.251:5353
case_ "unconnected UDP send to loopback passes" 0 "" "" -- sendto:127.0.0.1:5353
case_ "UDP to IPv6 loopback passes" 0 "" "" -- udp:[::1]:4433
# A net log that is not JSON, or is missing, fails closed.
n=$((n + 1))
printf '{"constants": ' > "$tmp/$n.json"
rc=0
python3 -I "$check" "$tmp/$n.json" > "$tmp/$n.out" 2>&1 || rc=$?
if [ "$rc" = 1 ] && grep -qF "cannot read the net log" "$tmp/$n.out"; then echo "ok   truncated net log fails closed"; else echo "FAIL truncated net log: exit $rc"; cat "$tmp/$n.out"; fails=$((fails + 1)); fi
rc=0
python3 -I "$check" "$tmp/missing.json" > "$tmp/missing.out" 2>&1 || rc=$?
if [ "$rc" = 1 ]; then echo "ok   missing net log fails closed"; else echo "FAIL missing net log: exit $rc"; fails=$((fails + 1)); fi
if [ "$fails" -ne 0 ]; then
  echo "$fails of $((n + 1)) cases failed"
  exit 1
fi
echo "all $((n + 1)) cases passed"
