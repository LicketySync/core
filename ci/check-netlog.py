#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Spike B: read Chrome's net log from a browser run.

1. Fails if Chrome connected anywhere but loopback (the tests use 127.0.0.1 only).
2. For every WebTransport session, prints the URL, how it ended, and the outer TLS facts Chrome
   received in the ServerHello (the negotiated key-exchange group, version and cipher suite),
   decoded from the QUIC CRYPTO frames the net log records at capture mode "Everything".
3. With --expect-pq, also fails unless at least one session negotiated X25519MLKEM768.
It fails closed: a net log it cannot read is a failure. Tested by ci/test-check-netlog.sh.
Usage: python3 -I ci/check-netlog.py [--expect-pq] <netlog.json> (ci/webtransport-chrome.sh runs it).
"""
import base64
import ipaddress
import json
import sys

GROUPS = {0x001D: "X25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x11EC: "X25519MLKEM768",
          0x11EB: "SecP256r1MLKEM768", 0x0201: "MLKEM768", 0x6399: "X25519Kyber768Draft00"}
SUITES = {0x1301: "TLS13_AES_128_GCM_SHA256", 0x1302: "TLS13_AES_256_GCM_SHA384",
          0x1303: "TLS13_CHACHA20_POLY1305_SHA256"}


def server_hello(data):
    """Returns (group, version, suite) from a TLS ServerHello handshake message, or None."""
    try:
        return parse_server_hello(data)
    except IndexError:
        return None


def parse_server_hello(data):
    if len(data) < 4 or data[0] != 2:
        return None
    body = data[4:4 + int.from_bytes(data[1:4], "big")]
    i = 2 + 32
    i += 1 + body[i]
    suite = int.from_bytes(body[i:i + 2], "big")
    i += 3
    end = i + 2 + int.from_bytes(body[i:i + 2], "big")
    i += 2
    group = version = None
    while i + 4 <= end and i + 4 <= len(body):
        etype = int.from_bytes(body[i:i + 2], "big")
        elen = int.from_bytes(body[i + 2:i + 4], "big")
        ext = body[i + 4:i + 4 + elen]
        if etype == 0x0033 and len(ext) >= 2:
            group = int.from_bytes(ext[0:2], "big")
        if etype == 0x002B and len(ext) >= 2:
            version = int.from_bytes(ext[0:2], "big")
        i += 4 + elen
    return group, version, suite


def is_loopback(address):
    host = address.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv):
    expect_pq = argv[:1] == ["--expect-pq"]
    if expect_pq:
        argv = argv[1:]
    if len(argv) != 1:
        print("usage: check-netlog.py [--expect-pq] <netlog.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[0]) as f:
            log = json.load(f)
    except (OSError, ValueError) as e:
        print(f"FAIL: cannot read the net log {argv[0]}: {e}")
        return 1
    types = {v: k for k, v in log["constants"]["logEventTypes"].items()}
    sources = {v: k for k, v in log["constants"]["logSourceType"].items()}
    outside = set()
    probes = set()
    udp_remote = {}
    udp_sent = set()
    sessions = {}
    for e in log["events"]:
        t = types.get(e["type"])
        p = e.get("params", {})
        sid = e["source"]["id"]
        if t in ("TCP_CONNECT", "TCP_CONNECT_ATTEMPT"):
            addr = p.get("address")
            if addr and not is_loopback(addr):
                outside.add("tcp " + addr)
        if t == "UDP_CONNECT" and p.get("address") and not is_loopback(p["address"]):
            udp_remote[sid] = p["address"]
        if t == "UDP_BYTES_SENT":
            udp_sent.add(sid)
            # An unconnected socket names the destination on each send
            # (mDNS or SSDP, for one).
            addr = p.get("address")
            if addr and not is_loopback(addr):
                outside.add("udp " + addr)
        # Real name lookups (system resolver or Chrome's own DNS) mean traffic; a request the
        # host-resolver rules answer with NOTFOUND does not.
        if t in ("HOST_RESOLVER_SYSTEM_TASK", "HOST_RESOLVER_DNS_TASK", "DNS_TRANSACTION"):
            outside.add("dns " + json.dumps(p)[:80])
        if sources.get(e["source"]["type"]) != "WEB_TRANSPORT_CLIENT":
            continue
        s = sessions.setdefault(e["source"]["id"], {"crypto": [], "end": None, "url": None})
        if t == "QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE" and p.get("url"):
            s["url"] = p["url"]
        elif t == "QUIC_SESSION_CRYPTO_FRAME_RECEIVED" and p.get("encryption_level") == "ENCRYPTION_INITIAL":
            s["crypto"].append((p.get("offset", 0), base64.b64decode(p.get("bytes", ""))))
        elif t == "QUIC_SESSION_WEBTRANSPORT_SESSION_READY":
            s["end"] = s["end"] or "ready"
        elif t == "QUIC_SESSION_CLOSED" and s["end"] != "ready":
            s["end"] = "closed: " + (p.get("details") or str(p.get("quic_error")))
    for sid, addr in udp_remote.items():
        if sid in udp_sent:
            outside.add("udp " + addr)
        else:
            # Chrome's IPv6 reachability check: connect() on a UDP socket, no packet sent.
            probes.add(addr)
    pq = 0
    for sid, s in sorted(sessions.items()):
        data = b"".join(b for _, b in sorted(s["crypto"]))
        sh = server_hello(data)
        if sh:
            g, v, c = sh
            facts = f"group={GROUPS.get(g, hex(g or 0))} version={'TLS1.3' if v == 0x0304 else v} suite={SUITES.get(c, hex(c))}"
            pq += g == 0x11EC
        else:
            facts = "no ServerHello"
        print(f"session {sid}: {s['url']} -> {s['end']}; {facts}")
    if outside:
        print("FAIL: Chrome contacted non-loopback hosts:", sorted(outside))
        return 1
    if probes:
        print("note: UDP sockets connected without sending (routing probes):", sorted(probes))
    if expect_pq and pq == 0:
        print("FAIL: no session negotiated X25519MLKEM768")
        return 1
    print(f"OK: no packet left loopback; {pq} session(s) negotiated X25519MLKEM768")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
