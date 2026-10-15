# Lickety-Sync — core

The sync core: keys, protocol, index, engine, networking, service, command line,
simulator and the offline decrypt tool, as a Cargo workspace. Rust only;
compiles for Windows, macOS, Linux (x86 and ARM), Android, iOS and WebAssembly.

Lickety-Sync syncs folders between your own devices and the people you share
with, and never contacts a server: no accounts, no tracker, no relay you did
not turn on. Every connection is encrypted and every key is one you issued.
Licensed under the Mozilla Public License 2.0.

- Plan and design: "Lickety-Sync: Project Plan" (the living document).
- Specification and threat model: [`spec/`](spec/) (being written in phase 0;
  so far it holds only the host allow-list).
- How work is done: [`CONTRIBUTING.md`](CONTRIBUTING.md) and the CI in `.github/workflows/`.
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md).

## Crates

| Crate | Holds |
| --- | --- |
| `licketysync-keys` | Recovery phrase, seed-derived keypairs, X-Wing/HPKE wrapping, hybrid signatures, grants and revocations |
| `licketysync-protocol` | Suites, framing, Hello, Status, record and relay messages |
| `licketysync-index` | SQLite index, version vectors, hash-chained records, tombstones, deletion brake |
| `licketysync-engine` | FastCDC + keyed BLAKE3, padding, scanning and change journals, conflicts, versioning, selective sync |
| `licketysync-net` | rust-libp2p transports, discovery, relays, DHT, HTTPS listener |
| `licketysync-daemon` | The service and its local API |
| `licketysync-cli` | The `licketysync` command |
| `licketysync-sim` | Deterministic multi-peer simulator (phase 0's gate) |
| `licketysync-decrypt` | Offline decrypt and verify tool |

## Status

Phase 0: skeleton. Nothing syncs yet. The roadmap and its gates are in the plan.
