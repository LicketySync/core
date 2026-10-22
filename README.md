# Lickety-Sync — core

The sync core: keys, protocol, index, engine, networking, service, command line,
simulator and the offline decrypt tool, as a Cargo workspace. Rust only;
compiles for Windows, macOS, Linux (x86 and ARM), Android, iOS and WebAssembly.

Lickety-Sync syncs folders between your own devices and the people you share
with, and never contacts a server: no accounts, no tracker, no relay you did
not turn on. Every connection is encrypted, and only the people you give a
folder's key can join it.
Licensed under the Mozilla Public License 2.0.

- Plan and design: "Lickety-Sync: Project Plan" (the living document).
- Specification: [`spec/threat-model.md`](spec/threat-model.md) (adversaries and
  the numbered requirements TM-1 to TM-42 every change is reviewed against, of
  which TM-16, TM-19, TM-34, TM-36 and TM-38 are retired),
  [`spec/suites.md`](spec/suites.md) (algorithms, parameters and the approved
  crates), [`spec/keys.md`](spec/keys.md) (a folder's three shared keys and
  their derivations, key strings and words, signed records, encryption of
  contents and names, the handshake's folder proof, and unlinking and sharing
  again), [`spec/protocol.md`](spec/protocol.md) (wire protocol, handshake,
  messages, index records and how peers exchange them) and
  [`spec/allowed-hosts.txt`](spec/allowed-hosts.txt) (the host allow-list).
- How work is done: [`CONTRIBUTING.md`](CONTRIBUTING.md) and the CI in `.github/workflows/`.
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md).

## Crates

| Crate | Holds |
| --- | --- |
| `licketysync-keys` | Shared folder keys (write, read, sealed) and their derivations, Ed25519-signed index records, record hashes and writer digests, chunk and sealed-metadata encryption, keyed BLAKE3 chunk hashes and Padmé padding, the handshake's folder hint and proof key, device keys, key strings and the write key's words (TM-9, TM-11, TM-12, TM-14, TM-15, TM-32) |
| `licketysync-protocol` | The wire protocol `/licketysync/sync/1`: framing and a strict decoder for every message, the Hello checks, roles and transcript, the device proof and the one folder proof for every tier, index records and sealed metadata (step 1 and step 6), the §5 rules table, the index exchange (rounds, listed requests, pages, pushes) and chunk rules, and the sans-IO state machine of one connection (TM-2, TM-3, TM-10, TM-22, TM-23, TM-30, TM-32, TM-41) |
| `licketysync-index` | SQLite index of signed records per device sequence, cached cursor digests, `supersedes` heads and conflicts, waiting records and tombstones (TM-17, TM-40, TM-41) |
| `licketysync-engine` | FastCDC chunking (sealed, hashed and padded through `keys`), scanning and change journals, conflicts, versioning, selective sync, the archive and the deletion brake (TM-35) |
| `licketysync-net` | rust-libp2p transports, discovery, relays, DHT, HTTPS listener |
| `licketysync-daemon` | The service and its local API |
| `licketysync-cli` | The `licketysync` command |
| `licketysync-sim` | Deterministic multi-peer simulator (phase 0's gate) |
| `licketysync-decrypt` | Offline decrypt and verify tool |

## Status

Phase 0: skeleton. Nothing syncs yet. The roadmap and its gates are in the plan.
