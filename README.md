# Lickety-Sync — core

The sync core: keys, protocol, index, engine, networking, service, command line,
simulator and the offline decrypt tool, as a Cargo workspace. Rust only;
compiles for Windows, macOS, Linux (x86 and ARM), Android, iOS and WebAssembly.

Lickety-Sync syncs folders between your own devices and the people you share
with, and contacts no server you did not turn on: there are no accounts and no
tracker; no relay is used, and your devices relay for no one, unless you turn
that on (a relay passes encrypted traffic, which it cannot read, between
devices that cannot reach each other). Every connection is encrypted; only
devices that hold one of a folder's keys can join it, and anyone who holds a
key can pass it on.
Licensed under the Mozilla Public License 2.0.

- Plan and design: "Lickety-Sync: Project Plan" (the living document).
- Specification: [`spec/threat-model.md`](spec/threat-model.md) (adversaries and
  the numbered requirements TM-1 to TM-43 every change is reviewed against, of
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
| `licketysync-keys` | Shared folder keys (write, read, sealed) and their derivations, Ed25519-signed index records and cleanups under one label each, record hashes, path tags (file IDs) and set digests, chunk encryption with keyed BLAKE3 chunk hashes, Padmé padding and the chunker's keyed gear table, sealed metadata padded to a power of two, the handshake's folder hint and proof key, device keys, the libp2p identity and the DHT key, discovery hashes, the linked-device code and proof, key strings and the write key's words (TM-9, TM-11, TM-12, TM-14, TM-15, TM-32) |
| `licketysync-protocol` | The wire protocol `/licketysync/sync/1`: framing and a strict decoder for every message, the Hello checks (the clock rule included), roles and transcript, the device proof and the one folder proof for every tier, index records and cleanups with their dots and version vectors (step 1 and step 7, and the drafts a writer signs), the §5 rules table, the index exchange (Since requests and resets, reconciliation over set digests in passes, pages, pushes, cursors and the round owed) and chunk rules, and the sans-IO state machine of one connection (TM-2, TM-3, TM-10, TM-22, TM-23, TM-30, TM-32, TM-40, TM-41) |
| `licketysync-index` | The per-folder index: the latest versions of each path, ordered by version vectors at read and write holders and by names at sealed holders, tree deletes judged without a walk and signed cleanups, expiry by the folder's own time, bases and the lost-update rule, stale-copy notes, writes in one commit, the set digests over 128-nibble keys and their cache, serving from committed state, and transactions kept only once their commit succeeded and undone exactly otherwise; every record verified before it is held and again when the folder opens; in memory behind a storage trait until SQLite lands in phase 1 (TM-9, TM-17, TM-22, TM-40, TM-41) |
| `licketysync-engine` | The sync engine on the runtime traits (time, timers, transport, storage, randomness): one protocol connection per peer and one index per folder, index sync in rounds with reconciliation, every folder proven on connect, chunks fetched, judged per record and served, local writes, deletes, tree deletes and renames, conflict copies, the clock rule and a folder kept closed by it, pauses on a store failure, folder states, issues and status, all in the simulator's file model; fixed-size chunks (sealed and hashed through `keys`) and an in-memory store until FastCDC or another keyed chunker (`spec/keys.md` §3.2) and SQLite (the plan's decision of 2026-10-14) replace them in phase 1, with scanning and watching the disk, ignore files and per-path sync status; selective sync, versioning and the archive in phase 5; the plan's roadmap does not yet place the deletion brake (TM-6, TM-9, TM-10, TM-13, TM-22, TM-40, TM-41; TM-4 and TM-35 to come) |
| `licketysync-net` | The transports on rust-libp2p: QUIC and TCP, each with TLS 1.3 on `aws-lc-rs` offering X25519MLKEM768 first and only one security protocol, the device's libp2p identity from its seed, connection, stream and memory limits, and the one byte stream of `/licketysync/sync/1`; `examples/spike.rs` connects two peers on 127.0.0.1. Not yet wired to the engine: LAN discovery and the daemon in phase 1, relays, the DHT and the HTTPS listener later (TM-1, TM-2, TM-6, TM-22, TM-23, TM-31, TM-32) |
| `licketysync-daemon` | Placeholder: the service and its local API |
| `licketysync-cli` | Placeholder: the `licketysync` command (phase 1) |
| `licketysync-sim` | Deterministic multi-peer simulator: seeded network, clock and storage with fault injection, the engine's gate scenarios and the oracle that checks that every peer holds the same records and every read and write peer the same files (run on every push, and over many more seeds nightly) |
| `licketysync-decrypt` | Placeholder: offline decrypt and verify tool |

## Status

Now: phase 0, spikes and the protocol. Main holds the four specifications, the
simulator, and the keys, protocol, index, engine and net crates. Every gate scenario
on the simulator ends with the same records on every peer and the same files
on every read and write peer. Phase 0 is not finished: its gate (simulated
peers converge; spec published) passed on 2026-11-02, with its threat-model §6
review recorded in [`gates/phase-0.md`](gates/phase-0.md); still to do, from
the plan's work list (the owner's decision of 2026-11-02): the phone shells and
the WebTransport native-side check (the Android and iOS app shells, and a check
that browser connections work from the device side); the libp2p transports
connect two peers on loopback but carry no sync yet. Nothing syncs on a real
disk or over a real network yet, and there is nothing to install.

Next: phase 1, "LAN sync from the command line". Its gate: two Linux machines
pass the fault-test suite. By the plan's roadmap it brings the folder keys into
use, LAN discovery (mDNS and broadcast), QUIC, scanning and watching the disk,
conflicts and ignore files on a real disk, and a per-path sync status in the
engine; with them come SQLite storage (the plan's decision of 2026-10-14) and
FastCDC or another keyed chunker (`spec/keys.md` §3.2). The roadmap and the
later phases' gates are in the plan.
