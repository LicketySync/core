# LicketySync — core

The sync core: keys, protocol, index, engine, the disk, networking, service,
command line, simulator and the offline decrypt tool, as a Cargo workspace.
Rust only; compiles for Windows, macOS, Linux (x86 and ARM), Android, iOS and
WebAssembly.

LicketySync syncs folders between your own devices and the people you share
with, and contacts no server you did not turn on: there are no accounts and no
tracker; no relay is used, and your devices relay for no one, unless you turn
that on (a relay passes encrypted traffic, which it cannot read, between
devices that cannot reach each other). Every connection is encrypted; only
devices that hold one of a folder's keys can join it, and anyone who holds a
key can pass it on.
Licensed under the Mozilla Public License 2.0.

- Plan and design: "LicketySync: Project Plan" (the living document).
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
| `licketysync-protocol` | The wire protocol `/licketysync/sync/1`: framing and a strict decoder for every message, the Hello checks, roles and transcript, the device proof and the one folder proof for every tier, index records and cleanups with their dots, version vectors and watermarks (step 1 and step 7, and the drafts a writer signs), the §5 rules table, the index exchange (Since requests and resets, reconciliation over set digests in passes, pages, pushes, cursors and the round owed, toward a sealed peer at most daily for a change of the watermark) and chunk rules, and the sans-IO state machine of one connection (TM-2, TM-3, TM-10, TM-22, TM-23, TM-30, TM-32, TM-40, TM-41) |
| `licketysync-index` | The per-folder index: the latest versions of each path, ordered by version vectors at read and write holders and by names at sealed holders, tree deletes judged without a walk and signed cleanups, expiry by the watermark a write holder signs (its arrivals, its candidate and its interval), bases and the lost-update rule, stale-copy notes, writes in one commit, the set digests over 128-nibble keys and their cache, serving from committed state, and transactions kept only once their commit succeeded and undone exactly otherwise; every record verified before it is held and again when the folder opens; in memory behind a storage trait until SQLite lands in phase 1 (TM-9, TM-17, TM-22, TM-40, TM-41) |
| `licketysync-engine` | The sync engine on the runtime traits (time, timers, transport, storage, randomness): one protocol connection per peer and one index per folder, index sync in rounds with reconciliation, every folder proven on connect, chunks fetched, judged per record and served, local writes, deletes, tree deletes and renames, conflict copies, a write holder's watermark checks (at open, on resuming from sleep and hourly) and the rounds a change of the watermark owes, pauses on a store failure, folder states, issues and status, all in the simulator's file model; fixed-size chunks (sealed and hashed through `keys`) and an in-memory store until FastCDC or another keyed chunker (`spec/keys.md` §3.2) and SQLite replace them in phase 1, with scanning and watching the disk, ignore files and per-path sync status; selective sync, versioning and the archive in phase 5; the plan's roadmap does not yet place the deletion brake (TM-6, TM-9, TM-10, TM-13, TM-22, TM-40, TM-41; TM-4 and TM-35 to come) |
| `licketysync-fs` | A folder's disk: the name policy for Linux, macOS and Windows, which says which names a device can store and turns a name on the disk into part of an index path (UTF-8, NFC, `check_path`, no name a file system could take for `.licketysync` at any depth, a length limit per platform, and on Windows no reserved character, control character, trailing dot or space, or device name); and the resolver beneath a folder's root, which makes and holds the hidden directory `.licketysync`, reaches every name one directory descriptor at a time, and never follows a symbolic link or enters another folder or the hidden directory, nor crosses a mount point (by mount ID on Linux 5.8 and later; by device on macOS and older Linux, which misses a bind mount of the same file system) (`openat2` on Linux, the walk with `O_NOFOLLOW` on macOS; Windows in phase 3). Not yet used by the engine: atomic writes, the scanner and the watcher come in phase 1 (TM-3, TM-4) |
| `licketysync-net` | The transports on rust-libp2p: QUIC and TCP, each with TLS 1.3 on `aws-lc-rs` offering X25519MLKEM768 first and only one security protocol, the device's libp2p identity from its seed, connection, stream and memory limits (no memory limit on iOS yet, so no node starts there, TM-22), and the one byte stream of `/licketysync/sync/1`; `examples/spike.rs` connects two peers on 127.0.0.1. Not yet wired to the engine: LAN discovery and the daemon in phase 1, relays, the DHT and the HTTPS listener later (TM-1, TM-2, TM-6, TM-22, TM-23, TM-31, TM-32) |
| `licketysync-daemon` | Placeholder: the service and its local API |
| `licketysync-cli` | Placeholder: the `licketysync` command (phase 1) |
| `licketysync-sim` | Deterministic multi-peer simulator: seeded network, clock and storage with fault injection, the engine's gate scenarios and the oracle that checks that every peer holds the same records and every read and write peer the same files (run on every push, and over many more seeds nightly) |
| `licketysync-decrypt` | Placeholder: offline decrypt and verify tool |

## Status

Now: phase 1, "LAN sync from the command line". Its gate: two Linux machines
pass the fault-test suite. Main holds the four specifications, the simulator,
and the keys, protocol, index, engine, fs and net crates. Every gate scenario on
the simulator ends with the same records on every peer and the same files on
every read and write peer. The libp2p transports (QUIC and TCP) connect two
peers on loopback, and the phone shell links the keys and net crates, but
nothing syncs on a real disk or over a real network yet, and there is nothing
to install.

Phase 1 builds, by the plan's roadmap: the folder keys in use, LAN discovery
(mDNS and broadcast), QUIC, scanning and watching the disk, conflicts and
ignore files on a real disk, and a per-path sync status in the engine; with
them SQLite storage and FastCDC or another keyed chunker (`spec/keys.md`
§3.2). It also builds the engine side of the relay, coordinator and
unreadable-copy spec change, the guided setup's starting values, the handling
of device problems, the QUIC limits required before 1.0 and the
mutation-testing mandate. The roadmap and the later phases' gates are in the
plan.
