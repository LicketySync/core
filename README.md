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
| `licketysync-keys` | A folder's three shared keys and their derivations, signed records, chunk and metadata encryption, the keyed chunker, path tags and set digests, handshake proofs, key strings and words |
| `licketysync-protocol` | The wire protocol `/licketysync/sync/1`: framing and a bounded decoder for every message, the handshake and folder proof, index records and version vectors, the index exchange and chunk rules, and the sans-IO state machine of one connection |
| `licketysync-index` | One folder's index: the latest versions of each path, tree deletes and cleanups, expiry by a signed watermark, set digests and serving, every record verified before it is held and again at open |
| `licketysync-engine` | The sync engine on runtime traits (time, timers, transport, storage, randomness): a connection per peer and an index per folder, chunks, writes, conflicts, issues and status; runs in the simulator, not yet on a real disk or network |
| `licketysync-fs` | A folder's disk: the name policy for Linux, macOS and Windows, and the one resolver beneath a folder's root, which never follows a symbolic link (Linux and macOS; Windows in phase 3); not yet used by the engine |
| `licketysync-net` | Networking on rust-libp2p: QUIC and TCP on TLS 1.3 with X25519MLKEM768, the device's libp2p identity, connection, stream and memory limits, and the protocol's byte stream; not yet wired to the engine |
| `licketysync-daemon` | The service; today the device's store: the engine's storage on SQLite |
| `licketysync-cli` | Placeholder: the `licketysync` command |
| `licketysync-sim` | Deterministic multi-peer simulator: seeded clock, network and storage with fault injection, and the engine's gate scenarios with the oracle that checks they converge |
| `licketysync-decrypt` | Placeholder: the offline decrypt and verify tool |

## Status

Now: phase 1, "LAN sync from the command line". Its gate: two Linux machines
pass the fault-test suite. Every gate scenario on the simulator ends with the
same records on every peer and the same files on every read and write peer.
The libp2p transports connect two peers on loopback, the daemon has its SQLite
store and the fs crate its resolver, but nothing syncs on a real disk or over
a real network yet, and there is nothing to install.

Phase 1 builds, by the plan's roadmap: the folder keys in use, LAN discovery
(mDNS and broadcast), QUIC, scanning and watching the disk, the deletion
brake, the Trash can archive, conflicts and ignore files on a real disk, a
per-path sync status, and the engine's use of the keyed chunker (`spec/keys.md`
§3.2) in place of fixed-size chunks. It also builds the engine side of the relay, coordinator
and unreadable-copy spec change, the guided setup's starting values, the
handling of device problems, the QUIC limits required before 1.0 and the
mutation-testing mandate. The roadmap and the later phases' gates are in the
plan.
