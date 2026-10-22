# Lickety-Sync cryptographic suites

Version 2, 2026-10-22 (version 1, 2026-10-14, described the issued-keys model). This file names
every algorithm, parameter and crate that may perform cryptography in this workspace, the apps and
the browser client. It is normative: first-party code uses nothing that is not listed here, and a
change that needs something else adds it here first, with the reason, and is reviewed as a change to
the key model. `threat-model.md` says what these choices must achieve (TM-5, TM-11, TM-12, TM-30,
TM-33); `keys.md` says which key is derived from which and holds the label registry and every
associated-data layout; `protocol.md` says where each primitive appears on the wire. This file
refers to both by topic, never by section number, so that they can be reorganised without breaking
it.

The plan's Security paragraph lists the approved crates by name and its Encrypted connections
section lists the algorithms; this file pins versions, fixes parameters and encodings, and records
what was checked on 2026-10-14. Where this file decides something the plan leaves open, the decision
is marked **(decision)** and listed in the change's report so the plan can record it.

**What changed on 2026-10-22.** With the shared-key model (the owner's decision of 2026-10-18) and
the owner's answer of 2026-10-22 ("Ed25519 alone"), the coordinator ruled that every signature is
Ed25519 (R-K1) and that suite 1 has no key encapsulation (R-K2): X-Wing, HPKE and ML-DSA-65 leave
suite 1, and with the owner key the exported root file (age) and the recovery phrase go too. The
`bip39` crate stays, for the write key's words. Later rulings of the same day leave two signatures
(index records and the DeviceProof: the folder proof is one sealed proof for every tier, S-1, and
the Folder record is gone, S-2), derive the handshake's hint key and payload key from the access key
so that no key is used raw for two purposes, move `bech32` to 0.12 and add `base64` 0.23 to the
helpers. Section numbers are kept; section 2.1 is now a note. The drafts never shipped, so their
labels carry no compatibility duty; the rule that a label is never reused applies from the first
release on.

## 1. The rule: suites are whole sets

A suite is one complete set of algorithms that work together, identified by one number. There is no
negotiation of individual parts, because a menu of parts is what let SSL's cipher-suite lists be
downgraded (FREAK, Logjam, POODLE) and what TLS 1.3 fixed by shrinking the menu to a handful of whole
suites.

- **Every record and every key carries a suite number.** It is an unsigned 16-bit integer. 0 is
  invalid and never appears on the wire or on disk. 1 is the suite in section 2. A record, key,
  signature or encrypted blob is entirely under one suite; its suite number is inside the signed or
  authenticated bytes, so it cannot be changed without detection.
- **A suite is a whole set, never a menu.** It fixes the signature, the data cipher, the hash, the
  key derivation and the passphrase function together. Code never combines a part of one suite with
  a part of another, and no message offers a choice of parts.
- **Suite lists in Hello are bound to the transcript.** Each side's Hello lists the suites it
  supports, preferred first. Both lists are included in the handshake transcript that the session
  keys authenticate, so if either side sees a list other than the one its peer sent, the handshake
  fails and the connection is dropped (TM-30). A downgrade is therefore detected, not negotiated.
  `protocol.md` specifies the transcript.
- **A folder's suite is fixed by its keys (decision 2026-10-22).** Every key string of a folder
  carries its suite and the folder ID hashes it, so every key and every record of a folder is under
  that one suite, and a record that names another is malformed. There is no per-folder minimum suite
  and nothing moves a folder to another suite: a folder under a newer suite is a new folder, made by
  unlinking and sharing again (`keys.md`, making, unlinking and sharing again). This replaces the
  drafts' rotation to a new suite and their root-rotation record.
- **Retiring an algorithm drops its suite.** A release that retires a weak algorithm stops making
  folders under its suite, and a later release removes the suite from the set the code will use at
  all; the app offers to share again, under a current suite, every folder still under the retired
  one.
- **Where a suite pairs two algorithms, both are required.** A later suite that pairs a classical
  and a post-quantum algorithm uses both, and both must succeed; there is no mode that accepts one of
  the two (TM-33). Suite 1 pairs none: its signature is Ed25519 alone.

## 2. Suite 1

Suite 1 is Ed25519 for signatures, XChaCha20-Poly1305 for data, BLAKE3 for hashing and key
derivation, Argon2id for passphrases (phase 1, the local key store), and TLS 1.3 or Noise on the
transport. The 256-bit symmetric
parts survive a quantum computer (Grover halves them to 128 bits). Ed25519 does not, and the owner
chose it alone (2026-10-22); `threat-model.md` TM-33 states what a future forger could do. The
record layer has no public-key encryption at all: no key is ever wrapped to anyone.

| Role | Algorithm | Crate (pinned range) | Sizes |
| --- | --- | --- | --- |
| Signature | Ed25519 (RFC 8032), pure, verified strictly | `ed25519-dalek` 3 | public key 32, signature 64, secret a 32-byte seed |
| Data encryption | XChaCha20-Poly1305 | `chacha20poly1305` 0.11 | key 32, nonce 24, tag 16 |
| Hash and key derivation | BLAKE3: hash, keyed hash, derive_key | `blake3` 1 | output 32, key 32 |
| Passphrase (phase 1) | Argon2id v1.3, m = 64 MiB, t = 3, p = 4 | `argon2` 0.6 | salt 16, output 32 |
| Transport | TLS 1.3 with X25519MLKEM768 over QUIC and TCP; Noise XX inside WebSocket, WebTransport and WebRTC (the WebSocket path is classical end to end as `libp2p-websocket` ships, section 2.6) | `rustls` 0.23 on `aws-lc-rs` 1; `libp2p-tls`, `libp2p-quic`, `libp2p-noise`, `libp2p-websocket`, `libp2p-identity` | as the transports specify |

### 2.1 Key encapsulation (removed 2026-10-22)

Suite 1 has no key encapsulation (ruling R-K2). The drafts wrapped the folder's data key to every
issued key with X-Wing (X25519 + ML-KEM-768) through HPKE, so that sealed peers could store wrapped
keys for years; with three shared folder keys there is nobody to wrap to, and no wrapped key is
stored anywhere. Keys move as key strings outside the protocol, and between a person's linked
devices over the authenticated device channel, which runs only over QUIC or TCP with TLS 1.3 and its
hybrid X25519MLKEM768 key exchange, never over the classical WebSocket path (`keys.md`, linked
devices) **(decision)**. The `hpke`, `x-wing` and `ml-kem` crates leave the approved list
(section 3.1), and `deny.toml` carries no entries for them. What was checked about X-Wing and HPKE on
2026-10-14 is in this file's history.

### 2.2 Signatures: Ed25519

Index records are signed with the folder's signing key, and the handshake's DeviceProof with the
device key; a forged signature is a forged change or a forged identity. Nothing else is signed in
suite 1: the folder proof is a sealed payload, not a signature (`keys.md`, handshake proofs). Every
signature in suite 1 is Ed25519 alone (ruling R-K1, after the owner's answer of 2026-10-22)
**(decision)**.

- **The algorithm.** Ed25519 as RFC 8032 pure Ed25519: no prehashing (not Ed25519ph), no context
  string (not Ed25519ctx). Public key 32 bytes, signature 64 bytes, secret a 32-byte seed. Crate
  `ed25519-dalek` 3 with the default features (`zeroize`, `fast`) and never `legacy_compatibility`
  or `hazmat`. Verification uses `verify_strict`, which rejects small-order and non-canonical
  components, so signatures are strongly unforgeable and not malleable; there is no other
  verification path in first-party code.
- **Domain separation.** Every signed layout has a label. The bytes signed are
  `M = label || 0x00 || body`, where `label` is the ASCII string `licketysync/v1/sig/<type>` and
  `<type>` one of the names `keys.md` registers (`index`, `device-proof`, and any the browser
  bundle manifest adds). For a record, `body` is its canonical encoding, which
  already contains the suite number. A label is never reused for two layouts; a layout change is a
  new label.
- **Encodings.** A signature is exactly 64 bytes and a public key exactly 32, the canonical encoding
  of a point that is not of small order (decoding and re-encoding gives the same bytes), so one key
  has one ID; anything else is malformed and the record or message is rejected before any
  verification runs. Where a
  folder or device is identified, the ID is the 32-byte labelled hash
  `H("licketysync/v1/hash/id/<kind>", be16(suite) || public_key)` of section 2.4, with `<kind>`
  `folder` over the folder's verification key or `device` over a device key.
- **Keys from seeds.** The folder's signing key comes from
  `derive_key("licketysync/v1/folder/signing-key", write secret)` and a device's from
  `derive_key("licketysync/v1/key/ed25519", device seed)`, loaded with `SigningKey::from_bytes`; the
  libp2p identity and the DHT key derive from the device seed under their own labels (section 2.6).
  Only the write secret and the device seed are stored.
- **Signing is deterministic.** Ed25519 needs no randomness and the same key and body always give
  the same signature, so test vectors reproduce through the production signing path; a record is
  identified by the hash of its body, never of its signature.
- **Removed.** With R-K1: ML-DSA-65, the hybrid signature that required both halves, the grant's
  proof-of-possession signature and key IDs. With S-1 and S-2: the write tier's folder-proof
  signature and the Folder record's signature. What a future quantum computer could forge is TM-33;
  post-quantum signatures would come as a later suite (section 5).

### 2.3 Data encryption: XChaCha20-Poly1305

The plan allows XChaCha20-Poly1305 or AES-256-GCM; suite 1 uses XChaCha20-Poly1305 **(decision)**.
Its 192-bit nonce makes the content-derived nonces that sealed-peer deduplication needs safe, since
the space is far too large for a derived nonce to collide with any random one, and it has no hardware
dependence, so the browser build and old ARM devices run it at full speed and without the timing side
channels of software AES. AES-256-GCM, with its 96-bit nonce, may become a later suite.

**Definition.** XChaCha20-Poly1305 as in draft-irtf-cfrg-xchacha-03: HChaCha20 derives a subkey
from the key and the first 16 bytes of the nonce, then ChaCha20-Poly1305 (RFC 8439) runs with the
remaining 8 nonce bytes. Key 32 bytes, nonce 24 bytes, tag 16 bytes, ciphertext length = plaintext
length + 16. It is a CFRG draft rather than an RFC, and the most widely deployed AEAD in libsodium
and its ports; its construction is a thin, standard extension of RFC 8439. Crate `chacha20poly1305`
0.11, type `XChaCha20Poly1305`; this crate has had one security audit (NCC Group, 2020, no
significant findings).

**Nonce rules (TM-12).**

1. **Chunks: content-derived.** The nonce of a chunk is the first 24 bytes of BLAKE3 in keyed mode,
   keyed with the folder's chunk-nonce key (derived from its data key under its own label,
   `keys.md`, keys derived from the data key), over the plaintext chunk exactly as it is encrypted,
   header and Padmé padding included. The same plaintext under the folder's key therefore yields the
   same ciphertext, which lets a sealed peer verify and deduplicate; two different plaintexts cannot
   share a nonce under one key unless BLAKE3 collides. This is the plan's sealed-peer rule, and its
   cost is stated in `threat-model.md` section 5: identical chunks look identical.
2. **Everything else: random.** Every other encryption (the sealed metadata of index records, the
   handshake's proof payload, the local key store) uses 24 bytes drawn through the runtime's
   randomness trait, which the operating system's generator backs in production (section 4.3),
   fresh for every encryption and never stored for reuse.
3. **Never reuse on re-encryption.** A (key, nonce) pair is used twice only when the plaintext
   **and** the associated data are both byte-identical, because the Poly1305 key is the first block
   of the keystream for that (key, nonce) and a second message under it with different bytes forges
   or leaks. Rule 1 makes this true for chunks: the nonce is a function of the padded plaintext, and
   the chunk associated data, the folder ID, is a function of the key alone, so identical plaintext
   under one key always meets identical associated data. A folder's keys never change, and a folder
   that needs new keys is a new folder with all-new keys, so no (key, nonce) pair crosses folders.
4. **One key, bounded use.** No counter is kept, and none is needed: a chunk is at most 4 MiB
   (`MAX_CHUNK_PLAINTEXT`), far below the 2^38-byte message bound; derived chunk nonces collide only
   if BLAKE3 does; and a 192-bit random nonce stays collision-free far beyond any number of records
   a folder will hold (2^64 random nonces under one key collide with probability below 2^-64).

**Compression before encryption.** A chunk may be compressed before it is padded and encrypted
(`keys.md`, chunk encryption; the code sits inside the ciphertext). Compression under encryption is a
CRIME-style length channel: when bytes an attacker can influence share a chunk with secrets, the
padded ciphertext size reveals how well the two compressed together. Padmé blunts the channel (2 KiB
granularity at 64 KiB, 128 KiB at 4 MiB) and does not remove it. Phase 0 uses no compression; the
release that enables one states the channel in `threat-model.md` section 5 and on the site before it
ships.

**Associated data.** Always present and never empty. The caller's specification names it:
`keys.md` for chunks and sealed metadata, `protocol.md` for the handshake payload. Every layout binds
at least the folder and whatever identifies the place (a chunk's `folder_id`; sealed metadata's
`folder_id || device_id || be64(seq)`; the proof payload's hint, which is keyed with a key derived
from the folder's access key and covers the folder ID, the transcript and the prover's role), so a
ciphertext cannot be moved to another folder, record or connection; the suite is bound by the key,
which exists under one suite only.

**Padding (decision).** Chunks and sealed metadata are padded before encryption with Padmé
(Nikitin et al., PURBs 2019), exactly as `keys.md` defines it (Padmé padding). It is the one padding
scheme in suite 1 and the one written in this workspace, in the `keys` crate, because no approved
crate provides it; `threat-model.md` TM-5 permits it by name. It is not a cryptographic primitive:
a mistake in it leaks sizes, never contents.

### 2.4 Hashing and key derivation: BLAKE3

BLAKE3 has three modes that are domain-separated from each other by construction: plain hashing,
keyed hashing, and key derivation from a context string. Suite 1 uses them for four jobs, each with
its own rule, so no two jobs can produce the same output from the same input. `keys.md`'s label
registry lists every label in use and is the one place a label is added; the table below copies it
and must stay identical to it. Output is always 32 bytes, truncated only where `keys.md` says so (a
16-byte LAN beacon ID, peer tag and link beacon ID under `licketysync/v1/link/discovery`, a 20-byte
DHT ID, and the 24-byte chunk nonce); the extendable-output mode is not used. Crate `blake3` 1 in its
default build, which is not pure Rust: on x86-64 its build script compiles the upstream assembly
with `cc`, and on little-endian AArch64 the C NEON code (the `pure` feature would turn both off);
WebAssembly gets SIMD only through the `wasm32_simd` feature, which is not enabled, so the browser
build runs the portable Rust code. Its unsafe and foreign code is accepted and shows in
cargo-geiger's report. The `rayon` feature may be used for large files, nothing else.

- **The labelled hash `H` for every identifier and link over public data.**
  `H(label, x) = BLAKE3(label || 0x00 || x)`, with `label` an ASCII label under
  `licketysync/v1/hash/`. It names folders and devices, records and stored chunks, the discovery
  hashes, the handshake transcript and the cursor digests that reconcile index records. Plain
  `BLAKE3(x)` without a label appears nowhere in first-party code: the label is part of the hashed
  bytes, so a hash of one kind can never equal a hash of another kind over the same bytes. The
  identity rule is `H("licketysync/v1/hash/id/<kind>", be16(suite) || public_key)` with `<kind>`
  `folder` (over the folder's verification key) or `device`, as `keys.md` fixes them, so a device key
  misused as a folder key, or the reverse, cannot produce a matching ID.
- **The keyed hash where the output must mean nothing without the key.** `BLAKE3_keyed(k, x)` with a
  32-byte key `k` that a `derive_key` label made for that one use, so the keyed input carries no
  label of its own: the plaintext chunk hash `plain_hash` under the folder's chunk-hash key (TM-14);
  chunk nonces under the chunk-nonce key (section 2.3); the handshake's folder hint under the hint
  key and its proof key under the payload key, both derived from the folder's access key; and the
  link proof under the link-confirm key. Every key holder at every tier derives the access key and
  nobody else can, so the hint and the proof key are secret from everyone without a key to the folder
  (a network observer, a relay, a connected peer with no key), from whom they hide which folder the
  other side is proving; the sealed payload that opens under the proof key is what admits a peer. The
  drafts keyed both with the folder ID, which every relay knew.
- **`derive_key` for every purpose key, from uniformly random key material only.**
  `derive_key(label, material)` with a registered label and 32 bytes of uniformly random material: a
  write secret, a data key, an access key, a device seed, a link secret. Every key in the system
  comes from its parent this way, so no key serves two purposes (TM-11). The material is never public
  data, which is `H`'s job, and never a passphrase (section 2.5).
- **The signature prefix** `M = label || 0x00 || body` under `licketysync/v1/sig/` (section 2.2) is
  the fourth labelled use; it is signed, not hashed.

**Who may call BLAKE3.** Only the `keys` crate, which owns all of the workspace's cryptography,
identifiers and hashes, and inside it only its labels module (`crates/keys/src/labels.rs`), so that
every hash in the workspace is one of the four jobs above under its label. On main `protocol` and
`index` are stubs with no dependencies. `protocol` is to depend on `keys`, take the folder hint and
the proof key from it, and build the transcript hash with its labelled hash
(`labels::labelled_hash`); it computes no hash itself and never sees plaintext. `index` uses `keys`'s
record hash and its cursor-digest helper. `keys` depends on neither. The control is cargo-deny:
`deny.toml`'s `blake3` and `chacha20poly1305` entries list `licketysync-keys` as their only wrapper,
so that no other crate may depend on either. In `keys` and `protocol`, a Semgrep tripwire
(`.semgrep/project.yml`) flags every call into `blake3` (`hash`, `keyed_hash`, `derive_key`, and a
`Hasher` from `new`, `default`, `new_keyed` or `new_derive_key`) and every `use` or `extern crate` of
it, except in `keys`'s labels module, which it excludes by path, in the crates' integration tests
and out-of-line `tests.rs` modules, and inside a `mod tests`; so the qualified paths the first rule
matches are the only way to reach the crate. It catches mistakes, not intent: Semgrep does not
resolve paths, so a call it cannot parse, such as one inside a macro, passes. The cases it must and
must not flag are in `.semgrep/tests/project.rs`, which CI runs with `semgrep --test` before the
scan; the exclusion by path is exercised by the scan itself.

**Label format.** A label is ASCII, lowercase, from `a-z`, `0-9`, `-` and `/`, and reads
`licketysync/v1/<area>/<purpose>`: `<area>` groups labels by what they derive from or serve
(`folder`, `data`, `key`, `link`, `handshake`, `hash`, `sig`), and `<purpose>` is one or more
`/`-separated words. The prefix `licketysync/v1/` is reserved for suite 1; suite 2 uses
`licketysync/v2/`. Every label is a `const` in `keys`'s label registry (`crates/keys/src/labels.rs`),
which the other crates import; every `derive_key` label has a test vector of its own (section 4.4),
and every other label is exercised by the vectors of the construction that uses it, so a changed
label fails a test. The table below is `keys.md`'s registry, copied row for row and byte for byte so
that the two can be compared mechanically; the section pointers inside it are the registry's own and
refer to `keys.md` and `protocol.md`, the one place this file carries a section number of either.
Removed on 2026-10-22: the `identity/`, `epoch/` and `wrap/` labels, `folder/root-seed`,
`folder/chunk-hash-key`, `key/ml-dsa-65`, `key/x-wing`, `hash/id/identity`, `hash/id/key`, the
keyed `handshake/folder-hint` and `handshake/proof-key`, and the `sig/` labels of the drafts' key
records, the Folder record, the folder proof and the grant proof of possession. Since the drafts
never shipped, the rule that a label is never reused applies from the first release on.

| Label | Mode | Material / input | Output |
| --- | --- | --- | --- |
| `licketysync/v1/folder/signing-key` | derive_key | write secret | Ed25519 seed of the folder signing key (§1.2) |
| `licketysync/v1/folder/data-key` | derive_key | write secret | data key `dk` (§1.2) |
| `licketysync/v1/data/access-key` | derive_key | data key | access key `ak` (§3.1) |
| `licketysync/v1/data/chunk-key` | derive_key | data key | `ck` (§3.1) |
| `licketysync/v1/data/chunk-nonce-key` | derive_key | data key | `nk` (§3.1) |
| `licketysync/v1/data/chunk-hash-key` | derive_key | data key | `hk` (§3.1) |
| `licketysync/v1/data/record-key` | derive_key | data key | `rk` (§3.1) |
| `licketysync/v1/handshake/hint-key` | derive_key | access key | keyed-BLAKE3 key of the folder hint (§4) |
| `licketysync/v1/handshake/payload-key` | derive_key | access key | keyed-BLAKE3 key that gives each connection's proof key (§4) |
| `licketysync/v1/key/ed25519` | derive_key | device seed | Ed25519 seed of the device key (§8.1) |
| `licketysync/v1/key/libp2p-identity` | derive_key | device seed | Ed25519 seed of the libp2p identity (§8.1) |
| `licketysync/v1/key/dht-bep44` | derive_key | device seed | Ed25519 seed of the BEP 44 DHT signing key (§8.1, phase 2) |
| `licketysync/v1/link/discovery` | derive_key | link secret | link beacon ID (16) (§8.3, phase 5) |
| `licketysync/v1/link/confirm` | derive_key | link secret | keyed-BLAKE3 key for the link proof (§8.3, phase 5) |
| `licketysync/v1/hash/id/folder` | `H` | be16(suite) \|\| folder verification key | folder ID (§0.3) |
| `licketysync/v1/hash/id/device` | `H` | be16(suite) \|\| device public key | device ID (§0.3) |
| `licketysync/v1/hash/record` | `H` | record body | record hash |
| `licketysync/v1/hash/chunk` | `H` | stored chunk blob | `cipher_hash` |
| `licketysync/v1/hash/writer-digest` | `H` | previous digest (32) \|\| record hash (32) | cursor digest (`protocol.md` §4.4) |
| `licketysync/v1/hash/discovery-peer` | `H` | salt (16) \|\| announcer libp2p identity key (32) | peer tag (16) in the LAN beacon (§2.2) |
| `licketysync/v1/hash/discovery-lan` | `H` | salt \|\| folder ID \|\| peer tag \|\| be64(minute) | LAN beacon ID (16) |
| `licketysync/v1/hash/discovery-dht` | `H` | folder ID \|\| be64(day) | DHT ID (20) |
| `licketysync/v1/hash/transcript` | `H` | protocol ID, both libp2p identity keys, both Hellos | transcript hash (`protocol.md` §3.3) |
| `licketysync/v1/sig/index` | prefix of `M` | record body | signed message (§5) |
| `licketysync/v1/sig/device-proof` | prefix of `M` | transcript hash \|\| role | signed message (`protocol.md` §3.4) |

BLAKE3's own guidance for `derive_key` contexts is "[application] [commit timestamp] [purpose]"; the
format above drops the timestamp in favour of the registry and the version segment, which give the
same global uniqueness **(decision)**.

### 2.5 Passphrases: Argon2id

A passphrase protects a key store on a device with no platform keystore (a headless Linux box, a NAS,
a container) and any other place `keys.md` names where a human-chosen secret unlocks key material. It
is never used to stretch a write secret or the write key's words, which already hold 256 bits of
entropy. All of this is phase 1's: the key store arrives with the daemon, phase 0 stores no key on
disk, and the keys crate has no Argon2id until then (decision).

**Parameters.** Argon2id, version 0x13 (1.3), memory m = 65536 KiB (64 MiB), iterations t = 3,
parallelism p = 4, salt 16 bytes through the runtime's randomness trait, output 32 bytes
**(decision)**. These are RFC 9106 section 4's second recommended option, chosen over the first
(2 GiB, t = 1) because phones and the browser build must run it. Crate `argon2` 0.6 with the
`zeroize` feature; the parameters are passed explicitly, never the crate's defaults.

**Minimum accepted.** m ≥ 19456 KiB, t ≥ 2, p ≥ 1, salt ≥ 16 bytes: the memory floor equals OWASP's
19 MiB option, and its lower-memory options are refused. A key store that asks for less is refused as
corrupt rather than derived with weak parameters.

**Raising them later.** The parameters and salt are stored in clear beside the ciphertext, in the
key-store format that the phase 1 change adding the daemon's key store fixes (`keys.md`, the local
key store), so a newer release derives with whatever the stored parameters say. When a release raises
the defaults, the store is re-encrypted under the new parameters the next time the person unlocks it,
which is the only time the passphrase is available; a release never changes them silently.

**The exported root file (removed 2026-10-22).** The drafts exported the owner key as an age file
whose passphrase recipient is scrypt, the one passphrase not under Argon2id. There is no owner key,
so there is no such file, and the `age` crate leaves the approved list (section 3.1).

### 2.6 Transport

The transport suite is separate from the record suite and is negotiated by libp2p (protocol
identifiers in multistream-select), because the transport protects the path and the record suite
protects the data: content, names and structure are encrypted under the folder's keys before they
reach any transport, so the transport adds forward secrecy for the session and hides from a network
observer what a sealed peer would otherwise see (threat model section 5).

**One security protocol per transport (decision).** Each transport offers exactly one security
protocol, so multistream-select has nothing to choose between before either side is authenticated:
TLS 1.3 on QUIC and on TCP; Noise only inside WebSocket, WebTransport and WebRTC, where TLS is not
offered. A side that is offered the other protocol on a transport closes the connection. This
qualifies the plan's "nothing is negotiated before the secure channel exists": libp2p does negotiate
the security protocol, so the sentence is made true by giving it one candidate per transport (threat
model, section 3.1 and TM-1). What the rule does not prevent is the choice of transport: an attacker
who blocks UDP and raw TCP steers a dialer onto the WebSocket path, whose Noise handshake is
classical, and whose outer TLS is classical too: `libp2p-websocket` 0.46.0 builds its rustls
configuration on rustls's `ring` provider, which offers X25519, P-256 and P-384 and no post-quantum
group, and has no way to be given another provider. A WebSocket session is therefore classical end to
end. It is still encrypted and authenticated, so nothing the record layer protects is weakened, but a
recording of it is readable by a future quantum computer up to what a sealed peer sees, as the threat
model's quantum entry (its section 5) states **(deviation from the plan's post-quantum transport;
phase 2 item: a reviewed patch to, or an upstream change in, `libp2p-websocket` that accepts a
provider, so that its outer TLS is built on `aws-lc-rs` and offers X25519MLKEM768 like the others)**.
For the same reason the linked-device channel, which carries folder keys, never runs over WebSocket
(section 2.1). It also builds with `with_safe_default_protocol_versions()`, so its outer TLS accepts
TLS 1.2 whenever rustls's `tls12` feature is on, and in rustls 0.23 `tls12` is a default feature, on
unless every crate that depends on rustls disables default features; the change that adds `net` checks
`cargo tree -e features -i rustls` for that and keeps it off.

- **TLS 1.3 only**, through `libp2p-tls` and `libp2p-quic`, which build their rustls 0.23
  configurations on the `aws-lc-rs` provider with rustls's `prefer-post-quantum` feature, so the key
  exchange offers X25519MLKEM768 (the hybrid the plan names, pre-standard but deployed by Chrome and
  Cloudflare) first and X25519 as the fallback for peers that lack it. Checked 2026-10-14:
  `libp2p-tls` 0.7.0 depends on rustls with the `aws-lc-rs` and `prefer-post-quantum` features, builds
  on `aws_lc_rs::default_provider()`, and carries a test that X25519MLKEM768 is preferred; the phase 2
  gate's packet capture confirms the group in the ClientHello. Cipher suites: `libp2p-tls`'s list is
  `TLS13_CHACHA20_POLY1305_SHA256`, `TLS13_AES_256_GCM_SHA384` and `TLS13_AES_128_GCM_SHA256`, in that
  order of preference, and suite 1 accepts that list as it ships **(decision, deviation from the
  plan's "256-bit symmetric everywhere")**: two Lickety-Sync peers share the list, so the suite chosen
  between them is the first one, and AES-128 is negotiated only with a foreign libp2p peer that offers
  nothing else; transport session keys are ephemeral and the record layer is 256-bit throughout, so
  dropping the 128-bit suite would buy little, and removing it means `net` building its own crypto
  provider, which is deferred until some other need forces it. Certificates follow the libp2p TLS
  specification: each side's certificate is self-signed by its own freshly generated P-256 key and
  carries the libp2p extension, in which the libp2p identity key signs the certificate's public key;
  inside `libp2p-tls`, `ring` verifies the certificate's own self-signature (P-256 for the
  certificates we generate) and the TLS 1.3 CertificateVerify signature, and the extension's Ed25519
  signature is verified by `libp2p-identity` on `ed25519-dalek`. `ring`'s other roles are listed under
  section 3.1. **Providers are passed explicitly (decision).** `libp2p-tls` and `libp2p-quic` build on
  `aws_lc_rs::default_provider()` and `libp2p-websocket` on `ring`, each passing its provider rather
  than using a process default. First-party code builds every rustls configuration with
  `builder_with_provider` and `rustls::crypto::aws_lc_rs::default_provider()` and never calls the
  default builders (`ClientConfig::builder()`, `ServerConfig::builder()`), which, with both providers
  compiled in, panic unless a process default is installed. `net` also installs
  `aws_lc_rs::default_provider()` as the process default at startup, so a dependency that uses the
  default builders gets it; an `Err` from `install_default` (a default already installed) is a
  startup error unless the installed default lists X25519MLKEM768 first, and a test checks the
  installed default.
- **QUIC** through `libp2p-quic` (quinn) with the same rustls configuration; QUIC's three-to-one
  anti-amplification limit stays at its default (TM-22).
- **TCP** through `libp2p-tls` with the same configuration.
- **Noise** `Noise_XX_25519_ChaChaPoly_SHA256` through `libp2p-noise` (the `snow` crate underneath,
  whose cipher and hash come from `ring` on native targets and from the RustCrypto crates on wasm32),
  which is the only pattern libp2p guarantees interoperable, inside WebSocket (locked-down networks),
  WebTransport and WebRTC only, where the libp2p specifications run Noise over the browser-grade
  outer layer because libp2p TLS is not available there. Noise is classical: the plan keeps it where
  a path needs it because the second layer protects content and names regardless. A recorded Noise
  session is readable by a future quantum computer, and what it reveals is what a sealed peer sees;
  `threat-model.md` section 5 states it.
- **Browser paths** (WebTransport with certificate hashes, WebRTC-direct, secure WebSocket to the
  HTTPS listener) use the browser's own TLS and DTLS stacks, which this file does not govern, with the
  libp2p Noise handshake above inside them. Chrome offers X25519MLKEM768, but the outer layer is
  post-quantum only if the native end accepts it: the secure WebSocket listener is `libp2p-websocket`
  on `ring`, so it does not (above), and the native WebTransport and WebRTC-direct stacks are checked
  in the change that adds them. The HTTPS listener's certificate is the user's own or Let's Encrypt
  through `rustls-acme` when turned on. `aws-lc-rs` does not build for wasm32-unknown-unknown, which
  is harmless because the browser build uses no rustls at all.
- **Tor** (phase 7) through Arti: onion-service cryptography is Tor's.

**The libp2p identity key (decision).** The transport authenticates each side's libp2p identity, an
Ed25519 key. It is not the device key, which signs only the DeviceProof, because no key serves two
protocols (TM-11). It is a separate Ed25519 key derived under `licketysync/v1/key/libp2p-identity`
from the device seed, used for nothing but what the libp2p TLS and Noise specifications require
(signing the libp2p extension in the certificate; signing the Noise static key), and it is bound to
the device key by the DeviceProof: the device key's Ed25519 signature over the handshake transcript,
which includes both libp2p identity public keys (32 bytes each, as the Hellos carry them). A verifier
therefore knows that the device whose identity the transport authenticated is the device whose key
signed the proof. `keys.md` defines the derivation and `protocol.md` the proof. The same pattern
gives the Mainline DHT its signing key: `licketysync/v1/key/dht-bep44` derives a third single-purpose
Ed25519 key from the device seed, which signs only the BEP 44 mutable items the device publishes
(phase 2) and, like the identity, is a stable per-device identifier (threat model, section 5).

The identity is one per device, so its peer ID is a stable handle across folders, days and addresses
for anyone the device connects to and anyone who reads its DHT records (threat model, section 5).
**Considered alternative, not adopted (for the plan to record).** A libp2p identity per folder, or one
rotated on a schedule, would remove that handle. Its cost: one connection per shared folder instead
of one per peer, with the matching multiplication of handshakes, NAT traversal and relay
reservations; a rotating identity would also defeat the LAN beacon's "dial expects exactly this
identity" check and any peer that pins an identity. Suite 1 keeps one identity per device and
documents the handle instead.

## 3. Approved crates

These tables are exhaustive for two things: any crate that performs cryptography (a cipher, hash,
KDF, signature, password function, random source or TLS stack) and any crate that encodes secrets for
people to carry (the write key's words, key strings), with `base64`, which encodes the public part of
the same links. No such crate enters first-party code until a
reviewed change adds it here, in `deny.toml` and in `supply-chain/`, with the reason in the changelog.
Ordinary dependencies (`prost`, `tokio`, SQLite bindings and the like) are governed by TM-8, not by
this file. "May be used for" is exhaustive; "may not" names the tempting misuse.

Versions are the range `Cargo.toml` pins (caret ranges within the stated minor); the exact version
checked on 2026-10-14 is in parentheses. A crate the plan names that this table omits (`x25519-dalek`,
`ml-kem`, `ml-dsa`) is never a direct dependency: it is reached, if at all, only through a listed crate
that wraps it.

### 3.1 Cryptography

The audit-status column is what the crate's own documentation says as of 2026-10-14; "none named"
means the crate names no independent audit. Removed on 2026-10-22 (rulings R-K1 and R-K2): `hpke`,
`x-wing`, `ml-kem`, `ml-dsa` and `age`, whose roles (key wrapping, the post-quantum signature half,
the exported root file) no longer exist; the deviation from the plan's "audited crates" that the
unaudited post-quantum crates required goes with them.

| Crate | Pin | Checked | Audit status | May be used for | May not be used for |
| --- | --- | --- | --- | --- | --- |
| `ed25519-dalek` | `3` | 3.0.0, 2026-07-06 | none named | Every signature in suite 1: the folder signing key, the device key, the libp2p identity key and the BEP 44 DHT signing key (section 2.6; the last signs only BEP 44 mutable items, phase 2): `SigningKey::from_bytes` on a derived seed; `verify_strict`; the canonical-encoding and small-order checks on a decoded public key | `verify` (non-strict); `hazmat`, `legacy_compatibility`, `pkcs8`; signing anything a label does not name |
| `libp2p-identity` | with `libp2p` `0.57` | 0.3.0, 2026-09-11 | none named; its Ed25519 is `ed25519-dalek` | The libp2p identity key of section 2.6 with the `ed25519` feature only: an `ed25519::SecretKey` from the derived 32-byte seed, its `Keypair` and `PeerId` | Its `secp256k1`, `ecdsa` and `rsa` features; generating an identity from randomness instead of the derived seed; signing anything the libp2p TLS and Noise specifications do not |
| `chacha20poly1305` | `0.11` | 0.11.0, 2026-06-28 | NCC Group 2020, no significant findings | `XChaCha20Poly1305` as section 2.3 | `ChaCha20Poly1305` (96-bit nonce) directly; the stream cipher without the MAC |
| `blake3` | `1` | 1.8.7, 2026-08-20 | none named; the designers' reference implementation | The labelled hash `H`, `keyed_hash`, `derive_key` under a registered label; `Hasher` for streaming; `rayon` feature for large files | Extendable output; as a password hash; as a MAC without the keyed mode; plain `hash` without a label |
| `argon2` | `0.6` | 0.6.0, 2026-08-27 | none named | Argon2id with the parameters of section 2.5, `zeroize` feature; from phase 1, with the key store | Argon2i or Argon2d; the crate's defaults; the `password-hash` PHC API as a verifier |
| `zeroize` | `1` | 1.9.1, 2026-10-06 | none named; small, widely reviewed | Every secret type: `Zeroize`, `ZeroizeOnDrop`, `Zeroizing<T>`, the `derive` feature | — |
| `subtle` | `2` | 2.6.1, 2024-06-24 | none named; small, widely reviewed | Constant-time comparison of secrets and tags: `ConstantTimeEq`, `Choice`, `CtOption` | — |
| `rustls` | `0.23` | 0.23.46, 2026-10-14 | Cure53 2020 | TLS 1.3 for QUIC and TCP as section 2.6, through `libp2p-tls` and `libp2p-quic`: `aws-lc-rs` provider, `prefer-post-quantum`; first-party configurations only through `builder_with_provider` with `aws_lc_rs::default_provider()`; `net` installs that provider as the process default at startup; the `ring` provider only as `libp2p-websocket` ships it | TLS 1.2; the default builders in first-party code; the `ring` provider in first-party code or as the installed default; its HPKE module |
| `aws-lc-rs` | `1` | 1.18.2, 2026-10-12 | AWS-LC's FIPS build is FIPS 140-3 validated | rustls's crypto provider only | Direct calls to any primitive |
| `libp2p-tls`, `libp2p-quic`, `libp2p-noise` | with `libp2p` `0.57` | 0.7.0, 0.14.0, 0.47.0, 2026-09-11 | none named | The transports of section 2.6 | Noise patterns other than XX; Noise on QUIC or TCP; TLS inside WebSocket, WebTransport or WebRTC |
| `libp2p-websocket` | with `libp2p` `0.57` | 0.46.0, read 2026-10-17 | none named | The WebSocket transport of section 2.6, its outer TLS classical as shipped (rustls on `ring`) | Any claim that its outer TLS is post-quantum until the phase 2 change lands; the linked-device channel |

Transitive dependencies these crates pull in, among them `curve25519-dalek`, `sha2`, `p256`, `snow`,
`ring`, `rcgen`, `webpki`, `quinn`, `chacha20`, `poly1305`, `aead`, and `rand` beneath the `libp2p-*`
crates and `quinn` (the list is illustrative; the tree decides), are allowed as dependencies of the
listed crates only; first-party code never names them in `Cargo.toml` or `use`s them. The rule
governs what a build ships, so a path to a cryptography crate that runs only through
dev-dependencies is outside it: for example `chacha20`, which `proptest`, the property-test tool,
depends on for its test generator. The check is
`cargo tree --workspace --all-features --target all -e no-dev -i <crate>`, which leaves
dev-dependencies out and keeps build-dependencies in, since those run at build time, and must show
every path to the crate running through a listed crate; a crate that only test tooling reaches is in
no production build. `deny.toml`'s ban entries with `wrappers` make cargo-deny enforce this for the
crates on the graph today, and a change that adds another adds its entry. Because cargo-deny's graph
includes dev-dependencies, an entry for a crate that test tooling also reaches lists that tool among
its wrappers (`proptest` for `chacha20`), and a second configuration, `deny-production.toml`, with
`[graph] exclude-dev = true` and the same entry without the tool, which `gate.sh` and CI also run,
keeps the test-only path out of production builds, as the `cargo tree` check does **(decision)**.
`ring` has five roles, all beneath listed crates: in `libp2p-tls`, verifying the certificate's
self-signature and the TLS 1.3 CertificateVerify signature; in `rcgen`, generating that certificate;
in `snow` via `libp2p-noise`, the Noise cipher and hash on native targets; in `quinn-proto` through
its `ring` feature via `libp2p-quic`, QUIC's stateless-reset HMAC and its token key; and in
`libp2p-websocket`, the whole outer TLS (rustls's `ring` provider, which also turns on `webpki`'s
`ring` feature). The exact wrappers of `ring`'s `deny.toml` entry are fixed in the change that adds
`net`, from `cargo tree -e no-dev -i ring` **(decision; `deny.toml` today bans `openssl`,
`openssl-sys`, `md5`, `sha1`, `rust-crypto`, `pkcs8`, `der` and `spki` outright, bans `ring` outright
until the change that adds `net` gives it wrappers, and restricts the crates `keys` uses, and the
primitives beneath them, to listed wrappers; it has no entries for `hpke`, `ml-dsa`, `x-wing`,
`ml-kem` or `x25519-dalek`, which no crate depends on)**. Expect `multiple-versions`
warnings, which `deny.toml` sets to `warn`, wherever two listed crates require different lines of a
shared dependency; each is read when it appears.

### 3.2 Encodings and non-cryptographic helpers

| Crate | Pin | Checked | May be used for | May not be used for |
| --- | --- | --- | --- | --- |
| `bip39` | `3` | 3.0.0, 2026-09-17 (rust-bitcoin/rust-bip39) | Encoding the 32-byte write secret as 24 English words with its checksum, and decoding and checksum-verifying the words back to the 32 bytes (`keys.md`, the write key as words); `zeroize` feature. Its SHA-256 checksum (via `bitcoin_hashes`) is allowed inside this crate only | Its seed function (PBKDF2); languages other than English; passphrase-extended mnemonics; any secret other than a write secret |
| `bech32` | `0.12` | 0.12.0, 2024-10-27 (rust-bitcoin/rust-bech32), read 2026-10-22 | Bech32m (BIP-350) encoding and checksum-verifying decoding of key strings and link codes with the `lsw`, `lsr`, `lss` and `lsl` prefixes (`keys.md`, key strings) | Bech32 (non-m); the error-correction API (`primitives::correction`): a damaged key string is refused, never repaired; anything that is not a key string or link code |
| `base64` | `0.23` | 0.23.1 (marshallpierce/rust-base64), read 2026-10-22 | The certificate hash in a link's `c` parameter, as base64url without padding (`URL_SAFE_NO_PAD`; `keys.md`, link form), with default features off and `alloc` only, so none of the SIMD engines and their unsafe code | Any secret: keys travel only as key strings and words; the `simd-unsafe` engines |
| `getrandom` | `0.4` | 0.4.3, 2026-06-17 | The operating system's generator: `getrandom::fill`, whose failure stops the process (`std::process::exit` with a distinct exit code in the daemon's handler, section 4.3), never `abort()`, whose SIGABRT can write a core dump holding keys, never a panic and never a weaker source; the `wasm_js` feature enabled by the browser binary crate only | Any user-space generator; `rand_core::UnwrapErr` (it panics); `std::process::abort()` on a failure |
| `rand_core` | `0.10` | 0.10.x, the line the listed crypto crates require | The `CryptoRng` and `TryCryptoRng` traits where a listed crate's API asks for a generator, always backed by `getrandom` | Seeding anything from any other source |

`rand` is not on the list: no first-party crate names or uses it. It appears in the dependency tree
only beneath listed crates (the `libp2p-*` crates, `quinn`), where section 3.1's transitive-wrapper
rule names it, and beneath test tooling such as `proptest`, a dev-only path that rule leaves outside.
The simulator's reproducible randomness comes from its own seeded statistical generator, SplitMix64
in the `sim` crate, which feeds the runtime's randomness trait in simulator runs only and is not
cryptography; TM-5 permits exactly that generator and nothing else written here (section 4.3).

**The write key's words (decision).** The words encode 256 bits of entropy per BIP39: 24 words from
the English word list, the last 8 bits a checksum. The write secret is that entropy itself, the 32
bytes the words encode, and nothing else (`keys.md`, the write key as words). BIP39's PBKDF2 seed
function, and its optional passphrase, are not used: the write secret is a uniformly random 256-bit
secret and needs no stretching, and tying derivation to BIP39's seed function would import PBKDF2 and
HMAC-SHA512 for no gain. Entry is case-insensitive and whitespace-separated, accepts a unique prefix
of four letters or more for any word, and refuses, in this order: a count other than 24, naming the
count; a token that is neither a word nor such a prefix, naming its position; a failed checksum,
naming no position. Nothing is ever corrected (`keys.md`, the write key as words). A later suite
defines its own word form. The word list is the BIP39 English list, which the crate
embeds and whose hash a test pins. The drafts used the same encoding for the owner's recovery phrase,
which is gone.

## 4. Secret handling

### 4.1 Zeroization

Every secret (write secrets, data keys, access keys and every key derived from them, signing keys,
device seeds, store keys, link secrets, session keys, passphrases, the local API token, and the
decoded parts of key strings and words) lives in a type that implements `ZeroizeOnDrop`, either a
newtype over `Zeroizing<[u8; 32]>` or a struct deriving `Zeroize, ZeroizeOnDrop`. Rules:

- The type's `Debug` prints the type name and `[redacted]`; it has no `Display`.
- It implements no `Serialize`; export paths (TM-39) are explicit functions that return a
  `Zeroizing` buffer.
- It is `Clone` only if a caller needs two copies, and never `Copy`.
- Intermediate buffers that held secret bytes (`Vec<u8>`, arrays, `String`s of words or of a key
  string) are `Zeroizing` too; a secret never passes through a plain `String` or `format!`.
- A secret is never a `HashMap` key, never indexed by, and never compared with `==` (section 4.2).
- Secrets are never logged, never placed in error values, never in panic payloads. An error value
  may carry the folder ID or device ID, which grant no access, and never the material; a folder ID
  does let its holder confirm and track the folder, so logs, where errors end up, redact it by
  default (`threat-model.md` TM-6).
- Memory locking (`mlock`) and swap are the operating system's concern and are not promised.

### 4.2 Constant-time comparison

Any comparison in which one side is secret or derived from a secret (keys, seeds, tokens,
passphrase-derived keys, AEAD outputs compared by hand, the local API token) uses `subtle::ConstantTimeEq::ct_eq` and branches on the resulting `Choice` through
`subtle`'s API; `==`, `assert_eq!` and `cmp` on such values do not appear outside tests. AEAD tags
and signatures are verified by their crates, which do this internally; first-party code never
reimplements tag or signature comparison. Comparisons of public values (hashes of public data, IDs,
lengths, cursor digests) may use `==`.

### 4.3 Randomness

Every random value first-party code draws in a production build (write secrets, device seeds, link
secrets, nonces, salts, tokens) comes from the operating system's generator through
`getrandom::fill`, or through a `rand_core::CryptoRng` that is itself backed by `getrandom` where a
listed crate's API requires one. First-party code writes no user-space PRNG for production, seeds
nothing from time, PIDs or addresses, and caches no random bytes for later; what listed crates do
internally is theirs. Every generator first-party code hands to the engine or to a listed crate is
infallible, the runtime's `Randomness::fill_random` included; the daemon's `getrandom`-backed
implementation is the one place a failure is handled, and it stops the process with
`std::process::exit` and a distinct exit code, never a panic and never `std::process::abort()`, whose
SIGABRT can write a core dump holding keys (TM-6); the daemon also switches core dumps off at startup
(a phase 1 item); and nothing ever falls back to a weaker source; the operating system is out of
scope (`threat-model.md` section 3.12) **(decision 2026-10-17)**. The browser build enables the
`wasm_js` feature in the binary crate only, so a library crate never decides the backend. The engine
draws randomness through its runtime trait; in a simulator run that trait is backed by the
simulator's own seeded statistical generator, SplitMix64 in the `sim` crate, so that a failure
replays exactly, and secrets, nonces and salts in such a run come from it. It is not cryptography
and it is the one generator TM-5 permits to be written in this workspace: `sim` is never a
dependency of `daemon`, `cli` or `decrypt` (reviewed on every `Cargo.toml` change), so no production
build contains it.

### 4.4 Test vectors

Every primitive and every derivation has a test vector in the crate that implements it, committed
under `crates/<crate>/tests/vectors/`, and the test fails if the output changes by one bit:

- Primitives: Ed25519 (RFC 8032 section 7.1 vectors); XChaCha20-Poly1305
  (draft-irtf-cfrg-xchacha-03 Appendix A vectors); BLAKE3 (the official test vector file, all three
  modes); BIP39 (the Trezor reference vectors, English, the 256-bit entries); and Argon2id (RFC 9106
  section 5.3) in the phase 1 change that adds the key store, which is when the keys crate gains it.
- Derivations: for every `derive_key` label in `keys.md`'s registry (section 2.4's table), a fixed
  32-byte input and the expected 32-byte output, generated once and committed, so that a changed
  label, a changed order of derivation or a changed parent fails a test with the label's name in the
  test name. Labels of the other modes are covered by the vectors of what they compute (identifiers,
  digests, the transcript, signatures), which `keys.md` and `protocol.md` list.
- Encodings: a public key and a signature over a fixed message under a fixed seed, each as bytes;
  the three key strings and the 24 words for a fixed write secret (`keys.md`, test vectors).
- Determinism: one body signed twice through the production signing path gives the same signature,
  so a vector that changes signs a different body or uses a different key.

Vectors are data files, not constants in code, so a reviewer can diff them, and the test that reads
them is named after the primitive or label (`fn vector_derive_key_folder_data_key()`).

## 5. Suite 2 (placeholder)

Suite 2 does not exist. It will when post-quantum signatures are added (the owner's answer of
2026-10-22: suite agility may add them in a later version), when a flaw is found in Ed25519,
XChaCha20-Poly1305 or BLAKE3, or when a preference for AES-256-GCM on hardware with AES instructions
is judged worth a second cipher. A folder never moves between suites: a folder under suite 2 is a new
folder, made by unlinking and sharing again (`keys.md`, making, unlinking and sharing again). Suite 2
would use the label prefix `licketysync/v2/` and, if its write secret is not 32 bytes, a word form of
its own. Nothing about it is specified here, deliberately: a suite is a whole set and is written down
whole.

## Appendix: what was checked on 2026-10-14

Versions and statements above come from docs.rs and the crates' READMEs as read on 2026-10-14;
rustls's post-quantum notes from its manual's defaults page; the `libp2p-tls` 0.7.0 facts (rustls
with the `aws-lc-rs` and `prefer-post-quantum` features, configurations built on
`aws_lc_rs::default_provider()`, a test that X25519MLKEM768 is preferred, the cipher-suite list
ChaCha20-Poly1305 then AES-256-GCM then AES-128-GCM, `ring` used to verify the certificate
self-signature) from its manifest and source; `ring`'s other roles (snow's resolver in
`libp2p-noise` on native targets, the stateless-reset HMAC and token key in `libp2p-quic`'s
`quinn-proto`, and `libp2p-websocket` enabling rustls's `ring` provider feature) from those crates'
manifests and source; that `libp2p-websocket` 0.46.0 builds its outer TLS on the `ring` provider with
no way to pass another, that `libp2p-tls` passes `aws-lc-rs` explicitly, and that `ring` also
verifies the CertificateVerify signature in `libp2p-tls`, from the round-4 security review of
2026-10-17. The rewrite of 2026-10-22 removed X-Wing, HPKE, ML-DSA-65 and age; it read `bech32`
0.12.0 (its changelog: the release adds the error-correction API this file bars) and `base64` 0.23.1
(its release notes: SIMD engines behind the default `simd-unsafe` feature, which stays off) from the
crates as published.
The crate pins are to be confirmed against `cargo search` when the first of these dependencies is
added to `Cargo.toml`, in the change that adds it.
