# Lickety-Sync keys

Status: draft for phase 0, rewritten 2026-10-22 for the shared-key model the owner chose on
2026-10-18 (plan, Decisions: "Key model simplified"), the owner's answers of 2026-10-22 and the
coordinator's rulings R-K1 to R-K6 and S-1 to S-4 of the same day. This file is what
`licketysync-keys` implements and what reviewers check it against. The plan ("Lickety-Sync: Project
Plan") is the design; where this file and the plan disagree, raise it. `suites.md` fixes the
algorithms and their crates; `threat-model.md` names the adversaries; `protocol.md` puts these keys
and records on the wire. **Issues** is the list of problems a device shows its person (the plan's
Issues panel): every failure this file and `protocol.md` name raises one that states its cause, so
nothing is dropped without trace.

Each section says in plain words what the thing is for, then defines it exactly. Anything marked
"phase N" is not needed for phase 0 ("simulated peers converge") and may be left unimplemented, but
its format is fixed now.

**What this file no longer has.** The drafts of 2026-10-14 to 2026-10-18 described an issued-keys
model. Removed on 2026-10-22, with nothing in its place unless this file says so: the owner (root)
key and its 24-word recovery phrase, the master secret, the identity key and its catalogue key,
issued, per-person and child keys, key IDs, grants and their chains, `may_share`, expiry and
renewal, revocation, suspension, lift, rotation, epochs of data keys and their ladder, wrapping a
data key to a public key (X-Wing through HPKE), the key-record quotas and refusal memory, per-key
device admission, fork evidence, hybrid ML-DSA signatures, the exported root file, the Folder record
(ruling S-2), separate handshake proofs per tier (ruling S-1) and version vectors (ruling R-K6). The
drafts never shipped, so their field numbers, record types and labels carry no compatibility duty:
where this file still marks one `reserved` or "never used", that is only a reading aid, and
`suites.md`'s rule that a label is never reused applies from the first release on.

**Section map.** Section numbers do not follow the drafts. Where each of the drafts' sections went:

| Drafts | Now |
| --- | --- |
| 0 Notation; 0.1 sizes; 0.2 hybrid signatures; 0.3 key pair sets; 0.4 identity hashes | 0; 0.1; 0.2 Ed25519 signatures; removed; 0.3 |
| 1 Derivation tree: 1.1 phrase and master secret, 1.2 from the master secret, 1.3 device keys, 1.4 issued keys | 1 Folder keys (new); removed; removed; 8.1; removed |
| 2 Folder identity: 2.1 folder ID and root key ID, 2.2 Folder record, 2.3 discovery hashes | 2: 2.1 folder ID; removed; 2.2 |
| 3 Data key and epochs: 3.1 definitions, 3.2 keys from a data key, 3.3 chunks, 3.4 Padmé | 3 Data encryption: removed; 3.1; 3.2; 3.3; and 3.4 sealed metadata (new) |
| 4 Issued keys: 4.1 tiers, 4.2 flags, expiry and fresh keys | 4 Handshake proofs (new); tiers in 1.3; removed |
| 5 Grant record and canonical encoding: 5.1 envelope, 5.2 encoding, 5.3 to 5.5 grants | 5 Signed records: 5.1; 5.2; 5.3 index records (new) |
| 6 Key string: 6.1 Bech32m, 6.2 link, 6.3 file | 6: 6.1; 6.3; 6.4; and 6.2 words (new) |
| 7 Rotation, revocation, suspension and lift | 7 Making, unlinking and sharing again (new) |
| 8 Linked devices and root holders: 8.1 linking, 8.2 exported root file, 8.3 paper form, 8.4 where secrets rest | 8 Keys on a device: 8.3; removed; removed (the words are 6.2); 8.4; and 8.1 device keys, 8.2 key store (new) |
| 9 Test vectors; 10 Label registry; 11 Phase map | 9; 10; 11 |

## 0. Notation and constants

- `a || b` is concatenation. `be16(n)`, `be32(n)`, `be64(n)` are unsigned big-endian integers of
  that width, `u8(n)` one byte. `x[0..n]` is the first `n` bytes of `x`.
- `BLAKE3(x)` is the plain 32-byte BLAKE3 hash. `H(label, x) = BLAKE3(label || 0x00 || x)` is the
  **labelled hash**, used for every identifier over public data. `BLAKE3_keyed(k, x)` is BLAKE3 in
  keyed mode with the 32-byte key `k`, which is always a key derived for that one use, so its input
  carries no label. `derive_key(label, material)` is BLAKE3 in derive-key mode: `label` is the
  context string, `material` uniformly random key material, output 32 bytes. Every label has the
  form `licketysync/v1/<area>/<purpose>` (`suites.md` §2.4) and is listed in the registry in section
  10. No key is ever used raw for two purposes: a key that serves several uses is the parent of one
  derived key per use.
- `XChaCha(k, n, aad, pt)` is XChaCha20-Poly1305 with a 32-byte key `k`, a 24-byte nonce `n`,
  associated data `aad`, returning ciphertext with the 16-byte tag appended.
- `Sign(sk, label, body)` and `Verify(pk, label, body, sig)` are defined in section 0.2.
- A **suite** number is a 16-bit integer, 1 to 65 535 (`suites.md` §1); Protocol Buffers carries
  it as `uint32`, and a value outside that range is malformed. A folder's suite is the suite of its
  keys, fixed when the folder is made (§1.1); nothing moves a folder to another suite (§7).
- A **tier** is one byte: `1` write, `2` read, `3` sealed. Lower numbers can do more.
- No key and no record in this file expires, and no verifier compares any field in it with a
  clock: every time field is informational.
- Randomness (secrets, nonces, salts) reaches the keys crate from the caller through **the
  runtime's randomness trait**: backed by the operating system's generator in production, by a
  seeded generator in the simulator so that a run replays exactly (`suites.md` §4.3).

### 0.1 Suite 1 sizes

Suite 1 is the whole set in `suites.md`: Ed25519 signatures, XChaCha20-Poly1305 for data, BLAKE3
for hashing and key derivation, and Argon2id for passphrases (phase 1, the local key store, §8.2).
Sizes the keys crate checks on every parse:

| Item | Bytes |
| --- | --- |
| Ed25519 public key / signature / seed | 32 / 64 / 32 |
| Write secret, data key, access key and every key derived from them | 32 |
| Folder ID, device ID, record hash, ciphertext hash | 32 |
| Device public key as Hello carries it, `be16(suite) \|\| ed25519_pk` | 34 |
| Sealed part of an index record (§3.4) | 40 to 1 572 864 |
| Key string payload: write / read / sealed (§6.1) | 34 / 66 / 66 |
| Key string: write / read / sealed (§6.1) | 65 / 116 / 116 characters |
| Write key as words (§6.2) | 24 words |

A key string that names a suite this release does not implement is refused with "this key needs a
newer release of Lickety-Sync" (§6.1); the suite is judged before the payload's length, since a later
suite's payloads may have other lengths, so the sizes above apply to suite 1 only. A record whose
`suite` is not its folder's suite is
malformed (`protocol.md` §5), since the folder's key exists under one suite only.

### 0.2 Signatures

Every signature in Lickety-Sync is pure Ed25519 (RFC 8032: no prehash, no context string) over the
body prefixed with a label, so a signature made for one purpose can never be presented for another
(`suites.md` §2.2):

```
M = label || 0x00 || body                          # label = licketysync/v1/sig/<type>, ASCII
Sign(sk, label, body)        = Ed25519.Sign(sk, M)                          # 64 bytes
Verify(pk, label, body, sig) = len(sig) == 64 AND Ed25519.VerifyStrict(pk, M, sig)
```

There are two labels: `sig/index` for index records (§5) and `sig/device-proof` for the DeviceProof
(`protocol.md` §3.4). Ed25519 signing is deterministic: the same key and body always give the same
signature, so test vectors reproduce through the production signing path and need no test-only
signing mode. Verification is always `verify_strict`, which rejects small-order and non-canonical
components, and every public key is checked as section 0.3 says before it is used.

Deviation from the drafts (ruling R-K1, after owner answer 1 of 2026-10-22, "Ed25519 alone"): there
is no ML-DSA and no hybrid signature anywhere, neither on records nor in the handshake. A later
suite may add post-quantum signatures (`suites.md` §5); what holds until then is
`threat-model.md` TM-33.

### 0.3 Identity hashes and canonical keys

```
folder_id = H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)    # 32 bytes, §2.1
device_id = H("licketysync/v1/hash/id/device", be16(suite) || device_pk)    # 32 bytes, §8.1
```

`folder_vk` is the folder's Ed25519 verification key (§1.2) and `device_pk` a device's Ed25519
public key (§8.1). The two kinds use two labels, so that a device key presented as a folder key, or
the reverse, can never produce a matching ID. Hashes of other public data (records, chunks,
discovery, the transcript, cursor digests) use `H` under their own `licketysync/v1/hash/<purpose>`
labels.

**Canonical keys.** A verification key or device public key received from anywhere (a key string,
§6.1; a Hello, `protocol.md` §3.2) must be the canonical encoding of an Ed25519 point: decoding it
and encoding the point again gives back the same 32 bytes. It must also not be of small order. Any
other is malformed. One key therefore has exactly one encoding and one ID. A key a device derives
itself is canonical by construction.

## 1. Folder keys

A folder is its write secret. Everything else derives from it in one direction only, so each tier's
key holds exactly what that tier may do, and any holder can hand out its own tier or a lower one
without asking anyone, as in Resilio Sync (plan, Folder keys). There is no owner, no per-person key
and no record of who holds which key: holding a key is the access.

### 1.1 The write secret

- A device creates a folder (§7.1) by drawing 32 bytes through the runtime's randomness trait: the
  **write secret** `ws`. The folder's suite is the suite this release creates folders under
  (suite 1); it is carried in every key string of the folder (§6.1) and hashed into its folder ID
  (§0.3).
- `ws` is the write key. It is never derived from anything, and it leaves a device only as the
  write key string or words (§6) or over a linked-device channel (§8.3), each time only after the
  operating system's own user authentication (§6).

### 1.2 Derivation tree

```
ws: the write secret, 32 random bytes
├── folder signing seed = derive_key("licketysync/v1/folder/signing-key", ws)
│     → the folder's Ed25519 key pair (folder_sk, folder_vk)
│     → folder_id = H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)          §0.3
└── data key dk = derive_key("licketysync/v1/folder/data-key", ws)
      ├── access key      ak  = derive_key("licketysync/v1/data/access-key", dk)        the sealed key's secret
      │     ├── hint key    = derive_key("licketysync/v1/handshake/hint-key", ak)       folder hints, §4
      │     └── payload key = derive_key("licketysync/v1/handshake/payload-key", ak)    folder-proof keys, §4
      ├── chunk key       ck  = derive_key("licketysync/v1/data/chunk-key", dk)         chunk ciphertext, §3.2
      ├── chunk nonce key nk  = derive_key("licketysync/v1/data/chunk-nonce-key", dk)   convergent chunk nonces, §3.2
      ├── chunk hash key  hk  = derive_key("licketysync/v1/data/chunk-hash-key", dk)    plaintext chunk hashes, §3.2
      └── record key      rk  = derive_key("licketysync/v1/data/record-key", dk)        sealed metadata, §3.4
```

Every derived key is 32 bytes and nothing below a node yields the node: `ak` does not give `dk`,
`dk` does not give `ws` or `folder_sk`, and `folder_vk` gives nothing secret. Names and folder
structure have no key of their own: paths exist only inside an index record's sealed metadata, so
`rk` is the key for names as well as for the rest of the metadata (decision). The keys last as long
as the folder. There are no epochs: a folder that needs new keys is a new folder (§7).

### 1.3 The three keys

| Tier | Byte | The key holds | Its holder can | Its holder cannot |
| --- | --- | --- | --- | --- |
| Write | 1 | `ws` | Derive every key in §1.2; sign index records; verify, decrypt, change and delete anything; give out any tier | — |
| Read | 2 | `folder_vk`, `dk` | Verify every record; decrypt contents, names and structure; derive `ak` and every key under `dk`; give out read or sealed | Sign: every peer rejects a change it makes, and its own edits are never sent (what the engine shows for them is phase 1's design) |
| Sealed | 3 | `folder_vk`, `ak` | Verify every record and every chunk against the hashes the signed records name; store, serve and relay ciphertext; give out sealed | Decrypt anything, test whether the folder holds a known file (TM-14), sign |

Read and sealed keys both carry `folder_vk`, so every holder verifies every update and computes the
folder ID. The two halves of a read or sealed key are not bound to each other by the key itself: a
key made by hand from halves of two different folders computes handshake hints that match no
peer's, because the hint covers the folder ID (§4), and so opens nothing anywhere.

A holder derives the lower keys from its own: the app shows a write holder all three key strings
and a read holder the read and sealed ones. **Lowering** a device means the device replaces its
stored key with a lower one; nothing lets one device lower another. **Raising** a device means
giving it a higher key; a device raised from sealed simply decrypts the ciphertext it already
holds, since the data key is the folder's for its whole life.

An **invite** is one of the three key strings sent as a link, a QR code or a file (§6). It is not a
separate kind: it has no expiry, no use count and no approval step, and any number of devices may
join with it (plan, Folder keys).

## 2. Folder identity

The folder ID names the folder on the wire once a folder is open, and in discovery only through
salted or dated hashes of it. Every holder of any key derives it; the sync protocol sends it only on
a connection where the folder is open, so only to peers that have proven a key to it.

### 2.1 Folder ID

```
folder_id = H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)    # 32 bytes, §0.3
```

Every protocol message after a folder has opened names it by this ID (`protocol.md` §3.5). The ID is
known to every key holder at every tier and to every relay the folder uses. It grants no access,
but it lets its holder confirm the folder's presence on a LAN and compute its DHT announcements
(§2.2), and so track it; logs therefore redact it by default (`threat-model.md` TM-6), and error
values may carry it because they are not logs (`suites.md` §4.1).

There is no folder-wide signed record. The drafts' Folder record, and the revision and required
features it last carried, are gone for now (ruling S-2): every reader decodes every format code its
release implements (§3.2), and features are negotiated per connection in the Hello
(`protocol.md` §5). A folder-level requirement, if one is ever needed, is a later phase's design.

### 2.2 Discovery hashes

Two different constructions, because the LAN can carry a fresh salt in every beacon and the DHT
cannot. Unchanged from the drafts but for the section that defines the device keys (now §8.1).

**LAN beacon (phase 1).** Every beacon carries a fresh random 16-byte `salt`, the announcer's **peer
tag** `peer_tag = H("licketysync/v1/hash/discovery-peer", salt || peer)[0..16]` where `peer` is its
32-byte libp2p identity key (§8.1), the current Unix minute `minute = floor(unix_seconds / 60)`, a
port, and per announced folder
`lan_id = H("licketysync/v1/hash/discovery-lan", salt || folder_id || peer_tag || be64(minute))[0..16]`.
A listener drops a beacon whose `minute` is more than 5 off its own clock (devices without a
real-time clock drift; ±5 minutes is the window), and raises the issue "clock differs from LAN
peers" when every beacon it has heard from one source address over the last window is outside it.
For a beacon in the window it computes `lan_id` for the salt and each folder it holds and on a match
dials the beacon's source address; once the transport has authenticated the peer's identity `p`
(`protocol.md` §3.1) the dialer checks `H("licketysync/v1/hash/discovery-peer", salt || p)[0..16] = peer_tag`
and drops the connection before sending Hello otherwise, so a beacon replayed from another address
cannot steer the dial to a different device. The beacon carries no identity in the clear: an
observer without the folder ID learns nothing and cannot link two beacons, even seconds apart, to
one folder or one device (libp2p's own mDNS would put the peer ID in every announcement, which is
why Lickety-Sync uses its own beacon). An observer who knows the folder ID can confirm it is present
on this LAN; and anyone can replay a fresh beacon from another address and learn, from the dial that
follows, that the dialer holds the folder: the dial is the signal, and that residual leak is the
one the plan accepts ("What stays visible"). Listeners rate-limit beacons per source address.
Beacons never carry the folder ID or key material.

**Mainline DHT (phase 2).** `day = floor(unix_seconds / 86400)` and
`dht_id(day) = H("licketysync/v1/hash/discovery-dht", folder_id || be64(day))[0..20]`. A device
announces under `dht_id(today)` and looks up `dht_id(today - 1)`, `dht_id(today)` and
`dht_id(today + 1)`, which covers clock disagreement of up to a day. The address record it announces
is a BEP 44 mutable item signed by the device's DHT key (§8.1) and carries addresses only, never the
libp2p peer ID, so the separate DHT key buys real unlinkability: a crawler ties announcements to a
DHT key, not to the identity the transport will authenticate; how the item is placed under `dht_id`
is phase 2's design. Announcements cannot be linked across days without the folder ID, except
through the stable DHT key itself (§8.1).

## 3. Data encryption

Contents, names and folder structure are encrypted under keys derived from the folder's data key
before they leave a device, so sealed peers, relays and the network see ciphertext only (plan,
Encrypted connections: "Second layer"). The data key is the folder's for its whole life.

### 3.1 Keys derived from the data key

| Key | Definition | Used for |
| --- | --- | --- |
| Access key | `ak = derive_key("licketysync/v1/data/access-key", dk)` | The sealed key's secret; parent of the handshake's hint key and payload key (§4), and used for nothing else |
| Chunk key | `ck = derive_key("licketysync/v1/data/chunk-key", dk)` | XChaCha key for chunk ciphertext (§3.2) |
| Chunk nonce key | `nk = derive_key("licketysync/v1/data/chunk-nonce-key", dk)` | Keyed BLAKE3 for convergent chunk nonces (§3.2) |
| Chunk hash key | `hk = derive_key("licketysync/v1/data/chunk-hash-key", dk)` | Keyed BLAKE3 over plaintext chunks (§3.2) |
| Record key | `rk = derive_key("licketysync/v1/data/record-key", dk)` | XChaCha key for the sealed metadata of index records (§3.4) |

### 3.2 Chunk encryption

The engine splits a file with FastCDC; this section fixes what one chunk becomes. The protocol
constant `MAX_CHUNK_PLAINTEXT` is 4 MiB (4 194 304 bytes) of raw content; the engine's FastCDC
maximum must not exceed it.

```
raw            : the chunk's bytes (1 ..= MAX_CHUNK_PLAINTEXT)
plain_hash     = BLAKE3_keyed(hk, raw)                           # 32 bytes; the key-holder-side reference
payload        = compress(compression, raw)                      # compression 0 = none (phase 0: always 0)
header         = u8(compression) || be32(len(payload))
L              = len(header || payload)
L'             = padme(L)                                        # §3.3
plaintext      = header || payload || zeros(L' - L)
nonce          = BLAKE3_keyed(nk, plaintext)[0..24]
ct             = XChaCha(ck, nonce, folder_id, plaintext)        # aad = the 32-byte folder ID
stored         = nonce || ct                                     # L' + 40 bytes
cipher_hash    = H("licketysync/v1/hash/chunk", stored)          # 32 bytes; what sealed peers and relays see
```

- Encryption is **deterministic** for the folder and the plaintext, so identical chunks give
  identical `stored` bytes and sealed peers can deduplicate and verify by `cipher_hash`. The nonce
  is a keyed hash of the exact padded plaintext, never of the raw content alone, so two different
  plaintexts never share a nonce under one key, and the associated data is a function of the key
  alone (`suites.md` §2.3).
- Writer rules: `1 ≤ len(raw) ≤ MAX_CHUNK_PLAINTEXT`; with compression `0`, `payload = raw`; with
  any other code the writer falls back to `0` when the compressed form is not shorter, so
  `len(payload) ≤ len(raw)` always.
- Decryption, in order: `46 ≤ stored_len ≤ 4 325 416` and `stored_len - 40 = padme(stored_len - 40)`
  (a stored length that is not a Padmé length is malformed); split the nonce; `XChaCha` open; read
  the header; `1 ≤ len(payload) ≤ L' - 5` and, for compression `0`, `len(payload) ≤ MAX_CHUNK_PLAINTEXT`;
  every padding byte is `0x00`; `compression` is a code this release implements; decompress into a
  buffer of at most `MAX_CHUNK_PLAINTEXT` bytes, stopping at the bound, and require at least one
  byte out; recompute `plain_hash` and compare with the record. Who is blamed for a failure is
  `protocol.md` §4.6's business: when the ciphertext hash matched, the sender delivered what the
  writer stored, so the fault is the writer's.
- **Compression codes**: `0` none, `1` deflate, `2` zstd, `3` lz4; the code sits inside the
  ciphertext because ciphertext itself does not compress. A reader decodes every code its release
  implements and treats any other as a writer fault (ruling S-2). Phase 0 implements and writes `0`
  only. A writer cannot know which releases will read its chunks, so a code other than `0` is
  written only by releases that every supported release of major 1 can read: a decoder added before
  1.0 (when no release has shipped) becomes part of major 1's baseline, and a code added after 1.0
  needs a folder-level requirement first, a later phase's design (decision). Known cost:
  compressing before encrypting makes the padded length depend on the content's compressibility, a
  CRIME-style length channel on top of the size leak Padmé already bounds; the threat model records
  it, and compression stays off by default.
- `hk` is the folder's for its whole life, so plaintext chunk hashes stay stable across renames and
  copies and local deduplication keeps working; only key holders can compute them.

### 3.3 Padmé padding

Padmé (Nikitin et al., PURBs 2019) rounds a length up to a multiple of `2^(E - S)`, where
`E = floor(log2 L)` and `S` is the number of bits in `E`: the low `E - S` bits of the padded length
are zero and only about `log2(log2 L) + 1` bits of it carry information. Overhead is at most 12 %,
3 % on average. It is the one padding scheme in suite 1, written in the keys crate (`suites.md`
§2.3).

```
padme(L):
    if L < 2: return L
    E = floor(log2(L))                  # position of the highest set bit
    S = bit_length(E)                   # bits needed to write E
    last = E - S
    mask = (1 << last) - 1
    return (L + mask) & ~mask
```

Examples the crate's vectors must reproduce: `padme(5) = 5`, `padme(9) = 10`, `padme(100) = 104`,
`padme(1000) = 1024`, `padme(65 537) = 67 584`, `padme(1 048 577) = 1 081 344`.

### 3.4 Sealed metadata

Everything that would name a file (path, kind, true size, times, mode, plaintext chunk hashes) sits
in the sealed part of its index record (`protocol.md` §4.4, `SealedMeta`), which only read and write
holders open.

```
meta   = canonical SealedMeta bytes (§5.2)
plain  = be32(len(meta)) || meta || zeros(padme(len(meta) + 4) - len(meta) - 4)    # Padmé-padded, §3.3
aad    = folder_id || device_id || be64(seq)              # 72 bytes, rebuilt from the record's clear fields
nonce  = 24 bytes through the runtime's randomness trait
sealed = nonce || XChaCha(rk, nonce, aad, plain)          # the record's field 13
```

`len(sealed)` is at least 40 (the nonce and the tag) and at most `MAX_SEALED_BYTES`, 1 572 864
(1.5 MiB); outside that range the record is malformed. The largest metadata `protocol.md` §4.4
allows (a 4 096-byte path and 32 768 plaintext hashes) seals to 1 146 920 bytes, so an honest
writer never reaches the cap; a writer whose sealed part would pass it does not write the record and
raises an issue. A reader opens `sealed` under the aad it rebuilds from the record's own
`folder_id`, `device_id` and `seq`, reads the length, requires `4 + len(meta) ≤ len(plain)` and
every padding byte to be zero, and parses `SealedMeta`. A sealed part therefore cannot be moved to a
record with another folder, device ID or sequence number. Two records of one device at one sequence
number (`protocol.md` §4.4, concurrent versions) share an aad; their random nonces keep their seals
distinct, and moving a seal between them would break the signature over the body that holds it.
Failures after the length check are writer faults (`protocol.md` §4.4 step 6).

## 4. Handshake proofs

At the folder proof (`protocol.md` §3.5) each side shows that it holds a key to the folder, without
sending the key and in a way bound to the one connection. There is one proof for all three tiers
(ruling S-1): possession of the access key `ak`, which every tier holds. The keys and values it
needs are derived here, so that the protocol crate computes none of them itself.

```
hint_key    = derive_key("licketysync/v1/handshake/hint-key", ak)          # once per folder
payload_key = derive_key("licketysync/v1/handshake/payload-key", ak)       # once per folder
hint        = BLAKE3_keyed(hint_key, folder_id || th || u8(role))         # 32 bytes
proof_key   = BLAKE3_keyed(payload_key, folder_id || th)                  # 32 bytes, the XChaCha key of the payload
```

- `th` is the transcript hash (`protocol.md` §3.3), which covers both sides' fresh nonces, and
  `role` is the prover's role byte (`protocol.md` §3.2).
- **The proof.** The prover seals a small payload under `proof_key` with `aad = hint`
  (`protocol.md` §3.5). Only a holder of `ak` derives `proof_key`, so a payload that opens proves
  that its sender holds `ak`; `proof_key` covers `th`, so it cannot be replayed into another
  connection, and the hint, which is the associated data, covers the role, so it cannot be
  reflected back to its sender. The payload names the tier the prover reports; nothing checks it,
  and it is shown marked "reported", like a device name, and never relied on, since nothing in the
  protocol gives a peer more for a higher tier: records and chunks are verified by signature and
  hash whoever sends them, and only a key holder can open what it receives.
- Every tier holds `ak` (write and read holders derive it from `dk`), so every holder computes the
  hints and proof keys of its folders, and nobody without a key can: a relay, or anyone who knows
  only the folder ID, can neither open a proof nor tell which folder one is for. The drafts keyed
  both with the folder ID, which every relay and every person who ever saw a key string knew
  (decision).
- `ak` itself keys nothing: it is only the parent of `hint_key` and `payload_key`, so no key is used
  raw for two purposes (§0).
- The folder ID in the hint and the proof key binds a key's halves (§1.3): a read or sealed key made
  from two folders' halves yields hints no holder of either folder computes.

## 5. Signed records and the canonical encoding

There is one kind of signed record: the index record (`protocol.md` §4.4). It is public within the
folder: every peer, sealed ones included, stores, verifies and forwards it. Everything signed is a
Protocol Buffers body that the signer serialises canonically and that every verifier treats as
opaque bytes: hashed, signed and forwarded exactly as received, never re-encoded. There are no key
records: no key ever travels inside a folder (TM-9).

### 5.1 The signed envelope

```proto
message SignedRecord {
  bytes body      = 1;   // canonical bytes of an index record (protocol.md §4.4)
  bytes signature = 2;   // Sign(folder_sk, "licketysync/v1/sig/index", body); 64 bytes
  reserved 3;            // was key_signature, a grant's proof of possession
}
```

`record_hash = H("licketysync/v1/hash/record", body)`. Two SignedRecords with equal bodies are the
same record, whatever their signatures: a receiver that already holds a record with that hash
ignores the second without verifying it (`protocol.md` §4.4 step 2). A `signature` of any length but
64 is malformed, and so is an encoded `SignedRecord` larger than `MAX_INDEX_RECORD_BYTES` (4 000 000
bytes, `protocol.md` §2), judged at parse, before the duplicate check. Every body begins with the
same three fields, so a parser can read the suite and type before anything else:

```proto
// Common prefix of every body: field numbers 1 to 3 mean this in every record type.
uint32 suite       = 1;   // the folder's suite; any other value is malformed
uint32 record_type = 2;   // 16 Index; every other value is malformed (1 to 8 were the drafts' Folder and key records)
bytes  folder_id   = 3;   // 32 bytes
```

The label is `licketysync/v1/sig/index` for record type 16. A record type a later release adds gets
its own label, so a body can never be presented as another type. Any write holder signs; every
verifier uses the folder's `folder_vk`.

### 5.2 Canonical encoding

Producers emit proto3 wire format under these rules, which prost's encoder follows; the encoding is
deterministic and every variable-length item is length-prefixed:

1. Fields in increasing field-number order, each exactly once.
2. A field whose value is the proto3 default (`0`, `false`, empty bytes or string, empty repeated)
   is omitted entirely.
3. Repeated scalars are packed; repeated messages and bytes appear in the order given and that
   order is part of the record's meaning (chunk lists).
4. Varints are minimal; no unknown fields; nested messages follow the same rules.
5. A list that the specification calls a set (an index record's `supersedes`) is written sorted
   ascending, bytewise, without repeats.

Verifiers never re-encode a body and never require it to be canonical: the bytes received are the
bytes hashed and signed, and unknown fields inside them are stored and forwarded untouched, which is
how a newer peer adds fields an older one never sees. A field number marked `reserved` in this file
or in `protocol.md` is an unknown field to every decoder. A verifier does reject a body it cannot
parse, a field of the wrong length, a value outside its stated range, or a field that is not
repeated occurring more than once; it accepts a repeated scalar field packed or unpacked, or partly
each, concatenating the values in the order they appear, and reads a set in any order, a repeated
entry counting once (`protocol.md` §2).

### 5.3 Index records

An index record's body is `protocol.md` §4.4's. Any write holder signs it with
`Sign(folder_sk, "licketysync/v1/sig/index", body)`; every peer, sealed ones included, verifies it
with `folder_vk`, and nothing in it is charged to anyone until that signature has verified; its
sealed metadata is §3.4's. The `device_id` in a record is the device ID of the device that wrote it
(§8.1), as the signer claims it, and nothing proves it: every write holder signs with the same key.
It is only the key of the sequence the record belongs to, used to sync, and is never shown as the
record's author (ruling S-4). Records of one device at one sequence number are concurrent versions
(`protocol.md` §4.4); nothing in a record says which person made it.

## 6. Key strings, words, QR codes, links and files

What a person hands to another person is one key string, nothing else: the folder ID, the
verification key and every key the tier needs are in it or derive from it. The string is designed
for QR codes and links, not for typing: a camera reads it in one go, and the checksum catches a
damaged scan or a stray edit. The write key can also be written down as words (§6.2).

Showing a write key in any of these forms, or exporting it, requires the operating system's own user
authentication on that device (owner's answer of 2026-10-22; `threat-model.md` TM-39), since it is
full control of the folder: the platform's prompt (the login password, Windows Hello, Touch ID or a
phone's PIN or biometrics, polkit on a Linux desktop), or, on a device that has no such prompt, such
as a headless box, the key store's passphrase (§8.2) (decision). The rule fails closed: the prompt or
the passphrase is asked at that moment, every time; an unlocked key store, a running daemon or a
local process that holds the local API's token does not count, so nothing exports a write key
without the person. A device that has neither such a prompt nor a passphrase-protected key store
refuses to show, export or link a write key until the person sets one of them. A read or sealed key
is shown on the person's explicit action alone, since neither can change anything (decision).

### 6.1 Key strings: Bech32m

```
payload_write  = be16(suite) || ws                     # 34 bytes
payload_read   = be16(suite) || folder_vk || dk        # 66 bytes
payload_sealed = be16(suite) || folder_vk || ak        # 66 bytes
key_string     = Bech32m(hrp, to_5bit(payload))        # BIP-350; hrp "lsw" write, "lsr" read, "lss" sealed
```

- Decision kept from the drafts, with one prefix per tier (ruling R-K3): Bech32m over z-base-32,
  Base58Check and Crockford base32. QR alphanumeric mode packs 45 symbols at 5.5 bits each, so any
  base-32 alphabet written in upper case fits it, while Base58's mixed case forces byte mode. Its
  alphabet omits the confusable `1`, `b`, `i` and `o`, its checksum is a 30-bit BCH code chosen for
  error detection rather than a truncated hash, and its human-readable prefix makes a pasted string
  recognisable and names its tier. z-base-32 has no checksum and Crockford's is one symbol.
- Lengths: a write key is `lsw` (3) + `1` (1) + 55 data characters + 6 checksum = **65 characters**;
  a read or sealed key is 3 + 1 + 106 + 6 = **116 characters**. By the capacity table of ISO/IEC
  18004 (table 7), 65 alphanumeric characters fit a version 3 code at error-correction level L (77)
  or a version 4 at level M (90), and 116 fit a version 5 at level M (122); the app generates
  level M.
- BIP-173 establishes its four-error detection guarantee only for strings up to 89 characters: the
  write key string has it; at 116 the code still detects every single-character error (a polynomial
  code with a non-zero constant term always does) and any other error with probability
  `1 - 2^-30`, which is what a damaged scan or a stray edit needs. Decoders accept up to 116
  characters (the `bech32` crate's 90-character default limit is lifted). A damaged string is
  refused, never repaired: the crate's error-correction API is not used (`suites.md` §3.2).
- Case: entirely lower-case in text and links; entirely upper-case in QR codes (which is what
  alphanumeric mode needs); mixed case is rejected. A QR code carries the upper-case key string and
  nothing else by default.
- Decoding, in this order, the first failure deciding: (1) the Bech32m string: a prefix other than
  the three, a bad checksum, a Bech32 (non-m) checksum, mixed case or a non-zero padding bit is
  malformed; (2) a payload shorter than 2 bytes is malformed; (3) the suite, `be16` of the first two
  bytes: suite 0 is malformed, and a suite this release does not implement is refused with "this
  key needs a newer release of Lickety-Sync", whatever the payload's length; (4) the length, under
  that suite: for suite 1, 34 bytes for `lsw` and 66 for `lsr` and `lss`, and any other is
  malformed; (5) for a read or sealed key, a `folder_vk` that is not canonical or is of small order
  (§0.3) is malformed.
- The secret parts of a decoded string are zeroised as soon as the key is stored (§8.2).
- The drafts' single `lsk` prefix, whose payload was a folder ID and an issued key's seed, is gone.

### 6.2 The write key as words

- The write key can also be shown and entered as 24 words (owner answer 3 of 2026-10-22: "Yes, also
  as words"): the BIP39 encoding of `ws` with the English word list. Checksum =
  `SHA-256(ws)[0..1]` (8 bits), appended to the 256 bits, split into 24 groups of 11 bits, each an
  index into the list. BIP39's PBKDF2 "seed" step is **not** used: the words are the secret itself.
- **Display**: lower case, numbered 1 to 24.
- **Entry**: the text is split at runs of whitespace (spaces, tabs, line breaks; leading and
  trailing whitespace ignored) into tokens, and letters are compared without regard to case. The
  checks run in this order, and the first that fails refuses the words:
  1. The number of tokens is 24; otherwise the refusal names the count ("23 words; a write key has
     24").
  2. Each token is a word of the list, or a prefix of at least four letters of exactly one word of
     the list (the English list's first four letters are unique, so four letters always suffice);
     otherwise the refusal names the position, 1 to 24, of the first token that is neither.
  3. The checksum matches; otherwise the refusal names no position, since any word may be the wrong
     one.
  Nothing is ever corrected or guessed.
- The words are another encoding of the same secret, not an owner key: whoever has them has the
  write key of that one folder and nothing else. They look like a cryptocurrency wallet's recovery
  phrase (the same list and length), which the threat model notes (TM-39).
- The words carry no suite: 24 words always mean a suite 1 write secret. A later suite defines its
  own word form (`suites.md` §5).
- Only the write key has words: read and sealed keys are 66 bytes, beyond what BIP39 encodes
  (decision; the owner's answer named the write key).

### 6.3 Link form

A link carries a key string after `#`, where browsers never send it, and may add, by the sender's
choice, current addresses:

```
https://licketysync.app/join#k=<key_string>[&a=<multiaddr>]...[&c=<base64url(cert_hash)>]
```

Rules: a link begins with exactly `https://licketysync.app/join#`, on the browser client's own
domain, and any other beginning, whatever its host, is refused (TM-18). A secret appears **only
after `#`**, never in the path or query, and the client never puts the fragment into a request,
referrer or log. `a` and `c` are appended only when the sender chooses, or automatically for
browser invites and parcel links (phase 6); `c` is base64url without padding. The folder is the one
the key string names: its ID derives from the key, and `a` is a hint for dialling, never an
identity. The drafts' `g=` (a grant chain) is gone with grants.

### 6.4 File form

A key file is the link text, UTF-8, one line, with the extension `.lskey`. The app registers the
extension. The same rules apply as for the link; the recipient's app deletes or shreds the file
after import on request.

## 7. Making, unlinking and sharing again

There is no re-key feature and nothing in the protocol for it (owner answer 2 of 2026-10-22:
"Unlink existing folder without deleting files. Start a new share and specify the existing folder.
No history is preserved. Only one copy is needed. No protocol changes. Manually (outside of client)
inform others about new share keys."). These are local actions on one device; peers see only their
effects.

### 7.1 Making a folder (a new share)

A device draws a fresh write secret (§1.1), so a new folder ID and new keys at every tier. The
folder starts empty or over an existing directory (§7.2). Nothing is announced to anyone until the
device announces the folder (discovery) or gives out a key.

### 7.2 Sharing an existing directory

A new folder (§7.1) made over a directory that already holds files: the engine indexes the files
already there as the folder's first records, so they are not copied anywhere, and no history comes
with them (sequences start afresh and no record supersedes anything). A device that joins the new
folder over its own copy of the same files, such as the directory of a folder it has just unlinked
(§7.3), adopts every file that already matches a record without downloading it (plan, Sync engine:
"identical content is not a change") and treats a local file that differs from the record for its
path as a concurrent version, kept as a conflict copy, never as a silent overwrite in either
direction (decision; an engine rule, phase 1). One directory belongs to at most one folder on a
device, so a device unlinks the old folder before it shares or joins the new one over the same
directory.

### 7.3 Unlinking a folder while keeping its files

The device erases the folder's key from its key store (§8.2), stops announcing and syncing the
folder and stops proving it to peers, and leaves the folder's files in place as ordinary files.
It also keeps the folder's archive (the replaced and deleted files, `threat-model.md` TM-35) as
ordinary files outside the folder's hidden directory, so that whatever was changed or deleted before
the unlink can still be restored afterwards; where they go and how the app shows them is the app's
design (phase 3). Nothing is sent to anyone: peers simply stop seeing the device prove the folder.

### 7.4 Removing someone

Removing a person, or a device that was lost or taken, means the people who stay move to a new
folder by hand: every device that stays unlinks the old folder (§7.3); one of them shares its copy
as a new folder (§7.2); the new key is given to the others outside the client; and each joins over
its own copy. Before any of this the app advises pausing the folder, so that nothing more arrives
from the person being removed, and restoring from the archive whatever they changed or deleted,
since deletions that arrive from peers are applied without a brake and only the archive keeps them
(owner's answer of 2026-10-22). It states plainly:

- the removed person keeps the old folder, its key and every copy they already had;
- any device still using the old key keeps syncing with them, so every device that stays must
  unlink, and a device that misses the message keeps the old folder alive;
- sealed peers store the new folder from scratch, since its data key is new, and their copy of the
  old folder is removed only by unlinking it there;
- the old folder's history (versions, archive) does not move to the new one; the archive stays on
  each device as ordinary files (§7.3).

No record, message or protocol change supports any of this, and nothing in the old folder changes.

## 8. Keys on a device

### 8.1 Device keys

Each device draws a 32-byte **device seed** through the runtime's randomness trait at first run and
keeps it in its key store (§8.2). From it:

- The **device key**: the Ed25519 key pair whose seed is
  `derive_key("licketysync/v1/key/ed25519", device_seed)`. It signs only the DeviceProof
  (`protocol.md` §3.4). **Device ID** = `H("licketysync/v1/hash/id/device", be16(suite) || device_pk)`
  (§0.3); Hello carries `be16(suite) || device_pk`, 34 bytes.
- The device's **libp2p identity**, a separate Ed25519 key,
  `Ed25519.FromSeed(derive_key("licketysync/v1/key/libp2p-identity", device_seed))`, used for
  nothing but the transport. The DeviceProof binds the two: the transcript it signs covers both
  sides' libp2p identity keys exactly as the Hellos carry them, so a device key cannot be presented
  over another device's channel. The libp2p peer ID is stable for the life of the device seed and is
  therefore a handle by which one observer can recognise the same device across folders and
  networks; the threat model lists it as a leak.
- The device's **DHT key** (phase 2), a third Ed25519 key,
  `Ed25519.FromSeed(derive_key("licketysync/v1/key/dht-bep44", device_seed))`, which signs nothing
  but the BEP 44 mutable items the device publishes in the Mainline DHT (§2.2). It is separate from
  the libp2p identity so that a DHT crawler cannot tie an announcement to a peer ID by key equality;
  it is itself stable for the life of the device seed and so a handle for linking that device's
  announcements across days and folders, which the threat model lists ("What stays visible").

The device ID is proven only at the handshake (the DeviceProof). Inside a folder it is only a sync
key: the sequence a device's records belong to (§5.3). A device whose sequence number for a folder
would pass `MAX_SEQ` (`protocol.md` §4.4) draws a new device seed and so takes a new device ID; a
peer holds a writer's records contiguously from 1, so no device ever comes near it. The browser
client keeps one device seed per installation, so clearing a session does not add a writer to the
folders it writes (plan, "Stable browser device ID", phase 6).

### 8.2 The local key store

A device keeps its device seed and, per folder, the one key it holds (its tier byte and that tier's
key string payload, §6.1). Nothing derived is stored: every key in §1.2 is recomputed from the
stored key when needed, and lives in memory only in zeroised types.

- **With a platform keystore** (Keychain, Credential Manager, Secret Service, Android Keystore), the
  keystore holds a random 32-byte store key, and the key store is a file encrypted with
  XChaCha20-Poly1305 under a key derived from it, with a fresh random nonce on every write.
- **Without one** (a headless Linux box, a NAS, a container), the store key is Argon2id over a
  passphrase the person sets, with `suites.md` §2.5's parameters and a fresh 16-byte salt, both kept
  in clear in the file's header so that a later release can raise them on the next unlock.
- The key store, its byte layout, its label in section 10 and its Argon2id use are all phase 1's,
  fixed by the change that adds the daemon's key store; phase 0 stores no key on disk and uses no
  Argon2id (decision). The browser client's store is phase 6's design.
- A device erases a folder's key from the store when the folder is unlinked (§7.3) or lowered
  (§1.3, replaced by the lower key).

### 8.3 Linked devices (phase 5)

A person's devices pass folder keys to each other; there is no master secret and no identity key
(plan, Decisions: "Key model simplified": "linked devices sharing folder keys"). The new device
shows a **link code**, `Bech32m(hrp = "lsl", data = device_id (32) || link_secret (32))`, 113
characters, where `link_secret` is 32 bytes drawn through the runtime's randomness trait. An
existing device scans it and connects over the LAN, announcing
`derive_key("licketysync/v1/link/discovery", link_secret)[0..16]` as the beacon ID. The ordinary
handshake runs (`protocol.md` §3, Hello and DeviceProof), and the dialled device ID must be the one
in the code; then each side sends a link proof
`BLAKE3_keyed(derive_key("licketysync/v1/link/confirm", link_secret), th || u8(role))` over the
transcript hash `th`, so that only the device whose screen was scanned and the device that scanned
it can complete the link. The existing device then sends, over that authenticated channel, the key
string of each folder the new device chooses, at the tier it chooses (Full, Selective, Sealed or Not
on this device) and at most the existing device's own tier, derived locally (§1.3). Sending a write
key this way requires the operating system's own user authentication on the sending device, asked
at that moment and failing closed, as showing one does (§6). The link channel runs only over QUIC or TCP with TLS 1.3, whose key exchange
offers the hybrid X25519MLKEM768 group, never over WebSocket, whose transport is classical end to
end (`suites.md` §2.6), because folder keys cross it (decision). Which folders the person's devices
hold (the catalogue) is exchanged between linked devices over the same channel and kept in each
device's key store (§8.2); keeping it consistent is phase 5's design. Message types for linking are
reserved in `protocol.md` §4.1.

### 8.4 Where secrets rest

| Secret | Devices | At rest |
| --- | --- | --- |
| Device seed | That device | Key store (§8.2) |
| Folder keys (one per folder, at the device's tier) | Devices that hold the folder | Key store (§8.2) |
| Keys derived from a folder key | — | Never stored; derived when needed |
| Link secret | The two devices being linked, while they link | Memory only |

All of these live in `zeroize`d types in memory and never reach logs (`suites.md` §4.1).

## 9. Test vectors the keys crate must publish

The crate author generates these with the reference implementation and checks them in as data files
under `crates/keys/tests/vectors/`; reviewers re-derive them independently where a second
implementation exists (BLAKE3, Ed25519, XChaCha20-Poly1305 and BIP39 have official vectors, which
the crate also checks, `suites.md` §4.4).

1. **Folder derivations**: for a fixed 32-byte `ws`: the folder signing seed, `folder_vk`,
   `folder_id`, `dk`, `ak`, the hint key, the payload key, `ck`, `nk`, `hk` and `rk`; and, for that
   `ws`, the read and sealed keys' payloads.
2. **Key strings**: the three strings for the fixed `ws` in lower and upper case, and the payloads
   they decode to; rejected variants: mixed case, one flipped character, a prefix other than the
   three, a Bech32 (non-m) checksum, a write payload under `lsr` and a read payload under `lsw`
   (wrong length), payloads one byte short and one byte long, a payload of 1 byte (malformed), a
   non-zero padding bit, suite 0, a suite this release does not implement with suite 1's length and
   with another length (both refused with the newer-release message, the suite judged first), and
   read keys
   whose `folder_vk` is not a point, is a non-canonical encoding of a valid point, or is of small
   order.
3. **Words**: the 24 words for the fixed `ws`; accepted entries of them in upper and in mixed case,
   with tabs, line breaks and repeated spaces between them, and as four-letter prefixes; and
   refusals: 23 and 25 tokens (each naming its count), a token in the list's alphabet that is no
   word (naming its position), a three-letter prefix of a longer word (naming its position), and the
   right count of valid words with a bad checksum (naming no position).
4. **Device**: a fixed device seed, its device public key, the 34-byte Hello form
   `be16(suite) || device_pk`, its device ID, its libp2p identity public key and the libp2p peer ID
   of that key, its DHT key, and the DeviceProof signature for a fixed transcript hash `th` (32
   bytes) in both roles.
5. **Discovery**: `peer_tag` and `lan_id` for a fixed salt, folder, announcer key and minute; a
   beacon one minute outside the ±5 minute window, refused; a peer tag that does not match the
   authenticated identity, refused; `dht_id` for a fixed day and the two neighbours.
6. **Chunk**: a fixed raw chunk with compression 0: `plain_hash`, padded length, nonce, `stored`
   bytes and `cipher_hash`; one corrupt variant per failure path (bad tag, non-zero padding, payload
   length over L', empty payload, a compression code this release does not implement, a stored
   length that is not a Padmé length, a stored length over the bound, bad plain hash), and the same
   chunk under another folder's keys (a different `stored`).
7. **Padmé**: the six values in §3.3 plus 1 000 random lengths against a reference.
8. **Index record signing and sealing**: a canonical body with two `supersedes` entries, its
   `record_hash` and signature; a `SealedMeta` sealed with a fixed nonce and opened with the aad
   rebuilt from the record; the seal failing when moved to another `seq`, `device_id` or folder;
   non-zero padding (refused); `sealed` of 39 and of 1 572 865 bytes (malformed); a body with one bit
   flipped inside a bytes field, so that it still parses, whose signature then fails (forged); a
   signature by another folder's key (forged); two records of one device at one `seq`, both
   verifying; and the writer digests (`protocol.md` §4.4) after each of three fixed record hashes.
9. **Handshake inputs** (shared with the protocol crate's vectors, `protocol.md` §8): for a fixed
   transcript hash `th` (32 bytes) and the fixed folder: the hint for both roles, the proof key, and
   the sealed payload for each reported tier in both roles under a fixed nonce, opened again; the
   same payload failing to open under another `th` and under the other role's hint; and a sealed
   key made from the halves of two folders, whose hint matches neither folder's.
10. **Labels**: for every `derive_key` label in section 10, a fixed 32-byte input and its output,
    named after the label (`suites.md` §4.4). The other modes are covered by the vectors above that
    use them.
11. **Links and files** (phase 1): a link with `k`, two `a` and a `c`, its `.lskey` file, and a
    link with the key string in the query (refused).
12. **Linking** (phase 5): a fixed link code, its beacon ID and the link proof for both roles over
    a fixed `th`.

## 10. Label registry

Every label in use, in one place. Adding a label is a change to this table.

The modes are the ones `suites.md` §2.4 fixes: `derive_key` only from uniformly random key
material; the labelled hash `H` for identifiers over public data, the identity hashes of §0.3
included; keyed BLAKE3 where the output must mean nothing without the key, always under a key that
a `derive_key` label below made for that one use, so keyed uses have no labels of their own; the
signature prefix `M`. Removed on 2026-10-22 with the issued-keys model and rulings S-1 and S-2:
every `identity/`, `epoch/` and `wrap/` label, `folder/root-seed`, `folder/chunk-hash-key` (now
`data/chunk-hash-key`), `key/ml-dsa-65`, `key/x-wing`, `hash/id/identity`, `hash/id/key`, the keyed
`handshake/folder-hint` and `handshake/proof-key` (now the derived hint key and payload key), and
the `sig/` labels `folder`, `folder-proof`, `grant`, `grant-pop`, `rotation`, `wrap`, `revocation`,
`suspension`, `lift` and `root-rotation`.

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

## 11. Phase map

| Section | Phase |
| --- | --- |
| 0, 1, 2.1, 3, 4, 5, 6.1, 6.2, 8.1 (device key and libp2p identity) | 0 |
| 2.2 LAN, 6.3 link, 6.4 file, 7 (making, unlinking, sharing an existing directory), 8.2 key store and Argon2id | 1 |
| 2.2 DHT, 8.1 DHT key; sealed tier in real use | 2 |
| 6 showing and exporting keys in the app, with the operating system's authentication for a write key | 3 (the CLI's export in phase 1) |
| 8.3 linking and the catalogue | 5 |
| 6.3 parcel links, the browser client's key store | 6 |

The keys crate implements the encodings of 6.1 and 6.2 in phase 0, with their vectors, since it
already has both; the app's entry and display of them are phase 1 and phase 3.
