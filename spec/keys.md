# Lickety-Sync keys

Status: draft for phase 0, 2026-10-14. This file is what `licketysync-keys` implements
and what reviewers check it against. The plan ("Lickety-Sync: Project Plan") is the
design; where this file and the plan disagree, raise it. `suites.md` fixes the
algorithms and their crates; `threat-model.md` names the adversaries; `protocol.md`
puts these records on the wire. **Issues** is the list of problems a device shows its
owner (the plan's Issues panel): every flag, rejection and missing dependency this file
and `protocol.md` name raises one that states its cause, so nothing is dropped without
trace.

Each section says in plain words what the thing is for, then defines it exactly.
Anything marked "phase N" is not needed for phase 0 ("simulated peers converge") and
may be left unimplemented, but its record formats are fixed now so that records carry
the type and suite fields that leave room for them.

## 0. Notation and constants

- `a || b` is concatenation. `be16(n)`, `be32(n)`, `be64(n)` are unsigned big-endian
  integers of that width. `x[0..n]` is the first `n` bytes of `x`.
- `BLAKE3(x)` is the plain 32-byte BLAKE3 hash. `H(label, x) = BLAKE3(label || 0x00 || x)`
  is the **labelled hash**, used for every identifier and link over public data.
  `BLAKE3_keyed(k, x)` is BLAKE3 in keyed mode with the 32-byte key `k`.
  `derive_key(label, material)` is BLAKE3 in derive-key mode: `label` is the context
  string, `material` uniformly random key material, output 32 bytes. Every label has
  the form `licketysync/v1/<area>/<purpose>` (`suites.md` §2.4) and is listed in the
  registry in section 10. No key is ever used raw for two purposes.
- `XChaCha(k, n, aad, pt)` is XChaCha20-Poly1305 with a 32-byte key `k`, a 24-byte
  nonce `n`, associated data `aad`, returning ciphertext with the 16-byte tag appended.
- `HPKE_Seal(pk, info, aad, pt)` and `HPKE_Open(sk, enc, info, aad, ct)` are RFC 9180
  base mode, single shot, with the KEM, KDF and AEAD fixed by the suite.
- `HybridSign(sk, label, body)` and `HybridVerify(pk, label, body, sig)` are defined in
  section 0.2.
- A **suite** number is a 16-bit integer, 1 to 65 535 (`suites.md` §1); Protocol Buffers
  carries it as `uint32`, and a value outside that range is malformed.
- A **tier** is one byte: `0` root (never appears in a grant), `1` write, `2` read,
  `3` sealed. Lower numbers have more authority.
- An **epoch** is a `u64` starting at 1 when the folder is created. Epoch 0 never
  occurs.
- A **key ID** is 16 bytes, **derived from both public halves of the key** (§0.4):
  `key_id = H("licketysync/v1/hash/id/key", be16(suite) || signing_pk || kem_pk)[0..16]`,
  recomputed by every verifier from the grant's own fields, so nobody can claim an ID for
  a key that is not theirs, nor pair a key's signing half with another encryption half
  (TM-19; decisions 2026-10-15 and 2026-10-17, replacing "16 random bytes from the
  issuer", which let an issuer squat on an ID). The root key, which has no grant, is
  named by the reserved constant `root_key_id` = 16 zero bytes; a derived ID that is all
  zero is malformed. One key may hold several grants (5.4); its ID is the same in all of
  them. The ID is 128 bits: finding two keys with one ID takes about 2^64 work (a birthday
  search), within reach only of an issuer that makes both keys, and what such a collision
  gets is stated in 5.4 step 7.
- Time fields are `u64` Unix seconds; `0` means "none" where a field is optional. Every
  comparison with "now" (expiry, a suspension's end) uses the device's wall clock as the
  runtime reports it (`Clock::wall_time()`, Unix seconds); the simulator derives it from
  the simulated instant plus a per-peer skew, so clock disagreement is a test scenario.
- Randomness (seeds, nonces, salts) reaches the keys crate from the caller
  through the runtime's randomness trait: OS-backed in production, seeded in the
  simulator so that a run replays exactly.

### 0.1 Suite 1 sizes

Suite 1 is the whole set in `suites.md`: X-Wing (X25519 + ML-KEM-768) through HPKE
for key wrapping; Ed25519 + ML-DSA-65 hybrid signatures; XChaCha20-Poly1305 for data;
BLAKE3 for hashing and key derivation; Argon2id for passphrases. A record or key that
names a suite this release does not implement is rejected without being partially
processed; the rejection is validity-only (`protocol.md` §5), since the sender may be a
newer release, never a close. The **folder's current suite** is the `suite` of its
Folder record (§2.2); moving a folder to another suite is undesigned phase 7 work
(§11). Sizes the keys crate must check on every parse:

| Item | Bytes |
| --- | --- |
| Ed25519 public key / signature | 32 / 64 |
| ML-DSA-65 public key / signature | 1952 / 3309 |
| Hybrid signing public key `ed25519_pk \|\| mldsa_pk` | 1984 |
| Hybrid signature `ed25519_sig \|\| mldsa_sig` | 3373 |
| X-Wing public key / ciphertext / private seed | 1216 / 1120 / 32 |
| HPKE wrap of a 32-byte key: `enc (1120) \|\| ct (32 + 16)` | 1168 |
| Folder ID, device ID, record hash, data key, seed | 32 |
| Key ID | 16 |

### 0.2 Hybrid signatures

Both halves must verify; there is no mode in which one suffices. The signed message is
the body prefixed with a label, so a signature over a grant can never be mistaken for
a signature over a revocation or a handshake proof (`suites.md` §2.2).

```
M = label || 0x00 || body                                # label = licketysync/v1/sig/<type>, ASCII
HybridSign(sk, label, body):
    s1  = Ed25519.Sign(sk.ed25519, M)                   # RFC 8032, pure: no prehash, no context
    s2  = ML-DSA-65.Sign(sk.mldsa, M, ctx = "")         # FIPS 204; deterministic now, hedged once the crate exposes it
    return s1 || s2                                      # 3373 bytes
HybridVerify(pk, label, body, sig):
    require len(sig) == 3373
    return Ed25519.VerifyStrict(pk.ed25519, M, sig[0..64]) AND ML-DSA-65.Verify(pk.mldsa, M, sig[64..3373], ctx = "")
```

Implementations run both verifications and fail if either fails; a failure is
reported as one error that does not say which half failed. Test vectors use the
deterministic ML-DSA variant (`rnd` = 32 zero bytes) so they reproduce.

### 0.3 Key pair sets from a seed

Every key in the system, root, issued, identity or device, is a **key pair set**
derived from one 32-byte seed. Holding the seed is holding the key. The three
components use three labels so that no two share randomness.

```
KeyPairSet(seed):
    ed25519_sk = Ed25519.FromSeed( derive_key("licketysync/v1/key/ed25519",   seed) )
    mldsa_sk   = ML-DSA-65.KeyGen_internal( xi = derive_key("licketysync/v1/key/ml-dsa-65", seed) )
    xwing_sk   = X-Wing.ExpandDecapsulationKey( derive_key("licketysync/v1/key/x-wing", seed) )
    signing_pk = ed25519_pk || mldsa_pk                  # 1984 bytes
    kem_pk     = xwing_pk                                # 1216 bytes
```

The **public key bytes** of a key pair set are `be16(suite) || signing_pk` (1986 bytes
under suite 1); Hello carries a device key in this form, and every identity hash is
taken over it (the key ID over it and `kem_pk`, §0.4), so the suite is part of the
identity.

### 0.4 Identity hashes

Folder, device and identity IDs are labelled plain hashes `H` over the public key bytes,
the construction `suites.md` §2.4 registers for identifiers over public data, each kind
under its own label (coordinator decision, 2026-10-14):

```
folder_id   = H("licketysync/v1/hash/id/folder",   be16(suite) || root_signing_pk)
device_id   = H("licketysync/v1/hash/id/device",   be16(suite) || device_signing_pk)
identity_id = H("licketysync/v1/hash/id/identity", be16(suite) || identity_signing_pk)
key_id      = H("licketysync/v1/hash/id/key",      be16(suite) || issued_signing_pk || issued_kem_pk)[0..16]
```

The four kinds never share a preimage format: a device key misused as a root key, or
a root key presented as a device, would otherwise produce equal IDs and let one kind of
record be matched against another. The key ID alone also covers the X-Wing half
(`kem_pk`, 1216 bytes under suite 1), because a grant, a Rotation's `KeyWrap` and a Wrap
record all encrypt to the `kem_pk` of the key the ID names: a key ID therefore names one
signing key and one encryption key together. Hashes of other public data (records, chunks,
discovery, the transcript) use `H` under their own `licketysync/v1/hash/<purpose>` labels.

## 1. Derivation tree

One 24-word phrase is the only secret a person has to keep. Everything the person owns
is derived from it with labels, so a phrase written on paper regenerates the identity
key and every folder root key, past and future, provided the folder's public metadata
(its nonce) is still available from any peer. Device keys are not derived from the
phrase: they are made on each device, because the phrase must never be present on a
device that is not a root holder.

### 1.1 Recovery phrase and master secret

- Generate 32 bytes from the operating system's CSPRNG at first run. This is the
  **master secret** `ms`.
- The phrase is the BIP39 encoding of `ms` with the English word list: checksum =
  `SHA-256(ms)[0..1]` (8 bits), appended to the 256 bits, split into 24 groups of 11
  bits, each an index into the list. Words are numbered 1 to 24 on paper; the first
  four letters of each English word are unique, so entry may accept prefixes.
- Decoding validates the checksum and refuses the phrase otherwise. BIP39's PBKDF2
  "seed" step is **not** used: the master secret is the entropy itself.
- The phrase and `ms` are stored only on root-holder devices, at rest in the platform
  keystore (section 8). Other devices never see them.

### 1.2 From the master secret

| Derived value | Definition | Phase |
| --- | --- | --- |
| Identity seed | `identity_seed = derive_key("licketysync/v1/identity/seed", ms)`; identity key pair set = `KeyPairSet(identity_seed)` | 5 |
| Identity ID | `H("licketysync/v1/hash/id/identity", be16(suite) \|\| identity signing_pk)` (§0.4) | 5 |
| Catalogue key | `derive_key("licketysync/v1/identity/catalogue-key", identity_seed)`; XChaCha key for the linked-device catalogue | 5 |
| Folder root seed | `root_seed = derive_key("licketysync/v1/folder/root-seed", ms \|\| folder_nonce)`; root key pair set = `KeyPairSet(root_seed)` | 0 |

`folder_nonce` is 32 random bytes created with the folder and published in the folder's
Folder record (section 2). The same phrase and the same nonce always give the same root
key, which is how a root holder re-derives the root for a folder it finds on any peer:
derive, compute the folder ID (section 2) and compare. A folder is therefore
**numbered under the phrase by its nonce**, not by an index; there is no counter to lose,
and two folders created on two root holders at once cannot collide.

The owner's identity signing key signs nothing in phase 0; it exists so that the
linked-device catalogue (phase 5) and the link channel have a stable owner identity.

### 1.3 Device keys

Each device generates a 32-byte **device seed** at first run (CSPRNG), stores it in the
platform keystore, and derives `KeyPairSet(device_seed)`. Decision and reasons:

- Device keys are **generated per device and linked**, not derived from the phrase. The
  plan keeps the phrase on root holders only, and a device must have an identity before
  it is linked (the link code it shows carries its device ID), so there is nothing to
  derive from yet. Revoking a lost device means revoking the folder keys it held; its
  device key is simply never trusted again.
- **Device ID** = `H("licketysync/v1/hash/id/device", be16(suite) || device signing_pk)`, 32 bytes (§0.4).
- The device's **libp2p identity** is a separate Ed25519 key derived from the same seed,
  `Ed25519.FromSeed(derive_key("licketysync/v1/key/libp2p-identity", device_seed))`,
  used for nothing but the transport. The device set's Ed25519 half never signs outside
  the hybrid. The DeviceProof (`protocol.md` §3.4) binds the two: the transcript it signs
  covers both sides' libp2p identity keys exactly as the Hellos carry them, so a device
  key cannot be presented over another device's channel. The libp2p peer ID is stable for
  the life of the device seed and is therefore a handle by which one observer can
  recognise the same device across folders and networks; the threat model lists it as a
  leak.
- The device's **DHT key** (phase 2) is a third Ed25519 key from the same seed,
  `Ed25519.FromSeed(derive_key("licketysync/v1/key/dht-bep44", device_seed))`, which signs
  nothing but the BEP 44 mutable items the device publishes in the Mainline DHT (§2.3).
  It is separate from the libp2p identity so that a DHT crawler cannot tie an
  announcement to a peer ID by key equality; the DHT key itself is stable for the life of
  the device seed and so is a handle for linking that device's announcements across days
  and folders, which the threat model lists ("What stays visible").

### 1.4 Issued keys

An issued key is `KeyPairSet(seed)` for a 32-byte seed chosen by the issuer's CSPRNG. The
seed travels in the key string (section 6); the grant (section 5) travels in the
folder. See section 4.

## 2. Folder identity

A folder is its root key. The folder ID is a hash of the root public key, so a peer that
holds the Folder record can check that the ID it was given names this root and no other.
Discovery exposes only hashes of the ID, so that a passive observer learns nothing it
did not already know, and so that a device cannot be followed from network to network by
the folders it announces.

### 2.1 Folder ID and root key ID

```
folder_id   = H("licketysync/v1/hash/id/folder", be16(suite) || root_signing_pk)   # 32 bytes, §0.4
root_key_id = 0x00 * 16                                          # reserved constant; names root in issuer_key_id, wraps and cursors
```

Root never presents at the handshake and never signs index records: it has no grant, so
no verifier can resolve it as a writer. A root holder issues itself a write key with
`may_share` for everyday work on the folder and keeps the root for issuing, revoking and
rotating.

### 2.2 The Folder record (type 1, phase 0)

The genesis record of a folder, signed by root. Every peer stores exactly one per folder
and rejects any other that names the same `folder_id` with different contents.

| # | Field | Type | Size | Meaning |
| --- | --- | --- | --- | --- |
| 1 | suite | u32 | | Suite of the root key and of this record |
| 2 | record_type | u32 | | `1` |
| 3 | folder_id | bytes | 32 | `H("licketysync/v1/hash/id/folder", be16(suite) \|\| root_signing_pk)`; checked, not trusted |
| 4 | root_signing_pk | bytes | 1984 | Root hybrid signing public key |
| 5 | root_kem_pk | bytes | 1216 | Root X-Wing public key; rotations wrap to it |
| 6 | folder_nonce | bytes | 32 | For re-deriving the root from the phrase (§1.2) |
| 7 | root_wrapped_data_key | bytes | 1168 | Epoch 1 data key wrapped to `root_kem_pk` (§5.3) with aad = `folder_id \|\| root_key_id \|\| 0x00 \|\| be64(1)` |
| 8 | created_at | u64 | | Informational |
| 9 | minimum_suite | u32 | 1 ..= suite | Peers whose keys or records use a lower suite are refused (phase 7 raises it) |
| 10 | required_features | repeated string | each `[a-z0-9:-]{1,32}`, ≤ 32 entries | Feature names a peer's feature set must contain to open the folder (`protocol.md` §5) |
| 11 | confirm | bytes | 32 | `derive_key("licketysync/v1/epoch/confirm", dk_1)`: epoch 1's key-confirmation value, against which the ladder of epoch 2 is checked (§3.1, §7.1) |

Verification, in order: parse (section 5.4 rules: sizes, `1 ≤ minimum_suite ≤ suite`, the
feature grammar; failure: malformed);
`HybridVerify(root_signing_pk, "licketysync/v1/sig/folder", body, signature)` (failure:
forged); `folder_id` recomputes from `suite` and `root_signing_pk` and equals the folder
being verified, the open folder or the one a link names (failure: malformed). A second
root-signed Folder record for the same `folder_id` with a different body is a signer
fault against root: the first one stored is kept, the newcomer rejected, and an issue
names the folder. Every holder that unwraps `dk_1`, from this record or from a grant at
epoch 1, checks it against `confirm` before use (5.3); a mismatch is a signer fault of
the record that carried the wrap, which is root only for this record's own
`root_wrapped_data_key`, and the holder does not use the key.

### 2.3 Discovery hashes

Two different constructions, because the LAN can carry a fresh salt in every beacon and
the DHT cannot.

**LAN beacon (phase 1).** Every beacon carries a fresh random 16-byte `salt`, the
announcer's **peer tag** `peer_tag = H("licketysync/v1/hash/discovery-peer", salt || peer)[0..16]`
where `peer` is its 32-byte libp2p identity key (§1.3), the current Unix minute
`minute = floor(unix_seconds / 60)`, a port, and per announced folder
`lan_id = H("licketysync/v1/hash/discovery-lan", salt || folder_id || peer_tag || be64(minute))[0..16]`.
A listener drops a beacon whose `minute` is more than 5 off its own clock (devices
without a real-time clock drift; ±5 minutes is the window), and raises the issue "clock
differs from LAN peers" when every beacon it has heard from one source address over the
last window is outside it. For a beacon in the window it computes `lan_id` for the salt
and each folder it holds and on a match dials the beacon's source address; once the
transport has authenticated the peer's identity `p` (`protocol.md` §3.1) the dialler
checks `H("licketysync/v1/hash/discovery-peer", salt || p)[0..16] = peer_tag` and
drops the connection before sending Hello otherwise, so a beacon replayed from another address cannot
steer the dial to a different device. The beacon carries no identity in the clear: an
observer without the folder ID learns nothing and cannot link two beacons, even seconds
apart, to one folder or one device (libp2p's own mDNS would put the peer ID in every
announcement, which is why Lickety-Sync uses its own beacon). An observer who knows the
folder ID can confirm it is present on this LAN; and anyone can replay a fresh beacon
from another address and learn, from the dial that follows, that the dialler holds the
folder: the dial is the signal, and that residual leak is the one the plan accepts
("What stays visible"). Listeners rate-limit beacons per source address. Beacons never
carry the folder ID or key material.

**Mainline DHT (phase 2).** `day = floor(unix_seconds / 86400)` and
`dht_id(day) = H("licketysync/v1/hash/discovery-dht", folder_id || be64(day))[0..20]`.
A device announces under `dht_id(today)` and looks up `dht_id(today - 1)`, `dht_id(today)`
and `dht_id(today + 1)`, which covers clock disagreement of up to a day. The address
record it announces is a BEP 44 mutable item signed by the device's DHT key (§1.3) and
carries addresses only, never the libp2p peer ID, so the separate DHT key buys real
unlinkability: a crawler ties announcements to a DHT key, not to the identity the
transport will authenticate; how the item is placed under `dht_id` is phase 2's design.
Announcements cannot be linked across days without the folder ID, except through the
stable DHT key itself (§1.3).

## 3. The data key and epochs

Content, names and folder structure are encrypted under a 256-bit **data key** that
belongs to an epoch. Every revocation starts a new epoch with a fresh data key wrapped to
every key that is still valid, so the revoked key cannot read anything written from then
on. Old ciphertext stays under its old epoch until a full re-encryption, so a member who
joins later must still be able to read it: each epoch's record carries the previous
epoch's key encrypted under the new one, a ladder that leads down but never up.

### 3.1 Definitions

- `dk_e`: the 32-byte data key of epoch `e`, generated by the root (epoch 1) or by the
  signer of the rotation that created epoch `e` (CSPRNG).
- Epoch 1 is created with the folder. Rotations (section 7.1) create `e + 1` from `e`.
  Epoch numbers are dense: a rotation creates `current + 1`. One naming a higher epoch
  is a missing dependency (an earlier rotation has not arrived), and one naming the
  current epoch or a lower one with another hash is a rival or stale rotation, stored as
  evidence once its signature has verified and never applied (7.1 step 1).
- **Ladder link**: for `e ≥ 2`, `ladder_e = n || XChaCha(derive_key("licketysync/v1/epoch/ladder-key", dk_e), n, folder_id || be64(e), dk_{e-1})`
  with a random 24-byte nonce `n`, 72 bytes in total, published in the rotation record.
  A holder of `dk_e` recovers `dk_{e-1}` and so every earlier epoch, checking each
  recovered key against that epoch's `confirm` value (the Rotation that created it, or
  the Folder record's `confirm` for epoch 1, §2.2). Only a `dk_e` that has itself been
  confirmed opens `ladder_e` (an unwrapped key is checked before any use, 5.3, and a
  mismatch there is charged to the record that carried the wrap); only then does a tag
  failure on `ladder_e`, or a recovered key that fails its epoch's `confirm`, mean that
  the rotator of epoch `e` published a ladder to a key nobody else holds, which flags
  that rotator, and the holder keeps only the epochs it has confirmed. A holder of
  `dk_{e-1}` learns nothing about `dk_e`. The ladder is deliberate: an epoch key is a
  reader's credential for the folder's whole history, so a leaked `dk_e` opens every
  epoch up to `e`, and only a revocation followed by `rekey --full` closes that.

### 3.2 Keys derived from a data key

| Key | Definition | Used for |
| --- | --- | --- |
| Chunk key | `ck_e = derive_key("licketysync/v1/epoch/chunk-key", dk_e)` | XChaCha key for chunk ciphertext (§3.3) |
| Chunk nonce key | `nk_e = derive_key("licketysync/v1/epoch/chunk-nonce-key", dk_e)` | Keyed BLAKE3 for convergent nonces (§3.3) |
| Record key | `rk_e = derive_key("licketysync/v1/epoch/record-key", dk_e)` | XChaCha key for the sealed part of index records (`protocol.md` §4.4) |
| Ladder key | `derive_key("licketysync/v1/epoch/ladder-key", dk_e)` | Encrypts `dk_{e-1}` (§3.1) |
| Chunk hash key | `hk = derive_key("licketysync/v1/folder/chunk-hash-key", dk_1)` | Keyed BLAKE3 over plaintext chunks; folder-lifetime so hashes survive rotations |

`hk` is derived from epoch 1's key on purpose: every reader can reach `dk_1` down the
ladder, so plaintext chunk hashes stay stable across rotations and renames and
deduplication keep working. `rekey --full` re-encrypts content under the current epoch
but does not change `hk`. A revoked holder keeps `hk`, but needs a valid key to obtain
anyone's records, so it gains no oracle.

### 3.3 Chunk encryption

The engine splits a file with FastCDC; this section fixes what one chunk becomes. The
protocol constant `MAX_CHUNK_PLAINTEXT` is 4 MiB (4 194 304 bytes) of raw content; the
engine's FastCDC maximum must not exceed it.

```
raw            : the chunk's bytes (1 ..= MAX_CHUNK_PLAINTEXT)
plain_hash     = BLAKE3_keyed(hk, raw)                           # 32 bytes; the key-holder-side reference
payload        = compress(compression, raw)                      # compression 0 = none (phase 0: always 0)
header         = u8(compression) || be32(len(payload))
L              = len(header || payload)
L'             = padme(L)                                        # §3.4
plaintext      = header || payload || zeros(L' - L)
nonce          = BLAKE3_keyed(nk_e, plaintext)[0..24]
ct             = XChaCha(ck_e, nonce, folder_id || be64(e), plaintext)
stored         = nonce || ct                                     # L' + 40 bytes
cipher_hash    = H("licketysync/v1/hash/chunk", stored)           # 32 bytes; what sealed peers and relays see
```

- Encryption is **deterministic** for a given epoch and plaintext, so identical chunks
  give identical `stored` bytes and sealed peers can deduplicate and verify by
  `cipher_hash`. The nonce is a keyed hash of the exact padded plaintext, never of the
  raw content alone, so two different plaintexts never share a nonce under one key.
- Writer rules: `1 ≤ len(raw) ≤ MAX_CHUNK_PLAINTEXT`; with compression `0`,
  `payload = raw`; with any other code the writer falls back to `0` when the compressed
  form is not shorter, so `len(payload) ≤ len(raw)` always.
- Decryption, in order: `46 ≤ stored_len ≤ 4 325 416` and `stored_len - 40 = padme(stored_len - 40)`
  (a stored length that is not a Padmé length is malformed); split the nonce; `XChaCha`
  open with the record's epoch; read the header; `1 ≤ len(payload) ≤ L' - 5` and, for
  compression `0`, `len(payload) ≤ MAX_CHUNK_PLAINTEXT`; every padding byte is `0x00`;
  `compression` is `0` or one the folder requires; decompress into a buffer of at most
  `MAX_CHUNK_PLAINTEXT` bytes, stopping at the bound, and require at least one byte out;
  recompute `plain_hash` and compare with the record. Who is blamed for a failure is
  `protocol.md` §4.7's business: when the ciphertext hash matched, the sender delivered
  what the writer stored, so the fault is the writer's.
- Compression codes: `0` none, `1` deflate, `2` zstd, `3` lz4. A writer uses only codes
  the folder's `required_features` guarantee every member can decode (phase 1+). The
  code sits inside the ciphertext because ciphertext itself does not compress. Known
  cost: compressing before encrypting makes the padded length depend on the content's
  compressibility, a CRIME-style length channel on top of the size leak Padmé already
  bounds; the threat model records it, and a folder that must not leak it keeps
  compression off (phase 0 and the default: `0` only).

### 3.4 Padmé padding

Padmé (Nikitin et al., PURBs 2019) rounds a length up to a multiple of `2^(E - S)`,
where `E = floor(log2 L)` and `S` is the number of bits in `E`: the low `E - S` bits of
the padded length are zero and only about `log2(log2 L) + 1` bits of it carry
information. Overhead is at most 12 %, 3 % on average.

```
padme(L):
    if L < 2: return L
    E = floor(log2(L))                  # position of the highest set bit
    S = bit_length(E)                   # bits needed to write E
    last = E - S
    mask = (1 << last) - 1
    return (L + mask) & ~mask
```

Examples the crate's vectors must reproduce: `padme(5) = 5`, `padme(9) = 10`,
`padme(100) = 104`, `padme(1000) = 1024`, `padme(65 537) = 67 584`, `padme(1 048 577) = 1 081 344`.

## 4. Issued keys

A key is the credential. The issuer picks a random seed, derives the key pair set and its
key ID (§0.4), and signs a grant that binds the public halves to a folder, a tier, an
expiry, a "may share" flag and an epoch, and that wraps the data key to the new key when
the tier can read; the new key signs the same grant as its proof of possession (5.3). Up
to `MAX_DEVICES_PER_KEY` (256) devices may write under the same key (`protocol.md` §4.4
counts the device IDs it writes under); the plan's default is one key per recipient and
per device so that each can be lowered or revoked alone.

### 4.1 Tiers

| Tier | Byte | Holder can | May issue, if `may_share` |
| --- | --- | --- | --- |
| Root | 0 | Issue and revoke at any tier, rotate, change the folder's settings. Derived from the phrase; never in a grant; never presents or writes itself (§2.1): a root holder works through a write key it issues itself | Any tier |
| Write | 1 | Change files (sign index records); receive and decrypt | Write, read, sealed |
| Read | 2 | Receive and decrypt; its index records are ignored | Read, sealed |
| Sealed | 3 | Hold, verify, serve and relay ciphertext and records it cannot open | Sealed |

An **invite** is any issued key with a short expiry; there is no separate kind.

### 4.2 Flags, expiry and fresh keys

- `may_share`: the holder may issue keys at or below its own tier (table above), and may
  revoke, suspend and lift keys it issued (section 7).
- **Fresh keys.** A `may_share` key may mint a child at its own tier or lower at any
  time, signed by itself, and the device may switch to the child at once. A self-minted
  child inherits its parent's lifetime: it is beneath the parent in the chain, so it
  expires, is suspended and is revoked with the parent. It therefore serves to give each
  recipient or device a key of its own that can be lowered or revoked alone, and to lower
  a device, but it cannot replace its parent. A device's **replacement key** (to retire a
  key that may have leaked, or that is about to expire) is issued by the old key's
  issuer, or by root over the linked-device channel, and the old key is then suspended or
  revoked by that issuer. Deviation from the plan ("Fresh keys": a device "can rotate its
  own key and retire the old one"): under cascading revocation a child cannot outlive the
  key that minted it, so retiring goes through the issuer.
- `expires_at`: Unix seconds, `0` = never, compared with the device's wall clock as the
  runtime reports it (§0). Expiry bounds **only** the key's ability to present at the
  handshake (`protocol.md` §3.5) and to issue, revoke, suspend or lift; it does not end
  the key's authority over index records: records signed by an expired key stay accepted
  wherever they arrive, because a relay cannot know the writer's clock and a rule that
  depended on it would make peers disagree. A temporary raise whose writes must also stop
  is ended by a suspension or a revocation signed by the issuer; the app offers that
  action when the expiry passes. Expiry **cascades for presenting**: a key is presentable
  only while some chain of it to root has every grant unexpired (a presentable chain,
  5.5), so an issuer that will expire cannot hand out keys that outlive its own access
  through it; the app warns when an expiring `may_share` key issues. A grant signed by a
  key after its expiry cannot be told from one signed before (the issuer's clock is its
  own): its holder cannot present the key through that issuer, since that chain contains
  an expired grant, but records signed under it are still accepted wherever they arrive
  (§5.5), exactly like the parent's, and the issuer's revocation cascades to it; this is
  why ending a temporary raise takes the issuer's suspension or revocation. The threat
  model relies on revocation, not expiry, for everything that matters. Deviation from the
  plan ("Changing a device's tier": "temporary changes are therefore built in", with a
  raise ending by expiry alone): the raise's writes end by the issuer's suspension or
  revocation, which the app issues at expiry.

## 5. The grant record and the canonical encoding

A grant is a public record in the folder: fetched from the first peer met, verified
against the chain to root, and stored by every peer including sealed ones. It carries no
secret; the wrapped data key can only be opened by the holder of the issued key's seed.
Key records are never garbage-collected: a revoked key's grant and its revocation stay in
every peer's set for the folder's life, because a late joiner needs them to interpret the
records the revoked writer left (5.4, 7.2). That is a known cost. The 7.1 caps bound one
rotation, not the store: what bounds the store is `protocol.md`'s
`MAX_KEY_RECORDS_PER_FOLDER` (65 536), past which a key record is a validity-only
rejection with an issue naming the folder. The residual, until phase 7 (5.4 step 9's open
item): an insider with a `may_share` key can fill the store to that cap, after which no
further key record is accepted; and at the cap the on-open key set a peer sends on every
connection is 65 536 records, about 739 MB were they all grants at their largest (11 277
bytes each). Everything signed in this project is a Protocol Buffers body that the signer
serialises canonically and that every verifier treats as opaque bytes: hashed, signed and
forwarded exactly as received, never re-encoded.

### 5.1 The signed envelope

```proto
message SignedRecord {
  bytes body          = 1;   // canonical bytes of one of the record bodies below
  bytes signature     = 2;   // HybridSign(signer, "licketysync/v1/sig/<type>", body); 3373 bytes under suite 1
  bytes key_signature = 3;   // grants only: HybridSign(issued key, "licketysync/v1/sig/grant-pop", body), 3373 bytes (5.3); empty in every other record
}
```

`record_hash = H("licketysync/v1/hash/record", body)`. Two SignedRecords with equal
bodies are the same record, whatever their signatures (ML-DSA signatures are randomised).
A non-empty `key_signature` on a record that is not a grant is malformed, and so is an
encoded `SignedRecord` larger than `protocol.md`'s cap for its kind
(`MAX_KEY_RECORD_BYTES`, 6 000 000 bytes, for every key record; `MAX_INDEX_RECORD_BYTES`,
4 000 000, for an index record), judged at parse, before the duplicate check. Every body
begins with the same three fields, so a parser can read the suite and type before
anything else:

```proto
// Common prefix of every body: field numbers 1 to 3 mean this in every record type.
uint32 suite       = 1;
uint32 record_type = 2;   // 1 Folder, 2 Grant, 3 Rotation, 4 Wrap, 5 Revocation, 6 Suspension, 7 Lift, 8 RootRotation (reserved), 16 Index
bytes  folder_id   = 3;   // 32 bytes
```

Signature labels, one per type: `licketysync/v1/sig/folder`, `.../grant`, `.../rotation`,
`.../wrap`, `.../revocation`, `.../suspension`, `.../lift`, `.../root-rotation`,
`.../index`; and `licketysync/v1/sig/grant-pop` for a grant's `key_signature`. The label
is chosen from the body's own `record_type`, so a body cannot be presented as another
type, and the issuer's signature and the issued key's over the same grant body can never
stand in for each other.

### 5.2 Canonical encoding

Producers emit proto3 wire format under these rules, which prost's encoder follows; the
encoding is deterministic and every variable-length item is length-prefixed:

1. Fields in increasing field-number order, each exactly once.
2. A field whose value is the proto3 default (`0`, `false`, empty bytes or string, empty
   repeated) is omitted entirely.
3. Repeated scalars are packed; repeated messages and bytes appear in the order given
   and that order is part of the record's meaning (chunk lists, cursors).
4. Varints are minimal; no unknown fields; nested messages follow the same rules.
5. Lists that the specification calls sorted (version vector entries, wraps, a
   rotation's `view`, cutoffs) are sorted by the named key before encoding, ascending,
   bytewise, and hold no duplicates.

Verifiers never re-encode a body and never require it to be canonical: the bytes received
are the bytes hashed and signed, and unknown fields inside them are stored and forwarded
untouched, which is how a newer peer adds fields an older one never sees. A verifier does
reject a body it cannot parse, a field of the wrong length, a value outside its stated
range, or a field that is not repeated occurring more than once; it accepts a repeated
scalar field packed or unpacked, or partly each, concatenating the values in the order
they appear (`protocol.md` §2).

### 5.3 The Grant body (type 2, phase 0)

| # | Field | Type | Size / range | Meaning |
| --- | --- | --- | --- | --- |
| 1 | suite | u32 | implemented suite | Suite of the issued key and of this record |
| 2 | record_type | u32 | `2` | |
| 3 | folder_id | bytes | 32 | |
| 4 | key_id | bytes | 16 | `H("licketysync/v1/hash/id/key", be16(suite) \|\| signing_pk \|\| kem_pk)[0..16]` (§0.4); checked, not trusted |
| 5 | tier | u32 | 1, 2 or 3 | |
| 6 | may_share | bool | | |
| 7 | expires_at | u64 | | `0` = never |
| 8 | issuer_key_id | bytes | 16 | `root_key_id`, or the key ID of a `may_share` key; never this grant's own `key_id` |
| 9 | epoch | u64 | ≥ 1 | Epoch of the wrapped data key |
| 10 | signing_pk | bytes | 1984 | Issued key's hybrid signing public key |
| 11 | kem_pk | bytes | 1216 | Issued key's X-Wing public key |
| 12 | wrapped_data_key | bytes | 1168, or empty | `dk_epoch` wrapped to `kem_pk`; **empty if and only if tier = 3** |
| 13 | issued_at | u64 | | Informational |
| 14 | issuer_device_id | bytes | 32 or empty | The device that issued; shown as "issued by" |

**Proof of possession.** A grant carries two signatures over the same body: `signature`
by the issuer, and `key_signature` by the issued key itself,
`HybridSign(issued key, "licketysync/v1/sig/grant-pop", body)`. Only a holder of the
issued key's private half can make the second: the issuer at the moment it mints the key
from a seed it chose, or the key's holder when it accepts a further grant for a key it
already has. Nobody can therefore grant a key that is not theirs to grant. Without it,
any `may_share` key could issue a second grant to someone else's key and so become one of
that key's issuers (with the power to revoke, suspend and lift it), make the key descend
from itself so that its own revocation withdrew the victim, shift the key's governing
grant, or close a loop in its chains (decision 2026-10-17). A holder signs
`key_signature` for a further grant of a key it already holds only on its owner's
explicit action, after the app has shown the issuer, the tier and the expiry, because
accepting makes that issuer, and every key it reaches now or later within the remaining
links, an ancestor of this key and of every key beneath it (5.5), with the power to
revoke and suspend them (section 7), for good. Deviation from the plan ("Issued keys": "a
grant signed by root"): a grant is signed by its issuer and by the key it grants.

**Sizes** under suite 1, with every `u64` at its longest varint: a grant body is at most
4522 bytes, the `SignedRecord` carrying it with both signatures at most 11 277 bytes, and
a chain of 16 grants at most 180 432 bytes.

The wrap, for tiers 1 and 2:

```
aad   = folder_id || key_id || u8(tier) || be64(epoch)           # exactly 57 bytes, in this order
info  = "licketysync/v1/wrap/data-key"                           # ASCII, no terminator
(enc, ct) = HPKE_Seal(kem_pk, info, aad, dk_epoch)               # KEM X-Wing, KDF HKDF-SHA256, AEAD ChaCha20-Poly1305, mode base
wrapped_data_key = enc || ct                                     # 1120 + 48
```

The holder unwraps with `HPKE_Open(xwing_sk, enc, info, aad, ct)` using the same `aad`
rebuilt from the grant's own fields, and accepts the result only after the grant's
signatures and chain have verified (section 5.4). Every wrap in this file (a grant's, the
Folder record's root wrap, a Rotation's `KeyWrap`, a Wrap record) is made to the `kem_pk`
of the key its `key_id` names (§0.4) and opens under the aad its own record names, and an
`HPKE_Open` failure is a hard error with no fallback key: the wrap sits in a validly
signed body, so it is a **signer fault** (`protocol.md` §5, `suites.md` §2.1): the holder
rejects the record locally, flags its signer, raises an issue and does not use the key,
and the connection stays open. Every key so unwrapped, from any record, is then checked
against its epoch's `confirm` value (the Folder record's for epoch 1, §2.2; the Rotation's
that created the epoch, §7.1) before any use; a mismatch is a signer fault of the record
that carried the wrap, with the same outcome. Only the holder can tell; other peers store
the record as usual. A sealed grant carries no wrap: a sealed key is never able to read,
and raising a sealed holder issues a new key at the higher tier whose grant carries the
wrap, and the device decrypts what it already holds. Deviation from the plan ("Fresh
keys": "every grant carries the wrapped data key"): sealed grants carry none, since the
sealed tier's whole point is that it cannot open the folder.

### 5.4 Verification of a grant

Input: a `SignedRecord`, the folder's Folder record, and the key records (grants,
rotations, wraps, revocations, suspensions, lifts) the verifier already holds for the
folder. Output: **store** (indexed by `key_id`; a key may come to hold several grants,
step 7) or **reject** with a cause; `protocol.md` §5 maps each cause to what happens on
the connection. A grant is stored whenever its signatures verify and its issuer resolves,
whether or not its issuer is currently valid and however long its chains are: validity
is a filter applied at use (5.5), not at storage, so that a late joiner can still
interpret a revoked writer's records up to their cutoff (section 7.2). A rejected record
is never stored or forwarded.

1. **Size, duplicate, then parse.** An encoded `SignedRecord` over `MAX_KEY_RECORD_BYTES`
   is malformed, judged first (5.1). A grant whose body is already stored (the same
   `record_hash`) is then a duplicate: ignored before anything else, its proof of
   possession not checked again. Otherwise `body` parses as a Grant; `suite` is
   implemented (else validity-only, §0.1) and `≥ minimum_suite`; `record_type = 2`; every
   bytes field has exactly the size in 5.3; `tier ∈ {1,2,3}`; `wrapped_data_key` is empty
   iff `tier = 3`; `epoch ≥ 1`; `key_id` equals
   `H("licketysync/v1/hash/id/key", be16(suite) || signing_pk || kem_pk)[0..16]`
   recomputed from the body, and is not `root_key_id`; `issuer_key_id` is not the grant's
   own `key_id` (a **self-grant**). Any failure: reject (malformed).
2. **Proof of possession.** `HybridVerify(signing_pk, "licketysync/v1/sig/grant-pop", body, key_signature)`
   with the grant's own `signing_pk`, before anything else is judged. A missing or failing
   `key_signature`: reject (forged), handled as any forged record (`protocol.md` §5);
   inside a FolderProof payload the answer is the uniform REJECTED (`protocol.md` §3.5).
3. **Folder.** `folder_id` equals the folder being verified; else reject (malformed).
4. **Epoch.** `epoch ≤` the folder's current epoch as this verifier knows it (in phases 0
   to 6, the epoch section 7 defines); a greater epoch means the rotation that created it
   has not arrived: the grant is a **missing dependency** (held or re-requested,
   `protocol.md` §4.6), never a rejection.
5. **Resolve the issuer.** If `issuer_key_id = root_key_id`, the issuer public key is
   `root_signing_pk` and the issuer has unlimited authority. Otherwise a grant for the
   issuer key must already be stored (any of them: every grant for one key ID carries the
   same public keys); if none is, the grant is a missing dependency (held or
   re-requested). The issuer's chains are not measured here: their length is judged at use
   (5.5), so a grant that has no chain within 16 grants is stored and is never
   chain-valid, rather than malformed.
6. **Signature.** `HybridVerify(issuer_signing_pk, "licketysync/v1/sig/grant", body, signature)`;
   failure: reject (forged). No step below runs on a record whose signatures have not
   verified, so none of them can blame a key for bytes it did not sign.
7. **Same key, another grant.** A different grant for a key ID already granted carries
   the same `signing_pk` and `kem_pk`, since the ID is derived from both, and its proof
   of possession shows that the key's holder agreed to it. It is **stored beside** the
   earlier one, and an issue names both issuers and both record hashes: a key with two
   grants is nobody's fault, since an issuer may re-issue a key at another tier or expiry
   with its holder, but it is worth the owner's eye. A key's chain validity, tier,
   `may_share` and expiry are then judged under its governing grant (5.5). A stored grant
   with that ID and other public keys would be a 128-bit hash collision (§0): the
   later-arriving grant is a **validity-only rejection** (not stored, the connection
   kept, an issue naming both issuers), never a close, since an honest relay may carry
   either. A cutoff or a Wrap may name a key whose grant has not arrived yet (7.2).
8. **Authority.** For a non-root issuer: `issuer.may_share = true` and
   `issuer.tier ≤ tier` (numerically; write may issue 1, 2 or 3, read 2 or 3, sealed
   only 3), judged under the issuer's governing grant. A failure here is the issuer's
   doing: reject and flag the issuer key.
9. **Revoked issuer.** Expiry and suspension of the issuer are not checked (4.2, 5.5). In
   phases 0 to 6 a grant whose issuer key is revoked, or none of whose issuer's chains
   (5.5) avoids a key revoked by a Revocation this verifier holds, is still stored and
   forwarded, with an issue naming that Revocation; its effect waits for phase 7, when
   Revocations are applied. Refusing it would make the stored set depend on arrival
   order: when R issues A, A issues W and root revokes R, a peer that held the Revocation
   before A's grant would refuse A's grant and then hold W's as a missing dependency for
   ever (ruling 20, 2026-10-17). Open item for phase 7: the cutoff semantics for
   intermediate issuers, which is also what bounds how much a revoked `may_share` key can
   make every peer store, settled by one of three options: store such a grant while a
   cutoff names a key whose grant is not yet stored; count held grants; or have cutoffs
   list the keys in between (7.2).
10. **Store.** Index by `key_id`; remember `issuer_key_id` for chain and cascade checks
    (5.5).

The holder of the seed additionally, after step 10, derives `KeyPairSet(seed)`, checks
that its `signing_pk` and `kem_pk` equal the grant's, and unwraps `dk_epoch` as in 5.3,
checking it against its epoch's `confirm` before use.

### 5.5 Chains, validity, presentability and effective tier

Two different questions are asked of a key, and they have different answers so that
peers converge on the same index while still refusing stale credentials at the door.
Both rest on the key's chains, which this section defines once for every rule in this
file and in `protocol.md`.

- **Chains.** A **chain** of a key is a sequence of stored grants `g_1, …, g_n` with
  `n ≤ 16`, where `g_1` is a grant for the key, each `g_(i+1)` is a grant for the issuer
  of `g_i`, the issuer of `g_n` is `root_key_id`, no key ID appears twice, and every link
  is **authorizing**: `g_(i+1)` has `may_share` and a tier at least as privileged as
  `g_i`'s (tier number ≤ `g_i`'s), so that a key issued under an issuer's temporary write
  grant cannot lean on that issuer's permanent read grant once the write grant has
  expired. A self-grant is malformed (5.4 step 1), and a grant to a key from one of its
  own descendants closes no chain, because the path back to the key would visit it twice.
  At the handshake, grants held for the connection (`protocol.md` §3.5) count as stored.
  A chain is **valid** when no key on it, the key itself included, is revoked by a stored
  Revocation that this release applies and none is under an active suspension with acting
  tier `none`; in phases 0 to 6 no Revocation, Suspension or Lift is applied (section 7),
  so there every chain is valid.
- **Ancestors.** A key's **ancestors** are the keys reachable from it along authorizing
  issuer links of stored grants within 16 links: key A, other than K, is an ancestor of
  key K when an authorizing walk of at most 16 links leads from a grant of K, through a
  grant of A, to root, repeats allowed and validity ignored; root is an ancestor of every
  key. "Ancestor", "beneath", "descends from" and every entitlement to revoke, suspend,
  lift or wrap anywhere in this file and in `protocol.md` use this set. It is found with
  two breadth-first passes over grants, one for each grant's distance from K's grants and
  one for its distance to root (A qualifies when the two add up to 16 or less for some
  grant of A), counting the key's own grant as 0 links from the key and a grant issued by
  root as 1 link from root, so that 16 links are a chain of 16 grants; so it costs
  polynomial time and every implementation reaches the same answer. Grants are never
  removed, so the set only grows as grants arrive: a record whose signer was entitled
  when it was stored stays entitled in every arrival order, which a rule over one chosen
  chain could not promise (a later, shorter chain would drop an ancestor).
- **Canonical chain.** Where one chain must be named, a key's **canonical chain** is its
  shortest chain, valid or not, and among equally short ones the one whose record
  hashes, read from the key towards root, are bytewise smallest, found by a
  level-by-level search bounded at 16 grants. It names the chain a push of the key's
  grant carries (`protocol.md` §4.6) and the chain along which suspensions weigh in a
  key's effective tier (below); nothing else depends on it.
- **Searches.** Whether some chain of a key is valid, or presentable (below), and its best
  presentable chain, are found by a search memoised per (grant, remaining depth), or
  equivalently per (key, remaining depth, tier the next link must authorize), never per
  (key, remaining depth) alone: an issuer may reach root through a read grant that cannot
  authorize a write child. A walk that repeats a grant contains a shorter chain that is at
  least as good, so every peer that holds the same grants finds the same answer, and depth
  never depends on the order in which grants arrived.
- **Chain-valid** (used when accepting records signed by the key): some grant of the key
  begins a valid chain. Its **governing grant** is, among the grants that begin a valid
  chain, the one with the most privileged tier, then `may_share`, then the later or
  absent expiry, then the numerically smaller `record_hash`; when none does, the same
  order over all its stored grants names the grant under which its records up to a
  cutoff are read. The governing grant decides the key's tier and `may_share` for record
  entitlement even when its chains differ, so a grant on a second branch can never raise
  them. A key none of whose chains is valid, or that has no chain within 16 grants, is
  not chain-valid: an index record it signs is a validity-only rejection (`protocol.md`
  §5), never malformed. A key that also has a valid chain avoiding a revoked key stays
  chain-valid (7.2), since both grants carry the key's own proof of possession. A
  Revocation or Suspension names the key ID and so covers every grant for it. Expiry is
  **not** part of chain validity (4.2): an expired key's records stay accepted; ending
  its writes takes a suspension or a revocation. A writer that is not chain-valid is
  still accepted **up to its cutoff**: records on the chain that a stored revocation or
  suspension names for it (7.2, 7.3) are applied, everything beyond is not, until a
  suspension ends and the writer's restart record continues the chain from the cutoff
  (7.3). Open items for phase 7: choosing the governing grant by effective tier, so that
  a suspension on the branch that granted it weighs in, and re-judging a writer's
  records when its governing grant changes.
- **Presentable** (used at the handshake and before the key issues, revokes, suspends,
  lifts or rotates): some chain-valid grant of the key begins a **presentable chain**, a
  valid chain every grant of which is unexpired at the device's wall clock and along
  which the effective tier (below) is not `none`; **and** the key's `suite ≥` the
  folder's `minimum_suite`. Any such chain will do: a key whose canonical chain holds an
  expired grant is still presentable through another, unexpired chain, and a key issued
  under a temporary grant of its issuer is presentable through it only until that grant
  expires. Its tier at the handshake is the effective tier of its best presentable chain
  (the most privileged; among equals, the order that picks the governing grant).
- **Effective tier**: along a chain, the numerically largest (least privileged) of the
  tier of the chain's first grant and the acting tiers of every active suspension on the
  key or on a key of that chain, where the acting tier `none` counts as **255**, greater
  than every tier, so that a suspension to `none` can never be outranked by the key's
  own tier (`max(1, none)` is `none`, not write). A write key whose issuer is suspended
  "acting as read" acts as read. Without a chain named, the key's effective tier is the
  numerically largest of its governing grant's tier and the acting tiers of every active
  suspension on it or on a key of its canonical chain, and that is what record
  entitlement uses, insensitive to expiry: only a key with effective tier 1 may sign
  index records that peers apply, and its issuing authority is its governing grant's
  (5.4 step 8); a presentable chain decides only whether the key may present, issue,
  revoke, suspend, lift or rotate at all, and its tier at the handshake. A key under any
  active suspension may not issue, revoke, suspend, lift or rotate.

## 6. The key string, QR code, link and file

What a person hands to another person is the folder ID and the seed, nothing else: the
grant is public and is fetched from the first peer met. A joiner with a bare string
derives its key pair set, both public halves and so its key ID from the seed (§0.4) and
presents that ID at the handshake (`protocol.md` §3.5); a peer that holds no grant for it
yet answers REJECTED, and the joiner retries later, once the grant has spread through the
folder's key records, or joins at once through a link that carries the chain (6.2). The
string is designed for QR codes and links, not for typing: a camera reads it in one go,
and the checksum catches a damaged scan or a stray edit.

### 6.1 Encoding: Bech32m

```
payload    = folder_id (32) || seed (32)                          # 64 bytes
key_string = Bech32m( hrp = "lsk", data = to_5bit(payload) )     # BIP-350
```

- Decision and reasons. The alternatives were Bech32m, z-base-32, Base58Check and
  Crockford base32. QR alphanumeric mode packs 45 symbols at 5.5 bits each, so any
  base-32 alphabet written in upper case fits it, while Base58's mixed case forces byte
  mode (8 bits per symbol). By the capacity table of ISO/IEC 18004 (table 7), 113
  Bech32m characters fit a version 4 code at error-correction level L (114
  alphanumeric characters) or a version 5 at level M (122), while Base58Check's 93 bytes
  need a version 5 at level L (106 bytes) or a version 6 at level M (106); the app
  generates level M. Bech32m's alphabet omits the
  confusable `1`, `b`, `i` and `o`, its checksum is a 30-bit BCH code chosen for error
  detection rather than a truncated hash, and it has a human-readable prefix so a pasted
  string is recognisable. z-base-32 has no checksum and Crockford's is one symbol.
- Length: `lsk` (3) + `1` (1) + 103 data characters + 6 checksum = **113 characters**.
  BIP-173 establishes its four-error detection guarantee only for strings up to 89
  characters; at 113 the code still detects every single-character error (a polynomial
  code with a non-zero constant term always does) and any other error with probability
  `1 - 2^-30`, which is what a damaged scan or a stray edit needs. Decoders must accept
  113 characters (the `bech32` crate's 90-character default limit is lifted).
- Case: entirely lower-case in text and links; entirely upper-case in QR codes (which
  is what alphanumeric mode needs); mixed case is rejected. The QR code carries the
  113-character upper-case string and nothing else by default.
- Decoding rejects: wrong prefix, bad checksum, a non-zero padding bit, any length that
  does not decode to exactly 64 bytes, or Bech32 (non-m) checksums.
- The seed in a decoded string is zeroised as soon as the key pair set is derived and
  stored.

### 6.2 Link form

A link carries the same string after `#`, where browsers never send it, and may add the
grant chain and, by choice, current addresses:

```
https://licketysync.dev/join#k=<key_string>[&g=<base64url(KeyBundle)>][&a=<multiaddr>]...[&c=<base64url(cert_hash)>]

message KeyBundle { repeated SignedRecord records = 1; }   // the Folder record, then a chain through which the key is presentable (its best presentable chain, 5.5), parent-first
```

Rules: a secret appears **only after `#`**, never in the path or query, and the client
never puts the fragment into a request, referrer or log. `g` lets a recipient join
through a peer that has not yet received the grant. `a` and `c` are appended only when
the issuer chooses, or automatically for browser invites and parcel links (phase 6).
Nothing in a link is trusted until the Folder record's ID matches `k` and the chain
verifies; `a` is a hint for dialling, never an identity.

### 6.3 File form

A key file is the link text, UTF-8, one line, with the extension `.lskey`. The app
registers the extension. The same rules apply as for the link; the file is deleted or
shredded by the recipient's app after import on request.

## 7. Rotation, revocation, suspension and lift (phase 7)

The formats are fixed now so that every record carries `suite` and `record_type` and a
phase 0 peer can store and forward records it does not yet act on. Peers in phases 0 to 6
run, for types 3 to 7, each procedure's parse, resolve-the-signer, signature and
entitlement steps (the cheap check that the signer is root, the issuer or an ancestor;
for a Lift, the Suspension's signer, root or an ancestor of that signer; for a Rotation,
root or a key that holds a stored grant of tier 1 or 2), **store and forward** what
passes, and raise an issue ("this folder uses records this release does not apply"); the
remaining steps are phase 7, and the phase 7 upgrade re-verifies every stored key record
under the full procedure. In phases 0 to 6 the folder's **current epoch**, for every
dependency check in this file and in `protocol.md` (a grant's `epoch`, a Rotation's
`new_epoch`, a Wrap's `epoch`), is the highest `e` for which a stored Rotation to each of
the epochs 2 to `e` exists, each having passed those steps (1 when there is none), so
that grants at later epochs and the rotations that follow are stored and forwarded rather
than held for ever as missing dependencies; a rival or stale rotation (7.1 step 1) passes
the same parse, resolve and signature steps before it is stored as evidence (decision
2026-10-17). Phases 0 to 6 ignore stored Revocations, Suspensions and Lifts in validity,
presentability and effective tier (5.5): such records are stored, forwarded and given the
cheap check above, never applied (ruling 21). Open item for phase 7: a folder that issues
a Revocation will require a feature in its `required_features`, so that peers of phases 0
to 6, which would not honour it, are refused the folder.

Who may sign what, in one table:

| Record | May be signed by | Effect | Cascade |
| --- | --- | --- | --- |
| Rotation (3) | Root; or the signer of the revocation or suspension-to-none it accompanies, when that signer holds a stored grant of tier 1 or 2 (validity ignored) | New epoch; wraps `dk_new` to every write and read key its `view` keeps and to root (7.1) | — |
| Wrap (4) | Root, the key's issuer, or an ancestor | Supplies `dk_e` to one key a rotation did not cover: issued concurrently, left outside a view, or back from a suspension | — |
| Revocation (5) | Root, the key's issuer, or any ancestor (5.5) | The key is dead forever on every peer that has the record; its records are kept up to the cutoff | Every key issued beneath it |
| Suspension (6) | Root, the key's issuer, or any ancestor | The key acts at a lower tier, or not at all, until `until` or a Lift; its records are kept up to the cutoff | Every key beneath it acts at most at the acting tier |
| Lift (7) | The Suspension's own signer, or root or an ancestor of that signer | Ends a suspension early | — |

Deviation from the plan ("Changing a device's tier": who may lift "follows the revocation
rule: the key's issuer, anything above it in its chain, and root"): a Lift may be signed
only by the Suspension's own signer, or by root or an ancestor of that signer, so that an
issuer cannot lift a suspension that a key above it signed (decision 2026-10-17).

A signer must be **presentable** (5.5) when it signs any of these. A verifier checks what
it can without the signer's clock: that the signer resolves, that its signature verifies,
and that it belongs to the set above by the stored grant chain. A signer outside the set
is a signer fault. What the verifier knows about the signer's own standing does **not**
change the outcome: a record whose signer is entitled is stored and applied even when
this verifier holds a Revocation or Suspension of that signer, with an issue naming the
signer, because validity is a filter at use (5.4, 5.5) and peers that learned of the
signer's revocation in different orders must still converge; the signer's revocation
cascades to everything beneath it in any case. Open item for phase 7: a revoked key so
keeps its signing authority over its descendants, and a Revocation of a key should cut
that key's own later key records, as a cutoff cuts its index records. Expiry is the
signer's own obligation, as for grants (4.2). In every procedure below the signature is
verified immediately after the signer is resolved and before any step whose failure is
charged to a signer, issuer or writer. Known cost: any `may_share` key can start a
rotation at will by issuing a throwaway child, revoking it and rotating with that
revocation as `cause`; the answer is to revoke the delegate. Cutoffs, shared by
Revocation and Suspension, are the wire message `Cutoff` of `protocol.md` §4.5:

```proto
message Cutoff { bytes key_id = 1; bytes device_id = 2; uint64 seq = 3; bytes head_hash = 4; }
// "From writer (key_id, device_id) keep exactly the chain that ends at the record with this seq and record hash";
// seq = 0 with head_hash empty keeps nothing from that writer. Everything else the writer signed is evidence.
```

A cutoff's **scope**: it applies to the writer `(key_id, device_id)` only once a grant
for that key is stored and the key is the revoked (or suspended) key itself or descends
from it; until then it is held with its record and has no effect. A cutoff naming a
writer outside that subtree is ignored and raises an issue against the revoker. A writer
inside the subtree that the record's list does not name has the implicit cutoff
`(0, empty)`. The record a cutoff's `head_hash` names is never a dependency (7.2).

### 7.1 Rotation body (type 3)

| # | Field | Type | Size | Meaning |
| --- | --- | --- | --- | --- |
| 1–3 | suite, record_type = 3, folder_id | | | |
| 4 | new_epoch | u64 | | The current epoch + 1 when signed; two rotations to one epoch are settled in step 7 |
| 5 | signer_key_id | bytes | 16 | Root, or the signer of `cause` |
| 6 | wraps | repeated KeyWrap | ≤ 4096, sorted by key_id | Exactly one per key with a grant in `kept` (step 6) plus one for root, and no other |
| 7 | ladder | bytes | 72 | `dk_{new-1}` under `dk_new` (§3.1) |
| 8 | cause | bytes | 32 or empty | Record hash of the Revocation or Suspension (to `none`) this rotation accompanies; empty only when root rotates with nobody excluded |
| 9 | issued_at | u64 | | |
| 10 | view | repeated bytes | 32 each, ≤ 8192, sorted | Record hashes of the key records (Grants, Revocations, Suspensions, Lifts) the signer held when it signed, less any it omitted under the cap rule below: the view the coverage rule is judged against |
| 11 | confirm | bytes | 32 | `derive_key("licketysync/v1/epoch/confirm", dk_new)`: lets every holder check it unwrapped the same key as everyone else |

```proto
message KeyWrap { bytes key_id = 1; bytes wrapped_data_key = 2; }  // 16; 1168 with aad = folder_id || key_id || u8(tier) || be64(new_epoch); tier = 0 for root, else the most privileged tier among that key's kept grants (step 6); sealed to the kem_pk of the key key_id names (root_kem_pk for root)
```

`wraps ≤ 4096` and `view ≤ 8192` are what make a rotation fit `MIN_MESSAGE_SIZE`
(`protocol.md` §2). Their consequences: the app refuses to issue a write or read key while
4096 are chain-valid, so that a rotation can always cover every key it must; and a signer
holding more than 8192 key records omits from `view`, in this order, grants of tier 3,
then the grants of keys it does not keep together with the records that exclude them (a
revoked key's grant with its Revocation), and never the grant of a key it keeps or of a key
in such a key's chain. A key whose grant is not in `view` is **outside the view**: the
rotation owes it no wrap and may carry none, and step 6 says what a verifier does when it
holds such a key.

Verification, in order; the cause of a failure maps to an action in `protocol.md` §5:

1. **Parse.** Sizes and bounds above; `wraps` sorted and unique; `view` sorted and
   unique; `cause` empty or 32 bytes; `ladder` 72 bytes; `confirm` 32. `new_epoch`
   against the verifier's current epoch `e`: `new_epoch = e + 1` is the normal case;
   `new_epoch > e + 1` is a missing dependency (an earlier rotation has not arrived);
   `new_epoch ≤ e` with a hash other than the rotation that created that epoch is a
   **rival rotation**: stored as evidence once steps 2 and 3 have passed (not applied,
   so it is not re-sent on every resync) and, when `new_epoch = e`, settled in step 7; a
   known hash is a duplicate.
   Failure of a size or bound: malformed.
2. **Resolve the signer.** `signer_key_id` is `root_key_id` (public key
   `root_signing_pk`) or names a stored grant; otherwise a missing dependency.
3. **Signature.** `HybridVerify(signer_pk, "licketysync/v1/sig/rotation", body, signature)`;
   failure: forged. No later step runs without it.
4. **Entitlement.** If `cause` is non-empty it names a stored Revocation, or a Suspension
   with acting tier `none`, signed by the same key (root included); a `cause` that names
   nothing stored is a missing dependency; one that names a record of another type or by
   another signer is a signer fault (reject, flag the signer). If `cause` is empty the
   signer must be root; any other signer with an empty `cause` is a signer fault. A
   non-root signer must hold a stored grant of tier 1 or 2, whatever its validity, so
   that the answer never depends on arrival order: a key granted only sealed cannot
   choose a folder's data key, so a sealed-only signer is a signer fault. A signer that
   is entitled but that this verifier knows to be revoked or suspended is applied with an
   issue naming it (section 7 intro), not rejected.
5. **View.** Every hash in `view` names a stored key record of type Grant, Revocation,
   Suspension or Lift; one the verifier does not hold is a missing dependency; one that
   names a stored record of another type is a signer fault. The view is closed under
   issuers: for every grant in it with a non-root issuer, the view holds a grant of that
   issuer that gives it a chain to root (5.5) lying wholly within the view; otherwise a
   signer fault (the signer built the list).
6. **Coverage.** Judged against the record's own declared inputs and nothing else. Let
   `kept` be every grant in `view` of tier 1 or 2 that itself begins a chain (5.5) lying
   wholly within `view` on which no key is named by a Revocation in `view ∪ {cause}`, nor
   by a Suspension to `none` in `view ∪ {cause}` that no Lift in `view` ends; it is
   judged per grant, not per key, so a key whose only surviving chain begins with a
   sealed grant has no grant in `kept`. Expiry, `until` and every record outside
   `view ∪ {cause}` play no part (TM-40): the verifier is checking what the signer did
   with what it declared, not what the verifier knows. The wraps are exactly one for
   every key with a grant in `kept`, at the most privileged tier among that key's kept
   grants, and one for `root_key_id`: a wrap for any other key ID (tier 3, a grant not in
   `view`, or a key that `cause` or a Revocation or Suspension-to-`none` in
   `view ∪ {cause}` excludes) is forbidden. A rotation that omits a key with a grant in
   `kept`, or carries a forbidden wrap, is a **lockout or leak attempt**: reject and flag
   the signer. Two further cases are not faults of the signer:
   - A wrap to a key with a grant in `kept` that this verifier knows to be revoked or
     suspended to `none` by a record outside `view ∪ {cause}`: the rotation is stored and
     applied as it stands, and the verifier raises the issue "epoch N reached revoked key
     X; rotate again", naming the rotator and that Revocation (or Suspension). The
     revocation's signer is a **losing concurrent revoker**: one whose revocation or
     suspension-to-`none` is named as `cause` by no applied rotation. Its app, on seeing
     the issue, signs a new Rotation to the then-current epoch + 1 with the same `cause`.
     What that buys, exactly: the revoked key has already read every epoch up to N
     through the ladder; the further rotation closes the epochs after it, and
     `rekey --full` is the remedy for what it read, which the app offers (TM-38).
   - A chain-valid write or read key this verifier holds whose grant is **outside the
     view**: the rotation is stored and applied, and the verifier raises the issue "key X
     awaits a wrap for epoch N; left out of the rotation by S", naming the signer `S`. The
     key's holder keeps reading the old epochs until a Wrap record (below) from root, the
     key's issuer or an ancestor arrives; the app of any such signer issues it on seeing
     the issue. Deviation from the plan ("Revocation and epochs": "a delegate cannot lock
     anyone out by leaving them off"): leaving a key out of the declared view cannot be
     prevented, because no verifier can prove what the delegate held; it is detected on
     every peer that holds the key, the issue names the delegate, and a Wrap repairs it,
     so the lockout lasts until the repair, not forever.
7. **Concurrent rotations.** When two rotations to the same `new_epoch` both pass steps
   1 to 6: if one's `cause` revokes or suspends to `none` the other's signer or an
   ancestor of it, that one wins; otherwise the one with the numerically smaller
   `record_hash` wins. The loser is stored as evidence and not applied; a verifier that
   had applied the loser un-applies it and applies the winner; the loser's `cause`, if
   any, is now named by no applied rotation, so its signer is a losing concurrent revoker
   and re-rotates as step 6 says. The choice is re-run when a Revocation arrives that
   revokes the applied rotation's signer while a rival for the same epoch is stored. A
   rival that arrives only after a later epoch has been built on the applied one stays
   evidence: peers then agree on the epoch chain by construction, not by this rule, and
   a rival that reached some peers first is the open item below. Open item for phase 7:
   records and chunks a writer sealed under a losing rotation's data key before it
   learned of the winner must be re-sealed and republished by that writer; the exact
   rule, how a reader tells such a seal from a writer fault in the meantime, and whether
   a later minor adds a `previous_rotation` field so that every rotation names the one
   it builds on, are settled when phase 7 implements rotation.
8. **Key confirmation.** A holder that unwraps its `KeyWrap` checks
   `derive_key("licketysync/v1/epoch/confirm", dk) = confirm` before any use (5.3); a
   mismatch means the rotator wrapped different keys to different recipients: the holder
   rejects the rotation locally, flags the signer and raises an issue, and does not use
   the key. Every holder runs this check, so a split epoch cannot go unnoticed. Only a
   confirmed `dk_new` opens this rotation's `ladder`; a ladder that then fails (a tag
   failure, or a recovered key that fails epoch `new_epoch - 1`'s `confirm`) flags the
   rotator (§3.1), and the holder does not adopt this rotation's `dk_new`.
9. A holder whose checks in step 8 passed records `dk_new` and climbs the ladder for any
   epoch it lacks, confirming each rung against that epoch's `confirm` (§3.1); one whose
   ladder check failed adopts nothing from this rotation.

**Wrap record (type 4).** Fields: 1–3; `4 key_id` (16); `5 epoch` (u64, `≤` the
verifier's current epoch); `6 wrapped_data_key` (1168, aad
`folder_id || key_id || u8(tier) || be64(epoch)`); `7 signer_key_id` (16); `8 issued_at`;
`9 tier` (u32, 1 or 2: the tier the aad uses, stated explicitly because a key may hold
grants at more than one tier). Label `licketysync/v1/sig/wrap`. Verification, in order:
parse (sizes; `epoch ≥ 1`; `tier ∈ {1, 2}`; an `epoch` above the current one is a missing
dependency); resolve the signer (root or a stored grant; else a missing dependency);
`HybridVerify` (failure: forged; no later step runs without it); a grant for the key is
stored (else a missing dependency, since a Wrap may travel ahead of the grant it serves)
and one of the key's grants has tier `tier` (else a signer fault; a Wrap for a key
granted only at tier 3 is a signer fault); the signer is root, the key's issuer under one
of its grants, or an ancestor of it (else a signer fault; what the verifier knows of the
signer's own standing raises an issue, not a rejection); **validity**, judged per grant:
the key needs a grant of tier `tier` that begins a valid chain (5.5) as this verifier
knows things; a Wrap for a key with none (revoked, or every such grant's chains passing a
revoked key or one under an active suspension to `none`) is a validity-only rejection
(reject, keep, push the record), since a Wrap is one key's share of a rotation and must
not reach a key the rotation itself may not; store. The wrap is sealed to the `kem_pk` of
the key `key_id` names. A holder that unwraps checks the key against the epoch's
`confirm` value before any use (5.3); a mismatch is a signer fault of the Wrap's signer.

### 7.2 Revocation body (type 5)

| # | Field | Type | Size | Meaning |
| --- | --- | --- | --- | --- |
| 1–3 | suite, record_type = 5, folder_id | | | |
| 4 | revoked_key_id | bytes | 16 | |
| 5 | signer_key_id | bytes | 16 | |
| 6 | cutoffs | repeated Cutoff | ≤ 4096, sorted by (key_id, device_id) | Per writer among the revoked key and its descendants: the last record kept, by `seq` and `head_hash`; a writer absent from the list keeps nothing |
| 7 | issued_at | u64 | | |

Verification, in order:

1. **Parse.** Sizes and bounds above; `cutoffs` sorted by `(key_id, device_id)` and
   unique; each cutoff has `head_hash` of 32 bytes and `seq ≥ 1`, or `seq = 0` with
   `head_hash` empty ("keep nothing from this writer"). Failure: malformed.
2. **Resolve the signer.** `signer_key_id` is root or names a stored grant; else a
   missing dependency.
3. **Signature.** `HybridVerify(signer_pk, "licketysync/v1/sig/revocation", body, signature)`;
   failure: forged. No later step runs without it.
4. **Revoked key.** Its grant is stored; else a missing dependency.
5. **Entitlement.** The signer is root, the revoked key's issuer under one of its
   grants, or an ancestor of it; else a signer fault (reject, flag the signer). A signer
   this verifier knows to be revoked or suspended is stored and applied all the same,
   with an issue naming it (section 7 intro). Expiry is the signer's own obligation
   (4.2).
6. **Store and apply.** A cutoff's writer grant and the record its `head_hash` names are
   **not** dependencies: a revoker may name a writer whose grant, or whose records, this
   verifier has not seen. Each cutoff takes effect under the scope rule of section 7:
   once a grant for the writer's key is stored and the key is the revoked key or beneath
   it, on that writer's records as they are held and as they arrive (`protocol.md` §4.4);
   a cutoff for a writer outside the subtree is ignored with an issue against the
   revoker. A duplicate (same `record_hash`) is ignored.

Effect: the revoked key, and every key all of whose chains pass through it, are no longer
chain-valid. A key that also has a valid chain avoiding the revoked key stays
chain-valid, and that is intended: the second chain needed the key's own proof of
possession (5.3), so its holder accepted the other issuer. Open items for phase 7: a
cutoff's scope narrowed to the writers the revocation leaves with no valid chain (today
it reaches every writer that descends from the revoked key, 5.5), and the gap
Revocation cutoffs leave for intermediate issuers, the keys between the revoked key and
the writers its cutoffs name. For each writer that is no longer chain-valid the peer
keeps exactly the records on the chain that ends at `(seq, head_hash)` and moves
everything else it holds from that writer to **evidence**: stored and forwarded (the
signature is the writer's, and other peers need the same bytes to reach the same state),
applied by no one, and the affected paths are re-evaluated from what remains. Every peer
therefore converges on the same set whatever order it learned things in, and a writer
that equivocated is cut back to the branch the revoker chose: a stored cutoff overrides
the equivocation withdrawal of `protocol.md` §4.4 for the chain it keeps; a Revocation's
cutoffs take precedence over every Suspension's for the same writer, and with several
Revocations a record is applied only if it lies on the chain of each one's cutoff
(`protocol.md` §4.4). A cutoff below a writer's applied head (the last record a peer
applies for it, `protocol.md` §4.4) is a **destructive act by the revoker**: records the
writer honestly made disappear from every peer, and the deletion brake and the archive
apply to every path the re-evaluation removes, exactly as for a deletion. The revoker's
app therefore defaults every known writer's cutoff to that writer's current applied head
and shows what a lower choice would remove; since a writer absent from the list keeps
nothing, the app lists every writer it knows under the revoked key. A revocation must be
accompanied by a Rotation (7.1) whose `cause` names it before peers treat the folder as
current; until then they raise an issue. A key ID names one public key for ever (§0.4),
so a revoked ID stays dead: a later grant for the same key is covered by the Revocation
and is never chain-valid.

### 7.3 Suspension (type 6) and Lift (type 7)

Suspension:

| # | Field | Type | Size | Meaning |
| --- | --- | --- | --- | --- |
| 1–3 | suite, record_type = 6, folder_id | | | |
| 4 | key_id | bytes | 16 | |
| 5 | acting_tier | u32 | 2, 3 or 0 | Read, sealed, or `0` = none (counts as 255 in §5.5) |
| 6 | until | u64 | | `0` = until lifted |
| 7 | signer_key_id | bytes | 16 | |
| 8 | issued_at | u64 | | |
| 9 | cutoffs | repeated Cutoff | ≤ 4096, sorted | As in 7.2: the last record kept from each affected writer. A Lift and a restart record name this Suspension by its `record_hash` |

Verification of a Suspension, in order, mirroring 7.2: (1) parse: sizes and bounds
above, `acting_tier ∈ {0, 2, 3}`, `cutoffs` sorted and unique with each entry as in 7.2
step 1 (failure: malformed); (2) resolve the signer (root or a stored grant; else a
missing dependency); (3) `HybridVerify(signer_pk, "licketysync/v1/sig/suspension", body, signature)`
(failure: forged; no later step runs without it); (4) a grant for the suspended key is
stored (else a missing dependency); (5) the signer is root, the key's issuer under one of
its grants, or an ancestor of it (else a signer fault); a signer this verifier knows
revoked or suspended is applied with an issue (section 7 intro); (6) store and apply:
cutoff writers and `head_hash` records are not dependencies and the scope rule of
section 7 applies (7.2 step 6). A Suspension is named by its `record_hash`; two
suspensions of one key are two records, each with its own cutoffs.

Lift: fields 1–3; `4 suspension` (32: the `record_hash` of the Suspension it ends);
`5 signer_key_id` (16); `6 issued_at`; label `licketysync/v1/sig/lift`. Verification, in
order: parse (malformed); resolve the signer (missing dependency); `HybridVerify`
(forged; no later step runs without it); the Suspension named by `suspension` is stored
(else a missing dependency); the signer is the Suspension's own signer, or root or an
ancestor of that signer (else a signer fault; one known revoked or suspended: applied
with an issue); store and apply.

Effect: while active (`now < until` or `until = 0`, and no Lift), the key and every key
beneath it have effective tier at most `acting_tier` (5.5). Records from an affected
writer are kept exactly up to its cutoff, as for a revocation, and everything else it
holds from that writer becomes evidence; records beyond the cutoff are **rejected, not
deferred**, which is what the plan promises ("peers reject changes the suspended key
signs in that window"). The suspended device, once it learns of the suspension, stops
writing and shows the issue. After a Lift, or once `until` has passed, the writer
continues its chain from the cutoff head: its next record names the cutoff's `head_hash`
as `previous` (empty, with `seq = 1`, after the implicit cutoff `(0, empty)` of a writer
the list did not name, or after a cutoff that kept nothing), has `seq = cutoff.seq + 1`,
and carries the Suspension's `record_hash` in `resumes` (`protocol.md` §4.4), which tells
every peer, including one that saw it write in the window, that this is the legitimate
restart and not a second history; whatever it signed in the window is abandoned and never
applied anywhere. There is exactly **one restart per Suspension**: a second record at
`cutoff.seq + 1` naming the same Suspension with a different hash is equivocation. The
restart's successors follow it under the ordinary chain rules. A writer always sets
`resumes` on that record, whether or not it wrote in the window, because it cannot know
what others saw. When a writer is under several cutoffs, a Revocation's take precedence
over every Suspension's, and among Suspensions the one with the highest `seq` this peer
holds binds, re-evaluated when another arrives; a Suspension's cutoff is continued only
by the restart that names it, a Revocation's by nothing (`protocol.md` §4.4). Peers that
learned of the suspension at different moments may disagree
about window records until the cutoff reaches them, and a peer whose clock has not yet
passed `until` rejects the restart until it has; those disagreements are rejections that
never close a connection (`protocol.md` §5). Suspension does not rotate the epoch unless
it is to `none` and accompanied by a Rotation: it is enforced by peers, not by
cryptography, which is why lowering someone for good is a revocation. When a suspension
to `none` that was accompanied by a Rotation ends, by a Lift or by `until`, the key and
every key beneath it hold no data key for the epochs created since; the signer of the
Lift (or, at `until`, of the Suspension) owes each of them a Wrap (7.1) for the current
epoch, from which the ladder reaches the rest, and its app issues those Wraps as soon as
the suspension ends.

## 8. Linked devices and root holders

A person's devices form a set that shares a catalogue of folders and tiers; new devices
join by scanning a code, and the owner's secret moves only to devices the owner marks as
root holders, over the same encrypted device-to-device channel, or as a passphrase file,
or as the phrase on paper.

### 8.1 Linking a device (phase 5)

The new device shows a **link code**: `Bech32m(hrp = "lsl", data = device_id (32) || link_secret (32))`,
113 characters like a key string, where `link_secret` is 32 fresh random bytes. An
existing linked device scans it and connects over the LAN, announcing
`derive_key("licketysync/v1/link/discovery", link_secret)[0..16]` as the beacon ID. The
ordinary handshake runs (`protocol.md` §3, Hello and device proof); then each side sends
a link proof `BLAKE3_keyed(derive_key("licketysync/v1/link/confirm", link_secret), th || role)`
over the transcript hash `th`, so that only the device whose screen was scanned and the
device that scanned it can complete the link. The existing device then sends, over the
encrypted channel:

| Item | Moves | Notes |
| --- | --- | --- |
| Identity seed (32) | Always | The new device derives the identity set and the catalogue key |
| Catalogue | Always | Every folder any linked device knows, the tier each holds, addresses; encrypted under the catalogue key |
| Per-folder issued key seeds | Per the new device's choice (Full, Selective, Sealed, Not on this device) | Minted by the existing device from a `may_share` key it holds, or by root; one key per device |
| Master secret (32) | Only on "Make this device a root holder", confirmed on the sending device | The new device becomes a root holder; it now derives every root key itself |

Message types for linking are reserved in `protocol.md` §4.1.

### 8.2 Exported root file (phase 3 or later)

`owner export` writes an **age v1** file whose payload is:

```proto
message OwnerExport { uint32 version = 1; bytes master_secret = 2; bytes catalogue = 3; uint64 created_at = 4; }
```

encrypted with age's passphrase recipient (scrypt, as the age specification defines it,
work factor at least 18, a fresh salt) so that the file can be opened by the standard
`age` tool. Deviation from the plan ("Argon2id for passphrases"): this is the one
passphrase in Lickety-Sync that is not under Argon2id, because age's passphrase mode
is scrypt with no Argon2id recipient, so the file uses age as it is (aligned with
`suites.md` §2). Argon2id is the password hash everywhere else a passphrase protects a
secret, such as the local key store on a platform with no keystore (parameters in
`suites.md`). The catalogue snapshot lets a restore onto a bare machine
know which folders exist and whose addresses to try.

### 8.3 Paper form

The 24 words, numbered, one per line, with the folder IDs of the root-held folders
optionally listed beneath (they are public). Re-entry validates the BIP39 checksum.
Nothing else is needed: folder nonces come from any peer's Folder record.

### 8.4 Where secrets rest

| Secret | Devices | At rest |
| --- | --- | --- |
| Master secret / phrase | Root holders only | Platform keystore (Keychain, Credential Manager, Secret Service, Android Keystore) |
| Identity seed | Every linked device | Platform keystore |
| Device seed | That device | Platform keystore |
| Issued key seeds, data keys, epoch ladder | Devices using them | Encrypted store under a key from the platform keystore |

All of these live in `zeroize`d types in memory and never reach logs.

## 9. Test vectors the keys crate must publish

The crate author generates these with the reference implementation and checks them in
as data files; reviewers re-derive them independently where a second implementation
exists (BLAKE3, Ed25519 and HPKE have official vectors; ML-DSA vectors use the
deterministic variant).

1. **Phrase**: a fixed 32-byte `ms`, its 24 words, and three malformed phrases (bad
   checksum, 23 words, a word not in the list) that must be refused.
2. **Master derivations**: `identity_seed`, the identity signing and KEM public keys, the
   identity ID; `root_seed` for a fixed `folder_nonce`, the root public keys and
   `folder_id`.
3. **Key pair set**: for a fixed 32-byte seed, the Ed25519, ML-DSA-65 and X-Wing public
   keys, the derived key ID over `be16(suite) || signing_pk || kem_pk`, the ID the same
   seed would get if only `signing_pk` were hashed (which must differ, so an
   implementation that leaves out `kem_pk` fails), and the 1986-byte Hello wire form
   `be16(suite) || signing_pk`.
4. **Device**: a fixed device seed, its device ID, its libp2p identity public key and the
   libp2p peer ID of that key, and its DHT key.
5. **Discovery**: `peer_tag` and `lan_id` for a fixed salt, folder, announcer key and
   minute; a beacon one minute outside the ±5 minute window, refused; a peer tag that
   does not match the authenticated identity, refused; `dht_id` for a fixed day and the
   two neighbours.
6. **Epoch keys**: for fixed `dk_1` and `dk_2`: `ck`, `nk`, `rk`, the ladder key, `hk`;
   one ladder link with a fixed nonce that recovers `dk_1`.
7. **Chunk**: a fixed raw chunk under epoch 1 with compression 0: `plain_hash`, padded
   length, nonce, `stored` bytes and `cipher_hash`; one corrupt variant per failure path
   (bad tag, non-zero padding, payload length over L', empty payload, unsupported
   compression code, a stored length that is not a Padmé length, a stored length over
   the bound, bad plain hash).
8. **Padmé**: the six values in 3.4 plus 1 000 random lengths against a reference.
9. **Folder record**: canonical body bytes (with `confirm` for the vector's `dk_1`),
   `record_hash`, and a signature that verifies (deterministic ML-DSA), plus the root
   wrap with a fixed HPKE ephemeral seed; a second record for the folder with another
   body (signer fault against root), and one naming another folder's `folder_id`
   (malformed).
10. **Grant**: one grant per tier from root and one write grant from a `may_share` write
    key, each with body bytes, hash, both signatures (the issuer's and the issued key's
    proof of possession), and (for tiers 1 and 2) the wrap with a fixed ephemeral seed
    that unwraps to the vector's `dk_1`; rejected variants for every numbered step of 5.4
    (wrong size, a self-grant whose `issuer_key_id` is its own `key_id`, a `key_id` that
    does not recompute from `signing_pk || kem_pk` and one whose `kem_pk` alone was
    swapped, an all-zero `key_id`, a missing `key_signature`, one made by another key and
    one over another body (all forged), folder ID of another folder, suite below
    `minimum_suite`, epoch beyond the current one, issuer lacking `may_share`, issuer
    tier too low, bad issuer signature, sealed grant with a wrap, write grant without
    one), the bad-signature variant also carrying a bad tier so the test shows the
    signature is judged first, and a non-grant record carrying a `key_signature`
    (malformed); in phases 0 to 6 the revoked-issuer chain (R issues A, A issues W, root
    revokes R) with A's grant arriving after the Revocation: stored with an issue, so W's
    grant is stored too; a second grant for the same key at another tier (both stored,
    the issue, and the governing grant); a tie between two grants equal in tier,
    `may_share` and expiry, settled by the smaller `record_hash`; a descendant re-grant
    (key A issues B, B issues a further grant to A: stored, begins no chain, never
    governs); a chain of exactly 16 grants (chain-valid) and one of 17 (stored, not
    chain-valid: a record under its leaf is a validity-only rejection); a key on two
    chains that survives the revocation of a key on one; an issuer with a valid chain
    through its read grant and a revoked chain through its write grant, whose write child
    is not chain-valid (a search memoised per key alone would wrongly find it valid); a
    key whose canonical chain holds an expired grant but which has another unexpired
    valid chain at a lower tier (presentable at that chain's tier, its index records
    still judged under the governing grant); a key K issued at write by an issuer that
    holds a temporary write grant with `may_share` and a permanent read grant (K
    presentable at write before the temporary grant expires and not presentable after,
    since the read grant cannot authorize a write link); two equally short chains whose
    canonical one is picked by record hashes, and the chain a push carries; a key that
    lies only on the longer of two chains and is still an ancestor of the key at their
    foot; a grant whose body is already stored, ignored as a duplicate even when its
    `key_signature` is corrupt; a grant whose body repeats the singular `tier` field
    (malformed); a wrap that fails to open under an aad with any one of folder ID, key
    ID, tier or epoch changed, and one that opens to a key that fails its epoch's
    `confirm` (both signer faults the holder finds, 5.3).
11. **Key string**: the Bech32m string for a fixed folder ID and seed in lower and upper
    case; rejected variants (mixed case, one flipped character, wrong prefix, Bech32
    checksum, 63- and 65-byte payloads); the link and file forms.
12. **Handshake inputs** (shared with the protocol crate's vectors): the transcript hash,
    folder hint, proof key, the sealed proof for a fixed 24-byte nonce, and both proof
    signatures for fixed Hellos.
13. **Rotation, Wrap, Revocation, Suspension, Lift** (phase 7, formats only now): one
    canonical body and hash each, the rotation's `confirm` value for the vector's `dk_2`,
    a Lift naming the Suspension's `record_hash`, so that phase 0 peers prove they store
    and forward them and run the cheap entitlement check; for phase 7's verifier: a
    Rotation that omits a key with a grant in `kept`, one that wraps a key outside its
    `view`, and one that wraps the key its `cause` revokes (all signer faults), one whose
    wrap reaches a key revoked outside its view (applied, with the issue), two concurrent
    rotations settled by `cause` and two settled by record hash, a ladder whose recovered
    key fails the previous epoch's `confirm` (rotator flagged), a Wrap for a key known
    revoked (validity-only), a Suspension with cutoffs and the one restart record that
    names it, a second restart (equivocation), a sealed `may_share` key that revokes its
    own child and then rotates (signer fault, and no holder adopts its data key), a
    rotation whose ladder fails for a holder (that holder adopts nothing from it), the
    sealed survivor (key K's read grant lies on a branch the rotation's `cause` revokes
    and its only surviving chain begins with a sealed grant of K: K has no grant in
    `kept`, and a rotation that leaves it out is no fault), a Lift signed by the
    suspended key's issuer for a Suspension that root signed (signer fault), and, for
    phases 0 to 6, a dense chain of rotations to epoch 3 that lets a grant at epoch 3 be
    stored; and the ancestry order case: root grants S, S grants I, I grants K, S revokes
    K, and root then grants K directly, the Revocation by S staying entitled whichever of
    it and root's grant arrives first (S still reaches K through I, 5.5).

## 10. Label registry

Every label in use, in one place. Adding a label is a change to this table.

The modes are the ones `suites.md` §2.4 fixes: `derive_key` only from uniformly random
key material; the labelled hash `H` for identifiers over public data, the four
identity hashes of §0.4 included; keyed BLAKE3 where the output must mean nothing
without the key; the signature prefix `M`.

| Label | Mode | Material / input | Output |
| --- | --- | --- | --- |
| `licketysync/v1/identity/seed` | derive_key | master secret | identity seed |
| `licketysync/v1/identity/catalogue-key` | derive_key | identity seed | catalogue XChaCha key |
| `licketysync/v1/folder/root-seed` | derive_key | master secret \|\| folder nonce (64 bytes) | root seed |
| `licketysync/v1/folder/chunk-hash-key` | derive_key | `dk_1` | `hk` |
| `licketysync/v1/key/ed25519` | derive_key | any key seed | Ed25519 seed |
| `licketysync/v1/key/ml-dsa-65` | derive_key | any key seed | ML-DSA-65 ξ |
| `licketysync/v1/key/x-wing` | derive_key | any key seed | X-Wing decapsulation seed |
| `licketysync/v1/key/libp2p-identity` | derive_key | device seed | Ed25519 seed of the libp2p identity (§1.3) |
| `licketysync/v1/key/dht-bep44` | derive_key | device seed | Ed25519 seed of the BEP 44 DHT signing key (§1.3, phase 2) |
| `licketysync/v1/epoch/chunk-key` | derive_key | `dk_e` | `ck_e` |
| `licketysync/v1/epoch/chunk-nonce-key` | derive_key | `dk_e` | `nk_e` |
| `licketysync/v1/epoch/record-key` | derive_key | `dk_e` | `rk_e` |
| `licketysync/v1/epoch/ladder-key` | derive_key | `dk_e` | key over `dk_{e-1}` |
| `licketysync/v1/epoch/confirm` | derive_key | `dk_e` | key-confirmation value in the Rotation (§7.1) and, for `dk_1`, in the Folder record (§2.2) |
| `licketysync/v1/link/discovery` | derive_key | link secret | link beacon ID (16) |
| `licketysync/v1/link/confirm` | derive_key | link secret | keyed-BLAKE3 key for the link proof |
| `licketysync/v1/hash/id/folder` | `H` | be16(suite) \|\| root signing public key | folder ID (§0.4) |
| `licketysync/v1/hash/id/device` | `H` | be16(suite) \|\| device signing public key | device ID |
| `licketysync/v1/hash/id/identity` | `H` | be16(suite) \|\| identity signing public key | identity ID |
| `licketysync/v1/hash/id/key` | `H`, first 16 bytes | be16(suite) \|\| issued signing public key \|\| issued KEM public key | key ID (§0.4) |
| `licketysync/v1/hash/record` | `H` | record body | record hash |
| `licketysync/v1/hash/chunk` | `H` | stored chunk blob | `cipher_hash` |
| `licketysync/v1/hash/discovery-peer` | `H` | salt (16) \|\| announcer libp2p identity key (32) | peer tag (16) in the LAN beacon (§2.3) |
| `licketysync/v1/hash/discovery-lan` | `H` | salt \|\| folder ID \|\| peer tag \|\| be64(minute) | LAN beacon ID (16) |
| `licketysync/v1/hash/discovery-dht` | `H` | folder ID \|\| be64(day) | DHT ID (20) |
| `licketysync/v1/hash/transcript` | `H` | protocol ID, both libp2p identity keys, both Hellos | transcript hash (`protocol.md` §3.3) |
| `licketysync/v1/handshake/folder-hint` | keyed, key = folder ID | label \|\| 0x00 \|\| transcript hash \|\| role | folder hint |
| `licketysync/v1/handshake/proof-key` | keyed, key = folder ID | label \|\| 0x00 \|\| transcript hash | XChaCha key over the proof payload |
| `licketysync/v1/sig/folder`, `grant`, `rotation`, `wrap`, `revocation`, `suspension`, `lift`, `root-rotation`, `index` | prefix of `M` | record body | signed message |
| `licketysync/v1/sig/grant-pop` | prefix of `M` | grant body | signed message: the issued key's proof of possession over its own grant (§5.3) |
| `licketysync/v1/sig/folder-proof` | prefix of `M` | folder ID \|\| key ID \|\| transcript hash \|\| role | signed message (`protocol.md` §3.5) |
| `licketysync/v1/sig/device-proof` | prefix of `M` | transcript hash \|\| role | signed message |
| `licketysync/v1/wrap/data-key` | HPKE `info` | — | — |

## 11. Phase map

| Section | Phase |
| --- | --- |
| 0, 1.1, 1.2 (root seed), 1.3, 1.4, 2.1, 2.2, 3, 4, 5 | 0 |
| 6 (key string, link, file), 2.3 LAN | 1 |
| 2.3 DHT; sealed tier in use | 2 |
| 8.2 export, 8.3 paper | 3 or later |
| 1.2 identity and catalogue, 8.1 linking | 5 |
| 6.2 parcel links | 6 |
| 7 (rotation, wrap, revocation, suspension, lift), root rotation, raising `minimum_suite`, moving a folder to another suite (undesigned; until then the Folder record's `suite` is the folder's current suite) | 7 |
