# Lickety-Sync sync protocol, major version 1

Status: draft for phase 0, 2026-10-14. This file is what `licketysync-protocol`,
`licketysync-index` and `licketysync-engine` implement on the wire, and what reviewers
check them against. `keys.md` defines every key, record and derivation this file uses;
`suites.md` the algorithms; `threat-model.md` the adversaries. Each section says in
plain words what it is for, then defines it exactly. "Phase N" marks what phase 0
("simulated peers converge") may leave out; the formats are fixed now.

Every byte that arrives from a peer is untrusted: lengths are checked before anything
is allocated, every collection a peer can grow is bounded, every decoder is fuzzed, and
nothing is ever silently skipped: section 5's table says, for every failure, whether it
closes the connection (malformed or forged input, the sender's fault), is rejected while
the connection stays open (a difference in what the two peers know), or is charged to
the writer whose signature covers it (flagged under Issues). **Issues** is the list of
problems a device shows its owner (the plan's Issues panel); every outcome in section 5
that says "issue" adds one that names its cause.

## 1. Protocol identifier and major versions

The protocol name carries its major version, and libp2p's protocol negotiation picks
the newest one both sides list. Within a major, everything new is optional: a new
message type with the critical bit clear, a new field, a new feature flag. A major
changes only when the handshake or the meaning of index records changes.

- Identifier: `/licketysync/sync/1`. A device may list several majors
  (`/licketysync/sync/2`, `/licketysync/sync/1`); the dialer lists them newest first and
  multistream-select picks the first one the listener also supports.
- Two devices with no major in common get a negotiation failure. The dialer reports it
  under Issues naming the versions it offered and, when the listener's list is known,
  the versions it saw; the site publishes which release speaks which major.
- This document is major 1. Minor evolution is by feature flags in Hello (section 4.2)
  and by Protocol Buffers' own rule that unknown fields are skipped.
- Phase 0: the simulator's transport hands each connection the string
  `/licketysync/sync/1`; nothing else is negotiated.

## 2. Framing

Every message is a length, a type and a Protocol Buffers body. The length comes first
so the receiver can refuse an oversized frame before it reads or allocates anything for
it; the type carries a critical bit so that a receiver that does not know a type knows
whether it may ignore it.

```
+----------------+----------------+------------------------+
| length  u32 BE | type  u16 BE   | body (length - 2 bytes)|
+----------------+----------------+------------------------+
length  = 2 + len(body)
type    = critical (bit 15) | number (bits 0..14)         # 0x8000 | n for critical types
```

Receiving, in this order and with no allocation for a frame before step 3 (the bytes
arrive in pieces of any size, 3.1; the frame decoder works through them):

1. Read exactly 4 bytes; `length` is the value.
2. If `length < 2`: send `Close(PROTOCOL_ERROR)` and close. If `length > limit`
   (defined below): send `Close(MESSAGE_TOO_LARGE)` and close without reading further.
3. Read `length` bytes, growing the frame's buffer as they arrive and never past
   `length`; when the frame is complete, split off the type.
4. Dispatch on the type: known type → decode the body with that type's schema; decode
   failure → `Close(PROTOCOL_ERROR)`. Unknown type with the critical bit set →
   `Close(UNSUPPORTED_CRITICAL_TYPE)`. Unknown type with the bit clear → send
   `Unsupported { message_type }` and continue. The first frame on a connection must be
   a Hello or a Close; any other type first, known or unknown, is `Close(PROTOCOL_ERROR)`.
   Until the peer's DeviceProof has verified, the only frames accepted are that one Hello,
   that one DeviceProof and Close: any other frame, an unknown non-critical type included,
   is `Close(PROTOCOL_ERROR)`, not `Unsupported` (section 3.2 takes precedence here).
   Frames are decoded and dispatched one at a time, each dispatched before the next is
   decoded, and nothing after a Close, sent or received, is processed.

Limits:

| Name | Value | Meaning |
| --- | --- | --- |
| `PRE_HELLO_LIMIT` | 65 536 | Applies to every frame received on a connection until the peer's DeviceProof has verified (its Hello, its DeviceProof or a Close), and to anything sent before the peer's Hello has arrived. The largest Hello is a frame of 4 617 bytes (length field included, 4 621) and a DeviceProof one of 3 378 (3 382), so both fit |
| `MIN_MESSAGE_SIZE` | 8 388 608 (8 MiB) | The smallest `max_message_size` a Hello may advertise; a smaller one is `Close(LIMIT_TOO_SMALL)` |
| `DEFAULT_MESSAGE_SIZE` | 16 777 216 (16 MiB) | What a device advertises unless configured otherwise |
| `MAX_MESSAGE_SIZE` | 67 108 864 (64 MiB) | The largest value a Hello may advertise; larger is treated as this value |
| `MAX_INDEX_RECORD_BYTES` | 4 000 000 | The largest encoded `SignedRecord` carrying an index record; a larger one is malformed at parse, before any duplicate check |
| `MAX_KEY_RECORD_BYTES` | 6 000 000 | The largest encoded `SignedRecord` carrying a key record (Folder, Grant, Rotation, Wrap, Revocation, Suspension, Lift); a larger one is malformed at parse, before any duplicate check |

- The limit for **incoming** frames is the receiver's own advertised `max_message_size`
  (what it told the peer it accepts), except that every frame received before the peer's
  DeviceProof has verified is also bounded by `PRE_HELLO_LIMIT`. The limit for
  **outgoing** frames is the peer's advertised value; a sender never emits a frame larger
  than that, and before the peer's Hello arrives it sends only Hello and Close.
- `MIN_MESSAGE_SIZE` is set so that one `ChunkReply` carrying the largest chunk
  (`MAX_CHUNK_PLAINTEXT` = 4 MiB plus Padmé and framing, `keys.md` §3.3), one index
  record with the most chunks (section 4.4: 32 768 chunk references of about 45 encoded
  bytes each, a sealed part of at most 1.5 MiB, a full version vector and the signature,
  about 3 MiB in all, and two of them, since one writer's records at one sequence are
  never split across pages, section 4.5) and one Rotation with its 4096 wraps and 8192
  view entries (`keys.md` §7.1, about 4.9 MiB) each always fit. The record caps make
  that hold for any record a peer accepts, unknown fields included: two index records
  at `MAX_INDEX_RECORD_BYTES` (8 000 000 bytes) or one key record at
  `MAX_KEY_RECORD_BYTES` fit one page of `MIN_MESSAGE_SIZE`, so no peer can be handed a
  record that another peer's advertised limit cannot carry, and a field that would make
  records grow past a cap is added only behind `required_features` (section 6). Every
  message that carries a list is additionally bounded by the peer's
  `max_message_size`: a sender pages before it reaches it.
- The body of every message is proto3 (`syntax = "proto3"`), package `licketysync.v1`.
  The protocol crate mirrors the schemas in section 4 with prost derives; the `.proto`
  text in this file is normative, the crate's generated types are the implementation.
- **Every decoder judges a body the same way.** A field number above 2^29 − 1
  (536 870 911) is malformed, and so is a field, known or unknown, with a group wire type
  (3 or 4); every other unknown field is skipped (and, inside a signed body, kept and
  forwarded, `keys.md` §5.2). Both rules are fixed because a signed body must be accepted
  or refused alike by every implementation: a record that one decoder skipped over and
  another refused would split peers. For the same reason a field that is not repeated and
  occurs more than once in a body is malformed (proto3 would keep the last occurrence; a
  verifier here refuses, so that a grant carrying tier 3 and then tier 1 means nothing to
  anyone), while a repeated scalar field is accepted packed or unpacked, as proto3 allows
  (producers pack, `keys.md` §5.2), or partly each, the values concatenated in the order
  they appear. Every fixed-size field (hashes, key IDs, device IDs, nonces, public keys,
  signatures) must be present at its exact size, unless its field says it may be empty
  (such as `previous` at `seq` 1, `resumes`, a `head_hash` at applied head 0, or
  `issuer_device_id`); an absent field reads as empty, which is then the wrong size, so
  it is malformed.

## 3. The handshake

Seven steps, as the plan draws them. Steps 1 and 2 belong to libp2p: the encrypted
channel, with exactly one security protocol per transport so that nothing is chosen
before either side is authenticated (TLS 1.3 on QUIC and on TCP; Noise inside WebSocket,
WebRTC and WebTransport, where TLS is not offered; `suites.md` §2.6), then protocol
negotiation; phase 0 simulates them. Steps 3
to 7 are this protocol. The folder proof in step 4 is the heart of it: each side shows
it holds an issued key for a folder without sending the key, without naming the folder
to anyone who does not already have it, and in a way that cannot be replayed into
another connection. Nothing about a folder leaves a device until the peer has proven
membership of that folder, and a failed proof is answered with the same result whether
the folder is unknown here or the proof was bad.

```
A (role 0x01)                                            B (role 0x02)
 1. encrypted channel  ──────────────── (libp2p: TLS on QUIC or TCP; Noise inside WebSocket, WebRTC, WebTransport)
 2. identify           ─── /licketysync/sync/1 ──────▶ newest common major
 3. Hello ───────────────────────────────────────────▶
    ◀──────────────────────────────────────────── Hello     roles are now known (3.2)
    DeviceProof ─────────────────────────────────────▶
    ◀─────────────────────────────────────── DeviceProof
 4. FolderProof(X) ──────────────────────────────────▶ verify; if X is here and valid:
    ◀────────────────────────── ProofResult(X, ACCEPTED), FolderProof(X)
    ProofResult(X, ACCEPTED) ────────────────────────▶ X is open on this connection
 5. KeyRecords(X) ◀──────────────────────────────────▶ KeyRecords(X)
    IndexRequest(X, cursors) ◀──────────────────────▶ IndexRequest(X, cursors)
    IndexRecords(X, …, more) ◀──────────────────────▶ IndexRecords(X, …)
 6. ChunkRequest(X, cipher_hash) ────────────────────▶
 7. ◀──────────────────────────────── ChunkReply(X, cipher_hash, data)
    Status ◀────────────────────────────────────────▶ Status   (periodic, non-critical)
```

### 3.1 Steps 1 and 2: channel, identity and version

**Transport contract.** This protocol runs over one reliable, ordered byte stream per
connection (a QUIC stream, a TCP connection, a WebTransport or WebRTC stream, or the
simulator's channel). The transport carries bytes, not frames: sending appends bytes, and
delivery hands over the next bytes with arbitrary chunk boundaries (at most 64 KiB at a
time), so the engine's frame decoder, the protocol crate's, assembles frames and enforces
every size limit of section 2 (`PRE_HELLO_LIMIT`, `max_message_size`), and nothing is
allocated for an oversized frame. While a connection lasts its bytes are never lost,
duplicated or reordered; when it ends, whatever the other side had not yet received may
be lost, and neither side can tell which. Loss therefore shows itself only as the
connection ending (`on_disconnected`), after which every per-connection table is freed
and a new connection starts from Hello. Across connections nothing is ordered. The
runtime may end a connection whose unsent bytes pass `MAX_SEND_QUEUE` (128 MiB), and it
reports a connection's unsent bytes (`Transport::unsent`) so that senders pace below
that. Every frame but Close counts: a side sends its next frame only while the unsent
bytes plus that frame stay below `MAX_SEND_QUEUE`, and the requests it is answering wait
meanwhile (a chunk request whose wait would be long is answered `CHUNK_BUSY`, 4.7). A
push that does not fit is deferred and coalesced: of a writer's fork pushes (4.5) only
the one for its lowest fork goes, and of its other pushed records only the newest, once
there is room, since the receiver's gap rule fetches the rest (4.4 step 6); key-record
pushes and the on-open key set wait in order, never dropped. While unsent bytes remain, a
connection whose delivered bytes (bytes sent minus `Transport::unsent`) have not grown
for `IDLE_TIMEOUT` is closed with `TIMEOUT`, and the next connection's on-open key set
resyncs what was waiting; that bounds the deferred key-record queue (TM-22) without
cutting a long transfer whose paced queue never empties.

**Identity.** The transport authenticates each side's **libp2p identity**, the
separate Ed25519 key of `keys.md` §1.3. Each Hello carries that key (`libp2p_identity`),
and the transcript (3.3) covers both, so the DeviceProof binds the device key to the
channel. From phase 1 the runtime exposes the transport-authenticated key and a side
checks that it equals the peer's `libp2p_identity`, closing with `PROTOCOL_ERROR`
otherwise; in phase 0 the simulator has no authenticated transport identity, the check
is a no-op, and the Hello field alone is what the transcript binds. The protocol
identifier chosen in step 2 is bound into the transcript as well.

### 3.2 Step 3: Hello, roles and DeviceProof

Both sides send Hello at once, without waiting; neither side's Hello depends on the
other's. On receiving the peer's Hello a side checks it, determines the roles, computes
the transcript hash, and sends DeviceProof. A side accepts nothing else until it has the
peer's valid Hello and DeviceProof: before the DeviceProof has verified, any frame other
than that DeviceProof or a Close, known or unknown, critical or not, is
`Close(PROTOCOL_ERROR)`; a second Hello or a second DeviceProof, at any time, is too. A
Close may arrive at any time.

**Roles.** The side whose device public key is byte-wise smaller, comparing the Ed25519
halves (`device_public_key[2..34]`), is **A** with role byte `0x01`; the other
is **B**, `0x02`. The rule depends only on the two Hellos, so it is the same on both
sides, needs no notion of who dialled, and settles simultaneous dials. Equal halves mean
a device connected to itself: `Close(PROTOCOL_ERROR)`.

Hello checks, each a `Close(PROTOCOL_ERROR)` unless noted: `device_public_key` is
exactly `be16(suite) || signing_pk` for an implemented suite; `libp2p_identity` is 32
bytes (and, from phase 1, equals the transport-authenticated key, 3.1); `suites` is
non-empty, has no duplicates and shares at least one implemented suite with ours (else
`Close(NO_COMMON_SUITE)`); `compressions` contains `"none"`; `hashes` contains
`"blake3"`; `max_message_size ≥ MIN_MESSAGE_SIZE` (else `Close(LIMIT_TOO_SMALL)`);
`max_requests_in_flight ≥ 1`; `nonce` is 32 bytes; list lengths and the feature grammar
(section 5) are within section 4.2's bounds. Hello carries no device name: field 2 is
reserved, and the name travels only once a folder is open, in Status (4.5).

### 3.3 The transcript hash

```
th = H("licketysync/v1/hash/transcript",                      # H(label, x) = BLAKE3(label || 0x00 || x), keys.md §0
        be32(len(protocol_id)) || protocol_id                  # "/licketysync/sync/1"
     || be32(32) || libp2p_identity_A                          # A's libp2p identity key, as A's Hello carries it
     || be32(32) || libp2p_identity_B                          # B's
     || be32(len(hello_A))     || hello_A                      # A's Hello frame: type || body, exactly as sent
     || be32(len(hello_B))     || hello_B )                    # B's
```

Both Hellos are in it byte for byte, so the suite lists, limits, features, device keys,
identities and nonces each side saw are the ones each side signs over. A peer that was
shown a different list from the one the other side sent, by anything able to alter
frames, gets a proof that does not verify: a downgrade is detected, not negotiated. The
protocol identifier and the two libp2p identities bind the proof to this channel and to
this major; from phase 1 the transport has authenticated those identities, so the
binding reaches the channel's own keys.

### 3.4 DeviceProof

```
device_signature = HybridSign(device_sk, "licketysync/v1/sig/device-proof", th || u8(role))
```

The verifier uses the `device_public_key` from the peer's Hello and the peer's role.
This proves the whole hybrid device key (the device set's Ed25519 half never signs
outside the hybrid) and, through `th`, binds it to the libp2p identity the transport
authenticated: device IDs are proven, device names only reported. Failure:
`Close(PROOF_REJECTED)`. A FolderProof that arrives before a valid DeviceProof is an
ordering violation: `Close(PROTOCOL_ERROR)`.

### 3.5 Step 4: FolderProof and ProofResult

A prover sends one FolderProof per folder it wants to sync on this connection: the
folder it discovered the peer by, or every folder it shares with a device it already
knows. The payload is encrypted under a key only a holder of the folder ID can derive.
What that hides, and from whom: a peer that does not have the folder, and anyone
reading the plaintext of this layer, learns neither which folder was meant, nor which key
ID presented, nor the grant chain (which names the folder ID in the clear); it sees only
that a proof was attempted. It is not a secrecy pillar: the folder ID is known to every
member and to anyone who saw a key string, and the transport already encrypts the
frame. The timing of the answer differs between a hint miss and a hit that then fails
verification, which tells a prover who already knew the folder ID that this device
holds the folder; that is the same fact the LAN beacon leaks to the same prover
(`keys.md` §2.3), and no more.

```
hint      = BLAKE3_keyed(folder_id, "licketysync/v1/handshake/folder-hint" || 0x00 || th || u8(role))
proof_key = BLAKE3_keyed(folder_id, "licketysync/v1/handshake/proof-key"  || 0x00 || th)
nonce     = 24 random bytes                                                  # fresh for every FolderProof
payload   = ProofPayload { key_id, signature, grants }                       # section 4.3
sealed    = XChaCha(proof_key, nonce, aad = hint, payload)
signature = HybridSign(issued_sk, "licketysync/v1/sig/folder-proof", folder_id || key_id || th || u8(role))
```

The key used is the holder's highest presentable key for the folder (`keys.md` §5.5);
`grants` carries the chain the key presents through, its best presentable chain
(`keys.md` §5.5), parent-first, so that its last record is the key's own grant (root has
no grant): at most 16 grants, preceded by the Folder record when the prover is joining
from a link (`keys.md` §6.2), so at most 17 records. With both signatures on every grant
(`keys.md` §5.3) a full payload is at most 192 840 bytes, 192 856 sealed, within the 262
144-byte bound on `sealed`. A prover always sends the chain it holds (a bare-string
joiner holds none, `keys.md` §6), sends at most four FolderProofs per folder per
connection (its other keys, lower tiers, each under a fresh nonce), and stops at
FEATURE_REQUIRED. The signature covers the key ID, so a proof cannot be replayed as
another key's. The folder ID is the key of both keyed hashes (the keyed-hash case of
`suites.md` §2.4); the transcript hash adds both sides' fresh nonces, and the per-proof
nonce keeps every retry on the same connection under a distinct `(key, nonce)` pair.
Deviation from the plan (Hello "carries ... the key ID it presents per folder"): the
per-folder key ID travels here, inside the encrypted proof, so that an unproven peer
learns nothing about which folders a device has.

Verification by the receiver, for each FolderProof, in order:

1. The peer's DeviceProof has verified; otherwise `Close(PROTOCOL_ERROR)` (3.4). The
   envelope is well formed: `hint` is 32 bytes, `nonce` 24, `sealed` at least 16 and at
   most 262 144 bytes; otherwise `Close(PROTOCOL_ERROR)` (malformed, the sender's doing).
   Every failure from step 2 on is answered REJECTED.
2. For every folder this device holds, compute `hint` with the peer's role; no match →
   `ProofResult { hint, REJECTED }` and stop. (A device with many folders caches the
   per-folder hints once per connection.) A verifier checks at most four proofs per
   hint-matched folder per connection, matching the prover's four attempts: a fifth for
   the same folder is answered REJECTED without being opened or verified.
3. Derive `proof_key`, open `sealed` with the message's `nonce` and `aad = hint`;
   failure → REJECTED.
4. Parse `ProofPayload`; `key_id` is 16 bytes; `grants` holds at most 16 grants plus an
   optional leading Folder record; failure → REJECTED.
5. **Leaf first.** Take the signing key the proof claims: when `grants` holds a grant,
   parse its last record as a Grant without verifying or storing it (`keys.md` §5.4 step
   1 only; its `key_id` must equal the payload's, and so recomputes from its own public
   keys) and take its `signing_pk`; when it holds none, resolve `key_id` to a stored
   or held grant and take its `signing_pk` (none → REJECTED: a prover joining from a bare
   key string presents its derived `key_id` with no chain, `keys.md` §0.4, §6, and is
   refused until the grant has spread). Then
   `HybridVerify(signing_pk, "licketysync/v1/sig/folder-proof", folder_id || key_id || th || u8(role), signature)`;
   failure → REJECTED, with no evidence attached and nothing stored. Only a prover that
   holds the key's private half gets past this step, so nothing below runs for anyone
   else.
6. Verify and store each record in `grants` in order by `keys.md` §5.4 (Folder record
   by §2.2), which check the signatures, the grant's proof of possession first, before
   anything a signer could be blamed for. Any rejection, a failed signature or proof of
   possession included, → REJECTED with a local issue: the proof is answered uniformly
   so that it cannot serve as an oracle, and nothing is pushed to a peer before a folder
   is open. A grant whose `epoch` is above this verifier's current epoch is verified
   through every step of §5.4 but step 4, resolving issuers against stored or held
   grants, and **held** rather than stored: it goes into a scratch set for this proof,
   which joins the folder's held set for the connection only if the proof is answered
   ACCEPTED and is discarded otherwise. A connection holds at most
   `MAX_HELD_GRANTS_PER_CONNECTION` (64) grants in all; a proof whose chain would pass
   that bound is answered REJECTED. A held
   grant is stored when the rotation that created its epoch arrives in the on-open key
   records (4.6) and discarded with the connection otherwise.
7. Resolve `key_id` to a stored or held grant; none → REJECTED. Its `signing_pk` is the
   one step 5 used, since the key ID fixes both public keys (`keys.md` §0.4).
8. The key must be **presentable** (`keys.md` §5.5), its chains running over the grants
   this verifier stores and those it holds for the connection: some chain-valid grant of
   it begins a presentable chain, one whose every grant is unexpired at this device's
   wall clock and along which the effective tier is not `none`; and
   `suite ≥ minimum_suite`. Otherwise REJECTED; only now, with the prover's possession of
   the key established, may the result carry the revocation or suspension records that
   explain it as `evidence`, so the holder can show the right issue; nothing else is
   pushed before the folder is open.
9. The folder's `required_features` ⊆ the peer's feature set (section 5), and the peer's
   `suites` includes the folder's current suite; otherwise
   `ProofResult { hint, FEATURE_REQUIRED, missing }`, where `missing` names each
   missing feature and, for a missing suite, `suite:<n>` with the folder's current suite
   number `n` in decimal.
10. A proof that would open more than `MAX_OPEN_FOLDERS_PER_CONNECTION` (64) folders on
    this connection is answered REJECTED (the prover opens the rest on another
    connection). Otherwise `ProofResult { hint, ACCEPTED }`. Record the peer's key ID,
    device ID and tier for this folder on this connection: the effective tier of the
    key's best presentable chain (`keys.md` §5.5), while the index records it signs are
    judged under its governing grant (4.4). If this side has not yet sent its own
    FolderProof for the folder, send it now.

A folder is **open** on a connection when both sides have sent ACCEPTED for each other's
proof. Only then do any of the folder's records, chunks or status cross the connection;
a message that names a folder not open on the connection is `Close(PROTOCOL_ERROR)`. A
connection on which no folder is open within `PROOF_TIMEOUT` (30 s) of the
DeviceProofs is closed with `NO_COMMON_FOLDER`. A ProofResult that answers no
FolderProof this side sent and has not yet had answered (a stray one), a second
ProofResult for one proof, or a `status` outside 1 to 3, is `Close(PROTOCOL_ERROR)`.

What each side learns on failure: a `REJECTED` result says only that this proof did not
open this folder here; it is the same whether the folder is absent, the hint did not
match, the key is unknown, the chain was rejected, a grant in it was forged or its proof
of possession failed, or the proof signature was bad. The prover may try its other keys
for the folder (lower tiers), at most four FolderProofs per folder per connection in all,
and then gives up. A verifier that receives more than `MAX_PROOFS_PER_CONNECTION` (256:
the four attempts a prover may make for each of the 64 folders a connection may open)
FolderProofs, or a second proof for a hint it already accepted, closes with
`PROTOCOL_ERROR`.

### 3.6 Steps 5 to 7

Once a folder is open, each side sends its full set of key records for it
(`KeyRecords`, section 4.6) and then an `IndexRequest` with its cursors; the peer
answers with `IndexRecords` in pages. Chunks are then requested by ciphertext hash and
returned whole. Status messages report progress periodically. Section 4 defines each
message; section 4.6 the ordering rules.

## 4. Messages

### 4.1 Type numbers

| Number | Critical | Name | Direction | Purpose |
| --- | --- | --- | --- | --- |
| 0x8001 | yes | Hello | both, first | Identity, capabilities, limits |
| 0x8002 | yes | Close | both, last | Reason for closing |
| 0x8003 | yes | DeviceProof | both | Signature over the transcript with the device key |
| 0x8004 | yes | FolderProof | both | Encrypted membership proof for one folder |
| 0x8005 | yes | ProofResult | both | Answer to one FolderProof |
| 0x8006 | yes | KeyRecords | both | Folder, grant, rotation, wrap, revocation, suspension, lift records |
| 0x8007 | yes | IndexRequest | both | "Send what I lack", by cursor |
| 0x8008 | yes | IndexRecords | both | Signed index records, paged or pushed |
| 0x8009 | yes | ChunkRequest | requester → holder | One chunk by ciphertext hash |
| 0x800A | yes | ChunkReply | holder → requester | The chunk, or why not |
| 0x800B | yes | KeyRecordsRequest | both | "Send the key records I lack" |
| 0x0001 | no | Status | both | Progress per open folder; the reported device name once a folder is open |
| 0x0002 | no | Unsupported | both | "I do not know that non-critical type" |
| 0x0003–0x000F, 0x800C–0x800F | | reserved | | Major 1 additions |
| 0x8010–0x801F | | reserved | | Linked-device channel (phase 5) |
| 0x0010–0x001F | | reserved | | Chunk availability for selective sync (phase 5), relay control (phase 7) |

Types 0x0000 and 0x8000 are never used. Every v1 message a v1 peer must understand is
critical except Status and Unsupported, which a peer may lack without harm.

### 4.2 Hello, Close, Unsupported

```proto
syntax = "proto3";
package licketysync.v1;

message Hello {
  bytes  device_public_key      = 1;  // be16(suite) || hybrid signing pk; 1986 bytes under suite 1; device_id = H("licketysync/v1/hash/id/device", this), keys.md §0.4
  reserved 2;                         // was device_name, which now travels in Status once a folder is open (section 4.5); a receiver ignores the field
  repeated uint32 suites        = 3;  // implemented suites, preferred first; <= 16; must share one with the peer
  repeated string compressions  = 4;  // chunk compressions this device can decode: "none" always; "deflate", "zstd", "lz4" as built; <= 32 entries, each [a-z0-9-]{1,20} so that compression:<c> fits the feature grammar
  repeated string hashes        = 5;  // "blake3" required in major 1; <= 32, each [a-z0-9-]{1,20}
  repeated string features      = 6;  // optional feature names this device supports; <= 32; the feature set (section 5) is this list plus compression:<c> and hash:<h> for every entry above
  uint32 max_message_size       = 7;  // frames this device accepts, bytes; MIN_MESSAGE_SIZE ..= MAX_MESSAGE_SIZE
  uint32 max_requests_in_flight = 8;  // chunk requests this device will hold open per connection; >= 1; default 64
  bytes  nonce                  = 9;  // 32 random bytes; makes the transcript unique to this connection
  bytes  libp2p_identity        = 10; // 32: Ed25519 public key of the libp2p identity (keys.md §1.3); from phase 1 must equal the transport-authenticated key
}

message Close {
  uint32 reason = 1;   // CloseReason
  string detail = 2;   // <= 256 bytes, optional; UTF-8 with no control characters (otherwise malformed: not shown, the connection closes all the same); rendered as text only, never as markup; never carries a folder ID, key ID, record hash, path or name
}

enum CloseReason {
  CLOSE_UNSPECIFIED            = 0;
  SHUTDOWN                     = 1;   // orderly: the device is stopping or the folder was paused
  PROTOCOL_ERROR               = 2;   // a frame or body could not be parsed, broke a bound, or arrived out of order (section 5)
  MESSAGE_TOO_LARGE            = 3;   // a frame exceeded the limit; nothing was allocated
  UNSUPPORTED_CRITICAL_TYPE    = 4;
  NO_COMMON_SUITE              = 5;
  LIMIT_TOO_SMALL              = 6;
  PROOF_REJECTED               = 7;   // the DeviceProof did not verify
  NO_COMMON_FOLDER             = 8;   // nothing opened within PROOF_TIMEOUT
  VERIFICATION_FAILED          = 9;   // this peer forwarded a record whose signature fails or a chunk whose ciphertext hash fails: forged or corrupted in its hands
  TOO_MANY_CONNECTIONS         = 10;  // this device's connection limit is reached (libp2p limits, phase 1)
  TIMEOUT                      = 11;  // HELLO_TIMEOUT or IDLE_TIMEOUT elapsed, or, while unsent bytes remained, none was delivered for IDLE_TIMEOUT (3.1); PROOF_TIMEOUT closes with NO_COMMON_FOLDER
  FEATURE_REQUIRED             = 12;  // reserved for a connection-level requirement; folder-level requirements use ProofResult
}

message Unsupported {
  uint32 message_type = 1;   // the full 16-bit type that was not understood
}
```

A side that receives Close stops sending, frees every per-connection table and closes
the transport. A side that sends Close sends nothing after it, and its engine asks the
runtime to close the connection when the engine's own 1 s timer fires (through the clock
trait) or when the peer disconnects, whichever comes first; the Close, and anything sent
before it, may still be lost if the connection ends before the peer has received it
(3.1). When a device stops, its runtime flushes what the stopping engine sent for up to
1 s and then closes, so a peer may receive `Close(SHUTDOWN)`, or may see only the
connection end.

### 4.3 DeviceProof, FolderProof, ProofResult

```proto
message DeviceProof {
  bytes signature = 1;   // HybridSign(device, "licketysync/v1/sig/device-proof", th || role); 3373 bytes
}

message FolderProof {
  bytes hint   = 1;      // 32 bytes, section 3.5
  bytes sealed = 2;      // XChaCha(proof_key, nonce, aad = hint, ProofPayload); <= 262 144 bytes (a full payload seals to at most 192 856)
  bytes nonce  = 3;      // 24 random bytes, fresh for every FolderProof
}

message ProofPayload {
  bytes key_id                   = 1;   // 16: derived from the key's public keys (keys.md §0.4)
  bytes signature                = 2;   // HybridSign(issued key, "licketysync/v1/sig/folder-proof", folder_id || key_id || th || role)
  repeated SignedRecord grants   = 3;   // optional Folder record first, then the best presentable chain parent-first, the key's own grant last; <= 16 grants, <= 17 records
}

message ProofResult {
  bytes hint                        = 1;   // echoes the FolderProof
  uint32 status                     = 2;   // ProofStatus
  repeated string missing_features  = 3;   // with FEATURE_REQUIRED; <= 32; a missing suite as "suite:<n>"
  repeated SignedRecord evidence    = 4;   // with REJECTED, optional: revocation or suspension of the presented key; <= 4
}

enum ProofStatus { PROOF_UNSPECIFIED = 0; ACCEPTED = 1; REJECTED = 2; FEATURE_REQUIRED = 3; }   // any other value: Close(PROTOCOL_ERROR)
```

### 4.4 The index record on the wire

An index record is one signed statement by one writer about one path: what it is, which
chunks hold it, which records it follows. Everything that would name a file is inside a
sealed part that only key holders open; sealed peers and relays see what they need to
store, verify, serve and garbage-collect, and nothing more. The record is a
`SignedRecord` (`keys.md` §5.1) whose body is:

```proto
message IndexRecord {
  uint32 suite        = 1;
  uint32 record_type  = 2;   // 16
  bytes  folder_id    = 3;   // 32
  bytes  writer_key_id = 4;  // 16: the write key that signs this record
  bytes  device_id    = 5;   // 32: the device that wrote it, as the key holder claims; attested by the key, not proven (see below)
  uint64 seq          = 6;   // per writer (writer_key_id, device_id); 1, 2, 3 … with no gaps
  bytes  previous     = 7;   // record_hash of this writer's seq - 1; empty iff seq = 1
  repeated bytes supersedes = 8;   // record_hash of each head record for this path that this one replaces; <= 64
  repeated VersionEntry version = 9;   // the path's version vector after this write; sorted by device_id; <= 1024
  uint64 epoch        = 10;  // epoch whose record key sealed field 13
  bool   deleted      = 11;  // tombstone: chunks is empty
  repeated ChunkRef chunks = 12;   // in file order; <= 32 768; empty for directories, tombstones and empty files
  bytes  sealed       = 13;  // nonce (24) || XChaCha(rk_epoch, nonce, aad, padded SealedMeta); <= 1 572 864 bytes
  bytes  resumes      = 14;  // empty, or 32: record_hash of the Suspension whose cutoff this record continues (keys.md §7.3); set on the
                             // one restart record after a suspension ends: seq = cutoff.seq + 1, previous = cutoff.head_hash (seq 1 and
                             // empty previous after a cutoff that kept nothing)
}

message VersionEntry { bytes device_id = 1; uint64 counter = 2; }   // counter >= 1

message ChunkRef {
  bytes  cipher_hash = 1;    // 32: H("licketysync/v1/hash/chunk", stored), keys.md §3.3
  uint32 stored_len  = 2;    // bytes of the stored blob; 46 ..= padme(MAX_CHUNK_PLAINTEXT + 5) + 40 = 4 325 416, and itself a Padmé length plus 40
  uint64 epoch       = 3;    // epoch whose chunk key encrypted it
}

// Inside `sealed`, visible to write and read keys only.
message SealedMeta {
  string path                 = 1;   // UTF-8, NFC, '/' separated, relative, no empty, "." or ".." component, no NUL, no backslash; <= 4096 bytes
  uint32 kind                 = 2;   // 1 file, 2 directory; others reserved
  uint64 size                 = 3;   // bytes of plaintext content; 0 for an empty file, which has no chunks
  int64  mtime_ns             = 4;   // modification time, nanoseconds since the Unix epoch
  uint32 mode                 = 5;   // Unix permission bits; 0 when the writer has none
  repeated bytes plain_hashes = 6;   // keyed BLAKE3 per chunk (keys.md §3.3), same order and count as `chunks`
  uint64 written_at           = 7;   // writer's wall clock; informational only, never used for ordering
}
```

- **Sealing**: `meta = canonical SealedMeta bytes`; `plain = be32(len(meta)) || meta || zeros(padme(len(meta) + 4) - len(meta) - 4)`
  (Padmé-padded, `keys.md` §3.4, so the sealed length says little about the path length
  or chunk count); `aad = folder_id || writer_key_id || device_id || be64(seq)` (88
  bytes); random 24-byte nonce; key `rk_epoch` (`keys.md` §3.2). A reader rebuilds the
  aad from the public fields, so a sealed part cannot be moved between records, and
  requires every padding byte to be zero.
- **Record hash**: `record_hash = H("licketysync/v1/hash/record", body)` over the
  canonical body bytes as received (`keys.md` §5.1); this is what `previous` and
  `supersedes` name.
- **Chain, cursor, fork and applied head**, per writer `(writer_key_id, device_id)`. A
  peer's **chain** for a writer is one record at each `seq` from 1 to its **cursor**
  for the writer, with no gaps: the first record it accepted at that `seq` (step 6). A
  second record at a `seq` the chain holds is an **evidence record**, kept beside it, at
  most one per `seq`. The cursor is the highest chain `seq` the peer holds for the
  writer, withdrawn records included; it is what the peer persists and advertises
  (`Cursor`, 4.5: "I hold this writer through here"), and it never decreases (step 7). A
  request may rewind it on purpose to fetch records again (cutoff recovery and an
  unknown parent, step 6), which changes nothing held. The writer's **fork** is the
  lowest `seq` at which the peer has seen it equivocate; there is none until then (step
  6). The writer's **applied head** is the last chain record the peer applies: the one
  just before the fork, or the chain's last record when there is no fork (a cutoff
  bounds it too, step 6). An evidence record never defines the cursor or the applied
  head.
- **Signature**: `HybridSign(writer, "licketysync/v1/sig/index", body)`.
- **Device ID**: `device_id` is the holder's claim, attested by the write key's signature
  and by nothing else; a key holder may write under any device ID it likes, and the
  per-writer chain is per claimed `(writer_key_id, device_id)`. Device IDs are proven only
  at the handshake (3.4); in a record the ID is a label for the chain, shown as "written
  by" with that caveat.
- **Chunk references** appear twice on purpose: `cipher_hash` in the clear, so that a
  sealed peer can fetch, verify and deduplicate by it, and `plain_hash` under the seal, so
  that only key holders can tell which plaintext a chunk is. A key holder maps between
  them by computing both when it writes (encryption is deterministic) and by decrypting
  when it reads; a sealed peer never can.
- **What a sealed peer or relay sees** (threat model, TM-15; these are leaks the design
  documents rather than claims away): the writer key ID and device ID, the sequence
  number and the hash chain (`previous`, `supersedes`, `resumes`), the version vector (device IDs
  and counters), the epoch, whether the record is a tombstone (`deleted`: sealed peers
  must see deletions to garbage-collect chunks), the number of chunks and each padded
  `stored_len`, the padded length of the sealed part, and the rate at which records
  arrive; and, because `supersedes` and the version vector link the records of one path,
  it can group records by file without knowing its name: how often each file changes,
  how its chunk count moves over time, and which devices touched it. It does not see the
  path, kind, true size, times, mode, plaintext hashes or `written_at`.
- **Bounds** that make the largest record fit `MIN_MESSAGE_SIZE`: 32 768 chunks per
  record and 4 MiB per chunk, so a file in major 1 is at most 128 GiB, and in practice
  32 768 times the engine's average chunk size, since FastCDC rarely produces maximal
  chunks; larger files are refused with an issue (continuation records are a phase 7
  addition). An empty file has `size = 0`, `kind = 1`, no chunks and `deleted = false`.

Verification of an index record, in order, on every peer including sealed ones. The
action on each failure is the one section 5's table gives for its cause; the causes are
named here in **bold**.

1. Parse the body; the encoded `SignedRecord` is at most `MAX_INDEX_RECORD_BYTES`
   (4 000 000) bytes; `suite` is not 0 (one this release does not implement is a
   validity-only rejection, `keys.md` §0.1); `record_type = 16`; sizes and bounds above,
   every fixed-size field present at its exact size; `folder_id` is the open folder;
   `writer_key_id` is not `root_key_id` (root never writes, `keys.md` §2.1); `deleted`
   implies `chunks` empty; `previous` empty iff `seq = 1`; `resumes` empty or 32 bytes;
   `version` sorted, unique, each counter ≥ 1; `epoch ≥ 1`; `sealed` at least 40 bytes
   (its nonce and tag); each chunk's `cipher_hash` 32 bytes, `epoch ≥ 1` and `stored_len`
   in range and a Padmé length plus 40. Failure: **malformed**.
2. A grant for `writer_key_id` is stored; if not, **missing dependency**. Every grant for
   a key ID carries the same `signing_pk` and `kem_pk` (`keys.md` §5.4), so the key is
   unambiguous.
3. `HybridVerify(signing_pk, "licketysync/v1/sig/index", body, signature)`; failure:
   **forged**. No later step runs without it: nothing below may be charged to the
   writer unless the writer signed it.
4. The key's governing grant (`keys.md` §5.5) has tier 1; a record signed by a key
   granted only read or sealed is the writer's doing: **writer fault**.
5. **Validity.** The writer's **binding cutoffs** are every stored Revocation cutoff in
   scope for it and, among the stored Suspension cutoffs in scope, the one with the
   highest `seq` (`keys.md` §7: scope, the implicit cutoff `(0, empty)`, precedence). The
   record passes when one of these holds:
   - the writer is chain-valid with effective tier 1 (`keys.md` §5.5) and no cutoff binds
     it;
   - `seq ≤ c.seq` for every binding cutoff `c`, so that it may lie on the kept chain
     (step 6 places it);
   - it is a **restart**: `resumes` names a stored Suspension whose cutoff for this writer
     is the binding Suspension cutoff `c`, `seq = c.seq + 1`, `previous = c.head_hash`,
     that suspension has ended (a stored Lift names it, or its `until` has passed at this
     device's wall clock), and no Revocation cutoff binds the writer below `seq`;
   - it continues an accepted restart (its chain leads back to the restart record, step
     6) and the writer is chain-valid with effective tier 1 now that the suspension has
     ended.
   A non-empty `resumes` naming no stored record is a **missing dependency**; one naming
   a stored record that is not a Suspension with a binding cutoff for this writer at
   `seq - 1` is the writer's doing: **writer fault**. Anything else is a **validity-only
   rejection**: this verifier knows a revocation, suspension or cutoff the sender may
   not, or its clock has not yet passed `until`; it rejects, keeps the connection and
   pushes the explaining key records, and its next `IndexRequest` (on open, on a gap,
   after a key-record resync, or when its clock passes `until`; section 4.5) fetches the
   record again.
6. **Chain, forks, cutoffs and duplicates.** Let `n` be this peer's cursor for
   `(writer_key_id, device_id)` (0 if nothing is stored) and `chain[i]` its chain record
   at `seq = i`, as defined above.
   - **Writer bound.** This peer holds at most `MAX_DEVICES_PER_KEY` (256) device IDs for
     one write key in a folder, and at most `MAX_WRITERS_PER_FOLDER` (16 384) writers for
     the folder: a record from a writer it does not yet hold, when the key already has
     256 device IDs or the folder already has 16 384 writers, is a **validity-only
     rejection** (not stored, an issue naming the key or the folder), so that every
     writer always fits one `IndexRequest` (4.5) and one key cannot fill the folder by
     inventing device IDs. The stated limit that remains: a `may_share` delegate that
     mints 64 or more write keys can still fill `MAX_WRITERS_PER_FOLDER` (64 × 256), and
     nothing frees those slots before phase 7, where the writers of a revoked key stop
     counting.
   - **The fork.** A record whose `previous` is not the hash of the writer's chain record
     at `seq - 1` is an equivocation at its own `seq`; two distinct records at one `seq`
     are an equivocation at that `seq`. The writer's fork is the lowest such `seq` this
     peer has seen: each equivocation sets `fork = min(fork, seq)` (`seq` when there was
     none), so the fork only ever moves down. The fork sits at the equivocating record's
     own `seq`, not just after the earlier record its `previous` names, because the fork
     must sit where the cursor exchange can carry the evidence: of the sequences a
     requester already holds, it is sent only the records at the responder's fork `seq`
     and, where the two differ, the responder's record at the requester's applied head
     (4.5), while just after the named record every peer may hold the same honest one.
     Chain records before the fork stay applied; chain records at and after it are
     **withdrawn**: hidden (applied by no one, and the affected paths are re-evaluated
     from the remaining records), kept as evidence and served like any other record,
     never deleted. A path that becomes absent because its writer's records were
     withdrawn goes through the archive and the deletion brake (`threat-model.md` TM-35)
     like any deletion, never a silent unlink. A record that arrives later at `n + 1`
     still joins the chain, withdrawn, so the cursor keeps advancing while the applied
     head is the record at `fork - 1` (none when the fork is 1), until a stored cutoff in
     scope names a chain for the writer.
   - **Cutoffs.** With binding cutoffs, let `c` be the lowest-`seq` binding Revocation
     cutoff, or the binding Suspension cutoff when no Revocation binds. Records with
     `seq ≤ c.seq` that extend the held chain are applied **provisionally** until the
     record at `c.seq` is held: if its hash is `c.head_hash` the provisional records are
     confirmed; if a held record at `c.seq` has another hash, or the held chain does not
     lead to `c.head_hash`, cutoff recovery runs (next bullet). With several Revocation
     cutoffs a record is applied only if it lies on the chain of every one of them (their
     common prefix when they disagree). Records with `seq > c.seq` are **evidence**
     (stored and forwarded, never applied), except the one restart record that names a
     Suspension cutoff and its successors, which continue the chain under the bullets
     below; a second record at `c.seq + 1` naming the same Suspension with a different
     hash is equivocation. A Revocation's cutoff is continued by nothing. When a
     Suspension cutoff with a higher `seq` arrives, the binding one changes and the
     writer's records are re-evaluated. A stored cutoff overrides a recorded fork for the
     chain it keeps.
   - **Cutoff recovery**, bounded: at most one rewound `IndexRequest` per writer per
     cutoff per connection, sent only to a peer whose own cursors (its `IndexRequest` to
     us) show that it holds the writer through `c.seq` or beyond, with the writer's
     cursor rewound to `seq` 0 (`fork` 0, no `head_hash`, as every rewound cursor is,
     4.5), merged into its next request there. Meanwhile the peer keeps applying what it
     has.
     When the records that arrive lead to `c.head_hash`, it replaces the writer's
     applied set with that chain in one step, moves the rest to evidence, and
     re-evaluates the affected paths once. If no held chain reaches `c.head_hash` after
     the reply, it raises "cutoff for writer W names a record no peer has" against the
     revoker and keeps applying what it has. A cutoff whose `seq` this peer has not
     reached waits: records arrive through the ordinary cursor and are judged against it
     then.
   - `seq ≤ n` and `chain[seq]`, or the evidence record held at `seq`, has this hash: a
     **duplicate**; ignore.
   - `seq ≤ n` and the record is neither (two distinct records at one `seq`), or
     `seq = n + 1` and `previous` is not the hash of `chain[n]`, and no cutoff or restart
     settles it: **equivocation** at `seq`: the writer signed two histories. Flag the key
     under Issues and set `fork = min(fork, seq)` (first bullet); when that sets or
     lowers the fork, this peer pushes the records it holds at the new fork at once
     (4.5), and every peer the evidence reaches does the same. Where the record goes: at
     `seq = n + 1` it joins the chain, withdrawn, and the cursor becomes `seq`; at
     `seq ≤ n` below the fork held before it (or with none) it is stored as the evidence
     record at `seq`; at `seq ≤ n` at or above that fork it is refused as a **duplicate
     of the fork** and not stored, since its `seq` is already withdrawn. So at most one
     evidence record per `seq` is ever kept. A duplicate of the fork has a duplicate's
     outcome (refused, nobody blamed, the connection kept); an implementation may report
     it as an outcome of its own (the index crate's `Withdrawn`). The withdrawal lasts
     until a stored Revocation or Suspension cutoff in scope names a chain for the
     writer; then exactly that chain up to the cutoff is applied and the withdrawal ends
     for it. The writer needs a fresh key once the issue is cleared. The connection stays
     open: the sender may be an honest relay.
   - **Unknown parent.** When an equivocating record, at a `seq` this peer already holds
     (different from its own) or at `seq = n + 1`, has a `previous` that names a record
     this peer does not hold, the collision that matters may lie lower, at a `seq` where
     another peer holds the other side: this peer re-requests the writer from cursor 0 on
     the connection the record arrived by (its next `IndexRequest` there carries that
     writer at `seq` 0, `fork` 0 and no `head_hash`, 4.5), at most once per writer per
     connection and whether or not the record itself was kept, so that the true lowest
     collision surfaces as two distinct records at one `seq` and the fork moves down to
     it. The bounded residual: a record above the fork whose parent is unknown is never
     held, so a peer that pushes it on every connection triggers one full re-request on
     each; the once-per-connection rule bounds that, and the reply's cost falls on the
     sender, which has to serve the writer's whole chain.
   - `seq > n + 1` (or `seq > 1` with nothing stored): a **gap**, whatever `previous`
     names, since this peer has not reached `seq - 1`. On a push, ignore the record and
     ask again from the current cursor in the next `IndexRequest` on that connection, at
     most one gap-triggered request per `INDEX_RESYNC_INTERVAL` per folder per connection
     (a request already outstanding, or one already due, covers the gaps found
     meanwhile, 4.5); in a reply to a cursor the sender promised contiguity, so this is a
     **sender violation**.
   - Otherwise `seq = n + 1` and `previous` is the hash of `chain[n]` (empty when
     `seq = 1`): the record joins the chain and the cursor becomes `seq`; it is applied
     when the writer has no fork and no cutoff withholds it, and withdrawn when it has a
     fork; a restart record extends the cutoff chain the same way, and so do its
     successors.
7. **Rollback.** A peer's cursor for a writer never decreases: nothing a peer sends
   moves it back, and forks and cutoffs change only which held records are applied. The
   applied head moves back only by a stored cutoff or an equivocation withdrawal (step
   6), each a signed cause this peer verified itself. A peer that offers a lower cursor
   is simply behind, and nothing is asked of it. Each peer persists its cursors and
   forks, so a stale snapshot from a sealed peer or relay can never be mistaken for the
   present.
8. Key holders then open `sealed` with the record's epoch (climbing the ladder if
   needed). A seal that will not open, non-zero padding, a path outside the grammar
   above (a name that is merely invalid on some platform is the path resolver's concern,
   TM-4, not a writer fault), a `kind` this release does not know, or a `plain_hashes`
   count different from `chunks` is the writer's doing, since the body already verified
   under its signature: **writer fault**;
   the record is stored opaque so the chain continues, not applied, and an issue names
   the writer key. Sealed peers store the record without opening it.

The version vector and `supersedes` carry the conflict semantics (version vectors detect
concurrent edits; both versions are kept; an edit beats a delete); the engine defines
them. What this layer guarantees is that every peer applies the same signed records in
the same per-writer order.

### 4.5 Index exchange and Status

```proto
// "I hold this writer's chain through seq", withdrawn records included (section 4.4); key_id 16 bytes, device_id 32.
// fork: the lowest fork seq the requester holds for this writer, 0 = none. head_hash: the record_hash of the
// requester's chain record at its applied head s, where s = seq when fork = 0 and min(seq, fork - 1) otherwise;
// 32 bytes when s > 0, empty when s = 0, any other length malformed. A responder ignores fork when seq = 0.
message Cursor { bytes key_id = 1; bytes device_id = 2; uint64 seq = 3; uint64 fork = 4; bytes head_hash = 5; }

// Used by Revocation and Suspension records (keys.md §7): keep from this writer exactly the
// chain that ends at the record with this seq and record hash; everything else is evidence.
// seq = 0 with head_hash empty keeps nothing.
message Cutoff { bytes key_id = 1; bytes device_id = 2; uint64 seq = 3; bytes head_hash = 4; }

message IndexRequest {
  bytes folder_id       = 1;
  repeated Cursor have  = 2;   // one per writer known, each writer at most once (twice is malformed); <= MAX_WRITERS_PER_FOLDER (16 384), so every writer always fits: at most 110 bytes each encoded, 1 802 240 bytes in all, about 1.7 MiB, well within MIN_MESSAGE_SIZE; a writer absent from it is treated as cursor 0
  uint32 max_records    = 3;   // per reply page (the paging rule below); 0, or above MAX_PAGE_RECORDS (4096), means 4096; below 64 means 64
  uint32 request_id     = 4;   // >= 1, chosen by the requester, unique among its requests outstanding on the connection; every page of the reply echoes it
}

message IndexRecords {
  bytes folder_id                = 1;
  repeated SignedRecord records  = 2;   // <= MAX_PAGE_RECORDS (4096), more is malformed; per writer, in ascending seq: the records the fork rules send, then its chain records above the cursor, contiguous, each followed by the evidence record held at its seq
  bool more                      = 3;   // another page follows for the same request; never true when request_id = 0 (malformed)
  uint32 request_id              = 4;   // the request this page answers; 0 = a push
}

message Status {
  repeated FolderStatus folders = 1;   // open folders only; <= 1024
  string device_name            = 2;   // self-reported; <= 64 bytes of UTF-8, no control characters (else the Status is malformed); set in the first Status after the first folder opens on the connection, and again when the name changes; shown as text only, marked "reported"
}

message FolderStatus {
  bytes  folder_id       = 1;
  uint64 index_records   = 2;   // index records held for the folder (the "index version")
  uint64 bytes_needed    = 3;   // ciphertext bytes still to fetch
  bool   paused          = 4;
  uint64 free_disk_bytes = 5;
}
```

- The responder sends, for every writer it holds, every chain record with `seq` above
  the requester's cursor (0 for writers absent from `have`), withdrawn ones included, in
  ascending `seq` and without gaps, each followed by the evidence record it holds at
  that `seq`, if any; if it lacks `cursor + 1` for a writer it sends nothing above the
  cursor for that writer. Pages end with `more = false`.
- **One request at a time.** At most one `IndexRequest` per folder is outstanding on a
  connection: the requester sends the next only after the current reply's last page
  (`more = false`) has arrived. Every trigger that arises meanwhile (a gap in a push, an
  unknown parent, a completed key-record resync, a suspension's `until` passing, cutoff
  recovery) is merged into that next request, which carries the ordinary cursors with
  each writer being asked for again at `seq` 0, `fork` 0 and no `head_hash`. A responder
  that receives a second `IndexRequest` for a folder before it has queued the current
  reply's last page closes with `PROTOCOL_ERROR`. Pushes (`request_id = 0`) are not
  requests and are unaffected. The responder keeps no per-writer state about rewound
  cursors; instead it serves `IndexRequest`s for one folder on one connection at most
  once per `INDEX_REQUEST_MIN_INTERVAL` (1 s), counted from when it began serving the
  previous one, and delays a later request until then, never refusing it. A fair share
  of upload per peer, across folders and against chunk requests, is a phase 1 engine
  item.
- **Forks in a reply.** A cursor's `seq` alone cannot say which of two records a
  requester holds at a sequence, so each `Cursor` also carries the requester's `fork`
  for the writer and the `head_hash` of its chain record at its applied head, and:
  (a) for a writer whose fork this responder holds at sequence `f`, the reply carries the
  records the responder holds at `f` (the chain record and the evidence record there, if
  any) only when the requester's cursor for that writer is at or past `f` and the
  requester's `fork` is 0 or greater than `f`, and at most once per writer per
  connection; a requester whose cursor is below `f` gets them with the rest of the
  chain, and one whose `fork` is at or below `f` already withdraws everything they would
  make it withdraw, while its own reply in the other direction carries its fork to this
  peer when it is lower. (b) When `head_hash` is not empty and the responder's own chain
  record for the writer at the requester's applied head `s` (`s = seq` when `fork` is 0,
  `min(seq, fork - 1)` otherwise; applied or withdrawn on the responder's side) has
  another hash, the reply carries that record as evidence, unless (a) already carries
  it, and at most once per writer per connection, as the requester re-requests at most
  once. The requester then holds two distinct records at one sequence, an equivocation
  at `s`, so its fork falls to `s` or below, and it re-requests the writer from cursor 0
  when it lacks that record's parent (section 4.4, step 6). Comparing applied heads
  rather than cursors means that two peers sharing a fork but holding different
  withdrawn tails do not mismatch for ever, while a difference in what two peers apply
  is still found, by (b) or, below the responder's own fork, by (a). The records (a) and (b) send count against `max_records` and `max_message_size`
  like any other record and travel in that writer's place on the page, in ascending
  `seq` ahead of its records above the cursor. (c) Evidence is bounded to one record per
  sequence per writer: a record that collides at or above the fork is refused as a
  duplicate of the fork and not stored (section 4.4, step 6).
- **Pages.** A **sequence group** is what a reply carries for one writer at one `seq`:
  the chain record and the evidence record held there (two records at most), or the one
  record (b) sends. A group is never split across pages. The page limit is the request's
  `max_records` held between 64 and `MAX_PAGE_RECORDS` (4096): 0 or a value above 4096
  means 4096, and a value below 64 means 64, so that no requester can pin a responder's
  processor with one-record pages. The responder fills each page group by group in the
  order above and ends the page before a group when the page already holds a record and
  the group would take it past the page limit, or would take the encoded `IndexRecords`
  frame past the requester's `max_message_size`. An empty page always takes one whole
  group, which fits by section 2's sizing; so a page never holds more than the page
  limit, and never more than `MAX_PAGE_RECORDS`, the receiver's bound. `more` is set on
  every page but the last.
- **Fork push.** When this peer's fork for a writer is first set or moves down to `f`,
  it pushes the records it holds at `f` (its chain record and the evidence record there,
  if any) on every connection where the folder is open, the one the evidence came from
  included: one push of at most two records per fork change per connection. A receiver
  that already holds both gets duplicates, its fork does not change, and it pushes
  nothing; one whose fork the push sets or lowers pushes in turn. Without it, a peer
  that learned of a fork from a reply would not tell the peer it learned it from, whose
  own request had already been answered, until they reconnected.
- **Stated limit: a split is found at the first exchange.** A fork split so cleanly that
  no peer holds both sides (some peers hold one branch of a writer, the rest another,
  and every chain looks whole) is detected the first time two peers holding different
  branches exchange cursors for that writer: the one with the lower or equal applied
  head is sent the other's record at that sequence by (b), and the unknown-parent
  re-request then surfaces the lowest collision. Until two such peers exchange cursors,
  each side applies its own branch.
- **Replies and pushes.** A **reply** is what a sender produces for a request it
  received on this connection: the `IndexRecords` (or `KeyRecords`) pages carrying that
  request's `request_id`, up to and including the one with `more = false`. The sender
  paged it, so inside a reply it answers for contiguity (index records) and dependency
  order (key records): a gap or an absent dependency inside a reply is a sender
  violation (section 5). A **push** is an unsolicited `IndexRecords` or `KeyRecords`
  with `request_id = 0` and `more = false`; it carries what the pusher newly accepted
  (or, for a fork push, the records at a new fork), may arrive between two pages of a
  reply, and a receiver that lacks something it depends on re-requests rather than
  blaming the pusher. The on-open key-record set (4.6) is sent with `request_id = 0` but
  carries a reply's obligations, and is the only `request_id = 0` message that may set
  `more`: an `IndexRecords` push with `more = true`, or a `KeyRecords` one outside the
  on-open set, is malformed. A page whose `request_id` names no request outstanding on
  the connection is malformed.
- **Durability before transmission.** A writer commits a new record and its sequence
  counter to its own index before any peer may receive it, so a crash can never make it
  reuse a sequence number; a peer forwards only records it has itself verified and
  committed. Records a peer holds withdrawn, as evidence (of equivocation or beyond a
  cutoff) or opaque (section 4.4, steps 6 and 8) are forwarded like any other, since
  the signature is the writer's. A device restored from a backup of its index reuses
  sequence numbers and is flagged for equivocation like any forked writer (section 4.4,
  step 6); the app mints a fresh child key after a restore (an engine rule).
- After the first exchange, a peer **pushes** every record it newly accepts to every
  connection where the folder is open, as an unsolicited `IndexRecords` (`more` false,
  at most `MAX_PAGE_RECORDS` records), subject to the same ordering rule; a receiver
  that finds a gap asks again from its cursor in its next `IndexRequest` rather than
  failing the connection, at most once per `INDEX_RESYNC_INTERVAL` (10 s) per folder per
  connection (section 4.4, step 6). A receiver also asks again, in its next
  `IndexRequest` for a folder, when a `KeyRecordsRequest` reply for it completes, since
  index records it ignored for a missing grant are now acceptable, and when its wall
  clock passes a stored suspension's `until`.
- Status is sent every `STATUS_INTERVAL` (30 s, through the clock trait) and on change,
  for open folders only; it is advisory and never changes what a peer will accept.
- **Device name.** A device's self-chosen name travels only in Status, so only after a
  folder has opened on the connection (both ProofResults ACCEPTED): the first Status a
  side sends after its first open carries `device_name`, later ones carry it only when
  it changes, and the receiver shows the latest as reported, never proven. It is not in
  Hello (field 2 there is reserved) nor in the folder proof, because `proof_key` derives
  from the folder ID alone: anyone who knows a folder ID (any member, a relay, anyone who
  saw an invite) can open a FolderProof, and can make a device dial it by announcing the
  folder, so a name there would reach people who never proved a key. A name that breaks
  the grammar makes the Status malformed (`Close(PROTOCOL_ERROR)`). Deviation from the
  plan ("Capabilities": "The Hello message carries the device's ID and name"): the name
  moved from Hello to the first Status after a folder opens (decision 2026-10-17).

### 4.6 Key records

```proto
message KeyRecords {
  bytes folder_id                = 1;
  repeated SignedRecord records  = 2;   // <= 4096 per message and bounded by the peer's max_message_size
  bool more                      = 3;   // with request_id = 0, true only on the pages of the on-open set (else malformed)
  uint32 request_id              = 4;   // the KeyRecordsRequest this page answers; 0 = the on-open set or a push
}

message KeyRecordsRequest {
  bytes folder_id      = 1;
  repeated bytes have  = 2;   // record hashes of key records the requester holds: 32 each, sorted, unique; <= 16 384 (rotated beyond that, below); the reply carries only what is absent
  uint32 request_id    = 3;   // >= 1, as in IndexRequest
}
```

- On open, each side sends its whole set of key records for the folder (Folder record,
  grants, rotations, wraps, revocations, suspensions, lifts; `keys.md` §2.2, §5, §7),
  paged, with `request_id = 0`, finishing the set (the first page with `more = false`)
  before any push for the folder. The set carries a reply's obligations: dependency order
  over the sender's own records, so a dependency absent from it is a sender violation;
  a grant held from the handshake (3.5, step 6) is stored when the rotation it waited
  for arrives in it. The receiver merges by `record_hash`, verifying each new one by its
  section in `keys.md`; a Rotation's `view` is checked against records the receiver
  holds, and a `Cutoff` is applied to its writer's records, within its scope, as they are
  held and as they arrive (section 4.4, step 6).
- **Ordering rule**: a sender never sends a record before the records it depends on,
  on the same connection: the Folder record first; a grant after its issuer's grant and
  after the rotation that created its epoch; a rotation, wrap, revocation, suspension or
  lift after its signer's grant and after the records it names (`cause`, `view`,
  `suspension`); an index record after its writer's grant and, for a restart record,
  after the Suspension its `resumes` names and the Lift that ended it. A push of a newly
  accepted grant includes its canonical chain to root (`keys.md` §5.5, at most 16
  grants); the receiver skips records it already has.
- **Missing dependency.** A record whose dependency is absent when it arrives is not a
  close: the receiver ignores it (it is not stored) and sends `KeyRecordsRequest` for the
  folder, listing in `have` the key records it holds. When it holds more than 16 384 it
  lists 16 384 of them, rotating which on successive requests; the rest come back and
  are skipped as duplicates, so a folder with more key records than that re-sends some
  of them once per `KEY_RESYNC_INTERVAL` per connection, a cost bounded by that interval
  (paging the request by record-hash range, with the sender-violation rule relaxed for
  paged replies, is a phase 7 follow-up). At most one `KeyRecordsRequest` per folder is
  outstanding on a connection, and the requester sends the next only
  `KEY_RESYNC_INTERVAL` (30 s) after the previous reply's last page arrived. The
  responder replies with every key record it holds that is not in `have`, in dependency
  order, paged, each page queued behind the connection's other traffic like a chunk
  reply rather than all at once. It closes with `PROTOCOL_ERROR` when a request for the
  folder arrives while its reply to the previous one is still going out, or less than
  `KEY_RESYNC_INTERVAL / 2` after it queued that reply's last page. Both ends anchor on
  the reply's last page, not on when requests were sent, so an honest requester whose
  reply sat behind large chunk replies never trips the close; the margin covers delivery
  jitter inside the stream, and the rule bounds what a connection can make the
  responder send. Peers may differ in what they hold at any moment, and an honest relay
  cannot know what the receiver lacks.
- A key record whose signature fails, or a grant whose proof-of-possession signature is
  missing or fails (`keys.md` §5.4 step 2), is **forged**; one that a structural check
  charges to its signer (a grant from an issuer without `may_share`, a rotation that
  omits a key in its own view, a Wrap for a key granted only sealed) is **signer fault**:
  the record is rejected, the signer's key is flagged, and the connection stays open
  (section 5).
- Peers in phases 0 to 6 run, for rotation, wrap, revocation, suspension and lift
  records, the parse, resolve-the-signer, signature and entitlement steps of their
  procedures, store and forward what passes, and raise an issue that this release does
  not apply them; the later steps are phase 7, whose upgrade re-verifies every stored
  key record (`keys.md` §7). Their current epoch, for every dependency check, is set by
  the dense chain of stored rotations (`keys.md` §7), so later grants and rotations are
  stored and forwarded. This is the one statement of that rule.

### 4.7 Chunks

```proto
message ChunkRequest {
  bytes folder_id   = 1;
  bytes cipher_hash = 2;   // 32; absent or any other size is malformed
}

message ChunkReply {
  bytes  folder_id   = 1;
  bytes  cipher_hash = 2;   // 32, as requested
  uint32 status      = 3;   // ChunkStatus
  bytes  data        = 4;   // the stored blob (nonce || ciphertext), present iff status = CHUNK_OK
}

enum ChunkStatus { CHUNK_UNSPECIFIED = 0; CHUNK_OK = 1; CHUNK_NOT_FOUND = 2; CHUNK_BUSY = 3; }
```

- The chunk is sent exactly as stored; it is ciphertext, so no wire compression is
  applied or negotiated. The compression that was applied before encryption is inside
  the ciphertext (`keys.md` §3.3) and is one the folder's `required_features`
  guarantee every member can decode. Hello's `compressions` list is what a device can
  decode inside the second layer; a writer never writes with a compression the folder
  does not require of every member, and a folder's `required_features` may only name
  compressions and hashes. Deviation from the plan (steps 6 and 7: "chunk request
  naming the compressions A can decode; chunk reply with the compression used or
  none"): ciphertext does not compress, so compression is chosen at write time and
  settled at folder level, and the reply carries the stored bytes verbatim.
- The requester keeps at most the holder's `max_requests_in_flight` requests
  outstanding on a connection; a holder that receives more closes with
  `PROTOCOL_ERROR`. A holder answers `CHUNK_BUSY` when it is rate-limiting, or when its
  send queue (3.1) would make the request wait long; the requester retries with backoff
  through the clock trait.
- On receipt the requester first checks `H("licketysync/v1/hash/chunk", data) = cipher_hash`.
  A mismatch is **forged** (section 5): the sender delivered bytes that are not the chunk
  it named. With the hash correct, the sender delivered exactly what the writer stored,
  so every later failure is the **writer's fault** and leaves the connection open:
  `len(data) ≠ stored_len` in the record that names the hash, a seal that will not open,
  bad padding, an unsupported compression code, a decompression that overruns the bound
  or yields nothing, or a `plain_hash` mismatch; the chunk is marked corrupt under Issues
  naming the writer key. When several records name one `cipher_hash` (deduplication),
  each is judged on its own: a record whose `stored_len`, epoch, seal, padding or
  `plain_hash` the chunk fails is that record's writer's fault and the chunk is corrupt
  for that record only; a record it satisfies stays good.
- A requester sends chunk requests for a record on a connection only after it has sent
  that record on the connection or received it from the peer, or once the holder's own
  cursor for the record's writer (its `IndexRequest`) covers the record's `seq` and that
  cursor's `head_hash` equals the requester's own chain record at the same applied head,
  so that both hold the same chain there and the holder normally holds a record that
  names the hash. The holder answers a hash named by no record it holds for the folder
  with `CHUNK_NOT_FOUND`. "Sent" includes records the holder then rejected: a hash named
  only by those is answered `CHUNK_NOT_FOUND` too, and the requester does not ask that
  holder for it again on the connection until a record naming it arrives from the holder.
  The holder keeps the hashes it has answered this way on the connection, a set of at
  most 64, and closes with `PROTOCOL_ERROR` when a request would make the set exceed 64,
  or asks again for a hash already in it (the requester must not re-ask); the set is
  emptied whenever the holder comes to hold, by any connection, a record naming one of
  its hashes, and it is the only record of hashes the holder keeps per connection; an
  honest burst of `max_requests_in_flight` requests cannot trip it, because every hash in
  it is named by a record the holder holds, save those it rejected. A `ChunkReply` for a
  hash the receiver has no request outstanding for on the connection is unsolicited:
  `Close(PROTOCOL_ERROR)`.

## 5. Rules

- **Unknown types**: non-critical → `Unsupported`, continue; critical →
  `Close(UNSUPPORTED_CRITICAL_TYPE)`. Both only once the peer's DeviceProof has verified:
  before that every frame but that DeviceProof or a Close is `Close(PROTOCOL_ERROR)`
  (section 2, 3.2).
- **Features and the feature set.** A feature name is `[a-z0-9:-]{1,32}`. A device's
  **feature set** is its Hello `features` plus `compression:<c>` for every entry of
  `compressions` and `hash:<h>` for every entry of `hashes`; so every device's set
  contains `compression:none` and `hash:blake3`. A folder may require features
  (`required_features` in its Folder record, `keys.md` §2.2); a peer whose feature set
  lacks one is told which in `ProofResult(FEATURE_REQUIRED)` and nothing of the folder
  is exchanged with it. Major 1 defines no features beyond the compression and hash
  names; new ones are registered in this file.
- **Never use what the peer did not list**: a sender never relies on a suite,
  compression, hash or feature the receiver's Hello did not list, and may always
  fall back to `none` or `blake3`.
- **Limits are per connection**: every per-peer table (open folders, pending proofs, held
  grants, cursors, the one outstanding `IndexRequest` and `KeyRecordsRequest` per folder,
  outstanding chunk requests, pending pages, unknown-hash counters, resync timers, the
  once-per-writer flags of sections 4.4 and 4.5, rate-limit state) is bounded by the
  constants in this file (the per-writer flags by `MAX_WRITERS_PER_FOLDER`) and is freed
  when the connection closes. Nothing a peer sends can grow a table past its bound; the
  next item is refused with `PROTOCOL_ERROR`.
- **Every decoder is fuzzed**: frames, every message body, every record body, the
  sealed metadata, chunk blobs, key strings and links. A decoder never panics and never
  reads past a declared length.
- **Nothing is silently skipped.** Every failure has exactly one of three outcomes, and
  the table below is the complete mapping. *Close* is for what only the sender can be
  blamed for: it forwarded bytes that do not parse or do not verify, or broke the
  protocol's order or bounds. *Reject and keep* is for differences in knowledge: the
  verifier holds a record the sender may not, or lacks one the sender assumed. *Flag the
  writer* (or issuer, signer) is for anything a valid signature covers: the body is what
  its signer made, the sender merely carried it, so the issue is raised against that key
  and the connection stays open. Every outcome raises an issue or a log line that names
  the cause; none drops the item without trace.
- **No blame before a signature.** No outcome in the Flag rows may be reached on a
  record whose signature has not verified; a signature failure is always forged. Every
  procedure in this file and in `keys.md` verifies the signature immediately after
  parsing and resolving the signer, before any step whose failure is charged to a
  signer, issuer or writer; until then every failure is malformed, forged or a missing
  dependency.

| Cause | Outcome |
| --- | --- |
| **Malformed**: frame length below 2, body that does not parse, a field number above 2^29 − 1 or a group wire type, a size or bound or grammar violated, a fixed-size field absent or of another size, a FolderProof envelope with a wrong `hint` or `nonce` size or `sealed` over its bound, a message for a folder not open here, a message before Hello or DeviceProof, a known type where only Hello or Close may come, any frame but DeviceProof or Close before the peer's DeviceProof verified, a second Hello or DeviceProof, a list past its bound, a second proof for an accepted hint, more proofs or chunk requests than allowed, a stray or second `ProofResult` or one whose `status` is outside 1 to 3, a self-grant, a `key_signature` on a record that is not a grant, an index record whose writer is `root_key_id`, a `Cursor` whose `head_hash` length does not match its applied head, a writer listed twice in `have`, an `IndexRecords` page of more than `MAX_PAGE_RECORDS` records, an `IndexRecords` push with `more` set or a `KeyRecords` one outside the on-open set, a second `IndexRequest` for a folder before the reply to the first has queued its last page, a 65th hash named by no record the holder holds in the connection's set of such hashes, or a repeat request for one already in it, a `ChunkReply` for no outstanding request, a reply page whose `request_id` names no outstanding request, a `KeyRecordsRequest` for a folder while the reply to the previous one is going out or within `KEY_RESYNC_INTERVAL / 2` after its last page was queued, a Status whose `device_name` breaks its grammar, a field that is not repeated occurring twice in a body, an encoded `SignedRecord` over `MAX_INDEX_RECORD_BYTES` or `MAX_KEY_RECORD_BYTES` | `Close(PROTOCOL_ERROR)` |
| Frame over the limit | `Close(MESSAGE_TOO_LARGE)`, nothing allocated |
| Unknown critical type | `Close(UNSUPPORTED_CRITICAL_TYPE)` |
| Unknown non-critical type | `Unsupported`, continue |
| No common suite; `max_message_size` below the floor | `Close(NO_COMMON_SUITE)`; `Close(LIMIT_TOO_SMALL)` |
| DeviceProof does not verify | `Close(PROOF_REJECTED)` |
| `HELLO_TIMEOUT` or `IDLE_TIMEOUT` elapsed; `PROOF_TIMEOUT` elapsed with nothing opened | `Close(TIMEOUT)`; `Close(NO_COMMON_FOLDER)` |
| **Forged**: a record whose signature fails, or a grant whose proof-of-possession `key_signature` is missing or fails (a grant inside a FolderProof payload excepted: REJECTED); a chunk whose ciphertext hash fails | `Close(VERIFICATION_FAILED)`; issue naming the peer |
| **Sender violation**: a gap inside a cursor reply; a dependency absent inside a reply the sender itself paged | `Close(PROTOCOL_ERROR)` |
| FolderProof payload fails for any reason (hint, seal, parse, the leaf's proof signature, chain, a forged grant or a failed proof of possession in it, an unknown key, presentability, the open-folder bound, the held-grant bound, a fifth proof for one folder) | `ProofResult(REJECTED)`, keep; evidence only after the signature verified, and nothing else pushed before the folder is open |
| Required feature or suite missing | `ProofResult(FEATURE_REQUIRED)` naming each missing feature, a missing suite as `suite:<n>`; keep |
| **Missing dependency**: writer's or issuer's grant, a record named by `cause`, `view`, `suspension` or `resumes`, the key a Wrap serves, the rotation of a grant's epoch, a Rotation's `new_epoch` above current + 1, a Wrap's `epoch` above current, not held here (a cutoff's writer or `head_hash` is never one) | Reject (not stored), keep; `KeyRecordsRequest` or `IndexRequest` to re-request |
| **Gap** on a push (`seq > cursor + 1`, whatever `previous` names) | Ignore, keep; ask from the cursor in the next `IndexRequest`, at most once per `INDEX_RESYNC_INTERVAL` |
| **Duplicate** (`seq ≤ cursor`, the same hash as the chain or evidence record held there; a record that collides at or above the writer's fork, a duplicate of the fork, which an implementation may report as an outcome of its own; a key record with the same `record_hash`) | Ignore, keep |
| A rival or stale Rotation (`new_epoch ≤` current, another hash) | Store as evidence once its parse, signer and signature steps pass, keep; settled by `keys.md` §7.1 step 7 when it is for the current epoch |
| **Rollback**: a peer offers cursors below those stored here | Ignore, keep; nothing is asked for; a cursor never decreases, and the applied head moves back only by a stored cutoff or an equivocation withdrawal |
| **Validity-only rejection**: a record from a writer this verifier knows to be revoked or suspended beyond its cutoff; a restart before this device's clock passes the suspension's `until`; a Wrap for a key this verifier knows revoked or suspended to `none`; a record naming a suite this release does not implement; a record from a writer that is not chain-valid (its grants begin no valid chain of at most 16 grants, `keys.md` §5.5) and that no cutoff covers; a key record once the folder holds `MAX_KEY_RECORDS_PER_FOLDER`; a record from a further writer once `MAX_WRITERS_PER_FOLDER` are held, or from a further device ID once its key has `MAX_DEVICES_PER_KEY`; the later of two grants whose key IDs collide over different public keys | Reject, keep; push the explaining key records to the sender (after open), where there are any |
| **Equivocation**, each at the record's own `seq` (two records from one writer at one `seq`; a record whose `previous` is not the hash of the chain record at `seq - 1`; a second restart naming the same Suspension) | Flag the writer key; `fork = min(fork, seq)`, pushing the records at a new or lower fork on every open connection; keep the record on the chain at `cursor + 1`, or below the earlier fork as the one evidence record at its `seq` (one at or above that fork is refused as a duplicate of the fork); withdraw the writer's chain from the fork onward on every peer, a path it empties going through the archive and the deletion brake; with an unknown parent, re-request the writer from cursor 0 on the connection the record came by, at most once per writer per connection; keep |
| **Writer fault**: a record signed by a read or sealed key; a restart whose `resumes` names a stored record that is not a Suspension cutting this writer off at `previous`; a seal that will not open, bad padding, malformed path, unknown kind or hash-count mismatch; a chunk with a correct ciphertext hash whose length, seal, padding, compression or plaintext hash fails, judged per record that names it | Flag the writer key; store the record opaque (not applied) or mark the chunk corrupt for that record; keep |
| **Signer fault** on a key record: issuer without `may_share` or tier too low; a Rotation by a signer other than root that holds no stored grant of tier 1 or 2; a Rotation that omits a key its own `view` keeps, wraps a key outside `kept ∪ {root}`, has a `view` that is not closed under issuers or names a record of another type, or whose `confirm` does not match what a holder unwrapped; a ladder that does not confirm against the previous epoch (against the rotator); a `cause` naming a record of another type or signer, or an empty `cause` from a non-root signer; a Wrap for a key granted only sealed or at a tier no grant of it has; a revocation or suspension by an unentitled signer, or a lift by a signer that is not the Suspension's own signer, root or an ancestor of that signer; a second Folder record for the folder with a different body (against root); a wrap that will not open under the aad its record names, or that opens to a key failing its epoch's `confirm` (found by the key's holder, which rejects the record locally) | Flag the signer key; reject; keep |
| Accepted with an issue: in phases 0 to 6, a grant beneath a key revoked by a Revocation this verifier holds (`keys.md` §5.4 step 9); a Rotation whose wrap reaches a key revoked by a record outside its view, or that leaves out a chain-valid key this verifier holds (`keys.md` §7.1, step 6); a key record whose signer this verifier knows revoked or suspended; a second grant for a key already granted; a cutoff naming a writer outside the revoked key's subtree (ignored); a cutoff whose head no peer has | Store and apply (the cutoff excepted); issue naming the revocation's signer and the rotator, the omitting signer (a Wrap is owed), the revoked signer, both issuers, or the revoker; keep |

- **Time** comes from a clock trait (wall time for expiry and suspension ends, as the
  device believes it; monotonic time for intervals) and the network from a transport
  trait, so every rule here is testable without sleeping. The constants are fixed by this
  protocol, since a peer enforces some of them (`KEY_RESYNC_INTERVAL`, the bounds); the
  simulator may scale them, both sides alike.

| Constant | Default |
| --- | --- |
| `HELLO_TIMEOUT` (channel up → peer's Hello and DeviceProof) | 10 s |
| `PROOF_TIMEOUT` (DeviceProofs → first open folder) | 30 s |
| `IDLE_TIMEOUT` (no frame in either direction, Status counting; also, while unsent bytes remain, the longest a connection may go without delivering one, 3.1) | 5 min |
| `STATUS_INTERVAL` | 30 s |
| `KEY_RESYNC_INTERVAL` (from the last page of one `KeyRecordsRequest` reply to the next request for the folder; the responder closes below half of it, 4.6) | 30 s |
| `INDEX_RESYNC_INTERVAL` (minimum gap between gap-triggered `IndexRequest`s per folder) | 10 s |
| `INDEX_REQUEST_MIN_INTERVAL` (a responder serves a folder's `IndexRequest`s on a connection at most this often, delaying, never refusing, the rest; 4.5) | 1 s |
| `MAX_HELD_GRANTS_PER_CONNECTION` (future-epoch grants held from accepted proofs, all folders together, 3.5 step 6) | 64 |
| `MAX_WRITERS_PER_FOLDER` (writers a peer holds per folder; a further one is refused validity-only, 4.4 step 6) | 16 384 |
| `MAX_DEVICES_PER_KEY` (device IDs one write key may write under in a folder; a further one is refused validity-only, 4.4 step 6) | 256 |
| `MAX_KEY_RECORDS_PER_FOLDER` (key records a peer stores per folder; a further one is a validity-only rejection with an issue naming the folder; an insider can fill it until phase 7, and at the cap the on-open set is 65 536 records per connection, `keys.md` §5) | 65 536 |
| `MAX_SEND_QUEUE` (unsent bytes per connection; the runtime may end a connection past it, and senders pace below it, 3.1) | 128 MiB |
| `MAX_PAGE_RECORDS` (records per `IndexRecords` page or push; the cap on `max_records` and the receiver's bound, 4.5) | 4096 |
| `MAX_PROOFS_PER_CONNECTION` (4 attempts per folder × `MAX_OPEN_FOLDERS_PER_CONNECTION`; a verifier also checks at most 4 per hint-matched folder, 3.5 step 2) | 256 |
| `MAX_OPEN_FOLDERS_PER_CONNECTION` (a proof past it is REJECTED, 3.5 step 10) | 64 |
| Default `max_requests_in_flight` | 64 |
| `MAX_CHUNK_PLAINTEXT` | 4 MiB |

## 6. Compatibility

- The previous major stays supported for twelve months after its successor ships; a
  device speaks both and the dialer offers the newer first.
- CI runs the last two released binaries against each build (the protocol
  compatibility matrix in the integration suite) so that a change that breaks either
  fails before it merges.
- New optional messages (critical bit clear), new fields in any message or record, new
  feature names, new compressions and hashes, and new suites **never** bump the major.
  A new suite ships in a release that lists it in Hello; how a folder moves to it is
  undesigned phase 7 work (`keys.md` §11), and until then a folder's current suite is
  its Folder record's. A new field whose absence would change the meaning of a record or
  message for an old peer is never added as optional: it is gated by a feature name in
  `required_features`, so that old peers are refused the folder rather than misread it.
- Index records follow the same optional-field rule: a new metadata kind is a new field
  in `IndexRecord` or `SealedMeta` that old peers store and forward unread, because
  verifiers never re-encode a body (`keys.md` §5.2).
- Retiring a suite is a release that drops it from the allowed set plus a folder's
  `minimum_suite` (phase 7) that refuses older peers; peers that cannot meet it are told
  so under Issues.

## 7. Phase 0 scope

The phase 0 gate is "simulated peers converge; spec published". The simulator
(`licketysync-sim`) provides a deterministic clock (monotonic time and a per-peer wall
clock with injectable skew), a transport that honours the contract of 3.1 (a reliable,
ordered stream per connection, with seeded delay, disconnects and partitions; loss is
only ever a disconnect), seeded randomness, and peer identities; over it the real
`licketysync-protocol`, `licketysync-keys`, `licketysync-index` and
`licketysync-engine` code runs unchanged. Because the simulated transport has no
authenticated identity, the transport-identity check of 3.1 is a no-op in phase 0 and
the libp2p identity keys the transcript binds are the ones the Hellos carry. In phase 0
the following are exercised with real cryptography:

- Framing (section 2) with every limit and failure path.
- Hello, roles and DeviceProof (3.2 to 3.4) with real hybrid signatures over the
  transcript.
- FolderProof and ProofResult (3.5): real grants signed by a root key derived from a
  phrase, the encrypted payload under a fresh nonce, the hint, the uniform rejection,
  expiry against a skewed wall clock.
- KeyRecords and KeyRecordsRequest (incremental, by `have`) with Folder and Grant
  records; IndexRequest and IndexRecords with cursors, pages, pushes and gap recovery;
  chain, duplicate, equivocation and rollback handling; sealed metadata.
- ChunkRequest/ChunkReply with real convergent encryption, Padmé padding, ciphertext
  hashes and both attribution paths.
- Status and Unsupported; every row of section 5's table that phase 0 can reach.

Not in phase 0: QUIC, TLS, Noise, mDNS, the DHT and everything else libp2p provides
(phase 1 and 2); key strings, links and files (phase 1); rotation, wrap, revocation,
suspension and lift being applied (phase 7; stored and forwarded from phase 0);
linked devices (phase 5); compressions other than `none` (phase 1+).

## 8. Test vectors the protocol crate must publish

Generated by the reference implementation, checked in as data files, shared with
`keys.md` §9 item 12 where the inputs overlap:

1. **Frames**: a valid frame; length 0 and 1; length one over each limit; an unknown
   critical and an unknown non-critical type; a first frame that is not Hello; an
   unknown non-critical type before the peer's DeviceProof (`Close(PROTOCOL_ERROR)`, not
   `Unsupported`); a frame between the peer's Hello and its DeviceProof one byte over
   `PRE_HELLO_LIMIT` (`Close(MESSAGE_TOO_LARGE)`); a body with a field number of 2^29 and
   one with a group wire type (malformed); a fixed-size field left absent (malformed)
   and one that may be empty left absent (accepted); a singular field occurring twice
   (malformed); a repeated scalar field packed, the same unpacked, and the same partly
   each (all accepted, the values concatenated in order, same meaning).
2. **Hello**: canonical bytes of two fixed Hellos (A and B by the role rule, including
   one pair where the dialler is B), and each failing variant (missing `none`, missing
   `blake3`, limit below the floor, no common suite, bad identity length, bad feature
   grammar, equal device keys); a second Hello (`Close(PROTOCOL_ERROR)`).
3. **Transcript**: `th` for those Hellos and `/licketysync/sync/1`.
4. **DeviceProof** for both roles, one that fails, and a second DeviceProof
   (`Close(PROTOCOL_ERROR)`).
5. **FolderProof**: hint, proof key, sealed payload for a fixed nonce (with a full
   16-grant chain, both signatures on every grant), and `ProofResult` for each of
   ACCEPTED, REJECTED (one per numbered step of 3.5, among them a payload carrying a
   grant with a bad signature, one whose leaf grant's proof of possession fails, and a
   proof signature over another key ID; a bad proof signature is rejected before any
   grant of the chain is stored) and FEATURE_REQUIRED (with a missing feature and with
   `suite:<n>`); an envelope with a wrong nonce size (`Close(PROTOCOL_ERROR)`); a proof
   by a bare-string joiner whose grant is unknown (REJECTED); a fifth proof for one
   hint-matched folder (REJECTED without being opened); a stray `ProofResult`, a second
   one for the same proof and one with `status = 4` (all `Close(PROTOCOL_ERROR)`); a key
   presentable only through a chain that is not its governing one (ACCEPTED, at that
   chain's tier); a grant at a future epoch held through the handshake and stored on
   open, one held by a proof that is then REJECTED (discarded), and a chain that would
   pass `MAX_HELD_GRANTS_PER_CONNECTION` (REJECTED); these arise in phase 0 too, since the
   dense chain of stored rotations sets the epoch (`keys.md` §7).
6. **IndexRecord**: canonical body, record hash, signature and sealed part (fixed nonce)
   for a file, a directory, an empty file and a tombstone; variants for every row of
   section 5's table that an index record can reach (malformed, among them a writer of
   `root_key_id`, a chunk of epoch 0, `suite` 0 and a `sealed` of 39 bytes; forged;
   missing dependency; gap; duplicate; validity-only, among them a writer past
   `MAX_WRITERS_PER_FOLDER`, the 257th device ID of one key (an issue against the key)
   and one whose key's only chain is 17 grants long; malformed again, a record one byte
   over `MAX_INDEX_RECORD_BYTES`;
   equivocation at `seq ≤ cursor` and at `seq = cursor + 1` with `previous` not the
   chain record at `seq - 1` (the fork at the record's own `seq`), a lower collision
   that moves the fork down and the fork push it causes, a collision at or above the
   fork refused as a duplicate, an unknown parent at `cursor + 1` and at a held `seq`,
   each with the request from cursor 0 it triggers on the connection it came by; writer
   fault in the seal; a forged record that would also be a writer fault, showing forged
   wins); a record under a key with two grants, judged under the governing one. Phase 7:
   a restart record with `resumes` (accepted), one at `seq = 1` after a cutoff that kept
   nothing, one whose Suspension is absent (missing dependency), one whose `resumes` does
   not continue the cutoff (writer fault) and a second restart for the same Suspension
   (equivocation); a cutoff that disagrees with the held chain and the one rewound
   `IndexRequest` it triggers; records applied provisionally below a cutoff and
   confirmed; two Revocation cutoffs that disagree and the common prefix that survives.
7. **Cursors and pages**: an `IndexRequest`, a two-page `IndexRecords` reply, a push, a
   push arriving between the two pages and told apart by `request_id`, a push with a gap
   and the `IndexRequest` it triggers, a reply for a forked writer that carries both
   fork-sequence records in that writer's place, counted against `max_records`, to a
   requester whose cursor is past the fork and whose `fork` is 0, the same request with
   `fork` at the fork, which carries neither, a `Cursor` whose `head_hash` names the
   record at its applied head `min(seq, fork - 1)` and one whose `head_hash` differs
   from the responder's record there, with the evidence record its reply carries once
   and not on a second request on the connection, a third record at the fork refused as
   a duplicate; paging at `max_records = 64` with an evidence pair at the boundary (a
   page never holds more than 64), `max_records = 1` served as 64, a page cut by
   `max_message_size`, `max_records = 0` and 5000 both served as 4096; a page of 4097
   records, a writer listed twice in `have`, a `head_hash` of the wrong length for its
   applied head, an `IndexRecords` push with `more = true`, and a second `IndexRequest`
   before the first reply's last page (all `Close(PROTOCOL_ERROR)`); a request that
   arrives within `INDEX_REQUEST_MIN_INTERVAL` of the previous one, served once the
   interval has passed; pushes deferred while the send queue is full, then sent
   coalesced (per writer the push for its lowest fork and its newest other record, the
   receiver fetching the rest through its gap rule); a connection whose unsent count has
   not fallen for `IDLE_TIMEOUT` (`Close(TIMEOUT)`), and a long paced transfer whose
   queue never empties but keeps falling (kept open).
8. **KeyRecords**: the on-open set in dependency order with `request_id = 0`, a
   `KeyRecordsRequest` with `have` and the incremental reply it earns, a batch that
   violates the ordering rule, a request that arrives `KEY_RESYNC_INTERVAL / 2` after
   the previous reply's last page was queued (served) and one that arrives while that
   reply is going out (`Close(PROTOCOL_ERROR)`), a grant whose proof of possession
   fails (forged), and a key record one byte over `MAX_KEY_RECORD_BYTES` (malformed).
9. **Chunks**: `ChunkRequest`, `ChunkReply` for the `keys.md` chunk vector, and the three
   statuses; a reply whose hash fails (forged), one whose length fails (writer fault), a
   chunk named by two records of which only one it satisfies (one writer fault), a
   request answered `CHUNK_BUSY` while the holder's unsent bytes are near
   `MAX_SEND_QUEUE`, a
   request with no `cipher_hash` (malformed) and an unsolicited reply
   (`Close(PROTOCOL_ERROR)`).
10. **Close** for every reason, with and without `detail`, and one whose `detail` holds a
    control character (not shown).
11. **Closes the rules reach**: the request that would make the set of hashes named by no
    record the holder holds exceed 64, a repeat request for a hash already in it, a
    `KeyRecordsRequest` inside the interval, a message for a folder not open, a second
    proof for an accepted hint, a reply page with an unknown `request_id`, a frame other
    than DeviceProof before the peer's DeviceProof.
12. **Status**: one per open folder, the first after the first open carrying a
    `device_name`, and one whose name holds a control character (`Close(PROTOCOL_ERROR)`).
