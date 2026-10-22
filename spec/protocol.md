# Lickety-Sync sync protocol, major version 1

Status: draft for phase 0, rewritten 2026-10-22 for the shared-key model (`keys.md`) and the
coordinator's rulings R-K1 to R-K6 and S-1 to S-4 of that day. This file is what
`licketysync-protocol`, `licketysync-index` and `licketysync-engine` implement on the wire, and
what reviewers check them against. `keys.md` defines every key, record and derivation this file
uses; `suites.md` the algorithms; `threat-model.md` the adversaries. Each section says in plain
words what it is for, then defines it exactly. "Phase N" marks what phase 0 ("simulated peers
converge") may leave out; the formats are fixed now.

Every byte that arrives from a peer is untrusted: lengths are checked before anything is allocated,
every collection a peer can grow is bounded, every decoder is fuzzed, and nothing is ever silently
skipped: section 5's table says, for every failure, whether it closes the connection (malformed or
forged input, the sender's fault), is set aside while the connection stays open (a difference in
what the two peers hold), or is raised under Issues against the record a valid signature covers.
**Issues** is the list of problems a device shows its person (the plan's Issues panel); every
outcome in section 5 that says "issue" adds one that names its cause.

**What changed on 2026-10-22.** The drafts of 2026-10-14 to 2026-10-18 carried the issued-keys
model. Removed, with nothing in their place unless this file says so: key records and the two
messages that carried them (`KeyRecords`, `KeyRecordsRequest`), grant chains in the folder proof,
key IDs, per-key device admission, writer and per-key caps, forks, equivocation evidence and
withdrawal, cutoffs and restart records, held grants, the key-record quotas and refusal memory,
hybrid signatures, version vectors (ruling R-K6), the Folder record with its required features
(ruling S-2), separate proofs per tier (ruling S-1), the rule on whom a chunk may be requested from
(ruling S-3) and any "written by" display (ruling S-4). Added: one folder proof, by the access key,
for every tier; cursor digests that reconcile concurrent versions (ruling R-K5); range requests so
that no message or table grows with the number of writers (ruling R-K4); and `supersedes`, by which
each version names the versions it replaces (ruling R-K6). The drafts never shipped, so their type
numbers, field numbers and enum values carry no compatibility duty: a `reserved` marker here is only
a reading aid. Sections 1 to 4.5 and 5 to 8 keep their numbers; the drafts' 4.6 (key records) is
gone, and their 4.7 (chunks) is now 4.6.

## 1. Protocol identifier and major versions

The protocol name carries its major version, and libp2p's protocol negotiation picks the newest one
both sides list. Within a major, everything new is optional: a new message type with the critical
bit clear, a new field, a new feature flag. A major changes only when the handshake or the meaning
of index records changes.

- Identifier: `/licketysync/sync/1`. A device may list several majors (`/licketysync/sync/2`,
  `/licketysync/sync/1`); the dialer lists them newest first and multistream-select picks the first
  one the listener also supports.
- Two devices with no major in common get a negotiation failure. The dialer reports it under Issues
  naming the versions it offered and, when the listener's list is known, the versions it saw; the
  site publishes which release speaks which major.
- This document is major 1. Minor evolution is by feature flags in Hello (section 4.2) and by
  Protocol Buffers' own rule that unknown fields are skipped.
- Phase 0: the simulator's transport hands each connection the string `/licketysync/sync/1`;
  nothing else is negotiated.

## 2. Framing

Every message is a length, a type and a Protocol Buffers body. The length comes first so the
receiver can refuse an oversized frame before it reads or allocates anything for it; the type
carries a critical bit so that a receiver that does not know a type knows whether it may ignore it.

```
+----------------+----------------+------------------------+
| length  u32 BE | type  u16 BE   | body (length - 2 bytes)|
+----------------+----------------+------------------------+
length  = 2 + len(body)
type    = critical (bit 15) | number (bits 0..14)         # 0x8000 | n for critical types
```

Receiving, in this order and with no allocation for a frame before step 3 (the bytes arrive in
pieces of any size, 3.1; the frame decoder works through them):

1. Read exactly 4 bytes; `length` is the value.
2. If `length < 2`: send `Close(PROTOCOL_ERROR)` and close. If `length > limit` (defined below):
   send `Close(MESSAGE_TOO_LARGE)` and close without reading further.
3. Read `length` bytes, growing the frame's buffer as they arrive and never past `length`; when the
   frame is complete, split off the type.
4. Dispatch on the type: known type → decode the body with that type's schema; decode failure →
   `Close(PROTOCOL_ERROR)`. Unknown type with the critical bit set →
   `Close(UNSUPPORTED_CRITICAL_TYPE)`. Unknown type with the bit clear → send
   `Unsupported { message_type }`, at most once per type per connection (later frames of that type
   are ignored with a log line), and continue. The first frame on a connection must be a Hello or a
   Close; any other type first, known or unknown, is `Close(PROTOCOL_ERROR)`. Until the peer's
   DeviceProof has verified, the only frames accepted are that one Hello, that one DeviceProof and
   Close: any other frame, an unknown non-critical type included, is `Close(PROTOCOL_ERROR)`, not
   `Unsupported` (section 3.2 takes precedence here). Frames are decoded and dispatched one at a
   time, each dispatched before the next is decoded, and nothing after a Close, sent or received, is
   processed.

Limits:

| Name | Value | Meaning |
| --- | --- | --- |
| `PRE_HELLO_LIMIT` | 65 536 | Applies to every frame received on a connection until the peer's DeviceProof has verified (its Hello, its DeviceProof or a Close), and to anything sent before the peer's Hello has arrived. The largest Hello a release of major 1 sends is a frame of 2 664 bytes (length field included, 2 668) and a DeviceProof one of 68 (72), so both fit |
| `MIN_MESSAGE_SIZE` | 8 388 608 (8 MiB) | The smallest `max_message_size` a Hello may advertise; a smaller one is `Close(LIMIT_TOO_SMALL)` |
| `DEFAULT_MESSAGE_SIZE` | 16 777 216 (16 MiB) | What a device advertises unless configured otherwise |
| `MAX_MESSAGE_SIZE` | 67 108 864 (64 MiB) | The largest value a Hello may advertise; larger is treated as this value |
| `MAX_INDEX_RECORD_BYTES` | 4 000 000 | The largest encoded `SignedRecord`; a larger one is malformed at parse, before any duplicate check |

- The limit for **incoming** frames is the receiver's own advertised `max_message_size` (what it
  told the peer it accepts), except that every frame received before the peer's DeviceProof has
  verified is also bounded by `PRE_HELLO_LIMIT`. The limit for **outgoing** frames is the peer's
  advertised value; a sender never emits a frame larger than that, and before the peer's Hello
  arrives it sends only Hello and Close.
- `MIN_MESSAGE_SIZE` is set so that one `ChunkReply` carrying the largest chunk
  (`MAX_CHUNK_PLAINTEXT` = 4 MiB plus Padmé and framing, `keys.md` §3.2) and one index record with
  the most chunks (section 4.4: 32 768 chunk references of about 41 encoded bytes each, a sealed part
  of at most 1.5 MiB, at most 16 `supersedes` entries and the signature, about 3 MiB in all) each
  always fit. The record cap makes that hold for any record a peer accepts, unknown fields included:
  a record at `MAX_INDEX_RECORD_BYTES` fits one page of `MIN_MESSAGE_SIZE`, so no peer can be handed
  a record that another peer's advertised limit cannot carry, and a field that would let records
  grow past the cap needs a new major (section 6). Every message that carries a list is
  additionally bounded by the peer's `max_message_size`: a sender pages before it reaches it.
- The body of every message is proto3 (`syntax = "proto3"`), package `licketysync.v1`. The protocol
  crate mirrors the schemas in section 4 with prost derives; the `.proto` text in this file is
  normative, the crate's generated types are the implementation. A field number marked `reserved`
  belonged to the drafts and reads as an unknown field; from the first release on, no number that a
  release has used is ever given a new meaning in major 1.
- **Every decoder judges a body the same way.** A field number above 2^29 − 1 (536 870 911) is
  malformed, and so is a field, known or unknown, with a group wire type (3 or 4); every other
  unknown field is skipped (and, inside a signed body, kept and forwarded, `keys.md` §5.2). Both
  rules are fixed because a signed body must be accepted or refused alike by every implementation: a
  record that one decoder skipped over and another refused would split peers. For the same reason a
  field that is not repeated and occurs more than once in a body is malformed (proto3 would keep the
  last occurrence; a verifier here refuses, so that a record carrying two sequence numbers means
  nothing to anyone), while a repeated scalar field is accepted packed or unpacked, as proto3 allows
  (producers pack, `keys.md` §5.2), or partly each, the values concatenated in the order they
  appear. Every fixed-size field (hashes, device IDs, nonces, public keys, signatures, digests) must
  be present at its exact size, unless its field says it may be empty (such as a `Cursor`'s
  `digest` at `seq` 0, or an `IndexRequest`'s `after` and `through`); an absent field reads as
  empty, which is then the wrong size, so it is malformed. A `bool` whose varint is neither 0 nor 1,
  and a `uint32` whose varint is 2^32 or more, are malformed too, rather than truncated as proto3
  decoders may, for the same reason.

## 3. The handshake

Seven steps, as the plan draws them. Steps 1 and 2 belong to libp2p: the encrypted channel, with
exactly one security protocol per transport so that nothing is chosen before either side is
authenticated (TLS 1.3 on QUIC and on TCP; Noise inside WebSocket, WebRTC and WebTransport, where
TLS is not offered; `suites.md` §2.6), then protocol negotiation; phase 0 simulates them. Steps 3 to
7 are this protocol. The folder proof in step 4 is the heart of it: each side shows it holds a key
to the folder (any of the three, since each holds the folder's access key) without sending the key,
in a way that only a holder of a key to that folder can even open, and that cannot be replayed into
another connection. Nothing about a folder leaves a device until the peer has proven it holds a key
to that folder, and a failed proof is answered with the same result whether the folder is unknown
here or the proof was bad.

```
A (role 0x01)                                            B (role 0x02)
 1. encrypted channel  ──────────────── (libp2p: TLS on QUIC or TCP; Noise inside WebSocket, WebRTC, WebTransport)
 2. identify           ─── /licketysync/sync/1 ──────▶ newest common major
 3. Hello ───────────────────────────────────────────▶
    ◀──────────────────────────────────────────── Hello     roles are now known (3.2)
    DeviceProof ─────────────────────────────────────▶
    ◀─────────────────────────────────────── DeviceProof
 4. FolderProof(X) ──────────────────────────────────▶ verify; if X is here and the proof holds:
    ◀────────────────────────── ProofResult(X, ACCEPTED), FolderProof(X)
    ProofResult(X, ACCEPTED) ────────────────────────▶ X is open on this connection
 5. IndexRequest(X, range, cursors) ◀───────────────▶ IndexRequest(X, range, cursors)
    IndexRecords(X, …, more) ◀──────────────────────▶ IndexRecords(X, …)        (replies, and pushes from now on)
 6. ChunkRequest(X, cipher_hash) ────────────────────▶
 7. ◀──────────────────────────────── ChunkReply(X, cipher_hash, data)
    Status ◀────────────────────────────────────────▶ Status   (periodic, non-critical)
```

### 3.1 Steps 1 and 2: channel, identity and version

**Transport contract.** This protocol runs over one reliable, ordered byte stream per connection (a
QUIC stream, a TCP connection, a WebTransport or WebRTC stream, or the simulator's channel). The
transport carries bytes, not frames: sending appends bytes, and delivery hands over the next bytes
with arbitrary chunk boundaries (at most 64 KiB at a time), so the engine's frame decoder, the
protocol crate's, assembles frames and enforces every size limit of section 2 (`PRE_HELLO_LIMIT`,
`max_message_size`), and nothing is allocated for an oversized frame. While a connection lasts its
bytes are never lost, duplicated or reordered; when it ends, whatever the other side had not yet
received may be lost, and neither side can tell which. Loss therefore shows itself only as the
connection ending (`on_disconnected`), after which every per-connection table is freed and a new
connection starts from Hello. Across connections nothing is ordered. The runtime may end a
connection whose unsent bytes pass `MAX_SEND_QUEUE` (128 MiB), and it reports a connection's unsent
bytes (`Transport::unsent`) so that senders pace below that. Every frame but Close counts: a side
sends its next frame only while the unsent bytes plus that frame stay below `MAX_SEND_QUEUE`, and the
requests it is answering wait meanwhile (a chunk request that the holder dispatches while its
unsent bytes are at least half of `MAX_SEND_QUEUE` is answered `CHUNK_BUSY` instead, 4.6). A push
that does not fit is
dropped, and the sender then owes the receiver one empty push for that folder, which makes the
receiver owe itself a round (4.5); replies and empty pushes wait in order and are never dropped.
While unsent bytes remain, a connection whose delivered bytes (bytes sent minus `Transport::unsent`)
have not grown for `IDLE_TIMEOUT` is closed with `TIMEOUT`, and the next connection's exchange
fetches what was waiting; that bounds what waits without cutting a long transfer whose paced queue
never empties.

**Identity.** The transport authenticates each side's **libp2p identity**, the separate Ed25519 key
of `keys.md` §8.1. Each Hello carries that key (`libp2p_identity`), and the transcript (3.3) covers
both, so the DeviceProof binds the device key to the channel. From phase 1 the runtime exposes the
transport-authenticated key and a side checks that it equals the peer's `libp2p_identity`, closing
with `PROTOCOL_ERROR` otherwise; in phase 0 the simulator has no authenticated transport identity,
the check is a no-op, and the Hello field alone is what the transcript binds. The protocol
identifier chosen in step 2 is bound into the transcript as well.

### 3.2 Step 3: Hello, roles and DeviceProof

Both sides send Hello at once, without waiting; neither side's Hello depends on the other's. On
receiving the peer's Hello a side checks it, determines the roles, computes the transcript hash, and
sends DeviceProof. A side accepts nothing else until it has the peer's valid Hello and DeviceProof:
before the DeviceProof has verified, any frame other than that DeviceProof or a Close, known or
unknown, critical or not, is `Close(PROTOCOL_ERROR)`; a second Hello or a second DeviceProof, at any
time, is too. A Close may arrive at any time.

**Roles.** The side whose device public key is byte-wise smaller, comparing the Ed25519 keys
(`device_public_key[2..34]`), is **A** with role byte `0x01`; the other is **B**, `0x02`. The rule
depends only on the two Hellos, so it is the same on both sides, needs no notion of who dialled, and
settles simultaneous dials. Equal keys mean a device connected to itself: `Close(PROTOCOL_ERROR)`.

Hello checks, each a `Close(PROTOCOL_ERROR)` unless noted: `device_public_key` is exactly
`be16(suite) || ed25519_pk` (34 bytes under suite 1) for an implemented suite, and its Ed25519 key is
canonical and not of small order (`keys.md` §0.3), so that one device has one device ID;
`libp2p_identity` is 32 bytes (and, from phase 1, equals the transport-authenticated key, 3.1);
`suites` is non-empty, has no duplicates, each entry is 1 to 65 535, and it shares at least one
implemented suite with ours (else `Close(NO_COMMON_SUITE)`); `compressions` contains `"none"`;
`hashes` contains `"blake3"`; `max_message_size ≥ MIN_MESSAGE_SIZE` (else `Close(LIMIT_TOO_SMALL)`);
`max_requests_in_flight ≥ 1`; `nonce` is 32 bytes; list lengths and the feature grammar (section 5)
are within section 4.2's bounds. Hello carries no device name: field 2 is reserved, and the name
travels only once a folder is open, in Status (4.5).

### 3.3 The transcript hash

```
th = H("licketysync/v1/hash/transcript",                      # H(label, x) = BLAKE3(label || 0x00 || x), keys.md §0
        be32(len(protocol_id)) || protocol_id                  # "/licketysync/sync/1"
     || be32(32) || libp2p_identity_A                          # A's libp2p identity key, as A's Hello carries it
     || be32(32) || libp2p_identity_B                          # B's
     || be32(len(hello_A))     || hello_A                      # A's Hello frame: type || body, exactly as sent
     || be32(len(hello_B))     || hello_B )                    # B's
```

Both Hellos are in it byte for byte, so the suite lists, limits, features, device keys, identities
and nonces each side saw are the ones each side signs over. A peer that was shown a different list
from the one the other side sent, by anything able to alter frames, gets a proof that does not
verify: a downgrade is detected, not negotiated. The protocol identifier and the two libp2p
identities bind the proof to this channel and to this major; from phase 1 the transport has
authenticated those identities, so the binding reaches the channel's own keys.

### 3.4 DeviceProof

```
device_signature = Sign(device_sk, "licketysync/v1/sig/device-proof", th || u8(role))     # Ed25519, 64 bytes, keys.md §0.2
```

The verifier uses the `device_public_key` from the peer's Hello and the peer's role, with
`verify_strict`. This proves the device key and, through `th`, binds it to the libp2p identity the
transport authenticated: device IDs are proven, device names only reported. Failure:
`Close(PROOF_REJECTED)`. A FolderProof that arrives before a valid DeviceProof is an ordering
violation: `Close(PROTOCOL_ERROR)`.

### 3.5 Step 4: FolderProof and ProofResult

A prover sends one FolderProof per folder it wants to sync on this connection: the folder it
discovered the peer by, or every folder it shares with a device it already knows; at most one per
folder per connection, since a device holds one key per folder (`keys.md` §1.3). There is one proof
for every tier (ruling S-1): the payload is sealed under a key that only a holder of the folder's
access key can derive, and every tier holds that key, and its hint is computed under the same access
key (`keys.md` §4). What that hides, and from whom: a peer that holds no key to the folder, a relay,
and anyone who knows only the folder ID learn neither which folder was meant nor the tier the prover
reports; they see only that a proof was attempted. The timing of the answer differs between a hint
miss and a hit that then fails, which tells only a prover that already holds a key to the folder
that this device holds it too, which an honest proof would have told it anyway.

```
hint      = BLAKE3_keyed(hint_key, folder_id || th || u8(role))        # keys.md §4; hint_key derives from ak
proof_key = BLAKE3_keyed(payload_key, folder_id || th)                 # keys.md §4; payload_key derives from ak
nonce     = 24 bytes through the runtime's randomness trait            # fresh for every FolderProof
payload   = ProofPayload { tier }                                      # section 4.3: the tier the prover reports
sealed    = XChaCha(proof_key, nonce, aad = hint, payload)
```

The payload that opens is the proof: it shows that the prover holds the access key, bound to this
connection by `th` in the proof key and to the prover's role by the hint it is sealed under. A full
payload is 2 bytes, 18 sealed, within the 1 024-byte bound on `sealed`, which leaves room for fields
a later release adds. The hint covers the role, so a proof reflected back to its sender matches none
of the sender's hints; the transcript hash covers both sides' fresh nonces, so a proof replayed from
another connection opens nowhere; and the per-proof nonce keeps every proof on a connection under a
distinct `(key, nonce)` pair. Deviation from the plan ("Capabilities": the Hello "carries the
device's ID", with "the key IDs it presents per folder" inside the folder proof): there are no key
IDs any more, and the proof carries only the reported tier.

Verification by the receiver, for each FolderProof, in order:

1. The peer's DeviceProof has verified; otherwise `Close(PROTOCOL_ERROR)` (3.4). The envelope is
   well formed: `hint` is 32 bytes, `nonce` 24, `sealed` at least 16 and at most 1 024 bytes; the
   `hint` differs from that of every earlier FolderProof on this connection; and this is at most
   the `MAX_PROOFS_PER_CONNECTION`th (256th) FolderProof on the connection. Otherwise
   `Close(PROTOCOL_ERROR)` (malformed, the sender's doing). Every failure from step 2 on is answered
   REJECTED.
2. For every folder this device holds and has not paused, compute `hint` with the peer's role; no
   match → `ProofResult { hint, REJECTED }` and stop. (A device with many folders caches the
   per-folder hints once per connection.)
3. Derive `proof_key`, open `sealed` with the message's `nonce` and `aad = hint`; failure →
   REJECTED.
4. Parse `ProofPayload`: `tier` is 1, 2 or 3; failure → REJECTED. Nothing checks the tier: it is the
   prover's report, shown and never relied on.
5. The peer's Hello `suites` includes the folder's suite; otherwise REJECTED.
6. A proof that would open more than `MAX_OPEN_FOLDERS_PER_CONNECTION` (64) folders on this
   connection is answered REJECTED (the prover opens the rest on another connection). Otherwise
   `ProofResult { hint, ACCEPTED }`. Record the peer's device ID and reported tier for this folder on
   this connection; the tier is shown marked "reported", like a device name. If this side has not yet sent its own FolderProof for the folder, send it now.

A folder is **open** on a connection when both sides have sent ACCEPTED for each other's proof. Only
then do any of the folder's records, chunks or status cross the connection; a message that names a
folder not open on the connection is `Close(PROTOCOL_ERROR)`. A connection on which no folder is open
within `PROOF_TIMEOUT` (30 s) of the DeviceProofs is closed with `NO_COMMON_FOLDER`. A ProofResult
that answers no FolderProof this side sent and has not yet had answered (a stray one), a second
ProofResult for one proof, or a `status` other than 1 or 2, is `Close(PROTOCOL_ERROR)`.

What each side learns on failure: a `REJECTED` result says only that this proof did not open this
folder here; it is the same whether the folder is absent or paused, the hint did not match, the seal
did not open, the payload was malformed, the peer did not list the folder's suite, or the
open-folder bound was reached. The prover does not try the folder again on that connection. The
reported tier is shown and never relied on: nothing in this protocol gives a peer more for a higher
tier, since index records and chunks are verified by signature and hash whoever sends them, and only
a key holder can open what it receives. A read or sealed holder may report write, and a write holder
sealed; either changes only what the other side displays.

### 3.6 Steps 5 to 7

Once a folder is open, each side runs a round of `IndexRequest`s with its cursors, and from then on
pushes every index record it newly accepts; the peer answers each request with `IndexRecords` in
pages. Chunks are requested by ciphertext hash and returned whole. Status messages report progress
periodically. Section 4 defines each message; section 4.5 the exchange.

## 4. Messages

### 4.1 Type numbers

| Number | Critical | Name | Direction | Purpose |
| --- | --- | --- | --- | --- |
| 0x8001 | yes | Hello | both, first | Identity, capabilities, limits |
| 0x8002 | yes | Close | both, last | Reason for closing |
| 0x8003 | yes | DeviceProof | both | Signature over the transcript with the device key |
| 0x8004 | yes | FolderProof | both | Sealed proof of holding a key to one folder |
| 0x8005 | yes | ProofResult | both | Answer to one FolderProof |
| 0x8007 | yes | IndexRequest | both | "Send what I lack", by range and cursor |
| 0x8008 | yes | IndexRecords | both | Signed index records, paged or pushed |
| 0x8009 | yes | ChunkRequest | requester → holder | One chunk by ciphertext hash |
| 0x800A | yes | ChunkReply | holder → requester | The chunk, or why not |
| 0x0001 | no | Status | both | Progress per open folder; the reported device name once a folder is open |
| 0x0002 | no | Unsupported | both | "I do not know that non-critical type" |
| 0x0003–0x000F, 0x8006, 0x800B–0x800F | | reserved | | Major 1 additions (0x8006 and 0x800B carried key records in the drafts) |
| 0x8010–0x801F | | reserved | | Linked-device channel (phase 5) |
| 0x0010–0x001F | | reserved | | Chunk availability for selective sync (phase 5), relay control (phase 7) |

Types 0x0000 and 0x8000 are never used. Every v1 message a v1 peer must understand is critical except
Status and Unsupported, which a peer may lack without harm.

### 4.2 Hello, Close, Unsupported

```proto
syntax = "proto3";
package licketysync.v1;

message Hello {
  bytes  device_public_key      = 1;  // be16(suite) || Ed25519 public key, canonical and not of small order; 34 bytes under suite 1; device_id = H("licketysync/v1/hash/id/device", this), keys.md §0.3
  reserved 2;                         // was device_name, which now travels in Status once a folder is open (section 4.5); a receiver ignores the field
  repeated uint32 suites        = 3;  // implemented suites, preferred first; 1 to 16 entries, each 1 ..= 65 535, no duplicates; must share one with the peer
  repeated string compressions  = 4;  // chunk compressions this device can decode: "none" always; "deflate", "zstd", "lz4" as built; <= 32 entries, each [a-z0-9-]{1,20} so that compression:<c> fits the feature grammar
  repeated string hashes        = 5;  // "blake3" required in major 1; <= 32, each [a-z0-9-]{1,20}
  repeated string features      = 6;  // optional feature names this device supports; <= 32; the feature set (section 5) is this list plus compression:<c> and hash:<h> for every entry above
  uint32 max_message_size       = 7;  // frames this device accepts, bytes; MIN_MESSAGE_SIZE ..= MAX_MESSAGE_SIZE
  uint32 max_requests_in_flight = 8;  // chunk requests this device will hold open per connection; >= 1; default 64
  bytes  nonce                  = 9;  // 32 random bytes; makes the transcript unique to this connection
  bytes  libp2p_identity        = 10; // 32: Ed25519 public key of the libp2p identity (keys.md §8.1); from phase 1 must equal the transport-authenticated key
}

message Close {
  uint32 reason = 1;   // CloseReason
  string detail = 2;   // <= 256 bytes, optional; UTF-8 with no control characters (otherwise malformed: not shown, the connection closes all the same); rendered as text only, never as markup; never carries a folder ID, record hash, path or name
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
  TIMEOUT                      = 11;  // HELLO_TIMEOUT, IDLE_TIMEOUT or REPLY_PAGE_TIMEOUT (4.5) elapsed, or, while unsent bytes remained, none was delivered for IDLE_TIMEOUT (3.1); PROOF_TIMEOUT closes with NO_COMMON_FOLDER
  reserved 12;                        // was FEATURE_REQUIRED, with the Folder record (ruling S-2)
}

message Unsupported {
  uint32 message_type = 1;   // the full 16-bit type that was not understood
}
```

A side that receives Close stops sending, frees every per-connection table and closes the
transport. A side that sends Close sends nothing after it, and its engine asks the runtime to close
the connection when the engine's own 1 s timer fires (through the clock trait) or when the peer
disconnects, whichever comes first; the Close, and anything sent before it, may still be lost if the
connection ends before the peer has received it (3.1). When a device stops, its runtime flushes what
the stopping engine sent for up to 1 s and then closes, so a peer may receive `Close(SHUTDOWN)`, or
may see only the connection end.

### 4.3 DeviceProof, FolderProof, ProofResult

```proto
message DeviceProof {
  bytes signature = 1;   // Sign(device key, "licketysync/v1/sig/device-proof", th || role); Ed25519, 64 bytes
}

message FolderProof {
  bytes hint   = 1;      // 32 bytes, section 3.5; never repeated on a connection
  bytes sealed = 2;      // XChaCha(proof_key, nonce, aad = hint, ProofPayload); 16 ..= 1 024 bytes (a full payload seals to 18)
  bytes nonce  = 3;      // 24 random bytes, fresh for every FolderProof
}

message ProofPayload {
  reserved 1, 2, 3;      // were key_id, the tier's proof and the grant chain
  uint32 tier  = 4;      // the tier the prover reports, for display only: 1 write, 2 read, 3 sealed; any other value: REJECTED
}

message ProofResult {
  bytes hint    = 1;     // echoes the FolderProof
  uint32 status = 2;     // ProofStatus
  reserved 3, 4;         // were missing_features and evidence
}

enum ProofStatus { PROOF_UNSPECIFIED = 0; ACCEPTED = 1; REJECTED = 2; }   // any other value: Close(PROTOCOL_ERROR)
```

### 4.4 The index record on the wire

An index record is one signed statement about one path: what it is, which chunks hold it, and which
versions of it, by record hash, it replaces. Every write holder signs with the same folder key
(`keys.md` §5.3), so a record names its writer only by the device ID the signer claims, which is the
key of the sequence it belongs to and nothing more. Everything that would name a file is inside a
sealed part that only read and write holders open; sealed peers and relays see what they need to
store, verify, serve and garbage-collect, and nothing more. The record is a `SignedRecord`
(`keys.md` §5.1) whose body is:

```proto
message IndexRecord {
  uint32 suite        = 1;   // the folder's suite
  uint32 record_type  = 2;   // 16
  bytes  folder_id    = 3;   // 32
  reserved 4;                // was writer_key_id
  bytes  device_id    = 5;   // 32: the writer's device ID, as the signer claims it; a sync key only, never shown as an author (keys.md §5.3)
  uint64 seq          = 6;   // per device_id: 1, 2, 3 … ..= MAX_SEQ (2^62); one device may have several records at one seq (concurrent versions, below)
  reserved 7;                // was previous: the cursor digest (below) finds every difference a per-writer hash chain would
  repeated bytes supersedes = 8;   // a set: the record_hash of each version this record replaces (below); each 32 bytes; <= MAX_SUPERSEDES (16)
  reserved 9;                // was the version vector (ruling R-K6)
  reserved 10;               // was epoch
  bool   deleted      = 11;  // tombstone: chunks is empty
  repeated ChunkRef chunks = 12;   // in file order; <= 32 768; empty for directories, tombstones and empty files
  bytes  sealed       = 13;  // nonce (24) || XChaCha(rk, nonce, aad, padded SealedMeta), keys.md §3.4; 40 ..= MAX_SEALED_BYTES (1 572 864)
  reserved 14;               // was resumes
}

message ChunkRef {
  bytes  cipher_hash = 1;    // 32: H("licketysync/v1/hash/chunk", stored), keys.md §3.2
  uint32 stored_len  = 2;    // bytes of the stored blob; 46 ..= padme(MAX_CHUNK_PLAINTEXT + 5) + 40 = 4 325 416, and itself a Padmé length plus 40
  reserved 3;                // was epoch
}

// Inside `sealed`, visible to write and read holders only.
message SealedMeta {
  string path                 = 1;   // UTF-8, '/' separated, relative, no empty, "." or ".." component, no NUL, no backslash; <= 4096 bytes; writers normalise every component to NFC, and readers do not check it (step 6)
  uint32 kind                 = 2;   // 1 file, 2 directory; others reserved
  uint64 size                 = 3;   // bytes of plaintext content; 0 for an empty file, which has no chunks
  int64  mtime_ns             = 4;   // modification time, nanoseconds since the Unix epoch
  uint32 mode                 = 5;   // Unix permission bits; 0 when the writer has none
  repeated bytes plain_hashes = 6;   // keyed BLAKE3 per chunk (keys.md §3.2), same order and count as `chunks`
  uint64 written_at           = 7;   // writer's wall clock; informational only, never used for ordering
}
```

- **Sealing**: `keys.md` §3.4: Padmé-padded `SealedMeta` under the record key `rk`, a random
  24-byte nonce, and `aad = folder_id || device_id || be64(seq)` (72 bytes), which a reader rebuilds
  from the clear fields, so a sealed part cannot be moved between records of different folders,
  devices or sequence numbers.
- **Record hash**: `record_hash = H("licketysync/v1/hash/record", body)` over the body bytes as
  received (`keys.md` §5.1); this is what `supersedes` names, what duplicates are found by and what
  cursor digests cover.
- **Records, cursor and digest**, per writer (`device_id`). A peer's **records** of a writer are
  every record of it the peer has stored, applied or opaque (step 6). Their **canonical order** is
  ascending `seq`, then ascending `record_hash`, bytewise. The peer holds at least one record at
  every `seq` from 1 to its **cursor** for the writer, the highest `seq` it holds (0 when it holds
  none); the cursor never decreases (below, "Rollback"). The writer's **digest at s**, for
  `1 ≤ s ≤ cursor`, is the value of `D` after the last record with `seq ≤ s` when `D` starts as 32
  zero bytes and each record, in canonical order, sets
  `D = H("licketysync/v1/hash/writer-digest", D || record_hash)`. Equal digests at `s` mean the same
  records through `s`, short of a BLAKE3 collision. A peer **caches** each writer's digest at every
  `seq` it holds and keeps the cache current as records arrive: a record at the cursor plus one
  extends it by one step, and a record that lands below others in canonical order recomputes it from
  its own `seq` up. Serving a request reads the cache and never recomputes a digest (4.5).
- **Concurrent versions** (ruling R-K5). A record of a writer at a `seq` where the peer already
  holds another record of that writer is a concurrent version: it is stored like any other record,
  in canonical order, and the heads (below) decide what it means for its path, as for any concurrent
  edit (`threat-model.md` TM-40). Nobody is blamed, nothing is withdrawn and no evidence is kept.
  Only three things make them: a write holder signing twice under its own device ID at one `seq`, a
  write holder signing under another device's ID (any write holder can), and a device restored from
  a backup of its index, which reuses sequence numbers (4.5, "Durability before transmission").
- **Versions and heads** (ruling R-K6). A device that writes a path (an edit, a delete, a rename)
  names in `supersedes` every **head** of that path it holds: usually one; several when the write
  resolves a conflict; none for a path new to it. A rename is one record at the new path whose
  `supersedes` names the heads of the old path (and of the new path, if it had any), so the old path
  is left with no head (decision). A device whose path has more than `MAX_SUPERSEDES` heads names the
  first 16 in display order (below), and the others stay heads, still a conflict, until a later
  write names them; a rename whose old and new paths have more than 16 heads together names the old
  path's heads first, in display order, then the new path's, up to 16, and the rest stay heads. Read
  and write holders compute heads after step 6 of the verification below:
  - A record is **waiting** while some entry of its `supersedes` names a record this peer does not
    hold, or one that is itself waiting (decision: so a chain that arrives out of order waits as a
    whole). A waiting record takes no part in heads, neither as a version nor as replacing one, until
    every record it names is held and none of them waits; so a record that arrives before a version it
    replaces makes no false conflict. Index sync brings what it waits for: whoever wrote the record held every version
    it names, and two peers that exchange come to hold the same records (4.5, TM-41).
  - A **version** of a path is an applied record (step 6) that is not waiting and whose sealed path
    is that path. The **heads** of a path are its versions that no applied, non-waiting record
    supersedes. Opaque records are neither versions nor replace anything, but they are held, so a
    record that names one does not wait for it.
  - One head is the path's current version; a tombstone head means the path is deleted. Two or more
    heads are a **conflict**, and every head is kept until a write names them. The **display order**
    of a path's heads is: heads that are not tombstones first; among those, directories before files
    (decision: a directory's children need it at the path); then the greater `mtime_ns` first; then
    the smaller `record_hash` first. The first head in display order sits at the path; when every
    head is a tombstone, the path is deleted. Every other head that is not a tombstone and whose
    content differs from the first becomes a conflict copy (TM-40); writing those copies to disk is
    the engine's (phase 1). Content differs when the kinds differ or, between two files, when their
    `plain_hashes` lists differ; two directories never differ, and nor do two files with the same
    `plain_hashes`, whatever their times or modes. So: one file and one tombstone show the file and
    make no copy (an edit beats a delete); a file and a directory show the directory and make the
    file a conflict copy; two files with different content show the one first in display order and
    copy the other; two identical files or two directories show the first and copy nothing.
  - So a device restored from an old backup, which still holds an old head, makes its next edit name
    that old head: every peer that holds the later versions then holds two heads, a conflict, and
    nothing is lost silently.
  - Sealed peers compute no heads, since they cannot read paths. What a sealed peer may
    garbage-collect is the index design's (phase 1); it can follow `supersedes` without opening a
    seal.
  - Stated residual: a record that names a version no peer holds (only a write holder can sign one)
    waits for good: it is stored, counted and forwarded, and is no version of anything. A waiting
    record writes a log line when it starts to wait, and raises an informational issue that names
    the record, never a device, once at least one peer has the folder open and a round with every
    peer that has it open has completed since the record began to wait, and it still waits.
  - Open item: compaction of a path's history (a later phase) must keep enough of each replaced
    version, at least its record hash, that a record naming it is not left waiting and an old
    version is never taken for a new one.
- **Signature**: `Sign(folder_sk, "licketysync/v1/sig/index", body)` (`keys.md` §0.2), by any write
  holder; every peer verifies with `folder_vk`.
- **Device ID**: `device_id` is the signer's claim, attested by the folder key's signature and by
  nothing else; a write holder may write under any device ID it likes. Device IDs are proven only at
  the handshake (3.4); in a record the ID is the key of a sequence, used to sync, and is never shown
  as the record's author (ruling S-4).
- **Chunk references** appear twice on purpose: `cipher_hash` in the clear, so that a sealed peer can
  fetch, verify and deduplicate by it, and `plain_hash` under the seal, so that only key holders can
  tell which plaintext a chunk is. A key holder maps between them by computing both when it writes
  (encryption is deterministic) and by decrypting when it reads; a sealed peer never can.
- **What a sealed peer or relay sees** (threat model, TM-15; these are leaks the design documents
  rather than claims away): the device ID and the sequence number, `supersedes` (which record
  replaces which), whether the record is a tombstone (`deleted`: sealed peers must see deletions to
  garbage-collect chunks), the number of chunks and each padded `stored_len`, the padded length of
  the sealed part, and the rate at which records arrive; and, because `supersedes` links the versions
  of one path, it can group records by file without knowing its name: how often each file changes,
  how its chunk count moves over time, which device IDs wrote its versions, and where its history
  forked into a conflict and joined again. It does not see the path, kind, true size, times, mode,
  plaintext hashes or `written_at`.
- **Bounds** that make the largest record fit `MIN_MESSAGE_SIZE`: 32 768 chunks per record and
  4 MiB per chunk, so a file in major 1 is at most 128 GiB, and in practice 32 768 times the engine's
  average chunk size, since FastCDC rarely produces maximal chunks; larger files are refused with an
  issue (continuation records are a phase 7 addition). At most `MAX_SUPERSEDES` (16) `supersedes`
  entries, and `seq` at most `MAX_SEQ` (2^62), so that no arithmetic on sequence numbers can
  overflow. An empty file has `size = 0`, `kind = 1`, no chunks and `deleted = false`.

Verification of an index record, in order, on every peer including sealed ones. The action on each
failure is the one section 5's table gives for its cause; the causes are named here in **bold**.

1. **Parse** the body; the encoded `SignedRecord` is at most `MAX_INDEX_RECORD_BYTES` (4 000 000)
   bytes; `suite` is the folder's suite; `record_type = 16`; sizes and bounds above, every fixed-size
   field present at its exact size; `folder_id` is the open folder; `1 ≤ seq ≤ MAX_SEQ`; `deleted`
   implies `chunks` empty; at most 16 `supersedes` entries, each 32 bytes; `sealed` 40 to
   1 572 864 bytes; each chunk's `cipher_hash` 32 bytes and `stored_len` in range and a Padmé length
   plus 40; the `SignedRecord`'s `signature` 64 bytes. Failure: **malformed**.
2. **Duplicate**: compute `record_hash`. A record with this hash is already held for the folder: a
   **duplicate**; ignore it without verifying its signature, since it is the record held, whatever
   its signature bytes say (ruling DUP).
3. **Placement**, against this peer's cursor `n` for the record's `device_id`: `seq > n + 1` is a
   **gap**, since this peer has not reached `seq − 1`. On a push, ignore the record without verifying
   it and mark the writer (4.5). In a reply, a gap is a **sender violation**, since the responder
   answers for contiguity (4.5), and so is a record of a writer outside the request's range (or, for
   a listed request, outside its `have`). None of these is charged to the signer, so none needs the
   signature.
4. **Signature**: `Verify(folder_vk, "licketysync/v1/sig/index", body, signature)`; failure:
   **forged**. Nothing below may be charged to anyone unless the folder key signed it, and every
   signature a peer verifies either stores a record it did not hold or closes the connection
   (TM-22).
5. **Store**: `seq ≤ n`: a **concurrent version**: store it, and recompute the writer's cached
   digests from `seq` up. `seq = n + 1`: store it; the cursor becomes `seq`. Every stored record
   counts in its writer's records, cursor and digest, whatever step 6 finds.
6. **Seal**: read and write holders open `sealed` (`keys.md` §3.4). A seal that will not open,
   non-zero padding, a path outside the grammar above (a name that is merely invalid on some platform
   is the path resolver's concern, TM-4, not a writer fault), a `kind` this release does not know, a
   directory (`kind` 2) with chunks, a file (`kind` 1) that is not a tombstone with `size > 0` and no
   chunks, or a `plain_hashes` count different from `chunks` is the signer's doing, since the body
   already verified under the folder key: **writer fault**; the record is stored **opaque** (it counts in the
   writer's records, cursor and digest, and is applied by no one), and an issue names the record by
   its hash, never a device (ruling S-4). Otherwise the record is **applied**. Sealed peers store the
   record without opening it. NFC is the writer's duty only: readers check the rest of the path
   grammar and not normalisation, so no difference between releases' Unicode tables can split peers.
   The stated residual: a write holder can write a name that is not NFC, which is then a path
   distinct from its NFC form (a trusted writer's doing, `threat-model.md` §3.6); where a file
   system treats the two as one name, the path resolver handles them as any collision (TM-4).
7. **Heads**: read and write holders bring the heads of the record's path, and of every path whose
   heads it supersedes, up to date (above); a record that waits joins the heads once every record it
   names is held and none of them waits.

**Rollback.** A peer's cursor for a writer never decreases and nothing a peer sends removes a record
(tombstone expiry, which drops a path's visibility and keeps its records, and any compaction are the
index design's, phase 1). A peer that offers lower cursors is simply behind, and nothing is asked of
it. Each peer persists its records, so a stale snapshot from a sealed peer or relay can never be
mistaken for the present.

What this layer guarantees is that every peer that holds the same records applies the same ones and
computes the same heads, in any arrival order, and that two peers that serve each other's requests
come to hold the same records for every writer either holds (4.5). The one exception is release
skew: a record with a `kind` (or another value step 6 judges) that an older release does not know
is opaque there and applied on a newer one, so the two compute different heads for that path. A
`kind` added before 1.0 therefore joins major 1's baseline, and one added after 1.0 needs a
folder-level requirement first, like a compression code (`keys.md` §3.2; section 6).

### 4.5 Index exchange and Status

```proto
// The requester's state for one writer: "I hold this writer's records through seq, and their digest there is digest".
// seq = 0 with digest empty means "I hold none". seq >= 1 needs a 32-byte digest; any other length is malformed.
message Cursor {
  reserved 1;            // was key_id
  bytes  device_id = 2;  // 32: the writer
  uint64 seq       = 3;  // the requester's cursor for the writer (section 4.4); <= MAX_SEQ
  reserved 4, 5;         // were fork and head_hash
  bytes  digest    = 6;  // the requester's digest at seq (section 4.4); empty iff seq = 0
}

message IndexRequest {
  bytes folder_id       = 1;
  repeated Cursor have  = 2;   // ascending by device_id, each writer at most once; every entry inside the request's range; <= MAX_CURSORS_PER_REQUEST (16 384): at most 81 bytes each encoded, about 1.3 MiB in all, well within MIN_MESSAGE_SIZE
  uint32 max_records    = 3;   // per reply page (the paging rule below); 0, or above MAX_PAGE_RECORDS (4096), means 4096; below 64 means 64
  uint32 request_id     = 4;   // >= 1, chosen by the requester, unique among its requests outstanding on the connection; every page of the reply echoes it
  bytes  after          = 5;   // empty, or 32: the range holds the device IDs strictly above this one, in unsigned bytewise order (empty: from the lowest)
  bytes  through        = 6;   // empty, or 32: the range holds the device IDs up to and including this one (empty: to the highest); after < through when both are set
  bool   listed         = 7;   // true: the request is for exactly the writers in have, which is then non-empty, with after and through empty
}

message IndexRecords {
  bytes folder_id                = 1;
  repeated SignedRecord records  = 2;   // <= MAX_PAGE_RECORDS (4096), more is malformed; per writer, in canonical order (section 4.4)
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
  uint64 chunks_stored   = 6;   // the chunks this device has stored for the folder since the folder opened on this connection: 0 in the first Status, one more with each chunk stored, never falling, even when chunks are freed (4.6)
}
```

- **Rounds and ranges** (ruling R-K4). There is no cap on writers per folder (owner answer 4 of
  2026-10-22: "No limit"), so a requester's cursors cannot be bounded to one message. A requester
  therefore asks by **round**: range requests that together cover every device ID, split by this
  rule. The first request's `after` is empty. Each request lists in `have` the requester's cursors
  for its next writers above `after`, in ascending device-ID order, at most
  `MAX_CURSORS_PER_REQUEST`; its `through` is the device ID of the last writer it lists, or empty
  when no writer of the requester's lies above those it lists, which makes it the last request of
  the round; the next request's `after` is that `through`. A requester with at most 16 384 writers
  thus sends a round of one request with `after` and `through` empty, and one with none sends one
  request with `have` empty. A requester sends a round when a folder opens on the connection and when
  it owes one (below). A **listed** request asks about exactly the writers in its `have` and serves
  marks. A responder keeps no state between requests: each is served on its own, so nothing a
  requester sends grows a table on the responder past one request's reply. The stated residual
  (`threat-model.md` §3.6, TM-22): a write holder can sign under any number of device IDs, and every
  peer then stores, lists and compares that many writers; no message and no per-connection table
  grows with them, but storage, the number of requests in a round and the time a round takes do.
- **Serving.** For every writer `w` in the request (every writer the responder holds inside the
  range, or every writer in `have` for a listed request), in ascending device-ID order, with the
  requester's cursor `(s, D)` for `w` from `have`, or `s = 0` when `w` is absent from it, and the
  responder's own cursor `n` for `w`, the responder sends, in canonical order:
  (a) `s = 0`: every record of `w` it holds;
  (b) `1 ≤ s ≤ n` and its own cached digest at `s` equals `D`: its records of `w` with `seq > s`;
  (c) `1 ≤ s ≤ n` and its digest at `s` differs from `D`: every record of `w` it holds (a **full
  resend**), and it marks `w` (below);
  (d) `s > n`: nothing.
  A record the responder accepts while it serves may appear in the reply as well as in a push; the
  receiver ignores the second copy as a duplicate.
- **Marks.** A mark is a writer this side will ask about in a listed request, with its own cursor
  and digest. Serving case (c) marks the writer: after the full resend the requester holds every
  record this side holds, so this side's listed request, which the requester serves by (b) or (c),
  brings back whatever only the requester held. A gap in a push marks the writer too (4.4 step 3).
  A side sends a listed request for its marks once the reply to its current request has completed;
  a listed request for gap marks alone waits until `INDEX_RESYNC_INTERVAL` (10 s) has passed since
  the previous gap-triggered listed request for the folder on the connection. Sending a request
  clears the marks it covers: a listed request the writers it lists, and a range request the marks
  for writers in its range that were set before it was sent. A mark set after the request whose
  range holds its writer was sent stays, and a listed request serves it (ruling MARK). A side holds
  at most `MAX_MARKED_WRITERS` (1 024) marks per folder per connection; when one more would be
  marked it drops them all and owes a round instead, which covers them.
- **Round owed** (ruling PUSH-1). Each side keeps one flag per folder per connection: it owes a
  round. The flag is set when an empty push arrives (the peer dropped pushes for the folder) and when
  marks overflow. Once the reply to its current request has completed, no round of its own is under
  way (a round under way runs to its end first, so that every round finishes however often the flag
  is set; with at most 16 384 writers a round is one request), and no sooner than
  `INDEX_RESYNC_INTERVAL` after the previous owed round began for the folder on the connection, a
  side whose flag is set clears it and starts a round; when a listed request is due at the same time,
  the owed round goes first, since its ranges cover the marks. The flag is one bit, so any number of
  empty pushes and overflows owe one round, and one set while an owed round runs owes the next;
  nothing a peer dropped is ever left unasked for.
- **Why it converges.** On open both sides send a round, so each serves the other's cursors for
  every writer either holds; from open on, each pushes what it newly accepts, and a dropped push
  owes a round. For each writer either holds, the side with the higher cursor compares at the lower
  one's `seq` ((b) or (c)), or either side does when the cursors are equal, and the side with the
  lower cursor needs to do nothing ((d)), since its own cursor reaches the other side, which compares
  there. Every difference produces a full resend and a mark, after which a listed request finds
  equal digests. So two peers that exchange in both directions end with the same records for every
  writer, whatever a write holder signed and in whatever order records arrived (TM-41). The cost: one
  concurrent version low in a writer's history makes every pair of peers whose digests then differ
  resend that writer's whole history to each other once, and makes every peer recompute that
  writer's cached digests from that `seq` up (`threat-model.md` §3.6, TM-22).
- **One request at a time.** At most one `IndexRequest` per folder is outstanding on a connection:
  the requester sends the next (the next range of its round, a listed request, or the first range of
  an owed round) only after the current reply's last page (`more = false`) has arrived. A responder
  that receives a second `IndexRequest` for a folder before it has queued the current reply's last
  page closes with `PROTOCOL_ERROR`. Pushes (`request_id = 0`) are not requests and are unaffected. A
  responder serves `IndexRequest`s for one folder on one connection at most once per
  `INDEX_REQUEST_MIN_INTERVAL` (1 s), counted from when it began serving the previous one, and delays
  a later request until then, never refusing it. A fair share of upload per peer, across folders and
  against chunk requests, is a phase 1 engine item.
- **Reply deadline.** A requester closes with `TIMEOUT` when the reply to its outstanding
  `IndexRequest` has brought no page for `REPLY_PAGE_TIMEOUT` (10 min). The count starts when the
  request has left the requester's send queue (`Transport::unsent` has fallen past it, 3.1) and
  restarts on every page of a reply to any of the requester's own requests on the connection, on a
  `ChunkReply` with `CHUNK_OK` to one of its own chunk requests (4.6), and on a push that brings at
  least one record this side then stores, since an honest page may wait behind any of those in the
  peer's send queue (3.1). A `ChunkReply` with `CHUNK_BUSY` or `CHUNK_NOT_FOUND`, a Status, an empty
  push, a push of duplicates only and an `Unsupported` do not restart it. So a responder that sets
  `more = true` and never sends the last page, or answers only `CHUNK_BUSY`, or pushes only what the
  requester already holds, cannot hold the one outstanding request slot, and with it the marks of
  that connection, past the deadline; the next connection asks again. The stated residual: a
  responder that keeps delivering new records or chunks can delay its page on that one connection;
  other connections recover.
- **Pages.** The page limit is the request's `max_records` held between 64 and `MAX_PAGE_RECORDS`
  (4096): 0 or a value above 4096 means 4096, and a value below 64 means 64, so that no requester can
  pin a responder's processor with one-record pages. The responder fills each page record by record
  in the order above and ends the page before a record when the page already holds one and the
  record would take it past the page limit, or would take the encoded `IndexRecords` frame past the
  requester's `max_message_size`. A page never holds more than the page limit, and never more than
  `MAX_PAGE_RECORDS`, the receiver's bound; every record fits a page on its own (section 2). A page
  may end anywhere: two records of one writer at one `seq` may lie on two pages, since the second is
  a concurrent version once the first is held. A reply with nothing to send is one empty page with
  `more = false`; `more` is set on every page but the last.
- **Replies and pushes.** A **reply** is what a sender produces for a request it received on this
  connection: the `IndexRecords` pages carrying that request's `request_id`, up to and including the
  one with `more = false`. The sender paged it, so inside a reply it answers for contiguity and for
  the request's scope: a record whose `seq` is above the requester's cursor for its writer plus one,
  when the requester comes to it, and a record of a writer outside the request's range (or, for a
  listed request, outside its `have`), are **sender violations** (section 5). A **push** is an
  unsolicited `IndexRecords` with `request_id = 0` and `more = false`; it carries records the pusher
  newly accepted, may arrive between two pages of a reply, and a receiver that finds a gap in it marks
  the writer rather than blaming the pusher. An **empty push** says that the sender dropped pushes
  for the folder (3.1): the receiver owes a round (above). An `IndexRecords` push with `more = true`,
  and a page whose `request_id` names no request outstanding on the connection, are malformed.
- **Pushes** (ruling PUSH-2). From the moment a folder opens on a connection, a peer pushes every
  index record it newly accepts to every connection where the folder is open except the one the
  record arrived on, so that a record accepted while the first round runs is not missed: each
  writer's records in canonical order, at most `MAX_PAGE_RECORDS` records per push. A push that the
  send queue cannot take is dropped, and the sender then owes the receiver one empty push for the
  folder (one flag per folder per connection), which waits in order like a reply and is never
  dropped (3.1).
- **Durability before transmission.** A writer commits a new record and its sequence counter to its
  own index before any peer may receive it, so a crash can never make it reuse a sequence number; a
  peer forwards only records it has itself verified and committed, opaque ones (4.4 step 6)
  included. A device that comes to hold a record under its own device ID at a `seq` at or above the
  next one it would use (it was restored from a backup of its index, or another write holder wrote
  under its ID) moves its counter past the highest such `seq` before it writes again and raises an
  informational issue that names no one. A restored device's reused sequence numbers make concurrent
  versions (4.4), never a fault, and its edits name the heads it still held, which makes a conflict
  rather than a silent loss (an engine rule). A device whose next `seq` would pass `MAX_SEQ` takes a
  new device ID (`keys.md` §8.1); since a peer holds a writer's records contiguously from 1, no
  device comes near it.
- Status is sent every `STATUS_INTERVAL` (30 s, through the clock trait) and on change, for open
  folders only; a change in `chunks_stored` alone sends at most one Status per second per folder per
  connection. It is advisory and never changes what a peer will accept.
- **Device name.** A device's self-chosen name travels only in Status, so only after a folder has
  opened on the connection (both ProofResults ACCEPTED): the first Status a side sends after its
  first open carries `device_name`, later ones carry it only when it changes, and the receiver shows
  the latest as reported, never proven. It is not in Hello (field 2 there is reserved), which any
  peer that completes the transport handshake reads, nor in the folder proof, so that only a peer
  that has opened a folder with the device learns its name. A name that breaks the grammar makes the
  Status malformed (`Close(PROTOCOL_ERROR)`). Deviation from the plan ("Capabilities": "The Hello
  message carries the device's ID and name"): the name moved from Hello to the first Status after a
  folder opens (decision 2026-10-17).

### 4.6 Chunks

```proto
message ChunkRequest {
  bytes folder_id   = 1;
  bytes cipher_hash = 2;   // 32; absent or any other size is malformed
}

message ChunkReply {
  bytes  folder_id   = 1;
  bytes  cipher_hash = 2;   // 32, as requested
  uint32 status      = 3;   // ChunkStatus
  bytes  data        = 4;   // the stored blob (nonce || ciphertext), present iff status = CHUNK_OK; <= 4 325 416 bytes, the largest stored chunk (keys.md §3.2), which an honest holder never exceeds: longer is malformed
}

enum ChunkStatus { CHUNK_UNSPECIFIED = 0; CHUNK_OK = 1; CHUNK_NOT_FOUND = 2; CHUNK_BUSY = 3; }
```

- The chunk is sent exactly as stored; it is ciphertext, so no wire compression is applied or
  negotiated. The compression that was applied before encryption is inside the ciphertext
  (`keys.md` §3.2): a reader decodes every code its release implements and treats any other as a
  writer fault, and a writer uses only codes that every supported release of major 1 reads (ruling
  S-2). Hello's `compressions` list says what a device can decode; it is negotiated per connection
  and governs nothing a writer stores. Deviation from the plan (steps 6 and 7: "chunk request naming
  the compressions A can decode; chunk reply with the compression used or none"): ciphertext does
  not compress, so compression is chosen at write time and the reply carries the stored bytes
  verbatim.
- **Who may ask** (ruling S-3). Any peer with the folder open may request any `cipher_hash`,
  whatever tier it reports: a sealed peer fetches ciphertext to hold and serve. A device **holds a
  chunk for the folder** when it has the stored blob and holds a record of the folder that names its
  `cipher_hash`. The holder sends the chunk when it holds it for the folder and answers
  `CHUNK_NOT_FOUND` otherwise; `CHUNK_NOT_FOUND` is an ordinary answer and never closes the
  connection. Requests are bounded only by the in-flight limit: the requester keeps at most the
  holder's `max_requests_in_flight` requests outstanding on a connection, and a holder that receives
  more closes with `PROTOCOL_ERROR`.
- **Busy.** A holder answers `CHUNK_BUSY` exactly when its unsent bytes on the connection (3.1) are at
  least `MAX_SEND_QUEUE / 2` (64 MiB) as it dispatches the request; otherwise it queues the request,
  which holds only the hash until the chunk is read from storage, as it is sent, and then waits for
  room like any frame. (The fair share of upload, a phase 1 engine item, may add a second condition,
  stated with it.) After a `CHUNK_BUSY` the requester sends no chunk request on that connection
  until `CHUNK_BUSY_BACKOFF` has passed: 1 s at first; a `CHUNK_BUSY` for a request sent after the
  current backoff ended doubles it, up to 64 s, while busy answers to requests sent before then do
  not; a `CHUNK_OK` sets it back to 1 s; all through the clock trait. It is one timer per
  connection, since the holder's queue is per connection, and the requester may ask other peers
  meanwhile.
- **Passes** (no state per hash). A requester asks a peer for a folder's chunks in **passes**: in
  ascending `cipher_hash` order over the chunks it still lacks, keeping only its position, the last
  hash it asked that peer for; a pass ends when no lacking hash lies above the position. A
  `CHUNK_NOT_FOUND` does not pause the pass, which goes on with the next hash, and the requester asks
  other peers that have the folder open for the missing chunk. After a pass that got no
  `CHUNK_NOT_FOUND`, the next pass to that peer starts whenever the requester lacks chunks again.
  After a pass that got any, the next pass to that peer for the folder starts only once a trigger has
  fired, either a Status from the peer showing a `chunks_stored` greater than in its last Status
  before the latest `CHUNK_NOT_FOUND`, or a completed round with that peer, and no sooner than 1 s
  (`CHUNK_BUSY_BACKOFF`'s minimum) after the latest `CHUNK_NOT_FOUND`; the requester evaluates the
  trigger at most once per `STATUS_INTERVAL`, and a trigger that comes inside that window is
  deferred, by one pending bit, and evaluated when the window ends, never dropped. Per folder per
  connection the state is one position, one number (the peer's `chunks_stored` at the latest
  `CHUNK_NOT_FOUND`), one time (that answer's) and the pending bit, whatever the number of hashes; Status comes at least every `STATUS_INTERVAL` (4.5), so
  a peer that fetches a chunk it lacked is asked again within about twice that.
- On receipt the requester first checks that `data` is at most 4 325 416 bytes (longer is
  **malformed**, before any hash is computed), then `H("licketysync/v1/hash/chunk", data) = cipher_hash`.
  A mismatch is **forged** (section 5): the sender delivered bytes that are not the chunk it named.
  With the hash correct, the sender delivered exactly what the writer stored, so every later failure
  is a **writer fault** and leaves the connection open: `len(data) ≠ stored_len` in the record that
  names the hash, a seal that will not open, bad padding, a compression code this release does not
  implement, a decompression that overruns the bound or yields nothing, or a `plain_hash` mismatch;
  the chunk is marked corrupt under Issues for that record, naming the record (and its path, which a
  read holder knows), never a device. When several records name one `cipher_hash` (deduplication),
  each is judged on its own: a record whose `stored_len`, seal, padding or `plain_hash` the chunk
  fails is a writer fault of that record and the chunk is corrupt for that record only; a record it
  satisfies stays good.
- A `ChunkReply` for a hash the receiver has no request outstanding for on the connection is
  unsolicited: `Close(PROTOCOL_ERROR)`.

## 5. Rules

- **Unknown types**: non-critical → `Unsupported`, at most once per type per connection, continue;
  critical → `Close(UNSUPPORTED_CRITICAL_TYPE)`. Both only once the peer's DeviceProof has verified:
  before that every frame but that DeviceProof or a Close is `Close(PROTOCOL_ERROR)` (section 2,
  3.2).
- **Features and the feature set.** A feature name is `[a-z0-9:-]{1,32}`. A device's **feature
  set** is its Hello `features` plus `compression:<c>` for every entry of `compressions` and
  `hash:<h>` for every entry of `hashes`; so every device's set contains `compression:none` and
  `hash:blake3`. Features are negotiated per connection, in the Hello, and nothing folder-wide
  requires one (ruling S-2). Major 1 defines no features beyond the compression and hash names; new
  ones are registered in this file.
- **Never use what the peer did not list**: a sender never relies on a suite, compression, hash or
  feature the receiver's Hello did not list, and may always fall back to `none` or `blake3`.
- **Limits are per connection**, and none grows with the number of writers (ruling R-K4): every
  per-peer table (open folders, the hints of proofs received (at most `MAX_PROOFS_PER_CONNECTION`),
  the one outstanding `IndexRequest` per folder and its reply in progress, outstanding chunk
  requests (at most `max_requests_in_flight`), each holding only its hash, the one `CHUNK_BUSY`
  backoff timer, per folder the chunk pass's position, the peer's `chunks_stored` at the latest
  `CHUNK_NOT_FOUND`, that answer's time and the pending trigger bit, pending pages, the unknown
  types already answered with `Unsupported` (at most 32 768, a 4 KiB set), marks (at most
  `MAX_MARKED_WRITERS` per folder), the empty push owed per folder, the round owed per folder,
  resync timers, reply-page deadlines, rate-limit state) is bounded by the constants in this file
  and is freed when the connection closes. Nothing a peer sends can grow a table past its bound; the
  next item is refused with `PROTOCOL_ERROR` where this file says so, and otherwise dropped as
  section 4.5 says.
- **Every decoder is fuzzed**: frames, every message body, every record body, the sealed metadata,
  chunk blobs, key strings, words and links. A decoder never panics and never reads past a declared
  length.
- **Nothing is silently skipped.** Every failure has exactly one of three outcomes, and the table
  below is the complete mapping. *Close* is for what only the sender can be blamed for: it forwarded
  bytes that do not parse or do not verify, or broke the protocol's order or bounds. *Set aside and
  keep* is for differences in what two peers hold: a gap, a duplicate, a record waiting for a version
  it names, a proof for a folder that is not here, a chunk the holder lacks. *Issue against the
  record* is for what a valid signature covers: the body is what a write holder signed, the sender
  merely carried it, so the issue names the record (by hash, and by path where the seal opened),
  never a device (ruling S-4), the item is kept opaque or marked corrupt, and the connection stays
  open. Every outcome raises an issue or a log line that names the cause; none drops the item without
  trace.
- **No blame before a signature.** No writer-fault outcome may be reached on a record whose signature
  has not verified; a signature failure is always forged. Every procedure in this file and in
  `keys.md` verifies the signature before any step whose failure is charged to the signer; until
  then every failure is malformed, forged or a sender violation, which is the sender's whatever the
  signature, and a record ignored unverified (a duplicate, or a gap on a push, 4.4) is charged to no
  one. An unverified gap on a push may still set a mark for the device ID it names, so a peer can
  make this side ask about writers that do not exist; that is bounded by `MAX_MARKED_WRITERS` per
  folder per connection, whose overflow owes one round, started at most once per
  `INDEX_RESYNC_INTERVAL` (4.5), and costs this side a listed request answered with nothing.

| Cause | Outcome |
| --- | --- |
| **Malformed**: frame length below 2, body that does not parse, a field number above 2^29 − 1 or a group wire type, a size or bound or grammar violated, a fixed-size field absent or of another size, a `bool` other than 0 or 1, a `uint32` of 2^32 or more, a field that is not repeated occurring twice in a body, a Hello that fails a check of 3.2 (a device key that is not canonical or is of small order included) other than the two rows below, a FolderProof envelope with a wrong `hint` or `nonce` size or a `sealed` outside 16 to 1 024 bytes, a FolderProof whose `hint` repeats one already received on the connection, more than `MAX_PROOFS_PER_CONNECTION` FolderProofs, a message for a folder not open here, a message before Hello or DeviceProof, a known type where only Hello or Close may come, any frame but DeviceProof or Close before the peer's DeviceProof verified, a second Hello or DeviceProof, a list past its bound, more chunk requests than allowed, a stray or second `ProofResult` or one whose `status` is not 1 or 2, a record whose `suite` is not its folder's or whose `record_type` is not 16, a `seq` of 0 or above `MAX_SEQ`, more than `MAX_SUPERSEDES` `supersedes` entries, a `sealed` part outside 40 to 1 572 864 bytes, a signature that is not 64 bytes, an encoded `SignedRecord` over `MAX_INDEX_RECORD_BYTES`, a `Cursor` whose `digest` length does not match its `seq` or whose `seq` is above `MAX_SEQ`, an `IndexRequest` whose `have` is not ascending and unique, holds a writer outside its range, or holds more than `MAX_CURSORS_PER_REQUEST` entries, whose `after` and `through` are both set and `after ≥ through`, or that is `listed` with `after` or `through` set or with `have` empty, an `IndexRecords` page of more than `MAX_PAGE_RECORDS` records, an `IndexRecords` push with `more` set, a second `IndexRequest` for a folder before the reply to the first has queued its last page, a reply page whose `request_id` names no outstanding request, a `ChunkReply` for no outstanding request or with `data` over 4 325 416 bytes, a Status whose `device_name` breaks its grammar | `Close(PROTOCOL_ERROR)` |
| Frame over the limit | `Close(MESSAGE_TOO_LARGE)`, nothing allocated |
| Unknown critical type | `Close(UNSUPPORTED_CRITICAL_TYPE)` |
| Unknown non-critical type | `Unsupported`, at most once per type per connection (later frames of that type ignored with a log line); continue |
| No common suite; `max_message_size` below the floor | `Close(NO_COMMON_SUITE)`; `Close(LIMIT_TOO_SMALL)` |
| DeviceProof does not verify | `Close(PROOF_REJECTED)` |
| `HELLO_TIMEOUT`, `IDLE_TIMEOUT` or `REPLY_PAGE_TIMEOUT` (an outstanding reply brought no page, 4.5) elapsed; `PROOF_TIMEOUT` elapsed with nothing opened | `Close(TIMEOUT)`; `Close(NO_COMMON_FOLDER)` |
| **Forged**: an index record that is neither a duplicate nor a gap and whose signature does not verify under the folder key (4.4 step 4); a chunk whose ciphertext hash fails | `Close(VERIFICATION_FAILED)`; issue naming the peer |
| **Sender violation**: a gap inside a reply (a record whose `seq` is above the requester's cursor for its writer plus one); a record in a reply of a writer outside the request's range or list | `Close(PROTOCOL_ERROR)`, before and whatever the signature |
| FolderProof fails for any reason (hint, seal, payload, the folder's suite missing from the peer's Hello, the open-folder bound) | `ProofResult(REJECTED)`, keep; nothing of any folder is sent before it is open |
| **Gap** on a push (`seq > cursor + 1`) | Ignore without verifying, keep; mark the writer (4.5), its listed request at most once per `INDEX_RESYNC_INTERVAL` |
| **Duplicate** (an index record whose `record_hash` is already held) | Ignore without verifying, keep |
| **Concurrent version** (a record of a writer at a `seq` at which another record of that writer is held; ruling R-K5) | Store, and apply unless 4.4 step 6 finds a writer fault; the writer's cached digests recomputed from its `seq` up; keep; no issue, no blame |
| **Waiting** (a record whose `supersedes` names a record not held; ruling R-K6) | Store; it takes no part in heads until every record it names is held and none of them waits; keep; a log line when it starts to wait, and an informational issue naming the record once it still waits after a completed round with every peer that has the folder open (4.4) |
| **Digest mismatch** while serving (the requester's digest at its `seq` differs from this side's, 4.5 case (c)) | Send every record of the writer; mark the writer for a listed request; keep |
| **Empty push** (the sender dropped pushes, 3.1) | Owe a round: it starts once the current reply has completed and no sooner than `INDEX_RESYNC_INTERVAL` after the previous owed round (4.5); keep |
| **Rollback**: a peer offers cursors below those stored here | Ignore, keep; nothing is asked for; a cursor never decreases and no record is removed on a peer's say-so |
| **Writer fault**: a seal that will not open, bad padding, malformed path, unknown kind, a directory with chunks, a file that is not a tombstone with `size > 0` and no chunks, or hash-count mismatch; a chunk with a correct ciphertext hash whose length, seal, padding, compression or plaintext hash fails, judged per record that names it | Issue naming the record, never a device (ruling S-4); store the record opaque (not applied) or mark the chunk corrupt for that record; keep |
| `CHUNK_BUSY` | An ordinary answer: the requester sends no chunk request on that connection for `CHUNK_BUSY_BACKOFF` (one timer per connection) and may ask other peers (4.6); keep |
| `CHUNK_NOT_FOUND` | An ordinary answer: no state is kept for the hash; the pass to that peer goes on, and the requester asks other peers for the chunk; the next pass to that peer waits for a greater `chunks_stored` in its Status or a completed round with it, and at least 1 s (4.6); keep |
| A record under this device's own device ID at or above the next `seq` it would use (4.5, "Durability before transmission") | Store and apply; move its counter past it before writing again; informational issue naming no one; keep |

- **Time** comes from a clock trait (wall time, as the device believes it, for the LAN beacon window
  and informational fields; monotonic time for intervals) and the network from a transport trait, so
  every rule here is testable without sleeping. The constants are fixed by this protocol, since a peer
  enforces some of them (the intervals, the bounds); the simulator may scale them, both sides alike.
  Each is defined once, in the protocol crate, and the engine and the runtime import it rather than
  define their own; `MAX_SEND_QUEUE`, which the runtime enforces (3.1), included.

| Constant | Default |
| --- | --- |
| `HELLO_TIMEOUT` (channel up → peer's Hello and DeviceProof) | 10 s |
| `PROOF_TIMEOUT` (DeviceProofs → first open folder) | 30 s |
| `IDLE_TIMEOUT` (no frame in either direction, Status counting; also, while unsent bytes remain, the longest a connection may go without delivering one, 3.1) | 5 min |
| `STATUS_INTERVAL` | 30 s |
| `REPLY_PAGE_TIMEOUT` (the longest a requester waits for the next page of the reply to its outstanding `IndexRequest`, counted from when the request left its send queue and restarted by every page of a reply to its own requests, every `CHUNK_OK` reply to its own chunk requests and every push that brings a record it stores; past it, `Close(TIMEOUT)`, 4.5) | 10 min |
| `INDEX_RESYNC_INTERVAL` (minimum gap between gap-triggered listed requests, and between the starts of owed rounds, per folder per connection, 4.5) | 10 s |
| `INDEX_REQUEST_MIN_INTERVAL` (a responder serves a folder's `IndexRequest`s on a connection at most this often, delaying, never refusing, the rest; 4.5) | 1 s |
| `MAX_CURSORS_PER_REQUEST` (entries in one `IndexRequest`'s `have`; a round of range requests covers any number of writers, 4.5) | 16 384 |
| `MAX_MARKED_WRITERS` (marks a side holds per folder per connection; one more drops them and owes a round, 4.5) | 1 024 |
| `MAX_SEND_QUEUE` (unsent bytes per connection; the runtime may end a connection past it, senders pace below it, and a chunk request the holder dispatches with half of it unsent is answered `CHUNK_BUSY`, 3.1, 4.6) | 128 MiB |
| `CHUNK_BUSY_BACKOFF` (how long a requester sends no chunk request on a connection after a `CHUNK_BUSY`; doubled, up to 64 s, by a `CHUNK_BUSY` for a request sent after the current backoff ended, back to 1 s after a `CHUNK_OK`; one timer per connection; also the least wait before the next chunk pass to a peer that answered `CHUNK_NOT_FOUND`, 4.6) | 1 s |
| `MAX_PAGE_RECORDS` (records per `IndexRecords` page or push; the cap on `max_records` and the receiver's bound, 4.5) | 4096 |
| `MAX_SUPERSEDES` (entries in a record's `supersedes`, 4.4) | 16 |
| `MAX_SEQ` (the largest `seq` of a record or cursor, 4.4) | 2^62 |
| `MAX_PROOFS_PER_CONNECTION` (FolderProofs a verifier accepts on one connection, four times `MAX_OPEN_FOLDERS_PER_CONNECTION`, since a prover may hold folders the peer no longer holds; one more is malformed, 3.5 step 1) | 256 |
| `MAX_OPEN_FOLDERS_PER_CONNECTION` (a proof past it is REJECTED, 3.5 step 6) | 64 |
| Default `max_requests_in_flight` | 64 |
| `MAX_CHUNK_PLAINTEXT` | 4 MiB |

The drafts' `KEY_RESYNC_INTERVAL`, `MAX_HELD_GRANTS_PER_CONNECTION`, `MAX_WRITERS_PER_FOLDER`,
`MAX_DEVICES_PER_KEY`, `MAX_KEY_RECORDS_PER_FOLDER`, `MAX_KEY_RECORD_BYTES_PER_FOLDER`,
`MAX_KEY_RECORDS_PER_SIGNER`, `MAX_REFUSED_REMEMBERED`, `MAX_KEY_RECORD_BYTES` and
`MAX_FOLDER_RECORD_BYTES`, and the 1 024-entry version vector, are gone.

## 6. Compatibility

- The previous major stays supported for twelve months after its successor ships; a device speaks
  both and the dialer offers the newer first.
- CI runs the last two released binaries against each build (the protocol compatibility matrix in
  the integration suite) so that a change that breaks either fails before it merges.
- New optional messages (critical bit clear), new fields in any message or record, new feature
  names, new compressions and hashes, and new suites **never** bump the major. A new suite ships in a
  release that lists it in Hello; a folder never moves to it, since a folder's suite is the suite of
  its keys: a folder under the new suite is a new folder (`keys.md` §7). A new field whose absence
  would change the meaning of a record or message for an old peer is never added as optional: it
  needs a new major, or a folder-level requirement mechanism if a later phase adds one (ruling S-2),
  so that old peers are refused rather than misread it. The same holds for a compression code added
  after 1.0 (`keys.md` §3.2).
- Index records follow the same optional-field rule: new metadata is a new field in `IndexRecord`
  or `SealedMeta` that old peers store and forward unread, because verifiers never re-encode a body
  (`keys.md` §5.2). A new value of `SealedMeta.kind` is different, since an older release treats a
  kind it does not know as a writer fault and keeps the record opaque (4.4, release skew): a kind
  added before 1.0 joins major 1's baseline, and one added after 1.0 needs a folder-level
  requirement first.
- Retiring a suite is a release that stops making folders under it and, later, one that drops it;
  a folder under a retired suite is shared again as a new folder under a current one (`keys.md`
  §7.1, §7.2), and peers that still hold it are told so under Issues.

## 7. Phase 0 scope

The phase 0 gate is "simulated peers converge; spec published". The simulator (`licketysync-sim`)
provides a deterministic clock (monotonic time and a per-peer wall clock with injectable skew), a
transport that honours the contract of 3.1 (a reliable, ordered stream per connection, with seeded
delay, disconnects and partitions; loss is only ever a disconnect), seeded randomness, and peer
identities; over it the real `licketysync-protocol`, `licketysync-keys`, `licketysync-index` and
`licketysync-engine` code runs unchanged. Because the simulated transport has no authenticated
identity, the transport-identity check of 3.1 is a no-op in phase 0 and the libp2p identity keys the
transcript binds are the ones the Hellos carry. In phase 0 the following are exercised with real
cryptography:

- Framing (section 2) with every limit and failure path.
- Hello, roles and DeviceProof (3.2 to 3.4) with real Ed25519 signatures over the transcript, and
  the canonical-key check.
- FolderProof and ProofResult (3.5) with folder keys from real write secrets (`keys.md` §1), by
  holders of each of the three keys: the sealed payload under a fresh nonce, the hint, the reported
  tier, the uniform rejection.
- `IndexRequest` and `IndexRecords` with rounds, ranges, listed requests, cursors and cached
  digests, pages, pushes from open, empty pushes and the round owed, marks and gap recovery;
  duplicates and push gaps ignored unverified, concurrent versions, full resends and rollback;
  `supersedes`, waiting records and heads (a conflict is two heads; the conflict copies on disk are
  phase 1's); sealed metadata.
- `ChunkRequest` and `ChunkReply` with real convergent encryption, Padmé padding, ciphertext hashes,
  both attribution paths, `CHUNK_NOT_FOUND` and `CHUNK_BUSY`.
- Status and Unsupported; every row of section 5's table that phase 0 can reach.

Not in phase 0: QUIC, TLS, Noise, mDNS, the DHT and everything else libp2p provides (phase 1 and 2);
links and files (phase 1); unlinking and sharing an existing directory (phase 1, `keys.md` §7);
linked devices (phase 5); compressions other than `none` (`keys.md` §3.2).

## 8. Test vectors

Generated by the reference implementation, checked in as data files in the protocol crate, shared
with `keys.md` §9 item 9 where the inputs overlap. Each vector names the section 5 row of every
outcome it reaches.

**Who checks what.** Each item says which crate's tests check it. The **protocol** crate checks
frames, message bodies and its handshake state machine: items 1 to 5 and 10, and the decoder vectors
of items 6, 8, 9 and 11. The **index** crate checks what a record does to a store: in item 6 each
record's outcome against its writer's records (duplicate, gap, concurrent version, next, opaque, a
record under the device's own ID); item 7 (heads) whole; and in item 8 the digests, the cached
digests and the serving cases (a) to (d). The **engine** crate checks what a connection then does:
the connection vectors of items 6 (marks, closes, issues), 8 (rounds and their split, marks, the
round owed, pushes, pages, intervals and timeouts), 9 (busy answers, the backoff, passes, serving and
attribution) and 11 (`chunks_stored` and how often it is sent). The **keys** crate checks what
`keys.md` §9 lists, the shared inputs included.

**Two shapes.** A **decoder vector** is a frame or body and its expected outcome (accepted, with the
decoded value, or the row that refuses it). A **connection vector** is a scenario run against one
side, the side under test, with the other side scripted: (1) the **starting state**: both sides'
keys and Hellos, the folders each holds and which are open, each side's records, cursors, cached
digests, marks and flags, the unsent bytes, and the monotonic and wall clocks; (2) the **frames in**,
each with the monotonic time at which it arrives (and, where it matters, how far the side's unsent
bytes have fallen by then); (3) the **frames out** the side under test must send, each with its
time, and nothing else; (4) the section 5 **row** of each outcome; and (5) the **end state**: records
held, cursors, digests, heads (for a side that opens seals), marks, the empty push and round owed,
issues raised, and whether the connection is open or closed and with which reason. Times are
explicit so that every timeout and interval in section 5's constants is a vector.

1. **Frames** (decoder; protocol): a valid frame; length 0 and 1; length one over each limit; an
   unknown critical and an unknown non-critical type; a first frame that is not Hello; an unknown
   non-critical type before the peer's DeviceProof (`Close(PROTOCOL_ERROR)`, not `Unsupported`); a
   frame between the peer's Hello and its DeviceProof one byte over `PRE_HELLO_LIMIT`
   (`Close(MESSAGE_TOO_LARGE)`); a body with a field number of 2^29 and one with a group wire type
   (malformed); a fixed-size field left absent (malformed) and one that may be empty left absent
   (accepted); a singular field occurring twice (malformed); a repeated scalar field packed, the
   same unpacked, and the same partly each (all accepted, the values concatenated in order, same
   meaning); a `bool` with varint 2 and a `uint32` with varint 2^32 (both malformed); a body
   carrying a reserved field number (read as an unknown field: skipped, and kept in a signed body);
   two frames of one unknown non-critical type (one `Unsupported`, the second ignored).
2. **Hello** (decoder; protocol): canonical bytes of two fixed Hellos (A and B by the role rule,
   including one pair where the dialer is B), the largest Hello (2 664-byte frame), and each failing
   variant (a device key of 1 986 bytes, the drafts' hybrid form, and of 33 bytes; a device key that
   is a non-canonical encoding of a valid point, and one of small order; missing `none`, missing
   `blake3`, limit below the floor, no common suite, a suite entry of 0 and one of 65 536, 17
   suites, bad identity length, bad feature grammar, equal device keys); a second Hello
   (`Close(PROTOCOL_ERROR)`).
3. **Transcript** (protocol): `th` for those Hellos and `/licketysync/sync/1`.
4. **DeviceProof** (protocol) for both roles, one that fails (`Close(PROOF_REJECTED)`), a signature
   of 63 bytes (malformed), and a second DeviceProof (`Close(PROTOCOL_ERROR)`); `HELLO_TIMEOUT`
   elapsing after the peer's Hello with no DeviceProof (`Close(TIMEOUT)`).
5. **FolderProof** (protocol): for a fixed transcript hash (the inputs of `keys.md` §9 item 9), the
   hint, proof key and sealed payload under a fixed nonce for each reported tier, in both roles;
   `ProofResult` ACCEPTED for a proof by a holder of each of the three keys to a verifier holding
   each of the three (the reported tier recorded as sent, and a sealed holder reporting write
   accepted all the same); REJECTED for each numbered failure of 3.5 (a hint that matches no folder,
   a folder held but paused, a seal that does not open, tier 0 and tier 4, a peer whose Hello does
   not list the folder's suite, the open-folder bound), a proof reflected back to its sender, a
   proof replayed from another connection and a proof by a key made from two folders' halves (all
   REJECTED); an envelope with a wrong nonce size, a `sealed` of 15 and of 1 025 bytes, a second
   proof with the same hint, and a 257th proof (all `Close(PROTOCOL_ERROR)`); a stray `ProofResult`,
   a second one for the same proof and one with `status = 3` (all `Close(PROTOCOL_ERROR)`);
   `PROOF_TIMEOUT` elapsing with nothing open (`Close(NO_COMMON_FOLDER)`).
6. **IndexRecord** (protocol for bodies and decoding, index for each record's outcome, engine for
   what the connection does): canonical body, record hash, signature and sealed part (fixed nonce)
   for a new file, a file that supersedes one version, a directory, an empty file, a tombstone and a
   rename; decoder variants for every row of section 5's table that an index record can reach:
   malformed (`suite` 0, a `suite` other than the folder's, `record_type` 1, `seq` 0, `seq` of
   `MAX_SEQ` + 1 (and `MAX_SEQ` itself accepted), a `device_id` of 31 bytes, `deleted` with chunks,
   17 `supersedes`, a `supersedes` entry of 31 bytes, a chunk whose `stored_len` is not a Padmé
   length plus 40, a `sealed` of 39 bytes and one of 1 572 865, a signature of 65 bytes, a record
   one byte over `MAX_INDEX_RECORD_BYTES`); forged (a bit flipped inside a bytes field of the body,
   so that it still parses; a record signed by another folder's key). Connection vectors: an exact
   duplicate whose signature bytes are garbage (ignored, not verified, the connection open); a gap
   on a push (ignored unverified, the writer marked) and the same gap with a forged signature (also
   ignored, unverified, open); a gap in a reply, with a valid and with a forged signature (both
   `Close(PROTOCOL_ERROR)`, a sender violation); a concurrent version below the cursor and one at
   the cursor (each stored and applied, the digests recomputed from its `seq`, no issue); a record
   at `cursor + 1`; a writer fault in the seal (stored opaque, counted in the cursor and digest, the
   issue naming the record); writer faults in the metadata: a directory with one chunk, a file with
   `size` 5 and no chunks, and a path that is not NFC (accepted, not a fault: a distinct path); a
   forged record that would also be a writer fault (forged wins); a record under the receiver's own
   device ID above its counter (counter moved past it, the informational issue).
7. **Heads** (index; ruling R-K6; on a read holder, one path each unless named): a version
   superseding the one head (one head); two versions superseding one (two heads, a conflict: the
   greater `mtime_ns` at the path; on equal `mtime_ns`, the smaller record hash); a record naming
   both heads (one head again); each case of the display order and of "content differs": a file and
   a tombstone (the file shown, no copy), a file and a directory (the directory shown, the file a
   conflict copy, whatever their times), two files with different `plain_hashes` (one copy), two
   files with the same `plain_hashes` and different modes and times (no copy), two directories (no
   copy), only tombstones (the path deleted); out-of-order `supersedes`: R2 superseding R1 arriving
   before R1 (R2 waits and the old head stays, no conflict; when R1 arrives, R2 is the one head); a
   chain R3 superseding R2 superseding R1 arriving as R3, R2, R1 (both wait, no conflict at any
   point, R3 the one head at the end); a record naming a hash no peer holds (it waits for good, is
   stored and is forwarded, with the log line at once and the informational issue only after a round
   with every open peer has completed); a restored device: D's index restored from before R1, D
   writes R2 superseding R0 while its peer holds R1 superseding R0 (after the exchange both hold two
   heads, a conflict, nothing lost, and D's counter has moved past its own reused sequence numbers);
   a rename (the old path has no head, the new path one); 17 heads and a write naming 16 (two heads
   remain); a rename whose old path has 10 heads and new path 10 (the old path's 10 named first,
   then 6 of the new path's in display order; 4 heads remain at the new path); a record naming an
   opaque record (not waiting); an opaque record naming the one head (the head stays).
8. **Cursors, rounds and pages** (index for digests and serving, protocol for the decoder vectors,
   engine for the rest; connection vectors unless noted): digests for a writer with one record per
   `seq` and for one with two records at one `seq`, in canonical order, and the cached digests after
   a concurrent version lands below the cursor; the round split for a requester with no writers (one
   request, `have` empty), with 16 384 (one request, `after` and `through` empty) and with 16 385
   (two requests: the first's `through` the 16 384th writer, the second's `after` that and its
   `through` empty), and the replies; a listed request; a requester whose digest matches
   (incremental reply, case (b)); a requester absent from `have` (case (a)); a requester with a
   concurrent version the responder lacks at equal cursors, and one the responder lacks behind a
   lower cursor (case (c) then the listed request, case (d) on the other side), each ending with
   both sides holding the same records; decoder vectors: a request with `MAX_CURSORS_PER_REQUEST`
   cursors (accepted) and one more, `have` unsorted, a writer listed twice, a writer outside
   `(after, through]`, `after ≥ through`, `listed` with a range, `listed` with `have` empty, and a
   `digest` of the wrong length for its `seq` (all malformed); sender violations, each with a record
   the receiver does not hold (a held one would be a duplicate, ignored): a reply carrying a writer
   outside the request's range, a reply to a listed request carrying a writer not in its `have`, and
   a reply with a gap; paging at `max_records = 64` (a page never holds more than 64),
   `max_records = 1` served as 64, a page cut by `max_message_size`, `max_records = 0` and 5000 both
   served as 4096, two records of one `seq` split across pages (accepted), a reply with nothing to
   send (one empty page); a page of 4097 records, an `IndexRecords` push with `more = true`, a page
   with an unknown `request_id`, and a second `IndexRequest` before the first reply's last page (all
   `Close(PROTOCOL_ERROR)`); a request that arrives within `INDEX_REQUEST_MIN_INTERVAL` of the
   previous one, served once the interval has passed; a push arriving between two pages and told
   apart by `request_id`; **PUSH-2**: a record the responder accepts after the folder opened, while
   the requester's round is under way and past that writer's range, pushed at once and held at the
   end; **PUSH-1**: pushes dropped while the send queue is full, then the empty push, the round owed
   and the round; a second empty push within `INDEX_RESYNC_INTERVAL` of the first owed round's start
   (the flag kept, a second round started once the interval has passed, and the record dropped in
   between held at the end); an empty push arriving while an owed round runs (the next one after
   it); **MARK**: a mark set after the range request covering its writer was sent (kept, then served
   by a listed request) and one set before it (cleared by that request); a gap mark from a push, its
   listed request sent only `INDEX_RESYNC_INTERVAL` after the previous gap-triggered one; 1 025
   marks (the marks dropped, a round owed and sent); timeouts: a connection whose unsent count has
   not fallen for `IDLE_TIMEOUT` (`Close(TIMEOUT)`), and a long paced transfer whose queue never
   empties but keeps falling (kept open); a reply whose next page has not come `REPLY_PAGE_TIMEOUT`
   after the previous one while Status frames and pushes of duplicates keep arriving
   (`Close(TIMEOUT)`), one whose responder answers every chunk request `CHUNK_BUSY` meanwhile
   (`Close(TIMEOUT)`), one whose next page waits behind `CHUNK_OK` replies to the requester's own
   requests (kept open), and one whose next page waits behind pushes that bring new records (kept
   open).
9. **Chunks** (protocol for the decoder vectors, engine for the rest): `ChunkRequest`, `ChunkReply`
   for the `keys.md` chunk vector, and the three statuses; a reply whose hash fails (forged), one
   whose length fails (writer fault, naming the record), one whose `data` is 4 325 417 bytes
   (malformed, no hash computed), a chunk named by two records of which only one it satisfies (one
   writer fault); `CHUNK_BUSY` for a request dispatched with exactly `MAX_SEND_QUEUE / 2` bytes
   unsent, and the request queued, holding only its hash, for one dispatched a byte below, the chunk
   read from storage only as it is sent; the requester's `CHUNK_BUSY_BACKOFF` on the connection: no
   chunk request there for 1 s after a busy answer, then 2 s, 4 s and so on up to 64 s for busy
   answers to requests sent after each backoff ended, while busy answers to requests already
   outstanding when it began leave it unchanged, back to 1 s after a `CHUNK_OK`; passes: a peer that
   lacks 1 of 100 chunks the requester needs serves the other 99 at once in one pass in ascending
   `cipher_hash` order (one `CHUNK_NOT_FOUND`, 99 `CHUNK_OK`), the missing hash asked of another
   open peer at once, and no next pass to that peer until its Status shows a greater `chunks_stored`
   or a round with it completes, and not before 1 s; a trigger that comes inside the
   `STATUS_INTERVAL` window (deferred, then acted on when the window ends) and two that come inside
   one window (one pass); a peer that answered `CHUNK_NOT_FOUND`, then fetches the chunk from a
   third peer and sends a Status with a greater `chunks_stored`, asked again in the next pass and
   serving the chunk on the same connection (`CHUNK_OK`); a request with no `cipher_hash`
   (malformed); an unsolicited reply (`Close(PROTOCOL_ERROR)`); a request from a peer that reports
   the sealed tier (served); a request for a hash the holder does not hold (`CHUNK_NOT_FOUND`,
   connection kept), and `max_requests_in_flight` such requests at once, then as many again for
   other hashes (all `CHUNK_NOT_FOUND`, connection kept); one request more than
   `max_requests_in_flight` outstanding (`Close(PROTOCOL_ERROR)`).
10. **Close** (protocol) for every reason, with and without `detail`, and one whose `detail` holds a
    control character (not shown).
11. **Status** (protocol for decoding, engine for what is sent and when): one per open folder, the
    first after the first open carrying a `device_name`, and `chunks_stored` 0 in the first Status
    after the folder opens on the connection; one whose `chunks_stored` grows between two Statuses
    and stays put after a chunk is freed; fifty chunks stored within one second (one Status sent for
    them, not fifty); and one whose name holds a control character (`Close(PROTOCOL_ERROR)`).
