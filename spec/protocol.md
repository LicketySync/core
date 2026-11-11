# Lickety-Sync sync protocol, major version 1

Status: draft for phase 0, rewritten 2026-10-22 for the shared-key model (`keys.md`) and the
coordinator's rulings R-K1 to R-K6 and S-1 to S-4 of that day, its index (4.4, 4.5) rewritten
2026-10-25 for the owner's decision of that day, and amended 2026-11-08 for the owner's answers of
2026-11-03 to 2026-11-08 (4.4's paths with no heads; 3.1's relayed connections and hole punches)
and 2026-11-10 for the reviews of that amendment and the owner's decisions of that day.
This file is what
`licketysync-protocol`, `licketysync-index` and `licketysync-engine` implement on the wire, and
what reviewers check them against. `keys.md` defines every key, record and derivation this file
uses; `suites.md` the algorithms; `threat-model.md` the adversaries. Each section says in plain
words what it is for, then defines it exactly. "Phase N" marks what phase 0 ("simulated peers
converge") may leave out; the formats are fixed now.

Every byte that arrives from a peer is untrusted: lengths are checked before anything is allocated,
every collection a peer can grow is bounded, every decoder is fuzzed, and nothing is ever silently
skipped: section 5's table says, for every failure, whether it closes the connection (malformed or
forged input, the sender's fault), is set aside while the connection stays open (a difference in
what the two peers hold), or is raised under Issues against the record a valid signature covers. A
record in this device's own index store that fails its check when a folder opens involves no
connection: it is dropped and reported (4.4, "Opening a folder"; `threat-model.md` TM-9).
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

**What changed on 2026-10-25** (the owner's decisions of that day: "version vectors, latest
only", growth bounded, "one record for a whole folder tree" for deletions, "sealed peers see almost
nothing", deletions forgotten by "the folder's own time", and the clock rule). Removed:
`supersedes` and waiting records, which replace ruling R-K6; per-writer sequence numbers, cursors,
cursor digests, range and listed requests and marks, which replace ruling R-K5's reconciliation and
ruling R-K4's ranges; keeping every record; and the device ID and sequence number in a record's
clear fields. Added: a file ID (keyed path tag) and the fingerprints of the versions a record
replaces in the clear, and, inside the seal, a version vector of at most 32 entries with a
device-wide counter (4.4); keeping only the latest versions of each path (4.4); the tree delete and
the signed cleanup record (4.4); the expiry of deletions by the folder's own time (4.4); the clock
rule, with a clock reading in Hello (3.2, 4.4); per-peer local sequences with an index epoch, set
digests and reconciliation (4.5); what the engine needs (4.7); and the index in plain words (9).
Nothing was released, so the protocol stays major 1.

**What changed on 2026-11-08** (the owner's answers of 2026-11-03 to the phase 0 report and its
follow-up questions, and their decisions of 2026-11-04 and 2026-11-08). A path whose live records
are all opaque now follows the rule for a path with no heads, so the device's outdated copy leaves
its disk ("Yes, remove the old copy"; 4.4, "Heads, display order and conflicts"); the stated
residual of an earlier ruling (S3-A), that such a path kept whatever its disk had and two devices
could differ there, is gone. Relays are public only and used or served only when turned on; hole
punches are coordinated only by devices whose persons turned that on, and a device takes part in
one only as its folders' settings allow; neither side syncs on a circuit through a device it
reserved with, or dialed through, only for a punch (`threat-model.md` TM-25; 3.1 here). No message
changes. Relay control is the relay protocol's own, versioned with it, and not this protocol's
(TM-25), so 4.1 reserves no range for it. Nothing on the wire changes, so the protocol stays
major 1.

**What changed on 2026-11-10** (the reviews of the 2026-11-08 amendment and the owner's decisions of
2026-11-10). A device remembers the versions it moved to the archive because a path's records became
unreadable, and its next write there covers them, so that a device that missed the unreadable record
no longer brings the old version back beside that write (the owner's "Also what was archived"; 4.4,
"A path with no heads"); such copies stay in the archive until a version this device reads covers
them (the owner's "Until fixed"). A conflict copy that has become a version at its own path stays on
the disk. On relayed connections (3.1): a circuit whose stated limit is at most a coordinator's
bounds is punch-only whatever the device in the middle says; that device, as relay or coordinator,
never receives Hello; only the side a circuit reached opens this protocol's stream on it; a punch
admits only a requester the device knows from a shared folder, or one
that proves a key to one of its folders with this protocol's handshake up to the folder proof
("Known peers or key holders"), and only the folders whose own settings allow a punch through that
coordinator count; and each folder's own connectivity settings decide whether it opens on a
connection a punch brought ("Both must allow"). Per-peer state keeps the peer's libp2p peer ID
(4.5). Nothing on the wire changes.

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
| `PRE_HELLO_LIMIT` | 65 536 | Applies to every frame received on a connection until the peer's DeviceProof has verified (its Hello, its DeviceProof or a Close), and to anything sent before the peer's Hello has arrived. The largest Hello a release of major 1 sends, with `clock_days` below 2^21, is a frame of 2 668 bytes (length field included, 2 672) and a DeviceProof one of 68 (72), so both fit |
| `MIN_MESSAGE_SIZE` | 8 388 608 (8 MiB) | The smallest `max_message_size` a Hello may advertise; a smaller one is `Close(LIMIT_TOO_SMALL)` |
| `DEFAULT_MESSAGE_SIZE` | 16 777 216 (16 MiB) | What a device advertises unless configured otherwise |
| `MAX_MESSAGE_SIZE` | 67 108 864 (64 MiB) | The largest value a Hello may advertise; larger is treated as this value |
| `MAX_INDEX_RECORD_BYTES` | 4 000 000 | The largest encoded `SignedRecord`; a larger one is malformed at parse, before any duplicate check |
| `MAX_REQUESTS_IN_FLIGHT` | 1 024 | The largest `max_requests_in_flight` a Hello may advertise; larger is treated as this value, so that a requester never keeps more chunk requests outstanding on a connection, whatever the holder advertises (4.6) |

- The limit for **incoming** frames is the receiver's own advertised `max_message_size` (what it
  told the peer it accepts), except that every frame received before the peer's DeviceProof has
  verified is also bounded by `PRE_HELLO_LIMIT`. The limit for **outgoing** frames is the peer's
  advertised value; a sender never emits a frame larger than that, and before the peer's Hello
  arrives it sends only Hello and Close.
- `MIN_MESSAGE_SIZE` is set so that one `ChunkReply` carrying the largest chunk
  (`MAX_CHUNK_PLAINTEXT` = 4 MiB plus Padmé and framing, `keys.md` §3.2) and one index record with
  the most chunks (section 4.4: 32 768 chunk references of about 41 encoded bytes each, a sealed
  part of at most 2 MiB, at most 64 names (2 176 bytes), the path tag and the signature, about 3.5
  MB in all) each always fit. The record cap makes that hold for any record a peer accepts, unknown
  fields included: a record at `MAX_INDEX_RECORD_BYTES` fits one page of `MIN_MESSAGE_SIZE`, so no
  peer can be handed a record that another peer's advertised limit cannot carry, and a field that
  would let records grow past the cap needs a new major (section 6). Every message that carries a
  list is additionally bounded by the peer's `max_message_size`: a sender pages before it reaches
  it.
- **Index record sizes.** A record is about 185 bytes in the clear (its fixed fields, file ID, one
  name and signature) plus about 40 per chunk reference and 35 per further name, and a sealed part
  of 40 bytes plus a power of two of at least 256 (`keys.md` §3.4), which holds the path, the dot,
  the vector (46 bytes an entry), a plaintext hash per chunk (34 bytes) and the times. So, for a
  path of about 90 bytes: a one-chunk file whose record names one or two devices (its writer, and at
  most one entry in its vector) is about 520 bytes; with three to seven devices named, or a few more
  chunks, its sealed part doubles to 512 and the record is about 780 bytes; with eight to eighteen
  devices about 1.3 KB; and with nineteen or more, up to a full vector, about 2.3 KB. A shorter path
  moves each boundary up by about one device for every 46 bytes. Each further chunk adds about 40
  bytes in the clear and 34 inside the seal, so a file's chunk list, not its vector, dominates a
  large file's record (a 1 MB file in 64 KiB chunks, written by one device: about 1.9 KB). The
  power-of-two padding (the coordinator's ruling of 2026-10-25, for the owner's review, so that
  sealed peers cannot read the number of writers or the path length from the sealed part) costs up
  to half the sealed part, about a quarter on average, against Padmé's 3 %. The plan's budget
  becomes "typically under 1 KB per file; files written by many devices up to about 2.3 KB" (the
  coordinator's ruling of 2026-10-25, for the owner's review).
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
  last occurrence; a verifier here refuses, so that a record carrying two counters means nothing
  to anyone), while a repeated scalar field is accepted packed or unpacked, as proto3 allows
  (producers pack, `keys.md` §5.2), or partly each, the values concatenated in the order they
  appear. Every fixed-size field (hashes, device IDs, nonces, public keys, signatures, digests) must
  be present at its exact size, unless its field says it may be empty; an absent field reads as
  empty, which is then the wrong size, so it is malformed. A `bool` whose varint is neither 0 nor 1,
  and a `uint32` whose varint is 2^32 or more, are malformed too, rather than truncated as proto3
  decoders may, for the same reason.

## 3. The handshake

Seven steps, as the plan draws them. Steps 1 and 2 belong to libp2p: the encrypted channel, with
exactly one security protocol per transport so that nothing is chosen before either side is
authenticated (TLS 1.3 on QUIC and on TCP, and inside a relay's circuit between native ends; Noise
inside WebSocket, WebRTC and WebTransport, where TLS is not offered, and inside a circuit with a
browser client at one end; `suites.md` §2.6), then protocol negotiation; phase 0 simulates them.
Steps 3 to 7 are this protocol. The folder proof in step 4 is the heart of it: each side shows it
holds a key to the folder (any of the three, since each holds the folder's access key) without
sending the key, in a way that only a holder of a key to that folder can even open, and that cannot
be replayed into another connection. Nothing about a folder leaves a device until the peer has
proven it holds a key to that folder, and a failed proof is answered with the same result whether
the folder is unknown here or the proof was bad.

```
A (role 0x01)                                            B (role 0x02)
 1. encrypted channel  ──────────────── (libp2p: TLS on QUIC or TCP; Noise inside WebSocket, WebRTC, WebTransport)
                       (inside a circuit, 3.1: TLS between native ends; Noise with a browser end)
 2. identify           ─── /licketysync/sync/1 ──────▶ newest common major
 3. Hello ───────────────────────────────────────────▶
    ◀──────────────────────────────────────────── Hello     roles are now known (3.2)
    DeviceProof ─────────────────────────────────────▶
    ◀─────────────────────────────────────── DeviceProof
 4. FolderProof(X) ──────────────────────────────────▶ verify; if X is here and the proof holds:
    ◀────────────────────────── ProofResult(X, ACCEPTED), FolderProof(X)
    ProofResult(X, ACCEPTED) ────────────────────────▶ X is open on this connection
 5. IndexRequest(X, epoch, since) ◀─────────────────▶ IndexRequest(X, epoch, since)
    IndexRecords(X, …, more) ◀──────────────────────▶ IndexRecords(X, …)        (replies, and pushes from now on)
    ReconcileRequest(X, prefix, digest) ◀───────────▶ ReconcileReply(X, …)      (the round's check, and what differs)
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

**Relayed connections and hole punches** (`threat-model.md` TM-25). A **relayed connection** is one
the transport reports as passing through a circuit (libp2p's circuit relay v2). The device in the
middle, a public relay or a hole-punch coordinator, is never a party to this protocol in that role:
a side runs `/licketysync/sync/1` only end to end through a circuit, never to the device in the
middle, over the circuit or with it as relay or coordinator, so that in that role it receives no
Hello and learns no device key from one (relay control is the relay protocol's own, TM-25); a device
in the middle that is also a peer of a shared folder runs this protocol with each side as any peer
does, over a connection of its own (the confirm review of 2026-11-10). A side runs this protocol
over a relayed connection to sync only when all of these hold, each judged by the side itself:

1. It reserved with, or dialed through, the device in the middle as a public relay its person turned
   on, and the protocol serves only the folders whose public-relays switch is on (the folder's own
   setting, or the device-wide default, TM-25): there it treats every other folder as paused (3.5,
   step 2) and sends no FolderProof for one, and with no such folder it does not run the protocol
   over that connection at all (the coordinator's ruling of 2026-11-08, a reading for the owner's
   review).
2. The circuit is not **punch-only**. A circuit through a device it reserved with, or dialed
   through, only for a hole punch is punch-only, whatever the switches say (the coordinator's ruling
   of 2026-11-08, confirmed by the owner that day: "I don't want random connected clients used as
   relays without the operator's consent"); so is any circuit whose stated limit (circuit relay v2's
   `Limit`, in the reservation or in the status that opens the circuit) is a duration of at most 60
   s or data of at most 64 KiB, a coordinator's bounds (TM-25), whatever the device in the middle
   says it is (the coordinator's ruling of 2026-11-10).
3. Nothing the device in the middle says of itself marks the circuit punch-only: what it says can
   turn sync off, never on.

So a coordinator never carries file data, even when both sides would take it for a public relay. On
every circuit, whatever either side takes it for, only the side the circuit reached, the one that
holds the reservation and to which circuit relay v2's STOP came, opens a stream of this protocol,
and it refuses one that the side that dialed through the device in the middle opens (the spec
author's choice, for the owner's review, on the re-confirm review of 2026-11-10): on a circuit it
takes for a public relay's, it opens one when it has a folder whose public-relays switch is on (the
first condition above), and on a punch-only one only for the admission handshake (below). On a
circuit that the side that dialed through the device in the middle takes for a public relay's, it
closes the circuit, with no Close, when no stream of this protocol has come within `HELLO_TIMEOUT`
of the channel's set-up, and counts the session as refused for the backoff below (the spec author's
choice, for the owner's review, on the check of 2026-11-11): the side the circuit reached may take
it for punch-only or have no folder to prove, and the dialing side opens none. On a
punch-only circuit a side runs this protocol only for the admission handshake (below), whatever its
folders' public-relays switches say; the circuit carries nothing else but the two sides' channel
set-up, libp2p's identify and the punch's own messages (DCUtR), within the coordinator's bounds of
64 KiB and 60 s, and the two sync once the direct connection the punch brings exists. While a
relayed connection lasts (the coordinator's rulings of 2026-11-10; the backoff's lengths are the
spec author's choice, for the owner's review):

- a side whose person turns a folder's public-relays switch off while that folder is open on the
  connection closes the connection with `Close(SHUTDOWN)`, as for a paused folder, and may connect
  again through the relay for the folders whose switch is still on;
- a side whose relayed session to a peer is refused (no folder opened) or cut (the connection ended
  before a round with the peer completed) opens no new relayed session to that peer for a backoff:
  1 minute, doubled after each refused or cut session up to 1 hour, and back to 1 minute after a
  session that completed a round;
- once a direct connection to the same peer is open, brought by a punch or found otherwise, and the
  relayed connection's folders are open on it, the side closes the relayed connection with
  `Close(SHUTDOWN)`.

**Admitting a punch's requester** (the owner's decision of 2026-11-10, "Known peers or key
holders"). From phase 2 (the owner's answer to Q4 of 2026-11-04), by the owner's decision of
2026-11-08, a device coordinates punches for others only if its person turned that on, and takes
part in one only as its folders' settings allow (TM-25). At admission only the folders whose own
settings allow a punch through the coordinator in the middle count, on each side: the folder's
direct-connections switch on and its hole-punch level allowing that coordinator ("Both must allow",
the owner's decision of 2026-11-10; the coordinator's ruling of that day on the confirm review). The
device to be reached takes a punch only from a requester that is a **peer of** such a folder (a
device that has opened that folder with it, as the folder's per-peer state shows by the requester's
libp2p peer ID, 4.5), or from one that first proves, over the coordinator's circuit, that it holds a
key to such a folder; in that proof every other folder is treated as paused (3.5, step 2), and the
public-relays switches play no part in it. The proof is this protocol's handshake up to the folder
proof, as 3.2 to 3.5 define it, on a stream that only the device to be reached opens, and only for a
requester it does not know (the spec author's choice, for the owner's review): Hello and DeviceProof
each way, then the requester's FolderProofs, of which the device to be reached, on a circuit it
takes for punch-only, looks at 4 and answers each one past the fourth REJECTED, unexamined and up to
`MAX_PROOFS_PER_CONNECTION` as on any connection, so that a requester that takes the circuit for a
public relay's and proves more folders is not closed for it (the spec author's choice, for the
owner's review, on the check of 2026-11-11), and the answering ProofResults. One ACCEPTED admits the
requester. No folder opens on the circuit: the device to be reached sends no FolderProof of its own
there (3.5, step 6); the requester answers any FolderProof there REJECTED, up to
`MAX_PROOFS_PER_CONNECTION` as on any connection, treating every folder as paused for the other
side's proofs (3.5, step 2); any message that names a folder is `Close(PROTOCOL_ERROR)` (3.5); the
clock rule's check, which waits for an open folder, does not run (3.2); and `PROOF_TIMEOUT` does not
apply there, the punch attempt's 10 s bounding the admission and the punch together (TM-25), so that
a requester not admitted within them is refused. These are a few small messages and no record,
within the circuit's bounds. The requester, which dialed through the device in the middle, opens no
stream of this protocol on the circuit (above), so it runs Hello there, before the punch, only when
the device to be reached opens that stream, and it proves only folders whose own settings allow the
punch through that coordinator; a requester the device to be reached knows runs no handshake, the
punch starting at once. The device to be reached knows who asks: the circuit relay v2 STOP message
by which the coordinator opens the circuit names the initiator's peer ID, and the channel inside the
circuit authenticates it; a requester whose authenticated peer ID differs from the one the STOP
named is refused. Until the requester is admitted, the device to be reached sends it no address (its
identify on the circuit lists none) and does not start the punch, which, as the side the circuit
reached, it starts (DCUtR). A requester that it refuses once it has opened the stream for the
handshake gets `Close(NO_COMMON_FOLDER)`, as on a connection where nothing opened, before the
circuit is closed; one refused before that (its peer ID not the STOP's, or past the caps of TM-25)
gets no Close, its circuit closed. The caps in all (TM-25) are checked at the moment of admission,
counting the attempts already admitted: a requester whose admission, by an ACCEPTED proof or as a
known peer, would bring them above 4 at once or 20 in the minute is refused, so that attempts that
began below the caps cannot all finish above them, and it gets `Close(NO_COMMON_FOLDER)` if the
stream is open and no Close if not; that refusal counts toward the caps through its coordinator only
(the spec author's choice, for the owner's review, on the check of 2026-11-11). It takes a STOP only
from a device in the middle that it holds a reservation with, and answers any other circuit relay
v2's NO_RESERVATION (TM-25). On the direct connection a punch brings, this protocol starts afresh
from Hello, and each side treats as paused (3.5, step 2), sending no FolderProof for it, every
folder whose own settings do not allow that punch: its direct-connections switch off, or its
hole-punch level not allowing the coordinator that timed it ("Both must allow", the owner's decision
of 2026-11-10, TM-25). Coordinating needs no proof of a key to any folder, and the direct connection
a punch brings is like any other: nothing of a folder crosses it before both sides' folder proofs
(3.5). `threat-model.md` TM-25 has the details, with the spec author's choices marked (the levels'
names and meanings, how a coordinator announces itself, how many reservations a device keeps, which
addresses a punch accepts, and the bounds).

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
`be16(suite) || ed25519_pk` (34 bytes under suite 1) for an implemented suite, and its Ed25519 key
is canonical and not of small order (`keys.md` §0.3), so that one device has one device ID;
`libp2p_identity` is 32 bytes (and, from phase 1, equals the transport-authenticated key, 3.1);
`suites` is non-empty, has no duplicates, each entry is 1 to 65 535, and it shares at least one
implemented suite with ours (else `Close(NO_COMMON_SUITE)`); `compressions` contains `"none"`;
`hashes` contains `"blake3"`; `max_message_size ≥ MIN_MESSAGE_SIZE` (else `Close(LIMIT_TOO_SMALL)`);
`max_requests_in_flight ≥ 1`; `nonce` is 32 bytes; `clock_days` is at most 2 097 151 (2^21 − 1, so
that it takes at most a 3-byte varint, which the largest Hello of section 2 counts); list lengths
and the feature grammar (section 5) are within section 4.2's bounds. Hello carries no device name:
field 2 is reserved, and the name travels only once a folder is open, in Status (4.5).

**The clock rule at the handshake** (4.4, "The clock rule"). When the first folder opens on the
connection (3.5), and before any record, chunk or Status of it is sent, each side compares the
peer's `clock_days` with the `clock_days` its own Hello carried. When they differ by more than
`CLOCK_RULE_LIMIT` (365 days), in either direction, it sends `Close(CLOCK_OUT_OF_RANGE)`, so that
the two sync nothing, and raises the clock-rule issue for that folder, naming the peer's proven
device ID and both readings; both sides judge the same two numbers, so both close. The check waits
for an open folder (the coordinator's ruling of 2026-10-25, for the owner's review) so that only a
peer that has proven it holds a key to a folder this device holds can raise the issue: anyone who
can reach the port can complete the handshake under a freshly made device key, and a Hello out of
range from a peer that opens no folder is only counted, in a log line. Neither side can tell from
two readings which clock is wrong. The issue says so and asks the person to compare this device's
clock with a trusted one; it does not guess from how many peers disagree, since a holder of any key
can make up any number of device identities that all claim one false date. A peer that lies about
its clock costs only its own refusal, and a read or write holder checks every record's counter as
well (4.4).

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
2. For every folder this device holds and has not paused, nor treats as paused on this connection
   (3.1: on a relayed connection through a public relay, each folder whose public-relays switch is
   off; on a punch-only circuit, at the device to be reached each folder whose own settings do not
   allow a punch through the coordinator in the middle, and at the requester every folder; on a
   direct connection a punch brought, each folder whose own settings do not allow that punch),
   compute `hint` with the peer's role; no match → `ProofResult { hint, REJECTED }` and stop. (A
   device with many folders caches the per-folder hints once per connection.)
3. Derive `proof_key`, open `sealed` with the message's `nonce` and `aad = hint`; failure →
   REJECTED.
4. Parse `ProofPayload`: `tier` is 1, 2 or 3; failure → REJECTED. Nothing checks the tier: it is the
   prover's report, shown and never relied on.
5. The peer's Hello `suites` includes the folder's suite; otherwise REJECTED.
6. A proof that would open more than `MAX_OPEN_FOLDERS_PER_CONNECTION` (64) folders on this
   connection is answered REJECTED (the prover opens the rest on another connection). Otherwise
   `ProofResult { hint, ACCEPTED }`. Record the peer's device ID and reported tier for this folder
   on this connection; the tier is shown marked "reported", like a device name. If this side has not
   yet sent its own FolderProof for the folder, send it now, except on a punch-only circuit, where
   the device to be reached sends none (3.1).

A folder is **open** on a connection when both sides have sent ACCEPTED for each other's proof. Only
then do any of the folder's records, chunks or status cross the connection, and when the first
folder opens on a connection the clock rule's check of the two Hellos runs before any of them does
(3.2); a message that names a folder not open on the connection is `Close(PROTOCOL_ERROR)`. A
connection on which no folder is open within `PROOF_TIMEOUT` (30 s) of the DeviceProofs is closed
with `NO_COMMON_FOLDER` (on a punch-only circuit, where no folder opens, the punch attempt's bound
applies instead, 3.1). A ProofResult that answers no FolderProof this side sent and has not yet had
answered (a stray one), a second ProofResult for one proof, or a `status` other than 1 or 2, is
`Close(PROTOCOL_ERROR)`.

What each side learns on failure: a `REJECTED` result says only that this proof did not open this
folder here; it is the same whether the folder is absent or paused, the hint did not match, the seal
did not open, the payload was malformed, the peer did not list the folder's suite, or the
open-folder bound was reached. The prover does not try the folder again on that connection. The
reported tier is shown and never relied on: nothing in this protocol gives a peer more for a higher
tier, since index records and chunks are verified by signature and hash whoever sends them, and only
a key holder can open what it receives. A read or sealed holder may report write, and a write holder
sealed; either changes only what the other side displays.

### 3.6 Steps 5 to 7

Once a folder is open, each side runs a round: an `IndexRequest` for what the peer came to hold
since the last exchange, when it remembers one, then a comparison of set digests that finds and
exchanges whatever still differs; from then on it pushes every index record it comes to hold. The
peer answers each request with `IndexRecords` in pages, or with a `ReconcileReply`. Chunks are
requested by ciphertext hash and returned whole. Status messages report progress periodically.
Section 4 defines each message; section 4.5 the exchange.

## 4. Messages

### 4.1 Type numbers

| Number | Critical | Name | Direction | Purpose |
| --- | --- | --- | --- | --- |
| 0x8001 | yes | Hello | both, first | Identity, capabilities, limits |
| 0x8002 | yes | Close | both, last | Reason for closing |
| 0x8003 | yes | DeviceProof | both | Signature over the transcript with the device key |
| 0x8004 | yes | FolderProof | both | Sealed proof of holding a key to one folder |
| 0x8005 | yes | ProofResult | both | Answer to one FolderProof |
| 0x8007 | yes | IndexRequest | both | "Send what you came to hold since", by epoch and local sequence |
| 0x8008 | yes | IndexRecords | both | Signed index records, paged or pushed |
| 0x8009 | yes | ChunkRequest | requester → holder | One chunk by ciphertext hash |
| 0x800A | yes | ChunkReply | holder → requester | The chunk, or why not |
| 0x800B | yes | ReconcileRequest | both | "Here is my digest of this subtree" (the drafts' key records) |
| 0x800C | yes | ReconcileReply | both | Equal, the subtree's 16 child digests, or its records |
| 0x0001 | no | Status | both | Progress per open folder; the reported device name once a folder is open |
| 0x0002 | no | Unsupported | both | "I do not know that non-critical type" |
| 0x0003–0x000F, 0x8006, 0x800D–0x800F | | reserved | | Major 1 additions (0x8006 carried key records in the drafts, 0x800D a `Covered` message in an earlier draft of 2026-10-25) |
| 0x8010–0x801F | | reserved | | Linked-device channel (phase 5) |
| 0x0010–0x001F | | reserved | | Chunk availability for selective sync (phase 5); relay control is not here: it is the relay protocol's own (`threat-model.md` TM-25) |

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
  uint32 max_requests_in_flight = 8;  // chunk requests this device will hold open per connection; >= 1; default 64; a value above MAX_REQUESTS_IN_FLIGHT (1 024) is treated as that
  bytes  nonce                  = 9;  // 32 random bytes; makes the transcript unique to this connection
  bytes  libp2p_identity        = 10; // 32: Ed25519 public key of the libp2p identity (keys.md §8.1); from phase 1 must equal the transport-authenticated key
  uint32 clock_days             = 11; // the sender's wall clock in whole days since the Unix epoch, 0 ..= 2 097 151 (2^21 - 1, in the year 7711): 0 for a clock before 1970, the bound for one after it, and a value above it malformed; for the clock rule (4.4); whole days so that the Hello gives no finer clock reading to anyone who connects
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
  NO_COMMON_FOLDER             = 8;   // nothing opened within PROOF_TIMEOUT, or a punch's requester refused after the admission handshake started (3.1)
  VERIFICATION_FAILED          = 9;   // this peer forwarded a record whose signature fails or a chunk whose ciphertext hash fails: forged or corrupted in its hands
  TOO_MANY_CONNECTIONS         = 10;  // this device's connection limit is reached (libp2p limits, phase 1)
  TIMEOUT                      = 11;  // HELLO_TIMEOUT, IDLE_TIMEOUT or REPLY_PAGE_TIMEOUT (4.5) elapsed, or, while unsent bytes remained, none was delivered for IDLE_TIMEOUT (3.1); PROOF_TIMEOUT closes with NO_COMMON_FOLDER
  reserved 12;                        // was FEATURE_REQUIRED, with the Folder record (ruling S-2)
  CLOCK_OUT_OF_RANGE           = 13;  // the clock rule (3.2, 4.4): the two Hellos' clock_days differ by more than CLOCK_RULE_LIMIT; sent only when the first folder opens on the connection
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

An index record is one signed statement about one version of one path: what it is, which chunks
hold it, and which versions of that path it replaces. A device keeps, per path, only the records
that nothing it holds replaces (**latest only**, the owner's decision of 2026-10-25, which replaces
ruling R-K6's design of keeping every record). The two kinds of holder see a record differently (the
owner's decision of 2026-10-25, "sealed peers see almost nothing"):

- **Read and write holders** open the record's sealed part and order versions by the **version
  vector** inside it (below): they find which version replaces which, keep concurrent versions as a
  conflict, apply deletions and forget them after the deletion horizon.
- **Sealed peers** read only four things: the path's opaque **file ID** (its keyed path tag), the
  **fingerprints** (record hashes) of the versions the record names as replaced, the chunk IDs with
  their padded sizes, and the signature. (A relay forwards a connection's encrypted bytes and reads
  no record at all, `threat-model.md` TM-25, §5.) A sealed peer replaces a version only when
  a signed record or a signed cleanup (below) names it; otherwise it keeps both. The index is
  read-only to it: it resolves no conflict and changes nothing ("sealed peers should not be allowed
  to resolve conflicts nor modify anything", the owner).

Every write holder signs with the same folder key (`keys.md` §5.3), so a record names its writer
only by the device ID the signer claims, inside the seal. The record is a `SignedRecord` (`keys.md`
§5.1) whose body is:

```proto
message IndexRecord {
  uint32 suite        = 1;   // the folder's suite
  uint32 record_type  = 2;   // 16
  bytes  folder_id    = 3;   // 32
  reserved 4, 7, 8, 10, 14;  // were writer_key_id, previous, supersedes, epoch and resumes
  reserved 5, 6, 9, 11, 16;  // were device_id, counter, vector, deleted and tree in the clear; inside the seal since 2026-10-25
  repeated ChunkRef chunks = 12;   // in file order; <= 32 768; empty for directories, tombstones, tree deletes and empty files
  bytes  sealed       = 13;  // nonce (24) || XChaCha(rk, nonce, aad, padded SealedMeta), keys.md §3.4; 40 bytes plus a power of two from 256 to 2^21, so 296 ..= MAX_SEALED_BYTES (2 097 192)
  bytes  path_tag     = 15;  // 32: the file ID (below)
  repeated bytes replaces = 17;  // 32 each: the record hashes of the versions this record replaces (below); 0 ..= MAX_REPLACES (64), ascending, no repeats
}

message ChunkRef {
  bytes  cipher_hash = 1;    // 32: the chunk ID, H("licketysync/v1/hash/chunk", stored), keys.md §3.2
  uint32 stored_len  = 2;    // bytes of the stored blob, its padded size; 46 ..= padme(MAX_CHUNK_PLAINTEXT + 5) + 40 = 4 325 416, and itself a Padmé length plus 40 (keys.md §3.3)
  reserved 3;                // was epoch
}

// Inside `sealed`, visible to write and read holders only.
message SealedMeta {
  string path                 = 1;   // UTF-8, '/' separated, relative, no empty, "." or ".." component, no NUL, no backslash; <= 4096 bytes; writers normalise every component to NFC, and readers do not check it (step 7); for a tree delete, the deleted directory
  uint32 kind                 = 2;   // 1 file, 2 directory; others reserved
  uint64 size                 = 3;   // bytes of plaintext content; 0 for an empty file, which has no chunks
  int64  mtime_ns             = 4;   // modification time, nanoseconds since the Unix epoch
  uint32 mode                 = 5;   // Unix permission bits; 0 when the writer has none
  repeated bytes plain_hashes = 6;   // keyed BLAKE3 per chunk (keys.md §3.2), same order and count as `chunks`
  uint64 written_at           = 7;   // writer's wall clock in microseconds since the Unix epoch, the unit of clock_us (0 for a clock before 1970); informational only, never used for ordering
  bytes  device_id            = 8;   // 32: the writer's device ID, as the signer claims it; with `counter`, the record's dot (below); never shown as an author (keys.md §5.3)
  uint64 counter              = 9;   // the writer's counter (below): 1 ..= MAX_COUNTER (2^62)
  repeated VectorEntry vector = 10;  // the version vector: 0 ..= MAX_VECTOR_ENTRIES (32) entries, ascending by device_id, no device twice, every counter below `counter`
  bool   deleted              = 11;  // a tombstone, or with `tree` a tree delete; the record then has no chunks
  bool   tree                 = 12;  // a tree delete of the path and of everything beneath it (below); requires deleted, kind 2 and size 0
}

message VectorEntry {
  bytes  device_id = 1;      // 32
  uint64 counter   = 2;      // 1 ..= MAX_COUNTER (2^62)
}
```

- **Sealing**: `keys.md` §3.4: `SealedMeta` padded to the least power of two that holds it, at least
  256 bytes, under the record key `rk`, a random 24-byte nonce, and `aad = folder_id || path_tag`
  (64 bytes), so a sealed part cannot be moved to a record of another folder or path; the signature
  over the whole body binds it to everything else.
- **Record hash**: `record_hash = H("licketysync/v1/hash/record", body)` over the body bytes as
  received (`keys.md` §5.1): the record's **fingerprint**, which duplicates are found by, set
  digests cover (4.5) and `replaces` and cleanups name.
- **Cleanup records**, the second kind of signed record (`record_type` 17), are defined below
  ("Cleanup"); every rule here that speaks of records covers them unless it says otherwise.

**File IDs (path tags).** Read and write holders derive the path-tag key `tk` from the data key
(`keys.md` §3.1, §3.5), and a path's **file ID** is `path_tag = BLAKE3_keyed(tk, path)`, over the
path's UTF-8 bytes as `SealedMeta.path` holds them.

- One path has one tag, so every version of a path carries the same tag on every device, whoever
  wrote it; two paths share a tag only by a BLAKE3 collision. Paths are compared byte for byte, as
  everywhere, so a name that is not NFC has a tag of its own (step 7).
- Without `tk` nobody can compute a tag, so a sealed peer cannot test whether a guessed path is in
  the folder (TM-14), and tags say nothing about which paths share a directory. A read or write
  holder finds which tags lie **at or beneath** a directory `P` from paths: a record lies beneath
  `P` when its path begins with `P` and a separator, and at `P` when its path is `P`.
- The drafts of 2026-10-25 built tags as chains of hashes, so that sealed peers could check that
  one tag lay beneath another; with cleanups (below) no sealed peer needs to, and the chains, the
  `Covered` message that carried them and `MAX_PROOF_COMPONENTS` are gone.

**Dots and counters.** These live inside the seal and only read and write holders see them. A
record's **dot** is the pair `(device_id, counter)`: which device wrote it, and its place among that
device's records in the folder. Its **vector** lists, for other records, the dots its writer had
seen: a version or tombstone's vector names the versions of its path that it replaces, and a tree
delete's the records beneath its directory that it deletes (below). The dot is kept apart from the
vector, as in dotted version vectors (Preguiça, Baquero, Almeida, Fonte and Gonçalves 2010, the
scheme Riak recommends from release 2.0), so that a record's own counter says nothing about other
records of its device that its writer never saw.

- **The writer's rule.** Each device keeps, per folder, a **high-water mark** `hw`: the greatest
  counter of every applied record (step 7) it has held or written in the folder, never decreasing,
  persisted with its index store and raised before any record that raises it is used. Its **next
  counter** is `max(hw + 1, min(clock_us, CLOCK_FLOOR_MAX))`, where `clock_us` is the device's wall
  clock in microseconds since the Unix epoch (0 for a clock that reads before 1970) and
  `CLOCK_FLOOR_MAX` is 2^61, and a record it writes takes it; then `hw = counter`. The records of
  one commit (4.7) take consecutive counters from one reading of the clock, in this order: versions,
  then tree deletes, then tombstones, then cleanups, and within each kind by ascending path tag
  (cleanups in the order they are paged); so a rename's version comes before its tombstone, and the
  tombstones a pruned tree delete leaves to write come after it (below). So a device's counters rise
  with every record it writes in the folder, whatever the path; every counter is greater than every
  counter its writer had seen in the folder (a Lamport clock: Lamport 1978); and counters follow the
  writers' clocks, which ranks vector entries by how recently they advanced (pruning, below) and
  gives the folder a time of its own (expiry, below). The counters are microseconds, so read and
  write holders learn when each version was written to the microsecond (`threat-model.md` §5);
  sealed peers never see them. That is the owner's decision of 2026-10-25, with the instruction
  "Make sure this is documented - do not hide this detail", and the reason for microseconds rather
  than minutes: "I can work on files in multiple locations nearly simultaneously and the per-minute
  version resolution is not accurate enough".
- **Why the clock floor.** A device whose index store is restored from a backup, rebuilt or lost has
  a lower `hw` than before. Without the floor its next counters would repeat those of records it
  wrote before, which peers still hold. With the floor its next counters lie above every counter it
  used before, unless its clock reads earlier than the last of them (the residual, "Why it is
  safe"). Syncthing's version counters take the same floor, `max(value + 1, now)` in seconds
  (`lib/protocol/vector.go`, `Vector.Update`); microseconds here let a device write a million
  records in a second without running ahead of its clock by more than a second. The cap keeps a
  clock that is wildly wrong from bringing honest counters near `MAX_COUNTER`: past 2^61 a device
  still has 2^61 counters to write with.
- **A fast clock carries forward.** A device whose clock runs ahead writes counters ahead of real
  time, and since every later counter in the folder must exceed every counter its writer has seen,
  every device that comes to hold such a record writes just above it until its own clock passes it:
  the folder's counters stay ahead by as much for as long as the fast device keeps writing, and once
  it stops the lead runs out over as much real time, since a counter carried forward rises by only
  one per record. Nothing orders versions by it (TM-40); what it moves is the ranking of entries
  when vectors are pruned and the folder's own time (expiry, below), so that deletions are forgotten
  early, by up to as much. A read or write holder that holds a record whose counter is more than
  `CLOCK_AHEAD_WARNING` (one day) ahead of its own clock, its signature verified, raises an
  informational issue worded "this folder's time is N ahead of this device's clock (first seen on a
  record claiming device X)": X is where the lead was seen first, not its cause, since a device with
  a correct clock that wrote after holding a fast device's record carries the same lead, so the
  issue blames no device's clock (the coordinator's ruling of 2026-10-25, for the owner's review).
  How far ahead a counter may be at all is the clock rule's (below).
- A device whose next counter would pass `MAX_COUNTER` writes nothing more in the folder and raises
  an issue saying that the folder must be shared again (`keys.md` §7). Only a record that a write
  holder signed with a counter near `MAX_COUNTER` brings that about, since honest counters stay
  below `CLOCK_FLOOR_MAX` plus the records written: a stated residual of a dishonest writer
  (`threat-model.md` §3.6).
- What a reader checks (step 7) is only what one record shows: every counter in its vector is
  below its own counter. Nothing in this design relies on more than that and the writer's rule.

**The clock rule** (the owner's decision of 2026-10-25: "Refuse to sync with clients that are more
than a year out of date"; its record check, below, is the coordinator's reading of the owner's rule,
shown to the owner on 2026-10-25). It is a different thing from the deletion horizon below, though
both are 365 days: the deletion horizon decides when a deletion is forgotten, and the clock rule
which devices and records are too far out of step with this device's clock to be synced with at all.
The clock rule, and expiry by the folder's own time (below), are to be replaced by a signed
watermark (the owner's decision of 2026-11-08; a later change).

- **Peers.** Each Hello carries the sender's wall clock in whole days since the Unix epoch
  (`clock_days`, 4.2; days, not finer, so that the Hello does not hand out a fine clock reading to
  anyone who connects). When the first folder opens on a connection, a device that finds the two
  Hellos' `clock_days` more than `CLOCK_RULE_LIMIT` (365 days) apart, in either direction, closes
  the connection with `CLOCK_OUT_OF_RANGE` before any record crosses, and syncs nothing with that
  peer (3.2); a peer that opens no folder is only counted. Sealed peers apply this too, since it
  needs only their own clocks.
- **Records** (the coordinator's reading of the owner's rule, shown to the owner on 2026-10-25). A
  read or write holder neither holds nor relays a record whose counter is more than
  `CLOCK_RULE_LIMIT` ahead of its own clock when it arrives (step 4): such a record is **from the
  future**. The check is made on arrival only; records already in the store are held whatever the
  clock, and a store whose records lie more than a year ahead keeps the folder from opening
  ("Opening a folder", below). A sealed peer cannot read counters, so it holds and relays such a
  record like any other; the read and write holders it reaches refuse it. A record behind the clock
  is no fault: old versions are ordinary.
- **The issue.** Both cases raise an issue on the device that refuses, for the folder concerned. For
  a peer it names the peer's device ID, proven at the handshake, and says that this device's clock
  and the peer's differ by more than a year. For a record it says "a record dated more than a year
  ahead of this device's clock" and names the device ID the record claims only as where the record
  came from: the record's counter is the folder's time carried forward (below), so that device's
  clock may be right. Neither case can tell which clock is wrong; the issue asks the person to
  compare this device's clock with a trusted one, and gives the remedy for the device whose clock is
  wrong: stop syncing the folder (unlink it, keeping its files, `keys.md` §7.3), set the clock
  right, and add the folder again with the same key over the same directory (`keys.md` §7.2); and it
  says what the remedy leaves: edits made while the clock was wrong may later reappear, or push
  later edits to the archive (below). `CLOCK_AHEAD_WARNING` (one day) stays as the early warning.
- **What adding the folder again resets on that device.** Its index store for the folder starts
  empty: no records, no bases, a high-water mark of 0 (so its next counter comes from its corrected
  clock), a new index epoch, no per-peer state. Its key, its device ID and its files stay. It then
  syncs as a device joining over its own copy of the files (`keys.md` §7.2): files that match a
  record are adopted without downloading; files that differ become new versions with empty vectors,
  concurrent with what the others hold, so they show as conflict copies the person settles, never as
  silent overwrites; files it deleted while its clock was wrong come back from the others, since its
  deletions were refused or are undone. This is the rule's real cost, which the person pays on the
  device that was wrong.
- **What adding the folder again leaves** (a stated residual; the A2 failure of "Why it is safe"
  8c). The device keeps its device ID, and its counters start again from its corrected clock, below
  those it wrote while its clock was ahead. Records it wrote then and that survive elsewhere (sealed
  peers relay them; devices whose clocks were close to its own hold them) become acceptable once
  real time comes within a year of them, and come back as versions. One whose vector carries one of
  those future counters of its device, because the device wrote over its own earlier record of that
  path while its clock was wrong, or another device wrote from such a record, then covers the edits
  the device made at that path after the fix: they are replaced as by a later edit, and their files
  go to the archive, with no conflict copy. So edits made while the clock was wrong may later
  reappear, or push later edits to the archive. A per-folder writer generation that re-adding a
  folder would bump would close this; it is an open question for phase 1.
- **What it does not catch.** A clock up to a year ahead passes both checks. Its records raise the
  folder's own time by up to a year, so deletions are forgotten up to that much early: files come
  back, never lost (expiry, below). A device whose clock is up to a year behind and that has seen
  little of the folder (its high-water mark low) dates its first deletions in the past, so they too
  are forgotten up to that much early. And a record refused as from the future is not destroyed:
  sealed peers, which cannot read its counter, keep and relay it, and a read or write holder accepts
  it once its own clock comes within a year of it, when it joins the folder as a concurrent version
  (a conflict copy where its content differs) and moves the folder's time forward, years later if
  its clock was far off. Re-adding the folder on the device that wrote it does not recall it.
- **What it does to the devices in between.** The record check measures a record's counter, which is
  the folder's time as its writer carried it forward, not that writer's clock. Once a read or write
  holder accepts a record from a clock up to a year ahead, every record it writes afterwards is
  dated at least as far ahead, until real time reaches it, and so is every record of every device
  that then holds one of them. A device whose own clock lies far enough behind that the two leads
  add up to more than a year refuses all of them, although its handshakes pass: with W's clock 300
  days ahead and X's 70 days behind, every pair but W and X syncs, Y (whose clock is right) accepts
  W's records, and X then refuses every record that Y and the others write afterwards, while its own
  edits still flow out, for up to a year. The refused records raise the folder's time on the other
  side only, so X and the others also disagree on which deletions have been forgotten, and the
  records written over them are refused in turn: a partition that lasts until real time comes within
  a year of the records or the lead runs out. The issue X raises therefore blames no device (above);
  the remedy belongs on the device whose clock is wrong, W or X, and Y needs none.

**Coverage.** Record `V` **covers** record `U` when `V`'s vector gives `U`'s device a counter at
least `U`'s counter: `V.vector[U.device_id] ≥ U.counter`, a device absent from a vector counting 0.
Two records **conflict**, or are **concurrent**, when neither covers the other. Coverage reads the
seal, so only read and write holders judge it; sealed peers judge by names instead (below). It holds
only between applied records (step 7): a record whose seal does not open or fails a check of step 7
covers nothing and is covered by nothing, and goes only by a name. Read and write holders run step
7's checks on a seal at step 3, before using its dot or vector, so that coverage never reads a
vector that has not been checked, and no record is ignored as obsolete on one device and held opaque
on another: whether such a record arrives before or after any other changes nothing.

- Coverage looks at one entry, the covered record's own dot, as dotted version vectors do. Comparing
  whole vectors, as Syncthing's `Compare` does, would make a pruned vector fail to replace the very
  version it was written from.
- No record covers its own dot, since every counter in its vector is below its own (step 7); so two
  records with one dot never cover each other, whatever their vectors, and are concurrent: both are
  kept and ordered like any other heads (the display order, below, ends with the record hash). One
  dot stands for two records only when two devices write under one device ID, a write holder signs
  twice under one dot, or a restored device's clock reads early ("Why it is safe" 13). Two records
  are equal only when their bodies are, and then they are one record.
- `V` covers `U` only when `U`'s counter is below `V`'s, so coverage has no cycle.
- Every read and write holder that opens the same records finds the same coverage between them,
  whatever release it runs, short of a record one release cannot read (step 7).

**Names.** A record **names** the records whose fingerprints its `replaces` lists, and a cleanup
names the records its groups list (below). Names are in the clear and signed, so every tier reads
them. A write holder names only records whose signatures it has verified and that it has judged
replaced by vectors or forgotten: the bases, twins and archived versions its write replaces, stale
copies its write covers, and, in cleanups, what the cleanup cases list (below). So for read and
write holders a name says no more than coverage and expiry already do ("Why it is safe" 10); for
sealed peers it is the only thing that replaces a version.

**Bases.** A read or write holder that puts versions on its disk keeps, for each path, its
**bases**: the records whose content it has on disk there, that is the version the file at the path
holds and the version each of its conflict copies holds (below), or, for a path it has removed from
disk, the tombstone or tree delete it applied there. The engine names the bases (4.7): a record
becomes a base when the engine has applied it to the disk (its content in place, or the path
removed) or when this device wrote it from the disk, and stops being one when another record becomes
the base of that path or copy. The index keeps every base record, its dot and vector included, even
after it is replaced and dropped from the live set, until the engine reports a newer version applied
there: so a base can be a live record or a record kept only as a base. A base kept only as a base is
local state: it is not held in the sense of the live set, not served, not counted in any set digest
and not pushed; it is persisted, as its signed envelope, with the index store and checked again when
the folder opens, like any record. A device keeps at most one base per path and per conflict copy on
its disk. Bases are kept per file ID, each with the place it stands for (the path itself, or one of
its conflict copies on the disk), and persisted with the index store's metadata, in the commit of
the change that makes them (4.7). A record is **applied to the disk** when the engine has written
that version there, or removed the path for a deletion; in phase 0 the disk is the simulator's. A
conflict copy counts once it is on the disk: the engine names, as a base of the path's file ID, the
record whose content it wrote beside the path as that copy, beside the base at the path itself; when
a write over the conflict turns the copy into a version at its own path ("What becomes of a conflict
copy"), that version becomes the base of the copy's own path, and the copy is no longer a base of
the original one. When a path loses its heads to records this release cannot read and the engine
moves its file and conflict copies to the archive, the index keeps the bases it had there as
**archived versions** of the path, in the slots they held ("A path with no heads"), beside the base
each slot takes later: so a slot can hold a base and archived versions, more of them each time
records this release cannot read take the path's heads again, a number bounded by such records that
write holders sign (`threat-model.md` §3.6). No record is both a base and an archived version: an
archived version is dropped when the same record is held again or becomes a base again. Sealed
holders put nothing on disk and keep no bases.

A base's **twins** are the other live heads at its path that hold its content and are concurrent
with it: their content does not differ from the base's (below, "Heads": two directories, two files
with the same `plain_hashes`, or two tombstones whatever their kinds; a tree delete is no one's
twin); their vector does not cover the base's dot, so a later version of the base, one that changed
only its mode or time say, is never its twin; for the base at the path itself, they come after it in
display order (below); and a twin is never the first head in display order at its path, the record
the engine puts there, which counts only once it is a base. So a twin is never the head the engine
has yet to put at the path, whose time and mode are not yet on the disk, even when the base at the
path is no longer the first head (a later version of it still arriving replaced it) or the twin
matches a conflict copy's base. Neither the second condition nor the third implies the other: a
concurrent version with a later `mtime_ns` comes first, and a later version with the same `mtime_ns`
can come after. A conflict copy's base has twins by all but the third, its place being beside the
path whatever the display order. The display order shows a base and its twins as one file with no
conflict copy, and the engine names only one of them as the base, but the content of each is on the
disk as much as the base's is, so a write counts the twins with the bases (below). Between a base
and its twins, concurrent, times and modes are not compared: the time and mode on the disk are the
base's, which at the path comes first of them in display order. Twins are common: two devices that
create the same file apart make a pair, and a folder linked on two devices that already hold it
makes every file a pair (the identical-heads fix of 2026-11-08: before it, a write counted the bases
alone and covered one twin, and the others stayed live on every device, a conflict copy of the old
content after an edit, the old file back after a delete or a rename, a deleted directory back; the
reviews of the fix made a twin concurrent with its base, not ahead of the base at the path and never
the first head, so that a version still arriving whose only change is its mode or time stays a
conflict, 4.7 item 6).

**The vector and names of a new record.**

- **A version or a tombstone** that device `d` writes at path `p`, from what it finds on its disk:
  let `S` be `d`'s bases at `p` (above), their twins there and the versions `d` archived at `p`
  ("A path with no heads"), never a tree delete, a set in which each record counts once, at most
  `MAX_VECTOR_ENTRIES` (32) of them: the
  bases first, then the twins, then the archived versions, its own records first within each, then
  the first in display order (below) when there are more (decision: so a twin never takes a place a
  base would have had, and records signed under `d`'s own device ID, "Why it is safe" 8b, cannot
  push its base out; that the archived versions come last, ranked among themselves by the display
  order's rule, is the spec author's choice, for the owner's review). `S` is built from what is on
  `d`'s disk, or, for the archived versions, what was on it until records this release cannot read
  took the path's heads, and never from what it holds: a version `d` holds whose content is not yet
  on its disk is not in `S`, so the write does
  not cover it, and it stays a head beside the write, a conflict (the owner's rule that an edit is
  never silently replaced; "Why it is safe" 9). A twin's content is a base's, on the disk, and a
  time or mode in which a twin differs from its base was never there, the base's being shown in its
  place, so covering it replaces no content the person has not seen. Every live record at `p` that
  is not in `S` stays a head until a later write covers it. So do the twins past 32, the last in
  that order: beside the write they are conflict copies of the old content after an edit, or the old
  file back after a delete, until the next write there, made with them on the disk, covers them (40
  twins take two writes); archived versions past 32 stay archived versions, for the next write
  there. The vector is the **join** of the dots and vectors
  of `S` (for each device, the greatest counter that any record of `S` gives it, in its vector or as
  its own dot), then pruned. A write therefore covers every record in `S`, and every record that
  those covered, unless pruning took that record's entry out. An edit, a delete and a write that
  resolves a conflict (`d` holding the conflict's heads on its disk, at the path and as conflict
  copies) are all this one rule; a path new to `d` has `S` empty and an empty vector.
- **Its names.** The record's `replaces` lists, first, the fingerprint of every record in `S` (at
  most 32); then the fingerprint of every record held at `p`'s tag that `d` judges a **shared writer
  fault**, one whose seal fails a check of step 7 other than the check of `kind`: those checks are
  fixed for major 1 (section 6), so every release judges such a record a fault and none applies it;
  and then, up to `MAX_REPLACES` (64) in all, the fingerprints of the **stale copies** at `p`'s tag
  that `d` knows of and that the new vector covers: records that a peer offered `d` in an exchange
  and that `d` found replaced by what it holds (4.5, "Stale copies"). Shared writer faults that do
  not fit go, in the same commit, into a cleanup group `because` the new record (case (a), below),
  and a stale copy left over into the cleanup at the round's end. The rule that a write holder names
  nothing that a cleanup it holds names in any group (case (b), below) covers shared writer faults
  too: one that a held cleanup names waits, held opaque, until the writer forgets that cleanup. One
  named only in an earlier write's `replaces` can be replayed after the path's next write and is
  named again by the write after it, one name per fault per write, bounded by the faulty records
  write holders have signed (`threat-model.md` §3.6). So a sealed peer that holds the version `d`
  wrote over, a stale copy `d` has learned of, or a record no release can apply, drops it when the
  new record arrives, and a shared writer fault lasts only until its path is next written (the
  coordinator's ruling of 2026-10-25, for the owner's review). A record that is opaque here only
  because its `kind` is one this release does not know is not named: it may be a newer release's
  version ("Latest only, as read and write holders keep it", below).
- **Pruning.** When the join has more than `MAX_VECTOR_ENTRIES` (32) entries, the record keeps its
  **mandatory** entries, those of the devices of the records in `S` (for a tree delete, of the
  records it names at its own path, below), and fills the remaining places with the other entries of
  greatest counter, the smaller device ID first between equal counters; the rest are dropped. Since
  counters follow writes, the entries dropped are those whose devices wrote least recently on that
  path's line of versions: the least recently active writer goes first (the owner's choice of
  2026-10-25 between a count and a time window), as Riak prunes its vector clocks (Sheehy, "Why
  Vector Clocks Are Hard", 2010). The mandatory entries are at most 32, one per record of `S` or of
  those a tree delete names, so they always fit.
- **A rename** from `p` to `q` is two records, written in this order: a version at `q` (with `S` the
  bases at `q` and their twins), then a tombstone at `p` (with `S` the bases at `p` and their
  twins). Written in that order and pushed in it (4.5), a peer that receives both from one device
  over one connection sees at worst both paths for a moment, never neither; from two devices, or
  through a reconciliation, the tombstone may arrive first. A directory moved with what it holds is
  a version at every new path, then a tree delete of the old directory. A copy is a version at the
  new path.
- **A tree delete** of directory `P` that `d` writes when its disk no longer holds `P`: its vector
  is the join of the dots and vectors of every base `d` keeps at or beneath `P` (the versions on its
  disk there, and the tombstones and tree deletes it applied there), of their twins and of the
  versions it archived there ("A path with no heads"; that a tree delete takes them too is the spec
  author's choice, for the owner's review), pruned with the devices of the records it names at `P`'s
  own tag mandatory; its `replaces` names, first, the bases at `P`'s own tag, their twins and the
  versions it archived there, at most 32 of them, in `S`'s order (above), then the shared writer
  faults held there (as above). So its vector covers every record it names ("Names"),
  and its names stay within `MAX_REPLACES` however many conflict copies sit at `P`'s own path
  (decision of 2026-11-08: before, it named every base there, and with 64 or more the write was
  refused, so `d` could not delete the directory). A record at `P`'s own tag past those 32 goes if
  the vector covers it, and otherwise stays a head until the next delete there: when more than 32
  device IDs made `P` alike, apart, the directory comes back, until it is deleted again, made with
  them on the disk (a stated residual, section 9; `threat-model.md` TM-43). Like `S`, the join is
  built from the disk: a version `d` holds beneath `P` whose content never reached its disk is not
  in it, and survives the delete, unless the join reaches a later record of its device beneath `P`
  ("Why it is safe" 8a). Opaque records are never bases or twins, so they are in neither. When the
  pruned vector leaves some base or twin beneath `P` uncovered, `d` then writes a tombstone at its
  path (as above, `S` holding that path's bases and twins), after the tree delete, so that `d` holds
  nothing of its own beneath `P` but tombstones; this happens when more than 32 device IDs wrote at
  or beneath `P`, and the files of the devices pruned out each get a tombstone. An archived version
  beneath `P` that the pruned vector leaves uncovered gets no such tombstone, no version of it being
  held here to write over: the tree delete does not take it, the cleanup does not name it, and it
  stays an archived version, for the next write at its path, with its copy kept (a stated residual
  of the confirm review of 2026-11-10, which needs more than 32 device IDs at or beneath `P`; the
  record this release cannot read that took it, which no tree delete names below its own directory's
  path, goes on replacing that version on every device that holds it). In the same commit
  `d` writes a cleanup, `because` the tree delete, naming every record beneath `P` that it held,
  kept as a base or kept as an archived version and that the tree delete covers (below), so that
  sealed peers forget them. The
  vector is that of the tree `d` deletes, not of the whole folder (decision: a folder-wide vector
  would cover more versions that `d` never held, "Why it is safe", and would fill its 32 places with
  devices that never wrote beneath `P`).

**Latest only, as read and write holders keep it.** For each file ID, a read or write holder holds
that tag's **live** records: those not **replaced**, where a record is replaced when a record held
at its tag covers it, when a record held at its tag names it, when a held tree delete covers it
(below), or when a held cleanup names it in a group that applies (below). It also holds every tree
delete until a later tree delete covers it or the deletion horizon passes, and every cleanup until
its own horizon passes (expiry, below). A new record `R` that arrives or is written (step 6): every
live record that `R` replaces is dropped, and `R` is held unless something held replaces it. So a
device holds, per path, its current heads, normally one; a path changed a million times by a few
devices holds one record whose vector has a few entries. Names in a record's `replaces` count only
at the record's own tag.

- A record this release cannot read (opaque, step 7) has no vector it can judge, so it covers
  nothing and is replaced only by a name, as at a sealed peer. A shared writer fault is named by the
  next write at its path ("Its names").
- **A newer release's version.** A record opaque here only because its `kind` is unknown is held,
  served and relayed like any record, shown after the heads as an update this release cannot read
  (Heads, below), and kept until a name drops it, which a release that can read it gives it when it
  writes over that version, as for any version. No release silently replaces such a version. This
  release never names it: it is no shared writer fault, never a base and never covered here, so it
  is neither in `S`, nor among the shared faults, nor a stale copy, and no cleanup case reaches it.
  And at a release that can read it, a write made here covers it only through an entry that a
  record of `S` brought (its vector is the join of `S`, this device's bases and their twins), that
  is through a base or twin that already covered it or was a later record of its own device at the
  path, so a version that came after it ("Why it is safe" 3 and 9); otherwise the newer release
  holds the write and the newer version side by side, a conflict, and loses neither. Tree deletes
  and cleanups written here are built the same way, from bases, their twins and what this release
  can judge.
- Nothing else drops a record: what replaces it is a signed record or cleanup that the device holds,
  and expiry drops only tombstones, tree deletes and cleanups. A base kept only as a base (above) is
  no held record, and goes when the engine names a newer base. No peer's say-so and no clock drops a
  live version (TM-17).
- A dropped record is gone from this device. It comes back only if it arrives again and nothing held
  replaces it then, which pruning and expiry make possible ("Why it is safe").

**Latest only, as a sealed peer keeps it (the sealed-peer rule).** A sealed peer holds, per file ID,
every record that no record it holds at that tag names and no held cleanup names in a group that
applies. A new record `R` at tag `t`: every record held at `t` that `R` names is dropped, and `R` is
held unless a record held at `t` names it or a held cleanup does. So a sealed peer replaces a
version only when an incoming signed record or cleanup names it, keeps both versions otherwise
(concurrent versions, or a stale copy replayed to it), and never drops a version that no signed
record or cleanup names. It never expires anything and never applies a tree delete by itself: a tree
delete is to it one more record at its directory's file ID, and what lay beneath the directory goes
only when a cleanup names it. It reads no seal, so it sees no vector, counter, device ID, deletion
mark or time. What it holds, and what it refuses, depends only on the records it holds, as at a read
or write holder (Cleanup, below). Beside what a read or write holder holds that has seen the same
records, it holds stale copies, which a write holder names when it meets it, or, for one that a
cleanup the write holder holds already names, once it has forgotten that cleanup (4.5), and it can
lack, for a while, a version that came back after its deletion was forgotten and that a replayed old
deletion took away again ("Stale copies at a sealed peer", below).

**Tree deletes.** A record whose seal sets `tree` (and `deleted`, with no chunks) deletes the
directory whose tag it carries and everything beneath it. For read and write holders it **covers**
every record `U` whose path lies at or beneath its own and to whose device its vector gives a
counter at least `U`'s, an earlier tree delete included; it is no head, and is held until a later
tree delete covers it or the deletion horizon passes. Sealed peers learn what it deleted only from
the cleanup its writer issues with it.

- **An edit beats a delete.** A version written beneath `P` by a device that had not seen the
  delete, nor anything the delete's writer had seen of that version, keeps a dot the delete's vector
  does not cover, and stays live ("Why it is safe"). Its directories have no version any more; the
  engine creates on disk the directories an applied live record needs (phase 1), and none for a
  record this release cannot read ("A path with no heads").
- **Nested deletes.** A tree delete of `P` covers every earlier tree delete at or beneath `P` whose
  dot its vector covers, since its writer's join includes the tree deletes it applied there: so a
  directory deleted again and again (a build directory) keeps one tree delete, not one per deletion.
  What the earlier one covered, the later one covers as well, through the entries its join took
  from the earlier one's vector, except where pruning dropped them; there a version the earlier one
  covered can be live again, the spurious survival of "Why it is safe" 7, never a wrong deletion.
  The later one's vector obeys the same bound of 32 entries, and its cleanup names the earlier one.
- A read or write holder applies a tree delete to the records whose paths it can read; a record
  beneath it that it cannot read stays until a cleanup names it.
- One tree delete takes the place of a tombstone per file while at most 32 device IDs wrote what
  lies beneath the directory; past 32 device IDs, each file of a device pruned out of the vector
  gets a tombstone as well ("The vector and names of a new record"). Its cleanup, which read and
  write holders hold for the cleanup horizon and sealed peers until a later cleanup names it, names
  each record beneath (below).
- **Judging a tree delete without a walk** (the coordinator's ruling of 2026-10-26, for the owner's
  review). A read or write holder keeps, per device ID, the applied records it holds (live versions
  and tombstones, and tree deletes; not opaque records, which nothing covers, nor cleanups, nor
  bases kept only as bases), ordered by path bytewise in a search tree whose every node also keeps
  the least counter in its subtree: one entry per held record, changed in the commit that holds or
  drops the record. In that order the records at or beneath `P` are those at `P` itself and the run
  from `P` followed by `/` up to, not including, `P` followed by `0`, the byte after `/`. So a tree
  delete `T` of `P` covers some held record exactly when, for some entry `(d, c)` of its vector, the
  least counter of device `d`'s records in those two runs is at most `c`. That is the definition of
  coverage beneath a tree delete, not an approximation: `T` covers `U` when `U`'s path is at or
  beneath `P` and `T.vector[U.device_id] ≥ U.counter`; a device absent from the vector counts 0 and
  no counter is below 1, so only the vector's entries can qualify, and for each the least counter
  decides. An earlier tree delete at or beneath `P` is in the index under its own dot, so nested
  deletes are judged by the same rule; and what an earlier tree delete covers is no longer held and
  so not in the index, as "replaces nothing held" requires. The records `T` covers, which step 6
  drops, are found by descending only into the parts of each run whose least counter is at most `c`.
  Costs, with `n` the records held: judging an arriving tree delete costs at most two queries per
  entry of its vector (at most 32 entries, so at most 64 queries), each `O(L log n)` for paths of at
  most `L` bytes (`L` ≤ 4 096), since each of its `O(log n)` steps compares paths that can share a
  long prefix, plus a lookup per ancestor directory of `P` for a held tree delete above it, `O(L)`
  work for a path of `L` bytes (step 3), and a look at its own tag, whatever lies beneath `P`;
  holding it costs `O(L log n)` more per record it drops, and a record is dropped once; keeping the
  index costs `O(L log n)` per record held or dropped, and one entry per record. A walk over every
  record beneath `P` took 17 to 48 ms per tree delete at 20 000 files, before any signature was
  checked; the index bounds the judgement by the record, not by the directory. Verifying a tree
  delete's signature before a walk, with a memory of those already judged and a budget of walks, was
  weighed and not chosen: it would bound the cost only per connection and window, and make an
  obsolete tree delete the one obsolete record that costs a verification.

**Cleanup.** A **cleanup** is a signed record (`record_type` 17) by which a write holder tells every
peer "forget these records": its fingerprints name records the write holder has found replaced, or
forgotten, and the chunks that only those records named are then freed wherever they were held. It
is how deletions and stale copies reach sealed peers, which cannot judge them, and it takes the
place of the drafts' sealed-peer expiry and `Covered` chains. Its body:

```proto
message CleanupRecord {
  uint32 suite       = 1;   // the folder's suite
  uint32 record_type = 2;   // 17
  bytes  folder_id   = 3;   // 32
  repeated CleanupGroup groups = 4;  // 1 ..= MAX_CLEANUP_GROUPS (1 024)
  bytes  sealed      = 5;   // nonce (24) || XChaCha(rk, nonce, aad = folder_id, padded CleanupMeta); 40 bytes plus 256, 512 or 1 024
}

message CleanupGroup {
  bytes because = 1;        // empty, or 32: the fingerprint of the record that replaces those named
  repeated bytes forget = 2;  // 32 each: fingerprints of the records to forget; 1 ..= MAX_CLEANUP_ENTRIES (16 384) across the record's groups; ascending within a group, no repeats
}

// Inside a cleanup's `sealed`, visible to write and read holders only.
message CleanupMeta {
  bytes  device_id = 1;     // 32: the issuer's device ID, as the signer claims it
  uint64 counter   = 2;     // the issuer's counter, by the writer's rule
}
```

- It is signed with `Sign(folder_sk, "licketysync/v1/sig/cleanup", body)` (`keys.md` §5), so only a
  write holder can issue one, and every tier verifies it. Its fingerprint, `record_hash` over its
  body like any record's, is also its key in the set digests (4.5), where a version's key is its
  path tag. It takes a counter from the writer's rule, so it has a place in the folder's own time.
- **A group applies** while its `because` is empty or names a record the device holds (live, a tree
  delete, or a cleanup), and only then, on every tier. While a group applies, every record it names
  is dropped, at whatever file ID it lies, and a named record that arrives is refused as obsolete
  (step 3). A group whose `because` is not held waits, held with its cleanup, and applies when that
  record comes to be held, so that a sealed peer never forgets a version before it holds what
  replaced it. Once its `because` record is dropped (replaced by a later version, or forgotten), the
  group no longer applies: the records it dropped stay dropped, and one that arrives again is judged
  without it. No device remembers that a group once applied, so what each tier holds and refuses
  depends only on the records it holds, never on the order in which they came (the coordinator's
  ruling of 2026-10-25, for the owner's review: an earlier draft of that day kept an "applied" bit
  per group, with which two devices holding the same records could refuse different ones and still
  end their rounds caught up). The cost: at a sealed peer, a stale copy that a group named can come
  back once the group's `because` has been replaced, offered again by any peer that kept it, and
  stays until a write holder names it again (case (b), below); a read or write holder judges such a
  copy by coverage and expiry, which the group never changed for it ("Why it is safe" 10). The names
  are exact fingerprints, never file IDs: a cleanup replayed at any later time can remove only the
  very records it named, never a later version of the same file.
- **When a write holder issues one.** (a) With every tree delete, in the same commit, `because` the
  tree delete, naming every record at or beneath its directory that it held, kept as a base or kept
  as an archived version ("A path with no heads") and that the tree delete covers; and with every
  write whose shared writer faults do not fit its `replaces`, in the same commit, `because` that
  write, naming the rest. (b) At the end of a round
  with a peer, for the stale copies it has noted (4.5, "Stale copies") that no write of its has
  named yet: each judged again when the cleanup is written, since the record noted with it may have
  been dropped since, and named in a group `because` the held record that replaces it then, a record
  at its file ID that covers it or a tree delete above it that covers it; a note that nothing held
  replaces any more is dropped, unnamed. (c) At the end of a round, for the forgotten records it has
  noted, tombstones, tree deletes and cleanups that a peer offered it after it had forgotten them
  past their horizon: named in a group with `because` empty, so that the peer forgets it too. In (b)
  and (c) it names only records whose signatures it has verified and that no record it holds at
  their file ID names and no cleanup it holds names in any of its groups, whether or not that group
  applies (a rule of the write holder's own, which changes nothing any device holds; the
  coordinator's ruling of 2026-10-25, for the owner's review): so a record is named again only once
  the write holder has forgotten the cleanup that named it, `CLEANUP_HORIZON` of the folder's time
  later, however often its file is written meanwhile, and the cost is that a stale copy offered
  again after its group stopped applying stays at the sealed peer until then. In a folder nobody
  writes to, the folder's time stands still, the cleanup is never forgotten, and such a copy stays
  for good: it costs the sealed peer's storage and nothing else. And it names, of the records one
  peer offered (by the device ID its DeviceProof proved), at most `MAX_PEER_NAMES` (1 048 576) in
  any `CLEANUP_HORIZON` (30 days) as its own wall clock counts, in writes and cleanups together (the
  cap is the coordinator's ruling of 2026-10-25, for the owner's review, and its value the author's:
  enough for a NAS back from a long absence over a folder of a million files, little enough that one
  peer identity costs at most about 36 MB of cleanups a month); past that, the peer's copies wait
  for the next window, with a log line (4.5, "Stale copies"). Read holders cannot sign, so they
  issue none; they hold and relay cleanups like any record. A write holder issues at most one
  cleanup per tree delete, one per write whose faults do not fit, and one per round per connection,
  each paged into as many records as `MAX_CLEANUP_ENTRIES` and `MAX_CLEANUP_GROUPS` require.
- **How it travels.** A cleanup is a record: pushed when held, served in replies and reconciled by
  the set digests like any other, held by read, write and sealed holders alike. A sealed peer that
  missed one gets it from any peer that still holds it. Once the read and write holders have
  forgotten it, a sealed peer that holds, or holds again, a stale copy it named, or records beneath
  a tree delete it named, meets the next write holder as before: the write holder finds those
  records again, and issues a new cleanup.
- **How it is forgotten.** Read and write holders forget a cleanup once the folder's own time passes
  its counter by `CLEANUP_HORIZON` (30 days, expiry below; the coordinator's ruling of 2026-10-25,
  for the owner's review: what a lost cleanup costs is only that a write holder finds the same
  records again). A sealed peer forgets a cleanup only when a later cleanup names it, which happens
  by case (c) when a write holder meets it. So sealed peers always hold the last generation of
  case-(c) cleanups, and case (c) has an ongoing cost, which is bounded: each write holder that
  meets sealed peers issues at most one cleanup per round naming the forgotten cleanups of the
  generation before (a few hundred bytes), never one naming what a cleanup it holds already names,
  so a generation is at most one cleanup per write holder that issued in it, and a new generation
  comes only after the folder's time has moved on by `CLEANUP_HORIZON`, that is after someone has
  written again.
- **A folder of 100 000 files deleted.** The deleting device writes one tree delete (a few hundred
  bytes) and, in the same commit, 7 cleanup records naming the 100 000 fingerprints `because` the
  tree delete, about 3.4 MB in all (34 bytes per name, 16 384 names per record). Every peer receives
  them once, by push or by reconciliation. A sealed peer holds the tree delete, applies the groups,
  drops the 100 000 records and frees every chunk they alone named; a read or write holder has
  already dropped them by the tree delete and only relays the cleanups. Read and write holders keep
  the cleanups for 30 days of the folder's time and the tree delete for 365; a sealed peer keeps
  each until a later cleanup names it.

**Stale copies at a sealed peer, and their bound.** A **stale copy** is a record that a sealed peer
holds and that read and write holders hold replaced: the sealed peer missed the records that named
it. The common case: a sealed NAS offline while a file goes V1 → V2 → V3 holds V1, and receives V3,
which names V2; it keeps V1 and V3. The next write holder to exchange with it finds V1 replaced by
V3 (4.5, "Stale copies") and, once V1's signature has verified, names V1, in its next write of the
file or in the cleanup at the end of the round, `because` V3; the NAS then drops V1. Nothing is lost
meanwhile: V1 is an old version, and V3 is held everywhere.

- Under honest use a sealed peer holds at most one stale copy per run of versions it missed, until a
  write holder meets it; read holders alone cannot clear them. A stale copy spreads to every sealed
  peer that meets one holding it, and comes back to a peer that a cleanup cleared once that
  cleanup's `because` record has been replaced there, or the cleanup itself named away (above, "A
  group applies"), until a write holder names it again, which a write holder that still holds the
  cleanup does only once it has forgotten it (below).
- A hostile holder of the sealed or read key that kept the folder's whole history can replay every
  genuine old version to a sealed peer, which cannot tell them from concurrent versions and keeps
  them all, fetching and storing their chunks: its storage grows by up to the folder's whole past,
  content included. A write holder that meets it verifies each such record once and names it in a
  cleanup, unless a record it holds at the file ID names it or a cleanup it holds names it in any
  group, and names at most `MAX_PEER_NAMES` records a `CLEANUP_HORIZON` for any one peer identity
  (4.5, "Stale copies"). So each old version costs write holders one verification and one name per
  life of the cleanup that names it, `CLEANUP_HORIZON` of the folder's time, however often the file
  is written meanwhile. Without the rule that a name in any group of a held cleanup counts, every
  edit of a file, which replaces the `because` of the groups that named its old versions, would let
  its whole history be replayed and named again (a file edited hourly with 40 000 old versions:
  about 1.4 MB of cleanups an edit, sent to every peer), and every repeated deletion of a directory
  would reopen the generations before it. What an edit still costs is storage: once the group's
  `because` has been replaced at the sealed peer, the same old versions can be replayed to it and
  stay there, fetched and stored, until the write holders forget the cleanup that named them and
  name them again. No per-file bound is set (the coordinator's ruling of 2026-10-25, for the owner's
  review): a sealed peer cannot tell which of its records are stale, so refusing or evicting records
  past a bound could make it drop a live concurrent version that it alone holds, and nothing is ever
  lost this way. The growth has a bound, though not a constant: the folder's history, chunks
  included, once per `CLEANUP_HORIZON` of the folder's time. Every replayed record is a genuine
  signed version, and once a write holder's cleanup names it, the sealed peer refuses it while it
  holds that cleanup and the group's `because`, so the stale copies a sealed peer holds at one time
  never exceed the versions the folder has ever had (TM-22). A holder of any key can use any number
  of device identities, so `MAX_PEER_NAMES` bounds the names one connection costs, and the history
  bounds the total. A sealed peer counts the records it holds beyond one per file ID, its stale
  copies and the folder's real conflicts together, since it cannot tell them apart, and shows the
  count in its Status (`extra_versions`, 4.5), so that its person can see it grow.
- **A replay can also take a version away from a sealed peer, for a while.** A version that came
  back after its deletion was forgotten (expiry, below) is live at read and write holders. Once the
  case-(c) cleanup that named that deletion has itself been named away, a holder that kept the old
  tombstone, or the tree delete and its cleanup, can offer them to a sealed peer again; the sealed
  peer holds them, drops the version they name, and refuses it until a write holder meets it, finds
  the replayed deletion forgotten and names it again (case (c)), after which the next round brings
  the version back. Read and write holders, which judge the replayed deletion by expiry, ignore it,
  so the version is not lost; a sealed peer that only read holders visit lacks it for as long as no
  write holder comes (TM-22).

**Expiry (the folder's own time).** Only read and write holders expire anything, by the owner's
decision of 2026-10-25: "To solve the problem with deletions, use the folder's own time." The
folder's own time on a device is `G`, the greatest counter of any applied record it holds (live
records, tree deletes and cleanups). Bases kept only as bases, records refused by the clock rule and
opaque records (step 7) do not count, whatever counter an opaque record's seal may carry: every
release of major 1 judges a seal by the same checks, and a `kind` added after 1.0 needs a
folder-level requirement first (section 6), so every release that syncs a folder finds the same
records opaque and computes the same `G`. A tombstone or tree delete **expires** once `G` exceeds
its counter by more than `TOMBSTONE_HORIZON` (365 days of microseconds: the **deletion horizon**),
and a cleanup once `G` exceeds its counter by more than `CLEANUP_HORIZON` (30 days). Expiry is
checked whenever `G` rises, in the commit of the record that raised it, at every open, and for a
record that arrives (step 3). An expired record is dropped, with any base that is that deletion (so
that the bases of removed paths do not pile up), and one that arrives is ignored without verifying
it. Live versions never expire. Expiry by the folder's own time is to be replaced by a signed
watermark (the owner's decision of 2026-11-08; a later change).

- `G` depends only on the records a device holds. It does not fall when records are replaced by
  coverage, since only a record with a greater counter covers another, nor by expiry, which never
  reaches the greatest; it falls only when a write holder names the record that set it, or the
  device's own store loses records at rest, and either only delays expiry. So two read or write
  holders that hold the same records have expired the same ones, whatever their clocks: expiry no
  longer depends on any device's clock, and exchanges converge with it (4.5, "Why it converges").
  Cleanups are records with counters and move `G` too, but a write holder issues one only with a
  tree delete or a write whose faults do not fit, or for stale copies and forgotten records that a
  peer offers, so a folder in which nobody writes forgets nothing, since its time stands still. A
  cleanup that a peer's stale copies prompt brings the folder's time up to the issuing write
  holder's clock, as a write would.
- Sealed peers forget a deletion only when a write holder's cleanup names it (case (c) above).
- The deletion horizon is a protocol constant, 365 days on every device (the owner's decision of
  2026-10-25, in place of the plan's "configurable, zero meaning never"): two devices with different
  horizons would disagree for ever about which tombstones exist.
- Counters follow their writers' clocks, so a deletion is forgotten 365 days after it was written,
  as the folder's devices count time. A record whose counter runs ahead, from a clock set ahead,
  moves the folder's time forward by as much, and every deletion older than that time less the
  horizon is forgotten at once, on every device that comes to hold the record. The clock rule
  (above) limits this to a year ahead; within it, files deleted up to that much early come back,
  never lost.
- A device that comes back after a deletion was forgotten may still hold the version it deleted.
  Nothing held replaces that version any more, so it is live again, here and on every peer the
  device exchanges with: the deleted file reappears, as the file or as a conflict copy beside a
  newer version, and is never lost (the owner's decision of 2026-10-25: files reappear after the
  deletion horizon; the plan's rule that a returning device treats them as deleted is not adopted).
- The same holds the other way: a deletion made offline and delivered after the folder's time has
  passed it by the horizon arrives expired and is ignored, and the deleted file, which peers still
  hold, comes back to the device that deleted it. Offline deletions older than the horizon are
  undone.
- A sealed peer that kept a version a deletion replaced can bring it back at will once the
  deletion has been forgotten, by offering it again; a path re-created since then gets the old
  version beside its new one, as a conflict copy, since a version written after the deletion was
  forgotten names nothing of the old path (`threat-model.md` §3.3).

**Heads, display order and conflicts.** Read and write holders compute heads after step 7 of the
verification below.

- A **version** of a path is an applied record (step 7) live at the path's tag. The **heads** of a
  path are its versions. Opaque records (writer faults, step 7) are held, and replaced only by a
  name (above), but they are no versions and never bases. Where live records are listed or ordered
  together (the views, 4.7), opaque ones come after every head, by ascending record hash (decision:
  a reader can compare nothing else of them).
- **A path with no heads**: one whose versions a tree delete took, the tree delete's own directory,
  or a path all of whose live records are opaque (the owner's decision of 2026-11-03: "Yes, remove
  the old copy"). Its one base is at the path itself: the greatest, by record hash, of the tree
  deletes held at its tag, or none; it has no conflict copies. That is a function of the records
  held, so every device on one release that holds the same records keeps the same disk there, in
  whatever order they came (a release that reads a record this one cannot shows its version). So a
  device that held a version at the path, and then a record it cannot read that replaces it (a
  newer release's version, which names the version it was written over, or a shared writer fault
  whose writer named it), takes its outdated copy off its disk, with each conflict copy of it that
  has not become a version at its own path (one still a base of the path, "Bases"), to the archive
  (TM-35, phase 1), rather than show a version that every holder of those records has replaced. A
  twin that the record does not name is still a live head, and so is a head of a conflict that it
  does not name: then the path has heads and keeps its file. The file comes back when the device
  can read the record (a release that knows its `kind`), or when someone writes the path again.
  Directories that applied live records beneath the path need stay, as beneath a tree delete (4.7
  item 6); a record this release cannot read is put on no disk and keeps no directory, so a
  directory that the person deleted, or that such a record replaced, stays off the disk (the spec
  author's choice, for the owner's review).
- **What a device remembers of a path whose heads it lost** (the owner's decision of 2026-11-10,
  "Also what was archived"). When the engine moves those copies to the archive, the index keeps each
  base it had at the path, the version at the path and the version of each conflict copy moved, as
  an **archived version** of the path, in the slot that base held ("Bases"): its signed envelope,
  dot and vector, as a base is kept (local state, never held, served, counted in a digest or pushed;
  persisted with the index store and checked again when the folder opens, "Opening a folder"). This
  device's next write at the path covers them: they join `S`, after the bases and twins ("The vector
  and names of a new record"), so the write's vector covers them and its `replaces` names them, and
  a tree delete it writes at or above the path takes them too. The device had them on its disk, so
  "Why it is safe" 9 holds, and the write names nothing it does not cover (10). An archived version
  is dropped once a write of this device covers it; once an applied record held at the path covers
  or names it (someone saved over it with it in view, or this release came to read the record that
  took the path's heads), or an applied tree delete held at or above it covers it; or once the same
  record is held here again or becomes a base again. A head that does not cover it, a concurrent
  edit made elsewhere say, leaves it in place. When each is dropped is the spec author's choice, for
  the owner's review; it replaces an earlier choice that also dropped one once the folder's time had
  passed its archiving by `TOMBSTONE_HORIZON`, which, since the confirm review of 2026-11-10 tied
  the keep of its copy to its being covered (below), would have left that copy kept after the save
  meant to end the keep. Archived versions stay beside the base their slot takes later, so a second
  loss of the path's heads adds the versions then on the disk beside the earlier ones: their number
  at a path is bounded by the records this release cannot read that write holders sign
  (`threat-model.md` §3.6). So a device that missed the unreadable record and kept the old version,
  a sealed peer among them, meets that write and drops the old version as replaced, rather than
  bring it back beside the write. The remaining residual, by design: a version this device never
  had, an edit made elsewhere while it was off say, is no archived version of it, and stays a head
  beside the write, a conflict copy, as any version a write was not made from does ("Why it is safe"
  9).
- **The archived copies and the warning** (the owner's decision of 2026-11-10: "Until fixed. Warning
  notification. On desktops with a gui, a status bar indication and a system message. 30 days should
  be configurable."). The copies the engine moves to the archive because a path's records became
  unreadable are kept past the archive's retention (a setting, 30 days by default, TM-35), and on a
  device whose versioning is off too, each until the fault is fixed for it: until a record this
  release reads, held here, covers or names its version (this device's own next save at the path,
  which covers it as an archived version; a save made elsewhere over it; the record that took it,
  once a release here reads it), until that version is a base here again, its content back on the
  disk, or, for a copy whose archived version failed its check at open ("Opening a folder"), until
  this device next saves at the path. That the fault is fixed for a copy only so, and not by just
  any head, is the coordinator's ruling on the confirm review of 2026-11-10; that a tree delete held
  at or above the path that covers the version ends the keep too is the spec author's reading, for
  the owner's review. A head that does not cover the version, a concurrent edit made elsewhere say,
  goes on the disk and leaves the copy and the warning in place; a device that still holds that
  version as a head shows the two as a conflict, as usual, and this device's next save there covers
  both. Once the keep ends, the
  copy is kept as any file the archive takes at that moment, for its retention, or not at all with
  versioning off (the spec author's choice, for the owner's review). While a copy is kept so, the
  engine raises a **warning** issue for the path (how a warning shows is the plan's: on a desktop
  with a graphical interface, a status-bar indication and a system notification) that names the
  records this release cannot read held at the path and says what this device can and cannot do:
  that its copy is in the archive, kept until a save covers it; on a write holder, that saving a
  file at the path again clears the shared writer faults, since every write there names them ("Its
  names"), and ends the keep of each copy the save covers, which then goes as the archive's
  retention says, at once with versioning off, so that whatever the person wants of the old file is
  to be restored from the archive before that save; on a read holder, that this device cannot save,
  since it holds the read key, and that a device with the write key must save the file again; and,
  for a record opaque only for its `kind`, that this release cannot read it, which a newer release
  may (updating then shows it) or no release may (a faulty record), and that saving the file again
  on a device with the write key puts beside it a version this release reads (phase 1). Once no
  record this release cannot read is held at the path, as after a save made elsewhere that names the
  fault without covering the version, the warning names none and says that the copy in the archive
  is a version that the file now at the path was not made from, kept until a save covers it, so
  restore first (the re-confirm review of 2026-11-10).
- The stated residuals of a path with no heads: (i) the archived copy is the only copy, on each
  device that had the version on its disk: sealed peers drop the version, and free its chunks, once
  the record that names it arrives, and nothing else keeps it; it stays in the archive until a save
  covers it (above), and goes only if its person removes it by hand or the device is lost. (ii) A
  record of a `kind` that no release knows looks here like a newer release's version: it takes the
  file off the disk of every device that held the version it names, until someone saves the file
  again, and stays for good, shown as an update this release cannot read, beside any later version;
  the issue says it may be either. (iii) A read holder cannot clear a fault: its copy stays in its
  archive until a device with the write key saves over that version, which one that had it on its
  disk does with its next save there, and for good if none does. And a
  shared writer fault at a file ID that nobody writes again, and a cleanup that is itself a writer
  fault, stay on every tier.
- One head is the path's current version; a tombstone head means the path is deleted. Two or more
  heads are a **conflict**, and every head is kept until a write covers them; a write covers every
  head whose content is on its writer's disk, at the path, as a conflict copy, or as a twin of
  either ("Bases"), up to 32, so writing the path resolves its conflict, and contents are never
  merged.
  The **display order** of a path's heads is: heads that are not tombstones first, and among those
  directories before files (decision: a directory's children need it at the path); tombstones last,
  whose kind is not compared; then, within each of these groups, the greater `mtime_ns` first; then
  the smaller `record_hash` first (decision: so tombstones too have one order). The first head in
  display order sits at the path; when every head is a tombstone, the path is deleted. Every other
  head that is not a tombstone and whose content differs from the first becomes a conflict copy
  (TM-40): the engine puts its content on disk beside the path, under a name of its own (phase 1),
  and that content is then one of the path's bases. Content differs when the kinds
  differ or, between two files, when their `plain_hashes` lists differ; two directories never
  differ, and nor do two files with the same `plain_hashes`, whatever their times or modes. So: one
  file and one tombstone show the file and make no copy (an edit beats a delete); a file and a
  directory show the directory and make the file a conflict copy; two files with different content
  show the one first in display order and copy the other; two identical files or two directories
  show the first and copy nothing, twins that the next write covers together.
- **What becomes of a conflict copy.** Until some device writes the path, a copy is the index's
  second head, which every device shows the same way. The device that writes the path over a
  conflict, holding the heads on its disk, first writes each conflict copy it has on disk as a
  version at the copy's own path (the same chunks, `S` empty), in the same commit: from then on the
  copy is an ordinary live file, synced like any other and kept until a person deletes it, and the
  path's own heads are covered. Contents are never merged (the owner's decision), so every overlap
  of two concurrent edits leaves one such file, and the index grows with these live files, one
  record each, never with history.
- So a device restored from an old backup, which still holds an old head, makes its next edit cover
  that old head and not the later versions it never held: every peer that holds the later versions
  then holds two heads, a conflict, and nothing is lost silently.
- Sealed peers compute no heads, since they cannot read paths, vectors or deletion marks; they hold
  records by the sealed-peer rule, which is all they need to store, serve and garbage-collect: a
  chunk that no held record names is freed (4.6).

**Why it is safe.** These are the proofs that the rules above keep their promises; the index crate's
property tests check each (section 8, item 7). Items 1 to 9 are about read and write holders, which
judge by vectors; items 10 to 13 about names, cleanups and sealed peers. A record `R` **knows** a
record `U` when `R`'s writer, as it wrote `R`, held `U`, kept it as a base, or held a record that
knew `U` (at any time before, so records since dropped count). Two assumptions, which honest devices
meet and whose failures are stated at the end: **A1**, each device ID is used by one device, which
writes one record at a time; **A2**, a device's high-water mark never falls below a counter it has
used, or held as an applied record. Under A1 and A2 a dot names one record, and a device's records
are ordered by their counters. Write holders are trusted to build vectors by the rules above
(`threat-model.md` §3.6); one that does not can make its records cover anything, which a write
holder can do anyway by writing over it.

1. *A record's counter is above that of every record it knows.* If `R` knows `U`, `R`'s writer held
   `U` or a record `W` that knows `U`, so its `hw` was at least `U.counter`, or at least
   `W.counter`, which by induction along the finite chain of records is above `U.counter`; and
   `R.counter > hw`. This needs the writer's rule and A2, since a high-water mark that fell could
   forget what its device knew.
2. *Every entry of a vector names a record that the vector's record knows.* Each entry `(e, c)` of a
   version or tombstone's vector is the dot of a record that `e` wrote at the same tag and that the
   record knows; for a tree delete, at or beneath its tag. By induction on writes: the entries come
   from the dots of the records in `S`, or in a tree delete's join (bases, which the writer kept,
   and their twins, which it held), and from their vectors, whose entries name records they knew; a
   join keeps one of the counters it compares, and pruning only removes.
3. *Coverage means "after".* If `V` covers `U`, then `V` knows `U`, or `V` knows a record that `U`'s
   device wrote after `U`: at `U`'s tag, or, for a tree delete `V`, at or beneath its tag. For
   `V.vector[U.device_id] = c ≥ U.counter` names, by 2, a record `U'` of `U`'s device that `V`
   knows; if `c = U.counter`, `U'` is `U` (A1, A2); otherwise `U'` came after `U` on its device (A1,
   the writer's rule). For a version, `U'` was written by `U`'s own device at `U`'s path after `U`,
   from its bases there and their twins, which put the bases first and its own records first among
   them: so `U` was in that `S`, or had been replaced there by an applied version that `U'`'s `S`
   held, through a chain of records each covering the one before, or deleted there. `V` replacing
   `U` follows the path's own history.
4. *An older version never replaces a newer one.* If `V` knows `U`, then `U` does not cover `V`: `U`
   covering `V` needs `V.counter ≤ U.vector[V.device_id] < U.counter`, and `V` knowing `U` needs
   `U.counter < V.counter` (1). This looks at no entry but dots, so it holds however much either
   vector was pruned; it needs A2, through 1, and not A1.
5. *Pruning costs spurious conflicts only.* Pruning takes entries out and never adds or raises one,
   so a pruned vector covers a subset of what the full join covers, and every record dropped with
   pruning is dropped without it. What pruning can do is leave a record live that the full join
   would have dropped: an older version `U`, still held by some device, beside a newer `V` that its
   device receives. Both are kept as heads, a conflict, ordered by the display order, and the one
   not at the path becomes a conflict copy if their contents differ; nothing is replaced. It never
   happens between a version and the one written from it, whose dot is mandatory. It needs more than
   32 entries with counters above `U`'s to have entered the line of versions between `U` and `V`,
   while a device held `U` and none of the versions between: more than 32 devices writing that path,
   or fewer devices together with concurrent heads whose mandatory entries filled the 32 places.
6. *Nothing is lost silently.* At a read or write holder a version is dropped only by a held record
   that covers it (step 6), by a held tree delete that covers it (steps 6 and 8), or by a name
   (10); expiry drops tombstones, tree deletes and cleanups only, and a base kept only as a base is
   dropped only when the engine names a newer one, which drops nothing live. By 3 the record that
   drops a version came after it, from a writer that knew it or a later record of the same device on
   that path or beneath that directory. So every version that disappears was replaced or deleted by
   a later record that a write holder signed, and the engine moves the file replaced or deleted to
   the archive (TM-35).
7. *An edit beats a delete, and a pruned tree delete costs spurious survival only.* If, when a tree
   delete `D` was written, its writer knew neither a version `U` beneath `D`'s directory nor any
   later record of `U`'s device at or beneath it, `D` does not cover `U` (3): `U` stays live.
   Pruning removes entries from `D`'s vector, so a pruned `D` covers a subset of what the full join
   covers, and can only leave live a version the full join would have deleted: the deleted file
   reappears, as in expiry, and is never lost. The same holds when `D` covers a tombstone or an
   earlier tree delete beneath it without covering everything those covered: a file deleted earlier
   that a stale peer still holds can come back, and nothing is deleted that `D`'s join did not
   reach.
8. *Stated residuals.* (a) By 3's second case, a tree delete also covers a version beneath its
   directory that its writer never held, held but had not yet on its disk, or held but could not
   read (a newer release's version, judged at a release that reads it), when its join reached
   a later record that the version's device wrote at or beneath that directory, as the dot of a
   base or twin there or through one's vector: the version's device wrote it, then wrote something
   else in the same tree, and only the second reached the deleter's disk before the delete. The
   commonest case is a rename within the directory: a version at `P/b` and then a tombstone at
   `P/a`, of which the deleter received only the tombstone, so that deleting `P` also deletes `P/b`,
   which it never saw. Another is a folder linked on two devices, deleted on one while a file only
   the other had is still arriving there, when a file the other wrote after it beneath the folder
   holds what one of the deleter's holds, a twin or the base there (the owner's decision of
   2026-11-08: a folder delete takes what is inside it, a file still on its way included). Arrival
   order makes it, so a sealed peer that withholds the version, or a reconciliation that happens to
   deliver the tombstone's subtree first, can bring it about (`threat-model.md` §3.3). That version
   was written before the delete in the order the folder's devices saw events (Lamport 1978); it is
   deleted, and the engine moves it to the archive wherever it was on a disk. A tombstone per file
   would spare it; it is the price of one record per tree, and a folder-wide vector would widen it
   to the whole folder ("The vector and names of a new record"). (b) A1 fails when two devices write
   under one device ID: a cloned disk image that carries the device seed, or a write holder that
   writes under another's ID. Records with one dot stay concurrent, but a record can cover a
   concurrent record of the other device at the same path when its vector gives their shared ID a
   counter at least the other's: one that either clone wrote over its own earlier record of that
   path at such a counter, or one a third device wrote from such a record. The covered record is
   replaced, and its file goes to the archive. (c) A2 fails when a device's index store is restored,
   rebuilt or lost and its clock reads earlier than its last write before: its next records may take
   counters below ones it had used. Any record that carries one of those earlier counters for this
   device then covers a new record of its at the same path: another device's later version as much
   as its own, so a single write of that path after the backup suffices, and a tree delete whose
   vector carries such a counter deletes the new record beneath its directory. The new record is
   replaced as by a later edit, and its file goes to the archive. Once the device holds any record
   carrying its later counters, which index sync brings at once, its high-water mark is past them
   and the residual is closed. The clock rule's remedy is a case of it ("The clock rule", "What
   adding the folder again leaves"), where the later counters can return only once real time has
   come within a year of them.
9. *A local write never replaces a version whose content its device has not had on its disk,
   short of 8a for a tree delete.* `S`, and a tree delete's join, are built from bases, their twins
   and archived versions alone (above), and a twin's content is its base's: the display order showed
   the two as one file, and the person changed or deleted what they saw. An archived version's
   content was on the disk until records this release cannot read took the path's heads, and it is
   in the archive since ("A path with no heads"). A twin is concurrent with its base, never
   the first head at its path and, at the path, comes after its base, so neither a later version of
   the base still arriving, whatever its content, nor a version the engine has yet to put at the
   path is one. A held version `V` outside them is covered by the write only through an entry that
   some record `B` in them brings: `B`
   covers `V`, or `B` is a later record of `V`'s own device at that path; either way, by 3, the disk
   held the content of a version that came after `V` (for an archived version, until the path lost
   its heads). For a tree delete, `B` can also be a
   later record of `V`'s device at another path beneath its directory, and then `V` goes though its
   content never reached the disk: the residual of 8a. Its names are the fingerprints of `S` (for a
   tree delete, of records at its own path that its vector covers) and of stale copies the new
   vector covers, so they add nothing. So a version that arrived but whose content had not reached
   the disk when the person changed or deleted the file stays live beside the write: a conflict, or,
   against a delete, a file that comes back. The old file stays on disk until the new content is in
   place (4.7), so the base and the disk agree. This needs A1 and A2, as 3 does: two records under
   one dot are covered together by a write made from either (13), so a write made from the one on
   the disk also replaces the other, which never reached it. A record this release cannot read
   covers nothing here, whoever wrote it, this device included (under a newer release, before a
   downgrade); it drops a version only by a name, which a write holder gives only to a record whose
   signature it has verified (10). A path then has no heads only when no live version is left there,
   twins and the other heads of a conflict included (one that the record does not name is a head, so
   the path has heads and keeps its file), so
   what leaves the disk, to the archive ("A path with no heads"), is a copy whose version, and
   every live version beside it, a signed name has replaced; and this device's next write there
   covers that version as an archived version, one it had on its disk.
10. *A name says no more than coverage.* A write holder names only records whose signatures it has
    verified: in `replaces`, the bases, twins and archived versions its write covers (a tree
    delete's at its own path among them, their devices mandatory in its prune) and stale copies its
    new vector covers; in a cleanup, records that a held record at their file ID covers or a held
    tree delete covers (`because` that record), or tombstones, tree deletes and cleanups that the
    folder's time has passed by their horizon (`because` empty). A group applies only while its
    `because` record is held, or is empty, and then every applied record it names is covered by that
    `because` record, or has expired at every device that holds the cleanup, since the cleanup's own
    counter lies above its issuer's folder time (the writer's rule) and so lifts the folder's time
    past the named record's horizon wherever the cleanup is held. So at read and write holders a
    name or a cleanup drops no applied record that coverage or expiry would not drop at the same
    moment, and by 3 every record named was written before the record that names or explains it. An
    opaque record, which nothing covers, goes only by a name. The one name that coverage does not
    explain is that of a shared writer fault, which every write at its path names ("Its names"):
    every release judges it a fault and none applies it, so the name drops nothing any device shows
    as a version; and a record opaque only for its `kind` is never named this way ("A newer
    release's version"). The names that a record this release cannot read gives are judged by the
    release that can: a newer release's version names what its write covers there, by these same
    rules, and a writer fault's names are its signer's doing, as below; here such a name drops the
    version it names all the same (step 6), which then leaves the disk if no head is left ("A path
    with no heads"). Only a dishonest write holder can name more, which it could do as well by
    writing over the file (`threat-model.md` §3.6).
11. *A sealed peer loses nothing silently.* It drops a record only when a record it holds at that
    file ID names it, or a cleanup it holds names it in a group whose `because` it holds or is
    empty. In the first two cases it holds what replaced the dropped record, and by 10 that is a
    later version, or a deletion, of the same file; in the third, the dropped record is a deletion
    or a cleanup that the folder's time has passed. It drops no version that no signed record or
    cleanup names, keeps concurrent versions and stale copies alike, and never decides anything a
    seal holds. Since no group acts once its `because` record is gone, what it holds and refuses is
    a function of the records it holds. The one drop that read and write holders would not make at
    the same moment is a version that came back after its deletion was forgotten, taken away again
    by a replay of that genuine deletion; the read and write holders still hold it, and the next
    write holder to meet the sealed peer names the replayed deletion, after which the version
    returns ("Stale copies at a sealed peer").
12. *A replayed cleanup removes no later version.* A cleanup names exact fingerprints. A later
    version of a file has a fingerprint of its own, so no cleanup issued before it was written can
    name it, however often or late it is replayed; a replayed record that a held cleanup names, in a
    group that applies, is refused as obsolete, which is what the cleanup meant. What a replay can
    do at a sealed peer is remove again a version that came back after its deletion was forgotten,
    until a write holder names the replayed deletion (11); read and write holders, which judge a
    replayed deletion by expiry, ignore it.
13. *Equivocation is a conflict, and reconciliation finds it.* Two different records with one dot,
    from a write holder signing twice under one device ID or from two devices that share one, are
    two records with two fingerprints. Read and write holders hold both, since neither covers the
    other (no record covers its own dot): a conflict, ordered by the display order, whose heads a
    later write covers; two identical contents make no copy. A write made from either covers both,
    since coverage reads only the dot, so the conflict lasts until the next write of the path, and a
    device that had applied only one of them replaces the other with its next write, unseen (the A1
    failure of 8b). A sealed peer holds both, since neither names the other. Two devices that each
    hold one of them have different set digests over the subtree of that file ID (4.5), so
    reconciliation finds the difference and gives each the record it lacks: no two devices believe
    they agree while they hold different records, the property per-writer sequence numbers and
    version vectors alone lack (Kleppmann 2022). The index keeps both until a write covers both.

- **Signature**: `Sign(folder_sk, "licketysync/v1/sig/index", body)` for an index record and
  `Sign(folder_sk, "licketysync/v1/sig/cleanup", body)` for a cleanup (`keys.md` §0.2), by any write
  holder; every peer verifies with `folder_vk`.
- **Device ID**: `device_id`, inside the seal, is the signer's claim, attested by the folder key's
  signature and by nothing else; a write holder may write under any device ID it likes. Device IDs
  are proven only at the handshake (3.4); in a record the ID is the key of a counter, used to order
  versions, and is never shown as the record's author (ruling S-4).
- **Chunk references** appear twice on purpose: `cipher_hash` in the clear, so that a sealed peer
  can fetch, verify and deduplicate by it, and `plain_hash` under the seal, so that only key holders
  can tell which plaintext a chunk is. A key holder maps between them by computing both when it
  writes (encryption is deterministic) and by decrypting when it reads; a sealed peer never can.
- **What a sealed peer sees** (the owner's decision of 2026-10-25, "sealed peers see almost
  nothing", stated here in full; `threat-model.md` §5, TM-15; a relay sees no record, only what
  `threat-model.md` §5 lists for it): of a record, its file ID, so that it
  can group the versions of a file and count how often each file changes; the fingerprints it names,
  which show where a file's history forked into concurrent versions and joined again; its chunk IDs
  with their padded sizes, so that it can tell which chunks are identical across files and versions
  (and so a copy or a rename, a new file ID with the chunks of a file just deleted) and the
  approximate size of each version, and, from the sequence of chunk sizes, something of where a
  known file's chunk boundaries fall, which keying the chunker hides only in part (`keys.md` §3.2);
  that a record with no chunks is a deletion, a tree delete, a directory or an empty file, without
  telling which; the size class of the sealed part, a power of two from 256 bytes, which grows with
  the path's length, the number of chunks and the number of devices in the vector, coarsely; and of
  a cleanup, which records went together, at a deletion or a cleanup, and, from a group with an
  empty `because` (case (c)), which names only records a write holder has forgotten past their
  horizon, that the index records it names were deletions, tombstones or tree deletes more than a
  year old in the folder's time, and, since a group's `because` whose named records lie at other
  file IDs can only be a tree delete, which records are tree deletes (the coordinator's ruling of
  2026-10-26, for the owner's review). Of the exchange: when each record arrives and from which
  peer, which usually shows which device wrote it, since a new record reaches a sealed peer first
  from its writer or from a peer close to it; and everything a relay sees. It does not see a path, a
  directory's contents, a kind, a true size, a time, a mode, plaintext hashes, `written_at`, a
  device ID inside a record, a counter, a vector, or whether a record is a tombstone, short of the
  old deletions a cleanup group with an empty `because` names and the tree deletes that cleanup
  groups are issued `because` of.
- **What a read or write holder sees**, besides contents and names: every record's dot, so which
  device ID wrote each version and, from the counter, when to the microsecond, offline edits
  included; its vector, so which devices wrote the path before; deletion marks and tree deletes; and
  the exact sizes, times and modes. The microsecond times are the owner's decision of 2026-10-25
  ("Make sure this is documented - do not hide this detail"; the reason: "I can work on files in
  multiple locations nearly simultaneously and the per-minute version resolution is not accurate
  enough"; "The writer's rule").
- **Bounds** that make the largest record fit `MIN_MESSAGE_SIZE`: 32 768 chunks per record and 4 MiB
  per chunk, so a file in major 1 is at most 128 GiB, and in practice 32 768 times the engine's
  average chunk size, since FastCDC rarely produces maximal chunks; larger files are refused with an
  issue (continuation records are a phase 7 addition). At most `MAX_VECTOR_ENTRIES` (32) vector
  entries of at most 46 encoded bytes each (1 472 bytes), and counters at most `MAX_COUNTER` (2^62),
  so that no arithmetic on counters can overflow. At most `MAX_REPLACES` (64) names per record, and
  `MAX_CLEANUP_ENTRIES` (16 384) per cleanup record in at most `MAX_CLEANUP_GROUPS` (1 024) groups,
  so that the largest cleanup is about 600 KB. An empty file has `size = 0`, `kind = 1`, no chunks
  and `deleted = false`.

Verification of an index record or cleanup, in order. Sealed peers take steps 1, 2, 3, 5 and 6; read
and write holders take every step. The action on each failure is the one section 5's table gives for
its cause; the causes are named here in **bold**.

1. **Parse** the body; the encoded `SignedRecord` is at most `MAX_INDEX_RECORD_BYTES` (4 000 000)
   bytes; `suite` is the folder's suite; `record_type` is 16 or 17; `folder_id` is the open folder;
   sizes and bounds above, every fixed-size field present at its exact size. For an index record:
   `path_tag` 32 bytes; at most `MAX_REPLACES` names in `replaces`, ascending with no repeats, each
   32 bytes; `sealed` 40 bytes plus a power of two from 256 to 2^21; each chunk's `cipher_hash` 32
   bytes and `stored_len` in range and a Padmé length plus 40. For a cleanup: 1 to
   `MAX_CLEANUP_GROUPS` groups, each `because` empty or 32 bytes, 1 to `MAX_CLEANUP_ENTRIES` names
   in all, ascending within each group with no repeats, each 32 bytes; `sealed` 40 bytes plus 256,
   512 or 1 024. The `SignedRecord`'s `signature` 64 bytes. Failure: **malformed**.
2. **Duplicate**: compute `record_hash`. A record with this hash is already held for the folder: a
   **duplicate**; ignore it without verifying its signature, since it is the record held, whatever
   its signature bytes say (ruling DUP).
3. **Obsolete or expired**, judged on what the device already holds: a record that a record held at
   its file ID names, or that a held cleanup names in a group that applies, and that itself replaces
   nothing held, is **obsolete**; ignore it without verifying it, since holding it would change
   nothing. Read and write holders open the seal here, before the signature, and run on it every
   check of step 7, charging no one yet. When it passes them they add: a record that a record held
   at its tag covers, or that lies beneath a held tree delete that covers it (a lookup per ancestor
   directory of its path: the ancestor tags of a path of `L` bytes are computed in one pass over it,
   with one keyed BLAKE3 hasher under `tk` finalized before each `/` is fed in (finalizing does not
   consume the hasher; `keys.md` §3.5), or the held tree deletes are kept in a trie by path, so the
   lookup costs `O(L)` work, stopping at the first ancestor whose held tree delete covers the
   record; the coordinator's ruling of 2026-10-26, for the owner's review), and that replaces
   nothing held (for a tree delete, judged with the index of "Judging a tree delete without a walk",
   never by a walk), is obsolete too; and a tombstone, tree delete or cleanup whose counter the
   folder's own time has passed by its horizon is **expired**, ignored without verifying it. A seal
   that will not open or fails a check is judged at step 7, after the signature, and its record
   covers nothing and is covered by nothing (Coverage, above), so no record is obsolete here by
   coverage on one device and held opaque on another. A write holder that would note an obsolete or
   expired record from a peer as a stale copy or a forgotten record (4.5, "Stale copies": no note of
   it exists, no record or cleanup it holds names it, the peer is within `MAX_PEER_NAMES` and the
   connection within its `MAX_NOTE_VERIFICATIONS`) verifies its signature first and notes it only if
   it verifies; a forged one closes the connection as step 5 says.
4. **The clock rule** (read and write holders, on a seal that passed step 3's checks): a record
   whose counter is more than `CLOCK_RULE_LIMIT` ahead of this device's clock is **from the
   future**: verify its signature, and, if it verifies, neither hold nor relay it, and raise the
   clock-rule issue, "a record dated more than a year ahead of this device's clock", naming the
   device ID the record claims only as where it came from; a forged one closes the connection as
   step 5 says. A device remembers, per folder per connection, the record hashes of the last
   `MAX_FUTURE_KNOWN` (1 024) records it refused so, and ignores one of them that arrives again on
   that connection without verifying it.
5. **Signature**: `Verify(folder_vk, label, body, signature)`, with the label of its record type;
   failure: **forged**. Nothing below may be charged to anyone unless the folder key signed it, and
   every signature a peer verifies stores a record it did not hold, drops a record it held, refuses
   a record from the future with an issue (step 4), notes a stale copy or forgotten record that a
   write holder will name (step 3), or closes the connection (TM-22), short of a **store failure**,
   when this device's own index store cannot take the change and the folder pauses (section 5). (The
   check of this device's own store when a folder opens, below, verifies records already stored, one
   verification each. No peer can make it run directly, but a write holder that floods the folder
   with records makes every later open longer by one verification per record held, the cost class of
   `threat-model.md` §3.6; and a peer that fills this device's disk until a store failure makes the
   resume of a store that cannot stage atomically run it, once per failure (the coordinator's ruling
   of 2026-10-26, for the owner's review). Resuming after a store failure reopens the index only for
   a store that cannot stage atomically (4.7 item 1), whose failed commit may have left part of a
   change written, which the open repairs; an atomic store left nothing of the failed change and
   resumes without the check (the coordinator's ruling of 2026-10-26, for the owner's review).)
6. **Store**: drop every record held at the record's file ID that it names, and, for a cleanup,
   every held record named in a group that applies; read and write holders also drop every live
   record at its tag that it covers, and, for a tree delete, every live record beneath it that it
   covers. Then hold the record, unless something held replaces it (it replaced something, or step 3
   would have ignored it). Once it is held, every held cleanup group whose `because` it is applies,
   and drops what it names. An applied record (step 3 has judged its seal) that raises this device's
   high-water mark raises it, and one whose device ID is this device's own and whose counter is
   above the high-water mark (`counter > hw`) raises the informational issue of 4.5 ("Durability
   before transmission"); one whose counter is more than `CLOCK_AHEAD_WARNING` ahead of this
   device's clock raises the issue of "A fast clock carries forward" (above). An opaque record moves
   neither the high-water mark nor the folder's time.
7. **Seal** (read and write holders): open `sealed` (`keys.md` §3.4). A seal that will not open,
   non-zero padding, a sealed part longer than the least power of two of at least 256 bytes that
   holds its metadata (`keys.md` §3.4: so that every release judges padding alike), metadata that
   does not parse, a path outside the grammar above (a name that is merely invalid on some platform
   is the path resolver's concern, TM-4, not a writer fault), a path whose tag is not `path_tag`, a
   `device_id` that is not 32 bytes, a counter of 0 or above `MAX_COUNTER`, a vector of more than 32
   entries, not ascending, with a device twice or with a counter that is not below the record's,
   `tree` without `deleted`, `deleted` with chunks, a tree delete whose `kind` is not 2 or whose
   `size` is not 0, a `kind` this release does not know, a directory (`kind` 2) with chunks, a file
   (`kind` 1) that is not a tombstone with `size > 0` and no chunks, or a `plain_hashes` count
   different from `chunks` is the signer's doing, since the body already verified under the folder
   key: **writer fault**; the record is held **opaque** (held, counted, served, replaced only by a
   name, covering nothing, and applied by no one; the next write at its path names it, unless its
   only fault is a `kind` this release does not know, "Its names"), and an issue names the record by
   its hash, never a device (ruling S-4), and, unless its only fault is an unknown `kind`, says that
   saving the file again on a device with the write key clears it (on a read holder, that this
   device cannot; "A path with no heads" gives the warning for a path left with no heads).
   Otherwise the record is **applied**. NFC is the writer's duty
   only: readers check the rest of the path grammar and not normalisation, so no difference between
   releases' Unicode tables can split peers. The stated residual: a write holder can write a name
   that is not NFC, which is then a path distinct from its NFC form, with a tag of its own (a
   trusted writer's doing, `threat-model.md` §3.6); where a file system treats the two as one name,
   the path resolver handles them as any collision (TM-4).
8. **Beneath** (read and write holders): if a held tree delete covers an applied record by its path,
   drop it, as step 6 would have (step 3 has already ignored such a record when it replaced nothing
   held); a write holder that dropped it because a peer offered it notes it as a stale copy (4.5,
   "Stale copies"), its signature verified at step 5. A record still held after this step gets the
   next local sequence number and is pushed (4.5); a record dropped here gets neither, and its
   change commits as one with the rest of step 6's.
9. **Heads**: read and write holders bring the heads of the record's path up to date, and, for a
   tree delete or a cleanup, of every path whose records it dropped.

**Nothing moves backwards.** A device drops a record only as steps 6 and 8 say, by a held record,
tree delete or cleanup that the folder key signed, or, at a read or write holder, when the folder's
own time passes a tombstone, tree delete or cleanup by its horizon; nothing a peer says without such
a record drops anything. A stale snapshot from a sealed peer offers versions that what a
read or write holder holds covers: they are obsolete (step 3), and a peer that offers them is simply
behind. A sealed peer that receives a stale snapshot keeps the stale copies until a write holder
names them, and loses nothing it held, short of a version that came back after its deletion was
forgotten, which a replayed copy of that deletion takes away until a write holder meets it ("Stale
copies at a sealed peer"). Each device persists its records, so a stale snapshot can
never be mistaken for the present; a device that holds nothing for a path accepts what it is first
shown (TM-17). The one way a device loses records otherwise is its own store losing or corrupting
them at rest (below); nothing a peer sends causes it, and index sync fetches them again (4.5).

**Opening a folder** (the owner's decision of 2026-10-25). This device's own index store is trusted
to keep the records written to it, not for their authenticity (`threat-model.md` TM-9). When a
folder opens, every record its store returns gets the checks a record from a peer gets before it is
held: step 1 against the folder, its `folder_id` included, and step 5, its signature under the
folder's verification key, at every tier, a sealed holder's included; the signatures are verified
across the processor's cores, and the result does not depend on how many.

- A record that fails (corrupted or edited at rest, or not this folder's) is **dropped**: nothing of
  it is applied, held, counted in a digest, or served, and the open reports it by record hash (of
  the body as stored). A failing copy beside a copy of the same record hash that passes is dropped
  without a report, since the record itself is there.
- The records that pass are held again as steps 6 to 9 would hold them, in their stored local
  sequence order, with their stored local sequence numbers: the live sets, tree deletes, cleanups
  and their waiting groups, heads and set digests are rebuilt from them, exactly as the same records
  accepted from peers would give. A record that another stored record replaces (a crash between
  holding a record and dropping what it replaces) is dropped as step 6 says, and, at a read or write
  holder, an expired record as expiry says, both without a report; the clock rule judges records on
  arrival only (step 4), so a stored record is held whatever its counter and this device's clock
  now: nothing is removed for it, and the high-water mark never falls. Bases kept only as bases, and
  archived versions ("A path with no heads"), get
  the same two checks as records and are dropped and reported alike; a path that loses its base has
  none until the engine applies a version there again, so that its next local write covers nothing
  and makes a conflict rather than a guess, and an archived version that fails is one that the next
  write there does not cover, its copy kept until that write ("A path with no heads"). Applying the
  tree deletes uses the index of "Judging a
  tree delete without a walk", at open as on arrival, and builds it as the records are held again.
- **A clock set back.** When the greatest counter of an applied record in the store (bases and
  archived versions included, the re-confirm review of 2026-11-10) is more than `CLOCK_RULE_LIMIT`
  ahead of this device's clock, the folder does not open: the device raises the clock-rule issue,
  worded as "records here are dated more than a year ahead of this device's clock: it was set back,
  or was ahead when they arrived", with the remedy, since with that
  clock it could sync with none of the peers that wrote those records anyway. Removing those records
  instead could undo the device's own edit that no peer has yet, whose record would then survive
  only as a base and lose to an older version from the peers (the coordinator's ruling of
  2026-10-25, for the owner's review). The folder opens once this device's clock is within
  `CLOCK_RULE_LIMIT` of that greatest counter, or after the folder is added again (the
  clock rule's remedy). The device checks again when its clock passes that time, through the clock
  trait, not only at the next open, and opens the folder then. While it is kept closed, the folder
  counts as a paused folder for folder proofs (3.5, step 2): it is not proven to peers, and their
  proofs for it are answered REJECTED, so it receives nothing while it waits. This case goes with
  the clock rule, which a signed watermark is to replace (the owner's decision of 2026-11-08; a
  later change).
- The **high-water mark** stored is accepted only up to the greater of the greatest counter held
  (bases and archived versions included) and the clock floor, plus `CLOCK_AHEAD_WARNING` (one day);
  a stored mark above that, or at or above `MAX_COUNTER`, is reported as corrupt and replaced by
  that greater value, so that a mark changed at rest can neither lock the folder nor carry the
  device's counters far into the future. A mark below the greatest counter held is raised to it. So
  this device's next write takes a counter above that of every archived version, whose dots its
  vector carries: a dot at or above its own counter would make that write a writer fault on every
  device (step 7). Sealed peers keep no mark, since they write nothing.
- So a dropped record is one this device lacks, and index sync fetches every genuine one again from
  any peer that holds it: the device draws a new index epoch (4.5), at most once per open, whenever
  the open dropped anything, so every peer reconciles with it, and the digests of the subtrees that
  held the dropped records differ from those of every peer that holds them (4.5, "Why it
  converges").
- A record changed at rest under a new record hash stays in the store and is dropped and reported
  again at each open; one changed under the same hash (its signature bytes) is replaced in the store
  by the good copy when that arrives, since a store keeps the envelope written last under a hash.
- Stated residuals, of a store that lost records or had them withheld at rest: a record that no peer
  holds stays missing; a record that a missing one replaced may be live again here, and is replaced
  again when the missing one returns from a peer; withholding this device's own records lowers its
  high-water mark at most to the clock floor, the case A2 of "Why it is safe", 8c; and records that
  only this device held are lost with the store.
- For the engine (when it lands): it shows the folder as **Checking** in its folder state (the
  engine's own, which the Status message does not carry) while the index opens, and runs the open
  off any asynchronous executor, since the open blocks its thread for the whole check; it raises one
  issue for what was dropped (records and bases), for records dated more than a year ahead of the
  clock and for a corrupt high-water mark, with the counts and at most 16 of the record hashes (a
  fixed engine constant), never a device; when the store returned records and none of them passed (a
  store of another folder, or under another key), which it tells by an index that holds nothing and
  a non-empty dropped list, it treats the folder as misconfigured and shows an error rather than
  scanning the disk into an empty index; and a folder re-keyed under a new write key starts with a
  fresh store.
- A phase 1 store that keeps bytes decodes each envelope when it loads; bytes that no longer decode
  it drops and reports, as the open does for a record that fails its checks, and it never fails the
  whole load for them or loses them without trace; `Store::load` will need a way to report them, for
  example into the open's report.
- Opening costs one signature verification per stored record (`threat-model.md` TM-9 gives the
  measured cost), and, at a read or write holder, one seal opened per record; a labelled keyed
  checksum per stored record replaces the verification only if measurements on a phone or NAS show
  start-up too slow. With latest only, a store holds far fewer records than the history it
  replaces, so the check costs less than it did when every record was kept.

What this layer guarantees is that every read or write holder that holds the same records holds the
same live records, applies the same ones, has expired the same ones, refuses the same ones and
computes the same heads, in any arrival order, whatever records it held and dropped before, and
whatever its clock; that two read or write holders that exchange come to hold the same records; and
that a sealed peer holds what they hold plus the stale copies no write holder has yet named, less,
for a while, a version that came back after its deletion was forgotten and that a replayed deletion
took away again, and holds what a write holder holds once that write holder has met it and the
rounds its cleanups owe have run, short of records from the future and of stale copies that wait for
the write holder to forget a cleanup (4.5, "Why it converges"). Release skew splits what read and
write holders hold only for records one release cannot read: an older release holds such a record
opaque, replaced only by a name, where a newer one judges it by its vector. A `kind` added before
1.0 therefore joins major 1's baseline, and one added after 1.0 needs a folder-level requirement
first, like a compression code (`keys.md` §3.2; section 6).

### 4.5 Index exchange and Status

Two devices bring their indexes together in two ways. The quick way asks a peer for what it has come
to hold since the last exchange, by the peer's own numbering, as Syncthing's index exchange does
(BEP v1: an index ID and a maximum sequence per device). The thorough way compares hashes of the two
sets of records, subtree by subtree of the path tags, and sends only what differs; it serves a
device that is new, that lost its state, or whose peer's numbering changed, and it ends every round,
so that whatever the quick way missed is found. Sets are compared by hashes of records, never by
vectors or counters: a writer that signs two records with one dot cannot make two devices believe
they hold the same records (Kleppmann 2022; TM-41). Read and write holders end an exchange holding
the same records; a sealed peer, which judges only by names, may hold more, the stale copies that
the next write holder to meet it names in a cleanup, or, after a replay, lack a version for a while
(4.4, "Stale copies at a sealed peer").

```proto
message IndexRequest {
  bytes   folder_id   = 1;
  reserved 2;                 // was have (the drafts' cursors)
  uint32  max_records = 3;    // per reply page (Pages, below); 0, or above MAX_PAGE_RECORDS (4096), means 4096; below 64 means 64
  uint32  request_id  = 4;    // >= 1, chosen by the requester, unique among its requests outstanding on the connection (IndexRequest and ReconcileRequest alike); every page of the reply echoes it
  reserved 5, 6, 7;           // were after, through and listed
  fixed64 epoch       = 8;    // the responder's index epoch the requester's cursor belongs to; never 0
  uint64  since       = 9;    // the requester's cursor: the responder's local sequence through which it holds what the responder held; <= MAX_LOCAL_SEQ
}

message IndexRecords {
  bytes   folder_id              = 1;
  repeated SignedRecord records  = 2;   // <= MAX_PAGE_RECORDS (4096), more is malformed
  bool    more                   = 3;   // another page of the same reply follows; never on a push, nor on a page without records (both malformed)
  uint32  request_id             = 4;   // the request this page answers; 0 = a push
  fixed64 epoch                  = 5;   // the sender's index epoch; never 0
  uint64  through                = 6;   // a local sequence of the sender's that the receiver may count through (Cursors, below), or 0; <= MAX_LOCAL_SEQ
  bool    reset                  = 7;   // a reply to an IndexRequest whose epoch is not the sender's, or whose since is above the sender's local sequence: one page with no records, more and through not set; the requester reconciles
}

message ReconcileRequest {
  bytes  folder_id  = 1;
  uint32 request_id = 2;   // as in IndexRequest
  bytes  prefix     = 3;   // 0 ..= 128 bytes, each 0 ..= 15: the leading nibbles of a record's key (Set digests, below), high nibble first, naming a subtree; empty: the root
  bytes  digest     = 4;   // 32: the requester's digest of that subtree
}

message ReconcileReply {
  bytes   folder_id  = 1;
  uint32  request_id = 2;
  uint32  outcome    = 3;   // ReconcileOutcome
  repeated bytes children = 4;  // CHILDREN only, and then exactly 16 digests of 32 bytes: the subtrees at the prefix followed by 0, 1 … 15
  fixed64 epoch      = 5;   // the responder's index epoch; never 0
  uint64  through    = 6;   // for the root: the responder's local sequence when it answered; for any other prefix, not set
}

enum ReconcileOutcome { RECONCILE_UNSPECIFIED = 0; EQUAL = 1; CHILDREN = 2; RECORDS = 3; }   // any other value: malformed

message Status {
  repeated FolderStatus folders = 1;   // open folders only; <= 1024
  string device_name            = 2;   // self-reported; <= 64 bytes of UTF-8, no control characters (else the Status is malformed); set in the first Status after the first folder opens on the connection, and again when the name changes; shown as text only, marked "reported"
}

message FolderStatus {
  bytes  folder_id       = 1;
  uint64 index_records   = 2;   // index records held for the folder (the "index version"): live records, tree deletes and cleanups
  uint64 bytes_needed    = 3;   // ciphertext bytes still to fetch
  bool   paused          = 4;
  uint64 free_disk_bytes = 5;
  uint64 chunks_stored   = 6;   // the chunks this device has stored for the folder since the folder opened on this connection: 0 in the first Status, one more with each chunk stored, never falling, even when chunks are freed (4.6)
  uint64 extra_versions  = 7;   // records it holds beyond one per file ID: at a sealed peer its stale copies and the folder's real conflicts together, which it cannot tell apart; at a read or write holder the extra heads of its conflicts (4.4, "Stale copies at a sealed peer")
}
```

- **Local sequence and epoch.** Every device numbers the records it holds for a folder, live
  records, tree deletes and cleanups alike, in the order it came to hold them: its **local
  sequence**, 1, 2, 3 …, at most `MAX_LOCAL_SEQ` (2^62), persisted with each record; a dropped
  record's number is never given to another. A device whose next local sequence number would pass
  `MAX_LOCAL_SEQ` numbers every record it holds afresh from 1, in its present order, and draws a new
  epoch, so that every peer reconciles with it once; no device comes near it in practice. Its
  **index epoch** is a random non-zero 64-bit number, drawn through the runtime's randomness trait
  when its store is made, and drawn again whenever its local sequence may have gone back or lost
  records: when opening the folder dropped records (4.4), when it comes to hold a record under its
  own device ID with a counter above its high-water mark ("Durability before transmission", below),
  and when a peer asks with this epoch and a `since` above its local sequence. A peer's request
  forces this at most once per connection, and an open at most once, so that no peer can make a
  device change its epoch at the rate it can send requests. The pair (epoch, local sequence) names a
  point in that device's index.
- **Per-peer state.** For each folder and each peer, by the device ID its DeviceProof proved (3.4),
  a device keeps the peer's epoch, its **cursor** (the peer's local sequence through which this
  device holds what the peer held, or a record covering it), when the two last ended a round, caught
  up or not, and, at a write holder, how many of the peer's records it has named in the current
  window of `MAX_PEER_NAMES` (Stale copies, below); and, from phase 2, the libp2p peer ID that the
  peer's DeviceProof bound to that device ID (3.3, 3.4), the latest seen, by which hole punching
  tells a peer of a shared folder from a stranger (3.1; `threat-model.md` TM-25: a lookup by peer
  ID across the folders' per-peer states, one entry per state, the spec author's choice, for the
  owner's review); persisted. It drops a peer's state after
  `PEER_STATE_HORIZON` (90 days) without a round that ended, and, when the folder already holds
  `MAX_PEER_STATES` (4 096) of them, the one longest without a round, to admit another. Without
  state for a peer a round starts by reconciling, and, from phase 2, a punch through a coordinator
  no longer knows the peer by its peer ID, so it is admitted only once it proves a key (3.1); that
  is the whole cost of dropping it.
- **Rounds.** A side sends a round when a folder opens on the connection and when it owes one
  (below); no round of a folder paused for a store failure starts, and resuming owes one on every
  connection where the folder is open (section 5). A round is, in order:
  1. **Since**, when this side holds state for the peer: an `IndexRequest` with the peer's epoch and
     its cursor as `since`. The responder answers with every record it holds whose local sequence is
     above `since`, or with a reset.
  2. **Check**: a `ReconcileRequest` for the root with this side's root digest. `EQUAL` ends the
     round. Otherwise the side **reconciles** (below): one **pass** descends to every subtree whose
     digests differ and exchanges its records, and when the pass ends the side sends the root
     request again, at most `MAX_RECONCILE_PASSES` (4) passes in a round. The round also ends after
     a **quiet** pass: one that ran to its end, not cut short at `MAX_PASS_REQUESTS`, skipped no
     record, and brought this side no record it then held. A record is **skipped** when this side
     received it and could not judge it: its index store refused the change (a store failure,
     section 5) or the folder was paused meanwhile. What the peer still holds beyond this side's
     records is then only what this side holds replaced (stale copies, at a sealed peer) or refuses
     (records from the future, 4.4 "The clock rule"). A round ends **caught up** at `EQUAL` or after
     a quiet pass; that is the one meaning of "caught up" in this file. A round that ends otherwise,
     after `MAX_RECONCILE_PASSES` passes none of which was quiet, ends all the same, with a log
     line, and the side owes a round, which waits its interval (below) and whose records will differ
     less; a caught-up round owes none unless its side issued a cleanup at its end (Round owed,
     below), so a peer's stale copies or refused records cost one re-sending per round and never a
     storm of rounds. When the round ends, unless it skipped a record (in which case the cursor
     stays where it was, and the round, never caught up, owes another), the cursor becomes the
     `through` of the last page of the Since reply, or, after a reset or without Since, the
     `through` of the first root `ReconcileReply` of the Check, and the epoch the one that reply
     carried; pushes move it on from there (Cursors, below).
- **Serving an `IndexRequest`.** When `epoch` is the responder's and `since` is at most its local
  sequence: every record it holds whose local sequence is above `since`, in ascending local
  sequence, in pages; each page's `through` is the local sequence of its last record, and the last
  page's is the responder's local sequence when it began to serve the request (so a reply with
  nothing to send is one empty page whose `through` is that). Otherwise one page with `reset` set
  and nothing else; a `since` above its local sequence also draws a new epoch, at most once per
  connection (above). A responder keeps no state between requests.
- **Set digests.** Over the records a device holds for a folder (live records, tree deletes and
  cleanups, opaque ones included; nothing else), each has a 64-byte **key**: an index record's path
  tag followed by its record hash, and a cleanup's record hash twice. The **subtree** at a prefix of
  `k` nibbles (`0 ≤ k ≤ 128`, high nibble first) holds the records whose key begins with those
  nibbles; a key is unique, so a subtree at 128 nibbles holds at most one record. (The coordinator's
  ruling of 2026-10-26, for the owner's review: the drafts keyed records by the path tag alone, so
  that a file ID holding many records was one leaf at 64 nibbles, collected, sorted and hashed whole
  on each change, which made replaying one file's history at a sealed peer cost the square of that
  history; 8 000 copies of one file took 17 s to hold.) Its **digest** is: 32 zero bytes when it
  holds no record; when it holds at most `RECONCILE_LEAF_MAX` (64) records, or `k = 128`, the **leaf
  form** `H("licketysync/v1/hash/set-leaf", be32(n) || h_1 || … || h_n)`, the record hashes
  ascending; otherwise the **node form** `H("licketysync/v1/hash/set-node", d_0 || d_1 || … ||
  d_15)`, `d_i` being the digest of the subtree at the prefix followed by `i`. Equal digests mean
  the same records, short of a BLAKE3 collision, and the two labels keep the forms apart. A device
  caches the digest of every subtree in node form and of every leaf, and keeps them current as
  records come and go. The leaf form begins at the shortest prefix whose subtree holds at most 64
  records, wherever that falls: above 64 nibbles for a file ID that holds few records, and beneath
  it, by the record-hash nibbles of the key, for one that holds more; every record lies in exactly
  one leaf, and no leaf holds more than 64 records. So a change rehashes one leaf of at most 64
  record hashes and the node-form subtrees above it, at most 128 and in practice about `log16(n /
  64)`, plus `log16(m / 64)` beneath a file ID that holds `m` records, since record hashes are
  uniform and a write holder that ground them to share more nibbles would pay about 16 hash attempts
  per record for each nibble more (the record hash covers the body, not the signature, so grinding
  needs no signing), which the cap of 128 nibbles makes harmless. Serving reads the cache and
  computes no digest (TM-22). A requester whose own subtree at a prefix is in leaf form computes its
  16 child digests from those at most 64 records when a `CHILDREN` reply asks for them.
- **Serving a `ReconcileRequest`** for prefix `p` and digest `D`: when its own digest of `p` is `D`,
  `EQUAL`. Otherwise, when `D` is 32 zero bytes (the requester holds nothing there), or `p` has 128
  nibbles, or its own subtree at `p` is empty or in leaf form, `RECORDS`, followed by every record
  it holds in that subtree, in ascending key order (Set digests, above), as `IndexRecords` pages
  that carry the request's `request_id` and no `through` (one empty page when it holds none), the
  last with `more` clear. A subtree is a contiguous range of keys, so the responder builds each page
  from where the last key it sent left off, in `O(page · log n)` work and with only that key kept
  for the reply in progress, and never sorts the subtree (the coordinator's ruling of 2026-10-26,
  for the owner's review). Otherwise, that is when `D` is not zero, `p` is shorter than 128 nibbles
  and its subtree holds more than `RECONCILE_LEAF_MAX` records, `CHILDREN`, with its 16 child
  digests. Each of those three conditions is checked by the requester: `CHILDREN` for a 128-nibble
  prefix or answering a zero digest, and `RECORDS` carrying more than `RECONCILE_LEAF_MAX` records
  for a prefix shorter than 128 nibbles answering a non-zero digest, are **sender violations**. A
  reply to the root carries the responder's local sequence as `through`.
- **Reconciling.** The requester keeps a **work list** of prefixes, depth first and ascending, which
  starts with the root. On `CHILDREN` it compares each child digest with its own digest of that
  child and puts every child that differs on the list; on `RECORDS`, once the last page has come, it
  pushes every record it holds in that subtree that the reply did not carry (when the reply carried
  more than `RECONCILE_LEAF_MAX` records, every record it holds there; duplicates cost the peer a
  hash each), with `through` not set. It sends the next prefix's request once the current reply is
  complete, and the pass ends when the list is empty, or after `MAX_PASS_REQUESTS` (65 536)
  requests, with a log line: the next pass, from the root again, goes on where this one stopped,
  since what was exchanged is held and its subtrees answer `EQUAL`, and a pass cut short is never
  quiet. A requester's pass therefore costs it at most that many requests whatever the responder
  answers. Between devices that differ in every subtree, a pass over a folder of up to about 262 000
  records takes at most 4 369 requests; a larger one needs the next level of the trie, about 70 000
  requests at a million records, and so takes two passes. The list holds at most 1 921 prefixes (15
  unvisited siblings at each of 128 levels, and the one being visited), and nothing else is kept
  between requests but the record hashes of the current `RECORDS` reply, at most
  `RECONCILE_LEAF_MAX` of them. A record in a `RECORDS` reply whose key in the set digests (its path
  tag and record hash, or a cleanup's record hash twice) does not begin with the request's prefix is
  a **sender violation**.
- **Stale copies.** When a write holder receives from a peer a record that it does not hold because
  something it holds replaces it, by coverage or as a record beneath a tree delete it holds (4.4
  steps 3, 6 and 8), the peer holds a **stale copy**; a tombstone, tree delete or cleanup that the
  write holder has forgotten after its horizon is a **forgotten record** the peer still holds. The
  write holder notes either, with the record that replaces it (none for a forgotten one; judged
  again when it is named, 4.4 "Cleanup", case (b)), only when all of these hold, checked in this
  order:
  - no note with its fingerprint exists: a record noted once is never verified again while its note
    lasts;
  - no record it holds at the file ID names it, and no cleanup it holds names it in any group,
    whether or not that group applies (4.4, "When a write holder issues one"). When the naming group
    applies, the peer holds the copy only because it lacks that cleanup or the group's `because`,
    which lies in a subtree whose digests differ and which reconciliation therefore sends it, in
    this round or the next, and the copy goes when it arrives. When the group no longer applies (its
    `because` replaced or forgotten here), the copy stays at the peer until this write holder
    forgets the cleanup, `CLEANUP_HORIZON` of the folder's time later, and then notes it as any
    stale copy; in a folder nobody writes to, whose time stands still, it stays for good;
  - the peer, by the device ID its DeviceProof proved, has not had `MAX_PEER_NAMES` (1 048 576) of
    its records named in the current window of `CLEANUP_HORIZON` (30 days, by this device's wall
    clock; the count is kept with the per-peer state). Past it, the copies wait for the next window,
    with a log line;
  - this connection has verified fewer than `MAX_NOTE_VERIFICATIONS` (4 096) records for notes in
    the current window of `INDEX_RESYNC_INTERVAL` (10 s, by monotonic time): one budget per
    connection, shared by every folder open on it (the coordinator's ruling of 2026-10-26, for the
    owner's review). Past it, the rest wait for the next window, with a log line. 4 096
    verifications take about 0.24 s of one core (the cost TM-9 measured, about 60 µs each), and the
    budget is refilled at most every `INDEX_RESYNC_INTERVAL` (10 s), so a connection costs at most
    about 2.4 % of one core in such checks, however many folders are open on it, on average: the
    window is fixed, so a peer can spend up to two windows' budget in a short burst across a
    window's boundary (the coordinator's ruling of 2026-10-26, for the owner's review). The bound is
    per connection opened: a peer that reconnects starts a new connection, and with it a new budget,
    so what bounds the total is the rate of connections (a phase 1 connection limit);
  - its signature verifies (one verification per note; a forged record closes the connection with
    `VERIFICATION_FAILED`, as a forged record always does, 4.4 step 3).

  Notes are at most `MAX_STALE_KNOWN` (65 536) per folder, kept across connections in memory (not
  persisted: a restart forgets them, and a later round verifies those copies again), the oldest
  dropped first: they are the memory of records verified and not yet named, as `MAX_FUTURE_KNOWN` is
  for records from the future. Each is named in the write holder's next write of that path or in the
  cleanup it issues at the end of a round (4.4, "Cleanup", cases (b) and (c)), whichever comes
  first, and goes once its record is named; a note dropped as the oldest costs only that a later
  round verifies the copy again, within that round's limit. The stated residual (the coordinator's
  ruling of 2026-10-26, for the owner's review): the notes of a folder are shared by every
  connection and dropped oldest first, so a hostile peer with several connections and genuine old
  records can push an honest peer's notes out before they are named; that costs an honest sealed
  peer a slower cleanup, never a loss. Per-peer shares of the notes are a phase 1 follow-up. Read
  holders note nothing, since they cannot sign: a sealed peer that meets only read holders keeps its
  stale copies. The stated residual: a holder of any key that kept genuine old records can make
  write holders verify and name each of them once per life of the cleanup that names it,
  `CLEANUP_HORIZON` of the folder's time, however often the file is written meanwhile (4.4, "Stale
  copies at a sealed peer, and their bound"), at most `MAX_PEER_NAMES` names a window for each
  device identity it connects under and at most `MAX_NOTE_VERIFICATIONS` verifications for notes per
  connection per `INDEX_RESYNC_INTERVAL`, whatever the number of folders; it can make up identities
  and connections, so what bounds the names is the folder's history, and what bounds the
  verifications is the number and rate of connections (TM-22).
- **Pushes** (ruling PUSH-2). From the moment a folder opens on a connection, a device pushes every
  record it comes to hold (4.4 step 6), tree deletes and cleanups included, to every connection
  where the folder is open except the one the record arrived on, in the order of its local sequence,
  at most `MAX_PAGE_RECORDS` records per push, each push's `through` the local sequence of its last
  record. A push that the send queue cannot take is dropped, and the sender then owes the receiver
  one empty push for the folder (one flag per folder per connection), which waits in order like a
  reply and is never dropped (3.1); it queues no other push for the folder on that connection before
  it. Records sent in a reconciliation (above) are pushes with `through` not set.
- **Cursors.** A side **counts** a peer's pushes from the end of a round of its own on the
  connection, unless an empty push from the peer arrived after that round began, and until the next
  empty push arrives; while it counts, a push with `through` set raises its cursor for the peer to
  that `through`, unless this side skipped a record of that push or of an earlier one since it began
  counting, which stops the counting until the next round, as an empty push does. This is sound
  because the peer pushes, in order and over an ordered stream, every record it comes to hold after
  the folder opened, other than those that came from this side, and sends an empty push in the place
  of any it dropped: when a push with `through` `s` arrives while the side counts, the side holds,
  or holds a record covering, every record the peer held with a local sequence at most `s`. A push
  whose epoch is not the epoch of this side's cursor for the peer is not counted, stops the counting
  until the next round, and owes a round; a cursor that the peer's epoch does not match is no
  cursor, and that round reconciles.
- **Round owed** (ruling PUSH-1). Each side keeps one flag per folder per connection: it owes a
  round. The flag is set when an empty push arrives, when a round of its own ends not caught up
  (Rounds, above), and when it is a write holder that issued a cleanup at the end of its round, so
  that the next round finds what that cleanup's paging, `MAX_STALE_KNOWN` or `MAX_PEER_NAMES` left
  over and ends at `EQUAL` once the cleanups have done their work. Once no request of its own is
  outstanding for the folder, no round of its own is under way (a round under way runs to its end
  first, so that every round finishes however often the flag is set), and no sooner than
  `INDEX_RESYNC_INTERVAL` after the previous owed round began for the folder on the connection, a
  side whose flag is set clears it and starts a round. The flag is one bit, so any number of empty
  pushes owe one round, and one set while an owed round runs owes the next; nothing a peer dropped
  is ever left unasked for.
- **One request at a time.** At most one request, an `IndexRequest` or a `ReconcileRequest`, per
  folder is outstanding on a connection: the requester sends the next only after the current reply
  is complete, which is its last `IndexRecords` page (`more = false`), or a `ReconcileReply` that is
  `EQUAL` or `CHILDREN`, or a `RECORDS` reply's last page. A responder that receives a second
  request for a folder before it has queued the current reply's end closes with `PROTOCOL_ERROR`.
  Pushes (`request_id = 0`) are not requests and are unaffected. A responder serves a folder's
  `IndexRequest`s, and its `ReconcileRequest`s for the root, on one connection at most once per
  `INDEX_REQUEST_MIN_INTERVAL` (1 s), counted from when it began serving the previous one, and
  delays a later one until then, never refusing it; a `ReconcileRequest` for any other prefix it
  serves at once, since it costs at most 16 cached digests or the records of one subtree, and the
  requester waits for each reply before it sends the next. A fair share of upload per peer, across
  folders and against chunk requests, is a phase 1 engine item.
- **Reply deadline.** A requester closes with `TIMEOUT` when the reply to its outstanding request
  has brought nothing for `REPLY_PAGE_TIMEOUT` (10 min). The count starts when the request has left
  the requester's send queue (`Transport::unsent` has fallen past it, 3.1) and restarts on every
  `ReconcileReply` and every page of a reply to any of the requester's own requests on the
  connection, on a `ChunkReply` with `CHUNK_OK` to one of its own chunk requests (4.6), and on a
  push that brings at least one record this side then holds, since an honest reply may wait behind
  any of those in the peer's send queue (3.1). A `ChunkReply` with `CHUNK_BUSY` or
  `CHUNK_NOT_FOUND`, a Status, an empty push, a push of duplicates only and an `Unsupported` do not
  restart it. So a responder that sets `more = true` and never sends the last page, or answers only
  `CHUNK_BUSY`, or pushes only what the requester already holds, cannot hold the one outstanding
  request slot past the deadline; the next connection asks again. The stated residual: a responder
  that keeps delivering new records or chunks can delay its reply on that one connection; other
  connections recover. Every page of the reply restarts the count, whatever its records, and a page
  with `more = true` holds at least one (Pages, below), so the residual includes a responder that
  keeps sending pages of records the requester already holds: it holds the request slot on that
  connection for as long as it keeps sending such pages, and pays for each of them.
- **Pages.** The page limit of an `IndexRequest`'s reply is its `max_records` held between 64 and
  `MAX_PAGE_RECORDS` (4096): 0 or a value above 4096 means 4096, and a value below 64 means 64, so
  that no requester can pin a responder's processor with one-record pages; a `RECORDS` reply's limit
  is `MAX_PAGE_RECORDS`. The responder fills each page record by record in the order above and ends
  the page before a record when the page already holds one and the record would take it past the
  page limit, or would take the encoded `IndexRecords` frame past the requester's
  `max_message_size`. A page never holds more than the page limit, and never more than
  `MAX_PAGE_RECORDS`, the receiver's bound; every record fits a page on its own (section 2). A reply
  with nothing to send is one empty page with `more = false`; `more` is set on every page but the
  last. Since a page ends before a record only when it already holds one, a page with `more = true`
  holds at least one record: one without any is malformed.
- **Replies and pushes.** A **reply** is what a sender produces for a request it received on this
  connection: for an `IndexRequest`, its `IndexRecords` pages, up to and including the one with
  `more = false`; for a `ReconcileRequest`, its `ReconcileReply` and, after `RECORDS`, its pages. A
  **push** is an unsolicited `IndexRecords` with `request_id = 0` and `more = false`; it carries
  records the pusher came to hold, or records a reconciliation found the receiver lacking, and may
  arrive between two pages of a reply. An **empty push** says that the sender dropped pushes for the
  folder (3.1): the receiver stops counting pushes and owes a round (above). An `IndexRecords` push
  with `more = true` or `reset`, a reply page with `more = true` and no records, a page with `reset`
  and records, `more` or `through`, a page with `reset` in a reply to a `ReconcileRequest`, pages
  for a `ReconcileRequest` whose reply was not `RECORDS`, a `ReconcileReply` for an `IndexRequest`,
  and a page or reply whose `request_id` names no request outstanding on the connection, are
  malformed.
- **Why it converges.** Three statements, each short of records that arrive or are written
  meanwhile, which the pushes and the next round bring.
  - *Read and write holders.* Two read or write holders that each end a caught-up round with the
    other hold the same records, whatever each held before, in whatever order records arrived and
    whatever their clocks within the clock rule. (i) What a device holds never includes a record
    that another record it holds replaces (4.4 step 6), and whether a record is replaced, at any
    tier, is a function of the records the device holds and of nothing it remembers: no cleanup
    group acts once its `because` record is gone (4.4, "Cleanup"). (ii) A pass that runs to its end
    gives each side every record the other holds in every subtree where their digests differ: the
    `RECORDS` reply carries the responder's, and the requester pushes its own. (iii) A side that
    receives a record and does not hold it either holds something that replaces it, or has passed it
    by the folder's own time, or refuses it by the clock rule. In the first case the replacing
    record (a covering or naming record at the same file ID, a tree delete above it, or a cleanup
    together with its group's `because`), which by (i) the sender does not hold in full, lies in a
    subtree where their digests differ, so it reaches the sender in the same pass and drops the
    record there too, or is itself replaced there, by a record that reaches this side the same way.
    In the second, the record that set this side's time ahead reaches the sender the same way and
    expires the record there too, since expiry depends on the records held and on nothing else. So
    each pass that ends neither equal nor quiet either lowers the number of records the two hold
    between them or raises the number both hold, and neither can go on for ever: the passes end with
    equal roots, that is equal records. Since live records, expiry and heads are functions of the
    records held (4.4), the two then compute the same heads (TM-41). The third case is the one
    exception, and it spreads: a record that one side's clock puts more than a year ahead and the
    other's does not is held by one and refused by the other, which raises the clock-rule issue; it
    may set the folder's time on the side that holds it, so the two can also differ on which
    deletions have expired, and every record written after it by a device that holds it is refused
    as well, until real time comes within a year of them (4.4, "The clock rule", "What it does to
    the devices in between").
  - *A sealed peer and a write holder.* Let a write holder `W` end a caught-up round with a sealed
    peer `S`. (1) Everything `S` holds beyond `W`'s records reached `W` in the round and is replaced
    or forgotten at `W`, or refused there by the clock rule as from the future, which `W` neither
    holds nor names and `S` keeps (the one exception of the read and write holders' statement
    above). For a replaced or forgotten one: either `W` holds a record or a cleanup group that
    applies that names it, which `S` lacks (with the group's `because`) and receives by
    reconciliation; or `W` holds a cleanup that names it in a group that no longer applies, and then
    it waits at `S` until `W` has forgotten that cleanup, `CLEANUP_HORIZON` of the folder's time
    later (4.5, "Stale copies"); or `W` notes it, once its signature verifies, and names it in its
    cleanup at the round's end, `because` a record that replaces it, which `S` then holds or
    receives in the next round, or with `because` empty. In the first and last cases `S` drops it in
    that round or the next. (2) Everything `W` holds that `S` lacks reached `S` in the round. `S`
    refuses it only while a record it holds names it, or a cleanup group it holds together with the
    group's `because`. `W` holds the named record, so `W` lacks that naming record, or lacks the
    cleanup or its `because`; whichever `W` lacks is one of `S`'s extra records, which (1) removes,
    and the next round then gives `S` the record it refused. A round at whose end `W` issued a
    cleanup owes another (Round owed), and each such round removes at least one of `S`'s extra
    records or gives it one it lacked, so the rounds end, and then `S` holds what `W` holds, short
    of records from the future and of stale copies waiting for `W` to forget the cleanup that named
    them: in random runs of a model of these rules with replays, tree deletes, pruning and expiry,
    within four rounds, and within two rounds of `W` forgetting such a cleanup (section 8, item 7,
    property (g)). A read holder and a sealed peer end caught up with the same result less the
    cleanups: the sealed peer keeps its stale copies, which cost one re-sending per round, until a
    write holder meets it. So a sealed peer converges with the read and write holders once a write
    holder has met it and the rounds its cleanups owe have run, and the copies that a held cleanup
    names in a group that no longer applies once that cleanup is forgotten. Until then it holds
    their records plus its stale copies, less any version that a replayed old deletion took from it
    (4.4, "Stale copies at a sealed peer"), and every record it dropped is one that a signed record
    or cleanup replaced or forgot (4.4, "Why it is safe" 11).
  - *Cost.* A round between two devices that already agree costs one `IndexRequest` reply and one
    root `ReconcileRequest` answered `EQUAL`; a reconciliation costs, per subtree that differs, one
    request at each level above it, about `log16(n / 64)`, and the records of the subtree.
  - *Across long separations.* Nothing in this exchange expires but per-peer state, whose loss costs
    one reconciliation; a device that returns after months reconciles subtree by subtree and sends
    and receives only what differs. Versions it wrote meanwhile are concurrent with what others
    wrote and become heads beside theirs, never lost; versions others replaced meanwhile are covered
    and dropped, or, past 32 writers on one path or past the deletion horizon, kept as heads (4.4,
    "Why it is safe", 5 and 7). A device whose clock is more than a year off is refused by the clock
    rule until its clock is fixed and the folder added again (4.4).
  - *Through sealed peers.* A sealed peer holds and digests records by their fingerprints and
    judges them by names alone. It can withhold records from a device that meets no one else, and it
    can offer stale copies and old versions whose deletion has been forgotten; it cannot make two
    read or write holders that exchange with each other disagree, nor make a read or write holder
    drop a version, since every drop needs a signed record or cleanup (TM-17, TM-41). By replaying a
    genuine old deletion it can take a version that came back after that deletion was forgotten from
    another sealed peer, until a write holder meets that peer (4.4).
  - *Against junk.* A forged record or cleanup closes the connection before it drops anything (4.4
    step 5), and so does one a write holder verifies before noting it as a stale copy (step 3); a
    record outside the subtree a `RECORDS` reply was for closes it as a sender violation. A peer
    that offers genuine old records makes a write holder verify and name each once per life of the
    cleanup that names it, and at most `MAX_PEER_NAMES` a window (Stale copies, above). A peer that
    lies about its digests or withholds records can keep a round with itself from ending equal, and
    so make its partner owe rounds at `INDEX_RESYNC_INTERVAL` when it hands it new records; it
    cannot make two honest devices that exchange disagree, nor grow any per-connection table past
    its bound (section 5, TM-22).
- **Durability before transmission.** A writer commits a new record, its local sequence number and
  its high-water mark to its own index before any peer may receive the record, so a crash can never
  make it reuse a counter; a peer forwards only records it has itself verified and committed, opaque
  ones (4.4 step 7) included. A device that comes to hold a record under its own device ID with a
  counter above its high-water mark (`counter > hw`: it was restored from a backup of its index, its
  store lost or corrupted records of its own at rest, or another device writes under its ID) has its
  high-water mark raised to it by 4.4 step 6, draws a new index epoch, and raises an informational
  issue that names no one, which the engine words as a hint that the device was restored or cloned
  and that a cloned disk image must not run beside the device it was cloned from (`keys.md` §8.1).
  Its edits cover the bases on its disk, which makes a conflict rather than a silent loss when
  others hold later versions (4.4, "Why it is safe" 9).
- Status is sent every `STATUS_INTERVAL` (30 s, through the clock trait) and on change, for open
  folders only; a change in `chunks_stored` alone sends at most one Status per second per folder per
  connection. It is advisory and never changes what a peer will accept. A Status that the send queue
  cannot take (3.1) is skipped rather than queued behind other frames; the next is due within
  `STATUS_INTERVAL`.
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
  holder's `max_requests_in_flight` requests outstanding on a connection, a value above
  `MAX_REQUESTS_IN_FLIGHT` (1 024, section 2) taken as that, and a holder that receives more than it
  advertised closes with `PROTOCOL_ERROR`.
- **Busy.** A holder answers `CHUNK_BUSY` exactly when its unsent bytes on the connection (3.1),
  counting the frames it holds back until the transport has room for them, are at least
  `MAX_SEND_QUEUE / 2` (64 MiB) as it dispatches the request; otherwise it queues the request,
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

### 4.7 What the engine needs

What 4.4 to 4.6 ask of the engine, answered one question at a time for its index-sync boundary
(`crates/engine/src/sync/`). Where this section names a type or key, it describes what is needed,
not the only way to build it.

1. **Latest-only storage.** One change, a record this device writes or accepts (or a batch of them,
   4.4 "The writer's rule"), is one commit: the record held (`e/r/<f>/<record hash>`, its envelope
   as received, with its local sequence number), every record it drops removed, the bases that
   change (4.4, "Bases"), the folder's metadata (high-water mark, next local sequence number, index
   epoch), any cleanup written with it, and the chunks it leaves unnamed added to a pending-free
   list, all staged together; nothing that carries the record is sent before that commit (4.5,
   "Durability before transmission"). Removing what a record covers is never staged without the
   record that covers it. A store that cannot stage atomically writes, in this order, the record,
   then the next local sequence number, the high-water mark and the base slots, then the removals;
   the next open drops whatever a stored record covers and numbers on from the greatest stored local
   sequence number, whatever the stored metadata says (4.4, "Opening a folder"). The order
   guarantees that a base never points at a removed record, since the removals come last. A crash
   between the record and the metadata leaves the record stored and the path's base slot as it was,
   so the next scan can find the file on disk different from its base and write a spurious head with
   the same content, which as identical content makes no conflict copy. Such a store is reopened,
   its records checked as at open, before its folder resumes after a store failure, since the failed
   commit may have stopped between those writes (the coordinator's ruling of 2026-10-26, for the
   owner's review). The file on disk that a change replaces or removes stays in place, and its
   record stays a base, until the commit that applies the new content has succeeded; a key holder
   moves the old file to the archive from its disk as it does so, since the archive holds files, not
   chunks (TM-35). **Chunks.** A device keeps a chunk while a record it holds names its
   `cipher_hash` (4.6). The index counts, per `cipher_hash`, the held records that name it, and
   reports with each change the hashes whose count fell to zero. The engine puts those on a durable
   pending-free list in the same commit, and frees them at the end of the next round on any
   connection where the folder is open, or, when no connection is open, once a minute: each hash
   whose count is still zero then is deleted, blob and marker, and one whose count rose again stays
   (decision: a record dropped early in a round can be named again by one later in it, and its chunk
   need not travel twice). The list holds at most the chunks of the records dropped since the last
   free, and an open finishes whatever it lists before the folder syncs. A chunk request that
   arrives after the free is answered `CHUNK_NOT_FOUND`, and a download of a version that was
   dropped is abandoned.
2. **The exchange shape.** Paged replies, per-page judgements and reply deadlines stay: an
   `IndexRequest`'s reply and a `RECORDS` reply are `IndexRecords` pages, judged record by record,
   stopping at the first refusal that closes; `REPLY_PAGE_TIMEOUT` counts `ReconcileReply`s and
   pages alike (4.5). The judgements are now: duplicate, expired and obsolete (ignored unverified; a
   write holder notes an obsolete or expired record from a peer, after verifying it, unless it is
   noted already or something it holds names it, 4.5 "Stale copies"); from the future (verified,
   refused, the clock-rule issue); held (with the records it dropped and the chunk hashes left
   unnamed); held opaque (an issue names the record); dropped at once because a tree delete covers
   it (step 8, noted as a stale copy); the forged and malformed closes; and store failure. There are
   no gaps, marks or listed requests, and no record is held back to land later: latest only decides
   every record when it arrives. What waits is a cleanup group whose `because` record has not
   arrived, held with its cleanup (4.4, "Cleanup").
3. **Requests.** The cursor is per folder per peer device: the peer's epoch and local sequence
   number, persisted with when the two last ended a round (4.5, "Per-peer state"). An `IndexRequest`
   carries them; its reply lists every record the peer holds with a greater local sequence number,
   in ascending local sequence. A page ends before a record when it already holds one and the record
   would pass the page limit or the requester's `max_message_size`; each page's `through` is its
   last record's local sequence number, and the last page's the responder's local sequence number
   when it began serving. The responder builds pages lazily from its committed state, keeping only
   the request's starting point and the last number sent; a record dropped meanwhile is skipped, and
   one held meanwhile has a greater number and goes by push. A `RECORDS` reply pages the subtree's
   records in ascending key order, the key of 4.5 "Set digests" (path tag then record hash), keeping
   only the last key sent, and its pages carry no `through`.
4. **Rounds.** A round ends with the root check (4.5, "Rounds"), caught up or not in the one sense
   4.5 gives the words: at `EQUAL`, or after a quiet pass, which ran to its end, skipped no record
   and brought this side no record it then held. A round that ends otherwise, or one at whose end
   this side issued a cleanup, owes another, and a round that skipped a record (the folder paused,
   or a store failure) moves no cursor and has no quiet pass, so that the engine can treat a reply
   whose records it skipped as void. The protocol crate's `RoundCompleted` carries which; "a round
   completed on every connection" becomes "the last round on every connection where the folder is
   open is caught up". No round of a folder paused for a store failure starts; resuming owes a round
   on every such connection, as today; and while the store refuses, the side stops counting that
   folder's pushes on every connection (as after an empty push), so no cursor passes a record that
   was refused, and the owed round's `IndexRequest` asks for it again.
5. **Sealed holders.** A sealed holder fetches and keeps the chunks of every record it holds by the
   sealed-peer rule (4.4): every record that no record it holds at its file ID names and no held
   cleanup names in a group that applies. It cannot tell a tombstone from an empty file, so a record
   with no chunks simply costs no chunks. A stale copy is fetched and kept like a live version until
   a write holder names it, and then its chunks are freed with it; a cleanup frees the chunks of
   every record it names that no other held record names. Key holders fetch the same set: the chunks
   of every live record they hold, every head of a conflict included, and of opaque records too,
   which they keep so that they can serve them to a release that reads them, and whose chunks they
   can check only against the ciphertext hash and `stored_len`, since their plaintext hashes are not
   to be trusted (selective sync, a phase 5 refinement, chooses among this set).
6. **Writing.**
   - *Bases.* The engine names a path's bases to the index (4.4, "Bases"): the record it applies
     when it puts a version's content in place or removes the path, each conflict copy's record when
     it writes the copy's content beside the path, and the record the index writes from the disk.
     The index keeps a base it has dropped from the live set until the engine names a newer one.
     When the engine moves a path's file and conflict copies to the archive because the path's live
     records are all opaque, it tells the index so, and the index keeps those bases as the path's
     archived versions until a write covers them, an applied record covers or names them or an
     applied tree delete covers them, or the same record is held again or becomes a base again (4.4,
     "A path with no heads").
     Before the engine applies a record from a peer to a path, it compares the disk with that path's
     base and, if the person changed the file meanwhile, writes that change first; the record from
     the peer and the new write are then concurrent, a conflict, never one over the other.
   - *The current version.* The engine does not build vectors: it hands the index a change found on
     the disk and the index builds the vector from `S`, the path's bases, their twins (the heads
     of a base's content, concurrent with it and, at the path, after it in display order, never the
     first head) and its archived versions, never from records it holds whose content is not on the
     disk, nor from a later
     version of a base or one the engine has yet to put at the path (4.4, "Bases", "The vector and
     names of a new record"; "Why it is safe" 9). What the engine still
     needs of the current version, for a rename's content, is the base at the path (`Current`:
     kind, size, chunks, plaintext hashes). An edit, a delete (a tombstone) and a write that
     resolves a conflict are one change, a put at the path; a rename is a put at the new path, then
     a tombstone at the old, two records in that order and one commit; a copy is a put.
   - *The counter.* A written record's counter is the next counter, `max(hw + 1, min(clock_us,
     CLOCK_FLOOR_MAX))`, from the folder's high-water mark and the clock trait, and the records of
     one commit take consecutive counters from one reading of the clock, in the order of 4.4 "The
     writer's rule" (versions, tree deletes, tombstones, cleanups, each kind by ascending path tag);
     the new `hw` is staged in the records' own commit, and so is every rise that an accepted record
     brings. A record whose commit failed was never sent, so its counter being used again harms no
     one. At open, the stored mark is checked as 4.4 "Opening a folder" says.
   - *Conflicts.* A path's heads are its applied live records in display order; the views list them
     by record hash, the first sitting at the path and every other head whose content differs being
     a conflict copy (4.4), and `read_file` reads any head by its record hash, as today; opaque live
     records come last, by record hash, marked as an update this release cannot read; a path with
     only such records has no heads, and the engine moves its file, and each conflict copy that is
     still a base of the path rather than a version at its own path, to the archive, keeps each
     there until a record it reads covers or names its version or that version is a base again, a
     head that does not cover it leaving it there, and raises the warning while it does (4.4, "A
     path with no heads"). A write over a conflict first writes each conflict copy on the disk as a
     version at its own path, in the same commit, so that it becomes an ordinary live file the
     person deletes when they no longer want it (4.4, "What becomes of a conflict copy"). The state
     digest the simulator compares becomes the root set digest (4.5), equal on every tier for equal
     records, followed, for a key holder, by each path's heads by hash in display order.
   - *Tree deletes.* A scan that finds a directory gone, with everything beneath it, writes one tree
     delete of that directory (after the deletion brake, as today), its vector the join of the bases
     beneath it, their twins and the archived versions there, its names the first 32 of those at the
     directory's own path (4.4, "The vector and names of a new record"); the index then writes a
     tombstone for each base or twin beneath it that the pruned vector leaves uncovered (an archived
     version left uncovered gets none, a stated residual, 4.4 "A tree delete"), and the
     cleanup that names, `because` the tree delete, every record beneath it that it covers, paged by
     `MAX_CLEANUP_ENTRIES` and `MAX_CLEANUP_GROUPS`, all in one commit. Files that vanished from a
     directory that remains get a tombstone each. A directory renamed with what it holds is a put
     at every new path, then a tree delete of the old directory, in one commit. A tree delete
     received makes the engine move to the archive every file beneath it that has no live version
     left, and remove each directory beneath it with no applied live record left beneath it (a
     record this release cannot read keeps no directory, 4.4 "A path with no heads"); a file that a
     tree delete did not cover stays, with the directories it needs.
   - *Names and cleanups.* The index fills a record's `replaces` (`S`, its bases, their twins and
     its archived versions, then the shared writer faults held at the path, then the stale copies
     noted for that path, the
     faults that do not fit going into a cleanup in the same commit) and writes the cleanups of 4.4
     "Cleanup" (with tree deletes, and at the end of each round for the stale copies and forgotten
     records noted, 4.5); the engine only commits and pushes them. Sealed holders and read holders
     write neither.
   - *The clock rule.* The engine puts its wall clock in each Hello, compares the two Hellos when
     the first folder opens on a connection and refuses a peer out of range (3.2), and offers the
     remedy in the issue: unlink the folder keeping its files, fix the clock, add the folder again
     over the same directory, which starts its index store afresh (4.4), with the residual 4.4
     states ("What adding the folder again leaves").
7. **Informational issues.** "Still waiting" is gone: no index record waits for another; only a
   cleanup group waits for its `because` record, held with its cleanup (4.4, "Cleanup"), and that
   raises no issue. "Own sequence ahead" becomes "own counter ahead": a record under this device's
   own ID with a counter above its high-water mark (`counter > hw`) raises the mark to it, draws a
   new epoch, and raises the same informational issue, worded as a hint that the device was restored
   or cloned (4.5). A record whose counter is more than `CLOCK_AHEAD_WARNING` ahead of this device's
   clock raises, once its signature has verified, the issue "this folder's time is N ahead of this
   device's clock (first seen on a record claiming device X)" (4.4, "A fast clock carries forward").
8. **The open-time report.** Every stored record, every base kept only as a base and every archived
   version is still verified at open (step 1 and the signature, at every tier, across the
   processor's cores). The
   report gives the record hashes dropped (ascending, each once), the count of undecodable entries a
   phase 1 store found, whether the folder was kept closed because its records are dated more than a
   year ahead of the clock (4.4, "Opening a folder"), and whether the stored high-water mark was
   corrupt; there is no longer a list of records held back, since none are. Records that another
   stored record covers, and expired tombstones and tree deletes, are dropped at open without a
   report. An open that dropped anything draws a new index epoch, once.

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
- **Limits are per connection**, and none grows with the number of writers or of records (ruling
  R-K4): every per-peer table (open folders, the hints of proofs received (at most
  `MAX_PROOFS_PER_CONNECTION`), the one outstanding index or reconcile request per folder and its
  reply in progress (a `RECORDS` reply keeps only the last key it sent), the reconciliation's work
  list (at most 1 921 prefixes per folder, each at most 65 bytes with two nibbles packed per byte,
  so about 125 KB per folder and 8 MB per connection at 64 open folders, which a peer that lies
  about its digests can keep filled while its pass lasts, until `REPLY_PAGE_TIMEOUT` after its last
  answer) and the record hashes of its current `RECORDS` reply (at most `RECONCILE_LEAF_MAX`), the
  record hashes of records from the future already refused (at most `MAX_FUTURE_KNOWN` per folder on
  the connection), the count of records verified for notes in the current window (at most
  `MAX_NOTE_VERIFICATIONS` for the connection, shared by every folder open on it), outstanding chunk
  requests (at most `max_requests_in_flight`, itself at most `MAX_REQUESTS_IN_FLIGHT`), each holding
  only its hash, the one `CHUNK_BUSY` backoff timer, per folder the chunk pass's position, the
  peer's `chunks_stored` at the latest `CHUNK_NOT_FOUND`, that answer's time and the pending trigger
  bit, pending pages, the unknown types already answered with `Unsupported` (at most 32 768, a 4 KiB
  set), the empty push owed, the round owed, whether pushes are counted and the reconcile pass count
  per folder, resync timers, reply-page deadlines, rate-limit state) is bounded by the constants in
  this file and is freed when the connection closes. What outlives a connection is bounded too,
  though not by a constant: the per-peer state of 4.5 holds at most `MAX_PEER_STATES` entries per
  folder, each with its count of names against `MAX_PEER_NAMES` and, from phase 2, its peer ID,
  looked up by peer ID with one entry per state (3.1), and a write holder's notes of stale
  copies at most `MAX_STALE_KNOWN`; a read or write holder's index of held records by device and
  path, one entry per record held, through which judging an arriving tree delete costs at most two
  queries per entry of its vector whatever lies beneath its directory, and holding it `O(log n)`
  more per record it drops (4.4, "Judging a tree delete without a walk"); the digest cache, whose
  leaves hold at most `RECONCILE_LEAF_MAX` records each, so that a change rehashes at most one leaf
  and the node-form subtrees above it, at most 128, however many records one file ID holds (4.5,
  "Set digests"); both are the coordinator's rulings of 2026-10-26, for the owner's review; and a
  sealed peer's stale copies, which only a write holder's cleanup removes, are bounded only by the
  folder's history (4.4, "Stale copies at a sealed peer, and their bound"). The index and the digest
  cache grow only with the records held, one entry each; the stale copies grow with what any holder
  of the sealed or read key replays, and so do the cleanups write holders issue for them, at most
  `MAX_PEER_NAMES` names a window per peer identity (`threat-model.md` §3.3, §3.6, TM-22). Nothing a
  peer sends can grow a table past its bound; the next item is refused with `PROTOCOL_ERROR` where
  this file says so, and otherwise dropped as section 4.5 says.
- **Every decoder is fuzzed**: frames, every message body, every record body, cleanups, the sealed
  metadata, chunk blobs, key strings, words and links. A decoder never panics and never reads past a
  declared length.
- **Nothing is silently skipped.** Every failure on a connection has exactly one of three outcomes,
  and the table below is the complete mapping; its last two rows concern this device's own index
  store: a store failure, for a record that arrived on a connection and that the store cannot take,
  and a stored record that fails its check when a folder opens, which involves no connection
  (`threat-model.md` TM-9). *Close* is for what only the sender can be blamed for: it forwarded
  bytes that do not parse or do not verify, or broke the protocol's order or bounds. *Set aside and
  keep* (the item is not acted on, and the connection stays open) is for differences in what two
  peers hold, and is the only sense of "set aside" in this file: a duplicate, an obsolete or expired
  record, a stale copy, a cleanup group waiting for its `because`, a cursor of another epoch, a
  digest that differs, a proof for a folder that is not here, a chunk the holder lacks. *Issue
  against the record* is for what a valid signature covers: the body is what a write holder signed,
  the sender merely carried it, so the issue names the record (by hash, and by path where the seal
  opened), never a device (ruling S-4), the item is kept opaque or marked corrupt, and the
  connection stays open. Every outcome raises an issue or a log line that names the cause; none
  drops the item without trace.
- **No blame before a signature.** No writer-fault outcome may be reached on a record whose
  signature has not verified; a signature failure is always forged. Every procedure in this file and
  in `keys.md` verifies the signature before any step whose failure is charged to the signer, and
  before any held record is dropped because of the record; until then every failure is malformed,
  forged or a sender violation, which is the sender's whatever the signature, and a record ignored
  unverified (a duplicate, an expired or an obsolete record, 4.4) is charged to no one and changes
  nothing; a write holder verifies one before it notes it as a stale copy to name (4.5).

| Cause | Outcome |
| --- | --- |
| **Malformed**: frame length below 2, body that does not parse, a field number above 2^29 − 1 or a group wire type, a size or bound or grammar violated, a fixed-size field absent or of another size, a `bool` other than 0 or 1, a `uint32` of 2^32 or more, a field that is not repeated occurring twice in a body, a Hello that fails a check of 3.2 (a device key that is not canonical or is of small order, and a `clock_days` above 2 097 151, included) other than the two rows below, a FolderProof envelope with a wrong `hint` or `nonce` size or a `sealed` outside 16 to 1 024 bytes, a FolderProof whose `hint` repeats one already received on the connection, more than `MAX_PROOFS_PER_CONNECTION` FolderProofs, a message for a folder not open here, a message before Hello or DeviceProof, a known type where only Hello or Close may come, any frame but DeviceProof or Close before the peer's DeviceProof verified, a second Hello or DeviceProof, a list past its bound, more chunk requests than allowed, a stray or second `ProofResult` or one whose `status` is not 1 or 2, a record whose `suite` is not its folder's or whose `record_type` is neither 16 nor 17, a `path_tag` not 32 bytes, more than `MAX_REPLACES` names or names not ascending, repeated or not 32 bytes, a `sealed` part whose length less 40 is not a power of two from 256 to 2^21 (for a cleanup, 256, 512 or 1 024), a cleanup with no group or more than `MAX_CLEANUP_GROUPS`, with no name or more than `MAX_CLEANUP_ENTRIES`, with names not ascending within a group, repeated or not 32 bytes, or a `because` neither empty nor 32 bytes, a signature that is not 64 bytes, an encoded `SignedRecord` over `MAX_INDEX_RECORD_BYTES`, an `IndexRequest` whose `epoch` is 0 or whose `since` is above `MAX_LOCAL_SEQ`, an `IndexRecords` or `ReconcileReply` whose `epoch` is 0 or whose `through` is above `MAX_LOCAL_SEQ`, an `IndexRequest` or `ReconcileRequest` whose `request_id` is 0, an `IndexRecords` page of more than `MAX_PAGE_RECORDS` records, an `IndexRecords` push with `more` or `reset` set, an `IndexRecords` page with `more` set and no records, a page with `reset` and records, `more` or `through`, a `ReconcileRequest` whose `prefix` is over 128 bytes or holds a value above 15, a `ReconcileReply` whose `outcome` is not 1 to 3, whose `children` are not exactly 16 digests of 32 bytes on `CHILDREN` or are present on another outcome, or that sets `through` for a prefix other than the root, a reply part of the wrong kind for its request (4.5, "Replies and pushes"), a second request for a folder before the reply to the first has queued its end, a page or reply whose `request_id` names no outstanding request, a `ChunkReply` for no outstanding request or with `data` over 4 325 416 bytes, a Status whose `device_name` breaks its grammar | `Close(PROTOCOL_ERROR)` |
| Frame over the limit | `Close(MESSAGE_TOO_LARGE)`, nothing allocated |
| Unknown critical type | `Close(UNSUPPORTED_CRITICAL_TYPE)` |
| Unknown non-critical type | `Unsupported`, at most once per type per connection (later frames of that type ignored with a log line); continue |
| No common suite; `max_message_size` below the floor | `Close(NO_COMMON_SUITE)`; `Close(LIMIT_TOO_SMALL)` |
| DeviceProof does not verify | `Close(PROOF_REJECTED)` |
| `HELLO_TIMEOUT`, `IDLE_TIMEOUT` or `REPLY_PAGE_TIMEOUT` (an outstanding reply brought nothing, 4.5) elapsed; `PROOF_TIMEOUT` elapsed with nothing opened, or, on a punch-only circuit, a requester refused after the admission handshake started (3.1) | `Close(TIMEOUT)`; `Close(NO_COMMON_FOLDER)` |
| **Forged**: an index record or cleanup that is neither a duplicate, nor expired, nor obsolete, or that a write holder verifies before noting it as a stale copy or forgotten record, and whose signature does not verify under the folder key with its record type's label (4.4 steps 3 to 5); a chunk whose ciphertext hash fails | `Close(VERIFICATION_FAILED)`; issue naming the peer |
| **Sender violation**: a record in a `RECORDS` reply whose key in the set digests (its path tag and record hash, or a cleanup's record hash twice) does not begin with the request's prefix; a `CHILDREN` reply for a 128-nibble prefix or to a request whose digest was 32 zero bytes; a `RECORDS` reply carrying more than `RECONCILE_LEAF_MAX` records for a prefix shorter than 128 nibbles to a request whose digest was not zero (4.5, "Serving a `ReconcileRequest`") | `Close(PROTOCOL_ERROR)`, before and whatever the signature |
| FolderProof fails for any reason (hint, seal, payload, the folder's suite missing from the peer's Hello, the open-folder bound; at a device to be reached that takes the circuit for punch-only, any proof past the fourth, unexamined, 3.1) | `ProofResult(REJECTED)`, keep; nothing of any folder is sent before it is open |
| **Duplicate** (an index record whose `record_hash` is already held) | Ignore without verifying, keep |
| **Expired** (at a read or write holder, a tombstone or tree delete that the folder's own time has passed by `TOMBSTONE_HORIZON`, or a cleanup it has passed by `CLEANUP_HORIZON`, 4.4) | Ignore without verifying, keep; a log line; a write holder that would note it as a forgotten record (no note of it, nothing it holds names it, the peer within `MAX_PEER_NAMES`, the connection within `MAX_NOTE_VERIFICATIONS`) verifies it first, notes it if it verifies, and names it in its cleanup at the round's end (4.5, "Stale copies") |
| **Obsolete** (a record that something held replaces, by a name or a cleanup group that applies on every tier, by coverage or a tree delete above it at a read or write holder, and that replaces nothing held, 4.4 step 3) | Ignore without verifying, keep; a write holder that would note it as a stale copy (no note of it, nothing it holds names it, the peer within `MAX_PEER_NAMES`, the connection within `MAX_NOTE_VERIFICATIONS`) verifies it first, notes it if it verifies, and names it in its next write of the path or its cleanup at the round's end (4.5, "Stale copies") |
| **Replaces held records** (a record that names or covers records held, a tree delete that covers records held, or a cleanup whose groups apply to records held, 4.4 step 6) | Verify; drop what it replaces; hold it unless something held replaces it; keep; no issue, no blame |
| **Cleanup group waiting** (a cleanup group whose `because` names a record not held, 4.4 "Cleanup": not yet, or no longer) | Hold the cleanup; the group applies while that record is held, and not otherwise; keep |
| **From the future** (at a read or write holder, a record whose sealed counter is more than `CLOCK_RULE_LIMIT` ahead of this device's clock: the clock rule, 4.4) | Verify (once per record per connection, at most `MAX_FUTURE_KNOWN` remembered); neither hold nor relay; the clock-rule issue "a record dated more than a year ahead of this device's clock", naming the device ID the record claims as where it came from, with the remedy; a forged one closes as forged; keep |
| **Clock out of range** (the two Hellos' `clock_days` differ by more than `CLOCK_RULE_LIMIT`, judged when the first folder opens on the connection, 3.2) | `Close(CLOCK_OUT_OF_RANGE)` before any record of the folder crosses; the clock-rule issue for that folder naming the peer's device ID, both readings and the remedy; a peer that opens no folder is only counted in a log line |
| **Reset** (an `IndexRequest` whose `epoch` is not this side's, or whose `since` is above its local sequence, 4.5) | Answer one page with `reset`; when `since` was above the local sequence, draw a new epoch; the requester reconciles; keep |
| **Digest differs** (a `ReconcileRequest` whose digest is not this side's, 4.5) | Answer `CHILDREN` or `RECORDS`; the requester descends; keep |
| **Empty push** (the sender dropped pushes, 3.1) | Stop counting the peer's pushes; owe a round: it starts once no round is under way and no sooner than `INDEX_RESYNC_INTERVAL` after the previous owed round (4.5); keep |
| **Writer fault**: a seal that will not open, bad padding (non-zero, or past the least power of two that holds the metadata), malformed path, a path whose tag is not the record's `path_tag`, unknown kind, a directory with chunks, a file that is not a tombstone with `size > 0` and no chunks, or hash-count mismatch; a chunk with a correct ciphertext hash whose length, seal, padding, compression or plaintext hash fails, judged per record that names it | Issue naming the record, never a device (ruling S-4); hold the record opaque (not applied; it covers nothing, goes only by a name, which the next write at its path gives it unless the fault is only an unknown kind, and moves neither the high-water mark nor the folder's time) or mark the chunk corrupt for that record; keep |
| `CHUNK_BUSY` | An ordinary answer: the requester sends no chunk request on that connection for `CHUNK_BUSY_BACKOFF` (one timer per connection) and may ask other peers (4.6); keep |
| `CHUNK_NOT_FOUND` | An ordinary answer: no state is kept for the hash; the pass to that peer goes on, and the requester asks other peers for the chunk; the next pass to that peer waits for a greater `chunks_stored` in its Status or a completed round with it, and at least 1 s (4.6); keep |
| A record under this device's own device ID with a counter above its high-water mark (`counter > hw`; 4.5, "Durability before transmission") | Hold and apply as any record; the high-water mark rises to it; a new index epoch; informational issue naming no one; keep |
| A record whose counter is more than `CLOCK_AHEAD_WARNING` ahead of this device's clock (4.4, "A fast clock carries forward") | Judge it as any record; once its signature has verified and it is held, the informational issue "this folder's time is N ahead of this device's clock (first seen on a record claiming device X)", which blames no device; keep |
| A device's next counter would pass `MAX_COUNTER` (4.4) | Write nothing more in the folder; issue saying the folder must be shared again; keep syncing what others write |
| **Store failure**: this device's own index store cannot take a change whose record's signature verified (the disk is full, an I/O error) | Nothing is stored and nothing changes; the folder pauses until its store takes records again (the engine's to detect), accepting none of its records meanwhile (each of them skipped: no cursor moves past it and no pass that skipped one is quiet, 4.5), so that no peer can make this device verify the same record again and again (TM-22); no round of the folder starts while it is paused; a store that cannot stage atomically is reopened before the folder resumes (4.7 item 1); on resuming, the device owes each connection where the folder is open a round, which brings back the records it refused (decision); issue naming the cause; keep |
| **Stored record fails its check** when the folder opens: a record in this device's own index store that fails step 1 against the folder or whose signature does not verify under the folder key, or a base kept only as a base that fails the same checks (4.4, "Opening a folder"; the owner's decision of 2026-10-25) | Drop it: nothing of it is applied, held, counted or served (a failing copy beside a passing copy of the same record hash is dropped without a report); the open reports it by record hash and draws a new index epoch; the engine's folder state (not the Status message) shows the count, and one issue gives the count and at most 16 of the hashes (a fixed engine constant), never a device; index sync fetches the genuine ones again from peers; no connection is involved |

- **Time** comes from a clock trait (wall time, as the device believes it, for the LAN beacon
  window, the clock floor of new counters, the clock rule, the age of per-peer state, the window of
  `MAX_PEER_NAMES` and informational fields; monotonic time for intervals; expiry uses no clock but
  the folder's own time, 4.4) and the network from a transport trait, so every rule here is testable
  without sleeping. The constants are fixed by this protocol, since a peer enforces some of them
  (the intervals, the bounds) and every peer must agree on others (the deletion horizon, the clock
  rule); the simulator may scale them, all peers alike. Each is defined once, in the protocol crate,
  and the engine and the runtime import it rather than define their own; `MAX_SEND_QUEUE`, which the
  runtime enforces (3.1), included.

| Constant | Default |
| --- | --- |
| `HELLO_TIMEOUT` (channel up → peer's Hello and DeviceProof) | 10 s |
| `PROOF_TIMEOUT` (DeviceProofs → first open folder; not on a punch-only circuit, where the punch attempt's 10 s bounds the admission handshake, 3.1) | 30 s |
| `IDLE_TIMEOUT` (no frame in either direction, Status counting; also, while unsent bytes remain, the longest a connection may go without delivering one, 3.1) | 5 min |
| `STATUS_INTERVAL` | 30 s |
| `REPLY_PAGE_TIMEOUT` (the longest a requester waits for the next part of the reply to its outstanding request, counted from when the request left its send queue and restarted by every part of a reply to its own requests, every `CHUNK_OK` reply to its own chunk requests and every push that brings a record it holds; past it, `Close(TIMEOUT)`, 4.5) | 10 min |
| `INDEX_RESYNC_INTERVAL` (minimum gap between the starts of owed rounds, per folder per connection, 4.5) | 10 s |
| `INDEX_REQUEST_MIN_INTERVAL` (a responder serves a folder's `IndexRequest`s and root `ReconcileRequest`s on a connection at most this often, delaying, never refusing, the rest; 4.5) | 1 s |
| `MAX_SEND_QUEUE` (unsent bytes per connection; the runtime may end a connection past it, senders pace below it, and a chunk request the holder dispatches with half of it unsent is answered `CHUNK_BUSY`, 3.1, 4.6) | 128 MiB |
| `CHUNK_BUSY_BACKOFF` (how long a requester sends no chunk request on a connection after a `CHUNK_BUSY`; doubled, up to 64 s, by a `CHUNK_BUSY` for a request sent after the current backoff ended, back to 1 s after a `CHUNK_OK`; one timer per connection; also the least wait before the next chunk pass to a peer that answered `CHUNK_NOT_FOUND`, 4.6) | 1 s |
| `MAX_PAGE_RECORDS` (records per `IndexRecords` page or push; the cap on `max_records` and the receiver's bound, 4.5) | 4096 |
| `MAX_VECTOR_ENTRIES` (entries in a record's vector, and records a write covers at once, 4.4) | 32 |
| `MAX_COUNTER` (the largest counter, 4.4) | 2^62 |
| `CLOCK_FLOOR_MAX` (the most the clock floor of a new counter may be, 4.4) | 2^61 |
| `CLOCK_AHEAD_WARNING` (a received counter this far ahead of the local clock raises an issue; a stored high-water mark this far above what the records and the clock justify is corrupt, 4.4) | 1 day |
| `TOMBSTONE_HORIZON` (the deletion horizon: a tombstone or tree delete expires at a read or write holder once the folder's own time passes its counter by this, 4.4; the same on every device) | 365 days |
| `CLEANUP_HORIZON` (a cleanup expires at a read or write holder once the folder's own time passes its counter by this, 4.4) | 30 days |
| `CLOCK_RULE_LIMIT` (the clock rule: a peer whose clock differs from this device's by more, or a record whose counter is more ahead of it, is refused, 3.2, 4.4; a different rule from the deletion horizon) | 365 days |
| `MAX_REPLACES` (names in an index record's `replaces`, 4.4) | 64 |
| `MAX_CLEANUP_ENTRIES` (names in one cleanup record, 4.4) | 16 384 |
| `MAX_CLEANUP_GROUPS` (groups in one cleanup record, 4.4) | 1 024 |
| `MAX_STALE_KNOWN` (stale copies and forgotten records a write holder notes per folder, 4.5) | 65 536 |
| `MAX_NOTE_VERIFICATIONS` (records a write holder verifies for notes per connection per `INDEX_RESYNC_INTERVAL`, one budget shared by every folder open on the connection, 4.5) | 4 096 |
| `MAX_PEER_NAMES` (records of one peer's that a write holder names, in writes and cleanups, per window of `CLEANUP_HORIZON` by its wall clock, 4.4, 4.5) | 1 048 576 |
| `MAX_FUTURE_KNOWN` (record hashes of refused records from the future a device remembers per folder on a connection, 4.4 step 4) | 1 024 |
| `MAX_LOCAL_SEQ` (the largest local sequence number, 4.5) | 2^62 |
| `RECONCILE_LEAF_MAX` (the most records a subtree holds in leaf form, 4.5) | 64 |
| `MAX_RECONCILE_PASSES` (reconcile passes in one round, 4.5) | 4 |
| `MAX_PASS_REQUESTS` (`ReconcileRequest`s in one pass, 4.5) | 65 536 |
| `PEER_STATE_HORIZON` (per-peer state kept without a round that ended, 4.5) | 90 days |
| `MAX_PEER_STATES` (per-peer states kept per folder, 4.5) | 4096 |
| `MAX_PROOFS_PER_CONNECTION` (FolderProofs a verifier accepts on one connection, four times `MAX_OPEN_FOLDERS_PER_CONNECTION`, since a prover may hold folders the peer no longer holds; one more is malformed, 3.5 step 1) | 256 |
| `MAX_OPEN_FOLDERS_PER_CONNECTION` (a proof past it is REJECTED, 3.5 step 6) | 64 |
| Default `max_requests_in_flight` | 64 |
| `MAX_REQUESTS_IN_FLIGHT` (the largest `max_requests_in_flight` a Hello may advertise; larger is treated as this, 2, 4.6) | 1 024 |
| `MAX_CHUNK_PLAINTEXT` | 4 MiB |

The drafts' `KEY_RESYNC_INTERVAL`, `MAX_HELD_GRANTS_PER_CONNECTION`, `MAX_WRITERS_PER_FOLDER`,
`MAX_DEVICES_PER_KEY`, `MAX_KEY_RECORDS_PER_FOLDER`, `MAX_KEY_RECORD_BYTES_PER_FOLDER`,
`MAX_KEY_RECORDS_PER_SIGNER`, `MAX_REFUSED_REMEMBERED`, `MAX_KEY_RECORD_BYTES` and
`MAX_FOLDER_RECORD_BYTES`, and the 1 024-entry version vector, are gone; so, since 2026-10-25, are
`MAX_CURSORS_PER_REQUEST`, `MAX_MARKED_WRITERS`, `MAX_SUPERSEDES` and `MAX_SEQ`, with the cursors,
ranges, marks, `supersedes` and per-writer sequences they bounded, and `MAX_PROOF_COMPONENTS`, with
the chains and `Covered` messages of an earlier draft of that day.

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
- Index records follow the same optional-field rule: new metadata is a new field in `IndexRecord` or
  `SealedMeta` that old peers store and forward unread, because verifiers never re-encode a body
  (`keys.md` §5.2). A new value of `SealedMeta.kind` is different, since an older release treats a
  kind it does not know as a writer fault and holds the record opaque (4.4, release skew): such a
  record covers nothing and goes only by a name, where a newer release judges it by its vector, so
  the two can hold different records at that path, and the older shows no version for it; a kind
  added before 1.0 joins major 1's baseline, and one added after 1.0 needs a folder-level
  requirement first. A new clear field that changes what covers what, or what a record deletes,
  changes what peers hold and needs a new major.
- Step 7's checks other than the one on `kind` never change within major 1. Releases name each
  other's shared writer faults (4.4, "Its names"), so relaxing one of those checks would let an
  older release name, and every tier drop, a record that a newer release applies; relaxing one needs
  a new major. Making one stricter would split peers the same way, and needs a new major too. The
  compatibility matrix tests both directions (section 8, item 14).
- The twin rule (4.4, "Bases") never changes within major 1: which records hold one content (the
  kinds and `plain_hashes`, tombstones of any kind, never a tree delete), and that a twin is
  concurrent with its base and, for the base at the path, not ahead of it in display order, and
  never the first head in display order. A write covers and names the twins of what is on its
  writer's disk, so a release that judged twins otherwise (counting the mode, or
  a new optional field of `SealedMeta`, as content, say) would have its writers silently cover what
  an older release shows as a conflict, or keep as a conflict what the older covers; changing it
  needs a new major.
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
- Index records with file IDs, names and sealed counters, vectors and pruning, coverage, latest only
  on read and write holders and the sealed-peer rule on sealed ones, bases, tombstones, tree
  deletes, cleanups, stale copies, expiry by the folder's own time and the clock rule (the
  simulator's per-peer wall clocks with injectable skew); heads (a conflict is two heads; the
  conflict copies on disk are phase 1's); sealed metadata.
- `IndexRequest`, `IndexRecords`, `ReconcileRequest` and `ReconcileReply` with rounds,
  epochs, cursors and their counting, set digests and their cache, reconciliation passes, pages,
  pushes from open, empty pushes and the round owed; duplicates, expired and obsolete records
  ignored unverified; per-peer state and its horizon.
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
of items 6, 8, 9, 11, 12 and 13. The **index** crate checks what a record does to a store: in item 6
each record's outcome (duplicate, expired, obsolete, held, replacing, opaque, from the future, a
record under the device's own ID); item 7 (latest only, coverage, tree deletes, expiry, heads and
the property tests), but for its cases marked for the engine; in item 8 the set digests, their cache
and serving; and in item 12 the sealed-peer rule and every cleanup outcome. The **engine** crate
checks what a connection then does: the connection vectors of items 6 (closes, issues), 8 (rounds,
epochs and resets, the descent, cursors and counting, the round owed, pushes, pages, per-peer state,
intervals and timeouts), 9 (busy answers, the backoff, passes, serving and attribution), 11
(`chunks_stored` and how often it is sent), 12 (when a cleanup is written and sent) and 13 (the
clock rule at the handshake); the cases of item 7 marked for it (the archive's copies and the
warning, phase 1); and, with `net` from phase 2, item 15 (relayed connections); item 14 runs in the
integration suite's compatibility matrix. The **keys** crate checks what `keys.md` §9 lists, the
shared inputs included.

**Two shapes.** A **decoder vector** is a frame or body and its expected outcome (accepted, with the
decoded value, or the row that refuses it). A **connection vector** is a scenario run against one
side, the side under test, with the other side scripted: (1) the **starting state**: both sides'
keys and Hellos, the folders each holds and which are open, each side's records, local sequences,
epochs, high-water marks, per-peer state, stale-copy notes and flags, the unsent bytes, and the
monotonic and wall clocks; (2) the **frames in**, each with the monotonic time at which it arrives
(and, where it matters, how far the side's unsent bytes have fallen by then); (3) the **frames out**
the side under test must send, each with its time, and nothing else; (4) the section 5 **row** of
each outcome; and (5) the **end state**: records held, cursors, set digests, heads (for a side that
opens seals), stale-copy notes, the empty push and round owed, issues raised, and whether the
connection is open or closed and with which reason. Times are explicit so that every timeout and
interval in section 5's constants is a vector.

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
   including one pair where the dialer is B), the largest Hello (2 668-byte frame, `clock_days`
   2 097 151), and each failing variant (a `clock_days` of 2 097 152, a device key of 1 986 bytes,
   the drafts' hybrid form, and of 33 bytes; a device key that is a non-canonical encoding of a
   valid point, and one of small order; missing `none`, missing `blake3`, limit below the floor, no
   common suite, a suite entry of 0 and one of 65 536, 17 suites, bad identity length, bad feature
   grammar, equal device keys); a second Hello (`Close(PROTOCOL_ERROR)`).
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
   what the connection does): canonical body, record hash, signature and sealed part (fixed nonce,
   the 64-byte aad) for a new file (empty vector, no names), an edit of it (one entry, one name), a
   directory, an empty file, a tombstone, a rename (the version at the new path, then the tombstone
   at the old), a tree delete, a record with 32 vector entries and one with 64 names, and a cleanup
   of two groups (one with `because`, one without); decoder variants for every row of section 5's
   table that an index record or cleanup can reach: malformed (`suite` 0, a `suite` other than the
   folder's, `record_type` 1 and 18, a `path_tag` of 31 bytes, 65 names, names out of order, a
   repeated name, a name of 31 bytes, a chunk whose `stored_len` is not a Padmé length plus 40, a
   `sealed` of 295 bytes, one of 297 and one of 2^21 + 41, a cleanup with no group, with 1 025
   groups, with 16 385 names, with a `because` of 31 bytes, a signature of 65 bytes, a record one
   byte over `MAX_INDEX_RECORD_BYTES`); writer faults inside the seal, each held opaque and named by
   an issue (`counter` 0 and `MAX_COUNTER` + 1, with `MAX_COUNTER` itself accepted, a `device_id` of
   31 bytes, `deleted` with chunks, `tree` without `deleted`, 33 vector entries, a vector entry of
   31 bytes, two entries for one device, entries out of order, an entry whose counter equals the
   record's `counter`, with one just below it accepted, and an entry with counter 0); forged (a bit
   flipped inside a bytes field of the body, so that it still parses; a record signed by another
   folder's key). Connection vectors: an exact duplicate whose signature bytes are garbage (ignored,
   not verified, the connection open); an obsolete record with a forged signature (ignored, not
   verified, open) and the same record covering a live record (verified: forged, closed); an expired
   tombstone with a forged signature (ignored, open); a writer fault in the seal (held opaque,
   counted in the digest, replaced only by a name, the issue naming the record); a cleanup signed
   under the index label (forged); writer faults in the metadata: a path whose tag is not
   `path_tag`, a directory with one chunk, a file with `size` 5 and no chunks, and a path that is
   not NFC (accepted, not a fault: a distinct path with a tag of its own); a forged record that
   would also be a writer fault (forged wins); a record under the receiver's own device ID above its
   high-water mark (the mark raised to it, a new epoch, the informational issue) and one at it
   (nothing); a record whose counter is one day and one microsecond ahead of the receiver's clock
   (held, then the issue "this folder's time is … ahead", naming its device ID as where it was first
   seen) and one exactly a day ahead (no issue), and the first with a forged signature that is
   obsolete (ignored unverified, no issue); a record whose vector fails step 7 (an entry equal to
   its counter) and that a held record would cover by that vector, in both arrival orders (verified
   and held opaque both times, covering nothing and covered by nothing); a sealed part padded one
   power of two past what its metadata needs (writer fault); the counters of a commit of a version,
   a tree delete, two tombstones and a cleanup (consecutive, in that order, each kind by ascending
   path tag); a tree delete of `kind` 1, and one of `size` 5 (shared writer faults, held opaque,
   named by the next write at its path).
7. **Latest only, coverage and heads** (index; on a read holder and a write holder unless named; one
   path each unless named): file IDs for three fixed paths (shared with `keys.md` §9); coverage: an
   edit covering the one head (one live record, the old one dropped); two edits of one head (two
   heads, a conflict: the greater `mtime_ns` at the path; on equal `mtime_ns`, the smaller record
   hash); a write covering both (one head again); two records with one dot and different bodies
   (both held, a conflict, no matter their vectors); a record whose vector gives a device a counter
   one below another record's (not covered) and equal to it (covered); arrival order: an edit
   arriving before the version it covers (the version, arriving after, is obsolete and ignored), and
   every order of a chain of three edits by three devices (one head at the end, the same on every
   order); each case of the display order and of "content differs": a file and a tombstone (the file
   shown, no copy), a file and a directory (the directory shown, the file a conflict copy, whatever
   their times), two files with different `plain_hashes` (one copy), two files with the same
   `plain_hashes` and different modes and times (no copy), two directories (no copy), only
   tombstones (the path deleted); pruning: a line of versions by 40 devices in turn (each vector at
   most 32 entries, the 40th's with the 7 smallest counters dropped, each version covering the one
   before), a device holding the 5th version receiving the 40th (both heads: the spurious conflict,
   nothing dropped) and one holding the 20th (covered, dropped), and a write over 33 heads (32
   covered, one left a head); 32 heads written over by one write (all covered: the mandatory entries
   fit); a restored device: D's index restored from before its edit R1, D edits again while its peer
   holds R1 (after the exchange both hold two heads, a conflict, nothing lost, and D's high-water
   mark has moved past R1's counter); **the lost update**: a device holds V2, which covers V1, but
   its disk still holds V1 (V1 its base), and the person edits the file: the edit W covers V1 only,
   V2 and W are both heads (a conflict), V1 is kept as a base until V2's content is applied and is
   never served or counted in a digest, and the file on disk stays V1 until the commit that applies
   new content; the same with a scan's tree delete of the directory holding the path (V2 survives
   the delete, a file that comes back); **twins** (the identical-heads fix of 2026-11-08): two
   devices that write one file with the same `plain_hashes` apart, then a save by either, the one
   whose twin sits at the path or the other (the save names and covers both: one head, no copy, on
   both devices), the same with different `mtime_ns`, with three devices, with a delete and with a
   rename (nothing left at the path but the tombstone), two identical directories under a scan's
   tree delete (both covered, no head left), and two tombstones under a new version (both covered);
   40 twins and a conflict copy under one save by the device whose own twin is last in display
   order (`S` its two bases, then its own twin, then the next 29 twins in display order; the nine
   left are heads, conflict copies of the old content, until the next save, made with them on the
   disk, covers them), and 40 twins under a delete (32 covered, the file back until the next
   delete); what is no twin: a later version of the base with its content, still arriving, that
   changed only its mode, at the base's `mtime_ns`, a later one or an earlier one, under a save
   and under a delete (both heads, a conflict), a concurrent version of the base's content that
   comes first in display order and that the engine has yet to put at the path (both heads), the
   same coming after the base but first among the heads, the base replaced by a later version still
   arriving, of its content or other, under a save and under a tree delete (it and that version
   heads beside the write), and a concurrent version of a conflict copy's content first in display
   order (a head beside the save), a later
   version of a conflict copy's content (a head beside the save), a twin arriving after the write (a
   head, a conflict copy of the old content, on every device) and a tombstone beside a live base and
   its twin (a head beside the save); 32 records signed under the writer's own device ID with its
   base's content (the base, another device's, still in `S` and covered); 40 identical directories
   under a tree delete in three display orders (32 named, every one covered by its vector; the eight
   named nowhere left, the directory back, until the next delete takes them), a directory with 71
   conflict copies at its path (deleted, 32 names, the 40 copies past them left), and a folder
   deleted while a file beneath it is still arriving, reached through a twin's dot or a base's
   (deleted: the residual of 4.4 "Why it is safe" 8a); a conflict copy written beside the path (its
   record a base of the path's file ID; after a write over the conflict, the base of its own path,
   and no longer of the original); a store whose greatest counter lies more than `CLOCK_RULE_LIMIT`
   ahead of the clock at open, after the clock was set back (the folder does not open, the issue
   says the records are dated more than a year ahead of the clock, nothing is removed, the
   high-water mark kept), the clock then passing the time it needs while the device runs (the folder
   opens then, without a restart, nothing lost), and the same store opened after the clock is right
   (opens); **an archived version from a fast clock** (the re-confirm review of 2026-11-10): V,
   written on a device whose clock was more than a day fast, its counter more than
   `CLOCK_AHEAD_WARNING` above every other counter held and the clock floor, archived on a fault F
   (at open the stored mark, at V's counter, is accepted, not reported corrupt; the next write's
   counter is above V's, so it covers and names V and names F, and every device holds it, no writer
   fault), and a store whose only counter more than `CLOCK_RULE_LIMIT` ahead of the clock is an
   archived version's (the folder does not open); **no heads from opaque records**: a version V on
   the disk, then a record N of an unknown `kind` that names V (V dropped, the path's base none, the
   file off the disk, to the archive, and V kept as an archived version) and the same two records in
   the other order (the same disk); a shared writer fault F that names V (the same, and the next
   write at the path, with `S` V's archived version, covers and names V and names F, which every
   tier then drops); a tree delete held at that path besides (the base is the greatest tree delete
   held there, by record hash); N naming V but not V's twin T (T a head: the file stays, nothing
   archived or remembered); N naming one head of a conflict, V1 at the path with V2 as its conflict
   copy (V2 the one head, at the path, no copy, V1's file to the archive as a replaced version,
   nothing remembered); N naming both heads, V1 at the path and V2, whose conflict copy a write over
   the conflict elsewhere has made a version Q at the copy's own path, delivered Q then N (the copy
   on the disk is Q's base at its own path and stays; only V1's file goes to the archive) and N then
   Q (the copy goes to the archive with V1's file, then Q is put at its own path: the same disk at
   the end of both orders); **the returning device** (the owner's decision of 2026-11-10): D
   archives V on F, E missed F and holds V on its disk, and D's person restores V from the archive
   and saves it unchanged (D's write W covers and names V and names F; E, receiving W, drops V as
   covered and keeps W's content, with no conflict copy, and a sealed peer that held V drops it by
   W's name), the same with F reaching E before W (E archives V and keeps it as an archived version,
   its copy kept with the warning; W then covers V, which drops E's archived version and ends the
   keep: the same disk at the end), the same saved with changed content (the same, E's old file
   going to its archive), and E's own edit V2 of V, made while it was off (V2 a head beside W, a
   conflict copy: the stated residual); an archived version dropped when a version this release
   reads arrives at the path and covers it, when one arrives that names it, when this release comes
   to read N (a newer release reopening the store), and when an applied tree delete above the path
   covers it, and one that the folder's time does not drop (past `TOMBSTONE_HORIZON` after its
   archiving, the next write there still covers it); **an archived version held again** (the confirm
   review of 2026-11-10): F dropped by a write Y made elsewhere that names F and does not cover V,
   then V offered again (V held, its archived version dropped, its copy kept until V is back on the
   disk as a base; the next write's `S` holds V once and its `replaces` names V once); **a second
   loss of heads**: after F took V, a concurrent version X that does not cover V arrives (X on the
   disk, V's copy and the warning kept, V still an archived version), then a fault F2 that names X
   (X archived beside V; the next write covers and names both, ending both keeps); a tree delete
   written over a directory with V's archived version beneath it (its vector covers V and its
   cleanup names V; V's archived version dropped and the keep ended; E, which missed F, drops V on
   receiving it, and a sealed peer by the cleanup), and the same with more than 32 device IDs
   beneath the directory, the pruned vector leaving V uncovered (no tombstone at V's path, no
   cleanup naming V, V still an archived version with its copy kept: the stated residual); an
   archived version that fails its check at open (dropped and reported; the next write at the path
   does not cover V, so E keeps V beside it, a conflict; the copy kept until that write); 40
   archived versions under one write (32 covered and named, the eight left for the next write); an
   old release's tree delete over a directory beneath which one path holds only N (the tree delete
   neither covers nor names N, nor does its cleanup; on the old release the directory leaves the
   disk, kept by no opaque record, and N stays opaque; on a release that knows the kind, N is a head
   and its file comes back with the directories it needs, unless the tree delete's join reached a
   later record of N's device beneath the directory, 4.4 "Why it is safe" 8a); for the engine (phase
   1): the copies archived on a fault, kept past the archive's retention, and with versioning off,
   while a head that does not cover their version is held at the path, until this device saves at
   the path (the keep ended, the copy then under the archive's retention, or gone at once with
   versioning off), until a version from elsewhere that covers theirs arrives, until this release
   reads N, or until their version is a base again; and the warning's text on a write holder (saving
   ends the keep, so restore first), on a read holder, for an unknown `kind`, and with no record
   this release cannot read left at the path (F named by a write Y made elsewhere that does not
   cover V: the warning names no record, and V's copy and the warning stay until a save covers V); a
   base that fails its check at open (dropped and reported, the next write covers nothing, a
   conflict); a rename (the old path's only head a tombstone, the new path one version)
   and the same two records delivered in the other order; an opaque record beside the one head (both
   kept; the next write at the path names it, a shared writer fault, and every tier drops it), 70
   shared writer faults at one path (the next write names its bases and as many as fit 64 names, and
   a cleanup `because` it, in the same commit, the rest), and a record opaque here only because its
   `kind` is unknown (the next write here neither names nor covers it; on a release that knows the
   kind, the two are heads, a conflict); tree deletes: one over a directory of three files and a
   subdirectory (every record beneath it dropped on a read holder, and the cleanup written with it
   naming the four), a version beneath it written concurrently (kept, a head), a version beneath it
   whose device's later record the deleter held (dropped: the residual of 4.4 "Why it is safe" 8a),
   the rename within the directory of that residual delivered tombstone first, nested tree deletes
   (a second tree delete of the same directory covering the first, which its cleanup names; a tree
   delete of a parent covering one of a child), a tree delete whose pruned vector misses a held
   record (the tombstone written after it), and a new file written beneath it afterwards (kept); a
   tree delete over a directory of 20 000 held files judged by the index (obsolete or not with at
   most two queries per vector entry and no walk, the same verdict as a walk), one at `d` beside
   held records at `d-x`, `d.x`, `d0` and `d/x` (only `d` itself and `d/x` beneath it), and one that
   covers only an earlier tree delete beneath its directory (not obsolete: it replaces that one);
   expiry by the folder's own time: a tombstone whose counter the greatest counter held exceeds by
   one microsecond less than `TOMBSTONE_HORIZON` and one by one microsecond more (kept; dropped, and
   ignored when it arrives again), the same on two devices whose wall clocks differ by six months
   (the same outcome on both), a cleanup past `CLEANUP_HORIZON`, a folder with no write for two
   years (nothing expires), a record 11 months ahead raising the folder's time (deletions older than
   that time less the deletion horizon forgotten at once), and the version a tombstone covered
   offered again after the tombstone expired (live again: the deleted file reappears); the clock
   rule: a record whose counter is `CLOCK_RULE_LIMIT` plus one microsecond ahead of the receiver's
   clock (verified, refused, not relayed, the issue) and one exactly at it (held); the spread: three
   read or write holders whose clocks are 300 days ahead, right, and 70 days behind (every pair but
   the first and the last synced at the handshake), where the right one accepts the fast one's
   record and the slow one then refuses the right one's next record (the issue naming no culprit),
   and the folder's time on the two sides. Property tests (`proptest`) over random histories of
   writes (some made while a version of the path is still arriving), directories made, deletes, tree
   deletes and renames by up to 64 devices, twins among them, with random pruning, arrival orders,
   exchanges, expiry, cleanups and replays of old records: (a) no record is dropped except by a
   record that knows it or a later record of its device at its path or beneath the deleted directory
   (4.4 "Why it is safe" 3 and 6); (b) no record covers a record that knows it (4.4 "Why it is safe"
   4); (c) with pruning on, the records dropped are a subset of those dropped with pruning off, on
   the same history (5 and 7); (d) the live records, the expired ones, the heads and the records
   refused depend only on the records held: not on their order, nor on records held and dropped
   before, nor on any device's clock within the clock rule (two devices fed the same records in
   different orders, one of them after holding and dropping a cleanup group's `because`, judge every
   further record alike); (e) any two read or write holders that end caught-up rounds with each
   other hold the same records and heads (4.5, "Why it converges"), within `MAX_RECONCILE_PASSES`
   passes or over the rounds owed after, with each device's wall clock random within the clock rule;
   (f) a sealed peer drops a record only when a held record or a held cleanup group that applies
   names it (4.4 "Why it is safe" 11); (g) once replays stop, a sealed peer that a write holder
   meets holds the same records as that write holder after the rounds its cleanups owe, short of
   stale copies that a cleanup the write holder holds names in a group that no longer applies, which
   follow once the folder's time has passed that cleanup by `CLEANUP_HORIZON` (in the author's model
   of these rules, with vectors pruned to 3 entries, at most four rounds, and two after such a
   cleanup is forgotten); (h) a cleanup replayed at any later point removes no record written after
   it (12); (i) two records with one dot are both held on every tier, and two devices that hold one
   each find the difference and end holding both (13); (j) a reopen of the store gives the same
   index; (k) no local write or scan's tree delete covers a held version whose content was not on
   the writing device's disk (a base there, a twin of one, or an archived version), unless a base or
   twin there covered
   it or is a later record of its device there, for a tree delete at or beneath its directory (4.4
   "Why it is safe" 9 and 8a); (l) for every tree delete, the index of 4.4 "Judging a tree delete
   without a walk" finds the same held records covered as a walk over every record held beneath its
   directory does, nested tree deletes included (the author's model: 135 470 tree deletes over paths
   that share prefixes, all alike); (m) a device's set digests equal those computed afresh from the
   records it holds, after any sequence of changes; and, at open, a stored high-water mark above the
   greatest counter held (bases and archived versions included) and the clock floor by more than
   `CLOCK_AHEAD_WARNING` is reported corrupt and replaced (a connection-free vector).
8. **Exchange** (index for digests and serving, protocol for the decoder vectors, engine for the
   rest; connection vectors unless noted): set digests of an empty subtree (zeros), a leaf of one
   and of 64 records, a node over 65, 65 records at one tag (node form at its 64-nibble prefix, its
   children split by the first nibble of each record hash), a cleanup's key (its record hash twice),
   and a 128-nibble prefix (at most one record, leaf form); 8 000 records at one tag held one at a
   time and then dropped by one cleanup (each change rehashes at most one leaf of at most 64 record
   hashes and at most 128 nodes, counted, not timed); the cached digests after a record joins and
   one leaves a leaf; serving an `IndexRequest` with a matching epoch and `since` (the records above
   it, in local sequence order, each page's `through`), with nothing to send (one empty page
   carrying `through`), with another epoch and with a `since` above the local sequence (one page
   with `reset`; the second also draws a new epoch); a round with state (since, then the root check
   `EQUAL`) and without (the root check, `CHILDREN`, the descent, `RECORDS`, the requester's pushes
   of what the reply lacked); a requester holding nothing (its root digest zeros: one `RECORDS`
   reply of every record); a responder holding nothing in a subtree (`RECORDS`, one empty page, the
   requester's pushes); a `RECORDS` reply over a subtree of more than one page, among them a file ID
   holding many records (pages in ascending key order, the responder keeping only the last key sent
   between pages); the work list's bound (128 levels, at most 1 921 prefixes); a round whose roots
   stay unequal for `MAX_RECONCILE_PASSES` passes against a responder that lies about its digests
   (the round ends, a round owed, started `INDEX_RESYNC_INTERVAL` later); two devices with different
   histories of one path and records each lacks (equal records after the round); decoder vectors: an
   `IndexRequest` with `epoch` 0 and one with `since` of `MAX_LOCAL_SEQ` + 1, a `ReconcileRequest`
   with a 129-byte prefix and one with a nibble of 16, a `ReconcileReply` with outcome 4, with 15
   children, with children on `EQUAL`, with `through` on a non-root prefix (all malformed); sender
   violations: a `RECORDS` reply carrying a record outside its prefix (closed, whatever the
   signature); paging at `max_records = 64` (a page never holds more than 64), `max_records = 1`
   served as 64, a page cut by `max_message_size`, `max_records = 0` and 5000 both served as 4096, a
   reply with nothing to send (one empty page); a page of 4097 records, an `IndexRecords` push with
   `more = true`, a page with `reset` and a record, a page with an unknown `request_id`, a
   `ReconcileReply` answering an `IndexRequest`, and a second request before the first reply's end
   (all `Close(PROTOCOL_ERROR)`); an `IndexRequest` and a root `ReconcileRequest` within
   `INDEX_REQUEST_MIN_INTERVAL` of the previous one, served once the interval has passed, and
   non-root `ReconcileRequest`s served at once; a push arriving between two pages and told apart by
   `request_id`; **PUSH-2**: a record the responder comes to hold after the folder opened, while the
   requester's round is under way, pushed at once and held at the end; **cursors**: pushes counted
   after a round (the cursor at the last push's `through`), not counted after an empty push, and a
   reconnection that asks from the counted cursor and is sent nothing it already held; **PUSH-1**:
   pushes dropped while the send queue is full, then the empty push, the round owed and the round; a
   second empty push within `INDEX_RESYNC_INTERVAL` of the first owed round's start (the flag kept,
   a second round started once the interval has passed, and the record dropped in between held at
   the end); an empty push arriving while an owed round runs (the next one after it); per-peer
   state: dropped after `PEER_STATE_HORIZON` on a fixed clock (the next round reconciles), and the 4
   097th peer evicting the one longest without a round; a request with the right epoch and `since`
   of `MAX_LOCAL_SEQ`, twice on one connection (a reset each time, a new epoch only the first time);
   a device whose next local sequence number would pass `MAX_LOCAL_SEQ` (renumbered from 1 under a
   new epoch, every peer reconciling once); a pass stopped at `MAX_PASS_REQUESTS` (never quiet, even
   when it brought nothing) and finished by the next one; a pass and a Since reply whose records
   were skipped because the store refused them, and the same while the folder was paused (not quiet,
   no cursor moved, a round owed); a cleanup taking a local sequence number (pushed with its
   `through`, and served in a Since reply); a `CHILDREN` reply for a 128-nibble prefix, one
   answering a zero digest, and a `RECORDS` reply of 65 records at a 3-nibble prefix answering a
   non-zero digest (each a sender violation, closed); a `RECORDS` page carrying `through` and
   requests with `request_id` 0 (malformed); timeouts: a connection whose unsent count has not
   fallen for `IDLE_TIMEOUT` (`Close(TIMEOUT)`), and a long paced transfer whose queue never empties
   but keeps falling (kept open); a reply whose next part has not come `REPLY_PAGE_TIMEOUT` after
   the previous one while Status frames and pushes of duplicates keep arriving (`Close(TIMEOUT)`),
   one whose responder answers every chunk request `CHUNK_BUSY` meanwhile (`Close(TIMEOUT)`), one
   whose next page waits behind `CHUNK_OK` replies to the requester's own requests (kept open), and
   one whose next page waits behind pushes that bring new records (kept open).
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
    them, not fifty); `extra_versions` on a sealed holder with two stale copies and one real
    conflict (3) and on a read holder with that conflict (1); and one whose name holds a control
    character (`Close(PROTOCOL_ERROR)`).
12. **Cleanups and the sealed-peer rule** (protocol for decoding, index for each outcome, engine for
    when a cleanup is written and sent; on a sealed holder unless named): a record that names the
    one version held at its file ID (the version dropped, the record held); one that names nothing
    held (both kept); a stale replay of an old version that no held record names (kept beside the
    head); a stale replay that the held head names (refused as obsolete); the NAS case: V1 held, V3
    arriving naming V2 (V1 and V3 held), then a write holder's round with it (V1 verified and noted
    as a stale copy, the cleanup at the round's end naming V1 `because` V3, V1 dropped and its
    chunks freed), and the same when the write holder writes V4 first (V4 names V3 and V1); a
    cleanup group whose `because` is not held (waiting; applied when that record arrives, and never
    before); a group with empty `because` naming an expired tombstone (dropped); a cleanup naming a
    record not held (nothing; the record refused when it arrives later); a cleanup replayed after a
    later version of a named file was written (the later version kept); a tree delete over 100 000
    records with its seven cleanup records (every record dropped and its chunks freed, the tree
    delete kept); a later cleanup naming an earlier one (the earlier dropped); on a read holder, a
    cleanup naming a record its vectors already replace (no change) and a cleanup naming an opaque
    record (dropped); a read holder that meets a sealed peer holding stale copies (a caught-up
    round, the copies kept, no round owed); two records with one dot reaching two sealed peers one
    each (their digests differ, and both end holding both); a group whose `because` record is then
    replaced by a later version (the group no longer applies: a named record offered again is held
    as a stale copy on a sealed holder until a write holder names it again, and judged by coverage
    and expiry on a read holder); two read holders, one that held a group's `because` and the group,
    and one that received the cleanup after the `because` had expired, offered the record the group
    named (both hold it, or both refuse it, never one each); a replayed old tombstone, offered to a
    sealed holder after the case-(c) cleanup that named it was itself named away (the version it
    names, live at the read holders, dropped there until a write holder's round names the tombstone
    again, then held again); on a write holder (engine): a stale copy offered with a forged
    signature (verified before it is noted: closed), the same copy already named by a held cleanup
    whose group applies (not verified, not noted, no new cleanup, and the round's reconciliation
    sends the peer that cleanup), a peer past `MAX_PEER_NAMES` in the window (not noted, a log
    line), and a round at whose end a cleanup was issued (a round owed, which ends at `EQUAL`); file
    IDs for the fixed paths of `keys.md` §9 item 13.
13. **The clock rule at the handshake** (protocol for decoding, engine for the connection): two
    Hellos whose `clock_days` differ by 365 days (synced) and by 366, in each direction (both sides
    `Close(CLOCK_OUT_OF_RANGE)` when the first folder opens, before any record crosses, the issue
    naming the peer and both readings); the same two Hellos on a connection where no folder opens
    (no issue, a log count, `Close(NO_COMMON_FOLDER)` after `PROOF_TIMEOUT`); a Hello with
    `clock_days` 0 against a present clock (refused when a folder opens).
14. **Compatibility** (the integration suite's matrix of the last two released binaries against each
    build, section 6): a record of a `kind` the older binary does not know, written by the newer
    (the older holds it opaque, shows it as an update it cannot read, and its writes at that path
    neither name nor cover it; the newer holds both as a conflict, or drops the older's write's
    predecessor as usual); the same record written over a version the older had on its disk (the
    older archives its copy and keeps the version as an archived version, which its next write
    there covers; the newer holds that write and its own record as a conflict), and the older's
    tree delete over the directory holding that path (the newer keeps the record, with its
    directories); a shared writer fault at a path, met by both binaries (each binary's next
    write at the path names it, and both drop it); and every check of step 7 but the one on `kind`,
    run on the same fixed records by both binaries (the same verdicts).
15. **Relayed connections** (engine with `net`'s transport, from phase 2; connection vectors; 3.1):
    on a circuit through a public relay, a folder whose public-relays switch is on opens and syncs,
    on the stream the side the circuit reached opens, and one whose switch is off is not proven (no
    FolderProof sent) and its proof is answered REJECTED; with no folder's switch on, no Hello is
    sent; a stream of this protocol opened by the side that dialed through the device in the middle,
    on a circuit either side takes for a public relay's or for punch-only (refused); a circuit
    through a device reserved with only for a punch, and one whose stated limit is 60 s or 64 KiB
    though the device in the middle presents itself as a public relay, are punch-only (the admission
    handshake only); the two sides judging one circuit differently, the device to be reached taking
    it for punch-only and the requester for a public relay's (the requester opening no stream, the
    admission handshake on the stream the device to be reached opens, no folder open on the circuit,
    then the punch), and the other way round (the requester opens no stream and answers the other
    side's FolderProofs REJECTED, so no folder opens on the circuit, and an ACCEPTED proof of its
    own admits it to the punch); on a punch-only circuit, with every public-relays switch off, as by
    default: a requester that is a peer of a folder whose settings allow a punch through that
    coordinator (no handshake: the punch starts at once), one that is a peer only of folders whose
    settings do not (at never, or at a level that does not allow that coordinator: not known, so the
    handshake, in which those folders are paused and its proofs for them REJECTED), an unknown one
    whose FolderProof is ACCEPTED (admitted: no FolderProof sent back, no folder open, and an
    `IndexRequest` after it `Close(PROTOCOL_ERROR)`), one whose proofs are all REJECTED (not
    admitted, no address sent, `Close(NO_COMMON_FOLDER)`, the circuit closed), one still not
    admitted when the attempt's 10 s run out (refused alike), a fifth and a sixth FolderProof from
    the requester (each answered REJECTED, the connection kept, the 257th `Close(PROTOCOL_ERROR)`),
    a requester that takes the circuit for a public relay's and proves five folders at a device to
    be reached that takes it for punch-only (the first four examined, the fifth REJECTED), more than
    four from a device to be reached that takes the circuit for a public relay's, at a requester
    that takes it for punch-only (each answered REJECTED, the connection kept), six requesters
    admitted at once against a cap of 4 in all (the first four admitted, the fifth and sixth refused
    with `Close(NO_COMMON_FOLDER)`, counted toward the caps through their coordinators only), the
    21st admission in a minute likewise, and, on a circuit the side that dialed takes for a public
    relay's, no stream within `HELLO_TIMEOUT` of the channel's set-up (the circuit closed with no
    Close, the session counted as refused: no new one for 1 minute), a requester whose channel's
    peer ID differs from the one the STOP named (refused, no Close), and a STOP from a device in the
    middle that the device holds no reservation with (answered NO_RESERVATION, counted toward no
    cap); the requester's side (it opens no stream of this protocol, runs the handshake only on the
    one the device to be reached opens, proves only folders whose settings allow the punch, and
    answers a FolderProof sent to it REJECTED); six circuits refused at admission within a minute
    through one coordinator (a seventh through it closed with no handshake, and one through another
    coordinator admitted); the peer exchange of a device's coordinators (one listed on a connection
    where a folder whose settings allow a punch through it is open, and not on one where only
    folders that do not allow it are open); a folder's public-relays switch turned off while it is
    open on a relayed connection (`Close(SHUTDOWN)`); a relayed session cut before a round
    completed, twice (no new one for 1 minute, then 2), then a session that completes a round and
    one cut after it (back to 1 minute); a direct connection to the same peer opening with the same
    folders (the relayed one closed with `Close(SHUTDOWN)`); and, on the direct connection a punch
    brought, a folder whose direct-connections switch is off, and one whose hole-punch level does
    not allow the coordinator that timed it, treated as paused (not proven; the peer's proof
    REJECTED). `net`'s own tests carry the rest of `threat-model.md` TM-25 from phase 2: the
    addresses a punch accepts, one test for each block it refuses and for each range that carries an
    IPv4 address, with an embedded address that passes and one that does not, among them (the
    re-confirm review of 2026-11-10) fec0::1, ::192.168.1.1, ::808:808 and 1::1 (outside 2000::/3:
    refused), ::ffff:8.8.8.8 and ::ffff:192.168.1.1 (mapped: both refused), 64:ff9b::808:808
    (passes) and 64:ff9b::c0a8:101 (refused), 192.0.0.9, 192.0.0.10, 192.88.99.2, 2001:1::1,
    2001:1::2 and 2001:3::1 (refused whole with their blocks), an address under a NAT64 prefix of
    the device's own network that it knows, a /96 and a /64 one, carrying 8.8.8.8 (passes) and
    192.168.1.1 (refused), and the same two with no prefix known (both pass: the stated residual);
    an address of the side's own, global IPv6 or public IPv4, and the subnet-router anycast
    (interface identifier 0) and RFC 2526 anycast addresses in each of its own /64s (refused); no
    SO_BROADCAST on any socket a punch uses; the caps, an attempt counted toward the caps in all
    only once its requester is admitted (four circuits in admission at once through two
    coordinators, and a known peer's punch through a third still starts); and a coordinator's bounds
    and answers.

## 9. The index in plain words

This section is for the owner, who does not read Rust; it explains 4.4 and 4.5 with examples, and
relays and hole punching (`threat-model.md` TM-25), and decides nothing. Counters are shown as small
numbers; real ones are clock readings in microseconds.

**What a device keeps.** For each file, only its latest version, as one signed record. Each record
has a **fingerprint**, a 32-byte hash of the whole record that identifies it; in this section the
word means nothing else. Each record carries a short list, its version vector, of the earlier
versions it replaces: "the version that device L wrote at 1000". When a newer record arrives whose
list covers the version a device holds, the device drops the old record. When neither of two
records' lists covers the other, both are kept: that is a conflict, the file shows one of them and
the other becomes a conflict copy. Contents are never merged. Only devices that hold the read or
write key can read that list; devices that hold only the sealed key see far less (below). For them
each record also **names** the versions it replaces, by their fingerprints, in a part every device
can read; in this section "names" means only that. The list never holds more than 32 entries, about
1.5 KB at most, however often the file changes and however many devices change it. A record for a
small file written by one or two devices is about 520 bytes. The part only key holders can read is
rounded up to 256, 512, 1 024 or 2 048 bytes and up, so that a NAS cannot tell from its size how
many devices wrote the file or how long its name is; that rounding costs up to half of that part,
about a quarter on average. So a small file takes about 780 bytes with three to seven devices on its
list, 1.3 KB with eight to eighteen and 2.3 KB with more, and each piece (chunk) of a larger file
adds about 75 bytes: typically under 1 KB per file, and up to about 2.3 KB for a small file that
many devices wrote.

**A shared start, a long separation, edits on both sides.** A laptop L and a desktop D both hold
`report.txt` as L last wrote it: record V1, counter (L, 1000), list empty.

| Step | L holds | D holds |
| --- | --- | --- |
| Both start | V1 | V1 |
| Apart for six months, L edits: V2, counter (L, 2000), list "L at 1000" | V2 (V1 dropped: V2's list covers it) | V1 |
| D edits: V3, counter (D, 2500), list "L at 1000" | V2 | V3 (V1 dropped) |
| They meet; neither list covers the other | V2 and V3 | V2 and V3 |
| The person saves `report.txt` on L: V4, counter (L, 3000), list "L at 2000, D at 2500" | V4 | V4 (after the next exchange) |

While both V2 and V3 are held, `report.txt` shows the one with the later modification time and the
other appears as a conflict copy beside it; nothing is lost. When they meet after more than 90 days,
neither remembers where it stopped with the other, so they compare summary hashes (digests) of their
whole indexes, narrow down to the parts that differ, and swap only those: here, one file's records.

**An edit made while an update is still arriving.** D has received V2 from L but not yet its
content, so `report.txt` on D's disk is still V1, and the person edits it there. The list of D's new
version covers only V1, the version it was made from, and not V2, which the person never saw: so V2
and the new version are both kept, a conflict, and neither replaces the other. The same holds for a
delete: deleting a file or a folder deletes only what was on the deleting device's disk, and a newer
version still on its way comes back as a file.

**What becomes of a conflict copy.** Until someone saves the file again, the copy is the second
version the index keeps, shown the same way on every device. The device where the person saves the
file first turns each copy into an ordinary file of its own, beside the original, which syncs like
any other file and stays until the person deletes it. So every time two edits overlap, one file is
left over, and the index grows by that file's one record, never by history.

**Two devices create the same file independently.** L and D, apart, each create `notes.txt`: VL with
counter (L, 100) and VD with counter (D, 150), both with empty lists. When they meet, neither list
covers the other, so both are kept. If the two contents are identical, the file shows once and no
copy is made; if not, one is the file and the other a conflict copy. The next save covers both.

**A folder deleted.** Deleting a folder writes one record, "delete everything beneath `build/` that
I had on my disk", with a list, inside its sealed part, of what the deleting device had there. A
file someone else saved beneath `build/` without having seen the delete is not on that list, so it
survives: an edit beats a delete. While at most 32 devices wrote what lies beneath the folder,
deleting it adds one record, not one per file; past 32, each file of the devices that did not fit on
the list gets a record of its own as well. Deleting the same folder again later replaces the earlier
deletion record. Devices that cannot read the folder (below) cannot tell what lay beneath `build/`,
so the deleting device also sends a signed **cleanup**: "forget these records", one 34-byte
fingerprint per file. For 100 000 files that is about 3.4 MB in seven pieces, sent once to every
device; devices that can read the folder keep it 30 days of the folder's time, the others until a
later cleanup replaces it, and the deletion record itself is kept a year.

**When a deletion is forgotten: the deletion horizon.** A deleted file's record, and a deleted
folder's, are forgotten after one year (the owner's decision: fixed, the same on every device). The
year is measured in **the folder's own time**, the latest time stamped on any record the device
holds, not by any one device's clock (the owner's decision: "use the folder's own time"), so every
device that holds the same records forgets the same deletions, whatever its clock says; and a folder
in which nobody writes forgets nothing (a cleanup counts as a write here). A device that comes back
after more than a year, still holding an old copy of a deleted file, brings that file back as a live
file (or as a conflict copy beside a newer one): the owner chose this over treating such files as
deleted. It is the price of forgetting, and never a loss. In the same way, a file deleted on a
device that stayed offline for more than a year comes back when that device reconnects.

**The clock rule: devices whose clocks are more than a year apart do not sync.** This is a second
rule that also happens to be a year long, and it is not the deletion horizon. In the owner's words:
"Refuse to sync with clients that are more than a year out of date. Document this decision as it has
real impact for people's deleted files and for trying to settle the sync'd copies. A solution would
be to stop synchronizing a folder, fix the time, and then start synchronizing again."

- Every device tells the other its date when they connect. When they first open a folder together
  and the two dates are more than a year apart, in either direction, they disconnect at once and
  sync nothing, and each shows a message for that folder: "this device's clock and that device's
  differ by more than a year". When two devices never open a folder together, no message is shown,
  so a stranger cannot raise one. A device that can read the folder also refuses any single version
  that arrives stamped more than a year after its own clock, even through a third device (this check
  of single versions is the coordinator's reading of the owner's rule, shown to the owner on
  2026-10-25), and shows "a record dated more than a year ahead of this device's clock". Neither
  message can say which clock is wrong; both ask the person to compare this device's clock with a
  trusted one.
- The remedy, which the message gives, is on the device whose clock is wrong: stop syncing the
  folder there (remove it, keeping its files), set the clock right, then add the folder again with
  the same key over the same files. Adding it again starts that device's index afresh.
- What that costs the person. Files on that device that match what the others hold are kept as they
  are. Files that differ, because they were edited there while the clock was wrong, are offered as
  conflict copies beside the others' versions, to settle by hand; nothing is overwritten. Files that
  were deleted on that device while its clock was wrong come back from the other devices, since
  those deletions were refused or are undone. That is the "real impact for people's deleted files".
- What the remedy leaves. The device keeps its device ID, and its stamps start again from the right
  date, below the ones it wrote while its clock was ahead. Versions it wrote then, which other
  devices kept, come back once the real date reaches them; and one of them that was written over
  another of them can replace an edit the device made after the fix, as if it were newer (the edit
  goes to the archive). So edits made while the clock was wrong may reappear later, or push later
  edits to the archive.
- A fast clock can also cut off a slow one through a correct one. With one device 300 days ahead and
  another 70 days behind, every pair but those two syncs; but once a correct device has taken a
  version from the fast one, everything it writes afterwards is stamped at least 300 days ahead,
  which the slow device refuses for up to a year, while its own edits still go out. The slow
  device's message then comes from a correct device's version, so it blames no device: the remedy
  belongs on the fast device, or on the slow one.
- Why it is needed: a version stamped far in the future would move the folder's own time forward and
  make every device forget deletions early, and would push every later stamp in the folder ahead
  with it, for as long as that clock keeps writing and for as long again after it stops. A clock
  more than a year off is stopped; a clock up to a year ahead still gets through, and can make
  deletions up to that much early be forgotten (files come back, never lost), which is why a device
  that receives a version stamped more than a day ahead shows a warning, "this folder's time is N
  ahead of this device's clock", pointing to the device the version claims as where it was first
  seen; that device may only have carried a fast device's time forward.
- A device whose clock is unset, one with no battery-backed clock and no network time (a Raspberry
  Pi that booted without a network, say), reads a date far in the past and cannot sync until its
  clock is set.
- The remedy does not recall versions the wrong device already sent with dates far in the future.
  Devices that can read the folder refuse them; devices that cannot (sealed peers) keep passing them
  on; and once the real date comes within a year of a version's date, devices accept it as one more
  version of its file, a conflict copy where its content differs.

**What a device that cannot read the folder sees and keeps (a sealed peer, such as a NAS holding
encrypted backups).** By the owner's decision ("sealed peers see almost nothing"), it sees, for each
version: an opaque number standing for the file (it cannot tell the name), the fingerprints of the
versions it replaces, the IDs and rounded sizes of its pieces, and a signature. From those it can
tell how many files there are and how often each changes, where a file's history forked into a
conflict and joined again, which files share pieces (a copy, or a rename: a new number with the
pieces of a file just deleted), the approximate size of each version, and that a version without
pieces is a deletion, a folder deletion, a directory or an empty file, without telling which. It
also sees when each version arrives and from which device, which usually shows who wrote it; which
files were cleaned up together, and, from a cleanup that a device with the write key sends for
deletions it has forgotten, that those files were deleted more than a year ago, and, from the record
a cleanup names as the reason for forgetting files elsewhere, that it deleted a folder (the
coordinator's ruling of 2026-10-26, for the owner's review); and the size class of each version's
sealed part (256, 512, 1 024 or 2 048 bytes and up), which says only whether its name, its pieces
and the devices that wrote it together fit a small class or a large one. It does not see names,
dates, device IDs inside versions, sizes beyond the rounding, or whether a version is a deletion,
short of those old deletions and those folder deletions. From the sizes of a version's pieces,
someone who already has a copy of a file can try to tell whether that file is in the folder: the
pieces are cut at places only key holders can compute, which makes it harder, but published attacks
show that this is no full defence against someone who knows some of the folder's files (`keys.md`
§3.2).

- It replaces a version only when a newer one names it, and otherwise keeps both. A NAS that was
  off while a file went V1 → V2 → V3 holds V1, receives V3, which names V2, and keeps both. The next
  time a device with the write key meets the NAS, it sees that V1 is old and sends a signed cleanup
  naming it; the NAS drops V1. Until then nothing is lost: V1 is an old version, and V3 is held
  everywhere. Devices that can only read the folder cannot sign, so they cannot clear such copies.
- Someone holding the NAS key, or the read key, who kept every old version can send them all to
  another NAS, which cannot tell old from new and keeps them all, contents included, until a device
  with the write key meets it and cleans up. Each old version costs that device one check and one
  name in a cleanup, and the same versions can be sent again, and named again, only once that
  cleanup has been forgotten, about 30 days of the folder's time later, however often the file is
  written meanwhile; one device identity gets at most about a million names a month out of a
  write-key device. Sent again after the file has been written, they stay on the NAS until then, and
  for good in a folder nobody writes to any more, whose time stands still: the cost is the NAS's
  storage, not more cleanups. No cap is set (the coordinator's ruling of 2026-10-25, for the owner's
  review), since a cap could make a NAS drop the only copy of a real edit: the growth is bounded
  only by the folder's history, every version it ever had, because a version a cleanup has named is
  refused while the NAS holds that cleanup and the newer version it was named for. The NAS shows in
  its status how many extra versions it holds (old copies and real conflicts together, which it
  cannot tell apart), so its person can see it grow.
- The same person can take a file away from another NAS for a while: a file that came back after its
  deletion was forgotten is removed again there if they send that NAS the old deletion, until a
  device with the write key next meets it and the file returns. Devices that can read the folder
  ignore the old deletion, so the file is not lost.

**What a device that can read the folder sees.** Everything in the files and their names, and for
every version which device wrote it and when, to the microsecond, offline edits included, and which
devices wrote the file before. The owner asked for this to be stated: "Make sure this is documented
- do not hide this detail". The microsecond times are the owner's choice, for this reason: "I can
work on files in multiple locations nearly simultaneously and the per-minute version resolution is
not accurate enough".

**The worst case asked about: short-lived machines appending to one log file, for years.** A server
A holds `log.txt`. Every hour four new machines join, each with a new device ID, take the log, add
lines and leave.

| When | What the index holds for `log.txt` |
| --- | --- |
| Start | One record: A's, list empty |
| Hour 1: machine E1 appends after taking A's version | One record: E1's, list "A at 1" |
| Hour 1: E2, E3 and E4 append at the same moment from A's version, without E1's | Up to four records, a conflict: one log shown, the others conflict copies (no merging) |
| Hour 2: E5 appends, holding all four | One record, its list covering A and E1 to E4; each copy becomes an ordinary file |
| After 32 machines | One record; its list is full at 32 entries, and each new machine's entry pushes out the oldest |
| After five years (175 200 machines) | Still one record for `log.txt` (up to four during an overlap), its list at most 32 entries, about 1.5 KB. But every overlap leaves conflict-copy files beside it: up to 3 an hour, about 26 000 a year, each a live file whose record is about 12 KB for a 10 MB log, so about 300 MB of index a year and 1.5 GB over five years, unless someone deletes the copies |

Besides the records, each device remembers, for each machine it exchanged with in the last 90 days,
where it stopped: about 60 bytes each, at most 4 096 per folder, about 240 KB for the server, which
meets about 8 600 machines in 90 days and so forgets the oldest early; forgetting one costs only a
comparison of digests if that machine returns. Under the design this replaces, all 175 200 records
would have been kept for ever, each carrying the log's chunk list (for a 10 MB log in 64 KB chunks,
about 12 KB a record): about 2 GB, and a table entry per machine for ever.

The cost of the cap: a device that was away while more than 32 other machines appended (eight hours
at four an hour) comes back with a log version whose entry has been pushed out of every newer list.
Nothing says that its version is old, so it becomes a conflict copy, on every device once the
exchange has spread it, and the next append covers it; the copy stays as a file until someone
deletes it. Nothing is lost. Two ways to avoid even that: give each machine slot a stable device
seed that only one machine at a time ever runs with (never one seed for machines that can run at
once: that makes them one device and lets one's edit replace the other's, below), so that each slot
keeps one entry; or let each machine write its own log file, which also avoids the conflict copies
that two machines appending at once make, at the cost of one live file per machine, 175 200 over
five years, which the person or a cleanup job must delete.

**A version this device cannot read.** A newer release of Lickety-Sync may write a kind of entry
this release does not know, and a device with the write key may write a broken one. When such a
version replaces every version of a file this device has (the file shown, any identical copies of it
and any conflict copies), this device can neither show it nor tell whether it is newer, but it knows
the versions it has were replaced: every other device on its release that holds the same entries has
dropped them. So it takes its copy of the file off its disk, into the archive, and shows a warning
naming the entry it cannot read (the owner's decision of 2026-11-03: "Yes, remove the old copy").
When such a version replaces only some of them, the file stays, showing one that is left. The device
also remembers the version it archived, so that when someone saves the file again on it, restored
from the archive or changed, that save replaces the old version everywhere: a device that was off,
and still has the old version, takes the save instead of keeping its old copy beside it as a
conflict copy (the owner's decision of 2026-11-10, "Also what was archived"). Only a version this
device never had, an edit made on another device while this one was off say, still shows as a
conflict copy beside the save. The archived copy stays in the archive, past the archive's usual 30
days, which are a setting, and even where versioning is off, until the problem is fixed for it:
until a save replaces that old version (the next save of the file on this device does, and so does
one on a device that had the old version), or this device is updated to a release that reads the
entry. An edit made elsewhere without the old version brings the file back, but leaves the copy and
the warning (the owner's decisions of 2026-11-10: "Until fixed" and "30 days should be
configurable"). On a desktop the warning also shows in the status bar and as a system notification.
Saving the file on this device ends that keep, and the copy then goes as the archive's 30 days say,
or at once where versioning is off, so the warning says to restore from the archive first whatever
is wanted of the old file. The file comes back when this device is updated to a release that reads
the entry, or when someone saves the file again; a broken entry goes away when someone with the
write key saves that file again. The warning says what this device can
do: one with only the read key cannot save, and waits for one with the write key; and an entry of an
unknown kind may be a newer release's, which updating shows, or a faulty one that no release reads,
which stays beside the saved file. Every device on one release that holds the same entries shows the
same thing there.

**What can still go wrong, and how it shows.** Every case below keeps the file, as a conflict copy,
a reappearing file or a file in the archive; the few that can let one version replace another it
should not have, as if it were newer, say so, and the replaced file then goes to the archive:

- more than 32 writers on one file while a device was away (a conflict copy, above);
- a folder deleted while records at its own path from more than 32 devices are there (identical
  folders made apart, or conflict copies, files at its name): the deletion takes 32 of them, and the
  rest come back, as the folder, empty of what was deleted, or as a file and its conflict copies,
  until the next delete;
- a device back after a delete was forgotten, or a deletion made offline more than a year before it
  arrives (the file reappears, above);
- a sealed peer that kept an old copy of a file deleted more than a year ago can bring it
  back whenever it likes, even beside a new file created at the same name since (as a conflict
  copy);
- a clock up to a year ahead, which the clock rule lets through, makes deletions up to that much
  early be forgotten (the files come back);
- a device whose clock is more than a year off is refused until it is fixed and the folder added
  again there, which brings back what it deleted meanwhile and turns its edits into conflict copies
  to settle (above);
- two machines that share one device ID (cloned from one disk image), or a device restored from a
  backup while its clock reads too early, either of which can let one device's edit replace
  another's as if it were newer (the replaced file goes to the archive);
- a device whose clock was more than a year off and that was fixed by the remedy: edits it made
  while the clock was wrong can come back later, or push its later edits of the same file to the
  archive (above);
- a NAS sent an old deletion on purpose drops a file that came back after the deletion was
  forgotten, until a device with the write key meets it; devices that can read the folder keep the
  file (above);
- a record that a device with the write key got wrong (it cannot be read, or breaks a rule every
  release checks) stays, with its pieces on every NAS, until someone saves that file again, which
  the warning about it says; meanwhile a device that had the version it replaced moves its copy of
  the file to the archive, where it stays until a save replaces that version, and from where it can
  be restored and saved; one at a file nobody saves again, or a cleanup message that is itself
  wrong, stays for good, and so do those archived copies; a device that can only read the folder
  cannot save, so its copy waits for one with the write key; and an entry of a kind that no release
  knows takes the file off the disks until someone saves it again, and then stays beside it for
  good;
- a deleted folder that also takes a file the deleting device had not yet received, or not yet put
  on its disk, when the device that wrote that file later wrote something else in that folder that
  the deleting device had. The usual case is a rename inside the folder: the new name and the
  removal of the old name travel separately, and if only the removal had arrived when the folder
  was deleted, the renamed file goes too (to the archive). Another is a folder linked on two
  devices that already hold it, deleted on one before a file only the other had has finished
  arriving (the owner's decision of 2026-11-08: a folder delete takes what is inside it). A NAS
  that holds back the new name can make it happen.

And these lose nothing but limit the folder:

- a device whose clock runs ahead pushes every later time stamp in the folder ahead with it, up to
  the year the clock rule allows, for as long as it keeps writing and for as long again after, and
  can cut off a device whose clock is behind (above); a warning shows when the folder's time is more
  than a day ahead;
- every overlap of two edits leaves a conflict-copy file, which stays until someone deletes it: in
  the hourly-log case up to 3 an hour, about 26 000 a year and about 300 MB of index a year, close
  to the growth this design was chosen to avoid; deleting the copies, or giving each machine its own
  log file, avoids it;
- a NAS that only devices without the write key visit keeps its old copies, and one fed old versions
  on purpose keeps them all, until a device with the write key meets it, which then signs cleanups
  naming them that every device receives (above);
- a write-key holder who signs a record with a counter near the top of the range makes the folder
  unwritable for everyone, and it must be shared again; only a write-key holder can do this, and one
  can already delete everything.

**Relays and hole punching** (`threat-model.md` TM-25). A relay passes the encrypted traffic of two
devices that cannot reach each other. Every relay is public, which means it may be anyone's
computer, and none is used, and none relays for anyone, unless its person turns that on. Public
relays, which can carry whole transfers, come in phase 7.

Hole punching, from phase 2, is much lighter. Two devices behind home routers ask a third device, a
coordinator, to pass their first few messages, so that each learns the other's public address and
both try to connect at the same moment, which most home routers then let through. By the owner's
decision of 2026-11-08, any computer can be a coordinator, a friend's or a stranger's, once its
person turns "allow acting as a hole-punch coordinator" on; it is off unless turned on, and a phone
never coordinates, though it can be helped (the owner's decision of 2026-11-10, "Computers only"). A
coordinator needs no key to the folder.

The settings (the owner's decision of 2026-11-10: "Both must allow. Folders should be able to be
individually configured for hole punch, plus there should be global configuration for allowing
direct connect, DHT, etc. global settings set defaults. Folders can override."). Every way of
connecting has a setting for the whole device that each folder may override: finding devices on the
local network, direct connections (hole punching among them), the internet-wide DHT, public relays,
Tor, and whom a folder may use to coordinate a punch: never; only devices it shares a folder with
(the default); also devices it is directly connected to; or also any device it knows and any public
relay its person turned on. So asking for punches is on unless turned off, through devices that
share a folder; coordinating for others, and using or serving relays, are off unless turned on. A
punch serves a folder only if, on both devices, that folder's direct connections are on and its
setting allows the coordinator used; a folder whose settings do not allow it does not sync over that
connection, and the others do.

How the two find the same coordinator: the device that wants to be reachable chooses in advance, and
nothing is picked at random. It keeps a small standing connection with one to three coordinators its
settings allow (devices it is connected to first, then public relays its person turned on) and lists
them as "reach me through X", each only for the devices it shares a folder with whose settings allow
that coordinator, and in invites to such a folder that carry addresses. It never puts them, or its
own network ID, in the public DHT (the owner's decision of 2026-11-10, "Peers now, alias later":
phase 2 is to design a changing alias that coordinators accept, so that the DHT can carry them
without the network ID). A device that wants to reach it picks one of those coordinators that its
own settings allow, at most three of them and two at a time, and connects to it, and the coordinator
joins the two just long enough to time the punch; if that one fails, it tries the next.

Who may punch through to a device (the owner's decision of 2026-11-10, "Known peers or key
holders"): only a device that has shared with it a folder whose settings allow a punch through that
coordinator, or a new one that first proves, through the coordinator, that it holds a key to such a
folder, with a few small messages and no files. Anyone else gets no punch and no address: a
stranger, or a person removed from a folder, learns at most that the device is online and which
device it is, as trying an old address would tell them. A punch tries only a few addresses, all
public internet ones, so it cannot be aimed at a home network's private addresses, short of a
translator on its network whose prefix or mapping the device cannot learn, or a public-looking
network behind a non-default route, a split-tunnel VPN's (`threat-model.md` TM-25), and each device
limits how many punches it takes part in; a device it admitted, or that admitted it, can still make
it send a few short bursts of packets to public addresses of its choosing, its own network's public
ones among them, at most 160 a minute, which is all a punch can be used to send at someone else.

What a coordinator learns: that the two are connecting, when, their public addresses and their
network IDs (libp2p peer IDs), which both devices' settings let it learn. It learns no folder, no
key and no file, and a punch opens nothing to the internet beyond each side's address to the other.
The devices a device shares folders with, and whoever gets an invite with its addresses, also learn
which coordinators it uses. A coordinator passes at most 64 KiB and 60 seconds of set-up for each
punch, limits how often each device may ask and how many punches reach one device, and accepts
requests only over direct connections; the two devices never sync through it, whatever their
settings, so it never becomes a relay (the owner, on 2026-11-08: "I don't want random connected
clients used as relays without the operator's consent"), and a connection that states a
coordinator's limits is treated as one, whatever the device in the middle claims to be. A
coordinator that lies or stays silent only makes the punch fail: before anything is synced, the
connection the punch brings still proves which device is at the other end and that it holds a key to
the folder.

**Why this design, and what was rejected.** Each choice above, with the alternatives weighed against
it (sources read on 2026-10-25, listed in `threat-model.md`'s appendix):

- *Latest only*, against keeping every version and naming replaced ones by hash (ruling R-K6): the
  owner ruled out an index that grows for ever; and a bounded summary of what a version replaces is
  what makes dropping old versions possible.
- *Lists compared by the replaced version's own entry* (dotted version vectors, Preguiça et al.
  2010), against comparing whole lists entry by entry as Syncthing does (BEP v1; `Vector.Compare`):
  with a cap, comparing whole lists would make a version fail to replace the one it was written from
  as soon as that one's list was full.
- *A cap of 32 entries, the least recently updated dropped first* (as Riak prunes, Sheehy 2010),
  against no cap (Syncthing's lists grow with every device that ever wrote a file, which the hourly
  machines would make endless) and against 16 (two people's devices and a small team would already
  fill it; 32 entries cost at most 1 472 bytes, small beside a large file's chunk list). The ranking
  needs no timestamp per entry, as Riak's has, because counters follow the clock.
- *Interval tree clocks* (Almeida, Baquero and Fonte 2008), a scheme in which each device's identity
  is a share split off another device's and handed back when the device leaves, rejected: a device
  here joins from a key alone, with nobody to split a share from, the hourly machines vanish without
  handing theirs back, so the shares never return, and with one shared write key nothing could stop
  two devices claiming one share.
- *A summary of dropped entries*, rejected: a single "everything below this counter" would also
  cover an edit made offline long ago and never seen, and lose it; a compact probabilistic set of
  dropped entries (a Bloom filter, which sometimes says yes wrongly) would lose an edit on each
  wrong yes. Dropping entries that can only add conflicts was the condition.
- *A device-wide counter that always moves past every counter seen (a Lamport clock: Lamport 1978)
  and never falls behind the clock*, against a counter per file (Syncthing's): a tree delete has to
  compare versions across many paths with one list, which only a device-wide counter allows; the
  clock floor, Syncthing's own, keeps a restored device from reusing counters.
- *A tree delete's list over the tree it deletes*, against the folder-wide list first proposed: the
  folder-wide one would also cover versions beneath the directory written before unrelated writes
  elsewhere that the deleter had seen.
- *Edits and deletes built from what is on the disk*, against building them from what the index
  holds: the index may hold a version whose content has not arrived, and an edit built from the
  index would silently replace it.
- *Edits and deletes that cover every version of the content on the disk*, against covering only
  the one the device names as on its disk: when two devices write the same file apart, or a folder
  is linked on two devices that already hold it, each file has two versions of one content, shown as
  one file; an edit that covered only one left the other on every device, as a conflict copy of the
  old content, or as the deleted file back (the identical-heads bug of 2026-11-08). The other
  version's content was on the disk all the same, so covering it loses nothing. A later version of
  the same content, a change of mode still arriving say, or one the device has yet to put at the
  path, is not such a version: it stays a conflict.
- *One tombstone per deleted file, one tree delete per deleted directory*, against tree deletes for
  single files too: a tombstone keeps a file's list exact, and sealed peers need no cleanup for it,
  since it names the version it replaces.
- *Sealed peers that judge only by names* (the owner's decision), against showing them the vectors
  and counters: they then see no device IDs, no dates and no deletion marks, at the cost of keeping
  stale copies until a write holder names them, and of a signed cleanup message.
- *Cleanups that name exact fingerprints*, against telling sealed peers which files lie beneath a
  deleted folder (the earlier "chains"): a cleanup reveals only which records went together and, in
  a group with no `because`, that they were deletions more than a year old, and, naming exact
  records, can never remove a later version however late it is replayed.
- *Cleanup groups that act only while the record they were issued for is held*, against remembering
  that a group once acted (an earlier draft): with that memory, two devices holding the same records
  could refuse different ones, show different files and still believe they agree; without it a NAS
  can take back an old copy once the file has been written again, until a write-key device names it
  again.
- *Pieces cut at places derived from the folder's key*, against FastCDC's published table: with the
  published table a NAS could cut a file it already has and compare the sizes of its pieces with a
  record's; keyed, it cannot, though published attacks recover such keys from files the attacker
  knows (`keys.md` §3.2).
- *Deletions forgotten by the folder's own time* (the owner's decision), against each device's own
  clock: with each device's clock, two devices could disagree for ever about which deletions exist.
- *The clock rule* (the owner's decision), against letting any clock through: one clock far ahead
  would make every device forget every deletion at once.
- *Reconciling by the fingerprints of the records themselves*, against comparing lists or counters:
  a writer that signs two records with one counter would make the lists of two devices that hold
  different records look equal (Kleppmann 2022). And *digests over sorted lists of fingerprints*,
  against combining fingerprints by XOR (an operation in which suitably chosen inputs cancel out): a
  write holder could craft records that cancel and so make two devices that differ look alike.
- *A fixed deletion horizon of a year*, against one that each device sets: devices with different
  horizons would never agree on which deletion records exist (the owner's decision). And *a deleted
  file that comes back after the deletion horizon*, against the plan's rule that a device back after
  the horizon treats as deleted what the others lack (the owner's decision): that rule needs to know
  when each pair last met, and would send live files to the archive on a device whose peer had lost
  records.
