# LicketySync threat model

Version 2, 2026-10-22 (version 1, 2026-10-14, described the issued-keys model), revised the same day
for the coordinator's rulings R-K6 and S-1 to S-4 and the owner's second set of answers, and on
2026-10-25 for the index that keeps only the latest versions, ordered by version vectors (the
owner's decision of that day; `protocol.md` §4.4, §4.5), and on 2026-11-08 for the owner's answers
of 2026-11-03 to 2026-11-08: a path whose records a device cannot read follows the rule for a path
with no heads (TM-41); relays are public only, and hole punches are coordinated only by devices
whose persons turned that on (TM-25); and TM-22's "QUIC stream memory" is required before 1.0
(residual (h)); and on 2026-11-10 for the reviews of that revision and the owner's decisions of that
day: a device remembers what it archived when a path's records became unreadable, and keeps those
copies until a version it reads covers them (TM-35, TM-41); every connectivity setting is a
device-wide default each folder may override; a device takes a punch only from a known peer or a key
holder, counting only the folders whose settings allow a punch through that coordinator; and its
coordinators travel only to its folders' peers and in invites (TM-25); and on 2026-11-12 for the
owner's decisions of 2026-11-08 and 2026-11-12: a deletion or cleanup is forgotten only by a
watermark that a write holder signs once it has held it for a year by its own calendar, the clock
rule is gone, and counters have a fixed ceiling; a wrong or faked clock on one write holder can make
every device forget every deletion at once, and forgetting can be held back without bound, both
stated residuals (TM-40); and on 2026-11-13 for the owner's decisions of that day: every
connectivity setting is on, off, at default (the setting's default, TM-25) or unconfirmed, and
starts unconfirmed, which acts as off; the guided setup asks once, suggesting a recommended set that
never makes the device a relay, a DHT server or a coordinator for strangers (TM-24 to TM-26,
TM-31, section 5); a computer may coordinate punches only for two devices that have the same one
of its folders open with it; and a public relay also coordinates punches (TM-25); and the same day
for the consistency fixes the documentation site's reviews found: what the client does with a link's
fragment (TM-18), what a browser invite is (TM-37), and what LAN beacons, DHT lookups and Padmé show
(sections 3.1, 3.9 and 5). This file is normative for
every crate in this workspace, for the apps in `app/` and for the browser client in `web/`. Its
companions are `suites.md` (algorithms and approved crates), `keys.md` (folder keys, derivations,
records, key strings) and `protocol.md` (wire protocol). The plan, "LicketySync: Project Plan", is
the source these files are written from; where this file is silent the plan decides, and where they
disagree the disagreement is raised, never quietly resolved.

Every requirement below has a number, TM-1 to TM-43. Five of them, TM-16, TM-19, TM-34, TM-36 and
TM-38, are **retired** (2026-10-22): they existed only for issued keys, revocation and defences
against an insider who equivocates, and their numbers stay with a note so that an old citation is
never read as a new rule; TM-41 and TM-42 are new, and TM-43 was added on 2026-10-25. Code comments,
test names, changelog entries and review reports cite them (`// TM-4`, `fn
tm_4_symlink_then_directory()`). Section 6 says how a reviewer uses them.

Vocabulary, shared with `keys.md` and `protocol.md`: a **folder** is the unit of sharing. It has
three shared secret **keys**, as in Resilio Sync: the **write key** is a random 32-byte **write
secret** from which the folder's Ed25519 **signing key** (and its public **verification key**), its
**data key** and its **folder ID** derive; the **read key** carries the verification key and the
data key; the **sealed key** carries the verification key and the **access key**, which derives from
the data key and admits a peer to the folder's handshake. Holding a key is the access: there is no
owner key, no per-person key, no expiry and no revocation, and nobody records who changed what. A
**tier** is write, read or sealed. A **key string** is one key in Bech32m text with a checksum; the
write key can also be shown as 24 **words**. An **invite** is a key string sent as a link, QR code
or file. A **device** has a device key, a **device ID** (the labelled hash of its public key) and a
self-chosen name; **Hello** is the first message of the handshake, listing what a device supports
and its limits; the **index** is the folder's set of signed **records**, each carrying in the clear
a keyed **path tag** (its file ID, which names its path to key holders only) and the fingerprints of
the versions it replaces, and, sealed, the device ID its signer claims, a counter of that device's
and a **version vector**; a device keeps only the latest versions of each path, a **tombstone**
marks a deleted file, one **tree delete** a deleted directory with everything beneath it, and a
write holder's signed **cleanup** tells sealed peers which records to forget; a **chunk** is a piece
of a file, cut where a chunker keyed from the data key says (from phase 1; phase 0 cuts fixed-size
pieces); a **sealed peer** holds ciphertext it cannot open; a browser in **vault mode** is a sealed
peer that stores ciphertext in the browser's own storage; a **relay** forwards the encrypted bytes
of a connection between peers that cannot reach each other, and is always public: anyone's device
whose person turned relaying on, used only for the folders whose public-relays switch is on
(TM-25); **peer exchange** is peers telling each other the addresses of peers they share a folder
with; the **archive** keeps replaced and deleted files (Trash can, 30 days by default, a setting:
the owner's decision of 2026-11-10); the
**deletion brake** pauses a folder and announces no deletions when more than a threshold of its
files vanish at once from a device's own disk, until the person confirms; it never holds back
deletions that arrive from peers (TM-35); **unlinking** a folder removes it from a device and keeps
its files and its archive; **sharing again** makes a new folder over existing files (`keys.md` §7);
a **parcel link** is the plan's one-time "send one file to someone" invite, which carries addresses
because the recipient may share no peer with the sender.

## 1. What we protect (assets)

The program exists to copy people's files between devices without any party in the middle being
able to read, alter or withhold them. What must be protected is the files themselves, everything
that describes them, and the keys that open them. Some facts cannot be hidden by a peer-to-peer
design and are listed as leaks in section 5 rather than promised away.

| Asset | What it is | Who may learn it | Confidentiality, integrity, availability |
| --- | --- | --- | --- |
| File contents | The bytes of every file in a folder | Write and read key holders | All three; availability is what sync is for |
| Names and structure | Paths, tree shape, true sizes, modification times, modes, symlink targets | Write and read key holders | All three |
| The index | Per folder: each path's latest versions with size, time, mode, the versions they replace (version vectors), chunk list and deletion marker, and the tree deletes, as records signed by the folder key | Write and read key holders decrypt it; sealed peers carry it opaque | Integrity against everyone without the write key; confidentiality against sealed peers and relays. Write holders are trusted with it |
| Write key | The write secret, and so the signing key and every other key of the folder | Write key holders | Disclosure is full control of the folder for as long as it exists: nothing revokes it, and the remedy is sharing again (TM-42) |
| Read key | The verification key and the data key | Write and read key holders | Disclosure is permanent reading of the folder, past and future |
| Sealed key | The verification key and the access key | Holders of every tier | Disclosure lets a party join as a sealed peer: hold, verify and serve ciphertext, and see what section 5 lists for sealed peers |
| Device identity | Device key pair; device ID = hash of its public key | Public to anyone who completes a connection: the DeviceProof proves the key and ID before any folder is named, and the Hello carries the lists (section 5); the name is sent only after a folder has opened on the connection, so only a peer that has opened a folder with the device learns its name | Integrity: a device cannot claim another's ID at the handshake |
| Local key store | The device seed and one key per folder the device holds | That device | Confidentiality: its theft is the theft of every key in it (section 3.4) |
| Catalogue (phase 5) | Which folders a person's linked devices hold, and at which tiers | Those linked devices | Confidentiality against everyone else |
| Local API token | Authenticates the CLI and web UI to the service | The local user | Confidentiality against other local users and web pages |
| Metadata that leaks | Padded sizes, chunk counts, record counts and rates, timing, the salted folder and announcer hashes on the LAN with each beacon's port, number of folders and minute, the daily discovery hash, the lookups for it and the stable identifiers a device publishes with it on the DHT, that two addresses talk, device IDs and names, and to whoever completes a connection the libp2p peer ID, the protocols it offers in multistream-select, the device key, the suite, compression, hash and feature lists and limits, and a coarse count of the folders it holds (proof-result timing) | Sealed peers, relays, network observers, as section 5 states | Not protected; documented |

## 2. Parties and trust boundaries

Nothing in the design is a server, so there is no party that holds everyone's data, and every party
below is either a device that holds a key to a folder, or infrastructure that carries ciphertext.
Trust is attached to keys, never to addresses, names or the network a message came from, and every
holder of one key is trusted alike.

| Party | What it holds or sees | What we trust it with | Boundary it sits behind |
| --- | --- | --- | --- |
| Write key holders (the person's own devices and the people they share with) | The write secret, every derived key, plaintext | Everything in the folder: to change and delete honestly, and to hand keys only to people who should have them. Nothing detects or undoes a write holder acting in bad faith beyond the archive (section 3.6) | The operating system's user account and the key store |
| Read key holders | Verification key, data key, index, plaintext | To read; their changes are rejected by every peer | Same |
| Sealed key holders (sealed peers) | Verification key, access key, ciphertext, signed records, chunk ciphertext hashes | To store and serve ciphertext faithfully; nothing else, and faithfulness is verified rather than assumed | Same; a NAS, a friend's machine, a browser in vault mode |
| Linked devices (phase 5) | A person's devices, passing folder keys to each other over an authenticated channel | As holders of the keys they receive | Same |
| Relays (public only: the owner's decision of 2026-11-03) | Both endpoints' addresses and libp2p peer IDs, timing, volume and the sizes of the encrypted frames it forwards; no folder ID, since a reservation and a circuit name peers, never a folder | Nothing; forwards end-to-end ciphertext only, within the limits its person set (TM-25) | Any computer whose person turned relaying on, theirs or a stranger's, never a phone; no relay is used, and none is served, unless turned on: using per folder, serving per device (the guided setup's recommended set turns using on, never serving). There are no own-device, private or protected relays, since a device cannot tell its person's machines from a friend's when both share the same folders |
| Hole-punch coordinators (the owner's decisions of 2026-11-08 and 2026-11-13) | That two devices are connecting, when, their public addresses and libp2p peer IDs, which devices keep reservations with it, and at most 64 KiB of their encrypted set-up a circuit; no folder, key or file | Nothing; forwards only a punch's set-up, never file data, since neither side runs the sync protocol through it, within its limits (TM-25) | Any computer whose person turned coordinating on, theirs or a stranger's, for anyone or only for the devices of its own folders (the guided setup's recommended set: the owner's decision of 2026-11-13, "Both (Recommended)"; and only for two devices that have the same one of its folders open with it: "Narrow (Recommended)"), and any public relay (the owner's decision of 2026-11-13, "Yes, relays help too (Recommended)"); never a phone (the owner's decision of 2026-11-10, "Computers only"); needing no key to any folder; used only as each folder's settings allow, and reaching a device only for a requester that device knows from a shared folder or that proves a key to one of its folders (TM-25) |
| The LAN | Beacons (salted folder hashes, salted announcer hash, port, minute), multicast, every unencrypted byte | Nothing: a café network is the model | The network interface |
| The internet | Addresses, timing, volume, QUIC and TLS handshakes | Nothing | Same |
| The Mainline DHT | Daily discovery hashes with the addresses announcing them; signed address records (BEP 44) under a stable per-device key | Nothing; off until its person turns it on (the guided setup's recommended set turns it on, in client mode), and seeing a peer grants no access | UDP to strangers; client mode unless its person turns server mode on, which the recommended set never does |
| The browser client's static host (licketysync.app) | Serves the WebAssembly bundle; never sees invite fragments, keys or content | To serve the published bundle; a compromise serves a changed client, which a signed manifest lets the native app or a verifying extension detect | HTTPS; the service worker cache only delays what the host serves |
| The browser running the client | Keys and plaintext of the folders it joins, in origin-private storage or a chosen directory | As a peer at its key's tier; the browser's origin rules keep other sites out | The browser's same-origin policy |
| The local API and its clients | The service listens on a Unix socket or named pipe and on localhost HTTP; the CLI and web UI hold the token | The token holder is the local user | Host and Origin checks, the token, socket permissions |
| The operating system | File system, keystore, random number generator, clock, network stack | Fully: it is out of scope (section 3.12) | — |

## 3. Adversaries

Each subsection lists what the adversary can do, what the design promises it cannot, and the
requirements in section 4 that carry the promise. "Cannot" means the construction prevents it;
"detected" means a peer notices and raises an issue rather than being prevented in advance.

### 3.1 A network observer

Someone who sees packets on the LAN, at an internet exchange, at a proxy on a locked-down network,
or by crawling the DHT. They have no key.

Can: see which addresses talk, when, and how much, and the sizes and number of encrypted frames,
which approximate padded chunk sizes and counts; see that a device runs LicketySync and its port;
see the LAN beacons, each carrying, under a salt fresh to that beacon, one hash per announced folder
and one hash of the announcer's libp2p identity key, and confirm a folder is announced on this LAN
if they already know its ID, or that a device they have met before is announcing if they already
know its identity key; replay a captured beacon from their own address and learn, from the dial that
follows, which devices on the LAN hold the folder it named, without knowing that folder's ID, and
learn each such holder's libp2p identity, because the handshake authenticates it before the dialer
checks the peer tag and abandons the connection (the dial is the signal; `keys.md`, discovery
hashes); see the DHT's daily discovery hash and the addresses announcing it, and follow a device
across days by its address when that address is stable, by a stable identifier it publishes with
the announcement (the BEP 44 key its address record is signed with, a persisted DHT node ID), or by
computing every day's hash when they already hold the folder ID; block UDP and raw TCP so that a
dialer falls back to the WebSocket path, which is classical end to end as `libp2p-websocket` ships
it (its outer TLS is rustls on `ring`, and the Noise inside is classical; `suites.md`, transport),
so that a session forced there is open to a future quantum computer up to what a sealed peer sees
(section 5, the quantum entry); record traffic for a future quantum computer; drop, delay, reorder
or inject packets; reach the home router's port-mapping service from the LAN, which maps only this
device's one port for a bounded lease (TM-26); **move a write holder's clock** through time sync
that is not authenticated (NTP or SNTP, a time server a DHCP server names, or a fake cell tower's
NITZ), so that the device signs a genuine watermark early, and, a year or more ahead, one at the
greatest counter it holds, which makes every device forget every deletion in the folder at once and
undoes the deletions still on their way, bringing deleted files back wherever a copy survives and
losing none (the owner's decision of 2026-11-12, "Still accept, documented": no guard; TM-40,
`protocol.md` §4.4, "A wrong clock, or a faked one"); and **delay forgetting** by cutting a write
holder off and later letting through, together, the deletions it missed, so that it holds them
young and signs nothing past them for a year, again each time, which costs storage and never a
file, and matters only where no other write holder signs (the owner's decision of 2026-11-12 on a
slow release, "Accept, documented"; `protocol.md` §4.4, "What holds forgetting back").

Cannot: read contents, names, index records, keys or key material; learn the folder ID, a device's
identity key or any key from the hashes, or link two beacons to one folder or to one device by their
hashes without the ID or the key (the port, the number of announced folders and the minute, which
every beacon carries in the clear, and the source address can link them, section 5); join a folder,
open a folder proof, or learn whether a device holds a folder, by knowing its ID (TM-32); downgrade
the transport to plaintext (TM-1), or from TLS to Noise on one transport, because each transport
offers exactly one security protocol (`suites.md`, transport): blocking can force the choice of
transport, never of the protocol within one, and the WebSocket path it can force a dialer onto is
still encrypted and authenticated (TM-1); downgrade the suite (TM-30); open recorded traffic later
with a quantum computer beyond what a sealed peer sees, because content is encrypted under the
folder's symmetric keys before it leaves the device and no folder key ever travels inside the
protocol (TM-33, section 5); link one day's DHT announcements to the next without the folder ID, a
stable address or a stable published identifier (TM-24); impersonate a peer, because peers
authenticate by key, not address (TM-32).

What a network observer who answers at an address can also learn (recorded 2026-11-03): **a
dialer's libp2p identity**. `net` dials with the peer ID it expects, but `libp2p-tls` builds its
client configuration without one, so the dialer's TLS client certificate, which carries its
identity, goes to whichever server answers at the address, and only after the handshake does the
dialer compare the identity the server proved with the one it expected and close (`WrongPeerId`).
Whoever can answer at an address a device dials (a spoofed LAN beacon's address, a poisoned DHT
record) therefore learns the dialing device's stable identity, though not that it holds any folder.
A phase 1 item: a dial path that gives the expected peer ID to `libp2p-tls`'s certificate verifier,
so that the handshake fails before the dialer's certificate is sent.

### 3.2 A peer holding a valid key

A device that holds one of the folder's three keys. Holding a key is the access: there is no owner,
no per-person key and no record of who changed what (owner's decision, 2026-10-18), so what a holder
can do is exactly its tier's purpose, and every holder of one tier is indistinguishable from every
other. This is the design, as in Resilio Sync, and it is stated plainly here.

**Write key.** Can: read and change files, names and structure; delete everything; give out any of
the three keys, to anyone, any number of times; sign records under any device ID, its own or
another's, with any vector, so that its version of a path replaces whatever versions that vector
covers, or concurrent versions that every peer keeps (TM-41); delete a directory and everything
beneath it with one record; sign under any number of new device IDs, which costs peers only the
records it signs (section 3.6); see every other peer's device ID and name; act without being
identified, since a record names only a device ID its signer chooses and nothing shows it as an
author. Cannot: be removed, except by the people who stay unlinking the folder and sharing it again
by hand, after which it keeps the old folder and everything it held (TM-42); make honest peers that
meet disagree about which records exist (TM-41); make a peer with persisted state go backwards
(TM-17); destroy a file beyond the reach of the archive on a device whose versioning is on (TM-35).
Its destructive power over content is real and unlimited in scope: deletions it sends are applied
without a brake (the owner's answer of 2026-10-22), and the archive (Trash can, 30 days by default)
limits how much is lost for good, not what it can do.

**Read key.** Can: read everything, for as long as the folder exists (no key expires and nothing
revokes one); give out read and sealed keys; keep the folder's genuine old records and offer them
again, which costs write holders what section 3.3 says of a sealed peer's replays; as a write
holder's only link, hold forgetting back as section 3.3 says of a sealed peer, by releasing the
folder's deletions to it slowly (`protocol.md` §4.4, "What holds forgetting back"). Cannot: change
anything, because every peer rejects a record the folder key did not sign (TM-9); forge; derive the
write key or the signing key (`keys.md` §1.2); raise its tier.

**Sealed key.** Can: hold a complete copy, verify ciphertext against the hashes the signed records
name, serve it, forward it for others, give out sealed keys. Cannot: read contents, names or
structure; see plaintext chunk hashes; test whether the folder holds a known file (TM-14), short of
the chunk-length residual of section 5; sign; do anything in 3.3.

### 3.3 A sealed peer or a relay

A storage or forwarding party that handles ciphertext only. Every cloud break the plan's hardening
review cites (Nextcloud 2024, MEGA 2022, pCloud, Icedrive and Seafile 2024) relied on a storage
party that the client trusted too much. Here the storage party is untrusted by construction. A
relay forwards the encrypted bytes of a connection whose channel runs end to end between the two
peers (TM-25), so it sees no record at all, only what section 5 lists for a relay: it can drop,
delay or cut a connection, at a moment it chooses, midway through a reconciliation say, which can
bring about the arrival order that a reconciliation's own order can by chance, and with it the tree
delete of "Why it is safe" 8a below (`protocol.md` §4.4); the rest of this subsection, the sealed
peer's, is not in its reach.

Can: see what the owner's decision of 2026-10-25 ("sealed peers see almost nothing") leaves visible,
stated here in full (section 5 lists it): of every record, its file ID (the keyed path tag), so how
many files there are and how often each changes; the fingerprints of the versions it replaces, so
where each file's history forked into concurrent versions and joined again; its chunk IDs with their
padded sizes, so the approximate size of each version, which chunks are identical across files and
versions, and from that a copy or a rename, and, for a file it already has, a test of whether it is
in the folder that keyed chunk boundaries make harder but do not rule out (section 5, `keys.md`
§3.2); that a record with no chunks is a deletion, a directory or an empty file, without telling
which; the size class of its sealed part, a power of two from 256 bytes, which says only whether its
path, its chunk count and the number of devices that wrote the file together are small or large;
which records a cleanup named together, at a deletion or a cleanup; and when each record arrived and
from which peer, which usually shows which device wrote it. Besides: device IDs and names of the
peers it connects to, and folder IDs (no Hello carries a clock).
It can ask any peer for any chunk by its ciphertext hash; tell that two chunks are identical
(convergent encryption, section 5); withhold data, go offline, or serve slowly (delaying a chunk
another peer holds by about the chunk patience per connection ahead of the honest holder, while
it can be asked; one peer keeps it from a holder whose pass waits, TM-22); store far more than
asked; **keep stale copies and replay them**: a sealed peer cannot tell an old version from a
concurrent one, so it keeps every version no signed record or cleanup names, and a hostile holder of
the sealed key (or the read key) that kept the folder's history can replay every genuine old version
to another sealed peer, which fetches and keeps them all until a write holder meets it and names
them, bounded only by the folder's history, chunks included, and again once per life of the cleanup
that names each, until a watermark expires that cleanup, at least a year (sooner while a write
holder's clock is wrong or faked, TM-40): an edit of a file does not reopen its history for naming,
but old versions sent again after it stay at that sealed peer until
the cleanup that named them is forgotten (`protocol.md` §4.4, "Stale copies at a sealed peer, and
their bound"; TM-22), and can offer such versions to read and write holders, which drop them as
replaced, or, for a file more than 32 devices wrote since, keep them as conflict copies
(`protocol.md` §4.4, "Why it is safe" 5); **make write holders name them**: each such version a
write holder meets costs it one signature check and one name in a cleanup that every peer receives,
at most once per life of the cleanup that names it, however often its file is written meanwhile, at
most `MAX_PEER_NAMES` names a window for each device identity it connects under, and at most
`MAX_NOTE_VERIFICATIONS` (4 096) checks per connection in each 10 s, one budget shared by every
folder open on it, about 0.24 s of one core every 10 s at most (`protocol.md` §4.5, "Stale copies");
**learn which records were old deletions**: a cleanup group with an empty `because` (case (c)) names
only records a watermark has expired, which for an index record means a tombstone or tree delete
dated below a watermark, so the sealed peer learns that the index records such a group names were
deletions, and, since a group's `because` whose named records lie at other file IDs
can only be a tree delete, which records are tree deletes (the coordinator's ruling of 2026-10-26,
for the owner's review), and, from a cleanup with no group (case (d)), when a write holder signed a
watermark; **take a version away from another sealed peer for a while**: replaying a
genuine old tombstone, or a tree delete and its cleanup, whose deletion read and write holders have
forgotten, makes another sealed peer drop the version it names, which came back after that deletion
was forgotten and is live at the read and write holders, until a write holder meets that peer and
names the replayed deletion (`protocol.md` §4.4, "Stale copies at a sealed peer"); **bring back a
forgotten deletion**: offer again, whenever it likes, a version it kept whose tombstone or tree
delete a watermark has forgotten, which then becomes live again on every peer,
beside any file created at that path since, as a conflict copy (`protocol.md` §4.4, "Expiry by the
watermark"), and then, by replaying a record that every release judges a fault, or one of a kind no
release knows, that named that version, have each device that put it back on its disk move its copy
to the archive again and keep it there past the archive's retention until a save covers it (section
3.6, "keep copies past the retention"; the re-confirm review of 2026-11-10), bounded, as the rest,
by the folder's history; and **make a tree delete take a file its writer never saw**, by
withholding, or delivering late, the new version of a file renamed within a directory while
delivering the tombstone of its old name, so that a device that deletes the directory meanwhile
deletes the renamed file too, which goes to the archive where it was held (`protocol.md` §4.4, "Why
it is safe" 8a; a reconciliation's delivery order can do the same by chance); **withhold
watermarks** from a read or write holder that meets no one else, which then keeps deletions that its
peers have forgotten, a delay and never a loss; and **hold forgetting back**, as a write holder's
only link (and so can a holder of the read key, section 3.2), by releasing the folder's deletions
to it slowly, each young when it arrives, in any order (it need read no counter for that), so that
its candidate never passes them and forgetting is delayed without bound where no other write
holder signs: the owner's decision of 2026-11-12 on a slow release, "Accept, documented", which
costs storage and never a file (`protocol.md` §4.4, "What holds forgetting back"). It reads no
watermark and cannot sign one.

Cannot: see a path, a directory's contents, a kind, a true size, a time, a mode, a device ID inside
a record, a counter, a vector, or whether a record is a tombstone, short of the old deletions and
the tree deletes above; resolve a conflict, apply a deletion or forget anything by itself, since it
drops a record only when a signed record or a write holder's signed cleanup names it (TM-17); make a
read or write holder drop a version, since every drop needs a signature a sealed key cannot make;
make a cleanup remove a later version, since a cleanup names exact fingerprints (`protocol.md` §4.4,
"Why it is safe" 12); make a read or write holder hold again a deletion or cleanup that a
watermark it holds has expired, which it ignores unverified for as long as it holds that watermark's
cleanup, or forget anything early, since a watermark is a write holder's signature (`protocol.md`
§4.4, "Expiry by the watermark", "Why it is safe" 14); make a write holder sign a name for a record
whose signature it has not verified, verify again a record it has noted, or name a record that a
record it holds already names or that a cleanup it holds names in any group, whether or not that
group still applies (`protocol.md` §4.5, "Stale copies"); insert or replace key material and have a
client re-encrypt under it, because no key travels inside a folder and every record is verified
under the folder key (TM-9, Nextcloud key insertion); cause a client to fall back to a default or
empty key (TM-10, Nextcloud ghost key); use anything as a key-wrapping oracle, because nothing is
wrapped and every purpose key has its own derivation label (TM-11, MEGA); provoke a nonce reuse by
making a client re-encrypt, because chunk nonces are content-derived and every other nonce is random
(TM-12); drop, reorder, duplicate or substitute chunks within a file unnoticed, because the file
record signs its full chunk list and each chunk is verified against it (TM-13); forge or alter a
record (TM-9); serve an older snapshot as current to a peer that has persisted newer records,
because a peer never moves backwards on another peer's say-so (TM-17): a peer with nothing persisted
for a path, as on a first sync, accepts what it is shown, syncing from more than one peer narrows
that window, and the stale or withheld copy is found the moment a fresher peer is met (TM-41); make
two read or write holders that meet hold different records (TM-41); learn names, since names and
structure are inside the encrypted index and a path tag is a keyed hash that it cannot compute for a
guessed path (TM-33, TM-14); learn from hashes whether a known file is in the folder: plaintext
chunk hashes are keyed per folder, and the ciphertext hash of a guessed file needs the data key to
compute, so a sealed peer cannot even name the chunk it would ask about, and its requests for hashes
it took from the signed records confirm nothing it did not know (TM-14); its lengths are the
residual above. A relay that holds no key to the folder also cannot open a folder proof or tell
which folder a connection proves (TM-32).

### 3.4 A stolen or lost device

An attacker with physical possession of a device, or with its disk image. What they get is what the
device held, for as long as each folder exists.

Can: read whatever plaintext the device held on disk; use every folder key the device held, at its
tier, from any device and for ever, if they defeat the key store's protection (the operating
system's keystore, or the passphrase of a store without one; `keys.md` §8.2, TM-6), since no key
expires and none can be revoked; with a write key, do everything in 3.2; with a write or read key,
read everything the folder holds now and everything its members add later, until they share again.

Cannot: derive another folder's keys, or a higher tier's key from a lower one (`keys.md` §1.2);
learn anything about a folder the device never held, beyond the catalogue of a linked device
(phase 5).

The recovery is: the people who stay unlink each folder the device held and share it again (TM-42,
`keys.md` §7.4). The attacker keeps the old folders, and everything that any device still using an
old key adds to them. The keystore is the operating system's and is out of scope.

### 3.5 A hostile or leaked invite

An invite is one of the folder's three key strings, carried as a link, QR code or file; whoever has
the string holds the key. A key string sent over a channel an attacker can read (an email, a chat)
is a leaked invite: the plan's rule is that an invite travels by QR code or over a channel the user
already trusts.

Can: join at its tier from any number of devices, for as long as the folder exists: an invite has no
expiry, no use count and no approval step (plan, Folder keys); if the sender appended addresses,
learn the sender's current addresses; keep the folder ID for ever, and with it compute every day's
DHT discovery hash and watch which addresses announce it (section 3.9) and confirm the folder's
presence on any LAN it listens to (section 3.1); if it is a write key, do everything in 3.2.

Cannot: exceed its tier; learn the sender's home address from a bare invite, which carries no
addresses by default (TM-37); leak the secret through a web server, referrer or landing page,
because in a link the secret sits after `#` and the client origin serves no page that would log it
(TM-18).

The design's answer to a leak is to share again (TM-42); there is nothing in between, and the app
says so when it shows a key (TM-39).

### 3.6 A dishonest writer

A write-key holder, or anyone with a stolen write key, that tries to destroy, mislead or exhaust.
Write holders are trusted (section 3.2): this subsection says what that trust costs and what still
holds. A write holder acting on purpose is in scope and accepted, not out of scope.

Can: make any change, including destroying everything, which the archive limits only in how much is
lost for good: deletions that arrive from peers are applied without a brake (the owner's answer of
2026-10-22), and the archive keeps every file they removed, 30 days by default, on each device whose
versioning is on (TM-35); sign two different records with one dot (device ID and counter), which
every peer keeps as concurrent versions, never as evidence against anyone (TM-41); give a record any
vector, under its own device ID or another's, so that its version of a path replaces whatever
versions the vector covers, or a tree delete any vector, so that it deletes whatever beneath its
directory the vector covers, the replaced and deleted versions going to the archive (`protocol.md`
§4.4); **make vectors churn**: sign under any number of device IDs, which costs peers the records it
signs and, for the device IDs that connect, per-peer state bounded at `MAX_PEER_STATES` per folder,
since there is no per-writer table and a vector never holds more than 32 entries; what it costs
others is that a device that was away while more than 32 device IDs wrote one path sees an old
version of it as a conflict copy once (`protocol.md` §4.4, "Why it is safe" 5, TM-41); **flood
heads**: sign any number of concurrent versions of one path, which every peer keeps until a write
covers them, at most 32 per write (`protocol.md` §4.4), versions of one content (twins) as much as
others: a write covers the twins of what its writer has on its disk, up to 32, and those left over
are conflict copies of that content after an edit, or the file back after a delete, until the next
write; and a tree delete names at most 32 records at its directory's own path, so records there
from more than 32 device IDs (identical directories, or conflict copies) come back after it, until
the next delete (`protocol.md` §4.4, "A tree delete"); **forge twins**: sign a version whose
plaintext hashes are those of an honest device's version at a path, concurrent with it, after it in
display order and not the first head there, which that device's next write there then covers and
names (`protocol.md` §4.4, "Bases"), only removing the
forged version, and whose vector the write joins. Through a tree delete that join reaches further
than the forged version does: each entry of its vector covers the records of that entry's device at
other paths beneath the directory, versions the deleter holds whose content may not have reached
its disk ("Why it is safe" 8a). It gains the forger nothing it lacks: a forged version given a later
`mtime_ns` becomes the base, its vector joined as much, with no twin at all; and a write holder can
sign any tree delete, with any vector, itself; **issue cleanups**: name any record in a signed
cleanup, so that every peer forgets it, the same power over sealed peers that writing over a file or
deleting it gives over everyone (`protocol.md` §4.4, "Cleanup"), the cleanup that carries the
greatest watermark included, which lowers it wherever the naming cleanup is held, so that the
deletions it had expired are held again when they are offered, and the commit that lowers it owes
a round on every connection to a peer that reports the read or write tier, so that honest peers
that meet converge
(`protocol.md` §4.4, "Expiry by the watermark"; §4.5, "Round owed"); **keep copies past the
retention**: sign records that every release judges faults, or of a kind no release knows, naming
the versions at paths, so that each device that had one of those versions on its disk moves its copy
to the archive and keeps it there, past the archive's retention and with versioning off, until a
save covers that version (TM-35; `protocol.md` §4.4, "A path with no heads"; a stated residual of
the confirm review of 2026-11-10): bounded as flooding heads is, since each copy kept is a version
the device downloaded and had on its disk, which the write holder could as well keep there as a
conflict copy, so nothing is amplified, and the index remembers one archived version for each; a
sealed peer that kept such a record can replay it later, to have a version that came back after its
deletion was forgotten archived and kept so again, bounded by the folder's history (section 3.3);
**exhaust counters**: sign a record
whose counter is at or just below `MAX_COUNTER`, the fixed ceiling 10 000 years after 1970, after
which no device can write in the folder until it is shared again: the ceiling refuses only a counter
above it, alike on every device, and no rule that reads no clock can refuse one just below it, so
this is a stated residual (`protocol.md` §4.4, "The counter ceiling"; the research of 2026-11-08,
S2; the owner's decision of 2026-11-12 on this risk, "Accept, documented"); or sign one whose
counter lies far ahead of real time,
which the Lamport rule carries to every later record until real time catches up, and with it the
counters at which watermarks are signed, so that deletions by devices that have not yet held it are
forgotten early, files coming back; **sign a watermark** at any counter below its cleanup's own,
which makes every read and write holder that comes to hold it forget at once every tombstone, tree
delete and cleanup at or below it, and ignore them when they are offered again, so that the files
they deleted come back wherever a copy survives, at a device, a sealed peer or a key holder that
kept them, never lost (`protocol.md` §4.4, "Expiry by the watermark"); **hold forgetting back**:
sign, again and again, a tombstone dated just above the greatest watermark held, which every write
holder then holds less than a year, so that no write holder's candidate passes it and nothing more
is forgotten for as long as it goes on, which costs every read and write holder storage and a
verification per deletion kept at each open, and never a file (the owner's decision of 2026-11-12,
"Wait, never early"; `protocol.md` §4.4, "What holds forgetting back"); write names that are not in
Unicode NFC, which readers do not check and which are then paths distinct from their NFC forms
(`protocol.md` §4.4); flood with records and chunks; give the write key to anyone; act without being
identified, since records name only a device ID their signer chooses, never shown as an author, and
nothing records who changed what (the owner's decision, 2026-10-18).

Cannot: be removed except by the others unlinking and sharing again by hand (TM-42); make honest
peers that meet hold different records, because set digests over record hashes find every difference
and the exchange sends what each side lacks (TM-41, Kleppmann 2022); roll back a peer that has
persisted newer records (TM-17; a peer with no persisted state for a path accepts what it is shown
until it meets a fresher peer); have a record accepted without the folder key's signature; slip a
seal or a chunk past a reader's checks without an issue that names the record (TM-10); destroy a
file beyond the archive's reach on a device whose versioning is on (TM-35).

### 3.7 An attacker on the local network or a web page attacking the local API

The service exposes its API on a Unix socket or named pipe and on localhost HTTP for the web UI. The
attackers are another user on the same machine, a program on the LAN that resolves a hostname to
127.0.0.1 (DNS rebinding), and a web page in the user's browser making cross-site requests.

Can: send requests to localhost from a page the user has open; rebind a DNS name to the loopback
address and have the browser send requests with a foreign Host header; try the socket if its
permissions allow.

Cannot: have a request acted on without the token, which only the local user's CLI and web UI hold
and which is required on every request (TM-21, Dorsey 2018); succeed with a rebound hostname, because
the Host header is checked against the listener's own address and the Origin header against the UI's
origin (TM-21, Syncthing's host check); read the token from the page, because the UI's origin and the
browser's same-origin policy keep it out; read key material through the API, which never returns a
device seed or a derived key and returns a folder key only from the export command the person runs,
with the operating system's own authentication for a write key (TM-39); inject HTML through
peer-supplied strings, which render as text (TM-20); reach the native core from the app's web view
except through the commands its capability lists (TM-27).

### 3.8 A compromised static host for the browser client

licketysync.app serves the WebAssembly bundle. Subresource integrity cannot protect a page against
its own host, so a host that is compromised can serve a changed client to anyone who loads it.

Can: serve a bundle that exfiltrates keys or content for every user who loads it while it is
compromised; serve a correct bundle to the people it expects will check, and a changed one to
others.

Cannot: see invite secrets in requests, because they travel after `#` and the client origin serves no
landing page (TM-18); go undetected by a careful user, because each release publishes a signed
manifest of the bundle's hashes that the native app can verify against a served bundle, and the site
documents WEBCAT and Code Verify-style extensions as the way to check the page that loaded (TM-28);
affect native clients, which never load code from the host (TM-29, TM-31). What remains is stated
plainly: the service worker cache gives no protection against the host beyond its update interval,
since the host also serves the service worker; the native app's manifest check and a verifying
extension are the only checks; and a first-time visitor with no native device of their own and no
verifying extension trusts the host at the moment of loading, exactly as with any web application.

### 3.9 A Sybil or eclipse attacker on the DHT

Someone who runs many DHT nodes to surround a target's position in the routing space, enumerate
announcements, or use the DHT as an amplifier.

Can: see which addresses announce a given day's discovery hash, if they know the folder ID, and,
at the nodes they run that a lookup reaches, which addresses look it up; and the stable identifiers
each announcing device publishes (the BEP 44 key its address record is signed with, its DHT node ID;
the record carries no libp2p peer ID, the DeviceProof binds identity at the handshake instead, and
no list of the hole-punch coordinators the device uses, which travels only to its folders' peers and
in invites: the owner's decision of 2026-11-10, TM-25); serve an old signed address record to a
reader that holds no newer one, which is harmless because the address is only a dial hint and the
handshake decides the rest; eclipse a device so that its lookups return only the attacker's nodes,
denying discovery through the DHT; enumerate announcing addresses by crawling.

Cannot: turn a discovery hash back into the folder ID or any key; gain access to a folder by seeing
or impersonating its peers, since access needs a key (TM-32); link a folder's announcements across
days from the hashes alone, since the hash rotates daily (TM-24), though anyone who ever held the
folder ID (any key holder, anyone who saw a key string) can compute every day's hash, and a
device is linkable across days by a stable address or by a stable identifier it publishes with the
announcement (BEP 44 key, persisted node ID); use the device as a `get_peers` amplifier or exhaust it,
since the DHT runs in client mode unless the person turns on server mode, which adds a per-source
rate limit and bounded responses (TM-24, Adamsky 2015); replay an old BEP 44 address record over a
newer one a reader already holds, since the sequence number is persisted and never reused (TM-24);
affect anyone who has not turned the DHT on (it is off until its person turns it on, TM-24).
Eclipse denies one discovery
method; LAN, direct addresses and peer exchange remain, and so do public relays where the person
turned them on and learned of them other than through the DHT (from peer exchange or a list the
person adds, TM-25).

### 3.10 A resource-exhaustion attacker

Someone who opens connections, streams, reservations or registrations faster than a device can serve
them, or sends messages whose declared lengths would make the device allocate unbounded memory.

Can: send any number of connection attempts, handshakes, Hello messages, folder proofs, chunk
requests and relay reservations; declare absurd lengths; send malformed input to every decoder.

Cannot: make the device allocate before a length limit is checked (TM-2); grow any per-peer table
without bound, because every table is bounded, none grows with the number of writers in a folder,
and each dies with its connection or, if it outlives one, holds a fixed number of entries (TM-22,
go-libp2p and rust-libp2p 2022); make the device verify anything for a folder proof without holding
a key to the folder (TM-22); make it verify a record's signature except to store a record it lacked,
drop records it replaces, note a stale copy it will name, or close the connection (TM-22); hold
unlimited relay circuits or reservations, reserve a relay or a coordinator, or ask a coordinator for
a punch, through a relayed connection, make a hole-punch coordinator carry more than a punch's
set-up or more punches than its limits allow, aim a punch at more than a few public addresses or at
any private one, or have a device take a punch without being a peer of one of its folders whose
settings allow that punch or proving a key to one (TM-25), though one with many addresses can hold a
relay's or a coordinator's places from others, a requester that a device refuses but that has its
coordinators can use up the device's caps through them, and a punch can reach a private address
through a translator on its network whose prefix or mapping the side cannot learn, or through a
non-default route to a publicly numbered network (TM-25's stated residuals);
amplify through QUIC, whose three-to-one anti-amplification
limit stays at its default (TM-22), or through the DHT (TM-24). A panic on malformed input is made
unlikely and caught before merge rather than made impossible: every decoder is fuzzed, `unwrap`,
`expect` and `panic` are denied, and indexing on untrusted data warns and the gate treats warnings
as errors (TM-3, TM-23, rust-libp2p 2026 QUIC panic). What it can still do to the transport as phase
0 builds it, each a phase 1 item required before 1.0 (TM-22's residuals (a) to (c), owner,
2026-11-03, and (h), owner, 2026-11-08): cost the device a QUIC connection and a TLS server
handshake per Initial it sends, whatever the limits, at its own send rate, so that memory and CPU
follow that rate and connections are refused while they last; hold every pending slot with
connections that never finish their handshake, locking every inbound peer out for the handshake
timeout (10 s) at a time; as one TCP peer that delays its yamux pings, grow its connection's receive
window toward yamux's 1 GiB ceiling; and, as one QUIC peer that sends its stream data as small
datagrams back to back, which the device's GRO coalesces into one read each whether or not the
sender used GSO, keep alive far more memory than its connection's 4 MiB window counts, about 2 GiB
at the 64 KiB a read that is the realistic bound, by reading the code, not measured; (h) concerns
the native program, whose QUIC connections, those it accepts and those it dials, run on quinn, not
the browser client, whose QUIC is the browser's own. On iOS it can do nothing to the transport,
because there is none yet: `net` has no memory limit there and refuses to start until it has one
(TM-22's residual (d); the owner's answer of 2026-11-03 on the iOS gap: required before 1.0, fixed
in phase 4). Denial of service by sheer traffic volume is out of scope (3.12); a write holder's
flood is section 3.6's.

### 3.11 Supply-chain and update attackers

Named here because the hardening review names them, though they attack the build rather than the
protocol: a malicious or compromised dependency, a tampered update, a downgraded install.

Cannot: enter the build unnoticed, because a new dependency needs a written reason, an active
upstream and clean cargo-deny, cargo-audit and cargo-vet runs, and cargo-geiger's unsafe counts may
not change without a reviewed baseline change, and cargo-audit runs daily as the advisory feed
(TM-7, TM-8); install as an update without a verified signature or at a lower version than the one
running (TM-29, Syncthing 0.12.23); pass off a tampered or unreproducible build as a release, because
releases are built in CI, signed, and published with an SBOM and build provenance (TM-29); phone home,
because the binary contacts no host that `spec/allowed-hosts.txt` does not list and CI enforces the
list (TM-31).

### 3.12 Out of scope

These are stated so that nobody mistakes silence for a promise.

- **The operating system and the network the program runs on.** A kernel, a keystore, a random
  number generator or a file system that lies is not defended against. Malware running as the user
  reads what the user reads, keys included.
- **The device's own index store at rest**, and any backup of it restored into it, for what it keeps
  and nothing more: every record in it is verified again when the folder opens, and one that fails
  is dropped and reported (TM-9), so corruption or tampering at rest cannot make the device apply or
  serve a change no write holder signed. What a store changed at rest can still do is lose or
  withhold records, as an older backup would, and, on a write holder, change the arrivals it keeps,
  which no signature covers: earlier arrivals make the device sign a watermark early, so that
  deletions are forgotten early and files come back, never lost (`protocol.md` §4.4, "Expiry by the
  watermark"). No stored record keeps a folder closed for its counter. The device fetches the
  records again from its peers, with these stated residuals: a record that no peer holds stays
  missing; a record that a missing
  one covered may be live here again until the missing one returns; withholding this device's own
  records lowers its high-water mark only to its clock floor, so its next counters stay above those
  it used unless its clock reads earlier than its last write (`protocol.md` §4.4, "Why it is safe",
  A2); and records that only this device held are lost. **The key
  store** stays trusted, since whatever can change it can replace the folder's keys.
- **Denial of service by traffic volume** that a home connection would already fail under. The
  program bounds what it allocates and accepts; it cannot keep a saturated link usable.
- **Multi-file atomicity.** A git repository, an SQLite database, a password manager's vault or any
  set of files that must change together is synced file by file; a peer may observe a state no
  writer ever had on disk. The site's Limitations page says so.
- **Phone background limits.** A phone that the operating system has suspended does not sync, and a
  sync that it interrupted resumes later; nothing the program does can promise otherwise.
- **Traffic analysis beyond padding.** Section 5 lists what sizes, counts and timing reveal; Padmé
  padding reduces size fingerprinting and nothing hides volume or activity patterns.
- **The channel an invite travels by.** A key string read off an email, a chat or a photographed
  screen is a leaked invite (section 3.5); the program cannot protect a key after a person sends it.
- **Social engineering of a key holder** into giving out a key or linking a device.
- **Coercion.** There is no duress mode or deniability.

## 4. Requirements

Each requirement is one rule, the attack it stops with the incident the plan's hardening review
cites, and the layer that enforces it. "Enforced by" names the crate or layer whose tests carry the
proof; "reviewed in" names where a change must be checked against it even when it does not touch the
enforcing crate. Some requirements overlap on purpose (TM-2 and TM-22 on bounds, TM-9 and TM-41 on
records, TM-6 and TM-39 on secrets leaving the process): each states one rule from one angle, and a
change cites every number that applies.

**TM-1. The protocol has no plaintext mode.** A peer that cannot complete the encrypted handshake is
dropped, on a LAN exactly as over the internet, and no setting turns this off; and each transport
offers exactly one security protocol (TLS on QUIC and TCP; Noise only inside WebSocket, WebTransport
and WebRTC), so nothing weaker can be negotiated before authentication either. A relay's or a
coordinator's circuit (TM-25) carries an end-to-end channel of its own: TLS 1.3 with X25519MLKEM768
first, as on QUIC and TCP, between two native ends, and Noise only where a browser client is one
end, since libp2p TLS does not build there; a native dialer offers exactly one of them, so a device
in the middle that rewrites the negotiation gets a failed handshake, never a weaker one between two
native ends, and a native listener accepts Noise on a circuit only from phase 6, for browser
clients (`suites.md` §2.6; the spec author's choice, for the owner's review). What this does not
stop is stated: an attacker who blocks UDP and raw TCP steers a dialer onto the WebSocket path,
which is classical end to end as `libp2p-websocket` ships it (its outer TLS is rustls on `ring`; a
recorded deviation with a phase 2 item, `suites.md`, transport); that path is still encrypted and
authenticated, and the cost is what section 5's quantum entry lists. Stops passive reading and active
downgrade of the transport; the lesson of every protocol that kept a fallback. Enforced by `net` (no
unencrypted listener or dialer exists, one security protocol per transport) and `protocol` (no
message type is defined outside a session).

**TM-2. Every byte from a peer is untrusted, and length limits are checked before allocation.** Every
length field is compared against the limit the Hello agreed or the protocol fixes before any buffer
is sized to it, and every collection a peer can grow is bounded. Stops memory exhaustion from
declared lengths and unbounded tables (go-libp2p and rust-libp2p resource-exhaustion advisories,
2022). Enforced by `protocol` (framing) and `net` (per-connection budgets); reviewed in every decoder.

**TM-3. Every decoder is fuzzed.** Every network message, key string, word list, record, invite link,
file name and path decoder has a `cargo-fuzz` target with a committed corpus, run thirty minutes each
nightly today, and ten minutes per push and continuously once ClusterFuzzLite's configuration exists.
Stops crashes and panics on malformed input (rust-libp2p 2026 remote panic in the QUIC handshake).
Enforced by `fuzz/` and CI; a decoder without a target does not merge.

**TM-4. One beneath-root path resolver; symlinks are never followed.** Every subsystem that touches
the disk, including versioning, trash, temporary downloads, conflict copies, the ignore file and the
marker, resolves paths through one function that normalises, refuses traversal, reserved and
platform-invalid names, and refuses to follow a symlink at any component; the symlink-then-directory
sequence (a peer sends a symlink, then a directory of the same name, then a file beneath it) is a
committed test. Stops path traversal and symlink escape through a second code path (Syncthing 2016
traversal; CVE-2017-1000420 in versioning). Enforced by `engine`; `.semgrep/project.yml` forbids
`std::fs::canonicalize` and `read_link` throughout the workspace, the resolver included, which opens
with no-follow semantics instead.

**TM-5. Cryptography comes only from `suites.md`.** No primitive, combiner, key derivation, padding
scheme or random generator whose output reaches a key, a nonce, an identifier or any byte a peer
sees is written in this workspace; every algorithm and crate is the one `suites.md` lists, at the
version range it pins, and nothing not listed is used until a reviewed change adds it. The two
padding schemes written here are Padmé, for chunks, and the power-of-two padding of sealed metadata,
both in `keys`, which `suites.md` lists as written here because no approved crate provides them
(`suites.md`, data encryption). The one generator written here is the simulator's seeded statistical
one (SplitMix64 in the `sim` crate), which feeds the runtime's randomness trait in simulator runs
only, so secrets, nonces and salts in a simulated run come from it; it is not cryptography, `sim` is
never a dependency of `daemon`, `cli` or `decrypt` (reviewed on every `Cargo.toml` change), and no
production build contains it, so this rule permits both and says so (`suites.md`, randomness). Stops
the class of flaw that hand-written combiners and wrappers introduced in MEGA 2022 and Nextcloud
2024. Enforced by `deny.toml` bans and cargo-vet; reviewed in every change that touches `keys`,
`protocol` or `engine`.

**TM-6. Secrets live in zeroized types and never reach logs.** Write secrets, data keys, access keys
and every key derived from them, signing keys, device seeds, store keys, passphrases and session
keys are held in types that zeroize on drop, whose `Debug` output is redacted, and that are never
formatted into a log, error message or panic payload; logs redact folder IDs and addresses by
default. Stops secrets leaking through crash reports, log files and debugging output, which is how
the Tahoe-LAFS and BitTorrent Sync analyses found capability strings in the clear. Enforced by `keys`
(types) and `daemon` (logging); the rules are in `suites.md` section 4. One recorded deviation
(2026-11-03, to raise upstream): beneath `net`, `libp2p-identity` 0.3.1 keeps the libp2p identity's
secret key in types that are not wiped on drop and are cloned into the TLS and QUIC configurations
(`suites.md` 4.1); `net` refuses to build a node while `SSLKEYLOGFILE` is set, since `libp2p-tls`
gives every TLS configuration rustls's key-log writer. A second (spike B, feature `webtransport`;
proposed, for review): the WebTransport listener's certificate key is copied through `wtransport`
and rustls types that are not wiped on drop (`suites.md` 4.1); its rustls configuration keeps
rustls's default key log, which writes nothing.

**TM-7. No `unsafe` outside the platform-FFI crates.** The workspace lint `unsafe_code = "forbid"`
applies everywhere; a platform-FFI crate opts out explicitly and is covered by Miri nightly;
cargo-geiger's count is a report that CI publishes and reviewers read, and `ci/geiger.sh` (CI and
`gate.sh`) fails when any of a crate's five used unsafe counts (functions, expressions, impls,
traits, methods) differs from `ci/geiger-baseline.txt`, until a reviewed change to that file accepts
the new counts. CI scans in full on pushes to main and on pull requests; `gate.sh` skips the scan
when the inputs `ci/geiger.sh` lists are those of a scan that passed. The gate catches a change in
the unsafe code the build uses when its listing covers the change; otherwise CI catches it on main,
where it is fixed forward. Stops memory-safety bugs reachable from untrusted input. Enforced by
`core/Cargo.toml` (the lint), `ci/geiger.sh` (the counts) and review (each change to them).

**TM-8. A dependency enters only by a reviewed change with a written reason.** A new dependency needs
the reason in the changelog and the report, an active upstream, a clean `cargo deny check`,
`cargo audit` and `cargo vet --locked`, and an exemption, if one is needed, with its justification
committed in `supply-chain/`; the lockfile is committed, Dependabot's updates are reviewed before
merge, and cargo-audit runs daily in CI as the advisory feed, so a vulnerability published after a
crate was added is caught without a code change. Stops a malicious or abandoned crate reaching the
build. Enforced by `gate.sh` and CI.

**TM-9. Updates are accepted only when signed by the folder's write key, and no key travels inside a
folder.** Every index record is verified with the folder's verification key, which every key at
every tier carries, before anything in it is charged to anyone, and is stored only if it verifies
(an exact duplicate of a record already held, a tombstone, tree delete or cleanup that a watermark
held has expired, and an obsolete record, one that something held replaces, by a name, a cleanup
group that applies, coverage or a tree delete above it, and that replaces nothing held, are ignored
unverified, since nothing of them would be kept, `protocol.md` §4.4 steps 2 and 3; a write holder
verifies one before it notes it as a stale copy to name); a record whose vector covers held versions
drops them only once its signature has verified; read and sealed holders cannot sign, so every peer
rejects a change they make. Nothing a peer sends can add, replace or change a folder's keys, because
no record carries key material: keys move only as key strings outside the protocol and, between a
person's linked devices, over an authenticated channel (`keys.md` §8.3); a record handed over by a
sealed peer is data to be verified, never a reason to act. A device's own index store, and any
backup of it restored into it, is trusted to keep its records but not for their authenticity (the
owner's decision of 2026-10-25): a record is verified before it is stored and again every time its
folder opens, when every stored record gets step 1 against the folder and its signature under the
folder's verification key, at every tier, the signatures spread across the processor's cores
(`protocol.md` §4.4, "Opening a folder"); the engine (when it lands) shows the folder as Checking
meanwhile. A record that fails, because it was corrupted or edited at rest or is not this folder's,
is dropped: it is not applied, held, counted in a set digest, or served, and the open reports it by
record hash, so that the engine's folder state shows the problem and an issue (when the engine
lands) gives the count and names at most 16 of the records by hash (`protocol.md` §5). The bases a
device keeps for its own disk (`protocol.md` §4.4, "Bases") are checked the same way, and the stored
high-water mark is accepted only up to `MARK_SLACK`, a day of counters, above what the records held
and the clock floor justify, so that a mark changed at rest can neither lock the folder nor push the
device's counters far ahead. No stored record is dropped for its counter, and no clock keeps the
folder closed: a store whose records lie far ahead of the clock, after the clock was set back, opens
like any other, and the next write takes a counter above them. A write holder's arrivals, the local
notes by which it decides when to sign a watermark, are read back as stored and checked against
nothing, since no signature covers them: a store changed at rest can make the device sign early,
which forgets deletions early and loses nothing (`protocol.md` §4.4, "Opening a folder", "Expiry by
the watermark"). The live records, tree deletes and set digests are rebuilt from the records held,
and the device draws a new index epoch, so index sync fetches every genuine record dropped or
missing again from the peers that hold it. A store changed at rest can therefore at worst lose or
withhold records, or bring a watermark forward, with the residuals section 3.12 states; it can no
longer make the device apply a change no write holder signed, serve records its peers refuse as
forged, or count a junk record in a set digest. The check costs one Ed25519 verification per stored
record: opening 100 000 records of 100 writers took 5.6 to 6.1 s on one thread and 2.5 to 3.3 s on
all eight threads of a four-core laptop processor, against 0.5 to 0.8 s without the check (release
build, measured 2026-10-25 on a machine shared with other builds, whose clock moved between 1.3 and
2.5 GHz, so the figures are ranges). A labelled keyed checksum per stored record, which would need a
per-device secret, be forgeable by anything that reads it and be lost on reinstall, is adopted
instead only if measurements on a phone or NAS show start-up too slow. The key store remains trusted
(section 3.12). Stops key insertion, where a storage party introduces or replaces key material and
the client re-encrypts everything under it (Nextcloud 2024, Albrecht et al.), and forged changes,
including changes written into a device's own index store at rest. Enforced by `keys` (signing and
verification) and `index` (verifies before storing and again when the folder opens); `engine`
applies only stored records and, when it lands, shows the folder as Checking while its index opens.

**TM-10. Fail closed.** Any decryption failure, signature failure, hash mismatch or malformed record
that arrives on a connection ends in exactly one of three outcomes, none of them silent. The
connection that delivered it is closed, with an issue naming the peer and the cause, for what only
the sender can be blamed for: bytes that do not parse or do not verify, a broken order or bound. The
item is set aside and the connection kept for differences in what two peers hold (a duplicate, an
obsolete or expired record, a stale copy, a cleanup group waiting for its `because`, a set digest
that differs, a proof for a folder that is not here, a chunk the holder lacks), which the exchange
then repairs. An issue names the record (by hash, and by path where its seal opened; never a device,
since nothing proves which device wrote it, ruling S-4), the record is kept opaque or the chunk
marked corrupt, applied by no one, and the connection kept, for a failure inside what the folder key
signed (a seal that will not open, a chunk that fails its plaintext hash), because the body is what
a write holder signed and the sender, perhaps an honest sealed peer, merely forwarded it. A record
in the device's own index store that fails step 1 or its signature when its folder opens involves no
connection: it is dropped and reported, never applied or served (TM-9; `protocol.md` §5, "Stored
record fails its check"). One refusal is deliberately uninformative: a folder proof that fails for
any reason gets the same uniform REJECTED and the connection is kept, so that a probe learns nothing
about which folders a device holds. Nothing is skipped, defaulted or retried with weaker checks, and
no key has a default value; `protocol.md`'s rules table is the complete record of which cause has
which outcome (decision 2026-10-15: refines the plan's "drops the connection": a failure inside a
validly signed body keeps the connection, because the sender may be an honest forwarder). Stops the
"ghost key", where a missing key became an all-zero default and failures were skipped silently
(Nextcloud 2024). Enforced by `keys`, `protocol`, `index` and `engine`: every verifying function
returns a typed error and every caller propagates it to the connection; `clippy::unwrap_used` and
`expect_used` are denied.

**TM-11. Every purpose key has its own label, and associated data binds every ciphertext to its
place.** Every symmetric key, nonce key, chunk-hash key, handshake hint and payload key and signing
seed is derived from its parent with BLAKE3 `derive_key` under a distinct label registered in
`keys.md`, so no key serves two protocols and no key is used raw for two purposes (the access key
only parents the two handshake keys); chunk ciphertext is bound to its folder (its associated data
is the folder ID), an index record's sealed metadata to its folder and file ID (`folder_id ||
path_tag`, 64 bytes) and a cleanup's to its folder (32 bytes), the signature binding either to the
rest of its record, and the handshake payload to its hint, so a ciphertext cannot be moved to
another folder, record or connection; and no key is ever wrapped to a public key, so there is no
wrapping oracle. Stops one key reused across protocols and ciphertext moved between contexts (MEGA
2022, mega-awry.io). Enforced by `keys`; the labels are in `suites.md` section 2.4 and `keys.md`'s
label registry, their test vectors in `suites.md` section 4.4.

**TM-12. Fresh nonce per write; never a reused nonce under one key.** Every encryption uses either a
192-bit random nonce through the runtime's randomness trait (the operating system's generator in
production) or, for chunks only, a nonce derived with a keyed hash, under the folder's chunk-nonce
key, from the padded plaintext being encrypted, whose associated data, the folder ID, is a function
of the key alone, so that the same key and nonce never
meet two different plaintexts or two different associated data. Stops nonce reuse on re-encryption
and the two-time pad it creates (Nextcloud 2024; pCloud, Icedrive and Seafile 2024). Enforced by
`keys` (chunk and record sealing, with `keys.md`'s chunk vectors) and `engine`, which calls it and
never encrypts on its own; the rule is `suites.md` section 2.3.

**TM-13. Each file record signs its full chunk list.** A file's index record carries the ordered list
of its chunks (their hashes and sizes, as `protocol.md` lays them out) under the folder key's
signature, and a receiving peer accepts a chunk only at the position the record names and only if
its hashes match. Stops a store dropping, reordering, duplicating or substituting chunks unnoticed
(pCloud, Icedrive and Seafile 2024). Enforced by `keys`, which owns `SignedRecord` and the record
hash, `protocol`, which owns the wire format, and `index`, which verifies records; `engine` checks
each chunk against the verified record before it writes.

**TM-14. Keyed BLAKE3 per folder for chunk hashes; have-queries answered only inside the folder.**
Plaintext chunk hashes use BLAKE3 in keyed mode with a key derived from the folder's data key, so a
chunk hash is a fingerprint only to read and write holders; sealed peers (not relays) see hashes of
ciphertext only; a path appears in a record's clear fields only as a path tag, a keyed hash under a
key derived from the data key, so a sealed peer cannot test whether a guessed path is in the folder
either (`keys.md` §3.5); chunk boundaries come, from phase 1, from a FastCDC gear table keyed from
the data key, so that a sealed peer cannot cut a file it has and match its chunk lengths with a
record's, with the residual that keyed chunking yields to an attacker that knows some of the
folder's files (`keys.md` §3.2, section 5; phase 0 cuts fixed-size chunks, whose lengths show only a
file's size); and a "do you have this chunk" query is answered only on a connection where the folder
is open, which takes a proof of a key to it. Stops confirmation-of-a-file through content hashes and
deduplication used as an oracle (Tahoe-LAFS known issues; Harnik, Pinkas and Shulman-Peleg 2010;
Syncthing 1.28.0 regression). Enforced by `keys` (`plain_hash`, `cipher_hash`, the gear table),
`engine` (never hashes plaintext another way, and chunks with the keyed table) and `protocol`
(have-queries are folder-scoped). What makes "never another way" hold is cargo-deny: `deny.toml`
lets only `licketysync-keys` depend on `blake3` and on `chacha20poly1305`. `protocol` and `index`
reach hashes only through `keys`, and `protocol` never sees plaintext. In `keys` and `protocol`, a
Semgrep tripwire in `.semgrep/project.yml` flags every call into and every import of `blake3`
outside `keys`'s labels module, which it excludes by path, outside test files, and outside a `mod
tests`, with its cases in `.semgrep/tests/` run by CI; it catches mistakes, not intent (`suites.md`,
hashing).

**TM-15. Padmé padding of chunk sizes; the volume and timing leak is documented, not claimed away.**
Every chunk is padded by the Padmé rule (at most 12% overhead, 3% on average) before encryption, so
that sizes fingerprint less; what padding does not hide is listed in section 5 and on the site,
including the CRIME-style length channel that compression before encryption opens when
attacker-influenced bytes share a chunk with secrets: phase 0 compresses nothing, and a release that
enables a compression states the channel first. Stops size fingerprinting, where 45% of user files
have a unique size (PURBs, Nikitin et al. 2019). Enforced by `keys` (`padme` and the chunk layout)
and `engine` (FastCDC's maximum chunk is at most `MAX_CHUNK_PLAINTEXT`).

**TM-16. Retired 2026-10-22.** Was "Records name their predecessors; equivocation is flagged", with
per-key device admission. With one shared write key whose holders are all trusted, two records with
one dot (device ID and counter) are concurrent versions, kept and applied, never evidence against
anyone (ruling R-K5, kept in the index of 2026-10-25); TM-41 states what holds instead. Per-key
device admission (rulings 33 and 34) went with per-person keys.

**TM-17. Peers persist what they have seen and refuse regressions.** Each peer persists, per folder,
the latest versions of every path it holds, its tombstones, tree deletes and cleanups, and, at a
read or write holder, its high-water mark (`protocol.md` §4.4). A record is dropped only when a
signed record or cleanup that the device holds replaces it, which by construction was written after
it (`protocol.md` §4.4, "Why it is safe" 3 and 10): at a read or write holder by coverage, a name, a
tree delete or a cleanup; at a sealed peer only by a name or a cleanup, a cleanup's group acting
only while the record it was issued for is held, so that a sealed peer never drops a version that no
signed record or cleanup names (11). Besides, a read or write holder forgets a tombstone, tree
delete or cleanup once a watermark it holds has passed it, a write holder's signed decision
(`protocol.md` §4.4, "Expiry by the watermark"), and a device's own store
can lose or corrupt records at rest (TM-9, and index sync fetches them again). Nothing is dropped on
another peer's say-so, a sealed peer's included. A stale snapshot offers versions that
what a read or write holder holds replaces, so they are obsolete and ignored, and a peer that offers
them is simply behind; a sealed peer keeps them as stale copies until a write holder names them. The
limit is stated: a peer with nothing persisted for a path, as on a first sync, trusts what the first
peer it meets shows it, and a stale or withheld copy is found when a fresher peer is met (TM-41);
and pruning a vector or forgetting a deletion can bring an older version back as a head beside a
newer one, or a deleted file back, never replace a newer version with an older one (TM-41). Stops
rollback, where a store serves an older snapshot as current (Tahoe-LAFS known issues; Syncthing's
untrusted-device spec is silent on it). Enforced by `index`.

**TM-18. Invite secrets travel only after `#`, and the client origin has no landing page.** In a
link the key string sits in the fragment, which browsers never send to a server; licketysync.app
serves the client bundle and nothing else, so no page there logs, redirects or renders a link's
secret; the documentation site, on the separate registrable domain licketysync.com, links to the
client and never carries an invite; a link that does not begin with `https://licketysync.app/join#`
is refused (`keys.md` §6.3); and the client, whenever the page's address has a fragment, a refused
link's included, replaces that address with the same one less its fragment (`history.replaceState`),
once it has read the key from it if it carries one, so that the key leaves the address bar and the
page's entry in the tab's history, and a bookmark or a copy of the page's address no longer carries
it (the spec author's choice, for the owner's review). What the browser recorded before the client
ran, in its own list of visited pages and in anything that syncs that list, and the message the link
came in, the client cannot reach: a stated residual. Stops secrets in URLs leaking through
referrers, server logs and landing pages, and narrows what a browser's history keeps to that
residual (Resilio Sync 2024; BitTorrent Sync analysis 2014; Tahoe-LAFS). Enforced by `keys` (the
link parser), `web` (client) and `site` (documentation), reviewed in `app` and `cli` wherever a link
is built.

**TM-19. Retired 2026-10-22.** Was "Revocation, suspension and epochs". There is no revocation,
suspension, lift, rotation, epoch or grant (owner's decision, 2026-10-18); removing someone is
TM-42.

**TM-20. Peer-supplied strings render as text only.** Device names, file names, labels, folder names
and every other string that arrived from a peer are rendered as text, never as HTML or markup, in the
web UI, the apps and the CLI's terminal output, and the UI ships a content security policy that
forbids inline script. A device name and a Close's `detail` may carry Unicode format characters
(category Cf, bidirectional controls among them): the wire grammar admits them, since refusing Cf
would break emoji sequences, and the UI isolates each such string as bidirectional text when it shows
it, so that it cannot reorder the text around it. Stops peer-controlled names rendered as HTML
(Syncthing CVE-2022-46165). Enforced by `app` and `web`; reviewed in `cli` (terminal escape sequences
are stripped).

**TM-21. The local API checks Host and Origin and requires the token on every request.** The
localhost listener accepts a request only if its Host header names the listener's own address, its
Origin header, when present, is the UI's origin, and the token is present and correct, carried in a
request header and never in the URL; the socket or named pipe is created with permissions for the
owning user only. Stops DNS rebinding and cross-site requests against the local API (Dorsey 2018;
Syncthing's host check). Enforced by `daemon`.

**TM-22. Bounded per-peer tables tied to the connection.** Every table keyed by peer or request
(pending chunks, reservations, registrations, in-flight requests, have-query state, proof hints, the
reconciliation's work list, at most 1 921 prefixes per folder, each at most 65 bytes with two
nibbles packed per byte, so about 125 KB per folder and 8 MB per connection at 64 open folders,
which a peer that lies about its digests can keep filled while its pass lasts, until
`REPLY_PAGE_TIMEOUT` after its last answer, `protocol.md` §5) has a fixed maximum, counts against
the Hello's agreed limits, and is dropped with its connection; no table grows with the number of
writers or records in a folder, since an index request carries one cursor and a reconcile request
one prefix, and the tables that outlive a connection are of a fixed size: per-peer state, at most
`MAX_PEER_STATES` entries per folder (`protocol.md` §4.5), with, from phase 2, its lookup by libp2p
peer ID, one entry per state, by which hole punching tells a peer of a shared folder (TM-25); at a
public relay or a hole-punch coordinator, its per-requester counters, in tables of a fixed number of
peer IDs and source addresses, sized above its caps in all, whose entries with a live circuit or
reservation are never evicted (TM-25); and a device's own punch counters, per coordinator in a table
of a fixed size and in all (TM-25); libp2p's connection, stream and transient connection limits are
set, and tested under a flood on TCP (`net`'s TCP flood test; QUIC's is residual (a) below); QUIC's
three-to-one anti-amplification limit stays at its default; and the advisory feed in CI
(cargo-audit, daily) catches the next such advisory in a dependency. Eight residuals of the
transport as phase 0 builds it (`net` on
`libp2p-quic` 0.14, `libp2p-yamux` 0.48 and `libp2p-memory-connection-limits` 0.6), each required
before 1.0: (a) to (c), from the security review of 2026-11-03, each a phase 1 item ("I want safety
limits in version 1.0, no matter what. It is fine to pass until phase 1, but it must not get
lost.", owner, 2026-11-03), and (d), from the iOS build of the same day, a phase 4 item by the
owner's separate answer on it, below, and (e) to (g), of spike B's WebTransport listener, each a
phase 6 item, and (h), from spike B's follow-ups, a phase 1 item beside (a) to (c) (owner,
2026-11-08): (a) **QUIC Initials cost per Initial, not per limit.**
`libp2p-quic` accepts every Initial quinn hands it before the swarm's limits are asked, so each
one, from an attacker who never answers, costs a QUIC connection and a TLS
server handshake (the X25519MLKEM768 encapsulation and the certificate's signature) whatever
`max_pending_incoming` is, until it is refused and drained or times out; the review measured 10 000
Initials at about 412 MB of memory (about 41 KB each) and seconds of CPU, and connections refused
while they lasted. The cost therefore scales with the attacker's send rate; quinn's Retry (address
validation before any state) or its incoming-connection cap would bound it, and `libp2p-quic`
exposes neither. **Required before 1.0 (owner, 2026-11-03)**; phase 1 item "QUIC Initial limit":
Retry under load or a lower incoming cap, through an upstream change or QUIC configured by `net`
itself, and a QUIC Initial flood test with the bound it then states. (b) **One pending counter for
every source.** `max_pending_incoming` (32) connections that never finish their handshake, TCP
sockets that never speak or QUIC handshakes never answered, lock every inbound peer out for the
handshake timeout (10 s), and an attacker can renew them for as long as it likes. **Required before
1.0 (owner, 2026-11-03)**; phase 1 item "pending lockout": a per-address pending limit, budgets per
transport, and Retry when the pending slots are full. (c) **yamux's window on TCP.** `libp2p-yamux`
0.48 does not set yamux's connection receive window, whose ceiling stays yamux's 1 GiB; the window
auto-tunes from the round trip yamux measures with its pings and the rate this side reads, so a
remote that delays its ping answers inflates the estimate and can grow one connection's window, and
what it may send unread, toward that ceiling. **Required before 1.0 (owner, 2026-11-03)**; phase 1
item "yamux window": yamux configured by `net` with `max_connection_receive_window`, or an upstream
setter. (d) **No process-memory limit on iOS, so no node on iOS.**
`libp2p-memory-connection-limits` 0.6 requires sysinfo 0.38, which does not build for iOS on libc
0.2.190 and later (libc keeps four of the items it uses for macOS only), so on iOS `net` builds
without it, and `net`'s `node::build` refuses to build a node there
(`BuildError::NoMemoryLimitOnThisPlatform`, before it does anything else; `limits::has_memory_limit`
allows only Linux, Android, macOS and Windows): no iOS device runs the transport, so none takes a
connection without the memory limit. **Required before 1.0, fixed in phase 4, and
`net` refuses to start on iOS until then** (the owner's answer of 2026-11-03 on the iOS gap,
recorded under the same 1.0 safety-limits rule); phase 4 item "iOS memory limit": an iOS memory
check of `net`'s own, or an upstream release of `libp2p-memory-connection-limits` on a sysinfo that
builds for iOS, with the iOS refusal lifted and the memory-limit test compiled for iOS again.
Three more, of the WebTransport listener spike B adds to `net` (feature `webtransport`, off by
default, so in no build that ships; proposed, for review), each **required before 1.0, phase 6
(browser client)**: (e) **WebTransport sessions are not counted.** Each connection is held to
`net`'s QUIC limits, as QUIC's own are: at most 16 bidirectional and 16 unidirectional streams open
at once, 4 MiB unread a stream and a connection, and 64 KiB of unread datagrams (quinn's default is
about 1.25 MB) plus one more in `wtransport`'s channel for the connection (its `Driver::init`: a
`tokio` `mpsc` of capacity 1), so before authentication a connection holds at most about 4.06 MiB of
the dialer's unread data besides its TLS and QUIC state (with that one datagram a packet within the
1 472 bytes quinn advertises; under 4.125 MiB if the dialer sends it as large as quinn takes, under
64 KiB), and each step of the handshake (the session request, the session, Noise, a stream's
protocol) has a deadline, with a 20 s idle timeout. That figure bounds bytes, not memory (by reading
quinn 0.11.12, quinn-proto 0.11.19, quinn-udp 0.5.16 and `bytes` 1.12.1, not measured): quinn copies
each UDP read into one buffer, keeps each frame's data as a slice of that buffer, and frees the
buffer only when every slice is gone. A read is one UDP datagram (at most 65 527 bytes) or, on Linux
and Android, a GRO batch of up to 64 datagrams; quinn's buffer for it is 94 208 bytes (64 times
1 472) on Linux, Android and Windows and 1 472 bytes on macOS and iOS. So each datagram quinn
buffers, up to 2 048 of them (it counts 32 bytes with each, and an empty one that ends its packet
still holds a slice), and the one in `wtransport`'s channel can keep a whole read alive: up to about
184 MiB a connection (about 2.9 MiB on macOS and iOS). And quinn's check of a stream's
over-allocation takes each frame's allocation to be its packet's payload, not the read the packet
shares, and otherwise compacts a stream only above 2 048 chunks, so each stream's data may keep up
to about 184 MiB alive, about 5.75 GiB a connection across its 32 streams. (These are upper bounds,
from quinn's 94 208-byte buffer. The realistic bound is a read of 64 KiB, Linux's GRO and UDP limit,
since quinn 0.11.12 copies only the bytes a read brought (`endpoint.rs`, line 798):
about 128 MiB a connection for its datagrams (2 049 × 65 536 bytes), 128 MiB a stream (2 048 ×
65 536 bytes) and 4 GiB a connection across its 32 streams, and (h)'s 2.9 GiB becomes 2 GiB across
16 streams. GRO coalesces datagrams that arrive back to back, so the sender needs no GSO. Neither
set is measured.) But the listener takes every connection quinn hands it, with
no count of sessions per listener or per address and outside the swarm's connection and memory
limits, so the total grows with the number of dialers at their own rate, and an Initial costs what
residual (a) says. Phase 6 item "WebTransport limits": sessions counted with the swarm's limits (or
a transport the swarm's limits govern), per-address limits, the memory limit, and quinn's Retry
(`IncomingSession::retry`) under load; the memory a connection keeps alive bounded, not only its
unread bytes: datagrams, which `net` does not use, read and dropped or copied as they arrive, or
their buffer made small, and stream receive buffers that share a read counted or copied, upstream in
quinn or in `net`, with a test that measures a connection's memory against one-byte frames sent in
large UDP datagrams and in datagrams sent back to back, which the listener's GRO coalesces; and,
since a step that fails before Noise (the session request's deadline, a wrong path, a failed accept)
drops the session without closing its QUIC connection (and so do a panic in the contained handshake
task, TM-23, and an aborted handshake future), which the tasks `wtransport` spawns for the dialer's
streams then keep open while the dialer keeps it from idling, that connection closed explicitly on
every failure path, and QUIC connections counted, not sessions. (f) **No certificate rotation.** The
listener's certificate is made when it binds and is valid for at most 14 days, the longest a browser
accepts for a hash; once it expires no browser can dial until the listener binds again with a new
certificate whose hash is handed out again, and an invite carrying the old hash (`keys.md`'s `c`)
goes stale. Phase 6 item "WebTransport certificate rotation": a new certificate before expiry, Noise
reporting the current and the next hash, the certificate swapped in without dropping sessions, and
`not_before` back-dated for clock skew. (g) **The handshake facts are per process, and spike A's
transports keep none.** The outer key-exchange group a WebTransport handshake chose is recorded
process-wide, the last handshake's, so with handshakes at the same time it can name another
session's; QUIC and TCP record no such facts. Phase 6 item "handshake facts": per-connection facts
shared by the three transports, as TM-33's evidence. (h) **QUIC's windows bound bytes, not memory.**
QUIC's windows are set (`net`'s limits, 4 MiB a connection, for the swarm's QUIC and for the
WebTransport listener alike), and they bound bytes, not memory: by reading quinn 0.11.12 and
quinn-proto 0.11.19 (not measured), residual (e)'s stream effect applies to the swarm's QUIC too
(`libp2p-quic` 0.14: datagrams off, 16 bidirectional streams), whose stream data, sent as small
datagrams back to back, which the device's GRO coalesces into one read whether or not the sender
used GSO, may keep about 2 GiB alive a connection at the realistic 64 KiB a read, (e), and at most
about 2.9 GiB by quinn's buffer, against the 1 GiB process limit, which only refuses new
connections. It concerns the native program, whose QUIC connections, those it accepts and those it
dials, run on quinn, not the browser client, whose QUIC is the browser's own. **Required before 1.0
(owner, 2026-11-08)**; phase 1 item "QUIC stream memory", beside residuals (a) to (c): confirm it
with a raw quinn peer that sends such datagrams, with GSO and without, then bound it. Stops resource
exhaustion through unbounded streams, connections and registrations, and amplification through QUIC
(go-libp2p and rust-libp2p 2022; rendezvous 2026). The
stated costs: any Hello that passes its checks costs one Ed25519 signature (the DeviceProof sent in
answer) and one verification; a FolderProof from a peer with no key to the folder costs a lookup in
the connection's hint table and nothing else, so an outsider cannot make a device verify anything;
once a folder is open, each record received costs one BLAKE3 hash of its body, and an exact
duplicate stops there, and an expired or obsolete record after a look at what is held at its tag
(for a tree delete, at most two index queries per entry of its vector, at most 32 entries, each `O(L
log n)` for paths of at most `L` bytes, `L` ≤ 4 096, since its steps compare paths that can share a
long prefix, and a lookup per ancestor directory, whatever lies beneath it; for any record, the
ancestor lookups cost `O(L)` work for a path of `L` bytes, its ancestor tags computed in one pass
with one keyed hasher finalized before each `/` is fed in, or the held tree deletes kept in a trie
by path; the coordinator's ruling of 2026-10-26, for the owner's review), unverified (ruling DUP),
so every signature a device verifies either stores a record it did not hold, drops one it held,
notes a stale copy or forgotten record that a write holder will name in a
cleanup, or closes the connection (or, when the device's own index store cannot take the record,
pauses the folder until it can, `protocol.md` section 5; the check of its own store when a folder
opens, one verification per stored record, TM-9, is no peer's to trigger directly, and resuming
after a store failure reopens the index only for a store that cannot stage atomically, `protocol.md`
§4.7 item 1, so that for such a store a peer that fills the disk until a store failure, with records
a write holder signed or, at a sealed peer, with replayed genuine records and their chunks, triggers
that check indirectly, once per failure, the coordinator's ruling of 2026-10-26, for the owner's
review), and a peer of any tier can make it verify only as many signatures as it brings new records,
plus stale copies to note, none of them noted already and at
most `MAX_NOTE_VERIFICATIONS` (4 096) per connection per 10 s, one budget shared by every folder
open on it (the coordinator's ruling of 2026-10-26, for the owner's review), which at about 60 µs a
verification is at most about 2.4 % of one core per connection opened, however many folders are open
on it, on average (the window is fixed, so a burst across its boundary can spend two windows'
budget; the coordinator's ruling of 2026-10-26, for the owner's review; and a peer that reconnects
starts a new budget, so the total is bounded by the rate of connections, a phase 1 connection
limit), plus the one forged record that ends the connection; serving an index or reconcile request
reads cached set digests and recomputes none; a cleanup is a signed record like any other, at most
`MAX_CLEANUP_ENTRIES` names each, applied only to records the receiver holds; a write holder names a
stale copy or forgotten record that a peer offers only once its signature has verified (a forged one
closes the connection), never one that a record it holds names or that a cleanup it holds names in
any group, whether or not that group still applies, and at most `MAX_PEER_NAMES` for one peer
identity a window of `PEER_NAMES_WINDOW` (30 days), so that a holder of any key that kept genuine
old records makes write holders sign each into a cleanup at most once per life of the cleanup that
names it, until a watermark expires that cleanup, at least a year (sooner while a write holder's
clock is wrong or faked, TM-40), however often its file is written
meanwhile (without that rule each edit, which replaces the `because` of the groups that named a
file's old versions, would reopen the file's whole history for naming: about 1.4 MB of cleanups an
edit for a file edited hourly with 40 000 old versions); the cost of the rule is that old versions
replayed after an edit stay at a sealed peer, fetched and stored, until the cleanup is forgotten; a
folder's notes are shared by every connection and dropped oldest first, so a hostile peer with
several connections and genuine old records can push an honest peer's notes out before they are
named, which costs an honest sealed peer a slower cleanup and never a loss (per-peer shares are a
phase 1 follow-up; the coordinator's ruling of 2026-10-26, for the owner's review); the cleanups
that case (c) of `protocol.md` §4.4 issues for forgotten records cost each write holder at most one
cleanup per round per connection, naming what it has forgotten since that the peer still holds,
where a change of the greatest watermark owes a round toward a sealed peer at most once per
`WATERMARK_INTERVAL` (a day) on each connection, each itself forgotten once a later watermark passes
it, a year or more later (sooner while a write holder's clock is wrong or faked, TM-40), and named
in turn: 64 write holders, each with a connection to a sealed peer, in a folder whose watermarks
rise daily, add at most 64 a day through those rounds, about 23 000 a year, about 9 MB held and 1.4
s more at each open, as much again as the watermarks, and at most one more per round that comes for
another reason (the coordinator's rulings of 2026-11-12, for the owner's review); a write holder
checks for a watermark when a folder opens, when the device resumes from sleep, and at least once an
hour (`WATERMARK_CHECK_INTERVAL`) of monotonic time while it stays open, and signs at most once a
day (`WATERMARK_INTERVAL`), counted within one opening by a monotonic clock that counts time asleep
and across openings by its wall clock, and only when its candidate passes the greatest watermark
held and at least one tombstone, tree delete or cleanup with a group whose `because` is not empty,
never for case-(c) or watermark-only cleanups alone (the coordinator's rulings of 2026-11-12, for
the owner's review), so that another's watermark spares it only when it arrives before its check: up
to one watermark a day per write holder, each a cleanup of about 400 bytes that every read and write
holder keeps a year or more and verifies at every open, so that 64 write holders in a folder where
deletions arrive daily can sign about 23 000 a year, about 9 MB held and about 1.4 s of one core
more at each open, a wall clock that steps between opens adds at most one per open, and once
deletions stop no write holder signs again only to forget the watermark-only and case-(c) cleanups
of the last year, which stay held at every tier, at most one watermark-only cleanup per write holder
per day and one more per open where a wall clock steps, until a watermark that a deletion, or a
cleanup whose group has a `because`, brings, so that no case-(c) cleanup follows them; each rise of
the greatest watermark costs `O(log n)` per tombstone, tree delete or cleanup it drops, through an
index of them by counter, one entry each, and a write holder's check `O(log n)` and `O(log n)` per
record it passes, which its watermark then expires, or, when it signs nothing because it passed only
cleanups without a `because`, which it passes again at its next check (`protocol.md` §4.4, "Finding
what expires", "How many"); a commit that raises it and expires a record, or lowers it, owes one
round on each connection where the folder is open, at once toward a peer that reports the read or
write tier and at most once a day toward one that reports the sealed tier, through one more bit and
one monotonic time per folder per connection; a reconcile pass sends at most
`MAX_PASS_REQUESTS` requests, whatever the responder answers; chunk requests are bounded by
`max_requests_in_flight`, a queued request holds only its hash and the chunk is read from storage
only as it is sent, a requester keeps one `CHUNK_BUSY` backoff timer per connection and no state per
hash after `CHUNK_NOT_FOUND`; a hash outstanding on one connection goes to another only once every
connection holding it was asked at least the chunk patience ago (two `STATUS_INTERVAL`s, 60 s) or a
chunk for it arrived, one ask time kept per connection and dropped by its refusal or disconnect, and
then round the connections that could ask for it now (room in flight, no backoff, a pass not waiting
for a trigger) in the order the device made them, from the one after the connection asked last, one
made since the round began or passed by it waiting for the next round, two numbers per hash; so key
holders of any tier, under any number of device identities, that take requests and never answer, or
refuse, reconnect or report more chunks stored to be asked again, even by turns, have at most one
turn each a round, of at most about the patience: N connections ahead of an honest holder delay a
hash it holds about N times the patience, bounded by the connection limits, while the honest holder
can be asked; a connection that can no longer ask when its turn comes (its room filled, backing off,
or its pass past the hash or waiting) is passed over, the passes running again in the same handler
until none drops out, and a hash freed in a handler where no connection can ask for it starts its
round again with the first that does. Residual: an honest holder whose pass waits for a trigger,
after a `CHUNK_NOT_FOUND` for another hash it lacks, cannot be asked, so one peer that takes the
request and never answers keeps the hash from it until the folder brings a trigger (a Status with
more chunks stored, or a completed round, `protocol.md` §4.6), which a quiet folder may never do; a
third pass trigger, which fires when a hash the pass skipped comes free, is to close it, a phase 1
item. A key holder of any tier, under any number of device identities, can still make a device queue
up to `MAX_SEND_QUEUE` (128 MiB) of chunk replies per connection by reading them slowly, for as
long as it keeps the connection alive (a reader that trickles is never closed by `IDLE_TIMEOUT`), so
what bounds the total is the phase 1 connection limit; and a write
holder can make every peer store as many concurrent versions, tombstones and tree deletes as it
signs (section 3.6), and keep every deletion held past its year, without bound, by holding
forgetting back (section 3.6; a peer that is a write holder's only link, or a network attacker that
cuts it off, can do the same where no other write holder signs, sections 3.3 and 3.1), and with
them state that outlives connections, one entry per record held: an index of held records by device
and path, through which holding a tree delete costs `O(L log n)` per
record it drops, and a digest cache whose leaves hold at most 64 records, so that a change rehashes
at most one leaf and 128 nodes however many records one file ID holds (the coordinator's ruling of
2026-10-26, for the owner's review; `protocol.md` §4.4, "Judging a tree delete without a walk",
§4.5, "Set digests"); and any holder of the sealed or read key that kept a folder's history can make
a sealed peer store every old version it replays, with its chunks, until a write holder's cleanup
names them, and make write holders name them in cleanups that every peer receives, which has one
bound and it is not a constant: **the folder's history**, content included, once per life of the
cleanup that names each record, at least a year (sooner while a write holder's clock is wrong or
faked, TM-40: a clock faked forward again each day, a year further each time, shortens every
cleanup's life to a day, and with it this bound, so that the history can be replayed and named
again every day or two), since every replayed record is a genuine signed
version and one that a held cleanup names is refused while that cleanup and the record it was issued
for are held (the coordinator's ruling of 2026-10-25, for the owner's review: no per-file bound,
which could make a sealed peer drop a live version only it holds; the sealed peer shows the count in
its Status, `protocol.md` §4.4, "Stale copies at a sealed peer, and their bound"); this costs
storage, time and bandwidth, not per-connection memory, and lengthens every later open of the folder
on every peer by one signature verification per record held, the same cost class. Enforced by `net`,
`protocol`, `index` and `engine`; the flood test is in `sim`.

**TM-23. No `unwrap`, `expect`, `panic` or unchecked index on untrusted input.**
`clippy::unwrap_used`, `expect_used` and `panic` are denied workspace-wide, `indexing_slicing` warns
and is fixed, and `.semgrep/project.yml` forbids `expect` on decoded data in `protocol` and `net`.
Stops a remote panic (rust-libp2p 2026 QUIC handshake). Enforced by `core/Cargo.toml` lints and
Semgrep. In a dependency, the rule is met by containment where the dependency panics: `wtransport`
0.7.2's `Endpoint::accept` (beneath `net`'s WebTransport listener, feature `webtransport`, spike B;
proposed, for review) holds an `expect` that panics once quinn's endpoint is closed or its driver
has ended on a socket error, which is not provably unreachable from the network on every platform,
so `net` runs it in a task of its own and returns an error instead (`Listener::accept`, tested);
and `wtransport`'s per-connection worker, when it panics, makes whoever awaits that connection next
panic too (`Driver::result`, its `src/driver/mod.rs` lines 230-234), so `net` runs each step that
awaits a connection (the handshake, from the session request through Noise, and each stream's
protocol) in a task of its own, which returns `WebTransportError::Panicked` instead (tested with
residual (a)'s input).
One residual, **required before 1.0, phase 6 (browser client)**: (a) **`wtransport-proto` 0.7.2's
QPACK integer decoder overflows a shift on peer bytes.** A two-minute fuzz run of its parsers
(2026-11-04) found that `Decoder::decode_integer` (`src/qpack.rs`, line 173) shifts by a count that
grows 7 bits a continuation byte without bound, which panics where overflow checks are on (debug
and test builds, fuzzing). In a release build (overflow checks off) the shift wraps; on the
recorded input decoding then fails; in general it yields a wrong value, harmless because every
decoded value is checked before use (discarded, looked up in the static table, or checked as a
length against the bytes left). The input is the CONNECT request's HEADERS frame, from any client
before authentication, decoded inside the worker task `wtransport` spawns per connection; the
worker's panic then panics `net`'s handshake, which awaits that connection, and is contained there
(above): the handshake returns `WebTransportError::Panicked`, the process and the listener go on,
and `a_panicking_session_request_is_contained` sends the 18-byte input (`fuzz/known-crashes/`) to
show it. Phase 6 item "QPACK integer overflow": a fix upstream (or in a vendored copy) that stops
with `IntegerOverflow` once the shift reaches the integer's width, and the fuzz target for
`wtransport-proto`'s parsers (kept in `fuzz/known-crashes/`, outside the nightly list, since until
then it would fail the nightly fuzz job at once) moved into `fuzz_targets/`.

**TM-24. The DHT uses a daily-rotating discovery hash and runs in client mode by default.** The
announcement hash is derived from the folder ID and the current day; the node is a client unless the
person turns on server mode, which adds a per-source rate limit and bounded responses; the BEP 44
sequence number is persisted and never reused, and the BEP 44 signing key, like the node ID, is a
stable identifier the device publishes (section 5); the DHT is off until its person turns it on, for
the device or for a folder: in the guided setup, whose recommended set turns it on in client mode
and never in server mode (the owner's decisions of 2026-11-13, TM-25), or in the settings; server
mode is a setting of the device. Stops
Sybil and eclipse attacks learning more than one day's peers, announcement enumeration by crawlers,
and `get_peers` amplification (Wang and Kangasharju; BEP 42; Adamsky 2015). Enforced by `net`.

**TM-25. Relays and hole-punch coordinators serve only where their persons turned them on; relays
are used only where turned on, and punches only as each folder's settings allow; a relay is public,
carries ciphertext only and enforces its person's limits with bounded state; a coordinator carries
only a punch's set-up; and a device takes a punch only from a requester it knows or that proves a
key.** No device relays or coordinates hole punches for others, no device uses a relay, and no
device asks for a punch or is reached through one, unless its person turned that on (the owner's
answers of 2026-11-02, "Only relay when configured to do so", and of 2026-11-03, "drop the
private/protected relay idea and only work with public relays"; for hole punches, the owner's
decisions of 2026-11-08 and 2026-11-13, below). Every one of these settings starts unconfirmed,
which acts as off, and the guided setup asks once (below); the owner's default of 2026-11-08, by
which asking for punches through peers of a shared folder, and being reached through them, was on
unless turned off ("Those defaults are fine, go ahead"), is replaced by their decisions of
2026-11-13. Serving as a relay is a setting of each device, off until turned on, which the guided
setup never does, and offered on computers only, never on a phone (the plan's "Role in a folder": a
phone is a leaf, never a relay); using relays is each folder's public-relays switch, off until
turned on. Every relay serves whoever reaches it and is a stranger to the peers it carries: there
are no own-device, private or protected relays, since a device cannot tell its person's machines
from a friend's when both share the same folders.

**Connectivity settings** (the owner's decision of 2026-11-10: "Both must allow. Folders should be
able to be individually configured for hole punch, plus there should be global configuration for
allowing direct connect, DHT, etc. global settings set defaults. Folders can override."). Every
connectivity switch has a device-wide default that each folder may override: LAN discovery, direct
connections, the DHT, public relays, Tor, and the hole-punch level (below); the plan's "Connectivity
per folder" lists all six, with their device-wide defaults under Settings → Connectivity, and a
new folder starts from the device-wide settings (the owner's decision of 2026-11-11); each switch,
a folder's included, has the four states below, and a folder's at default follows the device's.
Offering to relay and offering to coordinate stay device-wide, and so do port mapping (TM-26) and
the DHT's server mode (TM-24), which concern the device's one port and its one DHT node. A
connection serves a folder only as that folder's own settings, or the defaults it keeps, allow, and
on a connection they do not allow the folder is treated as paused (`protocol.md` §3.1, §3.5).

**Every setting starts unconfirmed, and the guided setup asks once** (the owner's decisions of
2026-11-13). On finding devices on the local network the owner answered "Ask during setup", and
then: "Ask, suggest using recommended options. By default, let's turn on the usage of local network
discovery, opening a port on the router, using public trackers, hole punching, using public relays,
etc. because the user probably wants to have this 'just work.' The defaults would not enable this
node as a public relay - instead it would only enable features that would benefit the local
folders. However, some security-minded people will certainly want to disable these options. If the
user says no, they can be presented with the configuration screen to select what features they want
to enable."; on port mapping, "Yes, this feature should default to on (see the previous question)
and advanced users can turn it off before the folder even starts to sync."; on who helps with hole
punches, "Both (Recommended)"; on "public trackers", "Yes, the DHT (Recommended)"; on setup's "no",
"Start by showing the recommended settings enabled (as defaulted options). Again, at least three
states: on (override default), off (override default), and default (the recommended settings). Make
sure it's clear if the default setting is on or off."; and on settings that a later release adds,
"Ask once about each when there is a GUI and have it disabled until after the user decides. Then we
can turn it on (via default settings), but only if the person selected to use the recommended
settings. The settings should not be on/off, but on/off/default or on/off/default/unconfirmed where
default is the recommended settings and the unconfirmed state is where we didn't get confirmation.
Modifying them turns them into on/off and a button would reset all settings to recommended
defaults. When upgrading, we should be forthcoming with settings like this. CLI tools should start
with unconfirmed as well, offering a suggestion to run the command with specific flags to set the
option appropriately." So:

- **Four states.** Every connectivity setting, the device's and each folder's alike, is in one of
  four states: **on** or **off**, which override the default; **default**, which follows that
  setting's default, the app always showing whether that default is on or off; and **unconfirmed**,
  not yet confirmed, which acts as off. There are two defaults: a device setting's **recommended
  default**, which is on for the recommended set below and off for every other setting, and a
  folder switch's **device default**, the device's setting for it. Changing a setting makes it on or
  off, and a button resets every setting to default; the settings screen shows each default's value
  next to that button, and on the command line a reset and `settings confirm` each print every
  setting they set and the value it takes, so the person sees what a reset or a confirm turns on, a
  later or raised default among it. A new folder's switches start at
  default, following the device's, unless the person changes them as they make or join the folder;
  confirming the make or join confirms them, so a folder's switch is never unconfirmed itself,
  though at default it follows a device setting that may be. The hole-punch level, which has four
  levels rather than on and off, is likewise at a level the person chose, at default (the fourth
  level, or the device's), or unconfirmed (acting as never); and so is coordinating (below).
- **Before the answer.** Until the person answers the guided setup, every connectivity setting of
  the device is unconfirmed, and so acts as off: the six device-wide defaults above, the hole-punch
  level among them, which acts as never; port mapping (TM-26); the DHT's server mode; serving as a
  relay; coordinating; and the browser listeners, WebTransport and the secure WebSocket (HTTPS)
  listener with its certificate, the person's own or Let's Encrypt's (`suites.md`,
  transport). The device then contacts no host (TM-31): it sends no beacon, asks the DHT nothing,
  maps no port, reserves with no relay and dials no peer; and it opens no listening socket but the
  local API's (TM-21) and joins no multicast group. The same holds while the settings are
  unconfirmed after "No", and, once they are confirmed, until a setting that needs one of them is on
  and a folder that uses it starts to sync (below).
- **The answer is a setting of the device, and is never assumed.** The guided setup asks once,
  before the device's first folder is made or joined; closing it, or closing the graphical settings
  screen without confirming it, is no answer, and the setup asks again; no folder is made or joined
  until the setup has an answer. On the command line (phase 1, whose command names these examples
  only suggest), every setting starts unconfirmed too, and the setup is answered once no shown
  setting is unconfirmed: after a "yes" (`licketysync setup --recommended`, say), which sets every
  shown setting to default; after `licketysync settings confirm`, which confirms the shown defaults;
  after a reset, which sets every setting to default; or once every setting has been set. A "no"
  prints every setting with its default's value and the command that sets it on, off or default,
  and sets nothing, so alone it is no answer, like a closed screen. Until the setup is answered, a
  command that would make or join a folder makes or joins nothing: at a terminal it asks again, and
  without one, as on a headless device, it names the command that answers. The command line reports
  every setting still unconfirmed, with the command that sets it.
- **What it suggests.** It explains each setting, what it gives and what it shows (section 5), and
  suggests the **recommended set**: LAN discovery; port mapping (TM-26); the DHT in client mode
  ("public trackers", which the owner confirmed means the DHT, the spec's one internet-wide
  discovery, TM-24); direct connections, hole punching among them; using public relays; on
  computers, coordinating punches for the devices of this device's own folders only (below); and
  each folder's hole-punch level at the fourth, through any device it knows and any public relay
  its person turned on. Tor, serving as a relay, the DHT's server mode, coordinating for anyone and
  the browser listeners stay off.
- **"Yes" and "No".** "Yes" sets every setting the setup showed to default, so each follows its
  recommended default, and every new folder starts from them. "No" opens the settings screen with
  every setting at default, each showing whether its default is on or off; nothing is active until
  the person confirms the screen, every setting staying unconfirmed until then (the coordinator's
  reading of the owner's words, for the owner's review). Either way, one rule holds, however a
  setting was turned on: a service that contacts a host or listens (LAN discovery, port mapping, the
  DHT, relays and coordinating, and the listeners they need) starts only when the first folder that
  uses it starts to sync, and stops when the last such folder is paused or unlinked; and no folder
  starts to sync until the setup has closed and the person has confirmed making or joining it.
  Before a folder starts to sync, the person can turn any of them off: the six switches above for
  the device or for one folder, and port mapping, coordinating, relaying, the DHT's server mode and
  the browser listeners for the device, the only place they are set.
- **Settings a later release adds.** The setup shows only the settings its release has, and its
  answer covers only those. A setting that a later release adds starts unconfirmed, acting as off,
  on a device that has already answered. With a graphical app, the app asks once about it, explains
  it and suggests its recommended value; if the person picks that, the setting is at default,
  otherwise on or off as they chose (the coordinator's reading, for the owner's review). The command
  line reports it as unconfirmed and suggests the flags that set it. A later release that changes a
  recommended default so that it allows more (off to on, a more open hole-punch level, a wider
  coordinating value) makes that setting unconfirmed, acting as off, on every device that keeps it
  at default, and the app asks once about it, as for a new setting; a change that allows less
  applies at once, and the release says so.
- **What it never does, and what it shows.** The recommended set never makes the device a relay, a
  DHT server, or a coordinator for anyone but the devices of its own folders, and on a phone it
  turns no coordinating on. What it shows is section 5's ("What the recommended set shows"): at the
  fourth level, every coordinator a punch uses, a stranger's public relay among them, learns that
  two devices are connecting, when, and their addresses; the up to three coordinators a device
  keeps standing reservations with, strangers' public relays among them, learn its peer ID, its
  public address as it changes, and when it is online; and coordinating for the devices of its own
  folders keeps one residual: it serves no stranger only while its folders' keys stay secret.

A relay:

- accepts a reservation only on a direct connection, never on a relayed one, so relays do not chain;
- never receives Hello as a relay: devices run `/licketysync/sync/1` end to end through it, never
  to it over the circuit or with it as their relay (`protocol.md` §3.1; a relay that is also a peer
  of a shared folder runs the protocol with them as any peer does, over a connection of its own),
  and relay control, the plan's Reserve, Granted, Busy, Pause, Resume and Load
  messages, is the relay protocol's own and versioned with it (the plan's "Volunteer relay
  scheduling"): a libp2p protocol of its own beside circuit relay v2, which phase 7 designs, and no
  part of the sync protocol;
- is told no folder: a reservation and a circuit name the two peers only, so it learns their libp2p
  peer IDs and addresses, the timing and volume and the sizes of the encrypted frames, and never a
  folder ID (section 5; the owner's decision of 2026-11-04, "All three (Recommended)", since a
  folder ID would let a stranger compute the folder's DHT announcements and confirm its LAN beacons,
  `keys.md` §2.1);
- never terminates the end-to-end channel: the peers' encrypted channel (TLS 1.3 with X25519MLKEM768
  between native ends, Noise only where a browser client is one end, TM-1, `suites.md`
  §2.6) and the protocol's handshake (`protocol.md` §3) run inside the circuit, so the relay carries
  ciphertext only, and can drop, delay or cut a circuit, at a moment it chooses (§3.3), and nothing
  else;
- enforces, as requirements, the limits its person sets (the owner's list of 2026-11-03): (1) a
  **rate schedule**, a byte rate each way for each period of the week by time of day and day of
  week, which all its circuits together never pass, the periods read in the relay's own local time
  (the spec author's choice, for the owner's review); (2) a **cap on open connections**, past which
  it answers a new request busy, with a time to retry and its place in a queue, as the plan's
  "Volunteer relay scheduling" has it, the queue of a fixed length past which a request is answered
  busy with a time to retry only (that the cap counts the circuits it holds at once, reservations
  having a cap of their own, below, and the queue's bound, are the spec author's choices, for the
  owner's review; the first replaces an earlier choice that counted reservations too, by which, the
  security review of 2026-11-10 found, idle reservations could hold every place); (3) a
  **minimum transfer rate**: a circuit whose rate, averaged over a fixed window, stays below it is
  closed when another requester is waiting for room, and in any case once it has stayed below it for
  a longer idle time, so that idle circuits make room for others (the owner's decision of
  2026-11-04, "All three"; the lengths of the window and of the idle time are set with the relay
  messages); (4) **per requester**, a cap on its reservations, circuits and bytes per period,
  counted both by the libp2p peer ID the transport authenticated and by its source address, since
  peer IDs cost nothing to make (the owner's decision of 2026-11-04, "All three"; a source address
  counted as an IPv4 address or an IPv6 /64, the spec author's choice, for the owner's review); and
  (5) a fair share among active circuits, by deficit round-robin on bytes, a circuit that has used
  its turn yielding when others wait (the plan's "Volunteer relay scheduling": by default after 64
  MB or two minutes, then Pause, the front of the queue and Resume);
- caps **reservations** apart from circuits: besides (4)'s cap for each requester, by default 2 by
  peer ID and 8 by source address, at most 256 in all; when that is reached and others wait, it
  drops the reservation that has gone longest without a circuit; and reservations expire unless
  renewed (the numbers and the drop are the spec author's choices, for the owner's review, after the
  security review of 2026-11-10);
- keeps **bounded state per requester**: a fixed set of counters for each (its reservations,
  circuits, bytes in the current period and window, and its place in the queue), in tables of a
  fixed number of peer IDs and of source addresses (by default 4 096 each) that outlive its
  connections, sized above the caps in all, so that an entry with a live circuit or reservation,
  which is never evicted, always leaves room: of the other entries the least recently active is
  evicted to admit another (the spec author's choice, for the owner's review); and everything a
  circuit holds is freed when it closes (TM-22). The stated residual, of eviction and of denial of
  service: a requester with many source addresses, which IPv6 makes cheap, can push its own idle
  entries out and start again with fresh per-requester caps, and can hold every reservation and
  circuit place, active enough not to be the first dropped, so that others wait or are refused; the
  rate schedule, the caps in all and the minimum rate still bound what the relay carries, so what it
  costs is the relay's service to others, not the limits its person set, and its person can turn
  relaying off;
- announces itself only through methods its person turned on (the DHT under the relay hash, a list
  the person adds), and a client learns of relays only from those and from peer exchange, so no
  relay is contacted that the person did not turn on (TM-31).
  The load a relay announces (the plan's Load) is its own claim, which a client cannot check, so one
  that announces a low load draws circuits and sees more traffic; how a client weighs the claim is a
  phase 7 item (the security review of 2026-11-10).

**Hole-punch coordinators** (the owner's decision of 2026-11-08, which replaces their decision of
2026-11-04, "Folder peers time punches", and its requirement that the device timing a punch prove a
key to the folder; in part, verbatim: "Hole punching can now use any known client. Prefer ones that
we've connected to, but you can fall back to public relays. We no longer need to prove that we have
a key to the same folder.", and "The load there should be minimal (much less than a relay) and it
doesn't leak more than what others are willing to give up, so go for it."; and their decisions of
2026-11-13 on the guided setup, above). Hole punching, by which
two devices behind ordinary home routers reach each other directly, needs a third device that both
can reach, the **coordinator**, to carry their first messages over a short relayed connection, by
which each learns the other's public address and the two time a simultaneous open (libp2p's DCUtR
over circuit relay v2). From phase 2 (the owner's answer to Q4 of 2026-11-04):

- **Who coordinates.** A device coordinates punches only if its person turned coordinating on: a
  setting of each device, offered on computers only, desktops, laptops and NAS boxes, never on a
  phone, which can be helped but never helps (the owner's decision of 2026-11-10, "Computers only
  (Recommended)"), with three values: **off**; **for the devices of its own folders**, which the
  guided setup's recommended set turns on (the owner's decision of 2026-11-13, "Both
  (Recommended)"; below); and **for anyone**, "allow acting as a hole-punch coordinator", off unless
  turned on (the owner's decision of 2026-11-08, "Those defaults are fine, go ahead"), which the
  recommended set never turns on. In the four states above it is at a value the person chose (off,
  for the devices of its own folders, or for anyone); at default, which is for the devices of its
  own folders on a computer, and is not offered on a phone; or unconfirmed, acting as off, as it
  starts. A public relay also coordinates, for anyone, with no setting
  of its own (below). A coordinator announces itself by registering the punch's relay protocol with
  libp2p, whose identify lists it to every device it connects to, and a device uses as a coordinator
  only a device that lists it (the spec author's choice, for the owner's review); one for the
  devices of its own folders offers and lists it only on some connections (below).
- **For the devices of its own folders** (the owner's decisions of 2026-11-13, "Both (Recommended)",
  and on its scope, "Narrow (Recommended)"; how it admits is the spec author's choice, for the
  owner's review). In this mode a device offers the punch's relay protocol, in identify and in
  multistream-select, only on a direct connection where one of its folders is open (`protocol.md`
  §3.5), which a folder never is on a connection its own settings do not allow (above), and accepts
  a reservation, and a request for a punch (circuit relay v2's CONNECT), only there, from a device
  that has so proven a key to a folder this device holds. It joins two devices only when both have
  the same one of its folders open with it, on the connection that holds the reservation and on the
  one that carries the request: unless one of its folders is open on both, a request for a punch is
  answered as one for a device that holds no reservation with it (NO_RESERVATION). That check comes
  before any cap; a request it refuses then counts only toward the requester's own caps, never
  toward the reserved device's or the caps in all, so that the answer is NO_RESERVATION however
  often it comes, never busy, and the reserved device's punches are unaffected. A request on any
  other connection, if one comes, is answered first, without regard to any table or cap, a
  reservation refused (RESERVATION_REFUSED) and a request for a punch NO_RESERVATION, however often
  it comes; only then is it counted, at most toward its requester's cap by peer ID, never toward a
  source address's nor toward any other cap that the peers of its folders share (TM-22 bounds the
  streams that carry such requests), so that the answer tells the requester nothing of who reserves
  there and uses up nothing a peer of its folders needs. It drops a reservation once no such folder
  is open on the connection that holds it. A device that wants a reservation there asks on a
  connection once two things have happened, in either order: its folders' proofs there are answered
  (`protocol.md` §3.5), and identify lists the punch's relay protocol there; when a folder opens
  there later and the listing follows, it asks again, once, if it holds no reservation there; a
  requester refused tries the next coordinator it read. A device cannot tell a coordinator's mode,
  which identify does not carry, so it lists any coordinator that is a peer of one of its folders,
  whatever its mode, only in the peer exchange of the folders open between the two, and never in an
  invite (below). Phase 2 checks that circuit relay v2's server, as rust-libp2p builds it, can be
  offered and refused per connection. Everything else is as for any coordinator below: punch-only
  circuits of at most 64 KiB and 60 s, direct connections only, the same rate limits, caps and
  tables; each side of a punch it joins still filters the addresses it receives, and the device to
  be reached still admits the requester itself ("Known peers or key holders", below). So the two
  devices of every punch it joins are peers of one folder it holds, and a device that is not, a
  stranger among them, gets neither a reservation nor a punch; a removed person (TM-42) who still
  holds the old folder's key can still open that folder with it until this device unlinks it
  (`keys.md` §7.4), and is served until then.
  - **What it learns, and what remains** (the owner's words of 2026-11-08: "B can safely coordinate
    if it is the same folder because B isn't going to get any information it doesn't already
    have", and "If we must leak a share, then we don't do it."). It joins only peers of a folder it
    holds, whose addresses and peer IDs it has already from that folder, and learns of them only
    that they connect to each other, and when; its listing reaches only peers of that folder, who
    learn from it nothing that the folder's peer exchange does not show them; and a peer of its
    folders that asks for a punch to a device learns whether the device reserves there only when the
    device is a peer of the same folder, whose peer exchange shows its coordinators anyway. One
    residual remains: "never strangers" holds only while its folders' keys stay secret, since
    anyone who holds a key to one of its folders, a widely shared read or sealed key among them, is
    a peer of that folder. Section 5 and `protocol.md` §9 state the same.
- **Each folder's hole-punch level.** A folder's level, its own or the device-wide default, says
  which coordinators a punch for it may use, at one of four levels, the owner's: **never**, as which
  an unconfirmed level acts (above); **through peers of a shared folder**, the default of the
  owner's decision of 2026-11-08, which their decisions of 2026-11-13 replace; **through devices it
  is connected to directly**; or **through any device it knows and any public relay its person
  turned on**, the recommended default, which a device's level at default follows (the owner's
  decision of 2026-11-13, "Both (Recommended)"). The names of the levels are the spec author's, for
  the owner's review, and so are these meanings, which the reviews of 2026-11-10 asked for:
  - the levels are cumulative: each allows the coordinators of the levels before it;
  - a **peer of a shared folder** is a device that has opened a folder with this device, any folder
    this device still holds, as that folder's per-peer state shows by the libp2p peer ID the
    device's DeviceProof bound (`protocol.md` §4.5): a lookup by peer ID over the per-peer states,
    one entry per state, so at most `MAX_PEER_STATES` entries per folder, each going with its state
    (90 days without a round, eviction, or the folder unlinked; TM-22);
  - a device this device is **connected to directly** is one with which it has a direct, not
    relayed, connection open now that this device dialed, or on which a folder is open; a device
    that dialed in and opened nothing does not count, and at this level a device does not dial a
    coordinator only to punch through it;
  - a device this device **knows** is one whose peer ID and addresses it learned from a source its
    settings allow: the peer exchange of a peer of a shared folder (a device's coordinators among
    it), an invite, or a list its person added; a public relay counts once its person turned it on,
    through the methods of TM-31;
  - a public relay is a coordinator only for a folder at the fourth level whose public-relays switch
    is on, and its reservation counts among the device's coordinators (the owner's decision of
    2026-11-13, "Yes, relays help too (Recommended)": no second switch).
- **Both must allow** (the owner's decision of 2026-11-10). A punch serves a folder only when that
  folder's direct-connections switch is on and its level allows the coordinator that timed the
  punch, on each side: each side applies its own folders' settings when a folder opens on the
  connection the punch brought, and treats a folder whose settings do not allow it as paused there
  (`protocol.md` §3.1). A device asks for a punch, and keeps a reservation, only through a
  coordinator that some folder's settings allow. At admission (below) only the folders whose own
  settings allow a punch through the coordinator in the middle count, for the lookup of a known peer
  as for a key proof: every other folder is treated as paused in the admission handshake, and the
  public-relays switches play no part on a punch-only circuit (the coordinator's ruling of
  2026-11-10 on the confirm review). A coordinator for the devices of its own folders adds its own
  condition (above): it joins only two devices that have the same one of its folders open with it.
- **The device to be reached chooses its coordinators in advance; nothing is picked at random.** A
  device whose settings allow punches and that cannot be reached directly keeps a reservation, a
  small standing connection, with up to three coordinators its settings allow and that accept it:
  devices it is connected to that announce themselves as coordinators first, then public relays its
  person turned on. It lists them as an address through each ("reach me through X"), and the list,
  which names its own libp2p peer ID, goes only to known peers, each coordinator only for a folder
  whose own settings allow a punch through it: by peer exchange, over connections on which such a
  folder is open, and in the addresses of an invite to such a folder, where the sender adds them
  (`keys.md` §6.3; the coordinator's ruling of 2026-11-10 on the confirm review); but a coordinator
  that is a peer of one of the device's folders, whatever its mode, only in the peer exchange of the
  folders open between the two, and never in an invite (above). Its address record in the DHT
  carries neither its peer ID nor the list (the owner's decision of 2026-11-10, "Peers
  now, alias later"; `keys.md` §2.2), so a device found only through the DHT, and reachable only
  through punches, is not reached that way. **Phase 2 item** (the same decision): a rotating alias
  that coordinators accept in place of the device's peer ID, so that the DHT can carry the list
  without the peer ID. A device that wants to reach it reads at most three coordinators of its list,
  connects to those its own folders' settings allow, at most two at once, and the coordinator joins
  the two over a set-up circuit (below) to time the punch; if that fails, it tries the next. A
  device prefers coordinators it is already connected to and falls back to public relays acting as
  coordinators, only those its person turned on. How many reservations a device keeps, that it
  renews each before it expires and replaces one whose coordinator goes away, and how many
  coordinators a requester reads and tries at once, are the spec author's choices, for the owner's
  review.
- **Known peers or key holders** (the owner's decision of 2026-11-10, "Known peers or key holders
  (Recommended)"). The device to be reached takes a punch only from a requester that is a peer of a
  folder whose settings allow the punch (above), or one that first proves, over the coordinator's
  circuit, that it holds a key to such a folder: the sync protocol's handshake up to the folder
  proof, on a stream that only the device to be reached opens, and only for a requester it does not
  know, a few small messages and no record, within the circuit's bounds and the punch attempt's 10 s
  (`protocol.md` §3.1). It knows the requester by the circuit relay v2 STOP message, which names the
  initiator's peer ID, and by the end-to-end channel inside the circuit, which authenticates it; a
  requester whose authenticated peer ID differs from the STOP's is refused. Until the requester is
  admitted, the device sends it no address on the circuit and does not start DCUtR, which, as the
  side the circuit reached, it starts. A coordinator answers a requester whose punch the device
  refused as it answers one asking for a device that holds no reservation with it (circuit relay
  v2's NO_RESERVATION), so its answer tells nothing. A requester that is neither learns at most that
  the device is online, and what any connection to it shows before a folder opens (its device ID and
  Hello, section 5), from the set-up and handshake inside the circuit, and only if it already had
  the device's peer ID and coordinators, which travel only to its folders' peers and in invites; a
  removed person (TM-42), once no peer of a folder the device still holds and holding no key to one,
  learns nothing more through a punch: no address, no folder, no punch.
- **No proof for the coordinator, and nothing more to learn.** Coordinating needs no key to any
  folder. The coordinator learns that the two devices are connecting, when, both their public
  addresses and libp2p peer IDs, and which devices keep reservations with it, which both devices'
  settings let it learn; a punch exposes nothing else: no folder, no key, no file, and nothing to
  the internet beyond each side's address to the other, toward which each side's router opens a
  mapping.
- **Set-up only, never file data.** A circuit through a device a side reserved with, or dialed
  through, only for a punch, and any circuit whose stated circuit relay v2 limit is at most 60 s or
  64 KiB, is punch-only, whatever its folders' public-relays switches say and whatever the device in
  the middle says it is, since what that device says can turn sync off, never on (`protocol.md`
  §3.1; the coordinator's rulings of 2026-11-08, the first confirmed by the owner that day: "I don't
  want random connected clients used as relays without the operator's consent", and of 2026-11-10).
  After its security and muxer set-up, a punch-only circuit accepts only identify and DCUtR streams
  and, at the requester, the `/licketysync/sync/1` stream on which the device to be reached asks for
  the admission handshake above, and refuses every other stream.
  The coordinator, which cannot read what passes, states 60 s and 64 KiB as the circuit's limit and
  closes the circuit once it has carried 64 KiB in all or lasted 60 s, whichever comes first.
- **Direct connections only.** A coordinator accepts a reservation, and a request for a punch
  (circuit relay v2's CONNECT), only on a direct connection, never on a relayed one, so coordinators
  do not chain and a punch's 64 KiB bound is not multiplied (the reviews of 2026-11-10).
- **Rate limits whose state outlives a connection.** At most 4 punch circuits at once and 10 in any
  minute for each requester, counted both by libp2p peer ID and by source address, as a relay
  counts; at most 4 at once and 10 in any minute to one reserved device, however many requesters
  ask; and at most 64 at once and 120 in any minute in all; past any of them it answers busy. It
  accepts at most 2 reservations for each requester by peer ID and 8 by source address, and 128 in
  all; when the cap in all is reached and others wait, it drops the reservation that has gone
  longest without a circuit, and it keeps a device that is a peer of one of its folders before one
  that is not. The counters are kept in tables of a fixed number of peer IDs and of source addresses
  (by default 4 096 each) that outlive the requester's connections, sized above the caps in all: an
  entry with a live circuit or reservation is never evicted, and of the others the least recently
  active is evicted to admit another, with the relay's residual of that eviction and of denial of
  service (above), which the limits in all still bound. So a coordinator carries at most 64 circuits
  of at most 64 KiB at once, and opens at most 120 in any minute: about 7.5 MiB a minute over a long
  run, and at most about 11.5 MiB in any one minute (the 120 opened in it and up to 64 still open
  from before it), against the few kilobytes a punch needs: much less than a relay, which
  carries whole transfers.
- **What a punch may be aimed at** (the security review of 2026-11-10, and the confirm and
  re-confirm reviews of that day). Each side of a punch, the device to be reached and the requester
  alike, takes at most 8 addresses from the other side's DCUtR messages, and only global unicast
  ones with a non-zero port. Global unicast is judged by the IANA IPv4 and IPv6 Special-Purpose
  Address Registries: an address is refused when the most specific block of those registries that
  holds it is not marked globally reachable, and when it is multicast (224/4, ff00::/8). Three
  blocks are refused whole, whatever a more specific entry says: 192.0.0.0/24, 192.88.99.0/24 and
  2001::/23, whose anycast addresses (PCP's and TURN's among them) reach a service near the sender,
  its own router say (the spec author's choice, for the owner's review). An IPv6 address must also
  lie in global unicast space, 2000::/3, unless it is under the NAT64 prefix 64:ff9b::/96 (below),
  so that addresses that no block of the registry holds are refused too: site-local (fec0::/10,
  deprecated), IPv4-compatible (::/96, ::192.168.1.1 say) and the rest of ::/8. So never this
  network (0/8), loopback (127/8, ::1), private (10/8, 172.16/12, 192.168/16), shared (100.64/10),
  link-local (169.254/16, fe80::/10), unique local (fc00::/7), reserved (240/4), limited broadcast,
  unspecified (0.0.0.0, ::), documentation or benchmarking addresses. An IPv6 address that carries
  an IPv4 address is refused, or judged by that IPv4 address too, so that a dual-stack socket cannot
  be steered into a private network: an IPv4-mapped address (::ffff:0:0/96) is refused whatever it
  maps, since a side that means an IPv4 address sends it as one (the spec author's choice, for the
  owner's review); one under 64:ff9b::/96, which the registry marks globally reachable, passes only
  if the IPv4 address in its last 32 bits passes; 64:ff9b:1::/48, 6to4 (2002::/16) and Teredo
  (2001::/32), which the registry does not mark globally reachable, are refused whatever they carry;
  and one under a NAT64 prefix of the side's own network that the side knows, from its network's
  announcement (PREF64, RFC 8781) or its system, never by a DNS lookup (RFC 7050's), which would
  contact a host `spec/allowed-hosts.txt` does not list (TM-31), passes only if the IPv4 address
  that RFC 6052 §2.2 places in it passes, its last 32 bits under a /96 prefix (the spec author's
  choice, for the owner's review). A side also refuses its own addresses, so that a punch cannot be
  aimed at itself or its link: any global IPv6 or public IPv4 address of its own interfaces, and in
  each of its own IPv6 /64s the subnet-router anycast address (interface identifier 0, RFC 4291
  §2.6.1) and the reserved anycast identifiers (the last 128 of the /64, RFC 2526), the subnet-wide
  ones that reach a router (the spec author's choice, for the owner's review, on the check of
  2026-11-11). `net` never sets SO_BROADCAST on a socket a punch uses, so that no packet goes to a
  directed broadcast address (the same choice). Stated residuals: behind a translator on its network
  whose prefix or mapping the side cannot learn, since its network announces none or the mapping is
  not a prefix, an address passes as global unicast, and a punch's packets to it reach what the
  translator maps it to, a private IPv4 address included; and an address in a publicly numbered
  network that the side reaches only by a route other than its default, a split-tunnel VPN's say,
  passes, so the punch's packets reach that network; and the public address that its NAT maps it to,
  which is not one of its own addresses, so a punch can be aimed back at its own router through it
  (all three stated, not refused, for the owner's review); all within the caps below. `net` tests
  one address in each refused block and in each range that carries an IPv4 address, with an embedded
  address that passes and one that does not, the side's own addresses and anycast addresses, and
  that no punch socket has SO_BROADCAST (these rules, and the registries as their source, are the
  spec author's choice, for the owner's review). A device takes part in at most 2 punches at once
  and 6 in any minute through one coordinator, and in at most 4 at once and 20 in any minute in all,
  the caps in all checked at the moment of admission and counting the attempts already admitted, so
  a requester whose admission would bring them above is refused with `Close(NO_COMMON_FOLDER)` (when
  the handshake's stream is open), and that refusal counts toward the caps through its coordinator
  only (the spec author's choice, for the owner's review, on the check of 2026-11-11); an attempt
  runs from the circuit's opening, admission included, to the punch's end or the requester's
  refusal, and ends within 10 s; its counters per coordinator are kept in a table of at most 64
  coordinators, the least recently used evicted, which the counts in all still bound (TM-22). A
  circuit still in admission is not counted in the caps in all, so circuits in admission are bounded
  only by the per-coordinator caps times the table's 64 entries, up to 128 handshakes at once (a
  stated residual, for the owner's review). These numbers are the spec author's starting values, for
  the owner's review. At the device to be reached, an attempt counts toward its caps through the
  coordinator from the circuit's opening, and toward its caps in all only once it admits the
  requester, so a circuit that it refuses at admission counts toward its caps through that
  coordinator and never toward those in all (the spec author's answer to the confirm review of
  2026-11-10, for the owner's review); and it takes a circuit (circuit relay v2's STOP) only from a
  device in the middle that it holds a reservation with, answering any other circuit relay v2's
  NO_RESERVATION and counting it toward no cap (the re-confirm review of 2026-11-10). So a
  coordinator that ignores its own caps can make the device run at most 6 admission handshakes a
  minute through it, and at most 18 through its three. The cost, stated: a requester the device
  refuses that has its peer ID and coordinators, a former peer or anyone an invite reached, can keep
  the device from being reached by punches through each coordinator for as long as it keeps asking,
  as the coordinator's cap for each reserved device already lets it; the device's own punches
  through other coordinators, and its direct, LAN and relay connections, are unaffected. The other
  answer, refused circuits outside the caps, would bound the handshakes a device runs only by the
  caps its coordinators keep. The stated residual of the addresses: a requester that the device to
  be reached admits, a peer of a shared folder or a key holder, can still make it send a punch
  attempt's few packets to up to 8 public addresses of its choosing, its own network's among them
  (the global IPv6 address of a device on its link, or its router's public IPv4 address, which the
  router may pass on to a port it forwards), at most 20 attempts a minute, so at most 160 short
  bursts a minute toward third parties, and the device to be reached can do the same to a requester;
  a coordinator that lies about an address adds nothing beyond that, since each side filters what it
  receives.
- **Abuse, and its bounds.** A coordinator flooded with requests answers busy past the limits above,
  and its tables do not grow. A requester cannot aim a punch at a device that did not ask for one:
  the coordinator opens a circuit only to a device that holds a reservation with it, which a device
  makes only as its own settings allow, and that device takes the punch only from a requester it
  knows or that proves a key. A coordinator that lies about an address, or withholds or delays the
  set-up, costs a failed punch and nothing else: the connection a punch makes is authenticated by
  the transport's peer ID, and nothing of a folder crosses it before both sides' folder proofs
  (TM-32); the device then tries another coordinator, or stays unconnected.

The byte, time and count bounds, the coordinators' included, are the spec author's starting values,
fixed in phase 2 with the code that applies them. A public relay, when its person turns relaying on,
also coordinates punches, within its own limits above, with no second switch (the owner's decision
of 2026-11-13, "Yes, relays help too (Recommended)", which confirms the spec's reading of their "you
can fall back to public relays"), and the device to be reached admits a requester through it as
through any coordinator.

The defaults of a relay's limits are fixed with the relay protocol, in phase 7. Stops a relay or a
coordinator being used as free bandwidth beyond what its person allows, one requester, or many
identities from one address, taking a relay's capacity, a relay or a coordinator learning contents
or which folder a connection is for, a punch aimed at a third party or into a private network
beyond the residuals stated, a stranger or a removed person reaching a device through a punch, a
coordinator for the devices of its own folders joining anyone else, and a device relaying or
coordinating, a folder taking a punch its settings do not allow, a folder's traffic leaving through
a relay, or anything turned on before the guided setup's answer, without its person's consent
(Syncthing relay spec; libp2p circuit relay v2 and DCUtR). Enforced by `net`: hole-punch
coordinators from phase 2, public relays in phase 7 (the owner's decision of 2026-11-04), with
`protocol.md` §8 item 15's vectors; the settings' starting values and the guided setup by `daemon`
and `cli` from phase 1, by `app`, and by `web` for the browser client, whose own setup is phase 6's
design, with these tests: `tm_25_nothing_before_the_answer` (a fresh device has every setting
unconfirmed, opens no listening socket but the local API's, joins no multicast group and sends no
packet, until the answer and, after "No", until the screen is confirmed and a setting needs one),
`tm_25_yes_sets_every_shown_setting_to_default`, `tm_25_services_follow_their_folders` (a service
starts with the first folder that uses it and stops with the last, however it was turned on),
`tm_25_no_shows_defaults_and_turns_on_nothing_until_confirmed`,
`tm_25_a_change_overrides_the_default`, `tm_25_reset_sets_every_setting_to_default`,
`tm_25_a_folder_at_default_follows_the_device`, `tm_25_a_new_folder_starts_at_the_device_default`
(its switches at default unless changed as it is made or joined, and never unconfirmed),
`tm_25_a_phone_coordinates_for_no_one`, `tm_25_no_answer_makes_no_folder` (closing the setup or the
settings screen unconfirmed, a command-line "no" that leaves settings unconfirmed, or a command
without a terminal, makes or joins nothing), `tm_25_a_later_setting_is_unconfirmed_until_asked`,
`tm_25_a_default_that_allows_more_is_unconfirmed_until_asked` (a recommended default changed to
allow more, off to on, a more open hole-punch level or a wider coordinating value, leaves a setting
at default unconfirmed; one changed to allow less applies at once) and
`tm_25_the_command_line_reports_unconfirmed_settings` (its "no" sets nothing and prints each
setting's default and command; `settings confirm` and a reset set the shown settings to default and
print each with its value).

**TM-26. Port mapping is off until turned on, and maps one port for this device, with a bounded
lease, removed at exit.** Asking the home router to forward a port is a setting of each device, not
of a folder, off until its person turns it on: in the guided setup, whose recommended set turns it
on (the owner's decision of 2026-11-13, "Yes, this feature should default to on (see the previous
question) and advanced users can turn it off before the folder even starts to sync."; TM-25), or in
the settings. UPnP, NAT-PMP and PCP requests name only this device's single listening port and a
lease of bounded length, and the mapping is deleted on shutdown and when the setting is turned off.
The client talks only to the default gateway that the system reports for the network it is on, by
NAT-PMP or PCP at that address's port 5351, taking replies only from that address, and to SSDP's
multicast address (239.255.255.250 port 1900, or ff02::c on IPv6) to find the gateway's UPnP
service; it accepts a LOCATION or control URL only when the URL gives the gateway's own address
itself, refusing, and never looking up, one that names a host (TM-31), bounds every reply
before it allocates for it (TM-2, TM-22), and parses the UPnP descriptions' XML with no DTD and no
external entities; each of these parsers is fuzzed (TM-3). With the setting on, the device asks the
router of every network it joins, a café's or an office's among them, and that router, and anyone
on that network who watches SSDP, sees it ask. While the port is mapped, anyone on the internet can
reach it and learn what any connection to the device shows before a folder opens (section 5, "To a
network observer"): that it runs LicketySync, its libp2p peer ID, its device ID, the protocols it
offers, its Hello and, from how long a refused folder proof takes, a coarse count of its folders;
never a folder or a file without a key. Stops mappings injected or abused on home routers
(UPnProxy 2022; CallStranger 2020), a router's answers steering the device to another host or
exhausting it, and a port opened without its person's consent. Enforced by `net`, from phase 2.

**TM-27. The Tauri shell uses the isolation pattern, a content security policy and per-window
capabilities with the smallest command set.** Frontend code reaches the native core only through
commands a window's capability lists, through the isolation application that validates each message.
Stops frontend dependencies reaching the native core through IPC (Tauri 2 security documentation).
Enforced by `app`.

**TM-28. Each release publishes a signed manifest of the browser bundle's hashes.** The manifest is
signed with the release key, the native app can verify a served bundle against it, and the site
documents WEBCAT and Code Verify-style verification. The service worker cache gives no protection
against the host beyond its update interval, because the host serves the service worker too; the
native app's manifest check and a verifying extension are the only checks. Stops a compromised static
host serving a changed client, which subresource integrity cannot catch (W3C SRI; Code Verify;
WEBCAT). Enforced by `web` and the release workflow.

**TM-29. Updates come only through package managers and stores, with signatures verified before
unpacking and no downgrade; releases are signed and carry an SBOM and provenance.** The program
performs no update check and downloads no code; a package or store update is verified by that
channel's signature before any byte is unpacked, and a version lower than the one installed is
refused; every release is built in CI, signed, and published with a software bill of materials and
build provenance, so a shipped binary can be audited later. Stops auto-update downgrade and
malformed-archive attacks (Syncthing 0.12.23) and tampered or unreproducible releases. Enforced by
the release workflow and each platform's package or store channel.

**TM-30. Suite lists are bound to the transcript.** The Hello lists the suites each side supports,
the lists are bound into the transcript that the session keys authenticate, and a mismatch between
what was offered and what was seen ends the connection, so a downgrade is detected rather than
negotiated; the protocol version is chosen as the newest common one, never by the untrusted side
alone; and a folder's suite is fixed by its keys (the key strings carry it and the folder ID hashes
it), so no record of a folder can be read under another suite. Stops the protocol version chosen by
the untrusted side (Seafile 2024) and cipher-suite downgrade (FREAK, Logjam, POODLE). Enforced by
`protocol` and `keys`; the rule is `suites.md` section 1.

**TM-31. No host is contacted that `spec/allowed-hosts.txt` does not list.** A host is added only in
the change that adds the feature contacting it, and only for a feature that is off until the user
turns it on. Every connectivity setting starts unconfirmed, which acts as off, and the user turns
one on by answering yes to the guided setup's recommended set, by confirming the settings screen
with it at default or on, or by setting it on, and a setting a later release adds by answering the
app's question about it (the owner's decisions of 2026-11-13, TM-25): so LAN discovery's multicast
and broadcast addresses, which count as hosts and which the list will carry once phase 1 adds LAN
discovery, are contacted only while it is on, and before that answer the device contacts nothing.
Port mapping (TM-26) contacts the default gateway, whose address the system reports and no string
holds, and SSDP's multicast address, 239.255.255.250, which the list will carry once phase 2 adds
port mapping, and on IPv6 ff02::c, noted here rather than listed, since the list holds only
hostnames and IPv4 addresses; the DHT's first nodes to ask join the list with the DHT, in phase 2.
`ci/no-hostnames.sh` checks hostnames and IPv4 addresses in one-line string literals in the `.rs`
files under `crates/` against the list; it catches accidents, not adversaries, and states its limits
(names under six top-level domains only; not IPv6, not hosts assembled from pieces, not `Cargo.toml`
or included data files), which the reviewers cover. Of the project's own domains it exempts only the
join-link prefix: it removes the exact text `https://licketysync.app/join#` and checks the rest of
the string, so a URL that begins with it passes, and the reviewers confirm that the binary, which
parses and writes join links, never requests it. Any other URL on those domains needs its line in
the list like any other host. Stops telemetry, update checks and any contact the user did not
choose. Enforced by `gate.sh` and CI, and the settings' starting values by `daemon` and `cli` from
phase 1, and by `app`.

**TM-32. Each side proves it holds a key to the folder without sending it.** The handshake's folder
proof is one proof for every tier (ruling S-1): a payload sealed under a key derived from the
folder's access key, which every tier holds and nobody else does, with a hint keyed under a sibling
key, both bound to the session's transcript and the prover's role, so it cannot be replayed into
another connection or reflected to its sender (`keys.md` §4). The tier the payload names is the
prover's report, shown, and relied on only to tell how soon a change of the greatest watermark
owes a round on the connection: at once toward a peer that reports the read or write tier, and at
most once per `WATERMARK_INTERVAL` (a day) toward one that reports the sealed tier (the
coordinator's rulings of 2026-11-12, for the owner's review; `protocol.md` §3.5, §4.5 "Round
owed"), since records and chunks are verified by signature and hash whoever sends them: a false
report gains a peer nothing it could not have by withholding records or by opening the folder
again on a new connection. Knowing a folder ID from a LAN beacon or the DHT is not enough to
connect, to open a proof or to learn whether a device holds the folder; and a device ID is the hash
of the device's public key, canonically encoded, which it proves in the same handshake. Stops
impersonation, uninvited connection and probing for folders. Enforced by `protocol` and `keys`,
and `engine` for the rounds the reported tier decides.

**TM-33. Content is encrypted under symmetric keys before it leaves a device, and the public-key part
is stated, not overclaimed.** Contents, names and structure are encrypted under 256-bit keys derived
from the folder's data key, which never travels inside the protocol (key strings move outside it, and
between linked devices only over TLS 1.3 with the hybrid X25519MLKEM768 group, `keys.md` §8.3), so
recorded traffic yields at most what a sealed peer sees, even to a future quantum computer, and no
party stores a key wrapped for someone else. Signatures are Ed25519 alone (ruling R-K1, after the
owner's answer of 2026-10-22): a future quantum computer able to break Ed25519 would let anyone who
holds the folder's verification key (every read and sealed holder), and perhaps anyone who recorded
signed records, derive the signing key and forge updates; suite agility may add post-quantum
signatures as a later suite, whose folders are new folders (`suites.md` §5), and where a suite pairs
two algorithms both must verify. Stops "harvest now, decrypt later" against content and keys; it
does not stop a future forger, which the owner accepted. Enforced by `keys`; the construction is
`suites.md` section 2.

**TM-34. Retired 2026-10-22.** Was "Every change is attributable to a key, and to the device its
holder claims". Nobody records who changed what (owner's decision, 2026-10-18): a record names only a
device ID its signer chooses, used to sync and never shown as an author (`keys.md` §5.3, ruling S-4),
and section 3.6 says what that leaves.

**TM-35. Writes are atomic beneath the root, and destruction is reversible by default.** A file is
downloaded to a temporary file beneath the folder root (resolved by TM-4), verified against its
record, then renamed into place; replaced and deleted files go to the archive (Trash can, phones
included), which keeps them 30 days by default, a setting (the owner's decision of 2026-11-10, "30
days should be configurable"); the copies a device moves there because a path's records became
unreadable stay, past that retention and with versioning off, with a warning, until a version the
device reads covers theirs, a head that does not cover it leaving them there (the owner's decision
of 2026-11-10, "Until fixed"; `protocol.md` §4.4, "A path with no heads"); a scan that finds the
marker gone, the path unmounted, or more than the
threshold of files missing at once pauses the folder and announces no deletions until the person
confirms (the deletion brake). Deletions that arrive from peers are applied without a brake, however
many (the owner's answer of 2026-10-22): the archive is what keeps them. This is what limits a write
holder's power to destroy (section 3.2): the archive keeps every file a remote change replaced or
deleted, on each device whose versioning is on, and the brake keeps a device from announcing a mass
disappearance of its own that it did not mean; neither stops a write holder who deletes on purpose,
and what they limit is how much is lost for good. Unlinking a folder keeps its archive as ordinary
files (`keys.md` §7.3), so what a removed person destroyed can still be restored after the others
share again (TM-42). Stops partial files appearing as complete and limits what a hostile or mistaken
writer can destroy. Enforced by `engine` and `app`.

**TM-36. Retired 2026-10-22.** Was "The phrase derives everything and nothing derives the phrase".
There is no phrase and no owner key; within a folder, one-way derivation from the write secret is
`keys.md` §1.2 and TM-11.

**TM-37. Key strings carry only the key and a checksum; invites are bare by default.** A key string
carries the suite and the tier's key material (`keys.md` §6.1) and its checksum, and nothing else: no
address, no name, no expiry. Addresses and the certificate hash are appended to a link only by the
sender's choice: when the sender adds them, or, automatically, when the sender makes a browser
invite or a parcel link (phase 6). A browser invite is a link made for someone to open in the
browser client, which cannot find a device by LAN discovery or the DHT (the spec author's reading of
the plan's term, for the owner's review): a native device makes it when its person says the link is
for a browser, and appends, as it makes the link, the addresses at which a browser can reach it then
and the hash of its WebTransport listener's certificate, which lasts at most 14 days; that listener
is a device setting, off until turned on (TM-25), which making a browser invite asks to turn on,
saying what it shows (section 5, "To a network observer"; `keys.md` §6.3). The certificate's life is
no expiry: a leaked browser invite gives the folder away like any key string (section 3.5). The app
or the CLI says, as it makes a browser invite or a parcel link, that the link carries the device's
addresses. Stops an invite putting the sender's home address into an email or chat unasked. Enforced
by `keys` (encoding) and `cli`, `app`, `web` (what is offered).

**TM-38. Retired 2026-10-22.** Was "A revoked key never learns a new epoch". There are no epochs: a
folder's keys last its whole life, and anyone who held a key keeps what it opens until the others
share again (TM-42).

**TM-39. Folder keys and device secrets leave a device only by the person's explicit action.** The
local API returns a folder key, as a key string, words or QR code, only from its key-export command,
which the CLI and the UI call on the person's explicit action. Showing or exporting a write key, and
sending one to a linked device, also requires the operating system's own user authentication on that
device (the owner's answer of 2026-10-22), since it is full control of the folder; on a device that
has no such prompt, such as a headless box, the key store's passphrase stands in for it (`keys.md`
§6, decision). The rule fails closed: the prompt or the passphrase is asked at that moment, every
time, and an unlocked key store, a running daemon or a local process holding the API token does not
count, so nothing can export a write key without the person; a device that has neither a prompt nor
a passphrase-protected store refuses to show, export or link a write key until the person sets one
of them. A read or sealed key needs the explicit action only, since neither can change anything
(decision). The MCP server never calls the export (plan, AI
access); no endpoint returns a device seed or a derived key; a linked-device transfer confirms on
the sending device; and the app says, wherever it shows a key, that a key once given cannot be taken
back (TM-42). The write key's 24 words look like a cryptocurrency wallet's recovery phrase (the same
BIP39 list and length): a person may take them for one, and a program that hunts for wallet phrases
on disks and clipboards will take them too, so the app labels them, wherever it shows them, as one
folder's write key, to be kept as secret as a wallet phrase and typed nowhere else. Stops a local
process or page with the token, an agent, or a log reader obtaining keys. Enforced by `daemon`,
`cli`, `app`.

**TM-40. Versions are ordered by version vectors, never by wall clocks; deletions are forgotten only
by a signed watermark; and no record or peer is refused for its clock.** No ordering decision and no
decision about whether two versions conflict depends on a timestamp: every validly signed record
whose seal opens and that is not a writer fault is applied, and which versions of a path are live,
and so its heads, follows only from which records replace which, by the version vectors and the
signed names (`protocol.md` §4.4), in any arrival order (TM-41). The only timestamp use in conflict
handling is a deterministic tie-break among the heads of one path, all of which are kept: in the
display order (non-tombstones first, directories before files, then the later modification time,
then the smaller record hash; `protocol.md` §4.4) the first sits at the path, and the others, where
their content differs, become named conflict copies. It never outranks coverage, and every head
stays a head, so a writer who sets a future modification time or grinds record hashes gains only
which copy is shown first; a later record that covers them all replaces them. The modification time
is only ever compared, never subtracted, and a value the local file system cannot set is an issue
raised against the record, never a panic (TM-23). A device's clock enters the index in two places
only, and neither orders versions nor decides by itself what another device holds. First, a new
record's counter is at least its writer's wall clock, up to `CLOCK_FLOOR_MAX` (the clock floor,
which keeps a device restored from a backup from reusing counters, a protection of the writer's own
that no other device checks), so counters roughly follow time and rank a vector's entries when it is
pruned. Second, a write holder's clock decides when it signs a **watermark** (the owner's decisions
of 2026-11-08, "Switch" and "After 365 days", and of 2026-11-12, "A year after arrival, together",
for cleanups "the same logic as the deletion of a file", and "Wait, never early"): each write holder
notes, by its own calendar, when each tombstone, tree delete and cleanup arrived there, and signs,
in a cleanup, the greatest counter of one it has held for the 365-day deletion horizon that lies
below every one it has held for less; every read and write holder that holds the watermark forgets
every tombstone, tree delete and cleanup at or below it, all together, and ignores one offered again
(`protocol.md` §4.4, "Expiry by the watermark"). What is forgotten is then a function of the records
held, by the greatest watermark among them, so two devices that hold the same records forget the
same ones whatever their clocks say (TM-41). A wrong or faked clock costs at most deletions
forgotten early, never a version (the owner's decisions of 2026-11-12, on a clock that jumps,
"Accept, documented", and on a date an outsider fakes, "Still accept, documented": no guard, stated
plainly here). **The worst case**: one write holder whose clock jumps a year or more ahead signs, at
its next check, the greatest counter it holds, so that every device forgets every deletion in the
folder at once, and deletions still on their way, dated below it, are undone on arrival. Its clock
can get there by a mistyped year; by being a new device first synced with a wrong clock and then
corrected; by being a machine back after a year or more that boots with a wrong clock and receives
records before its time is synced; or by an outsider with no key who sets its date through time sync
that is not authenticated (NTP or SNTP, a time server a DHCP server names, or a fake cell tower's
NITZ), after which the device signs a genuine watermark (section 3.1). Short of that, a write holder
whose clock gains time signs early by as much; a device whose clock reads behind and that has held
little of the folder dates its deletions below a watermark, so they are undone on arrival; and a
fast clock's lead, carried forward by the Lamport rule, moves the watermarks ahead with the
counters. Each way a deleted file comes back wherever a copy survives, at a device that never saw
the deletion, at a sealed peer, or with a key holder that kept the old record, and none is lost
(TM-43). Forgetting can also come late, without bound: a deletion that arrives late holds back its
write holder's forgetting of the records dated above it until it, too, has been held a year; a
dishonest writer can keep forgetting from moving at all (section 3.6); a peer that is a write
holder's only link, or a network attacker that cuts it off, can release deletions to it slowly
(sections 3.3 and 3.1); and a write holder with no monotonic clock that counts time asleep (a
browser, phase 6, whose `performance.now()` may pause while the device sleeps) can sign late after
a sleep (`protocol.md` §4.4, "When a write holder signs one"); and, once deletions stop, a folder
keeps the watermark-only and case-(c) cleanups of its last year, since no write holder signs only to
forget them, until a watermark that the next deletion, or a cleanup with a `because`, brings (the
coordinator's ruling of 2026-11-12), all of which costs storage and never a file (the owner's
decisions of 2026-11-12, "Wait, never early" and, on a slow release, "Accept, documented"). The
clock rule of
2026-10-25 is gone (the owner's decision of 2026-11-08): no Hello carries a clock, no device refuses
a peer or a record for its clock, and no store is kept closed for one; its remedy (unlink, fix the
clock, add the folder again), the residuals that remedy left and the fast-clock warning are gone
with it. Counters have a fixed ceiling, `MAX_COUNTER`, 10 000 years after 1970, which every read and
write holder checks alike and with no clock (the owner's decision of 2026-11-12, "a fixed ceiling");
it cannot stop a write holder that signs a counter just below it from exhausting the folder's
counters, a dishonest writer's stated residual (section 3.6). Sealed peers read no counter and no
watermark, and forget deletions only by a write holder's cleanup. The one door-keeping decision that
reads the clock is the LAN beacon window, which drops beacons whose minute is far from the
listener's; no key expires. Everything else the local clock serves is advisory: lease lengths, the
daily discovery hash (looked up for the neighbouring days too), protocol timeouts, per-peer state's
age, the window that bounds the names a write holder issues for one peer, and the informational
`written_at` field, which is what a key holder's views show as a version's write time, never its
counter. Stops a clock from ordering versions, from deciding whether two conflict and from having a
peer or a record refused, and stops the clock of a device without the write key from moving what
any device forgets; a write holder's clock wrong by the same amount all year counts the year right.
Does not stop a write holder's clock, read when it signs, from bringing forgetting forward: a
person's mistake or an outsider's faked time can set it a year or more ahead, so that every deletion
in the folder is forgotten at once and deleted files come back, never a version lost (the stated
worst case above, which the owner accepted on 2026-11-12). Enforced by `index` (expiry by
the watermark, the index by counter, arrivals and the candidate, the counter ceiling) and `engine`
(when a write holder checks and signs, and the rounds a change of the greatest watermark owes); the
clock rule's checks leave `protocol` and `engine`.

**TM-41. Concurrent versions are kept, peers that exchange converge, and sealed peers lose
nothing.** At a read or write holder every validly signed index record is kept until a held record,
tree delete or cleanup replaces it, and applied when its seal opens and it is not a writer fault
(writer-fault records are held opaque, covering nothing, replaced only by a signed name, and applied
by no one; the next write at a path names the ones there that every release judges faults, and never
one opaque only because its kind is unknown to the writer's release, which may be a newer release's
version, `protocol.md` §4.4, "Its names", "A newer release's version"). Whatever replaces a record
was written after it, by a writer that knew it or a later record of its device on that path or
beneath that directory (`protocol.md` §4.4, "Why it is safe" 3 and 10). At a sealed peer, which
reads no seal, a record is kept until a signed record or a write holder's signed cleanup names it,
so it keeps concurrent versions and stale copies alike and drops nothing no signature names (11). A
cleanup's group acts only while the record it was issued for is held, on every tier, so what a
device holds and refuses depends only on the records it holds, never on what it held before (the
coordinator's ruling of 2026-10-25, for the owner's review); a cleanup names exact fingerprints and
can never remove a later version, however late it is replayed (12). Two records that do not replace
each other are concurrent and both kept, whatever made them: two devices editing apart, a write
holder's own choice of vectors, or **equivocation**, two different records with one dot (a write
holder signing twice under one device ID, a write holder writing under another device's ID, two
devices cloned from one disk image, or a device restored from a backup). Equivocated records have
two fingerprints: read and write holders hold both, since no record covers its own dot, as a
conflict that a later write covers (a write made from either covers both, since coverage reads only
the dot), two identical contents making no copy; sealed peers hold both, since neither names the
other; and two devices that each hold one of them have different set digests over that file ID's
subtree, so reconciliation finds the difference and each ends holding both. Their meaning for their
path the heads decide like any concurrent edit, with no blame, no withdrawal and no evidence (ruling
R-K5; `protocol.md` §4.4, "Why it is safe" 13). Peers compare what they hold by set digests over
record hashes, never by vectors or counters, subtree by subtree of the file IDs, and send each other
what differs (`protocol.md` §4.5); pushes start when a folder opens, a dropped push makes the
receiver owe a round, so does, toward a peer that reports the read or write tier, a commit that
raises the greatest watermark held and expires a record (a version a peer pushed, which the expired
deletion had replaced here, is no longer replaced), or lowers it (a deletion a peer pushed, which
had expired here, is no longer expired; the coordinator's rulings of 2026-11-12, for the owner's
review), and every round ends with that comparison, so no record either side holds is left unasked
for; toward a sealed peer, which judges by names alone, such a change owes a round at most once a
day (`WATERMARK_INTERVAL`), so what it leaves there waits at most about a day. So two
read or write holders that end caught-up rounds with each other hold the same records, whatever a
write holder signed, in whatever order the records arrived and whatever their clocks (expiry depends
only on the records held, by the greatest watermark among them, TM-40), and compute the same heads;
a sealed peer holds what they hold plus the stale copies a write holder has not yet named, less, for
a while, a version that came back after its deletion was forgotten and that a replay of that genuine
deletion took away again, and holds the same once a write holder has met it and the rounds its
cleanups owe have run, short of stale copies that wait for the write holder to forget the cleanup
that named them. A sealed peer can still withhold records from a peer that meets no one else; it
cannot make two read or write holders that meet disagree, nor make a read or write holder drop a
version. Pruning and expiry may cost spurious conflicts or reappearance, never silent loss (TM-43).
A local edit or delete is built only from the versions on the writing
device's disk and their twins, the other versions of the same content, concurrent with them and, at
the path, after them in display order, never the first head, which it covers with them (so that a
file two devices wrote alike, shown as one file, is one version after the next save: the
identical-heads fix of 2026-11-08). So a version that has arrived but whose content has not reached
the disk is never replaced by an edit made without it: the two become a conflict (`protocol.md`
§4.4, "Bases"; "Why it is safe" 9), and a version of the same content is replaced only as the one
already seen; a later version of it, one that changed only the mode say, and one the engine has yet
to put at the path stay conflicts too. A writer-fault record that every release judges a fault goes
when its path is next written, and the issue about it says that saving the file again clears it; the
stated residual is that one at a file ID nobody writes again, and a cleanup that is itself a writer
fault, stay on every tier (`protocol.md` §4.4, "Heads"). A path all of whose live records a device
cannot read (writer faults, or a newer release's version) follows the rule for a path with no heads,
so the device's outdated copy leaves its disk for the archive, and every device on the same release
that holds the same records keeps the same disk there, whatever the order they came in (the owner's
decision of 2026-11-03, "Yes, remove the old copy"; `protocol.md` §4.4, "A path with no heads"). The
device remembers the versions it so archived, and, on a device with the write key, its next write
there covers them, so that a device that missed the unreadable record does not bring the old version
back beside that write (the owner's decision of 2026-11-10, "Also what was archived"); only a
version it never had, an edit made elsewhere meanwhile, stays beside the write as a conflict. The
archived copies stay until a version the device reads covers theirs (TM-35). The stated residuals of
such a path (`protocol.md` §4.4): the archive holds the only copy on each device that had it; a
record of a kind no release knows takes the file off those disks until someone saves it, and stays
beside it for good; and a read holder cannot clear a fault. The stated residuals, each of which
replaces a version as a later edit would and moves its file to the archive (TM-35): a tree delete
also covers a version beneath its directory that its writer never held, held but had not yet on its
disk, or held but could not read, when that version's device later wrote another record there that
the writer had on its disk, as a base or a twin, or knew of through one, which a sealed peer or the
order of a reconciliation can bring about for a file renamed within the directory (§3.3), and a
folder linked on two devices can for a file still arriving when the folder is deleted (the owner's
decision of 2026-11-08); two devices under one device ID (a cloned disk image) can replace each
other's concurrent edits of a path one of them had written before, and so can a third device's edit
made from one of their records; and a device restored from a backup while its clock reads earlier
than its last write can have a new edit replaced by any record, its own or another device's, that
carries one of its earlier counters, after a single write of that path since the backup, a tree
delete included (`protocol.md` §4.4, "Why it is safe" 8). Stops honest peers diverging when a writer
signs two histories, which per-writer sequence numbers or version vectors alone let both sides miss
(Kleppmann 2022, "Making CRDTs Byzantine fault tolerant"), answered by keeping every concurrent
version and comparing hashes of records; stops a storage party resolving or discarding anything;
and, with TM-43, stops unbounded growth from turning into silent loss. Enforced by `index`
(coverage, names, cleanups, live sets, set digests, the property tests of `protocol.md` §8 item 7)
and `protocol` (the exchange); `engine` for the conflict copies and the archive.

**TM-42. Removing someone is unlinking and sharing again, and the app says what that does not do.**
There is no revocation and no re-key protocol (owner's decisions of 2026-10-18 and 2026-10-22): the
people who stay unlink the folder on every device, share one copy as a new folder with new keys, and
pass the new key outside the client (`keys.md` §7.4). Before any of it, the app advises pausing the
folder, so that nothing more arrives from the person being removed, and restoring from the archive
whatever that person changed or deleted, since deletions from peers are not braked (TM-35); unlinking
keeps the archive as ordinary files, so this can still be done afterwards (`keys.md` §7.3). It also
states that the removed person keeps the old folder, its key and every copy they had; that a device
still on the old key keeps syncing with them; and that sealed peers store the new folder afresh. A
removed person learns nothing through hole punches once the old folder is unlinked, unless they
still share another folder with the device: a device takes a punch only from a peer of a folder it
still holds whose settings allow the punch, or a requester that proves a key to such a folder
(TM-25), and the removed person is neither, so it gets no punch and no address, and learns at most
that the
device is online, with its device ID, which it knew, as a dial to an address it kept would tell it.
Nothing in the protocol moves a key or a folder's history between folders. Stops the false belief
that removing someone took something away, the over-promise the plan's hardening review found more
harmful than an honest leak, and the loss of what they destroyed on the way out. Enforced by `app`
and `cli` (what they say and offer); `keys.md` §7 defines the actions.

**TM-43. Pruning and expiry may cost spurious conflicts or reappearance, never silent loss.**
Bounding the index has two costs, both visible, neither a loss. Pruning a vector to
`MAX_VECTOR_ENTRIES` (the least recently active writer dropped first) can leave an older version
live beside a newer one, shown as a conflict copy; forgetting a tombstone, tree delete or cleanup by
a watermark, a year or more after it arrived at the write holder that signs it (sooner where that
write holder's clock is wrong, TM-40), can bring a deleted file back, as the file or as a conflict
copy, when a device, a sealed peer or a key holder that kept an old copy offers it again. The same
bound on a tree delete's names, 32 records at its directory's own path with their devices mandatory
in its vector, brings back records there from more than 32 device IDs (identical directories, or
conflict copies), until the next delete (`protocol.md` §4.4, "A tree delete"). None ever lets an
older version replace a newer one, and nothing drops a version that no later signed record or
cleanup replaces (`protocol.md` §4.4, "Why it is safe" 4 to 7 and 10 to 14). The same holds for a
wrong or faked clock: a write holder whose clock was set forward signs a watermark early, at the
greatest counter it holds when it jumped a year or more, and a device whose clock reads behind with
little of the folder held dates its deletions below one, so deletions are forgotten early, every one
at once in the worst case, and files come back, never go (TM-40); the watermark drops no version, so
a file comes back wherever a copy survives: at a device that never saw the deletion, at a sealed
peer, or with a key holder that kept the old record. Stops the bounds that keep the index small from
turning into silent loss, the failure the plan's hardening review found worse than a visible
conflict. Enforced by `index` (pruning, expiry by the watermark, the tree delete's names and the
property tests of `protocol.md` §8 item 7).

## 5. What stays visible

A peer-to-peer design cannot hide that it is running or who it talks to, and the sealed tier exists so
that a device that cannot read a folder can still hold and serve it, which means some facts about that
data are visible to it. The list is honest because the plan's hardening review found that the systems
it studied failed more often by promising too much than by leaking too much.

**To anyone on the LAN** (while LAN discovery is on, TM-25). That a device runs LicketySync and
which port it listens on; the device's address; in each beacon, under a salt fresh to that beacon,
one hash per announced folder and one hash of the announcer's libp2p identity key (its peer tag), so
that an observer who already knows the folder ID can confirm it is announced here, an observer who
already knows the device's identity key (anyone it has connected to) can confirm that device is
announcing, and an observer who knows neither cannot link two beacons to one folder or to one device
by their hashes; but each beacon also carries in the clear the port and the number of folders it
announces (one hash each), which change only when the device's port or its announced folders do, and
its Unix minute, which shows how far the device's clock is off, to the minute and more closely from
when the minute changes, an offset that stays about the same; these link a device's beacons from
their contents, across a change of its source address too (a temporary IPv6 address that rotates, or
a new address after its hardware address is randomised for the network, say), as the source address
links the beacons from one interface, which no hashing hides; and, by replaying a captured beacon
from its own address within the ±5-minute window listeners accept, which devices dial it and so hold
the folder the beacon named, without knowing that folder's ID: the dial is the signal, and `keys.md`
(discovery hashes) records it as the residual leak the design accepts.

**To a network observer.** That two addresses talk, when, for how long and how much; the sizes and
number of encrypted frames, which approximate padded chunk sizes and counts; QUIC and TLS handshake
metadata; on a locked-down network, the hostname of the HTTPS listener, timing and volume. Not
contents, names, keys or folder IDs, and not the peer ID: in TLS 1.3, QUIC and Noise XX the identity
key travels encrypted, so a passive observer does not learn which device is talking. Whoever
completes a connection to a device, with no key to anything, learns more: its libp2p peer ID, which
is stable because it derives from the device's libp2p identity key, so the device can be recognised
across networks, days and folders (the hashed form in LAN beacons confirms it to anyone who already
holds the key; DHT address records carry no peer ID); its device ID and public key, proven by the
DeviceProof before any folder is named; the protocols it offers in multistream-select; its suite,
compression, hash and feature lists and limits from the Hello (which carries no clock since
2026-11-12, `protocol.md` §3.2); and, from the time its first REJECTED folder
proof takes, a coarse count of the folders the device holds (about 6 µs at 1 folder and 1.4 ms at
2000; a constant-cost lookup table is a phase 7 follow-up). Not whether it holds a given folder: the
hint and the proof key need a key to that folder (TM-32), and a party that holds one would learn the
same from a successful proof. Not its name: the self-reported device name is sent only after a
folder has opened on the connection, in the first Status after the first folder opens, so only a
peer that has opened a folder with the device learns its name.

**To the DHT and anyone crawling it.** Which addresses announce a given day's discovery hash; a
signed address record under the device's DHT key; and, to each node a device asks, the device's
address and each discovery hash it looks up (for each folder, the hashes of the day before, the
day and the day after, `keys.md` §2.2): a node that knows the folder ID learns that this address
looks for that folder, and nodes placed near a day's hash, which anyone who knows the folder ID can
compute, are among those that lookups for it ask (section 3.9). The hash does not reveal the folder
ID and changes daily, but anyone who ever held the folder ID (any key holder, anyone who saw a key
string) can compute every day's hash and watch who announces it, and a device is linkable across
days by a stable address alone or by any stable identifier it publishes with the announcement: the
BEP 44 signing key its address record is signed with, or a persisted DHT node ID. The record carries
no libp2p peer ID, and no list of the hole-punch coordinators the device keeps reservations with,
whose addresses would name that peer ID (the owner's decision of 2026-11-10, "Peers now, alias
later"; TM-25); the DeviceProof binds identity at the handshake. The libp2p identity key still gives
every device a stable peer ID, which is a cross-folder tracking handle for anyone the device
connects to: they can tell it is the same device whatever folder, day or address is involved;
`suites.md` (the libp2p identity key) records the per-folder or rotating identity that would remove
the handle as a considered alternative.

**To a relay** (public only, TM-25). Both endpoints' addresses and libp2p peer IDs, timing and
volume, and the sizes and number of encrypted frames, which approximate padded chunk sizes and
counts. Not the folder, since a reservation and a circuit name peers, never a folder; not contents,
names, keys or any record: the end-to-end channel runs inside the relayed connection. A relay is
anyone's device whose person turned relaying on, so whatever it sees, a stranger may see.

**To a hole-punch coordinator** (any computer whose person turned coordinating on, theirs or a
stranger's, for anyone or for the devices of its own folders, and any public relay; never a phone;
TM-25; the owner's decisions of 2026-11-08, 2026-11-10 and 2026-11-13). What both devices' settings
let it learn: that the two are connecting, when, both their public addresses and libp2p peer IDs,
and at most 64 KiB of their encrypted set-up a circuit; and, of a device that keeps a standing
reservation with it, its peer ID, that it does, its public address as it changes, and when it is
online. Not the folder, not a key, not a file: neither runs the sync protocol through it beyond the
admission handshake, whose folder proof it cannot open (TM-32), and it needs no key to any folder.
One that coordinates for the devices of its own folders (the owner's decision of 2026-11-13,
"Narrow (Recommended)") joins only two peers of the same folder it holds, whose addresses and peer
IDs it has already, and learns of them only that they connect to each other, and when; it is
listed only to peers of that folder, and answers a request for a punch to a device of another
folder as if that device held no reservation, so it shows no one a share they do not already see in
the folder's own peer exchange. One residual remains: it serves no stranger only while its folders'
keys stay secret, since anyone who holds a key to one, a widely shared read or sealed key among
them, is a peer of that folder (TM-25). A folder at the second level,
through peers of a shared folder, gives this only to such peers; one at the fourth, which the guided
setup's recommended set picks, to every coordinator a punch for it uses, a stranger's public relay
among them (below).

**To the peers of a device's folders, and an invite's recipient.** Beyond what a key holder sees
(below), by peer exchange over connections on which a folder is open, and in an invite that carries
addresses: the device's addresses, its libp2p peer ID, and the coordinators it keeps reservations
with, by their peer IDs, each only to the peers of a folder whose settings allow a punch through it
and in an invite to such a folder, but a coordinator that is a peer of one of its folders, whatever
its mode, only to the peers of the folders open between the two, and in no invite (TM-25; the
owner's decision of 2026-11-10, "Peers now, alias later"). Not
the DHT: a crawler learns none of these from it. A requester that is no peer of the device's folders
and proves no key learns from a punch at most that the device is online, and what any connection to
it shows before a folder opens (TM-25).

**What the recommended set shows** (the guided setup's, TM-25; the owner's decisions of
2026-11-13). Before the person answers, and while its settings are unconfirmed, the device
contacts no one and listens only for the local API (TM-25, TM-31), and once on, however turned on,
each service starts with the first folder that uses it and stops with the last. Turning the
recommended set on adds: with LAN discovery, its beacons, to anyone on the same network, with
their port, folder count and clock offset (above); with port mapping, its port, to anyone on the
internet, who can then complete a connection and learn what the network-observer entry lists, its
peer ID, device ID, protocols, Hello and a coarse count of its folders, never a folder or a file
without a key, and its asking, to the router and anyone watching on every network it joins
(TM-26); with the DHT in client mode, what the DHT entry lists; with public relays, what a relay
sees, to whoever runs each relay used, a stranger among them; at the fourth hole-punch level, to
every coordinator a punch uses, a stranger's public relay among them, that two devices are
connecting, when, and their addresses and peer IDs, and, to the up to three coordinators the device
keeps standing reservations with, strangers' public relays among them, its peer ID, its public
address as it changes, and when it is online; and, as a coordinator for the devices of its own
folders, only that two peers of one of its folders connect to each other, and when, with the one
residual above. It never shows contents, names or keys, and sends no folder ID to anyone who has not
proven a key to the folder; and it never makes the device a relay, a DHT server or a coordinator for
strangers, so the device carries no one else's file data.

**To a sealed peer** (stated in full; the owner's decision of 2026-10-25, "sealed peers see almost
nothing"). Everything a relay sees, and: the folder ID and verification key (its key carries both);
device IDs from the handshake and self-chosen device names from the first Status once the folder
opens; the tier each peer it connects to reports; and, of the index, only what the owner's decision
of 2026-10-25 ("sealed peers see almost nothing") leaves in the clear (`protocol.md` §4.4):

- each record's **file ID** (its keyed path tag), so the number of files and how often each changes;
- the **fingerprints** of the versions each record replaces, so each file's branch and merge shape:
  where its history forked into concurrent versions and joined again, and, when it missed versions,
  roughly how many;
- each record's **chunk IDs with their padded sizes**, so the size of each version about as closely
  as Padmé shows its chunks', to within about 3 % for chunks from 64 KiB, 6 % from 256 bytes and
  12 % below that (`keys.md` §3.3), which chunks are identical across files and versions (convergent
  encryption, the cost of letting sealed peers verify and deduplicate), and from that a copy, or a
  rename (a new file ID with the chunks of a file just replaced at another); and, for a file the
  sealed peer already has a copy of, a test of whether it is in the folder from the sequence of
  chunk lengths: from phase 1 chunk boundaries come from a gear table keyed from the data key, which
  stops the plain test, but published attacks recover such keys from the chunk lengths of files an
  attacker knows or chose (Alexeev, Percival and Zhang 2025; Truong, Merz, Scarlata, Günther and
  Paterson 2025), after which the test works again in that folder (`keys.md` §3.2); phase 0's
  fixed-size chunks show only each version's size;
- that a record with no chunks is a deletion, a tree delete, a directory or an empty file, without
  telling which;
- the **size class of each sealed part**: it is padded to the least power of two of at least 256
  bytes that holds it (the coordinator's ruling of 2026-10-25, for the owner's review), so it says
  only whether the path, the plaintext hashes of the chunks and the vector together fit 256, 512,
  1 024 or 2 048 bytes or more, not how many devices wrote the file nor how long its path is, beyond
  those classes;
- **cleanups**: which records went together at a deletion or a cleanup, and so, for a deleted
  directory, how many files it held; from a group with an empty `because` (case (c)), which names
  only records a watermark has expired, that the index records it names were deletions, tombstones
  or tree deletes, dated below a watermark (not that a write holder held them a year: a watermark
  also passes deletions its signer never held), and, since a group's `because` whose named records
  lie at other file IDs can only be a tree delete, which records are tree deletes (the
  coordinator's ruling of 2026-10-26, for the owner's review); and, from a cleanup with no group
  (case (d)), which carries only a watermark, when a write holder signed one, and so, when that
  write holder's clock is right, that some deletion or cleanup had reached it at least a year before
  (the spec author's choice of case (d), for the owner's review; the watermark itself is sealed);
- **arrival**: when each record arrives and from which peer, which usually shows which device wrote
  it (a new record reaches it first from its writer or a peer close to it), and so the rate and
  times of activity;
- the number of index records; the Status message every peer sends for each open folder (its extra
  versions beyond one per file ID, records held, a running count of chunks stored, ciphertext bytes
  still to fetch, whether it is paused, free disk space); which chunks each device holds, since any
  peer with the folder open may ask for any chunk and a device answers `CHUNK_OK` exactly for the
  chunks it holds for the folder (it has the blob and a record naming it, `protocol.md` §4.6) and
  `CHUNK_NOT_FOUND` for the rest, so on a device using selective sync or "free up space" this shows
  which files it keeps locally (by ciphertext hash; a key holder can name them); the approximate
  total size of the folder.

Not the path, a directory's contents, the kind, the true size, any time stamp, the mode, plaintext
hashes, `written_at`, the device ID, counter or vector inside a record, nor whether a record is a
tombstone, short of the old deletions a cleanup group with an empty `because` names and the tree
deletes that cleanup groups are issued `because` of: those sit in the sealed part, padded to a power
of two. Padmé padding blurs each chunk's size, which still shows to within about 3% from 64 KiB, 6%
from 256 bytes and 12% below that (`keys.md` §3.3); it does not hide the number of chunks, the
total volume, or when changes happen. A sealed peer can also show a stale snapshot to a peer that
has no persisted state yet for a path, such as one on its first sync; the regression is found
when that peer meets a fresher one (TM-17). And it can bring back, whenever
it likes, a file whose deletion a watermark has forgotten, a year or more after a write holder
received it (sooner where that write holder's clock is wrong, TM-40), even at a path re-created
since, as a conflict copy; keep and replay stale copies,
which write holders then name; and take away again from another sealed peer, by replaying a genuine
old deletion, a version that came back after that deletion was forgotten, until a write holder meets
that peer (§3.3; `protocol.md` §4.4). Compression inside the encrypted chunk, when a writer enables
it, is a CRIME-style length channel: where bytes an attacker can influence share a chunk with
secrets, the padded size reveals how well they compressed together. Padmé blunts it (2 KiB
granularity at 64 KiB, 128 KiB at 4 MiB) but does not remove it; phase 0 uses no compression, and
the release that enables one states this channel on the site before it ships (TM-15).

**To a key holder.** A write or read key holder sees everything in the folder, every other peer's
device ID, name and reported tier (shown marked "reported", like the name), and, through chunk
requests, which files each device keeps locally. Inside every record's seal it reads the dot, the
vector and `written_at`: which device ID wrote each version (as the signer claims it) and when, to
the microsecond, as the writer's clock read it (`written_at`) and, about as closely, from the
counter, which follows the writer's clock unless carried forward past it, offline edits included;
and, from each cleanup's watermark, roughly when deletions were forgotten (the owner's
decision of 2026-10-25, "Make sure this is documented - do not hide this detail"; microseconds
rather than minutes because "I can work on files in multiple locations nearly simultaneously and the
per-minute version resolution is not accurate enough"); which devices wrote the file before; and the
deletion marks, sizes, times and modes. Holders of one tier look alike: nothing in the folder says
which person holds which key or made which change. A key holder with the chunk-hash key can test
whether a guessed file is in the folder: keyed hashes stop outsiders, not members.

**To a corporate proxy on a locked-down network.** The hostname dialled, timing and volume; the Noise
handshake runs inside the WebSocket, so a proxy that terminates the outer TLS sees encrypted frames.

**To a future quantum computer with recorded traffic.** The transport's X25519 share where a path used
Noise or a classical TLS group, and therefore the contents of that transport session: handshake
identities, Hello contents, folder proofs, record envelopes, chunk ciphertext. That includes every
WebSocket session, and so any session an attacker forced onto that path by blocking UDP and raw TCP
(section 3.1): as `libp2p-websocket` ships, its outer TLS is rustls on `ring` and the Noise inside is
classical, so both layers fall (`suites.md`, transport, records the deviation and the phase 2 change
that gives the outer TLS the post-quantum group). It also includes a relay's or a coordinator's
circuit with a browser client at one end, whose end-to-end channel is Noise, classical, so a relay
that records one could later read in it the folder ID that TM-25 keeps from it today; between two
native ends a circuit runs TLS 1.3 with X25519MLKEM768 first (TM-1, `suites.md`, transport), whose
recording a quantum computer does not open. Content, names and structure are encrypted under the
folder's symmetric keys before transport, and no folder key crosses a transport session in the
protocol, so the recovered session reveals what a sealed peer sees, less the verification key, and
nothing more. A quantum computer that can break Ed25519 is a forger, not a reader (TM-33).

## 6. How to use this document

For the author of a change: cite the requirement your change satisfies or depends on in the code
comment and the test name, and list the numbers in the changelog entry. Never cite a retired number
(TM-16, TM-19, TM-34, TM-36, TM-38) for new work; a test or comment that cites one is removed or
re-cited in the change that touches it. If your change needs a rule this file lacks, propose the new
TM number in your report; do not add it yourself.

For the two reviewers of every change: section 4 is the checklist for the "security" line of the
review. Read the requirements whose enforcing crate or reviewed-in layer your diff touches, and
confirm each is still true after the change, with a test that would fail if it were not.

For the security-reviewer pass (every change touching `keys`, `protocol`, file paths or the local
API, and every phase gate): work from sections 3 and 4 together. For each adversary in section 3
whose "Can" list the change could widen or whose "Cannot" list it could weaken, name the TM numbers
that carry the promise and check the change against each. The pass ends with a plain-language summary
for the owner: what the change does, what it risks, how to try it by hand. A finding blocks the
commit until it is fixed and re-reviewed, or the reviewer agrees it is not one; "the plan says so" is
not a defence against a finding, it is a reason to raise the conflict.

For every phase gate: the gate's reviewer walks every live requirement (TM-1 to TM-43 less the five
retired) against the code that exists and records, per requirement, enforced, partly enforced (with
what is missing) or not yet applicable (with the phase that will make it so).

## Appendix: incidents and sources cited

Read on 2026-10-14 for the plan's hardening review; the plan's Sources section holds the full list.

- Nextcloud 2024 (key insertion, ghost key): Albrecht et al., "Breaking Nextcloud End-to-End
  Encryption", https://eprint.iacr.org/2024/546.pdf
- pCloud, Icedrive, Seafile and others 2024: Albrecht and Backendal, "End-to-End Encrypted Cloud
  Storage in the Wild", https://eprint.iacr.org/2024/1616.pdf
- MEGA 2022: Backendal, Haller and Paterson, https://mega-awry.io/
- Tahoe-LAFS known issues: https://tahoe-lafs.readthedocs.io/en/stable/known_issues.html
- Harnik, Pinkas and Shulman-Peleg 2010, "Side Channels in Cloud Services: Deduplication in Cloud
  Storage", https://www.pinkas.net/PAPERS/hps.pdf
- PURBs 2019: Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with
  PURBs", https://www.petsymposium.org/popets/2019/popets-2019-0056.pdf
- Kleppmann 2022, "Making CRDTs Byzantine Fault Tolerant" (PaPoC 2022),
  https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf
- Read on 2026-10-25 for the index (`protocol.md` §4.4, §4.5): Syncthing's Block Exchange Protocol
  v1 (index ID and maximum sequence, version vectors), https://docs.syncthing.net/specs/bep-v1.html,
  and its `Vector.Update` and `Vector.Compare`,
  https://github.com/syncthing/syncthing/blob/main/lib/protocol/vector.go; Preguiça, Baquero,
  Almeida, Fonte and Gonçalves 2010, "Dotted Version Vectors: Logical Clocks for Optimistic
  Replication", https://arxiv.org/abs/1011.5808, and Riak's recommendation of them from release 2.0,
  https://docs.riak.com/riak/kv/latest/learn/concepts/causal-context/index.html; Sheehy 2010, "Why
  Vector Clocks Are Hard" (pruning costs a false merge, never quiet loss),
  https://riak.com/posts/technical/why-vector-clocks-are-hard/; Almeida, Baquero and Fonte 2008,
  "Interval Tree Clocks: A Logical Clock for Dynamic Systems",
  https://gsd.di.uminho.pt/members/cbm/ps/itc2008.pdf; and Lamport 1978, "Time, Clocks, and the
  Ordering of Events in a Distributed System" (Communications of the ACM 21(7))
- Keyed content-defined chunking: Xia et al. 2016, "FastCDC: a Fast and Efficient Content-Defined
  Chunking Approach for Data Deduplication" (USENIX ATC 2016); Alexeev, Percival and Zhang 2025,
  "Chunking Attacks on File Backup Services using Content-Defined Chunking",
  https://eprint.iacr.org/2025/532, and Truong, Merz, Scarlata, Günther and Paterson 2025, "Breaking
  and Fixing Content-Defined Chunking", https://eprint.iacr.org/2025/558 (both read on 2026-10-25)
- Syncthing advisories (CVE-2017-1000420 versioning traversal; CVE-2022-46165 HTML in device names;
  0.12.23 update handling; 1.28.0 untrusted regression):
  https://github.com/syncthing/syncthing/security/advisories; untrusted-device spec:
  https://docs.syncthing.net/specs/untrusted.html; relay spec:
  https://docs.syncthing.net/users/strelaysrv.html
- BitTorrent Sync analysis 2014 (Hackito Ergo Sum):
  https://2014.hackitoergosum.org/bittorrentsync-security-privacy-analysis-hackito-session-results/
- Dorsey 2018, DNS rebinding against local services (Google Home, Sonos, Roku, Radio Thermostat):
  https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325
- libp2p resource exhaustion 2022: https://github.com/libp2p/rust-libp2p/security/advisories and the
  go-libp2p advisories of the same year; rendezvous 2026 and the QUIC handshake panic 2026 are in the
  same list
- Mainline DHT: Wang and Kangasharju, "Real-world Sybil attacks in BitTorrent Mainline DHT",
  https://www.cl.cam.ac.uk/~lw525/publications/security.pdf; BEP 42,
  https://bittorrent.org/beps/bep_0042.html; Adamsky et al. 2015, "P2P File-Sharing in Hell:
  Exploiting BitTorrent Vulnerabilities to Launch Distributed Reflective DoS Attacks",
  https://www.usenix.org/system/files/conference/woot15/woot15-paper-adamsky.pdf
- UPnProxy 2022 (Akamai) and CallStranger 2020 (CVE-2020-12695): router port mapping abuse
- libp2p circuit relay v2: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
- Tauri 2 security documentation: isolation pattern, capabilities, CSP
- W3C Subresource Integrity; Meta's Code Verify; WEBCAT (Freedom of the Press Foundation): what SRI
  cannot do against a page's own host, and how an extension can
- Seafile 2024 protocol version downgrade: in Albrecht and Backendal above
- FREAK, Logjam, POODLE: cipher-suite negotiation failures that TLS 1.3 answered by shrinking the
  menu
