# Lickety-Sync threat model

Version 2, 2026-10-22 (version 1, 2026-10-14, described the issued-keys model), revised the same day
for the coordinator's rulings R-K6 and S-1 to S-4 and the owner's second set of answers. This file is
normative for every crate in this workspace, for the apps in `app/` and for the browser client in
`web/`. Its companions are `suites.md` (algorithms and approved crates), `keys.md` (folder keys,
derivations, records, key strings) and `protocol.md` (wire protocol). The plan, "Lickety-Sync:
Project Plan", is the source these files are written from; where this file is silent the plan
decides, and where they disagree the disagreement is raised, never quietly resolved.

Every requirement below has a number, TM-1 to TM-42. Five of them, TM-16, TM-19, TM-34, TM-36 and
TM-38, are **retired** (2026-10-22): they existed only for issued keys, revocation and defences
against an insider who equivocates, and their numbers stay with a note so that an old citation is
never read as a new rule; TM-41 and TM-42 are new. Code comments, test names, changelog entries and
review reports cite them (`// TM-4`, `fn tm_4_symlink_then_directory()`). Section 6 says how a
reviewer uses them.

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
and its limits; the **index** is the folder's set of signed **records**, each naming the device ID
its signer claims, a sequence number for that device and the record hashes of the versions it
replaces (`supersedes`); a **chunk** is a content-defined piece of
a file; a **sealed peer** holds ciphertext it cannot open; a browser in **vault mode** is a sealed
peer that stores ciphertext in the browser's own storage; a **relay** forwards ciphertext for peers
that cannot reach each other; **peer exchange** is peers telling each other the addresses of peers
they share a folder with; the **archive** keeps replaced and deleted files (Trash can, 30 days by
default); the **deletion brake** pauses a folder and announces no deletions when more than a
threshold of its files vanish at once from a device's own disk, until the person confirms; it never
holds back deletions that arrive from peers (TM-35); **unlinking** a folder removes it from a device
and keeps its files and its archive; **sharing again** makes a new folder over existing
files (`keys.md` §7); a **parcel link** is the plan's one-time "send one file to someone" invite,
which carries addresses because the recipient may share no peer with the sender.

## 1. What we protect (assets)

The program exists to copy people's files between devices without any party in the middle being
able to read, alter or withhold them. What must be protected is the files themselves, everything
that describes them, and the keys that open them. Some facts cannot be hidden by a peer-to-peer
design and are listed as leaks in section 5 rather than promised away.

| Asset | What it is | Who may learn it | Confidentiality, integrity, availability |
| --- | --- | --- | --- |
| File contents | The bytes of every file in a folder | Write and read key holders | All three; availability is what sync is for |
| Names and structure | Paths, tree shape, true sizes, modification times, modes, symlink targets | Write and read key holders | All three |
| The index | Per folder: each path with size, time, mode, the versions it replaces, chunk list and deletion marker, as records signed by the folder key | Write and read key holders decrypt it; sealed peers carry it opaque | Integrity against everyone without the write key; confidentiality against sealed peers and relays. Write holders are trusted with it |
| Write key | The write secret, and so the signing key and every other key of the folder | Write key holders | Disclosure is full control of the folder for as long as it exists: nothing revokes it, and the remedy is sharing again (TM-42) |
| Read key | The verification key and the data key | Write and read key holders | Disclosure is permanent reading of the folder, past and future |
| Sealed key | The verification key and the access key | Holders of every tier | Disclosure lets a party join as a sealed peer: hold, verify and serve ciphertext, and see what section 5 lists for sealed peers |
| Device identity | Device key pair; device ID = hash of its public key | Public to anyone who completes a connection: the DeviceProof proves the key and ID before any folder is named, and the Hello carries the lists (section 5); the name is sent only after a folder has opened on the connection, so only a peer that has opened a folder with the device learns its name | Integrity: a device cannot claim another's ID at the handshake |
| Local key store | The device seed and one key per folder the device holds | That device | Confidentiality: its theft is the theft of every key in it (section 3.4) |
| Catalogue (phase 5) | Which folders a person's linked devices hold, and at which tiers | Those linked devices | Confidentiality against everyone else |
| Local API token | Authenticates the CLI and web UI to the service | The local user | Confidentiality against other local users and web pages |
| Metadata that leaks | Padded sizes, chunk counts, record counts and rates, timing, the salted folder and announcer hashes on the LAN, the daily discovery hash and the stable identifiers a device publishes with it on the DHT, that two addresses talk, device IDs and names, and to whoever completes a connection the libp2p peer ID, the protocols it offers in multistream-select, the device key, the suite, compression, hash and feature lists and limits, and a coarse count of the folders it holds (proof-result timing) | Sealed peers, relays, network observers, as section 5 states | Not protected; documented |

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
| Relays: private, public, volunteer | Both endpoints' addresses, timing, volume, the folder a reservation names | Nothing; carries end-to-end ciphertext only | Another person's device, chosen per folder; off by default except own-device relays |
| The LAN | Beacons (salted folder hashes, salted announcer hash, port), multicast, every unencrypted byte | Nothing: a café network is the model | The network interface |
| The internet | Addresses, timing, volume, QUIC and TLS handshakes | Nothing | Same |
| The Mainline DHT | Daily discovery hashes with the addresses announcing them; signed address records (BEP 44) under a stable per-device key | Nothing; off by default, and seeing a peer grants no access | UDP to strangers; client mode by default |
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
which approximate padded chunk sizes and counts; see that a device runs Lickety-Sync and its port;
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
device's one port for a bounded lease (TM-26).

Cannot: read contents, names, index records, keys or key material; learn the folder ID, a device's
identity key or any key from the hashes, or link two beacons to one folder or to one device from the
beacons' contents without the ID or the key (the source address links beacons from one interface,
which no hashing hides); join a folder, open a folder proof, or learn whether a device holds a
folder, by knowing its ID (TM-32); downgrade the transport to plaintext (TM-1), or from TLS to Noise
on one transport, because each transport offers exactly one security protocol (`suites.md`,
transport): blocking can force the choice of transport, never of the protocol within one, and the
WebSocket path it can force a dialer onto is still encrypted and authenticated (TM-1); downgrade
the suite (TM-30); open recorded traffic later with a quantum computer beyond what a sealed peer
sees, because content is encrypted under the folder's symmetric keys before it leaves the device and
no folder key ever travels inside the protocol (TM-33, section 5); link one day's DHT announcements
to the next without the folder ID, a stable address or a stable published identifier (TM-24);
impersonate a peer, because peers authenticate by key, not address (TM-32).

### 3.2 A peer holding a valid key

A device that holds one of the folder's three keys. Holding a key is the access: there is no owner,
no per-person key and no record of who changed what (owner's decision, 2026-10-18), so what a holder
can do is exactly its tier's purpose, and every holder of one tier is indistinguishable from every
other. This is the design, as in Resilio Sync, and it is stated plainly here.

**Write key.** Can: read and change files, names and structure; delete everything; give out any of
the three keys, to anyone, any number of times; sign records under any device ID, its own or
another's, which every peer keeps as concurrent versions (TM-41), and name any versions in a
record's `supersedes`, so that its version of a path replaces them; sign under any number of new
device IDs, which makes every peer store, list and compare that many writers (section 3.6); see
every other peer's device ID and name; act without being identified, since a record names only a
device ID its signer chooses and nothing shows it as an author. Cannot: be removed, except by the
people who stay unlinking the folder and sharing it again by hand, after which it keeps the old
folder and everything it held (TM-42); make honest peers that meet disagree about which records
exist (TM-41); make a peer with persisted state go backwards (TM-17); destroy a file beyond the
reach of the archive on a device whose versioning is on (TM-35). Its destructive power over content
is real and unlimited in scope: deletions it sends are applied without a brake (the owner's answer
of 2026-10-22), and the archive (Trash can, 30 days by default) limits how much is lost for good,
not what it can do.

**Read key.** Can: read everything, for as long as the folder exists (no key expires and nothing
revokes one); give out read and sealed keys. Cannot: change anything, because every peer rejects a
record the folder key did not sign (TM-9); forge; derive the write key or the signing key (`keys.md`
§1.2); raise its tier.

**Sealed key.** Can: hold a complete copy, verify ciphertext against the hashes the signed records
name, serve it, relay for others, give out sealed keys. Cannot: read contents, names or structure;
see plaintext chunk hashes; test whether the folder holds a known file (TM-14); sign; do anything in
3.3.

### 3.3 A sealed peer or a relay

A storage or forwarding party that handles ciphertext only. Every cloud break the plan's hardening
review cites (Nextcloud 2024, MEGA 2022, pCloud, Icedrive and Seafile 2024) relied on a storage
party that the client trusted too much. Here the storage party is untrusted by construction.

Can: see sizes after padding, chunk counts, record counts, the rate of change, timing, device IDs
and names, folder IDs, and which record replaces which (`supersedes`); ask any peer for any chunk
by its ciphertext hash; tell that two chunks are identical
(convergent encryption, section 5); withhold data, go offline, or serve slowly; store far more than
asked.

Cannot: insert or replace key material and have a client re-encrypt under it, because no key travels
inside a folder and every record is verified under the folder key (TM-9, Nextcloud key insertion);
cause a client to fall back to a default or empty key (TM-10, Nextcloud ghost key); use anything as a
key-wrapping oracle, because nothing is wrapped and every purpose key has its own derivation label
(TM-11, MEGA); provoke a nonce reuse by making a client re-encrypt, because chunk nonces are
content-derived and every other nonce is random (TM-12); drop, reorder, duplicate or substitute
chunks within a file unnoticed, because the file record signs its full chunk list and each chunk is
verified against it (TM-13); forge or alter a record (TM-9); serve an older snapshot as current to a
peer that has persisted newer records, because a peer never moves backwards on another peer's say-so
(TM-17): a peer with no persisted state for a writer, as on a first sync, accepts what it is shown,
syncing from more than one peer narrows that window, and the stale or withheld copy is found the
moment a fresher peer is met (TM-41); make two peers that meet hold different records (TM-41); learn
names, since names and structure are inside the encrypted index (TM-33); learn whether a known file
is in the folder: plaintext chunk hashes are keyed per folder, and the ciphertext hash of a guessed
file needs the data key to compute, so a sealed peer cannot even name the chunk it would ask about,
and its requests for hashes it took from the signed records confirm nothing it did not know (TM-14). A relay that holds no
key to the folder also cannot open a folder proof or tell which folder a connection proves (TM-32).

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

Can: make any change, including destroying everything, which the archive limits only in how much
is lost for good: deletions that arrive from peers are applied without a brake (the owner's answer
of 2026-10-22), and the archive keeps every file they removed, 30 days by default, on each device
whose versioning is on (TM-35); sign two different records under one device ID and sequence number,
or records under another device's ID, which every peer keeps and applies as concurrent versions,
never as evidence against anyone (TM-41); name any versions in a record's `supersedes`, so that its
version of a path replaces them, the replaced versions going to the archive, or name a version no
peer holds, which leaves that record waiting for good and applied nowhere (`protocol.md` §4.4);
**make peers track many writers**: sign under any number of device IDs, so that every peer stores,
lists and compares that many writers, with storage, the number of requests in a round and the time a
round takes growing with them, though no message and no per-connection table does (ruling R-K4;
there is no cap on writers, owner answer 4 of 2026-10-22; `protocol.md` §4.5, TM-22); **make peers
recompute and resend**: a concurrent version signed low in a writer's history makes every peer
recompute that writer's cached digests from that sequence number up, and every pair of peers whose
digests then differ resend that writer's whole history to each other once, so C such records against
a history of n records cost each peer about C·n digest steps and each pair C full resends: time and
bandwidth, never per-connection memory (ruling DIGEST, accepted because write holders are trusted;
`protocol.md` §4.5, TM-22); write names that are not in Unicode NFC, which readers do not check and
which are then paths distinct from their NFC forms (`protocol.md` §4.4); flood with records and
chunks; give the write key to anyone; act without
being identified, since records name only a device ID their signer chooses, never shown as an
author, and nothing records who changed what (the owner's decision, 2026-10-18).

Cannot: be removed except by the others unlinking and sharing again by hand (TM-42); make honest peers
that meet hold different records, because cursor digests find every difference and the exchange
sends what each side lacks (TM-41, Kleppmann 2022); roll back a peer that has persisted newer records
(TM-17; a peer with no persisted state for the writer accepts what it is shown until it meets a
fresher peer); have a record accepted without the folder key's signature; slip a seal or a chunk past
a reader's checks without an issue that names the record (TM-10); destroy a file beyond the archive's
reach on a device whose versioning is on (TM-35).

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

Can: see which addresses announce a given day's discovery hash, if they know the folder ID, and the
stable identifiers each announcing device publishes (the BEP 44 key its address record is signed
with, its DHT node ID; the record carries no libp2p peer ID, the DeviceProof binds identity at the
handshake instead); serve an old signed address record to a reader that holds no newer one, which is
harmless because the address is only a dial hint and the handshake decides the rest; eclipse a
device so that its lookups return only the attacker's nodes, denying discovery through the DHT;
enumerate announcing addresses by crawling.

Cannot: turn a discovery hash back into the folder ID or any key; gain access to a folder by seeing
or impersonating its peers, since access needs a key (TM-32); link a folder's announcements across
days from the hashes alone, since the hash rotates daily (TM-24), though anyone who ever held the
folder ID (a sealed peer, a relay, anyone who saw a key string) can compute every day's hash, and a
device is linkable across days by a stable address or by a stable identifier it publishes with the
announcement (BEP 44 key, persisted node ID); use the device as a `get_peers` amplifier or exhaust it,
since the DHT runs in client mode unless the person turns on server mode, which adds a per-source
rate limit and bounded responses (TM-24, Adamsky 2015); replay an old BEP 44 address record over a
newer one a reader already holds, since the sequence number is persisted and never reused (TM-24);
affect anyone who has not turned the DHT on (it is off by default). Eclipse denies one discovery
method; LAN, direct addresses, own-device relays and peer exchange remain.

### 3.10 A resource-exhaustion attacker

Someone who opens connections, streams, reservations or registrations faster than a device can serve
them, or sends messages whose declared lengths would make the device allocate unbounded memory.

Can: send any number of connection attempts, handshakes, Hello messages, folder proofs, chunk
requests and relay reservations; declare absurd lengths; send malformed input to every decoder.

Cannot: make the device allocate before a length limit is checked (TM-2); grow any per-peer table
without bound, because every table is bounded, none grows with the number of writers in a folder, and
each dies with its connection (TM-22, go-libp2p and rust-libp2p 2022); make the device verify anything
for a folder proof without holding a key to the folder (TM-22); make it verify a record's signature
except to store a record it lacked or to close the connection (TM-22); hold unlimited relay circuits or
reserve a relay through a relayed connection (TM-25); amplify through QUIC, whose three-to-one
anti-amplification limit stays at its default (TM-22), or through the DHT (TM-24). A panic on
malformed input is made unlikely and caught before merge rather than made impossible: every decoder is
fuzzed, `unwrap`, `expect` and `panic` are denied, and indexing on untrusted data warns and the gate
treats warnings as errors (TM-3, TM-23, rust-libp2p 2026 QUIC panic). Denial of service by sheer
traffic volume is out of scope (3.12); a write holder's flood is section 3.6's.

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
  withhold records, as an older backup would. The device fetches them again from its peers, with
  these stated residuals: a record that no peer holds stays missing, and the records of its writer
  above it, whatever the writer, stay set aside, intact, and reported at every open until a record
  at that `seq` is held; withholding this device's own records makes it reuse their sequence
  numbers, which peers keep as concurrent versions, as after a restored backup (`protocol.md` §4.5,
  "Durability before transmission"), and its records set aside above land once it writes at the gap;
  and records of any writer that only this device held are lost. **The key store** stays trusted,
  since whatever can change it can replace the folder's keys.
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
and WebRTC), so nothing weaker can be negotiated before authentication either. What this does not
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
scheme or random generator whose output reaches a key, a nonce, an identifier or any byte a peer sees
is written in this workspace; every algorithm and crate is the one `suites.md` lists, at the version
range it pins, and nothing not listed is used until a reviewed change adds it. The one padding
scheme written here is Padmé, in `keys`, which `suites.md` lists as written here because no approved
crate provides it (`suites.md`, data encryption). The one generator written here is the simulator's
seeded statistical one (SplitMix64 in the `sim` crate), which feeds
the runtime's randomness trait in simulator runs only, so secrets, nonces and salts in a simulated
run come from it; it is not cryptography, `sim` is never a dependency of `daemon`, `cli` or `decrypt`
(reviewed on every `Cargo.toml` change), and no production build contains it, so this rule permits
both and says so (`suites.md`, randomness). Stops the class of flaw that hand-written combiners and
wrappers introduced in MEGA 2022 and Nextcloud 2024. Enforced by `deny.toml` bans and cargo-vet;
reviewed in every change that touches `keys`, `protocol` or `engine`.

**TM-6. Secrets live in zeroized types and never reach logs.** Write secrets, data keys, access keys
and every key derived from them, signing keys, device seeds, store keys, passphrases and session
keys are held in types that zeroize on drop, whose `Debug` output is redacted, and that are never
formatted into a log, error message or panic payload; logs redact folder IDs and addresses by
default. Stops secrets leaking through crash reports, log files and debugging output, which is how
the Tahoe-LAFS and BitTorrent Sync analyses found capability strings in the clear. Enforced by `keys`
(types) and `daemon` (logging); the rules are in `suites.md` section 4.

**TM-7. No `unsafe` outside the platform-FFI crates.** The workspace lint `unsafe_code = "forbid"`
applies everywhere; a platform-FFI crate opts out explicitly and is covered by Miri nightly;
cargo-geiger's count is a report that CI publishes and reviewers read, and `ci/geiger.sh` (CI and
`gate.sh`) fails when any of a crate's five used unsafe counts (functions, expressions, impls,
traits, methods) differs from `ci/geiger-baseline.txt`, so every change in the unsafe code the build
uses lands with a reviewed change to that file. Stops memory-safety bugs reachable from untrusted
input. Enforced by `core/Cargo.toml` (the lint), `ci/geiger.sh` (the counts) and review (each change
to them).

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
(an exact duplicate of a record already held, and a gap on a push, are ignored unverified, since
nothing of them is stored); read and sealed holders cannot sign, so every peer rejects a change they
make. Nothing a peer sends can add, replace or change a folder's keys, because no record carries key
material: keys move only as key strings outside the protocol and, between a person's linked devices,
over an authenticated channel (`keys.md` §8.3); a record handed over by a sealed peer or relay is
data to be verified, never a reason to act. A device's own index store, and any backup of it
restored into it, is trusted to keep its records but not for their authenticity (the owner's
decision of 2026-10-25): a record is verified before it is stored and again every time its folder
opens, when every stored record gets step 1 against the folder and its signature under the folder's
verification key, at every tier, the signatures spread across the processor's cores (`protocol.md`
§4.4, "Opening a folder"); the engine (when it lands) shows the folder as Checking meanwhile. A
record that fails, because it was corrupted or edited at rest or is not this folder's, is dropped:
it is not applied, counted in a cursor or digest, or served, and the open reports it by record hash,
so that the engine's folder state shows the problem and an issue (when the engine lands) gives the
count and names at most 16 of the records by hash (`protocol.md` §5). The records of its writer
above the gap it leaves, as above a record the store lost, are set aside: kept but not held,
reported, and landed without a second append once every gap below them is filled. The cursors and
digests are rebuilt from the records held, so index sync fetches every genuine record dropped or
missing again from the peers that hold it. A store changed at rest can therefore at worst lose or
withhold records, with the residuals section 3.12 states; it can no longer make the device apply a
change no write holder signed, serve records its peers refuse as forged, or count a junk record in a
writer's digest. The check costs one Ed25519 verification per stored record: opening 100 000 records
of 100 writers took 5.6 to 6.1 s on one thread and 2.5 to 3.3 s on all eight threads of a four-core
laptop processor, against 0.5 to 0.8 s without the check (release build, measured 2026-10-25 on a
machine shared with other builds, whose clock moved between 1.3 and 2.5 GHz, so the figures are
ranges). A labelled keyed checksum per stored record, which would need a per-device secret, be
forgeable by anything that reads it and be lost on reinstall, is adopted instead only if
measurements on a phone or NAS show start-up too slow. The key store remains trusted (section 3.12).
Stops key insertion, where a storage party introduces or replaces key material and the client
re-encrypts everything under it (Nextcloud 2024, Albrecht et al.), and forged changes, including
changes written into a device's own index store at rest. Enforced by `keys` (signing and
verification) and `index` (verifies before storing and again when the folder opens); `engine`
applies only stored records and, when it lands, shows the folder as Checking while its index opens.

**TM-10. Fail closed.** Any decryption failure, signature failure, hash mismatch or malformed record
that arrives on a connection ends in exactly one of three outcomes, none of them silent. The
connection that delivered it is closed, with an issue naming the peer and the cause, for what only
the sender can be blamed for: bytes that do not parse or do not verify, a broken order or bound. The
item is set aside and the connection kept for differences in what two peers hold (a gap, a
duplicate, a record waiting for a version it names, a proof for a folder that is not here, a chunk
the holder lacks), which the exchange then repairs. An issue names the record (by hash, and by path
where its seal opened; never a device, since nothing proves which device wrote it, ruling S-4), the
record is kept opaque or the chunk marked corrupt, applied by no one, and the connection kept, for a
failure inside what the folder key signed (a seal that will not open, a chunk that fails its
plaintext hash), because the body is what a write holder signed and the sender, perhaps an honest
relay, merely carried it. A record in the device's own index store that fails step 1 or its
signature when its folder opens involves no connection: it is dropped and reported, never applied or
served, and the records of its writer above it are set aside (TM-9; `protocol.md` §5, "Stored record
fails its check"). One refusal is deliberately uninformative: a folder proof that fails for any
reason gets the same uniform REJECTED and the connection is kept, so that a probe learns nothing
about which folders a device holds. Nothing is skipped, defaulted or retried with weaker checks, and
no key has a default value; `protocol.md`'s rules table is the complete record of which cause has
which outcome (decision 2026-10-15: refines the plan's "drops the connection": a failure inside a
validly signed body keeps the connection, because the sender may be an honest relay). Stops the
"ghost key", where a missing key became an all-zero default and failures were skipped silently
(Nextcloud 2024). Enforced by `keys`, `protocol`, `index` and `engine`: every verifying function
returns a typed error and every caller propagates it to the connection; `clippy::unwrap_used` and
`expect_used` are denied.

**TM-11. Every purpose key has its own label, and associated data binds every ciphertext to its
place.** Every symmetric key, nonce key, chunk-hash key, handshake hint and payload key and signing
seed is derived from its parent with BLAKE3 `derive_key` under a distinct label registered in
`keys.md`, so no key serves two protocols and no key is used raw for two purposes (the access key
only parents the two handshake keys); chunk ciphertext is bound to its folder (its associated data is the folder ID), sealed
metadata to its folder, device ID and sequence number, and the handshake payload to its hint, so a
ciphertext cannot be moved to another folder, record or connection; and no key is ever wrapped to a
public key, so there is no wrapping oracle. Stops one key reused across protocols and ciphertext
moved between contexts (MEGA 2022, mega-awry.io). Enforced by `keys`; the labels are in `suites.md`
section 2.4 and `keys.md`'s label registry, their test vectors in `suites.md` section 4.4.

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
chunk hash is a fingerprint only to read and write holders; sealed peers and relays see hashes of
ciphertext only; and a "do you have this chunk" query is answered only on a connection where the
folder is open, which takes a proof of a key to it. Stops confirmation-of-a-file through content
hashes and deduplication used as an oracle (Tahoe-LAFS known issues; Harnik, Pinkas and
Shulman-Peleg 2010; Syncthing 1.28.0 regression). Enforced by `keys` (`plain_hash`, `cipher_hash`),
`engine` (never hashes plaintext another way) and `protocol` (have-queries are folder-scoped). What
makes "never another way" hold is cargo-deny: `deny.toml` lets only `licketysync-keys` depend on
`blake3` and on `chacha20poly1305`. `protocol` and `index` reach hashes only through `keys`, and
`protocol` never sees plaintext. In `keys` and `protocol`, a Semgrep tripwire in
`.semgrep/project.yml` flags every call into and every import of `blake3` outside `keys`'s labels
module, which it excludes by path, outside test files, and outside a `mod tests`, with its cases in
`.semgrep/tests/` run by CI; it catches mistakes, not intent (`suites.md`, hashing).

**TM-15. Padmé padding of chunk sizes; the volume and timing leak is documented, not claimed away.**
Every chunk is padded by the Padmé rule (at most 12% overhead, 3% on average) before encryption, so
that sizes fingerprint less; what padding does not hide is listed in section 5 and on the site,
including the CRIME-style length channel that compression before encryption opens when
attacker-influenced bytes share a chunk with secrets: phase 0 compresses nothing, and a release that
enables a compression states the channel first. Stops size fingerprinting, where 45% of user files
have a unique size (PURBs, Nikitin et al. 2019). Enforced by `keys` (`padme` and the chunk layout)
and `engine` (FastCDC's maximum chunk is at most `MAX_CHUNK_PLAINTEXT`).

**TM-16. Retired 2026-10-22.** Was "Records name their predecessors; equivocation is flagged", with
per-key device admission. With one shared write key whose holders are all trusted, two records of
one device at one sequence number are concurrent versions, kept and applied, never evidence against
anyone (ruling R-K5); TM-41 states what holds instead. Per-key device admission (rulings 33 and 34)
went with per-person keys.

**TM-17. Peers persist what they have seen and refuse regressions.** Each peer stores, per folder
and per writer, every record it has accepted and its cursor, the highest sequence number it holds;
the cursor never decreases, short of records the device's own store loses or corrupts at rest (the
next open drops a corrupted record and sets aside those above a lost or dropped one, and index sync
fetches them again, TM-9), and no record is removed on another peer's say-so, a sealed peer's or
relay's included (tombstone expiry, which hides a path and keeps its records, is the index's own
rule). A peer that offers lower cursors is behind, and nothing is asked of it. The limit is stated:
a peer with no persisted state for a writer, as on a first sync, trusts what the first peer it meets
shows it, and a stale or withheld copy is found when a fresher peer is met (TM-41). Stops rollback,
where a store serves an older snapshot as current (Tahoe-LAFS known issues; Syncthing's
untrusted-device spec is silent on it). Enforced by `index`.

**TM-18. Invite secrets travel only after `#`, and the client origin has no landing page.** In a link
the key string sits in the fragment, which browsers never send to a server; licketysync.app serves
the client bundle and nothing else, so no page there logs, redirects or renders a link's secret; the
documentation site, on the separate registrable domain licketysync.com, links to the client and
never carries an invite; and a link that does not begin with `https://licketysync.app/join#` is
refused (`keys.md` §6.3). Stops secrets in URLs leaking through referrers, history and landing pages
(Resilio Sync 2024; BitTorrent Sync analysis 2014; Tahoe-LAFS). Enforced by `keys` (the link
parser), `web` (client) and `site` (documentation), reviewed in `app` and `cli` wherever a link is
built.

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
(pending chunks, reservations, registrations, in-flight requests, have-query state, proof hints,
marks) has a fixed maximum, counts against the Hello's agreed limits, and is dropped with its
connection; no table grows with the number of writers in a folder, since an index request lists at
most `MAX_CURSORS_PER_REQUEST` writers and a requester covers more with a round of range requests
(`protocol.md` §4.5); libp2p's connection, stream and transient connection limits are set and tested
under a flood; QUIC's three-to-one anti-amplification limit stays at its default; and the advisory
feed in CI (cargo-audit, daily) catches the next such advisory in a dependency. Stops resource
exhaustion through unbounded streams, connections and registrations, and amplification through QUIC
(go-libp2p and rust-libp2p 2022; rendezvous 2026). The stated costs: any Hello that passes its
checks costs one Ed25519 signature (the DeviceProof sent in answer) and one verification; a
FolderProof from a peer with no key to the folder costs a lookup in the connection's hint table and
nothing else, so an outsider cannot make a device verify anything; once a folder is open, each
record received costs one BLAKE3 hash of its body, and an exact duplicate or a gap on a push stops
there, unverified (ruling DUP), so every signature a device verifies either stores a record it did
not hold or closes the connection (or, when the device's own index store cannot take the record,
pauses the folder until it can, `protocol.md` section 5; the check of its own store when a folder
opens, one verification per stored record, TM-9, is no peer's to trigger, and resuming after a store
failure does not reopen the index), and a peer of any tier can make it verify only as many
signatures as it brings new records, plus the one forged record that ends the connection; serving an
index request reads cached digests and recomputes none; chunk requests are bounded by
`max_requests_in_flight`, a queued request holds only its hash and the chunk is read from storage
only as it is sent, a requester keeps one `CHUNK_BUSY` backoff timer per connection and no state per
hash after `CHUNK_NOT_FOUND`; a key holder of any tier, under any number of device identities, can
still make a device queue up to `MAX_SEND_QUEUE` (128 MiB) of chunk replies per connection by
reading them slowly, for as long as it keeps the connection alive (a reader that trickles is never
closed by `IDLE_TIMEOUT`), so what bounds the total is the phase 1 connection limit; and a write
holder can make every peer store and compare any number of writers, and recompute cached digests and
resend a writer's history for each concurrent version it signs low in that history (section 3.6),
which costs storage, time and bandwidth, not per-connection memory, and lengthens every later open
of the folder on every peer by one signature verification per record it signed, the same cost class.
Enforced by `net`, `protocol` and `index`; the flood test is in `sim`.

**TM-23. No `unwrap`, `expect`, `panic` or unchecked index on untrusted input.**
`clippy::unwrap_used`, `expect_used` and `panic` are denied workspace-wide, `indexing_slicing` warns
and is fixed, and `.semgrep/project.yml` forbids `expect` on decoded data in `protocol` and `net`.
Stops a remote panic (rust-libp2p 2026 QUIC handshake). Enforced by `core/Cargo.toml` lints and
Semgrep.

**TM-24. The DHT uses a daily-rotating discovery hash and runs in client mode by default.** The
announcement hash is derived from the folder ID and the current day; the node is a client unless the
person turns on server mode, which adds a per-source rate limit and bounded responses; the BEP 44
sequence number is persisted and never reused, and the BEP 44 signing key, like the node ID, is a
stable identifier the device publishes (section 5); the DHT is off until a folder turns it on. Stops
Sybil and eclipse attacks learning more than one day's peers, announcement enumeration by crawlers,
and `get_peers` amplification (Wang and Kangasharju; BEP 42; Adamsky 2015). Enforced by `net`.

**TM-25. Relays refuse reservations over relayed connections, bound circuits per requester, carry
ciphertext only, and Private mode relays only for peers that share a folder.** A relay accepts a
reservation only on a direct connection, limits circuits and bytes per requester, schedules by
deficit round-robin so no client starves, never terminates the end-to-end channel, and in Private
mode serves only peers whose handshake proved a key, at any tier, to a folder it also holds. Stops a
relay learning identities or being used as free bandwidth (Syncthing relay spec; libp2p circuit relay
v2). Enforced by `net`.

**TM-26. Port mapping maps one port for this device, with a bounded lease, removed at exit.** UPnP,
NAT-PMP and PCP requests name only this device's single listening port and a lease of bounded length,
and the mapping is deleted on shutdown. Stops mappings injected or abused on home routers (UPnProxy
2022; CallStranger 2020). Enforced by `net`.

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
turns it on. `ci/no-hostnames.sh` checks hostnames and IPv4 addresses in one-line string literals in
the `.rs` files under `crates/` against the list; it catches accidents, not adversaries, and states
its limits (names under six top-level domains only; not IPv6, not hosts assembled from pieces, not
`Cargo.toml` or included data files), which the reviewers cover. Of the project's own domains it
exempts only the join-link prefix: it removes the exact text `https://licketysync.app/join#` and
checks the rest of the string, so a URL that begins with it passes, and the reviewers confirm that
the binary, which parses and writes join links, never requests it. Any other URL on those domains
needs its line in the list like any other host. Stops telemetry, update checks and any contact the
user did not choose. Enforced by `gate.sh` and CI.

**TM-32. Each side proves it holds a key to the folder without sending it.** The handshake's folder
proof is one proof for every tier (ruling S-1): a payload sealed under a key derived from the
folder's access key, which every tier holds and nobody else does, with a hint keyed under a sibling
key, both bound to the session's transcript and the prover's role, so it cannot be replayed into
another connection or reflected to its sender (`keys.md` §4). The tier the payload names is the
prover's report, shown and never relied on, since records and chunks are verified by signature and
hash whoever sends them. Knowing a folder ID from a LAN beacon, the DHT or a relay is not enough to
connect, to open a proof or to learn whether a device holds the folder; and a device ID is the hash
of the device's public key, canonically encoded, which it proves in the same handshake. Stops
impersonation, uninvited connection and probing for folders. Enforced by `protocol` and `keys`.

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
record, then renamed into place; replaced and deleted files go to the archive (Trash can, 30 days by
default, phones included); a scan that finds the marker gone, the path unmounted, or more than the
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
sender's choice, or automatically for browser invites and parcel links. Stops an invite putting the
sender's home address into an email or chat. Enforced by `keys` (encoding) and `cli`, `app`, `web`
(what is offered).

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

**TM-40. Ordering comes from `supersedes` and record order, never from wall clocks.** No ordering
decision, no decision about whether two versions conflict, and no decision about which records are
applied depends on a timestamp: every validly signed record whose seal opens and that is not a writer
fault is applied, and which versions of a path are its heads follows only from which records
supersede which (`protocol.md` §4.4, ruling R-K6), in any arrival order (TM-41). The only timestamp
use in conflict handling is a deterministic tie-break among the heads of one path, all of which are
kept: in the display order (non-tombstones first, directories before files, then the later
modification time, then the smaller record hash; `protocol.md` §4.4) the first sits at the path, and
the others, where their content differs, become named conflict copies. It never outranks `supersedes`,
and every head stays a head, so a writer who sets a future modification time or grinds record hashes
gains only which copy is shown first; a later record that supersedes them all replaces them. The
modification time is only ever compared, never subtracted, and a value the local file system cannot
set is an issue raised against the record, never a panic (TM-23). The one door-keeping decision that
reads the clock is the LAN beacon window, which drops beacons whose minute is far from the
listener's; no key expires. Everything else the local clock serves is advisory: lease lengths, the
daily discovery hash (looked up for the neighbouring days too), protocol timeouts and the
informational `written_at` field. Stops clock-skew attacks from a peer or a stolen device with a
changed clock. Enforced by `index` and `engine`.

**TM-41. Concurrent versions are kept, and peers that exchange converge on the same records.** Every
validly signed index record is kept, and applied when its seal opens and it is not a writer fault
(writer-fault records are stored opaque and applied by no one). Two records of one device at one
sequence number, which only a write holder signing twice under its own device ID, a write holder
writing under another device's ID, or a device restored from a backup can make, are concurrent
versions in a deterministic order (ascending sequence number, then record hash), whose meaning for
their paths the heads decide like any concurrent edit (`protocol.md` §4.4), with no blame, no
withdrawal and no evidence (ruling R-K5). Every index request carries, per writer, a digest over the
records the requester holds through its cursor, and a responder whose own digest there differs sends
that writer's records in full and asks back (`protocol.md` §4.5); pushes start when a folder opens,
and a dropped push makes the receiver owe a round, so no record either side accepts is left unasked
for. So two peers that serve each other's requests end with the same records for every writer,
whatever a write holder signed and in whatever order the records arrived, and compute the same heads.
A sealed peer or relay can still withhold records from a peer that meets no one else; it cannot make
two peers that meet disagree. Stops honest peers diverging when a writer signs two histories, which
per-writer sequence numbers alone let both sides miss (Kleppmann 2022, "Making CRDTs Byzantine fault
tolerant"), now answered by keeping every version rather than flagging the writer. Enforced by
`index` (cached digests, canonical order and heads) and `protocol` (the exchange); `engine` for the
conflict copies.

**TM-42. Removing someone is unlinking and sharing again, and the app says what that does not do.**
There is no revocation and no re-key protocol (owner's decisions of 2026-10-18 and 2026-10-22): the
people who stay unlink the folder on every device, share one copy as a new folder with new keys, and
pass the new key outside the client (`keys.md` §7.4). Before any of it, the app advises pausing the
folder, so that nothing more arrives from the person being removed, and restoring from the archive
whatever that person changed or deleted, since deletions from peers are not braked (TM-35); unlinking
keeps the archive as ordinary files, so this can still be done afterwards (`keys.md` §7.3). It also
states that the removed person keeps the old folder, its key and every copy they had; that a device
still on the old key keeps syncing with them; and that sealed peers store the new folder afresh.
Nothing in the protocol moves a key or a folder's history between folders. Stops the false belief
that removing someone took something away, the over-promise the plan's hardening review found more
harmful than an honest leak, and the loss of what they destroyed on the way out. Enforced by `app`
and `cli` (what they say and offer); `keys.md` §7 defines the actions.

## 5. What stays visible

A peer-to-peer design cannot hide that it is running or who it talks to, and the sealed tier exists so
that a device that cannot read a folder can still hold and serve it, which means some facts about that
data are visible to it. The list is honest because the plan's hardening review found that the systems
it studied failed more often by promising too much than by leaking too much.

**To anyone on the LAN.** That a device runs Lickety-Sync and which port it listens on; the device's
address; in each beacon, under a salt fresh to that beacon, one hash per announced folder and one hash
of the announcer's libp2p identity key (its peer tag), so that an observer who already knows the
folder ID can confirm it is announced here, an observer who already knows the device's identity key
(anyone it has connected to) can confirm that device is announcing, and an observer who knows neither
cannot link two beacons to one folder or to one device from the beacons' contents (the source address
links beacons from one interface, which no hashing hides); and, by replaying a captured beacon from
its own address within the ±5-minute window listeners accept, which devices dial it and so hold the
folder the beacon named, without knowing that folder's ID: the dial is the signal, and `keys.md`
(discovery hashes) records it as the residual leak the design accepts.

**To a network observer.** That two addresses talk, when, for how long and how much; the sizes and
number of encrypted frames, which approximate padded chunk sizes and counts; QUIC and TLS handshake
metadata; on a locked-down network, the hostname of the HTTPS listener, timing and volume. Not
contents, names, keys or folder IDs, and not the peer ID: in TLS 1.3, QUIC and Noise XX the identity
key travels encrypted, so a passive observer does not learn which device is talking. Whoever completes
a connection to a device, with no key to anything, learns more: its libp2p peer ID, which is stable
because it derives from the device's libp2p identity key, so the device can be recognised across
networks, days and folders (the hashed form in LAN beacons confirms it to anyone who already holds the
key; DHT address records carry no peer ID); its device ID and public key, proven by the DeviceProof
before any folder is named; the protocols it offers in multistream-select; its suite, compression,
hash and feature lists and limits from the Hello; and, from the time its first REJECTED folder proof
takes, a coarse count of the folders the device holds (about 6 µs at 1 folder and 1.4 ms at 2000; a
constant-cost lookup table is a phase 7 follow-up). Not whether it holds a given folder: the hint and
the proof key need a key to that folder (TM-32), and a party that holds one would learn the same from
a successful proof. Not its name: the self-reported device name is sent only after a folder has
opened on the connection, in the first Status after the first folder opens, so only a peer that has
opened a folder with the device learns its name.

**To the DHT and anyone crawling it.** Which addresses announce a given day's discovery hash; a signed
address record under the device's DHT key. The hash does not reveal the folder ID and changes daily,
but anyone who ever held the folder ID (any key holder, a relay the folder uses) can compute every
day's hash and watch who announces it, and a device is linkable across days by a stable address alone
or by any stable identifier it publishes with the announcement: the BEP 44 signing key its address
record is signed with, or a persisted DHT node ID. The record carries no libp2p peer ID; the
DeviceProof binds identity at the handshake. The libp2p identity key still gives every device a stable
peer ID, which is a cross-folder tracking handle for anyone the device connects to: they can tell it
is the same device whatever folder, day or address is involved; `suites.md` (the libp2p identity key)
records the per-folder or rotating identity that would remove the handle as a considered alternative.

**To a relay.** Both endpoints' addresses, the folder a reservation names (as its ID), timing and
volume, and the sizes and number of encrypted frames, which approximate padded chunk sizes and counts.
Not contents, names or keys: the end-to-end channel runs inside the relayed connection.

**To a sealed peer.** Everything a relay sees, and: the folder ID and verification key (its key
carries both); device IDs from the handshake and self-chosen device names from the first Status once
the folder opens; the tier each peer it connects to reports; the clear fields of every index record,
which `protocol.md` (the index record on the wire) fixes: the device ID and the sequence number,
`supersedes`, which links the versions of each file and shows where its history forked into a
conflict and joined again, whether the record is a tombstone (sealed peers must see deletions to
garbage-collect chunks), the number of chunks with each chunk's padded stored length and ciphertext
hash, and the padded length of the sealed part; which records are concurrent versions of one device's
sequence; the number of index records and the rate at which they arrive; the Status message every
peer sends for each open folder (records held, a running count of chunks stored, ciphertext bytes
still to fetch, whether it is paused, free disk space); which chunks each device holds, since any peer with the folder open may ask for any
chunk and a device answers `CHUNK_OK` exactly for the chunks it holds for the folder (it has the
blob and a record naming it, `protocol.md` §4.6) and `CHUNK_NOT_FOUND` for the rest, so on a device
using selective sync or "free up space" this shows which files it keeps locally (by ciphertext hash;
a key holder can name them); which chunks are identical, because content-derived nonces make
identical plaintext under the folder's key identical ciphertext (the cost of letting sealed peers
verify and deduplicate); approximate total size of the folder; activity patterns in time. Not the path, kind, true size,
times, mode, plaintext hashes or `written_at`: those sit in the sealed part, which is Padmé-padded, so
its length says little about the path length or the chunk count. Padmé padding reduces size
fingerprinting of individual chunks to within 12%; it does not hide the number of chunks, the total
volume, or when changes happen. A sealed peer can also show a stale snapshot to a peer that has no
persisted state yet for a writer, such as one on its first sync; the regression is found when that
peer meets a fresher one (TM-17). Compression inside the encrypted chunk, when a writer enables it, is
a CRIME-style length channel: where bytes an attacker can influence share a chunk with secrets, the
padded size reveals how well they compressed together. Padmé blunts it (2 KiB granularity at 64 KiB,
128 KiB at 4 MiB) but does not remove it; phase 0 uses no compression, and the release that enables
one states this channel on the site before it ships (TM-15).

**To a key holder.** A write or read key holder sees everything in the folder, every other peer's
device ID, name and reported tier (shown marked "reported", like the name), and, through chunk
requests, which files each device keeps locally. Holders of one tier look alike: nothing in the
folder says which person holds which key or made which change. A key holder with the chunk-hash key can test whether a
guessed file is in the folder: keyed hashes stop outsiders, not members.

**To a corporate proxy on a locked-down network.** The hostname dialled, timing and volume; the Noise
handshake runs inside the WebSocket, so a proxy that terminates the outer TLS sees encrypted frames.

**To a future quantum computer with recorded traffic.** The transport's X25519 share where a path used
Noise or a classical TLS group, and therefore the contents of that transport session: handshake
identities, Hello contents, folder proofs, record envelopes, chunk ciphertext. That includes every
WebSocket session, and so any session an attacker forced onto that path by blocking UDP and raw TCP
(section 3.1): as `libp2p-websocket` ships, its outer TLS is rustls on `ring` and the Noise inside is
classical, so both layers fall (`suites.md`, transport, records the deviation and the phase 2 change
that gives the outer TLS the post-quantum group). Content, names and structure are encrypted under the
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

For every phase gate: the gate's reviewer walks every live requirement (TM-1 to TM-42 less the five
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
- Kleppmann 2022, "Making CRDTs Byzantine Fault Tolerant",
  https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf
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
