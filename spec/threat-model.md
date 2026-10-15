# Lickety-Sync threat model

Version 1, 2026-10-14. This file is normative for every crate in this workspace, for
the apps in `app/` and for the browser client in `web/`. Its companions are
`suites.md` (algorithms and approved crates), `keys.md` (key hierarchy, grants,
wrapping, epochs) and `protocol.md` (wire protocol). The plan, "Lickety-Sync:
Project Plan", is the source these files are written from; where this file is
silent the plan decides, and where they disagree the disagreement is raised, never
quietly resolved.

Every requirement below has a number, TM-1 to TM-40. Code comments, test names,
changelog entries and review reports cite them (`// TM-4`,
`fn tm_4_symlink_then_directory()`). Section 6 says how a reviewer uses them.

Vocabulary, shared with `keys.md` and `protocol.md`: a **folder** is the unit of
sharing; its **root key** signs every key record (grants, revocations,
suspensions, lifts, rotations; never an index record) and derives from the
owner's **recovery phrase** (the 24 words encode the 256-bit **master secret**)
and the **folder nonce**, 32 random bytes created with the folder and published in
its first record, so that a root holder can re-derive the root of any folder it
finds; every key is a **key pair set** (a signing keypair and a KEM keypair)
derived from one 32-byte **seed**; an **issued key** is such a seed plus a
**grant** signed by the chain to root naming the folder, the **tier** (write, read
or sealed), the **key ID** (the labelled hash of the key's signing and KEM public
keys, truncated to 16 bytes), an optional expiry and a "may share" flag, with the
folder's **data
key** wrapped to it if the tier is write or read (sealed keys get no wrap); the
data key changes with every **epoch** (rotation); a **device** has a device key
pair set, a **device ID** (the labelled hash of its public key) and a self-chosen
name; **Hello** is the first message of the handshake, listing what a device
supports and its limits; the **index** is the folder's set of signed,
hash-chained **records**; a **chunk** is a content-defined piece of a file; a
**sealed peer** holds ciphertext it cannot open; a browser in **vault mode** is a
sealed peer that stores ciphertext in the browser's own storage; a **relay**
forwards ciphertext for peers that cannot reach each other; **peer exchange** is
peers telling each other the addresses of peers they share a folder with; the
**deletion brake** pauses a folder and announces no deletions when more than a
threshold of its files vanish at once, until the person confirms (TM-35); a
**parcel link** is the plan's one-time "send one file to someone" invite, which
carries addresses because the recipient may share no peer with the sender.

## 1. What we protect (assets)

The program exists to copy people's files between devices without any party in the
middle being able to read, alter or withhold them. What must be protected is the
files themselves, everything that describes them, the keys that open them, and the
one secret that regenerates every key. Some facts cannot be hidden by a
peer-to-peer design and are listed as leaks in section 5 rather than promised away.

| Asset | What it is | Who may learn it | Confidentiality, integrity, availability |
| --- | --- | --- | --- |
| File contents | The bytes of every file in a folder | Write and read key holders | All three; availability is what sync is for |
| Names and structure | Paths, tree shape, true sizes, modification times, modes, symlink targets | Write and read key holders | All three |
| The index | Per folder: each path with size, time, mode, version vector, chunk list and deletion marker, as signed records that name their predecessors | Write and read key holders decrypt it; sealed peers carry it opaque | Integrity against everyone, including writers (equivocation, rollback); confidentiality against sealed peers and relays |
| Root key | Signs grants, revocations, suspensions, rotations; derived from the phrase and the folder's public nonce | Root-holding devices only | Confidentiality is total: its loss is the loss of control of the folder |
| Data key | The symmetric key of the current epoch; wrapped to every valid issued key | Write and read key holders | Confidentiality against sealed peers, relays and revoked holders |
| Issued keys | Seed → key pair set (signing and KEM keypairs); the grant is public | The holder; the grant is readable by every peer of the folder | A seed is a credential: whoever holds it is that key |
| Recovery phrase | 24 BIP39 words encoding 256 bits; the master secret of every folder the person owns, past and future, and of the identity key | The person, and the devices marked as root holders, encrypted at rest by the platform keystore | Disclosure is total compromise of every folder the person owns; loss ends the ability to issue and revoke |
| Identity key | Per person; links devices and encrypts the shared catalogue | The person's linked devices | Compromise lets an attacker join as a linked device and read the catalogue |
| Device identity | Device keypair; device ID = hash of its public key | Public to anyone who completes a connection: the DeviceProof proves the hybrid key and ID before any folder is named, and the Hello carries the lists (section 5); the name is sent only after a folder has opened on the connection, so only a peer that has opened a folder with the device learns its name | Integrity: a device cannot claim another's ID |
| Catalogue | Every folder the person has, with tiers and addresses, encrypted to the identity | Linked devices | Confidentiality against everyone else |
| Local API token | Authenticates the CLI and web UI to the service | The local user | Confidentiality against other local users and web pages |
| Metadata that leaks | Padded sizes, chunk counts, record counts and rates, timing, the salted folder and announcer hashes on the LAN, the daily discovery hash and the stable identifiers a device publishes with it on the DHT, that two addresses talk, the grant graph (key IDs, tiers, issuers, expiries), device IDs and names, and to whoever completes a connection the libp2p peer ID, the protocols it offers in multistream-select, the device's hybrid key, suite, compression, hash and feature lists and limits, and, for a folder ID they already hold, whether the device holds it (proof-result timing) | Sealed peers, relays, network observers, as section 5 states | Not protected; documented |

## 2. Parties and trust boundaries

Nothing in the design is a server, so there is no party that holds everyone's data,
and every party below is either the user's own device, a device the user chose to
share with, or infrastructure that carries ciphertext. Trust is attached to keys,
never to addresses, names or the network a message came from.

| Party | What it holds or sees | What we trust it with | Boundary it sits behind |
| --- | --- | --- | --- |
| Root-holding devices | The phrase (keystore-encrypted), root keys, write keys, plaintext | Everything: a compromise here is a compromise of every folder the person owns | The operating system's user account and keystore |
| Linked devices (not root) | Identity key, write keys with "may share" at the tiers chosen per folder, the catalogue, plaintext of folders they hold | Content and names of their folders; issuing keys at or below their tier; not the phrase, which they cannot derive | Same as above; loss is handled by revoking that device's keys |
| Write key holders (other people) | Data key, index, plaintext; may issue at or below write if "may share" | To change files honestly; the design detects equivocation and rollback and attributes every change to the key and device that made it | A separate person; their device is theirs |
| Read key holders | Data key, index, plaintext | To read; their changes are ignored by everyone | Same |
| Sealed key holders (sealed peers) | Ciphertext, grants, revocations, rotations, record envelopes, chunk ciphertext hashes | To store and serve ciphertext faithfully; nothing else, and faithfulness is verified rather than assumed | Same; a NAS, a friend's machine, a browser in vault mode |
| Relays: private, public, volunteer | Both endpoints' addresses, timing, volume, the folder a reservation names | Nothing; carries end-to-end ciphertext only | Another person's device, chosen per folder; off by default except own-device relays |
| The LAN | Beacons (salted folder hashes, salted announcer hash, port), multicast, every unencrypted byte | Nothing: a café network is the model | The network interface |
| The internet | Addresses, timing, volume, QUIC and TLS handshakes | Nothing | Same |
| The Mainline DHT | Daily discovery hashes with the addresses announcing them; signed address records (BEP 44) under a stable per-device key | Nothing; off by default, and seeing a peer grants no access | UDP to strangers; client mode by default |
| The browser client's static host (licketysync.dev) | Serves the WebAssembly bundle; never sees invite fragments, keys or content | To serve the published bundle; a compromise serves a changed client, which a signed manifest lets the native app or a verifying extension detect | HTTPS; the service worker cache only delays what the host serves |
| The browser running the client | Keys and plaintext of the folders it joins, in origin-private storage or a chosen directory | As a peer at its key's tier; the browser's origin rules keep other sites out | The browser's same-origin policy |
| The local API and its clients | The service listens on a Unix socket or named pipe and on localhost HTTP; the CLI and web UI hold the token | The token holder is the local user | Host and Origin checks, the token, socket permissions |
| The operating system | File system, keystore, random number generator, clock, network stack | Fully: it is out of scope (section 3.12) | — |

## 3. Adversaries

Each subsection lists what the adversary can do, what the design promises it cannot,
and the requirements in section 4 that carry the promise. "Cannot" means the
construction prevents it; "detected" means a peer notices and raises an issue
rather than being prevented in advance.

### 3.1 A network observer

Someone who sees packets on the LAN, at an internet exchange, at a proxy on a
locked-down network, or by crawling the DHT. They have no key.

Can: see which addresses talk, when, and how much, and the sizes and number of
encrypted frames, which approximate padded chunk sizes and counts; see that a
device runs Lickety-Sync and its port; see the LAN beacons, each carrying, under
a salt fresh to that beacon, one hash per announced folder and one hash of the
announcer's libp2p identity key, and confirm a folder is announced on this LAN
if they already know its ID, or that a device they have met before is announcing
if they already know its identity key; replay a captured beacon from their own
address and learn, from the dial that follows, which devices on the LAN hold the
folder it named, without knowing that folder's ID, and learn each such holder's
libp2p identity, because the handshake authenticates it before the dialler
checks the peer tag and abandons the connection (the dial is the signal;
`keys.md`, discovery hashes); see the DHT's daily discovery hash and the
addresses announcing it, and follow a device across days by its address when
that address is stable, by a stable identifier it publishes with the
announcement (the BEP 44 key its address record is signed with, a persisted DHT
node ID), or by computing every day's hash when they already hold the folder ID;
block UDP and raw TCP so that a dialler falls back to the WebSocket path, which
is classical end to end as `libp2p-websocket` ships it (its outer TLS is rustls
on `ring`, and the Noise inside is classical; `suites.md`, transport), so that a
session forced there is open to a future quantum computer up to what a sealed
peer sees (section 5, the quantum entry); record traffic for a future quantum
computer; drop, delay, reorder or inject packets; reach the home router's
port-mapping service from the LAN, which maps only this device's one port for a
bounded lease (TM-26).

Cannot: read contents, names, index records, keys or key material; learn the
folder ID, a device's identity key or any key from the hashes, or link two
beacons to one folder or to one device from the beacons' contents without the ID
or the key (the source address links beacons from one interface, which no
hashing hides); join a folder by knowing its ID; downgrade the transport to
plaintext (TM-1), or from TLS to Noise on one transport, because each transport
offers exactly one security protocol (`suites.md`, transport): blocking can
force the choice of transport, never of the protocol within one, and the
WebSocket path it can force a dialler onto is still encrypted and authenticated
(TM-1); downgrade the record suite to a weaker one (TM-30); open recorded
traffic later with a quantum computer, because the data key is wrapped with a
hybrid KEM and content is encrypted before it leaves the device, so recorded
traffic yields at most what a sealed peer sees (TM-33, section 5); link one
day's DHT announcements to the next without the folder ID, a stable address or a
stable published identifier (TM-24); impersonate a peer, because peers
authenticate by key, not address (TM-32).

### 3.2 A peer holding a valid key

A device that legitimately holds an issued key. What it can do is the tier's
purpose; what it must not be able to do is exceed the tier or act as another key.

**Write key.** Can: read and change files, names and structure; delete files;
issue keys at or below write if its grant carries "may share"; revoke and suspend
the keys it issued and every key beneath them in the chain, and lift a suspension
that it or a key beneath it signed (TM-19), and
with a revocation or suspension set the cutoff after which the named writer's
records are refused, which is destructive to that writer's later work (the brake
and the archive apply as to any destruction, TM-35); see every other peer's
device ID, name and key ID. Cannot: forge a record under another key (every
record is signed by its writer, TM-9, TM-33); revoke or suspend root, its own
ancestors, or any key outside the chain beneath it, or lift a suspension signed
above it (TM-19); attach a grant to a key it does not hold, and so gain an
issuer's powers over someone else's key, because every grant carries a signature
by the key it grants (TM-19); give two peers
different records under one version without detection (equivocation, TM-16,
within the limit it states); make peers accept an older state as current
(TM-17); have a rotation accepted that omits a key the rotation's own declared
view keeps (TM-19); learn the phrase or the root key; raise its own tier.
Detected, not prevented: leaving a
valid key out of the view a rotation declares. The holder left out is told by
name who omitted it and is repaired by a Wrap record from root or an ancestor
(TM-19; plan decision 2026-10-15). Its destructive power over content is real:
it can delete or overwrite everything it may write. The archive (Trash can, 30
days by default) and the deletion brake limit the damage, and every change names
the key that made it and the device the key holder claims (TM-34, TM-35), so the
owner can revoke precisely.

**Read key.** Can: read everything; issue read or sealed keys if "may share". Cannot:
change anything, because its records are ignored by every peer (TM-9); forge; learn
the phrase or root key; raise its tier.

**Sealed key.** Can: hold a complete copy, verify ciphertext against the hashes the
signed records name, serve it, relay for others, issue sealed keys if "may share".
Cannot: read contents, names or structure; see plaintext chunk hashes; test
whether the folder holds a known file (TM-14); do anything in 3.3.

### 3.3 A sealed peer or a relay

A storage or forwarding party that handles ciphertext only. Every cloud break the
plan's hardening review cites (Nextcloud 2024, MEGA 2022, pCloud, Icedrive and
Seafile 2024) relied on a storage party that the client trusted too much. Here the
storage party is untrusted by construction.

Can: see sizes after padding, chunk counts, record counts, the rate of change,
timing, epoch changes, the grant graph (key IDs, tiers, issuers, expiries, "may
share" flags), device IDs and names, folder IDs; tell that two chunks are identical
(convergent encryption, section 5); withhold data, go offline, or serve slowly;
store far more than asked.

Cannot: insert or replace key material and have a client re-encrypt under it,
because key material is accepted only when signed by the chain to root (TM-9,
Nextcloud key insertion); cause a client to fall back to a default or empty key
(TM-10, Nextcloud ghost key); use key wrapping as an oracle, because every wrap
is authenticated with the folder, key ID, tier and epoch as associated data and
every purpose key has its own derivation label (TM-11, MEGA); provoke a nonce
reuse by making a client re-encrypt, because re-encryption after a rotation is
under a new key and chunk nonces are content-derived (TM-12); drop, reorder,
duplicate or substitute chunks within a file unnoticed, because the file record
signs its full chunk list and each chunk is verified against it (TM-13); serve
an older snapshot as current to a peer that has persisted newer records for the
writer, because a peer never moves backwards on another peer's say-so (TM-17): a
peer with no persisted state for a writer, as on a first sync, accepts the newest
it is shown, syncing from more than one peer narrows that window, and the stale copy
is detected the moment a fresher peer is met; learn names, since names and
structure are inside the encrypted index (TM-33); learn whether a known file is
in the folder: plaintext chunk hashes are keyed per folder, and the ciphertext
hash a sealed peer may ask about needs the data key to compute, so a sealed
peer's chunk request for a guessed file is answered CHUNK_NOT_FOUND like any
other miss and confirms nothing (TM-14); learn the data key of a new epoch after
a revocation, because the rotation wraps it only to keys the rotation's view
keeps (TM-19, TM-38; a key revoked concurrently with a rotation that still
wrapped to it is cut off by the next rotation, within one further epoch).

### 3.4 A stolen or lost device

An attacker with physical possession of a device, or with its disk image. What they
get is what the device held; what the owner can take back is everything from the
moment of revocation on.

Can: read whatever plaintext the device held on disk; use the issued keys the
device held, at their tiers, until each is revoked or suspended and the news
reaches the peers they contact; read the catalogue if the device was linked; read
the phrase if the device was a root holder and they defeat the operating system's
keystore (login password, biometrics, secure element); keep forever the data and
epoch keys the device already had; with a write key it held, sign records under
the device ID of any other device that holds the same key, which forks that
device's chain, so that peers flag the key and withdraw that chain from the fork
(TM-16, TM-34).

Cannot: derive the phrase from the identity key or from any issued key, because
derivation is one way (TM-36); read anything encrypted under an epoch it did not
already hold, because the rotation wraps the new data key only to keys the
rotation's declared view keeps, and a revocation that raced the rotation is
honoured by the next one (TM-19, TM-38); forge records after revocation, since
records signed by a revoked key after its revocation are rejected (TM-19); undo
`rekey --full`, which re-encrypts existing content under the new key for the
case where old ciphertext might later fall into its hands. What it keeps for a
while: a writer that has not yet heard the revocation keeps writing under the
old epoch, and those writes are readable by the revoked key until that writer
learns of the rotation, which happens the moment it syncs with any peer that has
it (TM-38).

The owner's recovery is: revoke the device (one step revokes every key it held),
which rotates the epoch; run `rekey --full` if the device may have kept ciphertext;
if it was a root holder, treat the phrase as exposed unless the keystore is known to
have held. The keystore is the operating system's and is out of scope.

### 3.5 A hostile or leaked invite

An invite is an issued key with a short expiry, carried as a key string, QR code or
link: the folder ID, the 32-byte seed and a checksum. Whoever has the string is the
key.

Can: join at the invite's tier from any number of devices until it expires, is
revoked or is suspended; if the issuer appended addresses, learn the issuer's
current addresses; keep the folder ID forever, and with it compute every day's DHT
discovery hash and watch which addresses announce it (section 3.9) and confirm the
folder's presence on any LAN it listens to (section 3.1); if the invite was a write
key, do everything in 3.2, including signing records under the device ID of
another device that joined with the same invite, which forks that device's chain
so that peers withdraw it from the fork (TM-16, TM-34).

Cannot: join after revocation on any peer that holds the record, or after expiry
on any peer whose clock has passed it (TM-19, TM-40); exceed the tier; learn the
issuer's home address from a bare invite, which carries no addresses by default
(TM-37); leak the secret through a web server, referrer or landing page, because
in a link the secret sits after `#` and the client origin serves no page that
would log it (TM-18). A limitation, not a promise: uses of an invite are not
counted, because a count cannot be enforced without a peer online to count, so
there are none.

The design's answer to a leak is visibility and precision rather than prevention:
the Keys view lists the devices seen using each key, when, and what each changed
(TM-34), so a key in use on more devices than expected is suspended and fresh keys
are issued, one per recipient and per device by default.

Expiry is checked against the local clock; a device with a wrong clock may accept an
expired invite until it syncs with a peer whose records supersede it. Revocation,
not expiry, is the mechanism that is relied on.

### 3.6 A dishonest writer

A write key holder, or a stolen write key, that tries to make peers disagree, go
backwards, or lose data without being noticed.

Can: make any change its tier allows, including destructive ones; present two
different records under the same version to two peers (equivocation); sign
records under the device ID of any other device that holds the same key, which
forks that device's chain, so that peers flag the key and withdraw that chain
from the fork (TM-16, TM-34); try to re-send an old record as current
(rollback); flood with records.

Cannot: equivocate undetected (beyond the limit TM-16 states: a split stays
unseen until two peers holding different branches exchange cursors for the
writer), because every record names the hashes of its predecessors, so two
records from one key at the same point are detected by the first peer that sees
both and the key is flagged under Issues (TM-16, Kleppmann 2022); roll back a
peer that has persisted newer records for it, because a peer never moves
backwards on another peer's say-so (TM-17; a peer with no persisted state for
the writer accepts the newest it is shown until it meets a fresher peer), except
by equivocating, which flags its key, withdraws the chain it forked, which may
be another device's under the same key, from the fork, and sends whatever that
removes through the archive and the deletion brake (TM-16, TM-35); hide which
key made a change (TM-34: the key is proven by the signature; the device ID in a
record is the key holder's claim, proven only for the device that presented the
key at the handshake, and the Keys view shows the claimed device beside the
devices seen presenting the key); forge another key's records (TM-9); escalate
(3.2). Destructive but honest-looking changes are bounded by versioning, the
archive and the deletion brake, and are reversible by the owner from the archive
(TM-35).

### 3.7 An attacker on the local network or a web page attacking the local API

The service exposes its API on a Unix socket or named pipe and on localhost HTTP
for the web UI. The attackers are another user on the same machine, a program on
the LAN that resolves a hostname to 127.0.0.1 (DNS rebinding), and a web page in
the user's browser making cross-site requests.

Can: send requests to localhost from a page the user has open; rebind a DNS name to
the loopback address and have the browser send requests with a foreign Host
header; try the socket if its permissions allow.

Cannot: have a request acted on without the token, which only the local user's
CLI and web UI hold and which is required on every request (TM-21, Dorsey 2018);
succeed with a rebound hostname, because the Host header is checked against the
listener's own address and the Origin header against the UI's origin (TM-21,
Syncthing's host check); read the token from the page, because the UI's origin
and the browser's same-origin policy keep it out; read key material through the
API, which never returns private keys, seeds or the phrase except through the
explicit `owner` export commands that require the operating system's own unlock
(TM-39); inject HTML through peer-supplied strings, which render as text
(TM-20); reach the native core from the app's web view except through the
commands its capability lists (TM-27).

### 3.8 A compromised static host for the browser client

licketysync.dev serves the WebAssembly bundle. Subresource integrity cannot protect
a page against its own host, so a host that is compromised can serve a changed
client to anyone who loads it.

Can: serve a bundle that exfiltrates keys or content for every user who loads it
while it is compromised; serve a correct bundle to the people it expects will check,
and a changed one to others.

Cannot: see invite secrets in requests, because they travel after `#` and the
client origin serves no landing page (TM-18); go undetected by a careful user,
because each release publishes a signed manifest of the bundle's hashes that the
native app can verify against a served bundle, and the site documents WEBCAT and
Code Verify-style extensions as the way to check the page that loaded (TM-28);
affect native clients, which never load code from the host (TM-29, TM-31). What
remains is stated plainly: the service worker cache gives no protection against the
host beyond its update interval, since the host also serves the service worker; the
native app's manifest check and a verifying extension are the only checks; and a
first-time visitor with no native device of their own and no verifying extension
trusts the host at the moment of loading, exactly as with any web application.

### 3.9 A Sybil or eclipse attacker on the DHT

Someone who runs many DHT nodes to surround a target's position in the routing
space, enumerate announcements, or use the DHT as an amplifier.

Can: see which addresses announce a given day's discovery hash, if they know the
folder ID, and the stable identifiers each announcing device publishes (the BEP
44 key its address record is signed with, its DHT node ID; the record carries no
libp2p peer ID, the DeviceProof binds identity at the handshake instead); serve
an old signed address record to a reader that holds no newer one, which is
harmless because the address is only a dial hint and the handshake decides the
rest; eclipse a device so that its lookups return only the attacker's nodes,
denying discovery through the DHT; enumerate announcing addresses by crawling.

Cannot: turn a discovery hash back into the folder ID or any key; gain access to
a folder by seeing or impersonating its peers, since access needs a key (TM-32);
link a folder's announcements across days from the hashes alone, since the hash
rotates daily (TM-24), though anyone who ever held the folder ID (a sealed peer,
a relay, anyone who saw an invite string) can compute every day's hash, and a
device is linkable across days by a stable address or by a stable identifier it
publishes with the announcement (BEP 44 key, persisted node ID); use the device
as a `get_peers` amplifier or exhaust it, since the DHT runs in client mode
unless the person turns on server mode, which adds a per-source rate limit and
bounded responses (TM-24, Adamsky 2015); replay an old BEP 44 address record
over a newer one a reader already holds, since the sequence number is persisted
and never reused (TM-24); affect anyone who has not turned the DHT on (it is off
by default). Eclipse denies one discovery method; LAN, direct addresses,
own-device relays and peer exchange remain.

### 3.10 A resource-exhaustion attacker

Someone who opens connections, streams, reservations or registrations faster than
a device can serve them, or sends messages whose declared lengths would make the
device allocate unbounded memory.

Can: send any number of connection attempts, handshakes, Hello messages, chunk
requests and relay reservations; declare absurd lengths; send malformed input to
every decoder.

Cannot: make the device allocate before a length limit is checked (TM-2); grow any
per-peer table without bound, because every table is bounded and dies with its
connection (TM-22, go-libp2p and rust-libp2p 2022); hold unlimited relay circuits
or reserve a relay through a relayed connection (TM-25); amplify through QUIC,
whose three-to-one anti-amplification limit stays at its default (TM-22), or
through the DHT (TM-24). A panic on malformed input is made unlikely and caught
before merge rather than made impossible: every decoder is fuzzed, `unwrap`,
`expect` and `panic` are denied, and indexing on untrusted data warns and the gate
treats warnings as errors (TM-3, TM-23, rust-libp2p 2026 QUIC panic). Denial of
service by sheer traffic volume is out of scope (3.12).

### 3.11 Supply-chain and update attackers

Named here because the hardening review names them, though they attack the build
rather than the protocol: a malicious or compromised dependency, a tampered update,
a downgraded install.

Cannot: enter the build unnoticed, because a new dependency needs a written
reason, an active upstream and clean cargo-deny, cargo-audit and cargo-vet runs,
and cargo-geiger's unsafe count may not rise, and cargo-audit runs daily as the
advisory feed (TM-8); install as an update without a verified signature or at a
lower version than the one running (TM-29, Syncthing 0.12.23); pass off a
tampered or unreproducible build as a release, because releases are built in CI,
signed, and published with an SBOM and build provenance (TM-29); phone home,
because the binary contacts no host that `spec/allowed-hosts.txt` does not list
and CI enforces the list (TM-31).

### 3.12 Out of scope

These are stated so that nobody mistakes silence for a promise.

- **The operating system and the network the program runs on.** A kernel, a
  keystore, a random number generator or a file system that lies is not defended
  against. Malware running as the user reads what the user reads.
- **Denial of service by traffic volume** that a home connection would already fail
  under. The program bounds what it allocates and accepts; it cannot keep a
  saturated link usable.
- **Multi-file atomicity.** A git repository, an SQLite database, a password
  manager's vault or any set of files that must change together is synced file by
  file; a peer may observe a state no writer ever had on disk. The site's
  Limitations page says so.
- **Phone background limits.** A phone that the operating system has suspended
  does not sync, and a sync that it interrupted resumes later; nothing the program
  does can promise otherwise.
- **Traffic analysis beyond padding.** Section 5 lists what sizes, counts and
  timing reveal; Padmé padding reduces size fingerprinting and nothing hides volume
  or activity patterns.
- **A compromised root-holding device.** It holds the phrase; the keystore is the
  operating system's.
- **Social engineering of the owner** into issuing a key, reading out the phrase or
  approving a device.
- **Coercion.** There is no duress mode or deniability.

## 4. Requirements

Each requirement is one rule, the attack it stops with the incident the plan's
hardening review cites, and the layer that enforces it. "Enforced by" names the
crate or layer whose tests carry the proof; "reviewed in" names where a change must
be checked against it even when it does not touch the enforcing crate. Some
requirements overlap on purpose (TM-2 and TM-22 on bounds, TM-19 and TM-38 on
epochs, TM-6 and TM-39 on secrets leaving the process): each states one rule from
one angle, and a change cites every number that applies.

**TM-1. The protocol has no plaintext mode.** A peer that cannot complete the
encrypted handshake is dropped, on a LAN exactly as over the internet, and no
setting turns this off; and each transport offers exactly one security protocol
(TLS on QUIC and TCP; Noise only inside WebSocket, WebTransport and WebRTC), so
nothing weaker can be negotiated before authentication either. What this does
not stop is stated: an attacker who blocks UDP and raw TCP steers a dialler onto
the WebSocket path, which is classical end to end as `libp2p-websocket` ships it
(its outer TLS is rustls on `ring`; a recorded deviation with a phase 2 item,
`suites.md`, transport); that path is still encrypted and authenticated, and the
cost is what section 5's quantum entry lists. Stops passive reading and active
downgrade of the transport; the lesson of every protocol that kept a fallback.
Enforced by `net` (no unencrypted listener or dialer exists, one security
protocol per transport) and `protocol` (no message type is defined outside a
session).

**TM-2. Every byte from a peer is untrusted, and length limits are checked before
allocation.** Every length field is compared against the limit the Hello agreed
or the protocol fixes before any buffer is sized to it, and every collection a peer
can grow is bounded. Stops memory exhaustion from declared lengths and unbounded
tables (go-libp2p and rust-libp2p resource-exhaustion advisories, 2022). Enforced
by `protocol` (framing) and `net` (per-connection budgets); reviewed in every
decoder.

**TM-3. Every decoder is fuzzed.** Every network message, key string, grant,
record, invite link, file name and path decoder has a `cargo-fuzz` target with a
committed corpus, run thirty minutes each nightly today, and ten minutes per
push and continuously once ClusterFuzzLite's configuration exists. Stops crashes
and panics on malformed input (rust-libp2p 2026 remote panic in the QUIC
handshake). Enforced by `fuzz/` and CI; a decoder without a target does not
merge.

**TM-4. One beneath-root path resolver; symlinks are never followed.** Every
subsystem that touches the disk, including versioning, trash, temporary downloads,
conflict copies, the ignore file and the marker, resolves paths through one
function that normalises, refuses traversal, reserved and platform-invalid names,
and refuses to follow a symlink at any component; the symlink-then-directory
sequence (a peer sends a symlink, then a directory of the same name, then a file
beneath it) is a committed test. Stops path traversal and symlink escape through a
second code path (Syncthing 2016 traversal; CVE-2017-1000420 in versioning).
Enforced by `engine`; `.semgrep/project.yml` forbids `std::fs::canonicalize` and
`read_link` throughout the workspace, the resolver included, which opens with
no-follow semantics instead.

**TM-5. Cryptography comes only from `suites.md`.** No primitive, combiner, key
derivation, padding scheme or random generator whose output reaches a key, a
nonce, an identifier or any byte a peer sees is written in this workspace; every
algorithm and crate is the one `suites.md` lists, at the version range it pins,
and nothing not listed is used until a reviewed change adds it. The one
generator written here is the simulator's seeded statistical one (SplitMix64 in
the `sim` crate), which feeds the runtime's randomness trait in simulator runs
only, so seeds, nonces and salts in a simulated run come from it; it is not
cryptography, `sim` is never a dependency of `daemon`, `cli` or `decrypt`
(reviewed on every `Cargo.toml` change), and no production build contains it, so
this rule permits it and says so (`suites.md`, randomness). Stops the class of
flaw that hand-written combiners and wrappers introduced in MEGA 2022 and
Nextcloud 2024. Enforced by `deny.toml` bans and cargo-vet; reviewed in every
change that touches `keys`, `protocol` or `engine`.

**TM-6. Secrets live in zeroized types and never reach logs.** Seeds, private
keys, data keys, the phrase, passphrases and session keys are held in types that
zeroize on drop, whose `Debug` output is redacted, and that are never formatted
into a log, error message or panic payload; logs redact folder IDs and addresses by
default. Stops secrets leaking through crash reports, log files and debugging
output, which is how the Tahoe-LAFS and BitTorrent Sync analyses found capability
strings in the clear. Enforced by `keys` (types) and `daemon` (logging); the rules
are in `suites.md` section 4.

**TM-7. No `unsafe` outside the platform-FFI crates.** The workspace lint
`unsafe_code = "forbid"` applies everywhere; a platform-FFI crate opts out
explicitly and is covered by Miri nightly; cargo-geiger's count is a report that
CI publishes and reviewers read, and a rise in it is a finding, not something a
job compares. Stops memory-safety bugs reachable from untrusted input. Enforced
by `core/Cargo.toml` (the lint) and review (the count).

**TM-8. A dependency enters only by a reviewed change with a written reason.** A
new dependency needs the reason in the changelog and the report, an active
upstream, a clean `cargo deny check`, `cargo audit` and `cargo vet --locked`, and
an exemption, if one is needed, with its justification committed in
`supply-chain/`; the lockfile is committed, Dependabot's updates are reviewed
before merge, and cargo-audit runs daily in CI as the advisory feed, so a
vulnerability published after a crate was added is caught without a code change.
Stops a malicious or abandoned crate reaching the build. Enforced by `gate.sh` and
CI.

**TM-9. Key material is accepted only when signed by the chain to root.** A
grant, suspension, lift, revocation or rotation is stored only when its
signature chain verifies back to the folder's root public key, with every issuer
at or above the tier it grants, and is acted on only while it is valid at that
point in the record order (not revoked or suspended there; expiry ends a key's
presenting at the handshake, which every verifier checks, while its issuing,
revoking, suspending and lifting end only in the signer's own software, since no
verifier can tell when a record was signed: a revocation, suspension or lift by
an entitled key is applied whatever its expiry, a grant it signs later yields a
key that cannot present, and the records it signed stay accepted wherever they
arrive, as `keys.md` fixes); a wrapped key, a grant or a rotation handed over by
a sealed peer or relay is data to be verified, never a reason to act. Stops key
insertion, where a storage party introduces or replaces key material and the
client re-encrypts everything under it (Nextcloud 2024, Albrecht et al.).
Enforced by `keys`; `index` and `engine` call it before storing or applying any
record.

**TM-10. Fail closed.** Any decryption failure, signature failure, chain
failure, hash mismatch or malformed record ends in exactly one of three
outcomes, none of them silent. The connection that delivered it is closed, with
an issue naming the peer and the cause, for what only the sender can be blamed
for: bytes that do not parse or do not verify, a broken order or bound. The item
is rejected and the connection kept for differences in knowledge: the verifier
holds a record the sender may not, or lacks one the sender assumed, and asks for
it. The writer, issuer or signer is flagged under Issues, the item kept as
evidence and applied by no one, and the connection kept, for anything a valid
signature covers, because the body is what its signer made and the sender,
perhaps an honest relay, merely carried it. One refusal is deliberately
uninformative: a folder proof that fails for any reason gets the same uniform
REJECTED and the connection is kept, so that a probe learns nothing about which
folders a device holds; a forged grant inside the proof is answered the same way
(`protocol.md`'s rules table). Nothing is skipped, defaulted or retried with
weaker checks, and no key has a default value; `protocol.md`'s rules table is
the complete record of which cause has which outcome (decision 2026-10-15:
refines the plan's "drops the connection": a failure inside a validly signed
body is charged to its signer and keeps the connection, because the sender may
be an honest relay). Stops the "ghost key", where a missing key became an
all-zero default and failures were skipped silently (Nextcloud 2024). Enforced
by `keys`, `protocol`, `index` and `engine`: every verifying function returns a
typed error and every caller propagates it to the connection;
`clippy::unwrap_used` and `expect_used` are denied.

**TM-11. Wrapped keys are AEAD-sealed with binding associated data, and every
purpose key has its own label.** The folder's data key is wrapped to an issued key
through HPKE with the folder ID, key ID, tier and epoch as associated data, inside
a signed record that names the suite, so a wrap cannot be moved to another folder,
key, tier, epoch or suite; and every
symmetric key, nonce key, chunk-hash key, KEM seed and signing seed is derived from
its parent with BLAKE3 `derive_key` under a distinct label registered in `keys.md`,
so no key serves two protocols. Stops unauthenticated key wrapping used as an
oracle and one key reused across protocols (MEGA 2022, mega-awry.io). Enforced by
`keys`; the labels are in `suites.md` section 2.4 and `keys.md`'s label registry,
their test vectors in `suites.md` section 4.4.

**TM-12. Fresh nonce per write; never a reused nonce under one key.** Every
encryption uses either a 192-bit random nonce from the operating system's
generator or, for chunks only, a nonce derived with a keyed hash from the
plaintext being encrypted under the current epoch key, so that the same key and
nonce never meet two different plaintexts or two different associated data;
re-encryption after a rotation is under a new key. Stops nonce reuse on
re-encryption and the two-time pad it creates (Nextcloud 2024; pCloud, Icedrive
and Seafile 2024). Enforced by `keys` (chunk and record sealing, with
`keys.md`'s chunk vectors) and `engine`, which calls it and never encrypts on
its own; the rule is `suites.md` section 2.3.

**TM-13. Each file record signs its full chunk list.** A file's index record
carries the ordered list of its chunks (their hashes and sizes, as `protocol.md`
lays them out) under the writer's signature, and a receiving peer accepts a chunk
only at the position the record names and only if its hashes match. Stops a store
dropping, reordering, duplicating or substituting chunks unnoticed (pCloud,
Icedrive and Seafile 2024). Enforced by `index`, which owns the record format and
its verification; `engine` checks each chunk against the verified record before it
writes.

**TM-14. Keyed BLAKE3 per folder for chunk hashes; have-queries answered only
inside the folder.** Plaintext chunk hashes use BLAKE3 in keyed mode with a key
derived per folder, so a chunk hash is a fingerprint only to key holders; sealed
peers and relays see hashes of ciphertext only; and a "do you have this chunk"
query is answered only on a connection whose handshake proved a key to that
folder. Stops confirmation-of-a-file through content hashes and deduplication
used as an oracle (Tahoe-LAFS known issues; Harnik, Pinkas and Shulman-Peleg
2010; Syncthing 1.28.0 regression). Enforced by `keys` (`plain_hash`,
`cipher_hash`), `engine` (never hashes plaintext another way) and `protocol`
(have-queries are folder-scoped). What will make "never another way" hold is
cargo-deny: `deny.toml` is to let only `licketysync-keys` and
`licketysync-protocol` depend on `blake3`, an entry that lands with the first of
those crates to merge; `protocol` hashes public values only and never sees
plaintext. Inside those two crates, a Semgrep tripwire in `.semgrep/project.yml`
flags every call into and every import of `blake3` outside `keys`'s labels module
and `protocol`'s hash module, which it excludes by path, outside test files, and
outside a `mod tests`, with its cases in `.semgrep/tests/` run by CI; it catches
mistakes, not intent (`suites.md`, hashing).

**TM-15. Padmé padding of chunk sizes; the volume and timing leak is documented,
not claimed away.** Every chunk is padded by the Padmé rule (at most 12%
overhead, 3% on average) before encryption, so that sizes fingerprint less; what
padding does not hide is listed in section 5 and on the site, including the
CRIME-style length channel that compression before encryption opens when
attacker-influenced bytes share a chunk with secrets: phase 0 compresses
nothing, and a release that enables a compression states the channel first.
Stops size fingerprinting, where 45% of user files have a unique size (PURBs,
Nikitin et al. 2019). Enforced by `keys` (`padme` and the chunk layout) and
`engine` (FastCDC's maximum chunk is at most `MAX_CHUNK_PLAINTEXT`).

**TM-16. Records name their predecessors; equivocation is flagged.** Every index
record carries the hashes of the records it follows, like a Git commit, and each
writer (a key and the device its holder names) keeps one chain numbered by
sequence. A record whose `previous` is not the hash of the writer's chain record
at sequence − 1, or a different record at a sequence where the peer already
holds one, is an equivocation at its own sequence. The writer's fork is the
lowest such sequence the peer has seen, so it moves down as lower ones are found
and never up. The key is flagged under Issues, neither branch is silently
preferred, and the writer's chain is withdrawn from the fork onward: every peer
that has seen the same fork applies the same records, and the records held at
the fork travel in the index exchange so that other peers find it too.
Withdrawal hides records and never deletes them, and a path that becomes absent
through withdrawal goes through the archive and the deletion brake (TM-35),
never a silent unlink. A split is detected the first time two peers holding
different branches exchange cursors for that writer, and not before (the stated
limit): a cursor carries the hash of the requester's record at its applied head
(the lower of its cursor and the sequence before its fork, or its cursor when it
has no fork; nothing when that is 0); a responder whose chain record at that
sequence differs, applied or withdrawn on its side, sends it, at most once per
writer per connection; and a receiver treats a record that differs from its own
at a sequence it holds as an equivocation there, and when it does not hold that
record's parent re-requests the writer from sequence 0, at most once per writer
per connection, so that the lowest collision surfaces. Each mismatch lowers the
requester's fork, so two peers whose forks and applied chains agree exchange
nothing more. Stops equivocation, where one writer gives two peers different
records under the same version and version vectors alone let both believe they
agree (Kleppmann 2022, "Making CRDTs Byzantine fault tolerant"). Enforced by
`index`, and by `engine` for the archive and the brake.

**TM-17. Peers persist the newest version seen and refuse regressions.** Each
peer stores, per folder and per writer, the cursor it advertises: the highest
sequence it holds on the writer's chain, withdrawn records included. The cursor
never decreases, for any cause and on any connection, a sealed peer's or relay's
included; a bounded request from a lower sequence (cutoff recovery, or a record
whose parent the peer does not hold) fetches older records without lowering it,
and fetching older ancestors stays allowed, since the chain needs them. What the
peer applies for the writer ends at its applied head, which never moves
backwards on a peer's say-so and moves back only by two signed causes the peer
itself verified, as `protocol.md` fixes: a stored cutoff (revocation or
suspension), or an equivocation fork (TM-16), after which the applied head is
the last record before the fork. The limit is stated: a peer with no persisted
state for a writer, as on a first sync, trusts the first peer it meets for that
writer, and a stale copy is detected when a fresher peer is met.
Stops rollback, where a store serves an older snapshot as current (Tahoe-LAFS
known issues; Syncthing's untrusted-device spec is silent on it). Enforced by
`index`.

**TM-18. Invite secrets travel only after `#`, and the client origin has no
landing page.** In a link the folder ID, seed and checksum sit in the fragment,
which browsers never send to a server; licketysync.dev serves the client bundle and
nothing else, so no page there logs, redirects or renders a link's secret; the
documentation site links to the client and never carries an invite. Stops secrets
in URLs leaking through referrers, history and landing pages (Resilio Sync 2024;
BitTorrent Sync analysis 2014; Tahoe-LAFS). Enforced by `web` (client) and `site`
(documentation), reviewed in `app` and `cli` wherever a link is built.

**TM-19. Revocation, suspension and epochs.** A revocation or suspension record
spreads like any index record; peers refuse the named key and every key beneath
it, reject records it signs after the record's cutoff, and accept a rotation
only if it wraps the new data key to every write or read key valid in the view
the rotation declares, which they can check because grants are public; a holder
whose grant was left out of that view is told by name who omitted it and is
repaired by a Wrap record from root or an ancestor (plan decision 2026-10-15:
omission is detected, named and repaired, not prevented), and a rotation that
omits a key its own view keeps is rejected as a signer fault; a key ID is
derived from the key's signing and KEM public keys (the all-zero ID is reserved
for root), so two grants for one key carry one ID, are both stored, and raise an
issue naming their issuers, and a wrap to a key ID is encrypted to the KEM key
that ID names; every grant also carries a proof-of-possession signature by the
key it grants (label `licketysync/v1/sig/grant-pop`, over the grant body without
its signatures), verified with the grant's own signing key before anything else
in it is judged, so only a holder of that key's private half, its issuer at mint
time or its holder, can make a grant for it, and a grant without a valid one is
rejected as forged (`protocol.md`'s rules table, decision 2026-10-17); a
revocation or suspension may be signed by the key's issuer, by any ancestor in
its chain to root, or by root, a lift only by the suspension's signer or an
ancestor of that signer, and revoking a key revokes everything issued beneath it
(the plan's rule, Sharing, linked devices and revocation). Stops a key change
that does not propagate, the absence of revocation that Resilio and Syncthing
both have, and a key with "may share" attaching a grant to someone else's key to
gain revoke, suspend or lockout power over it, or to make that key descend from
it so that revoking the attacker would cut the victim off. Enforced by `keys`
(records and chain rules) and `index` (ordering).

**TM-20. Peer-supplied strings render as text only.** Device names, file names,
labels, folder names and every other string that arrived from a peer are rendered
as text, never as HTML or markup, in the web UI, the apps and the CLI's terminal
output, and the UI ships a content security policy that forbids inline script.
Stops peer-controlled names rendered as HTML (Syncthing CVE-2022-46165). Enforced
by `app` and `web`; reviewed in `cli` (terminal escape sequences are stripped).

**TM-21. The local API checks Host and Origin and requires the token on every
request.** The localhost listener accepts a request only if its Host header names
the listener's own address, its Origin header, when present, is the UI's origin,
and the token is present and correct, carried in a request header and never in the
URL; the socket or named pipe is created with permissions for the owning user only.
Stops DNS rebinding and cross-site requests
against the local API (Dorsey 2018; Syncthing's host check). Enforced by `daemon`.

**TM-22. Bounded per-peer tables tied to the connection.** Every table keyed by
peer or request (pending chunks, reservations, registrations, in-flight requests,
have-query state) has a fixed maximum, counts against the Hello's agreed limits,
and is dropped with its connection; libp2p's connection, stream and transient
connection limits are set and tested under a flood; QUIC's three-to-one
anti-amplification limit stays at its default; and the advisory feed in CI
(cargo-audit, daily) catches the next such advisory in a dependency. Stops resource
exhaustion through unbounded streams, connections and registrations, and
amplification through QUIC (go-libp2p and rust-libp2p 2022; rendezvous 2026).
Enforced by `net` and `protocol`; the flood test is in `sim`.

**TM-23. No `unwrap`, `expect`, `panic` or unchecked index on untrusted input.**
`clippy::unwrap_used`, `expect_used` and `panic` are denied workspace-wide,
`indexing_slicing` warns and is fixed, and `.semgrep/project.yml` forbids `expect`
on decoded data in `protocol` and `net`. Stops a remote panic (rust-libp2p 2026
QUIC handshake). Enforced by `core/Cargo.toml` lints and Semgrep.

**TM-24. The DHT uses a daily-rotating discovery hash and runs in client mode by
default.** The announcement hash is derived from the folder ID and the current
day; the node is a client unless the person turns on server mode, which adds a
per-source rate limit and bounded responses; the BEP 44 sequence number is
persisted and never reused, and the BEP 44 signing key, like the node ID, is a
stable identifier the device publishes (section 5); the DHT is off until a folder
turns it on. Stops Sybil and eclipse attacks learning more than one day's peers,
announcement enumeration by crawlers, and `get_peers` amplification (Wang and
Kangasharju; BEP 42; Adamsky 2015). Enforced by `net`.

**TM-25. Relays refuse reservations over relayed connections, bound circuits per
requester, carry ciphertext only, and Private mode relays only for peers that
share a folder.** A relay accepts a reservation only on a direct connection,
limits circuits and bytes per requester, schedules by deficit round-robin so no
client starves, never terminates the end-to-end channel, and in Private mode
serves only peers whose handshake proved a key to a folder it also holds. Stops a
relay learning identities or being used as free bandwidth (Syncthing relay spec;
libp2p circuit relay v2). Enforced by `net`.

**TM-26. Port mapping maps one port for this device, with a bounded lease, removed
at exit.** UPnP, NAT-PMP and PCP requests name only this device's single listening
port and a lease of bounded length, and the mapping is deleted on shutdown. Stops
mappings injected or abused on home routers (UPnProxy 2022; CallStranger 2020).
Enforced by `net`.

**TM-27. The Tauri shell uses the isolation pattern, a content security policy and
per-window capabilities with the smallest command set.** Frontend code reaches the
native core only through commands a window's capability lists, through the
isolation application that validates each message. Stops frontend dependencies
reaching the native core through IPC (Tauri 2 security documentation). Enforced by
`app`.

**TM-28. Each release publishes a signed manifest of the browser bundle's hashes.**
The manifest is signed with the release key, the native app can verify a served
bundle against it, and the site documents WEBCAT and Code Verify-style
verification. The service worker cache gives no protection against the host beyond
its update interval, because the host serves the service worker too; the native
app's manifest check and a verifying extension are the only checks. Stops a
compromised static host serving a changed
client, which subresource integrity cannot catch (W3C SRI; Code Verify; WEBCAT).
Enforced by `web` and the release workflow.

**TM-29. Updates come only through package managers and stores, with signatures
verified before unpacking and no downgrade; releases are signed and carry an SBOM
and provenance.** The program performs no update check and downloads no code; a
package or store update is verified by that channel's signature before any byte is
unpacked, and a version lower than the one installed is refused; every release is
built in CI, signed, and published with a software bill of materials and build
provenance, so a shipped binary can be audited later. Stops auto-update downgrade
and malformed-archive attacks (Syncthing 0.12.23) and tampered or unreproducible
releases. Enforced by the release workflow and each platform's package or store
channel.

**TM-30. Suite lists are bound to the transcript.** The Hello lists the suites each
side supports, the lists are bound into the transcript that the session keys
authenticate, and a mismatch between what was offered and what was seen ends the
connection, so a downgrade is detected rather than negotiated; the protocol version
is chosen as the newest common one, never by the untrusted side alone. Stops the
protocol version chosen by the untrusted side (Seafile 2024) and cipher-suite
downgrade (FREAK, Logjam, POODLE). Enforced by `protocol`; the rule is `suites.md`
section 1.

**TM-31. No host is contacted that `spec/allowed-hosts.txt` does not list.** A
host is added only in the change that adds the feature contacting it, and only
for a feature that is off until the user turns it on. `ci/no-hostnames.sh`
checks hostnames and IPv4 addresses in one-line string literals in the `.rs`
files under `crates/` against the list; it catches accidents, not adversaries,
and states its limits (names under six top-level domains only; not IPv6, not
hosts assembled from pieces, not `Cargo.toml` or included data files), which the
reviewers cover. Stops telemetry, update checks and any contact the user did not
choose. Enforced by `gate.sh` and CI.

**TM-32. Each side proves it holds a folder key without sending it.** The
handshake's folder proof is a signature or key-confirmation bound to the session's
transcript; knowing a folder ID from a LAN beacon or the DHT is not enough to
connect, and a device ID is the hash of the device's public key, which it proves in
the same handshake. Stops impersonation and uninvited connection. Enforced by
`protocol` and `keys`.

**TM-33. The public-key layer is hybrid from version 1, and a hybrid signature
needs both halves.** The data key is wrapped with X-Wing (X25519 plus ML-KEM-768)
through HPKE; grants, revocations, suspensions, rotations and index records are
signed with Ed25519 and ML-DSA-65 over the same domain-separated message, and a
verifier accepts only when both signatures verify, never one; content, names and
structure are encrypted with the data key before they leave the device, so
recorded traffic yields at most what a sealed peer sees. Stops "harvest now,
decrypt later" against recorded traffic and stored wrapped keys, and stops a
hybrid being only as strong as its weaker half. Enforced by `keys`; the
construction is `suites.md` section 2.

**TM-34. Every change is attributable to a key, and to the device its holder
claims.** Each index record carries a device ID under the key's signature, so
the key is proven and the device is the key holder's claim; the handshake proves
a device ID (the DeviceProof) and presents the key ID, so the claim is proven
only for the device that presented the key, and the Keys view shows the claimed
device beside the devices seen presenting the key; device names are
self-reported and marked as such. Because a chain belongs to a key and the device
its holder claims, any holder of a key can sign under another device's ID with
that key and fork that device's chain, which peers then withdraw from the fork
(TM-16); one key per device, the default, confines this to the attacker's own
chain. Recovery is a cutoff naming the chain to keep (phase 7) or a fresh key for
the device. A device restored from a backup re-signs sequences it already used
and equivocates the same way. Stops anonymous changes, and gives the owner what
it needs to revoke precisely: the key, which is what revocation acts on.
Enforced by `index` and `protocol`.

**TM-35. Writes are atomic beneath the root, and destruction is reversible by
default.** A file is downloaded to a temporary file beneath the folder root
(resolved by TM-4), verified against its record, then renamed into place;
replaced and deleted files go to the archive (Trash can, 30 days by default,
phones included); a scan that finds the marker gone, the path unmounted, or more
than the threshold of files missing at once pauses the folder and announces no
deletions until the person confirms. Stops partial files appearing as complete and
limits what a hostile or mistaken writer can destroy. Enforced by `engine`.

**TM-36. The phrase derives everything and nothing derives the phrase.** Every root
key and the identity key derive from the phrase with BLAKE3 `derive_key` under
registered labels; the phrase is stored only on devices marked as root holders,
encrypted at rest by the platform keystore, shown once at creation and again only
behind the operating system's own unlock; other linked devices hold the derived
identity key, which cannot be turned back into the phrase. Stops a lost non-root
device exposing every folder. Enforced by `keys` and `daemon`.

**TM-37. Key strings carry only the folder ID, the seed and a checksum; invites
are bare by default.** Addresses and the certificate hash are appended only by the
issuer's choice, or automatically for browser invites and parcel links; the grant
is a record in the folder, fetched from the first peer met, and a link may also
carry the grant chain (`g=`: the Folder record and the grants to root, public
records verified like any other before use) so that a recipient can join through a
peer that has not received the grant yet. Stops an invite putting
the issuer's home address into an email or chat. Enforced by `keys` (encoding) and
`cli`, `app`, `web` (what is offered).

**TM-38. A revoked key never learns a new epoch.** The rotation that every
revocation triggers wraps the new data key to the public half of every write or
read key its declared view keeps and to nothing else, so the revoked key reads
only data encrypted under epochs it already held; a revocation concurrent with a
rotation whose view still kept the key is honoured by the rotation that follows
it, so the promise holds within one further rotation; a writer that has not yet
heard the revocation keeps writing under the old epoch, and those writes stay
readable by the revoked key until that writer learns of the rotation, which
happens the moment it syncs with any peer that has it; `rekey --full`
re-encrypts existing content for the case where old ciphertext might fall into
its hands later. Stops post-revocation reading of anything new. Enforced by
`keys` and `engine`.

**TM-39. Private key material never leaves through the API, the UI or logs except
by the owner's explicit export.** The local API returns no seed, private key, data
key or phrase; the `owner words` and `owner export` commands and their UI
equivalents require the operating system's own unlock, confirm on the sending
device for a device-to-device transfer, and produce either the phrase or a
passphrase-protected age file. Stops a local process or page with the token, or a
log reader, obtaining keys. Enforced by `daemon`, `cli`, `app`.

**TM-40. Ordering comes from version vectors and hash chains, never from wall
clocks.** No ordering decision, no decision about whether two records conflict,
and no decision about which records are applied, depends on a timestamp. The
only timestamp use in conflict handling is a deterministic tie-break among the
concurrent heads of one path, all of which are kept: the later modification
time, then the smaller record hash, picks the copy at the path, and the others,
where their content differs, become named conflict copies. It never beats a
dominating version vector, and every copy stays a head, so a writer who sets a
future modification time or grinds record hashes gains only which copy is shown
first; a later record that supersedes them all wins by its vector. The
modification time is only ever compared, never subtracted, and a value the local
file system cannot set is an issue raised against the writer, never a panic
(TM-23). Two door-keeping decisions do read the clock, each bounded by the
record layer: presentability (a key past its expiry is not accepted at the
handshake, which every verifier checks; its issuing, revoking, suspending and
lifting end only in the signer's own software, so an entitled key's revocation,
suspension or lift is applied whatever its expiry, and the records it signs stay
accepted wherever they arrive, with revocation as the mechanism relied on) and
the end of a timed suspension (`until`); and the LAN beacon window drops
beacons whose minute is far from the listener's. Everything else the local clock
serves is advisory: lease lengths, the daily discovery hash (looked up for the
neighbouring days too), protocol timeouts and the informational `written_at`
field. Stops clock-skew attacks from a peer or a stolen device with a changed
clock. Enforced by `index` and `engine`.

## 5. What stays visible

A peer-to-peer design cannot hide that it is running or who it talks to, and the
sealed tier exists so that a device without a key can still hold and serve data,
which means some facts about that data are visible to it. The list is honest
because the plan's hardening review found that the systems it studied failed more
often by promising too much than by leaking too much.

**To anyone on the LAN.** That a device runs Lickety-Sync and which port it
listens on; the device's address; in each beacon, under a salt fresh to that
beacon, one hash per announced folder and one hash of the announcer's libp2p
identity key (its peer tag), so that an observer who already knows the folder ID
can confirm it is announced here, an observer who already knows the device's
identity key (anyone it has connected to) can confirm that device is announcing,
and an observer who knows neither cannot link two beacons to one folder or to
one device from the beacons' contents (the source address links beacons from one
interface, which no hashing hides); and, by replaying a captured beacon from its
own address within the ±5-minute window listeners accept, which devices dial it
and so hold the folder the beacon named, without knowing that folder's ID: the
dial is the signal, and `keys.md` (discovery hashes) records it
as the residual leak the design accepts.

**To a network observer.** That two addresses talk, when, for how long and how
much; the sizes and number of encrypted frames, which approximate padded chunk
sizes and counts; QUIC and TLS handshake metadata; on a locked-down network, the
hostname of the HTTPS listener, timing and volume. Not contents, names, keys or
folder IDs, and not the peer ID: in TLS 1.3, QUIC and Noise XX the identity key
travels encrypted, so a passive observer does not learn which device is talking.
Whoever completes a connection to a device, with no key to anything, learns
more: its libp2p peer ID, which is stable because it derives from the device's
libp2p identity key, so the device can be recognised across networks, days and
folders (the hashed form in LAN beacons confirms it to anyone who already holds
the key; DHT address records carry no peer ID); its device ID and hybrid public
key, proven by the DeviceProof before any folder is named; the protocols it
offers in multistream-select; its suite, compression, hash and feature lists and
limits from the Hello; for a folder ID the connecting party already holds,
whether the device holds that folder, from the timing of the uniform REJECTED
proof result; and, from the time its first REJECTED folder proof takes, a coarse
count of the folders the device holds (about 6 µs at 1 folder and 1.4 ms at
2000; a constant-cost lookup table is a phase 7 follow-up). Not its name: the
self-reported device name is sent only after a folder has opened on the
connection, in the first Status after the first folder opens, so only a peer that
has opened a folder with the device learns its name.

**To the DHT and anyone crawling it.** Which addresses announce a given day's
discovery hash; a signed address record under the device's DHT key. The hash
does not reveal the folder ID and changes daily, but anyone who ever held the
folder ID (a sealed peer, a relay, anyone who saw an invite string) can compute
every day's hash and watch who announces it, and a device is linkable across
days by a stable address alone or by any stable identifier it publishes with the
announcement: the BEP 44 signing key its address record is signed with, or a
persisted DHT node ID. The record carries no libp2p peer ID; the DeviceProof
binds identity at the handshake. The libp2p identity key still gives every
device a stable peer ID, which is a cross-folder tracking handle for anyone the
device connects to: they can tell it is the same device whatever folder, day or
address is involved; `suites.md` (the libp2p identity key) records the
per-folder or rotating identity that would remove the handle as a considered
alternative.

**To a relay.** Both endpoints' addresses, the folder a reservation names (as its
ID), timing and volume, and the sizes and number of encrypted frames, which
approximate padded chunk sizes and counts. Not contents, names or keys: the
end-to-end channel runs inside the relayed connection.

**To a sealed peer.** Everything a relay sees, and: the folder ID; every grant,
suspension, lift, revocation and rotation, which are public records, so the
grant graph with key IDs, tiers, issuers, expiries and "may share" flags; device
IDs from the handshake and self-chosen device names from the first Status once
the folder opens; the clear fields of every index record, which `protocol.md`
(the index record on the wire) fixes: the writer key ID and device ID, the
sequence number and the hash chain (`previous`, `supersedes` and `resumes`, the
last naming the Suspension whose cutoff a restart record continues), the version
vector with its device IDs and counters, the epoch, whether the record is a
tombstone (sealed peers must see deletions to garbage-collect chunks), the
number of chunks with each chunk's padded stored length, ciphertext hash and the
epoch that encrypted it, and the padded length of the sealed part; the number of
index records and the rate at which they arrive; the Status message every peer
sends for each open folder (records held, ciphertext bytes still to fetch,
whether it is paused, free disk space); which chunks are identical, because
content-derived nonces make identical plaintext under one epoch key identical
ciphertext (the cost of letting sealed peers verify and deduplicate); the epoch
number and when it changed; approximate total size of the folder; activity
patterns in time. Not the path, kind, true size, times, mode, plaintext hashes
or `written_at`: those sit in the sealed part, which is Padmé-padded, so its
length says little about the path length or the chunk count. Padmé padding
reduces size fingerprinting of individual chunks to within 12%; it does not hide
the number of chunks, the total volume, or when changes happen. A sealed peer
can also show a stale snapshot to a peer that has no persisted state yet for a
writer, such as one on its first sync; the regression is detected when that peer
meets a fresher one (TM-17). Compression inside the encrypted chunk, when a
folder enables it, is a CRIME-style length channel: where bytes an attacker can
influence share a chunk with secrets, the padded size reveals how well they
compressed together. Padmé blunts it (2 KiB granularity at 64 KiB, 128 KiB at 4
MiB) but does not remove it; phase 0 uses no compression, and the release that
enables one states this channel on the site before it ships (TM-15).

**To a key holder.** A write or read key holder sees everything in the folder,
every other peer's device ID, name, key ID and tier, and the grant graph. A key
holder with the chunk-hash key can test whether a guessed file is in the folder:
keyed hashes stop outsiders, not members.

**To a corporate proxy on a locked-down network.** The hostname dialled, timing and
volume; the Noise handshake runs inside the WebSocket, so a proxy that terminates
the outer TLS sees encrypted frames.

**To a future quantum computer with recorded traffic.** The transport's X25519
share where a path used Noise or a classical TLS group, and therefore the
contents of that transport session: handshake identities, Hello contents, record
envelopes, chunk ciphertext. That includes every WebSocket session, and so any
session an attacker forced onto that path by blocking UDP and raw TCP (section
3.1): as `libp2p-websocket` ships, its outer TLS is rustls on `ring` and the
Noise inside is classical, so both layers fall (`suites.md`, transport, records
the deviation and the phase 2 change that gives the outer TLS the post-quantum
group). The data key is wrapped with a hybrid KEM and content is encrypted under
it before transport, so the recovered session reveals what a sealed peer sees
and nothing more.

## 6. How to use this document

For the author of a change: cite the requirement your change satisfies or depends
on in the code comment and the test name, and list the numbers in the changelog
entry. If your change needs a rule this file lacks, propose the new TM number in
your report; do not add it yourself.

For the two reviewers of every change: section 4 is the checklist for the
"security" line of the review. Read the requirements whose enforcing crate or
reviewed-in layer your diff touches, and confirm each is still true after the
change, with a test that would fail if it were not.

For the security-reviewer pass (every change touching `keys`, `protocol`, file
paths or the local API, and every phase gate): work from sections 3 and 4
together. For each adversary in section 3 whose "Can" list the change could
widen or whose "Cannot" list it could weaken, name the TM numbers that carry the
promise and check the change against each. The pass ends with a plain-language
summary for the owner: what the change does, what it risks, how to try it by hand.
A finding blocks the commit until it is fixed and re-reviewed, or the reviewer
agrees it is not one; "the plan says so" is not a defence against a finding, it is
a reason to raise the conflict.

For every phase gate: the gate's reviewer walks all forty requirements against the
code that exists and records, per requirement, enforced, partly enforced (with
what is missing) or not yet applicable (with the phase that will make it so).

## Appendix: incidents and sources cited

Read on 2026-10-14 for the plan's hardening review; the plan's Sources section
holds the full list.

- Nextcloud 2024 (key insertion, ghost key): Albrecht et al., "Breaking Nextcloud
  End-to-End Encryption", https://eprint.iacr.org/2024/546.pdf
- pCloud, Icedrive, Seafile and others 2024: Albrecht and Backendal, "End-to-End
  Encrypted Cloud Storage in the Wild", https://eprint.iacr.org/2024/1616.pdf
- MEGA 2022: Backendal, Haller and Paterson, https://mega-awry.io/
- Tahoe-LAFS known issues:
  https://tahoe-lafs.readthedocs.io/en/stable/known_issues.html
- Harnik, Pinkas and Shulman-Peleg 2010, "Side Channels in Cloud Services:
  Deduplication in Cloud Storage", https://www.pinkas.net/PAPERS/hps.pdf
- PURBs 2019: Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
  Communication with PURBs", https://www.petsymposium.org/popets/2019/popets-2019-0056.pdf
- Kleppmann 2022, "Making CRDTs Byzantine Fault Tolerant",
  https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf
- Syncthing advisories (CVE-2017-1000420 versioning traversal; CVE-2022-46165
  HTML in device names; 0.12.23 update handling; 1.28.0 untrusted regression):
  https://github.com/syncthing/syncthing/security/advisories; untrusted-device
  spec: https://docs.syncthing.net/specs/untrusted.html; relay spec:
  https://docs.syncthing.net/users/strelaysrv.html
- BitTorrent Sync analysis 2014 (Hackito Ergo Sum):
  https://2014.hackitoergosum.org/bittorrentsync-security-privacy-analysis-hackito-session-results/
- Dorsey 2018, DNS rebinding against local services (Google Home, Sonos, Roku,
  Radio Thermostat): https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325
- libp2p resource exhaustion 2022: https://github.com/libp2p/rust-libp2p/security/advisories
  and the go-libp2p advisories of the same year; rendezvous 2026 and the QUIC
  handshake panic 2026 are in the same list
- Mainline DHT: Wang and Kangasharju, "Real-world Sybil attacks in BitTorrent
  Mainline DHT", https://www.cl.cam.ac.uk/~lw525/publications/security.pdf; BEP 42,
  https://bittorrent.org/beps/bep_0042.html; Adamsky et al. 2015, "P2P File-Sharing
  in Hell: Exploiting BitTorrent Vulnerabilities to Launch Distributed Reflective
  DoS Attacks", https://www.usenix.org/system/files/conference/woot15/woot15-paper-adamsky.pdf
- UPnProxy 2022 (Akamai) and CallStranger 2020 (CVE-2020-12695): router port
  mapping abuse
- libp2p circuit relay v2: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
- Tauri 2 security documentation: isolation pattern, capabilities, CSP
- W3C Subresource Integrity; Meta's Code Verify; WEBCAT (Freedom of the Press
  Foundation): what SRI cannot do against a page's own host, and how an extension
  can
- Seafile 2024 protocol version downgrade: in Albrecht and Backendal above
- FREAK, Logjam, POODLE: cipher-suite negotiation failures that TLS 1.3 answered by
  shrinking the menu
