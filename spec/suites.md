# Lickety-Sync cryptographic suites

Version 1, 2026-10-14. This file names every algorithm, parameter and crate that
may perform cryptography in this workspace, the apps and the browser client. It is
normative: first-party code uses nothing that is not listed here, and a change that
needs something else adds it here first, with the reason, and is reviewed as a
change to the key model. `threat-model.md` says what these choices must achieve
(TM-5, TM-11, TM-12, TM-30, TM-33); `keys.md` says which key is derived from which
and holds the label registry and every associated-data layout; `protocol.md` says
where each primitive appears on the wire. This file refers to both by topic, never
by section number, so that they can be reorganised without breaking it.

The plan's Security paragraph lists the approved crates by name and its Encrypted
connections section lists the algorithms; this file pins versions, fixes
parameters and encodings, and records what was checked on 2026-10-14. Where this
file decides something the plan leaves open, the decision is marked **(decision)**
and listed in the change's report so the plan can record it.

## 1. The rule: suites are whole sets

A suite is one complete set of algorithms that work together, identified by one
number. There is no negotiation of individual parts, because a menu of parts is
what let SSL's cipher-suite lists be downgraded (FREAK, Logjam, POODLE) and what
TLS 1.3 fixed by shrinking the menu to a handful of whole suites.

- **Every record and every key carries a suite number.** It is an unsigned 16-bit
  integer. 0 is invalid and never appears on the wire or on disk. 1 is the suite in
  section 2. A record, grant, wrapped key, signature or encrypted blob is entirely
  under one suite; its suite number is inside the signed or authenticated bytes, so
  it cannot be changed without detection.
- **A suite is a whole set, never a menu.** It fixes the key encapsulation, the
  signature, the data cipher, the hash, the key derivation and the passphrase
  function together. Code never combines a part of one suite with a part of
  another, and no message offers a choice of parts.
- **Suite lists in Hello are bound to the transcript.** Each side's Hello lists the
  suites it supports, preferred first. Both lists are included in the handshake
  transcript that the session keys authenticate, so if either side sees a list
  other than the one its peer sent, the handshake fails and the connection is
  dropped (TM-30). A downgrade is therefore detected, not negotiated. `protocol.md`
  specifies the transcript.
- **A folder has a minimum suite.** The folder's metadata, signed by root, names
  the lowest suite a peer may use for that folder. A peer whose key or records are
  below the minimum gets the same uniform REJECTED result as any other failed
  folder proof, so that a probe learns nothing; the refusing side records both
  numbers under Issues. Records below the minimum are rejected.
- **Retiring an algorithm drops its suite.** A release that retires a weak
  algorithm removes its suite from the set the code will use at all; folders raise
  their minimum by a signed metadata change, which the UI offers when every known
  peer supports the newer suite.
- **Rotation moves a folder to a new suite.** A rotation record under the new suite
  re-wraps the data key to every valid key under the new suite's KEM; `rekey --full`
  re-encrypts existing content under the new suite's cipher. During a migration a
  folder holds records of more than one suite, all at or above the minimum.
- **A new signature algorithm needs a new root while the old one still holds.**
  Root keys derive from the recovery phrase, so a new signature algorithm means a
  new root public key derived from the same phrase under the new suite's labels,
  installed by a root-rotation record signed by the old root. This must happen
  while the old algorithm is still believed secure; once it is broken, a
  root-rotation record signed by it proves nothing. Releases that add a signature
  suite therefore prompt the owner to rotate root promptly.
- **Hybrid means both.** Where a suite pairs a classical and a post-quantum
  algorithm, both are always used and both must succeed; there is no mode that
  accepts one of the two (TM-33).

## 2. Suite 1

Suite 1 is the set the plan names: X-Wing through HPKE for key encapsulation,
Ed25519 plus ML-DSA-65 for signatures, XChaCha20-Poly1305 for data, BLAKE3 for
hashing and key derivation, Argon2id for passphrases, and TLS 1.3 or Noise on the
transport. The 256-bit symmetric parts survive a quantum computer (Grover halves
them to 128 bits); the public-key parts are hybrid so that an attacker must break
both halves.

| Role | Algorithm | Crate (pinned range) | Sizes |
| --- | --- | --- | --- |
| Key encapsulation | X-Wing (X25519 + ML-KEM-768) as the KEM of HPKE (RFC 9180), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 | `hpke` 0.14, which uses `x-wing` 0.1, `ml-kem` 0.3, `x25519-dalek` 3 | public key 1216, secret seed 32, encapsulation 1120, shared secret 32 |
| Signature | Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204), both required | `ed25519-dalek` 3, `ml-dsa` 0.1 | public key 32 + 1952 = 1984, signature 64 + 3309 = 3373, each secret a 32-byte seed |
| Data encryption | XChaCha20-Poly1305 | `chacha20poly1305` 0.11 | key 32, nonce 24, tag 16 |
| Hash and key derivation | BLAKE3: hash, keyed hash, derive_key | `blake3` 1 | output 32, key 32 |
| Passphrase | Argon2id v1.3, m = 64 MiB, t = 3, p = 4 | `argon2` 0.6 | salt 16, output 32 |
| Exported root file | age v1, passphrase recipient (scrypt) | `age` 0.12 | as the age specification |
| Transport | TLS 1.3 with X25519MLKEM768 over QUIC and TCP; Noise XX inside WebSocket, WebTransport and WebRTC (the WebSocket path is classical end to end as `libp2p-websocket` ships, section 2.6) | `rustls` 0.23 on `aws-lc-rs` 1; `libp2p-tls`, `libp2p-quic`, `libp2p-noise`, `libp2p-websocket`, `libp2p-identity` | as the transports specify |

### 2.1 Key encapsulation: X-Wing through HPKE

The folder's data key must reach every issued key without any party in the middle
learning it, and the wrapped copies sit on every sealed peer for years, so this is
where "harvest now, decrypt later" bites first. X-Wing is the hybrid KEM that
combines exactly the two algorithms the plan names, and HPKE is the standard way to
turn a KEM into authenticated encryption of a small payload. Nothing in this
section is written by us: the crates are used as published, and the only
first-party work is choosing their parameters and feeding them the right bytes.

**X-Wing.** draft-connolly-cfrg-xwing-kem (an individual Internet-Draft submitted
to the CFRG, Informational, not a working-group document; revision 11 current on
2026-10-14). X-Wing combines ML-KEM-768 (FIPS 203, final)
and X25519 (RFC 7748) with the combiner

    ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)

where XWingLabel is the six ASCII bytes `\./` `/^\` (hex `5c2e2f2f5e5c`). Sizes:
encapsulation (public) key 1216 bytes (1184 ML-KEM-768 + 32 X25519),
decapsulation (secret) key 32 bytes (a seed, expanded with SHAKE-256 into the
ML-KEM seed and the X25519 secret), ciphertext 1120 bytes (1088 + 32), shared
secret 32 bytes. Draft -06 and draft -11 differ only editorially: the change log
from -06 onward lists an ASN.1 module, a PEM header correction, a wording change
on SHAKE output units and text on randomized versus derandomized functions, none
of which touches the combiner, label, encodings or test vectors, so a draft-06
implementation interoperates with -11. If a later draft changes the combiner or
label, that is suite 2 (section 5).

**HPKE.** RFC 9180, mode_base (0x00), with KEM X-Wing (identifier 0x647a,
requested by the X-Wing draft and used by the `hpke` crate), KDF HKDF-SHA256
(0x0001) and AEAD ChaCha20-Poly1305 (0x0003). The single-shot API is used:
`seal(pkR, info, aad, pt)` on the sender and `open(skR, enc, info, aad, ct)` on the
receiver. Wrapping is always to one recipient key; a rotation that wraps to many
keys performs one seal per key.

- `info` is the ASCII label `licketysync/v1/wrap/<purpose>` with no terminator;
  `licketysync/v1/wrap/data-key` is the data-key wrap, and `keys.md` registers any
  other purpose (the linked-device channel may be one).
- `aad` is the layout `keys.md` specifies for the purpose and binds the folder ID,
  the key ID, the tier and the epoch (TM-11); for the data-key wrap it is
  `folder_id || key_id || u8(tier) || be64(epoch)`. It is never empty. The suite is
  bound by the signed record that carries the wrap, whose body begins with it.
- The wire form of a wrapped value is `enc || ct`: 1120 bytes of encapsulation
  followed by the AEAD ciphertext. A wrapped 32-byte data key is therefore
  1120 + 32 + 16 = 1168 bytes.
- Any failure of `open` is a hard error with no fallback key. The wrap sits in a
  validly signed body, so the outcome is TM-10's signer-fault outcome: the
  issuer or rotator that produced the wrap is flagged, the record is rejected,
  and the connection is kept, as `protocol.md`'s rules table records.

**What exists off the shelf (checked 2026-10-14).** The question the plan left open
was whether an HPKE implementation with an X-Wing KEM exists so that no combiner
is written here. It does:

| Crate | Version | What it offers | Status |
| --- | --- | --- | --- |
| `x-wing` (RustCrypto/KEMs) | 0.1.1, 2026-10-01 | X-Wing per draft -06 on `ml-kem` 0.3 and `x25519-dalek` 3; implements the `kem` crate's `Encapsulate` and `Decapsulate`; `DecapsulationKey: From<[u8; 32]>` and `KeyInit` for seed import; `zeroize` feature | "has never been independently audited" (its README) |
| `ml-kem` (RustCrypto) | 0.3.2, 2026-05-10 | ML-KEM per FIPS 203 final; pure Rust; no default features; `zeroize` feature | not independently audited (its README) |
| `hpke` (rozbb, rust-hpke) | 0.14.1, 2026-09-06 | RFC 9180 in pure Rust; KEMs include `kem::XWing` (KEM_ID 0x647a) built on `x-wing` 0.1 and `ml-kem` 0.3, plus ML-KEM-768/1024 and the P-256 and P-384 hybrids; KDFs HKDF-SHA256/384/512 and SHAKE; AEADs ChaCha20-Poly1305 and AES-GCM-128/256; features `x25519`, `mlkem`, `chacha`; MSRV 1.85; builds for wasm32 | Cloudflare reviewed version 0.8; "nobody has performed a paid audit of this crate" (its README) |
| `hpke-rs` (Cryspen, libcrux) | 0.8.0, 2026-10-07 | RFC 9180 with pluggable backends; `hpke-rs-libcrux` is formally verified but "with limited ciphersuite support for now"; `hpke-rs-rust-crypto` uses RustCrypto; X-Wing listed as draft -06 | no audit stated |
| `aws-lc-rs` | 1.18.2, 2026-10-12 | ML-KEM and ML-DSA through its post-quantum modules; TLS key exchange X25519MLKEM768 for rustls; no HPKE API and no X-Wing; needs a C compiler; does not build for wasm32-unknown-unknown | AWS-LC's FIPS build is FIPS 140-3 validated; the Rust bindings are AWS-maintained |
| `rustls::crypto::aws_lc_rs::hpke` | with rustls 0.23 | HPKE for Encrypted Client Hello only; DHKEM suites only, no X-Wing | part of rustls |

**Decision (decision).** Suite 1 uses `hpke` 0.14 with `hpke::kem::XWing`,
`hpke::kdf::HkdfSha256` and `hpke::aead::ChaCha20Poly1305`, with default features
off and the `x25519`, `mlkem`, `hkdfsha2`, `chacha` and `alloc` features on
(`HkdfSha256` is behind `hkdfsha2`; the single-shot `seal` and `open` that return
a buffer are behind `alloc`). The `getrandom` feature stays off: the sender calls
`single_shot_seal_with_rng` with the generator section 4.3 allows, so that the
crate never picks its own source (`single_shot_seal` needs `getrandom` and draws
from the system generator itself). It is the only crate
that offers X-Wing inside a complete, standard HPKE in pure Rust and builds for
every target including the browser. No combiner, KDF step or AEAD call is written
in this workspace. `hpke-rs` with its libcrux backend is the named fallback if
`hpke` stalls or its X-Wing support is removed, and is also the second
implementation the test suite cross-checks against (section 4.4). Before phase 2
ships a wrap to anyone: the `keys` crate's use of HPKE gets a security-reviewer
pass against TM-9, TM-10, TM-11 and TM-33, the Tamarin or ProVerif model of the key
model (plan, Engineering practice checks table) includes the wrap, and the
implementation passes the X-Wing draft's test vectors and an interoperability test
against a second implementation.

**Keys from seeds.** Every key in the system is a **key pair set** derived from
one 32-byte seed (`keys.md`, key pair sets): the KEM half is
`<hpke::kem::XWing as hpke::Kem>::PrivateKey`, loaded with
`hpke::Deserializable::from_bytes(&blake3::derive_key("licketysync/v1/key/x-wing", seed))`
(the `kem::xwing` module is crate-private; the trait path is the public one), with
the public key taken from it. The derived 32 bytes are the X-Wing decapsulation
seed exactly as the draft defines it, loaded as such: the private key's
`from_bytes` wraps `x_wing::DecapsulationKey::from(seed)`. HPKE's `derive_keypair` is never
used for this, because it would expand the bytes once more with SHAKE-256 and
yield a different key; a test vector pins the keypair for a fixed seed (section
4.4). The same seed therefore yields the same keypair on every device, nothing but
the seed need be stored, and first-party code depends on `hpke` alone, never on
`x-wing` directly.

**Caveats stated plainly (decision, deviation from the plan's "audited crates").**
None of `x-wing`, `ml-kem` or `hpke` has had a paid independent audit; `ml-kem`
and `x-wing` are RustCrypto crates whose READMEs say so, and the same is true of
`ml-dsa`. The plan's Security paragraph asks for "an approved list of audited
crates"; for the post-quantum primitives no audited Rust crate exists, so suite 1
uses these unaudited ones, because the alternatives (writing a combiner, or binding
a C library that has no X-Wing and no HPKE) are worse. Section 3.1's audit-status
column records this per crate, and a paid audit stays the option the plan lists
for later. X-Wing itself is an Internet-Draft, not an RFC; its construction has a
published security proof (Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner,
Westerbaan, 2024) and is the X25519 + ML-KEM-768 hybrid that most implementations
have converged on.

### 2.2 Signatures: Ed25519 and ML-DSA-65, both required

Grants, revocations, suspensions, lifts, rotations and index records are signed, and
a forged signature is a forged key or a forged change. A hybrid that accepted
either half would be only as strong as the weaker, and an attacker could strip the
half they cannot break; so a hybrid signature here is both signatures over the
same bytes, and verification requires both to verify **(decision)**.

**Components.**

- Ed25519 as RFC 8032 pure Ed25519: no prehashing (not Ed25519ph), no context
  string (not Ed25519ctx). Public key 32 bytes, signature 64 bytes, secret a 32-byte
  seed. Crate `ed25519-dalek` 3 with the default features (`zeroize`, `fast`) and
  never `legacy_compatibility` or `hazmat`. Verification uses `verify_strict`, which
  rejects small-order and non-canonical components, so signatures are strongly
  unforgeable and not malleable.
- ML-DSA-65 as FIPS 204 (final), security category 3, with an empty context
  string; hedged or deterministic signing as "Signing variant" below says.
  Public key 1952 bytes, signature 3309 bytes, secret a 32-byte seed ξ expanded
  by `ML-DSA.KeyGen_internal` (FIPS 204 Algorithm 6). Crate `ml-dsa` 0.1 with
  `default-features = false` and the `zeroize`, `rand_core` and `alloc` features
  (`sign_randomized` is behind `rand_core`; `alloc` keeps the expanded signing key
  in one heap allocation rather than in copies on the stack **(decision)**);
  `SigningKey::<MlDsa65>::from_seed(&xi)` is the constructor, and signing goes
  through its `ExpandedSigningKey`: `sign_randomized` (hedged) in production,
  `sign_deterministic` for vectors, both with an empty context.

**Domain separation.** Every record type has a label. The bytes signed are

    M = label || 0x00 || body

where `label` is the ASCII string `licketysync/v1/sig/<record-type>` and `body` is
the record's canonical encoding, which already contains the suite number.
`<record-type>` is one of the names `keys.md` and `protocol.md` register (`folder`,
`grant`, `grant-pop`, `rotation`, `wrap`, `revocation`, `suspension`, `lift`,
`root-rotation`, `index`, `folder-proof`, `device-proof`, and any the browser
bundle manifest adds).
Both signatures are computed over exactly `M`; the ML-DSA context string stays empty
because the label in `M` already separates domains. A label is never reused for two
record layouts; a layout change is a new label.

**Signature encoding.** Fixed length, Ed25519 first: `sig = ed25519_sig (64) ||
mldsa65_sig (3309)`, 3373 bytes. A signature field of any other length is
malformed and the record is rejected before any verification runs.

**Public key encoding.** Fixed length, Ed25519 first: `pk = ed25519_pk (32) ||
mldsa65_pk (1952)`, 1984 bytes. A public key of any other length is malformed. Where
a key is identified rather than carried, the key ID is derived from both of its
public keys: `key_id = H("licketysync/v1/hash/id/key", be16(suite) || signing_pk ||
kem_pk)[0..16]`, with `kem_pk` the key's 1216-byte X-Wing public key (decision
2026-10-15, when it replaced 16 random bytes; `kem_pk` added 2026-10-17, so that the
ID also names the key a wrap to it is encrypted to, and a bare-string joiner derives
both halves from its seed). Uniqueness is then by construction, one ID per key, and
a verifier that sees two grants for one key stores both and raises an issue naming
the issuers, rather than guessing which to keep. The all-zero key ID (16 zero bytes)
is reserved: it names root, which has no grant, wherever an issuer or a wrap's
recipient is named, and a derived ID that is all zero is malformed (`keys.md`, key
IDs). Where a folder, device or identity is identified, the ID is the full 32-byte
labelled hash `H("licketysync/v1/hash/id/<kind>", be16(suite) || signing_pk)` of
section 2.4.

**Proof of possession in every grant (decision 2026-10-17).** A grant carries,
beside its issuer's hybrid signature, a hybrid signature by the key it grants: `M`
under the label `licketysync/v1/sig/grant-pop` over the grant body without its
signatures, verified with the grant's own `signing_pk` before anything else in the
grant is judged; a grant whose proof is missing or does not verify is forged
(`protocol.md`'s rules table). Only a holder of a key's private half, its issuer at
mint time or its holder, can therefore make a grant for it, so a key with "may
share" cannot attach a grant to someone else's key and so gain revoke, suspend or
lockout power over it, or make it descend from the attacker (TM-19).

**Verification.** `verify(pk, M, sig)` splits both fields at their fixed offsets,
runs Ed25519 `verify_strict` and ML-DSA-65 `verify`, and succeeds only if both
succeed. Both are always run; an implementation does not stop at the first
failure, so that timing does not say which half failed (both operations are on
public data, so this is hygiene, not a secrecy requirement). There is no
single-algorithm verification path anywhere in first-party code.

**Keys from seeds.** The two secret seeds derive from the issued key's 32-byte seed
(or, for root, from the phrase and the folder nonce as `keys.md` specifies):
`derive_key("licketysync/v1/key/ed25519", seed)` and
`derive_key("licketysync/v1/key/ml-dsa-65", seed)`. Only the seed is stored.

**Signing variant.** Ed25519 is deterministic by definition. FIPS 204 allows ML-DSA
to sign hedged (with 32 fresh random bytes) or deterministically, and a verifier
cannot tell which was used, so the choice is the signer's, not the suite's
**(decision)**: test vectors use `sign_deterministic` so that they reproduce;
production signing uses `sign_randomized` with the infallible `getrandom`-backed
generator of section 4.3 (a failure of the system generator exits the daemon with a
distinct exit code rather than reach the signer), because hedging resists fault
attacks on the signing
device and a weak generator cannot make it worse than deterministic. `ml-dsa` 0.1.1
exposes both on `ExpandedSigningKey`, each taking a context, which stays empty by
choice. Two signatures over one body may therefore differ; `keys.md` identifies a
record by the hash of its body, never of its signature.

### 2.3 Data encryption: XChaCha20-Poly1305

The plan allows XChaCha20-Poly1305 or AES-256-GCM; suite 1 uses XChaCha20-Poly1305
**(decision)**. Its 192-bit nonce makes the content-derived nonces that sealed-peer
deduplication needs safe, since the space is far too large for a derived nonce to
collide with any random one, and it has no hardware dependence, so the browser
build and old ARM devices run it at full speed and without the timing side
channels of software AES. AES-256-GCM, with its 96-bit nonce, may become a later
suite.

**Definition.** XChaCha20-Poly1305 as in draft-irtf-cfrg-xchacha-03: HChaCha20
derives a subkey from the key and the first 16 bytes of the nonce, then
ChaCha20-Poly1305 (RFC 8439) runs with the remaining 8 nonce bytes. Key 32 bytes,
nonce 24 bytes, tag 16 bytes, ciphertext length = plaintext length + 16. It is a
CFRG draft rather than an RFC, and the most widely deployed AEAD in libsodium and
its ports; its construction is a thin, standard extension of RFC 8439. Crate
`chacha20poly1305` 0.11, type `XChaCha20Poly1305`; this crate has had one security
audit (NCC Group, 2020, no significant findings).

**Nonce rules (TM-12).**

1. **Chunks: content-derived.** The nonce of a chunk is the first 24 bytes of
   BLAKE3 in keyed mode, keyed with the epoch's chunk-nonce key `nk_e` (derived
   from the data key `dk_e` under its own label, `keys.md`, keys derived from a
   data key), over the
   plaintext chunk exactly as it is encrypted, header and Padmé padding included.
   The same plaintext under the same epoch key therefore yields the same
   ciphertext, which lets a sealed peer verify and
   deduplicate; two different plaintexts cannot share a nonce under one key unless
   BLAKE3 collides. This is the plan's sealed-peer rule, and its cost is stated in
   `threat-model.md` section 5: identical chunks look identical.
2. **Everything else: random.** Every other encryption (index records, wrapped
   values other than HPKE's own, the catalogue, the local key store) uses 24 bytes
   from the operating system's generator (section 4.3), drawn fresh for every
   encryption and never stored for reuse.
3. **Never reuse on re-encryption.** A (key, nonce) pair is used twice only when
   the plaintext **and** the associated data are both byte-identical, because the
   Poly1305 key is the first block of the keystream for that (key, nonce) and a
   second message under it with different bytes forges or leaks. Rule 1 makes this
   true for chunks: the nonce is a function of the padded plaintext, and the chunk
   associated data, `folder_id || be64(epoch)`, is a function of the key alone, so
   identical plaintext under one epoch key always meets identical associated data.
   After a rotation, every re-encryption is under the new epoch's key, so no old
   (key, nonce) pair recurs.
4. **One key, bounded use.** No key is asked to encrypt more than 2^32 messages or
   more than 2^38 bytes in one message, and no counter is kept to enforce it: the
   bound holds by arithmetic. A chunk is at most 4 MiB (`MAX_CHUNK_PLAINTEXT`), a
   192-bit random nonce stays collision-free far beyond 2^32 messages, and derived
   chunk nonces collide only if BLAKE3 does; keys also change with every epoch.

**Compression before encryption.** A chunk may be compressed before it is padded
and encrypted (`keys.md`, chunk encryption; the code sits inside the ciphertext).
Compression under encryption is a CRIME-style length channel: when bytes an
attacker can influence share a chunk with secrets, the padded ciphertext size
reveals how well the two compressed together. Padmé blunts the channel (2 KiB
granularity at 64 KiB, 128 KiB at 4 MiB) and does not remove it. Phase 0 uses no
compression; the release that enables one states the channel in `threat-model.md`
section 5 and on the site before it ships.

**Associated data.** Always present and never empty. The caller's specification
names it: `keys.md` for wrapped keys, the epoch ladder, chunks and the catalogue,
`protocol.md` for index records and handshake payloads. Every layout binds at least the
folder ID and whatever identifies the purpose (the grant wrap's
`folder_id || key_id || u8(tier) || be64(epoch)`, a chunk's
`folder_id || be64(epoch)`), so a ciphertext cannot be moved to another folder,
epoch or purpose; the suite is bound by the key, which exists under one suite only.

### 2.4 Hashing and key derivation: BLAKE3

BLAKE3 has three modes that are domain-separated from each other by construction:
plain hashing, keyed hashing, and key derivation from a context string. Suite 1
uses them for four jobs, each with its own rule and its own labels, so no two jobs
can produce the same output from the same input. `keys.md`'s label registry lists
every label in use and is the one place a label is added; the rows below that
belong to the primitives are copied from it and must stay identical to it. Output
is always 32 bytes, truncated only where the registry says so (a 16-byte key ID,
LAN beacon ID, peer tag and link beacon ID under `licketysync/v1/link/discovery`,
a 20-byte DHT ID); the extendable-output mode is not used. Crate `blake3` 1 in
its default build, which is not pure Rust: on x86-64 its build script compiles the
upstream assembly with `cc`, and on little-endian AArch64 the C NEON code (the
`pure` feature would turn both off); WebAssembly gets SIMD only through the
`wasm32_simd` feature, which is not enabled, so the browser build runs the
portable Rust code. Its unsafe and foreign code is accepted and shows in
cargo-geiger's report. The `rayon` feature may be used for large files, nothing
else.

- **The labelled hash `H` for every identifier and link over public data.**
  `H(label, x) = BLAKE3(label || 0x00 || x)`, with `label` an ASCII label under
  `licketysync/v1/hash/`. It names folders, devices and identities, records and
  stored chunks, the discovery hashes and the handshake transcript. Plain
  `BLAKE3(x)` without a label appears nowhere in first-party code: the label is
  part of the hashed bytes, so a hash of one kind can never equal a hash of another
  kind over the same bytes. The identity rule is
  `H("licketysync/v1/hash/id/<kind>", be16(suite) || signing_pk)` with `<kind>` one
  of `folder` (over the root key), `device` and `identity`, and for `key`, over an
  issued key, the input also takes its KEM public key,
  `be16(suite) || signing_pk || kem_pk`, and only the first 16 bytes are kept
  (`[0..16]`, section 2.2), as `keys.md` fixes the four, so a device key misused as
  a root key, or a root key presented as a device, cannot produce a matching ID.
- **The keyed hash where the output must mean nothing without the key.**
  `BLAKE3_keyed(k, x)` with a 32-byte key `k`: the plaintext chunk hash
  `plain_hash` under the folder-lifetime chunk-hash key `hk` (TM-14); chunk nonces
  under `nk_e` (section 2.3); the link proof under the link-confirm key; and the
  handshake's folder hint and proof key, which are keyed with the folder ID itself
  over `label || 0x00 || …`. The folder ID is a deterministic hash of the root
  public key (the identity rule above), known to every key holder at every tier, to
  every relay the folder uses and to anyone who ever saw an invite string, so the
  hint and the proof key are secret only from a party that does not hold it: a
  network observer, or a connected peer with no key to that folder and no invite to
  it, from whom they hide which folder the other side is proving; the signature
  inside the proof, not the keyed hash, is what admits a peer.
- **`derive_key` for every purpose key, from uniformly random key material only.**
  `derive_key(label, material)` with a registered label and 32 or 64 bytes of
  uniformly random material: a seed, the master secret alone or with the folder
  nonce, a data key, a link secret. Every key in the system comes from its parent
  this way, so no key serves two purposes (TM-11). The material is never public
  data, which is `H`'s job, and never a passphrase (section 2.5).
- **The signature prefix** `M = label || 0x00 || body` under `licketysync/v1/sig/`
  (section 2.2) is the fourth labelled use; it is signed, not hashed.

**Who may call BLAKE3.** Only the `keys` crate, which owns all of the workspace's
cryptography, identifiers and hashes, and inside it only its labels module
(`crates/keys/src/labels.rs`), so that every hash in the workspace is one of the
four jobs above under its label. That is the target the crates are built to; on
main today `protocol` and `index` are stubs with no dependencies. `protocol` is to
depend on `keys`, take the folder hint and the proof key from it
(`labels::folder_hint`, `ProofKey`), and build the transcript hash with its
labelled hash (`labels::labelled_hash`); a hash module of its own may only
re-export `keys`'s functions and computes none itself, and `protocol` never sees
plaintext. `index` uses `keys`'s record hash. `keys` depends on neither. The
control is cargo-deny, whose target is a `blake3` entry in `deny.toml` with
`licketysync-keys` as its only wrapper, so that no other crate may depend on
`blake3`. Today `deny.toml` also lists `licketysync-protocol` as a wrapper of
`blake3` and of `chacha20poly1305`, and the Semgrep tripwire below also excludes
`crates/protocol/src/hash.rs`, for the protocol crate's work in progress; the
change that lands that crate removes the `licketysync-protocol` wrapper from both
entries and that exclusion. In `keys` and `protocol`, a Semgrep tripwire
(`.semgrep/project.yml`) flags every call into `blake3` (`hash`, `keyed_hash`,
`derive_key`, and a `Hasher` from `new`, `default`, `new_keyed` or
`new_derive_key`) and every `use` or `extern crate` of it, except in `keys`'s
labels module, which it excludes by path, in the crates' integration tests and
out-of-line `tests.rs` modules, and inside a `mod tests`; so the qualified paths
the first rule matches are the only way to reach the crate. It catches mistakes,
not intent: Semgrep does not resolve paths, so a call it cannot parse, such as one
inside a macro, passes. The cases it must and must not flag are in
`.semgrep/tests/project.rs`, which CI runs with `semgrep --test` before the scan;
the exclusion by path is exercised by the scan itself.

**Label format.** A label is ASCII, lowercase, from `a-z`, `0-9`, `-` and `/`, and
reads `licketysync/v1/<area>/<purpose>`: `<area>` groups labels by what they
derive from or serve (`key`, `folder`, `identity`, `epoch`, `link`, `handshake`,
`hash`, `sig`, `wrap`), and `<purpose>` is one or more `/`-separated words. The
prefix `licketysync/v1/` is reserved for suite 1; suite 2 uses `licketysync/v2/`.
Every label is a `const` in `keys`'s label registry (`crates/keys/src/labels.rs`),
which the other crates import, with a test vector each (section 4.4), so a changed
label fails a test. The labels that belong to the primitives themselves, as
`keys.md`'s registry carries them. These rows are copied from that registry byte
for byte, so that the two tables can be compared mechanically; the section
pointers inside them are the registry's own and refer to `keys.md` and
`protocol.md`, the one place this file carries a section number of either:

| Label | Mode | Material / input | Output |
| --- | --- | --- | --- |
| `licketysync/v1/key/ed25519` | derive_key | any key seed | Ed25519 seed |
| `licketysync/v1/key/ml-dsa-65` | derive_key | any key seed | ML-DSA-65 ξ |
| `licketysync/v1/key/x-wing` | derive_key | any key seed | X-Wing decapsulation seed |
| `licketysync/v1/key/libp2p-identity` | derive_key | device seed | Ed25519 seed of the libp2p identity (§1.3) |
| `licketysync/v1/key/dht-bep44` | derive_key | device seed | Ed25519 seed of the BEP 44 DHT signing key (§1.3, phase 2) |
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

BLAKE3's own guidance for `derive_key` contexts is "[application] [commit
timestamp] [purpose]"; the format above drops the timestamp in favour of the
registry and the version segment, which give the same global uniqueness **(decision)**.

### 2.5 Passphrases: Argon2id

A passphrase protects a key store on a device with no platform keystore (a
headless Linux box, a NAS, a container) and any other place `keys.md` names where a
human-chosen secret unlocks key material. It is never used to stretch the recovery
phrase, which already holds 256 bits of entropy.

**Parameters.** Argon2id, version 0x13 (1.3), memory m = 65536 KiB (64 MiB),
iterations t = 3, parallelism p = 4, salt 16 bytes from the operating system's
generator, output 32 bytes **(decision)**. These are RFC 9106 section 4's second
recommended option, chosen over the first (2 GiB, t = 1) because phones and the
browser build must run it. Crate `argon2` 0.6 with the `zeroize` feature; the
parameters are passed explicitly, never the crate's defaults.

**Minimum accepted.** m ≥ 19456 KiB, t ≥ 2, p ≥ 1, salt ≥ 16 bytes: the memory
floor equals OWASP's 19 MiB option, and its lower-memory options are refused. A
key store that asks for less is refused as corrupt rather than derived with weak
parameters.

**Raising them later.** The parameters and salt are stored in clear beside the
ciphertext, in the key-store format that `keys.md` will define (deferred: no phase
needs it before a headless device ships), so a newer release derives with whatever
the stored parameters say. When a release raises the defaults, the store is
re-encrypted under the new parameters the next time the person unlocks it, which
is the only time the passphrase is available; a release never changes them
silently.

**The exported root file.** The plan exports the owner key as a passphrase-
protected file in the age format, whose passphrase recipient is defined by the
age specification as scrypt. This file is the one place a passphrase is
processed by something other than Argon2id, because the format fixes it and the
point of using age is that any age implementation can open the file in twenty
years **(decision, deviation from the plan's "Argon2id for passphrases")**. The
`age` crate picks scrypt's work factor by timing the machine; the export calls
`scrypt::Recipient::set_work_factor(18)` explicitly instead (N = 2^18, r = 8, p
= 1: 256 MiB), so the file costs the same to open everywhere and a slow machine
never writes a weak one. The import reads the work factor from the file header,
as the format requires, and calls `scrypt::Identity::set_max_work_factor` with
18 or higher so that a file written here always opens and a file demanding far
more is refused rather than attempted.

### 2.6 Transport

The transport suite is separate from the record suite and is negotiated by libp2p
(protocol identifiers in multistream-select), because the transport protects the
path and the record suite protects the data: content, names and structure are
encrypted under the data key before they reach any transport, so the transport
adds forward secrecy for the session and hides from a network observer what a
sealed peer would otherwise see (threat model section 5).

**One security protocol per transport (decision).** Each transport offers
exactly one security protocol, so multistream-select has nothing to choose
between before either side is authenticated: TLS 1.3 on QUIC and on TCP; Noise
only inside WebSocket, WebTransport and WebRTC, where TLS is not offered. A side
that is offered the other protocol on a transport closes the connection. This
qualifies the plan's "nothing is negotiated before the secure channel exists":
libp2p does negotiate the security protocol, so the sentence is made true by
giving it one candidate per transport (threat model, section 3.1 and TM-1). What
the rule does not prevent is the choice of transport: an attacker who blocks UDP
and raw TCP steers a dialler onto the WebSocket path, whose Noise handshake is
classical, and whose outer TLS is classical too: `libp2p-websocket` 0.46.0 builds
its rustls configuration on rustls's `ring` provider, which offers X25519, P-256
and P-384 and no post-quantum group, and has no way to be given another provider.
A WebSocket session is therefore classical end to end. It is still encrypted and
authenticated, so nothing the record layer protects is weakened, but a recording
of it is readable by a future quantum computer up to what a sealed peer sees, as
the threat model's quantum entry (its section 5) states **(deviation from the
plan's post-quantum transport; phase 2 item: a reviewed patch to, or an upstream
change in, `libp2p-websocket` that accepts a provider, so that its outer TLS is
built on `aws-lc-rs` and offers X25519MLKEM768 like the others)**. It also builds
with `with_safe_default_protocol_versions()`, so its outer TLS accepts TLS 1.2
whenever rustls's `tls12` feature is on, and in rustls 0.23 `tls12` is a default
feature, on unless every crate that depends on rustls disables default features;
the change that adds `net` checks `cargo tree -e features -i rustls` for that and
keeps it off.

- **TLS 1.3 only**, through `libp2p-tls` and `libp2p-quic`, which build their
  rustls 0.23 configurations on the `aws-lc-rs` provider with rustls's
  `prefer-post-quantum` feature, so the key exchange offers X25519MLKEM768 (the
  hybrid the plan names, pre-standard but deployed by Chrome and Cloudflare) first
  and X25519 as the fallback for peers that lack it. Checked 2026-10-14:
  `libp2p-tls` 0.7.0 depends on rustls with the `aws-lc-rs` and
  `prefer-post-quantum` features, builds on `aws_lc_rs::default_provider()`, and
  carries a test that X25519MLKEM768 is preferred; the phase 2 gate's packet
  capture confirms the group in the ClientHello. Cipher suites: `libp2p-tls`'s list
  is `TLS13_CHACHA20_POLY1305_SHA256`, `TLS13_AES_256_GCM_SHA384` and
  `TLS13_AES_128_GCM_SHA256`, in that order of preference, and suite 1 accepts that
  list as it ships **(decision, deviation from the plan's "256-bit symmetric
  everywhere")**: two Lickety-Sync peers share the list, so the suite chosen between
  them is the first one, and AES-128 is negotiated only with a foreign libp2p peer
  that offers nothing else; transport session keys are ephemeral and the record
  layer is 256-bit throughout, so dropping the 128-bit suite would buy little, and
  removing it means `net` building its own crypto provider, which is deferred until
  some other need forces it. Certificates follow the libp2p TLS specification: each
  side's certificate is self-signed by its own freshly generated P-256 key and
  carries the libp2p extension, in which the libp2p identity key signs the
  certificate's public key; inside `libp2p-tls`, `ring` verifies the certificate's
  own self-signature (P-256 for the certificates we generate) and the TLS 1.3
  CertificateVerify signature, and the extension's Ed25519 signature is verified
  by `libp2p-identity` on `ed25519-dalek`. `ring`'s other roles are listed under
  section 3.1. **Providers are passed explicitly (decision).** `libp2p-tls` and
  `libp2p-quic` build on `aws_lc_rs::default_provider()` and `libp2p-websocket` on
  `ring`, each passing its provider rather than using a process default. First-party
  code builds every rustls configuration with `builder_with_provider` and
  `rustls::crypto::aws_lc_rs::default_provider()` and never calls the default
  builders (`ClientConfig::builder()`, `ServerConfig::builder()`), which, with both
  providers compiled in, panic unless a process default is installed. `net` also
  installs `aws_lc_rs::default_provider()` as the process default at startup, so a
  dependency that uses the default builders gets it; an `Err` from
  `install_default` (a default already installed) is a startup error unless the
  installed default lists X25519MLKEM768 first, and a test checks the installed
  default.
- **QUIC** through `libp2p-quic` (quinn) with the same rustls configuration; QUIC's
  three-to-one anti-amplification limit stays at its default (TM-22).
- **TCP** through `libp2p-tls` with the same configuration.
- **Noise** `Noise_XX_25519_ChaChaPoly_SHA256` through `libp2p-noise` (the
  `snow` crate underneath, whose cipher and hash come from `ring` on native
  targets and from the RustCrypto crates on wasm32), which is the only pattern
  libp2p guarantees interoperable, inside WebSocket (locked-down networks),
  WebTransport and WebRTC only, where the libp2p specifications run Noise over
  the browser-grade outer layer because libp2p TLS is not available there. Noise
  is classical: the plan keeps it where a path needs it because the second layer
  protects content and names regardless. A recorded Noise session is readable by
  a future quantum computer, and what it reveals is what a sealed peer sees;
  `threat-model.md` section 5 states it.
- **Browser paths** (WebTransport with certificate hashes, WebRTC-direct, secure
  WebSocket to the HTTPS listener) use the browser's own TLS and DTLS stacks, which
  this file does not govern, with the libp2p Noise handshake above inside them.
  Chrome offers X25519MLKEM768, but the outer layer is post-quantum only if the
  native end accepts it: the secure WebSocket listener is `libp2p-websocket` on
  `ring`, so it does not (above), and the native WebTransport and WebRTC-direct
  stacks are checked in the change that adds them. The HTTPS listener's
  certificate is the user's own or Let's Encrypt through `rustls-acme` when turned
  on. `aws-lc-rs` does not build for wasm32-unknown-unknown, which is harmless
  because the browser build uses no rustls at all.
- **Tor** (phase 7) through Arti: onion-service cryptography is Tor's.

**The libp2p identity key (decision).** The transport authenticates each side's
libp2p identity, an Ed25519 key. It is not the Ed25519 half of the device's key
pair set, because that half signs only as part of the hybrid signature (section
2.2) and no key serves two protocols (TM-11). It is a separate Ed25519 key derived
under `licketysync/v1/key/libp2p-identity` from the device seed, used for nothing
but what the libp2p TLS and Noise specifications require (signing the libp2p
extension in the certificate; signing the Noise static key), and it is bound to the
device key pair set by the DeviceProof: the hybrid signature over the handshake
transcript, which includes both libp2p identity public keys (32 bytes each, as the
Hellos carry them). A verifier therefore knows that the device whose identity the
transport authenticated is the device whose hybrid key signed the proof. `keys.md`
defines the derivation and `protocol.md` the proof. The same pattern gives the
Mainline DHT its signing key: `licketysync/v1/key/dht-bep44` derives a second
single-purpose Ed25519 key from the device seed, which signs only the BEP 44
mutable items the device publishes (phase 2) and, like the identity, is a stable
per-device identifier (threat model, section 5).

The identity is one per device, so its peer ID is a stable handle across folders,
days and addresses for anyone the device connects to and anyone who reads its DHT
records (threat model, section 5). **Considered alternative, not adopted (for the
plan to record).** A libp2p identity per folder, or one rotated on a schedule,
would remove that handle. Its cost: one connection per shared folder instead of one
per peer, with the matching multiplication of handshakes, NAT traversal and relay
reservations; a rotating identity would also defeat the LAN beacon's "dial expects
exactly this identity" check and any peer that pins an identity. Suite 1 keeps one
identity per device and documents the handle instead.

## 3. Approved crates

These tables are exhaustive for two things: any crate that performs cryptography
(a cipher, hash, KDF, signature, KEM, password function, random source or TLS
stack) and any crate that encodes secrets for people to carry (the phrase, key
strings). No such crate enters first-party code until a reviewed change adds it
here, in `deny.toml` and in `supply-chain/`, with the reason in the changelog.
Ordinary dependencies (`prost`, `tokio`, SQLite bindings and the like) are
governed by TM-8, not by this file. "May be used for" is exhaustive; "may not"
names the tempting misuse.

Versions are the range `Cargo.toml` pins (caret ranges within the stated minor);
the exact version checked on 2026-10-14 is in parentheses. A crate the plan names
that this table omits (`x25519-dalek` directly) is reached only through the crate
that wraps it.

### 3.1 Cryptography

The audit-status column is what the crate's own documentation says as of
2026-10-14; "none named" means the crate names no independent audit. The
post-quantum crates are unaudited, which section 2.1 records as a deviation from
the plan's "audited crates".

| Crate | Pin | Checked | Audit status | May be used for | May not be used for |
| --- | --- | --- | --- | --- | --- |
| `hpke` | `0.14` | 0.14.1, 2026-09-06 | Cloudflare reviewed 0.8; no paid audit | Wrapping a 32-byte key or a small secret to a public key: `kem::XWing`, `kdf::HkdfSha256`, `aead::ChaCha20Poly1305`, mode_base, single-shot; `<XWing as Kem>::PrivateKey` through `Deserializable::from_bytes` to load a derived seed; `single_shot_seal_with_rng` and `single_shot_open`; features `x25519`, `mlkem`, `hkdfsha2`, `chacha`, `alloc` | Any other KEM, KDF or AEAD it offers; streaming; auth or PSK modes; `derive_keypair`; the `getrandom` feature and `single_shot_seal` |
| `x-wing` | via `hpke` | 0.1.1, 2026-10-01 | none; "never been independently audited" | Only as `hpke`'s dependency | Any direct dependency or `use` |
| `ml-kem` | via `hpke` | 0.3.2, 2026-05-10 | none; "never been independently audited" | Only as a dependency of `x-wing` and of `hpke`, which also depends on it directly | Any direct dependency or `use` |
| `ed25519-dalek` | `3` | 3.0.0, 2026-07-06 | none named | Ed25519 half of the hybrid signature, the separate libp2p identity key and the BEP 44 DHT signing key (section 2.6; the last signs only BEP 44 mutable items, phase 2): `SigningKey::from_bytes` on a derived seed; `verify_strict` | `verify` (non-strict); `hazmat`, `legacy_compatibility`, `pkcs8`; signing anything else |
| `libp2p-identity` | with `libp2p` `0.57` | 0.3.0, 2026-09-11 | none named; its Ed25519 is `ed25519-dalek` | The libp2p identity key of section 2.6 with the `ed25519` feature only: an `ed25519::SecretKey` from the derived 32-byte seed, its `Keypair` and `PeerId` | Its `secp256k1`, `ecdsa` and `rsa` features; generating an identity from randomness instead of the derived seed; signing anything the libp2p TLS and Noise specifications do not |
| `ml-dsa` | `0.1` | 0.1.1, 2026-06-05 | none; "never been independently audited" | ML-DSA-65 half of the hybrid signature with `default-features = false` and `zeroize`, `rand_core` (`sign_randomized` is behind it) and `alloc`: `SigningKey::<MlDsa65>::from_seed`; `ExpandedSigningKey::sign_randomized` in production, `sign_deterministic` for vectors; verify | ML-DSA-44 or -87; `pkcs8`; a non-empty context; signing outside the hybrid |
| `chacha20poly1305` | `0.11` | 0.11.0, 2026-06-28 | NCC Group 2020, no significant findings | `XChaCha20Poly1305` as section 2.3 | `ChaCha20Poly1305` (96-bit nonce) directly; the stream cipher without the MAC |
| `blake3` | `1` | 1.8.7, 2026-08-20 | none named; the designers' reference implementation | The labelled hash `H`, `keyed_hash`, `derive_key` under a registered label; `Hasher` for streaming; `rayon` feature for large files | Extendable output; as a password hash; as a MAC without the keyed mode; plain `hash` without a label |
| `argon2` | `0.6` | 0.6.0, 2026-08-27 | none named | Argon2id with the parameters of section 2.5, `zeroize` feature | Argon2i or Argon2d; the crate's defaults; the `password-hash` PHC API as a verifier |
| `age` | `0.12` | 0.12.1, 2026-07-14 | none named | The exported root file: passphrase recipient with `set_work_factor(18)`, the `armor` feature and no other; reading it back | X25519, SSH or plugin recipients; the `ssh` feature; anything other than the root export |
| `zeroize` | `1` | 1.9.1, 2026-10-06 | none named; small, widely reviewed | Every secret type: `Zeroize`, `ZeroizeOnDrop`, `Zeroizing<T>`, the `derive` feature | — |
| `subtle` | `2` | 2.6.1, 2024-06-24 | none named; small, widely reviewed | Constant-time comparison of secrets and tags: `ConstantTimeEq`, `Choice`, `CtOption` | — |
| `rustls` | `0.23` | 0.23.46, 2026-10-14 | Cure53 2020 | TLS 1.3 for QUIC and TCP as section 2.6, through `libp2p-tls` and `libp2p-quic`: `aws-lc-rs` provider, `prefer-post-quantum`; first-party configurations only through `builder_with_provider` with `aws_lc_rs::default_provider()`; `net` installs that provider as the process default at startup; the `ring` provider only as `libp2p-websocket` ships it | TLS 1.2; the default builders in first-party code; the `ring` provider in first-party code or as the installed default; its HPKE module |
| `aws-lc-rs` | `1` | 1.18.2, 2026-10-12 | AWS-LC's FIPS build is FIPS 140-3 validated | rustls's crypto provider only | Direct calls to any primitive |
| `libp2p-tls`, `libp2p-quic`, `libp2p-noise` | with `libp2p` `0.57` | 0.7.0, 0.14.0, 0.47.0, 2026-09-11 | none named | The transports of section 2.6 | Noise patterns other than XX; Noise on QUIC or TCP; TLS inside WebSocket, WebTransport or WebRTC |
| `libp2p-websocket` | with `libp2p` `0.57` | 0.46.0, read 2026-10-17 | none named | The WebSocket transport of section 2.6, its outer TLS classical as shipped (rustls on `ring`) | Any claim that its outer TLS is post-quantum until the phase 2 change lands |

Transitive dependencies these crates pull in, among them `x-wing`, `ml-kem`,
`curve25519-dalek`, `x25519-dalek`, `sha3`, `shake`, `turboshake`,
`module-lattice`, `hkdf`, `sha2`, `hmac`, `scrypt`, `p256`, `snow`, `ring`,
`rcgen`, `webpki`, `quinn`, `chacha20`, `poly1305`, `aead`, and `rand` beneath
`age`, the `libp2p-*` crates and `quinn` (the list is illustrative; the tree
decides), are allowed as dependencies of the listed crates only; first-party code
never names them in `Cargo.toml` or `use`s them. The rule governs what a build
ships, so a path to a cryptography crate that runs only through dev-dependencies
is outside it: for example `chacha20`, which `proptest`, the property-test tool,
depends on for its test generator. The check is
`cargo tree --workspace --all-features --target all -e no-dev -i <crate>`, which
leaves dev-dependencies out and keeps build-dependencies in, since those run at
build time, and must show every path to the crate running through a listed crate;
a crate that only test tooling reaches is in no production build. `deny.toml`'s
ban entries with `wrappers` make cargo-deny enforce this for the crates on the
graph today, and a change that adds another adds its entry. Because cargo-deny's
graph includes dev-dependencies, an entry for a crate that test tooling also
reaches lists that tool among its wrappers (`proptest` for `chacha20`), and a
second configuration, `deny-production.toml`, with `[graph] exclude-dev = true`
and the same entry without the tool, which `gate.sh` and CI also run, keeps the
test-only path out of production builds, as the `cargo tree` check does
**(decision)**. `ring` has five roles, all beneath listed crates: in `libp2p-tls`,
verifying the certificate's self-signature and the TLS 1.3 CertificateVerify
signature; in `rcgen`, generating that certificate; in `snow` via `libp2p-noise`,
the Noise cipher and hash on native targets; in `quinn-proto` through its `ring`
feature via `libp2p-quic`, QUIC's stateless-reset HMAC and its token key; and in
`libp2p-websocket`, the whole outer TLS (rustls's `ring` provider, which also
turns on `webpki`'s `ring` feature). The exact wrappers of `ring`'s `deny.toml`
entry are fixed in the change that adds `net`, from `cargo tree -e no-dev -i ring`
**(decision; `deny.toml` today bans `openssl`, `openssl-sys`, `md5`, `sha1`,
`rust-crypto`, `pkcs8`, `der` and `spki` outright, bans `ring` outright until the
change that adds `net` gives it wrappers, and restricts the crates `keys` uses,
and the primitives beneath them, to listed wrappers)**. Expect `multiple-versions`
warnings, which `deny.toml` sets to `warn`: `age` 0.12 depends on
`x25519-dalek` 2, `chacha20poly1305` 0.10, `hpke` 0.12, `ml-kem` 0.2 and `p256`
(and, under its `ssh` feature, which is never enabled, `rsa`, `aes` and
`bcrypt-pbkdf`), while suite 1 uses newer lines of the first four; the duplicates
are confined to the `decrypt` and `cli` crates that perform the export.

### 3.2 Encodings and non-cryptographic helpers

| Crate | Pin | Checked | May be used for | May not be used for |
| --- | --- | --- | --- | --- |
| `bip39` | `3` | 3.0.0, 2026-09-17 (rust-bitcoin/rust-bip39) | Encoding 32 bytes of entropy as a 24-word English mnemonic with its checksum, and decoding and checksum-verifying a mnemonic back to the 32 bytes; `zeroize` feature. Its SHA-256 checksum (via `bitcoin_hashes`) is allowed inside this crate only | Its seed function (PBKDF2); languages other than English; passphrase-extended mnemonics |
| `bech32` | `0.11` | 0.11.1 (rust-bitcoin/rust-bech32); 0.12.0 has since been published and is evaluated in the change that adds the crate | Bech32m (BIP-350) encoding and checksum-verifying decoding of key strings and link codes with the `lsk` and `lsl` prefixes (`keys.md`, the key string) | Bech32 (non-m); anything that is not a key string or link code |
| `getrandom` | `0.4` | 0.4.3, 2026-06-17 | The operating system's generator: `getrandom::fill`, whose failure stops the process (`std::process::exit` with a distinct exit code in the daemon's handler, section 4.3), never `abort()`, whose SIGABRT can write a core dump holding keys, never a panic and never a weaker source; the `wasm_js` feature enabled by the browser binary crate only | Any user-space generator; `rand_core::UnwrapErr` (it panics); `std::process::abort()` on a failure |
| `rand_core` | `0.10` | 0.10.x, the line the listed crypto crates require | The `CryptoRng` and `TryCryptoRng` traits where a listed crate's API asks for a generator, always backed by `getrandom` | Seeding anything from any other source |

`rand` is not on the list: no first-party crate names or uses it. It appears in the
dependency tree only beneath listed crates (`age`, the `libp2p-*` crates, `quinn`),
where section 3.1's transitive-wrapper rule names it, and beneath test tooling such
as `proptest`, a dev-only path that rule leaves outside. The simulator's
reproducible randomness comes from its own seeded statistical generator,
SplitMix64 in the `sim` crate, which feeds the runtime's randomness trait in
simulator runs only and is not cryptography; TM-5 permits exactly that generator
and nothing else written here (section 4.3).

**The recovery phrase (decision).** The phrase encodes 256 bits of entropy per
BIP39: 24 words from the English word list, the last 8 bits a checksum. The master
secret is that entropy itself, the 32 bytes the words encode, and nothing else.
Every key derives from it with BLAKE3 `derive_key` and a registered label
(`keys.md`, the derivation tree: `licketysync/v1/identity/seed` and
`licketysync/v1/folder/root-seed`, then the key pair set labels beneath). BIP39's
PBKDF2 seed function, and its optional passphrase, are not used: the phrase is a
uniformly random 256-bit secret and needs no stretching, and tying derivation to
BIP39's seed function would import PBKDF2 and HMAC-SHA512 for no gain. A phrase
whose checksum fails is refused with the position of the first word that is not in
the list, never corrected. The word list is the BIP39 English list, which the crate
embeds and whose hash a test pins.

## 4. Secret handling

### 4.1 Zeroization

Every secret (phrase entropy, master and derived seeds, X-Wing and signing seeds,
data keys, chunk-nonce and chunk-hash keys, HPKE shared secrets, session keys,
passphrases, the local API token) lives in a type that implements `ZeroizeOnDrop`,
either a newtype over `Zeroizing<[u8; 32]>` or a struct deriving `Zeroize,
ZeroizeOnDrop`. Rules:

- The type's `Debug` prints the type name and `[redacted]`; it has no `Display`.
- It implements no `Serialize`; export paths (TM-39) are explicit functions that
  return a `Zeroizing` buffer.
- It is `Clone` only if a caller needs two copies, and never `Copy`.
- Intermediate buffers that held secret bytes (`Vec<u8>`, arrays, `String`s of the
  phrase) are `Zeroizing` too; a secret never passes through a plain `String` or
  `format!`.
- A secret is never a `HashMap` key, never indexed by, and never compared with
  `==` (section 4.2).
- Secrets are never logged, never placed in error values (errors carry the key ID
  or folder ID, which are public, and never the material), never in panic payloads.
- Memory locking (`mlock`) and swap are the operating system's concern and are not
  promised.

### 4.2 Constant-time comparison

Any comparison in which one side is secret or derived from a secret (keys, seeds,
tokens, passphrase-derived keys, HPKE or AEAD outputs compared by hand, the local
API token) uses `subtle::ConstantTimeEq::ct_eq` and branches on the resulting
`Choice` through `subtle`'s API; `==`, `assert_eq!` and `cmp` on such values do
not appear outside tests. AEAD tags and signatures are verified by their crates,
which do this internally; first-party code never reimplements tag or signature
comparison. Comparisons of public values (hashes of public data, IDs, lengths) may
use `==`.

### 4.3 Randomness

Every random value first-party code draws in a production build (nonces, salts,
seeds for new keys, tokens, the folder nonce) comes from the operating system's
generator through `getrandom::fill`, or through a `rand_core::CryptoRng` that is
itself backed by `getrandom` where a listed crate's API requires one. First-party
code writes no user-space PRNG for production, seeds nothing from time, PIDs or
addresses, and caches no random bytes for later; what listed crates do internally is
theirs. Every generator first-party code hands to the engine or to a listed crate is
infallible, the runtime's `Randomness::fill_random` included; the daemon's
`getrandom`-backed implementation is the one place a failure is handled, and it
stops the process with `std::process::exit` and a distinct exit code, never a panic
and never `std::process::abort()`, whose SIGABRT can write a core dump holding keys
(TM-6); the daemon also switches core dumps off at startup (a phase 1 item); and
nothing ever falls back to a weaker source; the operating system is out of scope
(`threat-model.md` section 3.12) **(decision 2026-10-17)**. The browser build
enables the `wasm_js` feature in the binary crate only, so a library crate never
decides the backend. The engine draws randomness through its runtime trait; in a
simulator run that trait is backed by the simulator's own seeded statistical
generator, SplitMix64 in the `sim` crate, so that a failure replays exactly, and
seeds, nonces and salts in such a run come from it. It is not cryptography and it is
the one generator TM-5 permits to be written in this workspace: `sim` is never a
dependency of `daemon`, `cli` or `decrypt` (reviewed on every `Cargo.toml` change),
so no production build contains it.

### 4.4 Test vectors

Every primitive and every derivation has a test vector in the crate that
implements it, committed under `crates/<crate>/tests/vectors/`, and the test fails
if the output changes by one bit:

- Primitives: Ed25519 (RFC 8032 section 7.1 vectors); ML-DSA-65 (NIST ACVP
  known-answer vectors); X-Wing (the draft's Appendix C vectors); HPKE with X-Wing
  (vectors generated once from `hpke` and checked against `hpke-rs`, since RFC 9180
  has none for X-Wing); XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 Appendix A
  vectors); BLAKE3 (the official test vector file, all three modes); Argon2id (RFC
  9106 section 5.3); BIP39 (the Trezor reference vectors, English); age (the age
  specification's test vectors for the passphrase recipient).
- Derivations: for every label in section 2.4's table and every label `keys.md`
  and `protocol.md` register, a fixed 32-byte input and the expected 32-byte
  output, generated once and committed, so that a changed label, a changed order of
  derivation or a changed parent fails a test with the label's name in the test
  name.
- Encodings: a full hybrid public key, a full hybrid signature over a fixed
  message under a fixed seed, a full wrapped data key under a fixed seed and fixed
  HPKE randomness (the `hpke` crate's deterministic test API), each as bytes; and
  the HPKE recipient keypair for a fixed 32-byte seed, the 1216-byte public key
  that `<XWing as Kem>::PrivateKey` loaded through `Deserializable::from_bytes`
  yields, so that a change of import path (such as `derive_keypair`) fails the
  test.
- Hedging: one body signed twice through the production signing path gives two
  signatures whose Ed25519 halves are equal and whose ML-DSA halves differ, so a
  regression to deterministic ML-DSA signing in production fails a test.

Vectors are data files, not constants in code, so a reviewer can diff them, and
the test that reads them is named after the primitive or label
(`fn vector_derive_key_ml_dsa_65()`).

## 5. Suite 2 (placeholder)

Suite 2 does not exist. It will when one of these happens: the X-Wing draft changes
its combiner, label or encoding before publication as an RFC, or a flaw is found in
X-Wing, ML-KEM-768 or ML-DSA-65 (the replacement becomes suite 2 and folders move
by rotation, as the plan decided); or a preference for AES-256-GCM on hardware with
AES instructions is judged worth a second cipher. Suite 2 would use the label
prefix `licketysync/v2/`. Nothing about it is specified here, deliberately: a suite
is a whole set and is written down whole.

## Appendix: what was checked on 2026-10-14

Versions and statements above come from docs.rs and the crates' READMEs as read on
2026-10-14; the X-Wing facts from draft-connolly-cfrg-xwing-kem-11 (September 2026,
expires 2027-03-27); rustls's post-quantum notes from its manual's defaults page;
the `libp2p-tls` 0.7.0 facts (rustls with the `aws-lc-rs` and `prefer-post-quantum`
features, configurations built on `aws_lc_rs::default_provider()`, a test that
X25519MLKEM768 is preferred, the cipher-suite list ChaCha20-Poly1305 then
AES-256-GCM then AES-128-GCM, `ring` used to verify the certificate self-signature)
from its manifest and source; `ring`'s other roles (snow's resolver in
`libp2p-noise` on native targets, the stateless-reset HMAC and token key in
`libp2p-quic`'s `quinn-proto`, and `libp2p-websocket` enabling rustls's `ring`
provider feature) from those crates' manifests and source; that `libp2p-websocket`
0.46.0 builds its outer TLS on the `ring` provider with no way to pass another, that
`libp2p-tls` passes `aws-lc-rs` explicitly, and that `ring` also verifies the
CertificateVerify signature in `libp2p-tls`, from the round-4 security review of
2026-10-17. The crate pins are to be confirmed against `cargo search` when the first
of these dependencies is added to `Cargo.toml`, in the change that adds it.
