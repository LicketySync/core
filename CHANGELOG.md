# Changelog

All notable changes to Lickety-Sync are recorded here. Each entry says what
changed and names the agents that reviewed it; anything touching keys, protocol,
paths or the API also names the security-reviewer pass.

## Unreleased

- Keys crate, phase 0 (`licketysync-keys`), built to `spec/keys.md` and
  `spec/suites.md` as main holds them (cfc41da and a544ad5, copied into `spec/`
  for the label-registry test) and to the rulings of 2026-10-17 numbered 8 (as
  amended), 13b and 16 to 23, which the next spec commit states. Under ruling
  13b the crate owns every cryptographic primitive, label, identifier and
  `SignedRecord`, and never depends on `licketysync-protocol`, which will depend
  on it. What it holds: the label registry with the four BLAKE3 uses behind
  typed label constants, each hasher that held key material wiped after use
  (`labels`); the 24-word phrase and the derivation tree (`phrase`, `derive`);
  key pair sets from one seed with hybrid Ed25519 + ML-DSA-65 signatures, both
  halves required, `verify_strict` (`keyset`); production signing is hedged and
  is the only form outside tests and the `test-vectors` feature; X-Wing
  data-key wraps through `hpke`'s `single_shot_seal_with_rng` and
  `single_shot_open`, the plaintext zeroizing at once (`wrap`); XChaCha20-
  Poly1305 under a caller's key, nonce and aad (`aead`), the handshake's
  `ProofKey` (`ProofKey::derive`) and `labels::folder_hint`, from which the
  protocol crate builds the FolderProof; the labelled keyed hash under them is
  crate-private, so the proof key exists only inside its zeroizing type; the
  data key, the epoch ladder, the derived keys and the
  index-record seal under a typed 88-byte aad (`epoch`); chunk sealing with
  Padme and the convergent nonce, the bound checked before allocation (`chunk`);
  Bech32m key strings, links and `.lskey` files, every secret string written
  into a buffer of its final length, a link's bundle accepted only when its
  leaf is the link's own key, and the phase 5 link code (`keystring`,
  `linking`); the LAN and DHT discovery hashes (`discovery`); and the key
  records (`records`): the signed envelope with the grant's proof of
  possession in `key_signature`, the bodies with canonical prost encoding and
  decoding that refuses a singular field twice, a `uint32` past 32 bits and
  any repeated field past its bound before prost allocates (ruling 16), caps of
  4 000 000 encoded bytes for an index record and 6 000 000 for a key record
  judged before the duplicate check, `FolderKeys` with every step of 5.4 and the
  phase 0 part of section 7 in signature-first order. Chains are authorizing
  (ruling 17: each issuer grant has `may_share` and a tier at least as
  privileged as the grant it issued); ancestry is reachability along those
  links within 16 grants, a key never its own ancestor, so entitlement never
  depends on arrival order (rulings 18 and 19); the canonical chain is the
  shortest, valid or not, with a hash tie-break, used for pushes and the
  suspension-weighted tier; presentability takes the best presentable chain at
  the wall clock. In phases 0 to 6 stored Revocations, Suspensions and Lifts are
  checked and stored but never applied (ruling 21); a grant beneath a stored
  Revocation is stored with an issue (ruling 20); a Rotation's signer must hold
  a stored grant of tier 1 or 2 (ruling 21); a Wrap's validity is judged per
  grant (ruling 19); a rival or stale Rotation is stored only after its
  entitlement step and once per (epoch, signer), root's always (rulings 22 and
  23); while an epoch has more than one stored rotation, every holder result for
  it is the no-blame `EpochAmbiguous`; a holder whose ladder check fails adopts
  nothing from that rotation (ruling 19). Quotas (ruling 23): non-root key
  records at most 65 536 in number and 512 MiB in encoded bytes per folder, 4 096
  per non-root signer (`MAX_KEY_RECORDS_PER_FOLDER`,
  `MAX_KEY_RECORD_BYTES_PER_FOLDER`, `MAX_KEY_RECORDS_PER_SIGNER`), root's
  records exempt; a record that would take a count past one of them is a
  validity-only rejection naming its signer. Rulings 24 to 26: a failure that
  rests only on a grant not being stored (an issuer's authority under its
  governing grant, a rotator's tier 1 or 2 grant, a Wrap's tier, entitlement
  as issuer or ancestor) is the validity-only `UnprovableFault`, naming the
  signer, the fault and the key whose absent grant it rests on, never a
  signer fault, in every arrival order; a key targeting itself, a Lift of
  root's Suspension by another key, and a Rotation's own view keep their
  blame. A record refused under a quota is remembered by hash with the key
  it grants or the epoch it creates (`refused_under_quota`, at most
  `MAX_REFUSED_REMEMBERED` = 16 384 per folder, oldest forgotten, not
  persisted, forgotten once stored), and so is a record refused because it
  needs a remembered one, transitively: a grant with the key it grants, which
  its verified proof of possession binds, any other record by its hash alone,
  so only a rotation that verified in full before a quota refused it provides
  an epoch and an unsigned or unentitled Rotation cannot turn root's later
  records from missing to refused (ruling 29); such a record is the validity-only
  `DependencyRefused`, never a missing dependency. Residual: a refusal that
  is forgotten (after a restart, or past the bound) is sent again and judged
  again, so re-sends recur, and a peer with no key can force that, evicting
  every genuine entry with 16 384 unsigned records that need a remembered
  one. `records()` yields the
  records in stored order, which senders use as it is. While an epoch is
  ambiguous no key of it is used and no ladder rung through it climbed; a
  wrap that does not open and a Rotation's own KeyWrap against its own
  `confirm` still blame, and only a check against the chain's `confirm`,
  then chosen among rivals, is the no-blame `EpochAmbiguous`. Grants held for
  a connection (`HeldGrants`, at most 64) are verified without the epoch step
  and count at the handshake (`FolderKeys::validity_with`); a full set
  refuses a grant before either signature is verified, with the
  held-set-full outcome `HeldSetFull` for the connection, which names no
  key, not the issuer the body claims (ruling 29). The chain searches run over
  groups of interchangeable grants (same key, issuer, tier and `may_share`)
  and the phase 0 to 6 walk level of every group is kept as grants are stored,
  so an insertion reads only the groups of the keys it names; a bulk load
  verifies every signature on all cores first, and never panics: with one
  thread and on WebAssembly it verifies on the calling thread, and a worker
  that cannot start leaves its part to the calling thread. The 16-grant
  bound is tested at its edge in each place it is applied (the kept walk
  levels, the top-down search of the phase 7 coverage rule, ancestry and
  `is_ancestor`), and a property test compares every search with brute
  force on graphs whose walks reach 15 to 18 grants. Randomness comes from the
  caller as `&mut dyn FnMut(&mut [u8])` (the engine's `Randomness`); nothing
  reads a clock. Test vectors for every item of keys.md section 9 and one per
  label are data under `crates/keys/tests/vectors/`
  (`LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-keys vector_`
  rewrites them), with the RFC 8032, X-Wing draft, XChaCha draft, BLAKE3, BIP39
  Trezor and LAMPS ML-DSA-65 known answers; fuzz targets for every decoder are
  in `fuzz/` with seeds from the vectors, which the nightly run passes as a
  second corpus; the fuzz crate builds the vectors' folder with hedged signing
  under a fixed randomness, not the `test-vectors` feature, and the gate's
  `ci/no-test-vectors.sh` (tested by `ci/test-no-test-vectors.sh`, also in
  CI) fails when `cargo tree` shows that feature enabled outside
  dev-dependencies. TM-2, TM-3, TM-5, TM-6, TM-9, TM-10,
  TM-11, TM-12, TM-14, TM-15, TM-18, TM-19, TM-22, TM-23, TM-33, TM-36, TM-37,
  TM-38, TM-40.
- Dependencies added (keys crate), each from `suites.md` section 3 or for
  encoding: `hpke` 0.14 (alloc, x25519, mlkem, hkdfsha2, chacha), `ml-dsa` 0.1
  (no default features; alloc, zeroize, rand_core), `ed25519-dalek` 3,
  `chacha20poly1305` 0.11 (alloc, zeroize; ChaCha20's own zeroize with it),
  `blake3` 1 (zeroize), `bip39` 3 (zeroize), `bech32` 0.11, `zeroize` 1,
  `subtle` 2, `rand_core` 0.10, `prost` 0.14 (the canonical record encoding),
  `base64` 0.22 (a link's bundle and certificate hash); dev-only `proptest` 1,
  `serde_json` 1 and `hex` 0.4 (property tests and the vector files). A
  compile-time guard fails the build if any secret type of the crate, the
  cipher, or a signing key stops zeroizing on drop. cargo-vet imports the five
  sets the other branches use (Bytecode Alliance, Google, ISRG, Mozilla,
  Zcash); the 80 crates they do not cover at these versions are exempted, each
  with a note, five of them (`base64ct`, `const-oid`, `der`, `pkcs8`, `spki`,
  the last three banned outright in `deny.toml`)
  present only in `Cargo.lock` through `ml-dsa`'s weak `pkcs8?/alloc` and
  never built. `deny.toml` confines `hpke`, `ml-dsa`, `ed25519-dalek` and
  `bip39` to this crate, every transitive cryptography crate to the crates that
  wrap it (`x-wing`, `ml-kem`, `x25519-dalek`, `curve25519-dalek`,
  `fiat-crypto`, `sha2`, `sha3`, `hkdf`, `chacha20`, and the rest), `blake3`
  and `chacha20poly1305` to the keys and protocol crates (the protocol entry
  until the protocol merge drops its own dependency), and bans `ring` until
  the transport adds it; `deny-production.toml`, run by `gate.sh` and CI,
  holds the one rule a dev-only test tool (proptest's ChaCha20 generator)
  would otherwise break. A denylist cannot block a cryptography crate it does
  not name; review and cargo-vet cover that.
- Deferred to phase 2 (`suites.md` 2.1 allows it): ML-DSA-65 ACVP sigGen and
  sigVer vectors, which are not in the local cargo registry (nothing was
  downloaded), and a cross-check of the HPKE wrap against `hpke-rs`. bech32
  0.12.0 was not evaluated against its source, which is not in the local
  registry either; the crate stays on 0.11.1, whose Bech32m encoding and
  checksum this crate's use needs no fix in, and the next Dependabot update
  re-opens the question. Upstream residues, outside this crate's reach: `hpke`'s
  shared secret and key schedule, and `bip39`'s stack arrays during encoding,
  are not wiped by those crates; the allocator probe that would show freed
  copies is a phase 1 item.
- Reviewed (2026-10-17 to 2026-10-18) by three fresh-context agents (Claude
  Opus 5.5), one of them the security-reviewer pass, since this change touches
  keys and the protocol's records. Authors: ae7dd3f326008d354 wrote 70ff269
  and 0712ee5, aa83d092ae2e67eeb the fix pass 64579fd, and a732b163f9d79a0d8
  the ruling 29 fix ad61d73. Correctness reviewer a5b5274857e805201: 70ff269
  blocked by 1 (no fuzz targets for the decoders), 0712ee5 clean. Quality
  reviewer a682018f8bcdd4072: 70ff269 blocked by 1 (`chacha20poly1305` built
  without its `zeroize` feature), 0712ee5 clean with two should-fixes (the
  bulk load could panic on WebAssembly, and the 16-grant bound was untested at
  its edge), fixed in 64579fd. Security reviewer ada5dcf23d93a0724: 70ff269
  blocked by 3 (store flooding, a validity search far past quadratic in
  attacker-chosen shapes, secret copies escaping zeroization), 0712ee5 clean,
  and 64579fd clean with two should-fixes, ruled as ruling 29 and fixed in
  ad61d73; that 64579fd confirm also covered the quality reviewer's two
  should-fixes. Every blocker and should-fix was fixed as the coordinator
  ruled on it, or recorded as deferred above, and confirmed by a reviewer on a
  later version, except ruling 29's fix: the delta from 64579fd to ad61d73 was
  checked by the merge agent only (it changes only what the refusal memory
  lets a record that needs a refused one provide, `Validity::HeldSetFull` in
  place of the held-set `QuotaExceeded`, their tests and docs, and this
  entry's sentences on them). At merge ad61d73 was rebased from 9883767 onto
  0b8864a; the only conflict was this file, resolved by keeping both entries,
  `spec/` is main's unchanged, and the label-registry test passes against
  main's specs. The merge agent wrote this review record, which was not
  re-reviewed.

- Specification follow-up from the keys crate's reviews (rulings 22 to 28), one small
  commit on `spec/keys.md`, `spec/protocol.md`, `spec/suites.md` and
  `spec/threat-model.md`. Key-record storage gets three quotas that count only records
  signed by keys other than root, each against its signer (a grant against its issuer):
  `MAX_KEY_RECORDS_PER_FOLDER` (65 536), `MAX_KEY_RECORD_BYTES_PER_FOLDER` (512 MiB) and
  `MAX_KEY_RECORDS_PER_SIGNER` (4 096). They are judged last, after the duplicate check
  and the record's whole procedure; a record that would take a count past one is
  validity-only, with an issue naming the record's signer for the per-signer quota and
  naming the folder and the quota (and perhaps the signers holding the most records) for
  the two folder quotas. Root's key records count against no quota and are always
  accepted, unless one names a refused non-root record, so a delegate flooding the store
  can no longer block root's Revocation. A peer remembers, per folder and not across
  restarts, only the records it refused under a quota and, transitively, those refused
  because they depend on one, up to `MAX_REFUSED_REMEMBERED` (16 384, oldest forgotten
  first), by hash and by the key ID or epoch each creates; it lists them in
  `KeyRecordsRequest.have` (now up to 32 768 hashes), every dependency of the
  missing-dependency list is matched against them by hash, by the key ID a refused grant
  grants or by the epoch a refused Rotation creates, and a record depending on one is
  validity-only, with no request and no sender violation; a record refused by a
  grant-not-stored check whose curing grant belongs to a key with a remembered refusal
  is remembered too; a remembered record that arrives again is judged again. A check
  that fails only because a grant is not stored (an issuer's authority, a Rotation
  signer's tier 1 or 2 grant, a Wrap's tier, a signer's entitlement as issuer or
  ancestor, and an index record's writer grant of tier 1, so that a read key that writes
  is refused, not flagged, and its record is fetched again after a key-record resync) is
  always validity-only, never a signer or writer fault, since no peer can know it holds
  all of a key's grants (TM-10); the cost, a key issuing beyond its authority refused
  but not flagged, is stated, and checks on a record's own declared inputs, a Rotation's
  view closure among them, keep their blame. Senders send key records in the order they
  stored them in on-open sets and replies. The residuals are stated: insiders can fill
  the quotas, one `may_share` key through its own children; a refused record is missing
  for good on that peer and the members beneath it cannot sync with that peer; which
  records fit depends on arrival order; a restart re-sends each refused record once; the
  on-open set at the caps is at most 65 536 non-root records and 512 MiB plus root's. A
  rival or stale Rotation is stored as evidence only after its entitlement step passes,
  at most one per epoch for each signer other than root (root's are always stored), and
  `new_epoch` is at least 2. An epoch with more than one stored rotation is ambiguous
  until phase 7 settles it: no key for it is used, from a wrap or a ladder rung; the
  holder still runs the key confirmation and the HPKE open, which keep their blame, and
  only a check against a `confirm` chosen among the rivals is blameless. A Rotation is
  sent after its signer's tier 1 or 2 grant (none for root) and after the rotation that
  created `new_epoch - 1` (`protocol.md` §4.6). In `protocol.md` §5 the phase 7 items of
  the validity-only row are marked one by one. `suites.md` §3.1 says `ml-kem` is a
  direct dependency of `hpke` as well as of `x-wing` (the §2.4 label rows still match
  `keys.md` §10 byte for byte), and `threat-model.md`'s vocabulary no longer says root
  signs every key record. Vectors for phases 0 to 6 cover the quotas, the root
  exemption, remembered refusals, the missing-grant rule, the rival-rotation rules and
  the ambiguous epoch. Phase 7 follow-ups recorded: admitting a non-root record past the
  quotas when a stored root record names it; delegated repair records in a full store;
  order-independent admission; revoked flooders and quotas; step 7's convergence with
  different rivals per (epoch, signer); settling ambiguity by the ladder or a
  `previous_rotation` field; wrong-confirm blame against root for an epoch of 2 or more
  when root's rotation waits on a refused dependency and an attacker's is the only one
  stored; a seal failing under a rotation that may lose; a restart's writer fault while
  peers disagree on the binding Suspension; aligning "unless the receiver refused it"
  with "refused and remembers" once a second suite exists. A gap that follows records of
  the same writer refused validity-only in the same reply is a gap, not a sender
  violation. Decisions for the plan (also in the notes' decisions-pending): the quotas,
  their placement and the root exemption; remembered refusals; the missing-grant rule;
  send order; one stored rival per non-root signer and epoch after entitlement; the
  ambiguous-epoch rule.
  Reviewed (2026-10-17 to 2026-10-18) by two fresh-context agents (Claude Opus 5.5),
  one of them the security-reviewer pass, since this change touches keys and the
  protocol; the author was a592da16a093b3de4. The change implements rulings 22 and 23
  (from the keys crate's security review) and rulings 24 to 28 (from these reviews).
  The general reviewer a80d32ffd45706cfe: 93cf6bd blocked by 7, bdcf8c7 blocked by 8
  (mostly the same items as ruling 25), and 32d6011, a confirm of the whole delta from
  bdcf8c7, blocked by 3 (wording only: the Missing-dependency row's list, the issue a
  quota refusal names, and the TM-10 clause), applied in the final commit as ruling 28
  in the reviewer's words. The security reviewer aaae9c1b5f1114d87: 93cf6bd blocked by 1
  (ruling 24), bdcf8c7 blocked by 2 (ruling 25), e749931 blocked by 1 (ruling 26) and
  1d81d78 clean, with two wording should-fixes applied in 32d6011 as ruling 27. Every
  finding was fixed as the coordinator ruled on it, or recorded as a phase 7 follow-up,
  and each fix was confirmed by a reviewer on a later version (ruling 27's two by the
  general reviewer's confirm of 32d6011), except the ruling 28 wording: the merge agent
  checked that the delta from 32d6011 to the final commit changes only the ruling 28
  sentences, that `suites.md` §2.4's 22 label rows are still byte-identical to
  `keys.md` §10, and that main had not moved (no rebase), and it wrote this review
  record, which was not re-reviewed.

- The runtime contract, real-network edition (ruling 14, a fix forward on the
  merged simulator). Every promise in `licketysync_engine::runtime` is now about
  what one side sees: each side hears of its own connections' ends one at a
  time, in the order its runtime learned of them, never in the middle of a
  handler's effects, and a hang-up it asked for reaches it after that handler's
  effects; nothing orders what one side hears against another side, or against
  when the other side hung up. The two tests that pinned a cross-peer order are
  renamed as properties of this simulator. `Transport` is a byte stream: `send`
  appends bytes and `on_message` hands over 1 to `MAX_CHUNK` (64 KiB) bytes
  split anywhere, so framing and every size limit are the engine's (the protocol
  crate's frame decoder); a runtime may end a connection whose unsent queue
  would pass `MAX_SEND_QUEUE` (128 MiB), and the new `Transport::unsent(to)`
  reports that queue (added at the protocol spec's security confirm): the engine
  paces on it against a budget of its own, far below `MAX_SEND_QUEUE`, which is
  only where a runtime cuts, and polls it on a timer, since nothing signals that
  the queue has drained. When a connection ends, what the other side had not
  received may be lost, and the side cannot tell which. The Close flush is the
  engine's (send Close, then `close` on its own 1 s timer or on
  `on_disconnected`); after `on_stop` the runtime flushes what it wrote for up
  to 1 s (`STOP_FLUSH`) and then closes. The refused-send cases are listed in
  the `send` and `SendError` docs; an `Instant` never survives a restart, and a
  change of underlying stream is reported as `on_disconnected` then
  `on_connected`. In the simulator, writes made at one instant are cut at seeded
  boundaries into pieces of at most 64 KiB (so writes coalesce and fragment),
  each travelling with its own first-in first-out latency; a drop is a lost
  piece; at an end each side that can still receive is handed a seeded prefix of
  what was travelling towards it before its `on_disconnected`
  (`NetworkConfig::deliver_at_close`, default one half), and the rest, with
  anything not yet handed to the network, is lost; a clean stop's connections
  stay open while its stream drains, for up to a second, and a restart ends them
  before the new instance connects; a write past `max_send_queue` ends the
  connection (`DropReason::Overflow`); the unsent queue drains at the end of
  each instant, so `unsent` is 0 at each new instant (there is no bandwidth
  model; one is a follow-up, beside the per-side detection delay); every
  instance's monotonic clock starts afresh while the wall clock does not; and
  `Sim::stats` returns a `NetStats` of what the network did. Bug fixes, each
  with a regression test named after it: a reconnection scheduled by a drop
  reopened a pair that had hung up since (SF 6; it now carries the epoch the
  drop left and does nothing if the epoch moved, and a hang-up when no
  connection is open moves no epoch, so the hang-up an engine makes on hearing
  `on_disconnected` after its goodbye does not cancel the reconnection); and,
  found by the reworked prober, a peer that hung up on a connection whose end
  was already on its way still received the bytes that end owed it, whether the
  notice was queued or being handed over. The toy, prober and test peers frame
  their messages with a small length-prefix helper (`licketysync_sim::frame`, a
  bounded `Deframer`). The `contract` probers now frame their messages, hang up
  far less often (about 1 in 40 actions, 1 in 60 on connecting, 1 in 20 on
  hearing a disconnect), sometimes the engine's way (a goodbye frame, then
  `close` on a 1 s timer or the other side's hang-up), say goodbye or hang up
  from `on_stop`, number their timers in a block per instance, arm spare timers
  up to 2 s ahead, and check four more rules (chunk size, `unsent` arithmetic,
  early timers, timers of an earlier instance); half the crashes and stops come
  just after a reconnection round; and a goodbye's receiver hangs up only half
  the time, leaving the end to the goodbye's sender (its timer, or after a stop
  the flush). Measured on main and on this tree over seeds 0 to 199 of the
  contract scenario, by counting trace records: of the 2,400 crashes and stops,
  those followed at the same instant by some peer's `on_disconnected` for the
  peer that went down went from 155 to 1,866 (2,269 were heard of before the
  restart; `NetStats::downs_heard`, downs of a peer with a connection open, is
  2,172); of the 1,200 stops, those whose `on_stop` sent a frame went from 50 to
  783, and those whose `on_stop` hung up from 8 to 106 (`Report::stop_hang_ups`,
  which counts the hang-ups themselves, is 982); the `on_disconnected` calls at
  the instant the partition began, two for each connection it cut plus any
  hang-ups those provoked at once, went from 6 to 948 (`NetStats::partitioned`,
  the connections it cut, is 453); `NetStats::stopped`, connections a clean stop
  ended rather than a hang-up, is 817; and sampled every 100 ms over seeds 0 to
  19, with `Sim::is_connected` over the 10 pairs, 3 to 10 connections were open
  in 90% of samples, where on main 0 to 2 were in 94%. Over seeds 0 to 299 the
  probers' `Report` went from 418,539 sends, 60,073 messages checked and 84,466
  hang-ups to 954,334 sends (`sends`, those the runtime accepted), 653,174
  frames checked (`frames`) in 824,814 chunks (`chunks`) and 30,442 hang-ups
  (`hang_ups`, those ending a goodbye included). The suite test sets floors on
  these counts, `NetStats::stopped` among them. The timer-after-a-crash test now
  has the restarted instance arm a different timer and asserts the old one never
  fires. Thirteen mutations of the scheduler, an earlier review's two survivors
  among them, failed the suite on the first version of this change; on this one,
  fifteen of the sixteen its reviewer tried fail it, removing the restart rule
  among them (the sixteenth, letting the side that hung up receive what was in
  flight, changes nothing a peer sees, since those bytes are then discarded),
  and so does letting a close with no connection open move the epoch again.
  Every fingerprint changes. Reviewed (2026-10-17) by fresh-context agents:
  ad1e98affa01ff5a5 reviewed the merged rework on f1a0138 (blocked by 1: the
  contract promised an order across machines that only one process can give,
  which led to ruling 14), then this change's first version,
  ff424ba461fd8f49c29617d443104fae46fe5aa4 (clean, with one should-fix: the
  restart rule was tested by nothing); a663de736552845f3 reviewed that version
  (blocked by 1: a no-op close cancelled the network's reconnection after a
  drop). Both items were fixed in 931c199, and the fresh reviewer
  a01f3b9a3545befbf confirmed the delta from the first version to 931c199
  clean. No security-reviewer pass was required: nothing here touches keys, the
  protocol, file paths or the local API. At merge 931c199 was rebased onto
  a544ad5 without a conflict (`git range-diff` shows the patch unchanged), and
  the merge agent wrote this review record, which was not re-reviewed.
- Simulator and runtime traits (phase 0's gate, "simulated peers converge").
  `licketysync_engine::runtime` is the surface the engine will run on: a
  monotonic `Instant` for intervals and timeouts, `PeerId` and `TimerId`, and
  the traits `Clock` (`now()`, and `wall_time()` in Unix seconds as the device
  believes them, whose only permitted use is expiry: no conflict, ordering or
  acceptance decision may depend on it), `Timers`, `Transport`, `Storage`
  (staged writes that become durable only at `commit`, so a crash mid-write is a
  precise event), `Randomness`, their union `Context`, and the event-driven
  `Peer` with six handlers (`on_start`, `on_message`, `on_timer`,
  `on_connected`, `on_disconnected`, `on_stop`) that do no I/O except through
  the context. `Transport` promises the contract of `spec/protocol.md` 3.1,
  every promise about what one side sees (the entry above made the stream one of
  bytes and its loss "may be lost", ruling 14): nothing is ordered across
  connections, `send` is accepted only between `on_connected` and
  `on_disconnected` for that peer, which strictly alternate per peer (a runtime
  whose transport holds several connections to one peer collapses them into
  one), `close` hangs up and whether a new connection follows is the runtime's
  business; what a handler asks for (sends, timers, hang-ups) takes effect in
  the order asked, all of it before that peer's next handler runs; each side
  hears of its own connections' ends one at a time, never in the middle of a
  handler's effects; and until a side has heard `on_disconnected` the connection
  is open as far as it is concerned, so its sends are accepted and may be lost
  (`DropReason::Closed`). `licketysync-sim` implements all this as a
  discrete-event simulator: a queue ordered by time then sequence number;
  per-piece latency within bounds with first-in first-out delivery per
  direction; connection drops (with the configured probability a piece takes its
  connection down instead of arriving: both sides hear `on_disconnected`, what
  was in flight on it may be lost, and the two reconnect after a configurable
  delay); reordering across connections when the latency range is wide;
  partitions over a time window that close the connections they cut; crash
  (memory, timers and staged writes gone; committed storage kept), clean stop
  (`on_stop` first) and restart through the peer factory; per-peer clock skew
  applied to both clocks over a scenario-set wall epoch; bounded disks and a
  full-disk window; and a `Reconnect` fault as the way back after a peer hung up
  (the simulator never reconnects such a pair by itself; a partition ending or a
  restart also does). Closing a connection only queues its two notices, the
  closer's first; they are delivered first in first out (a property of this
  simulator, not of the contract) once the handler that closed it (or, when a
  connection opens, both sides' `on_connected`, which run before either side's
  effects are applied) has had every effect applied, and each peer's context
  reports as connected exactly the peers it has heard `on_connected` for and not
  `on_disconnected`. Fault times are unskewed simulation time and a window given
  backwards is the same window. Both sides learn of a connection's end at the
  same instant, a phase-0 simplification; a per-side detection delay and a
  wall-clock step fault are follow-ups. Timer generations come from one counter
  per run that is never reset, so a firing queued before a cancel, a re-arm or a
  crash can never match a later arming. A `Scenario` builder takes the seed,
  peer count, network, faults, wall epoch, event budget and a convergence
  predicate; `run_until(time)` and `run_until_quiescent(limit)` return an
  `Outcome` with the seed, the FNV-1a hash of every event and the last events,
  so a failing seed replays exactly. "Quiescent" means the predicate holds with
  no message in flight and no fault (or reconnection) pending; timers alone do
  not count as busy. A run that spends its event budget (default one million)
  stops and is reported as not converged, so a peer that never settles cannot
  hang the nightly job. The `licketysync-sim` binary runs a named scenario over
  a seed range and stops at the first that does not converge; the nightly "long
  simulator runs" job now calls it for 20,000 seeds per scenario (it ran
  `--ignored` tests, which the plan forbids without an issue link). Scenarios:
  `clean`, `drops`, `reconnect`, `cross-reorder`, `partition`, `crash`, `skew`,
  `disk-full`, `chaos`, `contract` and the deliberately failing `broken`. In
  `contract`, five probing peers (the `contract` module) send, hang up and arm
  or cancel a timer at random from every handler, `on_connected`,
  `on_disconnected` and `on_stop` included, under crashes, stops, restarts, a
  partition, drops and a reconnection of every pair each second, and check the
  runtime's promises from the inside (alternation, messages only inside a
  connection, once, in order and never after a hang-up, no refused send inside a
  connection, no fired cancelled timer, no call after `on_stop`, every hang-up
  answered); it converges when none is broken. Try it:
  `cargo run -q -p licketysync-sim -- list`,
  `cargo run -q -p licketysync-sim -- drops 0 100` (exit 0, one line with the
  first seed's fingerprint), `cargo run -q -p licketysync-sim -- contract 0 100`
  (the same for the contract probers) and
  `cargo run -q -p licketysync-sim -- broken 0 1` (exit 1, the seed and the last
  events). A toy set-union replicator exercises every handler and fault; tests
  prove determinism (same seed, same hash; different seeds differ), convergence
  under each fault class, in-order once-only delivery within a connection and a
  clean cut when one drops, that a crash loses staged writes and keeps committed
  ones, that skew moves both clocks and changes nothing else, the three
  timer-generation regressions, that a send outside
  `on_connected`..`on_disconnected` is refused, one regression test per hang-up
  ordering case (a hang-up inside `on_connected`, effects after a close in the
  same handler, a crash that provokes a hang-up, a peer not yet told, a hang-up
  inside `on_stop`, a chain of nested hang-ups), the contract probers over eight
  seeds with zero breaches, and that a run that never converges or never settles
  is reported with its seed. No new dependency: `rand_chacha` 0.9 would bring
  `ppv-lite86`, `zerocopy` and four build-time crates, none covered by the
  imported audits at these versions, so the simulator's generator is
  `SplitMix64` written in the crate (twenty lines, public domain, reference
  vectors tested); it is a statistical generator for a test tool and never
  touches key material. Arguments are parsed by hand for the same reason.
  `deny.toml` now allows version-less path dependencies between the workspace's
  own (unpublished) crates, which cargo-deny otherwise counts as wildcards;
  `licketysync-sim` depends on `licketysync-engine` that way. Reviewed
  (2026-10-17) by fresh-context agents over five rounds: a971af2ed5ce87852
  (round 1 on 4532312, blocked by 1: timer generations reset), a5383ca62b1824701
  (round 2 on c30355c, clean), a36eb74abc5fab3d3 (round 2 clean; round 3 on
  9fef2f1 blocked by 1: a hang-up inside `on_connected` reordered the other
  side's calls), a663de736552845f3 (round 4 on 4183b8e blocked by 1: hang-ups
  broke effect order; round 5 on 88aa3d8 clean, its three doc-only nits applied
  in the final commit, whose delta was checked to change comment lines only);
  every blocker was fixed and its fix confirmed, and ae9261016346c9d04 (round 1)
  was stopped before it reported. No security-reviewer pass was required:
  nothing here touches keys, the protocol, file paths or the local API.
- Specification: `spec/keys.md` and `spec/protocol.md` written (phase 0, "spec
  published"). `keys.md` fixes the derivation tree from the 24-word phrase (BIP39
  entropy as the master secret; every key a key pair set from one 32-byte seed through
  labelled BLAKE3 derive_key; per-folder root from the master secret and a public folder
  nonce; device keys generated per device, with a separate libp2p identity key), folder
  and device IDs as labelled hashes, the LAN and DHT discovery hashes, data keys and
  epochs with a downward key ladder, convergent chunk encryption with Padmé padding,
  issued keys and tiers (key IDs derived from both public halves of the key and
  recomputed by every verifier, so an ID cannot be squatted; every grant also carries
  the issued key's proof-of-possession signature, so nobody can grant a key that is not
  theirs; a key may hold several grants and is judged under its governing one, chosen
  among acyclic chains of at most 16 grants), the grant record with its HPKE wrap and
  canonical encoding, the verification algorithm (signature checked before any step that
  could blame a signer; in phases 0 to 6 grants beneath a known revocation stored and
  forwarded with an issue, their effect waiting for phase 7), the Bech32m key string and
  link and file forms, the rotation (with its key-record view, coverage judged against
  that view alone, the concurrent-rotation tie-break by record hash and key
  confirmation; the Folder record carries epoch 1's confirmation value so every ladder
  rung is checked), wrap, revocation and suspension (with cutoffs scoped to the revoked
  key's subtree, cutoff recovery, the one restart record after a suspension and the
  Wraps owed when one ends; a Lift names its Suspension by record hash) and lift record
  formats (phase 7), linked devices and the exported root file, the test-vector list and
  the label registry (now also the LAN beacon's salted peer tag and the BEP 44 DHT
  signing key). `protocol.md` fixes `/licketysync/sync/1`, framing with the critical bit
  and the pre-allocation length check, the transport contract (one security protocol per
  transport), the seven-step handshake with a transcript-bound device proof and an
  encrypted folder proof under a fresh nonce, every message's number and `.proto`
  schema, the index record on the wire with its Padmé-padded sealed second layer, dual
  chunk references and `resumes` field, index exchange by per-writer cursors (every
  request numbered and echoed by its reply pages) with gap and cutoff recovery, the fork
  rule (an equivocation sits at the equivocating record's own sequence and a writer's
  fork is the lowest one a peer has seen, so that the cursor exchange can carry the
  evidence; records before the fork stay applied, records at and after it are withdrawn,
  kept and never deleted, and a path a withdrawal empties goes through the archive and
  the deletion brake; at most one evidence record per sequence), the cursor (the highest
  chain sequence held, withdrawn records included, never decreasing) told apart from the
  applied head (the last record before the fork), a `Cursor` that also carries the
  requester's fork and the hash of its chain record at its applied head (fork evidence
  is then counted like any record and not re-sent once learned, and a clean split is
  found the first time two peers on different branches exchange cursors), the re-request
  from cursor 0 when an equivocating record names a parent the peer does not hold,
  incremental key-record resync, chunk transfer with the request-after-record rule, the
  complete failure table (close, reject-and-keep, flag the writer; no blame before a
  signature has verified), compatibility, the phase 0 scope and its own vector list.
  Threat-model items these files implement: TM-2, TM-3, TM-9 to TM-19, TM-22, TM-24,
  TM-30, TM-32 to TM-40. `README.md` now points at the four spec files. Deviations from
  the plan, each marked in the text and to be recorded in the plan's Decisions by the
  coordinator: (1) chunk compression is applied before encryption and settled at folder
  level, because ciphertext does not compress (`protocol.md` §4.7); (2) the per-folder
  key ID travels inside the encrypted FolderProof, not in Hello, so an unproven peer
  learns nothing about a device's folders (`protocol.md` §3.5); (3) a device's
  replacement key is issued by the old key's issuer or by root, since under cascading
  revocation a self-minted child cannot outlive its parent (`keys.md` §4.2); (4) sealed
  grants carry no wrapped data key (`keys.md` §5.3); (5) the exported root file uses
  age's scrypt passphrase recipient, the one passphrase not under Argon2id (`keys.md`
  §8.2); (6) a delegate that leaves a key out of its rotation's declared view cannot be
  prevented from doing so, only detected on every peer that holds the key, named in the
  issue and repaired by a Wrap, where the plan's "Revocation and epochs" says a delegate
  cannot lock anyone out by leaving them off (`keys.md` §7.1); (7) a grant is signed by
  its issuer and by the key it grants, where the plan's "Issued keys" has a grant signed
  by root (`keys.md` §5.3); (8) a Lift may be signed only by the Suspension's own
  signer, root or an ancestor of that signer, where the plan's "Changing a device's
  tier" lets the key's issuer or anything above it lift (`keys.md` §7); (9) the device
  name moved from Hello to the first Status after a folder opens on the connection,
  where the plan's "Capabilities" has Hello carry it, because the folder proof can be
  opened by anyone who knows the folder ID (`protocol.md` §4.5). New decision to record:
  key IDs are derived from both public halves, `be16(suite) || signing_pk || kem_pk`
  (`keys.md` §0.4), replacing "16 random bytes, never reused". From the index crate's
  round-2 review (coordinator rulings of 2026-10-15 and 2026-10-17), also to be
  recorded: the fork rule and its reason; at most one evidence record per sequence, a
  further record at a withdrawn sequence refused as a duplicate of the fork; withdrawal
  through the archive and the deletion brake (TM-35); the unknown-parent re-request from
  cursor 0, at most once per writer per connection; `Cursor` fields 4 `fork` and 5
  `head_hash` and the clean-split detection they give, the responder sending a
  `head_hash` mismatch record at most once per writer per connection (`protocol.md`
  §4.4, §4.5); and a wrap that will not open under the aad its record names is a signer
  fault the holder finds, as `suites.md` §2.1 says (`keys.md` §5.3, `protocol.md` §5); a
  peer's cursor never decreases, while its applied head moves back only by a stored
  cutoff or an equivocation withdrawal. From the round-4 reviews of this change
  (coordinator rulings of 2026-10-17), also to be recorded: the proof-of-possession
  signature on every grant under the new label `licketysync/v1/sig/grant-pop` (`keys.md`
  §5.3, §10); chains as acyclic grant paths to root of at most 16 grants, found by a
  bounded memoised search, the governing grant ordered by tier, `may_share`, expiry and
  then the smaller record hash, the governing chain the shortest valid one, and a chain
  over 16 grants judged at use (not chain-valid) rather than malformed at storage, a
  self-grant malformed; a key presentable through any chain of it whose grants are all
  unexpired, at the handshake at its best presentable chain's tier, while record
  entitlement (writes, issuing authority) keeps the expiry-insensitive governing grant;
  a key on two chains surviving the revocation of a key on only one of them, which is
  intended (`keys.md` §4.2, §5.4, §5.5, §7.2); a rival or stale rotation stored as
  evidence once its signature verifies and one above the current epoch + 1 a missing
  dependency, now said alike in `keys.md` §3.1 and §7.1; every unwrapped data key
  checked against its epoch's `confirm` before use, a mismatch charged to the record
  that carried the wrap (`keys.md` §5.3); in phases 0 to 6 the dense chain of stored
  rotations sets the epoch for dependency checks (`keys.md` §7); the folder-proof
  signature covers the key ID and is verified against the payload's leaf grant before
  any grant is verified or stored, and a prover sends its chain and makes at most four
  attempts per folder per connection (`protocol.md` §3.5); a missing suite reported as
  `suite:<n>`; one outstanding `IndexRequest` per folder per connection, with every
  trigger merged into the next one and rewound writers sent at seq 0, fork 0 and no head
  hash; the fork push when a fork is set or moves down; `head_hash` at the requester's
  applied head; fork and head-hash evidence each sent at most once per writer per
  connection; `MAX_WRITERS_PER_FOLDER` (16 384), so every writer fits one request;
  `MAX_PAGE_RECORDS` (4096) and the paging rule (sequence groups never split, an empty
  page takes one whole group, pages bounded by bytes too); `KeyRecordsRequest` timing
  anchored on the reply's last page, one outstanding per folder, with the `have`
  rotation kept and its bounded re-send cost stated (paging it by record-hash range is a
  phase 7 follow-up); the unknown-hash rule for chunks (a hash named by no record the
  holder holds), chunk writer faults judged per record; field numbers above 2^29 − 1,
  group wire types and absent fixed-size fields malformed; every frame before the peer's
  DeviceProof bounded by `PRE_HELLO_LIMIT`, which fits the largest Hello (4 617 bytes)
  and a DeviceProof (3 378); future-epoch grants from a proof held in a per-proof
  scratch set kept only on ACCEPTED, at most `MAX_HELD_GRANTS_PER_CONNECTION` (64) per
  connection; a verifier checks at most four proofs per hint-matched folder per
  connection; a responder serves a folder's `IndexRequest`s at most once per
  `INDEX_REQUEST_MIN_INTERVAL` (1 s), delaying, never refusing, the rest (per-peer
  upload fairness a phase 1 engine item); `Close.detail` free of control characters; the
  transport a byte stream with arbitrary chunk boundaries whose frame decoder enforces
  every limit, frames dispatched one at a time, the 1 s Close flush the engine's, and
  bytes unreceived at a connection's end possibly lost (`protocol.md` §2, §3.5, §4.2 to
  §4.7, §5). From the delta confirms (rulings 16 and 17 and the keys and index crates'
  landings), also to be recorded: encoded records capped at `MAX_INDEX_RECORD_BYTES`
  (4 000 000) and `MAX_KEY_RECORD_BYTES` (6 000 000), larger ones malformed at parse and
  growth only behind `required_features`; `MAX_DEVICES_PER_KEY` (256), with the residual
  that a `may_share` delegate minting 64 or more write keys can still fill
  `MAX_WRITERS_PER_FOLDER` until phase 7 frees a revoked key's slots; a singular field
  occurring twice malformed and repeated scalars accepted packed, unpacked or partly
  each, concatenated in order; every chain link authorizing (the issuer's grant on it
  has `may_share` and a tier at least as privileged); ancestry ("ancestor", "beneath",
  "descends from", entitlement to revoke, suspend, lift or wrap) as the keys reachable
  along authorizing issuer links within 16 links, repeats allowed and validity ignored,
  found by two breadth-first passes and only growing as grants arrive, so entitlement
  never depends on arrival order (ruling 18); the canonical chain (the shortest, ties
  broken by record hashes) kept only where one chain must be named, a push's chain and
  the suspension-weighted tier; validity and presentability found by a search memoised
  per (grant, remaining depth); a grant whose body is already stored answered as a
  duplicate before its proof of possession is checked; the governing grant fixing a
  key's record-entitlement tier whatever its other branches say; an epoch-1 `confirm`
  mismatch charged to the record that carried the wrap; held grants counting toward
  chains at the handshake; a holder signing a further grant's `key_signature` only on
  its owner's explicit action; `MAX_SEND_QUEUE` (128 MiB) with every frame but Close
  paced below it through `Transport::unsent`, and pushes that do not fit deferred and
  coalesced (per writer the push for its lowest fork and its newest other record,
  key-record pushes and the on-open set waiting), and a connection whose delivered bytes
  have not grown for `IDLE_TIMEOUT` while unsent bytes remain closed so that the next
  on-open set resyncs (TM-22); rotation coverage judged per grant, a key's `KeyWrap` at
  the most privileged tier among its kept grants; the size cap judged before the
  duplicate check; the unknown-hash set bounded at 64 with a repeat request malformed;
  `max_records` held between 64 and 4096; the bounded residual of the unknown-parent
  re-request. Phase 7 follow-ups recorded in the text: choosing the governing grant by
  effective tier, re-judging records when it changes, narrowing a cutoff's scope to the
  writers left with no valid chain, the gap Revocation cutoffs leave for intermediate
  issuers, freeing a revoked key's writer slots, and a revoked key's lasting signing
  authority over its descendants. From the last security checks (rulings 19 and 20),
  also to be recorded: a key is never its own ancestor; a Rotation's signer is root or a
  key holding a stored grant of tier 1 or 2, validity ignored; a holder whose ladder
  check fails adopts nothing from that rotation; a Wrap's validity judged per grant (a
  grant of its tier that begins a valid chain); in phases 0 to 6 a grant beneath a known
  revocation is stored and forwarded with an issue rather than refused, so the stored
  set does not depend on arrival order, and the phase 7 cutoff semantics for
  intermediate issuers is an open item with three options (store while a cutoff names a
  key whose grant is not yet stored, count held grants, or have cutoffs list the keys in
  between). From ruling 21: `MAX_KEY_RECORDS_PER_FOLDER` (65 536), a key record past it
  a validity-only rejection naming the folder, with the stated residual that an insider
  can fill the store until phase 7 and an on-open set at the cap of 65 536 records;
  phases 0 to 6 ignore stored Revocations, Suspensions and Lifts in validity,
  presentability and effective tier (stored, forwarded, cheap-checked, never applied),
  and a phase 7 folder that issues a Revocation will require a feature so that older
  peers are refused it. Also ruled in review: expiry bounds presenting and issuing only,
  so a temporary raise whose writes must end is closed by the issuer's suspension or
  revocation rather than by expiry alone (`keys.md` §4.2; plan "Changing a device's
  tier" to be edited); the one-security-protocol-per-transport rule of `suites.md` §2.6
  is restated here.
  Reviewed (2026-10-15 to 2026-10-17) by fresh-context agents over four rounds, each
  round with a security-reviewer pass, since this change touches keys and the protocol
  (rounds 1 to 3 Claude Fable 5.1, round 4 Claude Opus 5.5). Round 1:
  aa1baaa2a6ca86d35 (implementability, on caa57ca, blocked by 1: the FolderProof nonce
  was reused), a2530ecc2c52e6021 (coherence, on caa57ca, blocked by 1: the same) and
  the security reviewer a25b8108bd19a8ed1 (on 1bfc601, blocked by 3). Round 2, the same
  three on 0973889: aa1baaa2a6ca86d35 clean, a2530ecc2c52e6021 blocked by 1 (blame
  before the signature was verified), a25b8108bd19a8ed1 blocked by 1 (the same).
  Round 3 on d6db946: a7c9ec4b520606c43 (implementability, blocked by 1),
  ade78e3bd4198d04e (coherence, blocked by 1) and the security reviewer
  abe85422b8b1cd8a2 (blocked by 4). Round 4: a9c3b0518cbd3b4ab and the security
  reviewer a4dcae51dba3214e1 (on 7a71834) were stopped before they reported; then
  a2d40e61c1929e035 (general) on 456a0ff (blocked by 4), f79e20b (3), 310d5eb (1) and
  4c7f80f (clean), and the security reviewer a0652d0ad9492e5e8 on 456a0ff (blocked by
  9), f79e20b (4), 310d5eb (3), 4c7f80f (1), 918854d (3), 93e4301 (3) and f46496b
  (clean, a check scoped to the last ruling's items). Every finding was fixed as the
  coordinator ruled on it, or recorded as a phase 7 follow-up where the round-4 policy
  allowed (only phase 0 formats and rules block), before the next round. The final
  confirms were clean: the general reviewer on 4c7f80f, and the security reviewer's
  scoped check on f46496b after it had checked the later deltas 918854d and 93e4301.
- Repository created; workspace skeleton with the lint policy and CI gates from the plan.
- Process (decision 2026-10-14): no pull requests for our own changes. Every change
  is reviewed by two fresh-context agents and committed to `main` once `gate.sh`,
  the local gate that runs every CI check that can fail and fits on one machine,
  passes; Dependabot's update pull requests are the
  exception and get an agent review before merge. `CONTRIBUTING.md` has the short
  version and the review checklist (moved from the removed pull-request template);
  the placeholder `cargo gate` alias is gone. CI no longer cancels an in-progress
  run when a second commit reaches `main`. ClusterFuzzLite is manual until its
  `.clusterfuzzlite/` config exists; it then runs on every push.
- Supply chain: cargo-vet initialised with the Mozilla and Google audit sets
  imported (`supply-chain/`); the CI step now fails when vetting fails (it was
  written so that it could not).
- CI: cargo-geiger runs once per crate with an absolute manifest path, built with
  vendored OpenSSL; the previous `--workspace` call failed on the virtual workspace
  manifest. It is a report: first-party unsafe is forbidden by the workspace lint.
- CI: the no-hostnames check is now `ci/no-hostnames.sh`, run by `gate.sh` and CI
  and tested by `ci/test-no-hostnames.sh`. It compares hostnames found inside string
  literals, hostnames and IPv4 addresses alike and regardless of case, against
  `spec/allowed-hosts.txt` (created, empty); skips comment lines such as the
  licence header, loopback and documentation addresses; fails closed on a missing
  list or a malformed entry; and does not let the project's own domain clear a
  subdomain or a neighbouring host. The old
  step failed on the missing file, on an empty list and on the licence header. The
  rest of `spec/` is written in the entries that follow (protocol and keys here; the
  threat model and suites in their own change).
- Local gate (`gate.sh`) also runs doc-tests and rustdoc with `-D warnings`, as CI
  does.
- Coverage: the 90% line threshold is enforced per crate for keys, protocol and
  engine, in `gate.sh` and CI, as the plan reads; it was one total across the
  three, which let a well-tested crate mask another.
- Reviewed (all entries above, 2026-10-14): two independent fresh-context agents
  (Claude Fable 5.1), two passes each. The first commit was made before the
  second reviewer's final verdict, which found that a comment added after the
  first clean verdict failed the typos check, so the gate had not passed on it;
  the word was changed, the gate rerun, and the final tree confirmed clean by
  both reviewers before the commit was amended. Nothing here touches keys, the
  protocol, file paths or the local API, so no security-reviewer pass.
- Spec: `spec/threat-model.md` and `spec/suites.md` written (phase 0). The
  threat model lists the assets, the parties and trust boundaries, one subsection
  per adversary (network observer; peers at each key tier; sealed peers and relays;
  a stolen device; a hostile invite; a dishonest writer; the local API's attackers;
  a compromised static host; DHT Sybil and eclipse; resource exhaustion; supply
  chain), what is out of scope, and the plan's hardening-review table, Security
  paragraph and "key material is authenticated" item as forty numbered
  requirements TM-1 to TM-40 that code comments, tests and reviews cite, each with
  the incident it answers and the crate that enforces it; it ends with what stays
  visible and how reviewers use it. The suites file fixes the suite rule and suite
  1 in full: X-Wing through HPKE (the `hpke` crate's `XWing`, HKDF-SHA256,
  ChaCha20-Poly1305, mode_base; researched 2026-10-14, an off-the-shelf
  implementation exists, no combiner is written here), hybrid Ed25519 + ML-DSA-65
  with both signatures required and fixed-length encodings, XChaCha20-Poly1305
  with the nonce rules, BLAKE3 in its three modes plus the labelled hash `H` for
  identifiers over public data, with the label format
  `licketysync/v1/<area>/<purpose>` and the registry shared with `keys.md`,
  Argon2id at 64 MiB / 3 / 4, the transport suite (one security protocol per
  transport, TLS on QUIC and TCP and Noise only inside WebSocket, WebTransport and
  WebRTC; X25519MLKEM768 offered first through `libp2p-tls` on `aws-lc-rs` with
  `prefer-post-quantum`, confirmed by the phase 2 packet capture; `libp2p-tls`'s
  cipher-suite list accepted as shipped, a recorded deviation from the plan's
  "256-bit symmetric everywhere"; a separate libp2p identity key, with a per-folder
  or rotating identity recorded as a considered alternative), the approved-crates
  table with pins, audit status and the forbidden uses (`libp2p-identity` added),
  BIP39 for the phrase with the 256-bit entropy as the master secret, zeroization,
  constant-time, randomness and test-vector rules, and a suite 2 placeholder. The
  label table is copied byte for byte from `keys.md`'s registry, `hash/discovery-peer`,
  the peer tag in `hash/discovery-lan` and `key/dht-bep44` included; key IDs are
  derived over the key's signing and KEM public keys (`hash/id/key`, its first 16
  bytes; root keeps the all-zero ID and a derived all-zero ID is malformed; rulings
  2026-10-15 and 2026-10-17), and every grant carries a proof-of-possession
  signature by the key it grants (`sig/grant-pop`), so that a key with "may share"
  cannot attach a grant to someone else's key (TM-19, which also limits a lift to
  the suspension's signer or its ancestors). The `hash/id/key`, `sig/grant-pop` and
  `sig/folder-proof` rows, placeholders until the merge, were then copied byte for
  byte from `keys.md`'s registry as merged (cfc41da), and a script confirms all 22 of
  the table's rows byte-identical to it and in registry order. TM-5
  names the one
  generator written in the workspace that it permits, the simulator's seeded
  statistical SplitMix64, which feeds the runtime's randomness trait in simulator
  runs only and never reaches a production build; `rand` leaves the approved list
  (ruling 2026-10-15). The transitive-crate rule governs what a build ships: a path
  to a cryptography crate that runs only through dev-dependencies (`chacha20`
  beneath `proptest`) is outside it, checked with `cargo tree -e no-dev` (build
  dependencies stay in), and either a `deny.toml` entry for a crate test tooling
  also reaches lists that tool among its wrappers or the production bans move to a
  second cargo-deny configuration with `exclude-dev`, as the change adding them
  chooses (index ruling 2026-10-15); the transitive list is illustrative. The
  WebSocket path is classical end to end as `libp2p-websocket` 0.46.0 ships it (its
  outer TLS is rustls on `ring`, with no way to pass a provider), a recorded
  deviation from the plan's post-quantum transport with a phase 2 item (a reviewed
  patch or upstream change so that it accepts one); the quantum entry, TM-1 and the
  network observer say so. Providers are passed explicitly: first-party code builds
  rustls configurations only with `builder_with_provider` on `aws-lc-rs`, and `net`
  installs that provider as the process default at startup, an `Err` being a
  startup error unless the installed default lists X25519MLKEM768 first. `ring` has
  five roles (`libp2p-tls`'s certificate self-signature and CertificateVerify,
  `rcgen`, `snow`, `quinn-proto`'s stateless reset and token key, and
  `libp2p-websocket`'s outer TLS), its exact wrappers fixed when `net` is added.
  ML-DSA signs hedged in production (`ExpandedSigningKey::sign_randomized`, behind
  the `rand_core` feature, with `alloc` for the expanded key) and deterministically
  for vectors, and a test checks that two production signatures of one body differ
  in the ML-DSA half; `hpke` runs with `alloc` and without `getrandom`, sealing
  through `single_shot_seal_with_rng`; every generator handed to the engine or a
  listed crate is infallible, and the daemon's `getrandom` handler stops the process
  with `std::process::exit` and a distinct exit code on a failure, never `abort()`
  (whose core dump could hold keys, TM-6), a panic or a weaker source, and the daemon
  switches core dumps off at startup as a phase 1 item (section 4.3 and the
  `getrandom` row, ruling 8 as amended);
  the HPKE private key is loaded through the public `Kem::PrivateKey` and
  `Deserializable` path (module `kem::xwing`). `blake3`'s default build is stated
  as it is (assembly and C through `cc`, no WebAssembly SIMD). Only `keys` and
  `protocol`, which never sees plaintext and does not depend on `keys`, may call
  BLAKE3, and only from `keys`'s labels module and `protocol`'s hash module: the
  control will be a `deny.toml` entry with those two crates as `blake3`'s wrappers,
  landing with the first of them to merge, and Semgrep is a tripwire in both
  (ruling 9). `libp2p-websocket`'s outer TLS accepts TLS 1.2 while rustls's `tls12`
  feature is on, and in rustls 0.23 it is a default feature, on unless every crate
  that depends on rustls disables default features; the change adding `net` checks
  it. The
  post-quantum crates are unaudited, recorded as a deviation from the plan's
  "audited crates".
  The threat model's fail-closed rule (TM-10) names the three outcomes (close,
  reject and keep, flag the signer) and makes `protocol.md`'s rules table the
  record (decision 2026-10-15); omission of a key from a rotation's declared view
  is detected, named and repaired by a Wrap, not prevented (TM-19, TM-38, plan
  decision 2026-10-15); a forged grant inside a folder proof gets the same uniform
  REJECTED as any other failed proof (TM-10); TM-9's validity follows the expiry
  rule; TM-40 names the clock's door-keeping decisions (expiry ends presenting,
  which every verifier checks, while issuing, revoking, suspending and lifting end
  only in the signer's own software, so an entitled key's revocation, suspension or
  lift is applied whatever its expiry, and the records it signed stay accepted
  wherever they arrive) and its one use in conflict handling, the
  tie-break among kept concurrent heads (later modification time, then smaller
  record hash), which never beats a dominating version vector, compares and never
  subtracts, and raises an issue against the writer for a value the file system
  cannot set; TM-12, TM-14 and TM-15 are enforced by `keys` with `engine` as
  the caller; TM-16 states the fork rule (a `previous` that is not the chain record
  at sequence − 1, or a second record at one sequence, is an equivocation at its
  own sequence; the fork is the lowest seen; withdrawal hides and never deletes,
  and a path it empties goes through the archive and the deletion brake) and when a
  split is detected: the first time two peers holding different branches exchange
  cursors for that writer, because a cursor carries the hash of the requester's
  record at its applied head, a responder whose record there differs sends it once
  per connection, and a receiver re-requests the writer from 0 once per connection
  when that record's parent is unknown (coordinator rulings 3 and 4, 2026-10-17);
  TM-17 separates the advertised cursor, the highest chain sequence held with
  withdrawn records included, which never decreases, from the applied head, which
  moves back only by a cutoff or a fork the peer verified (index rulings
  2026-10-15); TM-34 states that the device in a record is the key holder's claim,
  and that any holder
  of a key can sign under another device's ID with it and fork that device's chain
  (one key per device, the default, confines this; recovery is a cutoff naming the
  chain to keep, phase 7, or a fresh key; a device restored from a backup
  equivocates the same way), which the stolen-device, invite and dishonest-writer
  adversaries now list; TM-31 states the hostname check's limits; TM-37 names the
  grant chain a link may carry (`g=`); what stays visible covers the hashed LAN
  beacon (unlinkable from its contents only) and its replay probe within the
  ±5-minute window, the stable identifiers a device publishes on the DHT (its
  address record carries no peer ID), the clear fields of an index record
  (`resumes`, each chunk's epoch and the Status fields included), and what anyone
  who completes a bare connection learns (device ID and hybrid key, the
  multistream-select protocol list, the Hello's lists, the proof-timing folder
  oracle, and the coarse folder count the first REJECTED proof's timing gives,
  with a constant-cost table as a phase 7 follow-up; the device name is now sent
  only after a folder has opened on the
  connection, in the first Status after the first folder opens, as
  `protocol.md` is amended to do, ruling 10). CI: `nightly.yml` gains the
  cargo-audit job that makes "daily" true; `.semgrep/project.yml`'s chunk-name
  rule, which missed `plain_hash` and `cipher_hash`, is replaced by two tripwires
  scoped to
  `crates/keys` and `crates/protocol` (`blake3-only-in-hash-modules` for every call
  into `blake3`, and `no-blake3-imports` for any `use` or `extern crate` of it), both
  excluding the two hash modules by path, test files and a `mod tests`, with their
  cases in `.semgrep/tests/project.rs`, which the Semgrep job in `ci.yml` runs with
  `semgrep --test` before the scan; the scan now excludes `.semgrep/`.
  `CONTRIBUTING.md` and `SECURITY.md` now point at the two files, and `README.md`
  (reconciled at merge) at all four spec files; its crate table gives `keys` the
  chunk and record sealing, keyed chunk hashes and Padmé padding (TM-12, TM-14,
  TM-15), which leave the `engine` row, and says that `index` withdraws an
  equivocating chain (TM-16) and the `engine` runs the archive and the deletion
  brake (TM-35).
  Reviewed (2026-10-15 to 2026-10-17) by fresh-context agents over four rounds, each
  round with a security-reviewer pass, since this change touches keys and the protocol
  as specification (rounds 1 to 3 Claude Fable 5.1, round 4 Claude Opus 5.5). Round 1
  on 513f223: a74bb1a288d9489ec (completeness, blocked by 1: the hashing modes
  disagreed with `keys.md`), a08df45ccf856ac74 (adversary model and usability, blocked
  by 1: a service-worker promise with no mechanism behind it) and the security reviewer
  ac6b3c856555306cb (blocked by 1: the stated libp2p-tls post-quantum gap was false).
  Round 2, the same three on e58547d: a74bb1a288d9489ec blocked by 5 (drift from the
  sibling spec), a08df45ccf856ac74 blocked by 1 (a label row that differed from
  `keys.md`), ac6b3c856555306cb clean. Round 3 on 5fb188f: a695f9fb4ebc07279
  (completeness, blocked by 4), ad4ae3897576caeb3 (adversary model and usability,
  blocked by 7) and the security reviewer a701ca89e63043940 (blocked by 1: `ring`'s
  roles). Round 4: a7df3a592271e21d6 (general) on ae9556d (blocked by 4), d524088 (1)
  and 4c37972 (clean), and the security reviewer a39cb1ded7fe75afa on ae9556d (blocked
  by 5), d524088 (2) and 4c37972 (clean). Every finding was fixed as the coordinator
  ruled on it, or recorded as a follow-up where the round-4 policy allowed (only phase
  0 formats and rules block), before the next round. Both final confirms were clean on
  4c37972. The two later deltas, 5de6f1a and 50820fb, apply those confirms' accepted
  nits and one ruled line and are wording only (exit instead of abort, "labelled and
  keyed", "after the first folder opens", the `tls12` default note and the folder-count
  timing line in section 5); the merge agent checked that `git diff 4c37972 50820fb`
  changes nothing else. At merge the merge agent copied the three registry rows (the
  script above checks them), reconciled `README.md` as the coordinator directed,
  moved this entry below the 2026-10-14 line and made `.typos.toml` ignore review
  agents' IDs (`a` and 16 hex digits), one of which in this line holds a fragment
  typos rejects; those merge edits were not re-reviewed.
