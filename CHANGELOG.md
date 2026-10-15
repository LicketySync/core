# Changelog

All notable changes to Lickety-Sync are recorded here. Each entry says what
changed and names the agents that reviewed it; anything touching keys, protocol,
paths or the API also names the security-reviewer pass.

## Unreleased

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
  the context. `Transport` promises the contract of `spec/protocol.md` 3.1: one
  reliable, ordered stream per connection, so a message is never lost,
  duplicated or reordered within a connection and loss shows itself only as
  `on_disconnected`; nothing is ordered across connections, and `send` is
  accepted only between `on_connected` and `on_disconnected` for that peer,
  which strictly alternate per peer (a runtime whose transport holds several
  connections to one peer collapses them into one). `close` hangs up: both sides
  hear `on_disconnected`, what was in flight is lost (sends from `on_stop` are
  lost the same way), and whether a new connection follows is the runtime's
  business. What a handler asks for (sends, timers, hang-ups) takes effect in
  the order asked, all of it before that peer's next handler runs; a
  connection's end is reported to each side in the order connections ended,
  never in the middle of another handler's effects; and until a side has heard
  `on_disconnected` the connection is open as far as it is concerned, so its
  sends are accepted and lost with the connection (`DropReason::Closed`). The
  daemon must give the same guarantees. `licketysync-sim` implements all this as
  a discrete-event simulator: a queue ordered by time then sequence number;
  per-message latency within bounds with first-in first-out delivery per
  direction; connection drops (with the configured probability a message takes
  its connection down instead of arriving: both sides hear `on_disconnected`,
  everything in flight on it is lost, and the two reconnect after a configurable
  delay); reordering across connections when the latency range is wide;
  partitions over a time window that close the connections they cut and make
  in-flight messages stale; crash (memory, timers and staged writes gone;
  committed storage kept), clean stop (`on_stop` first) and restart through the
  peer factory; per-peer clock skew applied to both clocks over a scenario-set
  wall epoch; bounded disks and a full-disk window; and a `Reconnect` fault as
  the way back after a peer hung up (the simulator never reconnects such a pair
  by itself; a partition ending or a restart also does). Closing a connection
  only queues its two notices, the closer's first; they are delivered first in
  first out once the handler that closed it (or, when a connection opens, both
  sides' `on_connected`, which run before either side's effects are applied) has
  had every effect applied, and each peer's context reports as connected exactly
  the peers it has heard `on_connected` for and not `on_disconnected`. Fault
  times are unskewed simulation time and a window given backwards is the same
  window. Both sides learn of a connection's end at the same instant, a phase-0
  simplification; a per-side detection delay and a wall-clock step fault are
  follow-ups. Timer generations come from one counter per run that is never
  reset, so a firing queued before a cancel, a re-arm or a crash can never match
  a later arming. A `Scenario` builder takes the seed, peer count, network,
  faults, wall epoch, event budget and a convergence predicate;
  `run_until(time)` and `run_until_quiescent(limit)` return an `Outcome` with
  the seed, the FNV-1a hash of every event and the last events, so a failing
  seed replays exactly. "Quiescent" means the predicate holds with no message in
  flight and no fault (or reconnection) pending; timers alone do not count as
  busy. A run that spends its event budget (default one million) stops and is
  reported as not converged, so a peer that never settles cannot hang the
  nightly job. The `licketysync-sim` binary runs a named scenario over a seed
  range and stops at the first that does not converge; the nightly "long
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
