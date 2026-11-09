Threat-model §6 record of the phase 0 gate (2026-11-02, at main 55ddfb4, re-reviewed on this commit, as 8494dc3 before it was amended to add this record).

# Phase 0 gate record: threat-model walk and security-reviewer pass (2026-11-02)

Gate: phase 0, "simulated peers converge; spec published". Reviewed: `licketysync/core` origin/main
**55ddfb4**. Reviewer: the
phase 0 gate reviewer (a fresh agent that wrote none of this code), against
`spec/threat-model.md` sections 3 and 4 (version 2 as of 55ddfb4) and the plan's roadmap (phase 1:
CLI, folder keys, mDNS, QUIC, scan and watch, conflicts, ignore files; phase 2: invites with
addresses, port mapping, peer relay, DHT; phase 3: service and local API, MCP, web UI, site,
installers; phase 5: linked devices, versioning; phase 6: browser client; phase 7: relays, Tor).
File paths below are relative to `core/`.

## What was run

- `cargo nextest run --workspace` at 55ddfb4: **654 passed, 1 skipped** (the `#[ignore]`d
  release-only `a_tree_delete_over_100_000_records_and_its_seven_cleanups`). The 17 gate tests in
  `crates/engine/tests/converge.rs` passed (seeds 0 to 4; `clean` 207 s).
- CI at 55ddfb4 (`gh run view 41544450911`): all 17 jobs green (clippy pedantic `-D warnings`,
  geiger, coverage 90% per crate, no-hostnames, nextest on Linux, macOS and Windows, rustdoc,
  gitleaks, typos, udeps, rustfmt, deny/audit/machete/vet, Semgrep, pinned actions, CI-script
  tests, Codecov); CodeQL green. The last nightly (green) ran at 5593b8d, **before** the three
  commits that make up the gate (9905ece, 6e8db80, 55ddfb4).
- All 19 fuzz targets built with `nightly-2026-10-18` and each run 120 s from its committed seeds
  (see TM-3).
- A probe (scratch only, deleted): every gate scenario, seeds 0 and 1, counting writes the engine
  refused (finding S2).
- Two scratch mutations, reverted and the copy re-diffed identical to origin/main (finding S1).
- Semgrep 1.x on a scratch file of `canonicalize`/`read_link` forms (finding S3).

Status words: **ENFORCED** = code seen and a test seen that fails without it (all ran green above).
**PARTLY ENFORCED** = some part enforced; the missing part is named and placed in or out of phase 0's
scope. **NOT YET APPLICABLE** = the enforcing layer does not exist yet; the phase that brings it.

## Requirements

| TM | Title | Status | Evidence | What is missing / phase |
| --- | --- | --- | --- | --- |
| TM-1 | No plaintext mode | PARTLY ENFORCED | `protocol`: only Hello or Close before the peer's Hello, only DeviceProof or Close before it verified, unknown types close pre-session (`crates/protocol/src/connection/mod.rs:1025-1052`); tests `the_first_frame_must_be_hello_or_close` (`connection/tests/handshake.rs:162`), `before_the_device_proof_only_it_or_close_is_accepted` (:191), `a_second_device_proof_closes` (:253), `hello_timeout_closes` (:147) | `net` half (no unencrypted listener or dialer, one security protocol per transport): `crates/net` is a placeholder. Outside phase 0: phase 1 (QUIC, TCP) and phase 6 (WebSocket, WebRTC, WebTransport) |
| TM-2 | Untrusted bytes; lengths checked before allocation | PARTLY ENFORCED | Frame length checked before any body buffer (`crates/protocol/src/frame.rs:436-463`), tests `oversize_length_allocates_nothing` (frame.rs:630), `every_length_over_the_limit_is_refused_before_allocation` (:785, proptest); field lengths limit-then-remaining before slicing (`wire.rs:274-289`), test `length_delimited_fields_check_limit_then_remaining_before_slicing` (wire.rs:623); every repeated field counted before push (`wire.rs:439-463`), tests in `parse/tests.rs` (`hello_lists_and_grammar`, `index_record_step_one`, `cleanup_record_step_one`, `status_and_chunks`, ...); key strings and links checked against their maximum first (`crates/keys/src/keystring.rs:130`, :326) | `net` per-connection budgets: phase 1. NIT N1 on fields bounded only by their enclosing buffer |
| TM-3 | Every decoder fuzzed | ENFORCED | 19 targets in `fuzz/fuzz_targets` cover frames, every message body, Hello checks, FolderProof, the connection state machine, IndexRecords pages, the SignedRecord envelope, Record parse and step 7, SealedMeta and `check_path`, seal and chunk opening, device proofs, reconcile messages and `Prefix::from_wire`, key strings, words, links, link codes, stored keys and index operations over a stored state; `fuzz/seeds/<target>` committed for all 19; `.github/workflows/nightly.yml` runs each 30 min (`-max_total_time=1800`). Locally at 55ddfb4: all 19 built and ran 120 s each without a crash, leak or timeout | Per-push fuzzing waits for ClusterFuzzLite's config (stated in TM-3). NIT N2: the engine's own store decoders have no target; NIT N3: `index_ops` and `reconcile` (new in this gate) have never run in CI |
| TM-4 | One beneath-root resolver; symlinks never followed | NOT YET APPLICABLE | Phase 0 has no disk: the engine writes the simulator's file model, a flat map from path to base (`crates/engine/src/write.rs:5-8`, `crates/engine/src/lib.rs:13-16`, `sync/disk.rs`); there is no symlink kind (`crates/protocol/src/record.rs:417-433`, any other kind is a writer fault, held opaque). What exists: the path grammar `check_path` refuses empty, over 4 096 bytes, leading `/`, NUL, `\`, empty, `.` and `..` components (`record.rs:574-598`), test `paths` (`record/tests.rs:701`), applied to received records at step 7 (`record.rs:764`) and to local writes; Semgrep rule `no-follow-symlinks` with cases in `.semgrep/tests/project.rs:120-127` | Phase 1 (scan and watch): the resolver, reserved and platform-invalid names, no-follow opens, the committed symlink-then-directory test. Finding S3 (Semgrep misses the method forms) |
| TM-5 | Cryptography only from `suites.md` | ENFORCED | `deny.toml:42-104` confines blake3, chacha20poly1305, ed25519-dalek, bip39 to `licketysync-keys` and their primitives to their wrappers, bans ring, openssl, md5, sha1, PKCS#8/DER/SPKI; `deny-production.toml` drops the proptest exceptions; `cargo deny check` (both configs) and `cargo vet --locked` in `gate.sh:198-204` and green in CI. Padmé (`crates/keys/src/chunk.rs:52`) tested by `padme_bounds` (chunk.rs:526) and `vector_padme` against an independent reference (`test_vectors.rs:640`); power-of-two metadata padding (`sealed_meta.rs:119`) tested by `bucket_boundaries` (:460); SplitMix64 only in `crates/sim/src/rng.rs`, test `matches_the_reference_vectors` (:93); `sim` is a dependency of no production crate (daemon, cli, decrypt have none; engine has it as a dev-dependency only) | The `sim`-not-in-production rule is review-only, as TM-5 says. NIT N4 (test-only generators) |
| TM-6 | Secrets in zeroizing types, never in logs | PARTLY ENFORCED | `secret32!` (`crates/keys/src/secret.rs:38-66`): Zeroize + ZeroizeOnDrop, redacted `Debug`, no `Clone`, no `Display`; compile-time ZeroizeOnDrop guards over every secret type and the dependencies' key holders (`secret.rs:262-287`); `WriteKey`, `ReadKey`, `SealedKey`, device keys and handshake keys redact `Debug`; tests `debug_is_redacted_and_bytes_round_trip` (secret.rs:301), `debug_output_names_the_folder_and_nothing_secret` (folder.rs:904), `debug_names_no_secret` (`crates/engine/src/config.rs:332`); no error type carries secret bytes; engine issues carry no secret | Daemon logging and its redaction of folder IDs and addresses, the store key and passphrase types: phase 1 (key store) and phase 3 (daemon). Outside phase 0 |
| TM-7 | No `unsafe` outside FFI crates | ENFORCED | `unsafe_code = "forbid"` (`Cargo.toml:15`), `[lints] workspace = true` in all nine crates; no `unsafe` in `crates/` or `fuzz/`; `ci/geiger.sh` against `ci/geiger-baseline.txt`, tested by `ci/test-geiger.sh`, both in `gate.sh:220-221` and green in CI | NIT N5 (the fuzz crate has no lint table) |
| TM-8 | Dependencies only by reviewed change | ENFORCED | `gate.sh:198-204` (deny, production bans, audit of both lockfiles, vet `--locked`); `supply-chain/config.toml` exemptions each with notes; both lockfiles committed; daily `cargo audit` (`.github/workflows/nightly.yml`, job `audit`); `.github/dependabot.yml` with a 7-day cooldown; CI green at 55ddfb4 | — |
| TM-9 | Only signed updates; no key in a folder; store re-checked at open | ENFORCED | Verify before store (`crates/index/src/index.rs:636`, store at :648); duplicate, expired and obsolete ignored unverified (:595-621); a covering record drops only inside `store` after verification; a write holder verifies before noting (:849-855); at open every stored record and base gets step 1 and its signature, across threads (`crates/index/src/verify.rs:34-61`, `open.rs:52-58`), stored mark accepted only up to a day over what records and clock justify (`open.rs:115-128`), folder kept closed when records lie more than a year ahead (:129-131), epoch redrawn when anything dropped (:135-140, as `protocol.md` section 5 says). Tests: `vector_outcomes` (`crates/index/src/tests/outcomes.rs:59`: garbage-signature duplicate, forged obsolete, forged expired), `a_stale_copy_is_verified_before_it_is_noted_c1_sc1` (outcomes.rs:505), `a_record_changed_at_rest_is_dropped_and_reported_at_every_tier` (`tests/open.rs:99`), `the_stored_high_water_mark_is_checked` (open.rs:227), `clock_set_back_at_open` and `base_failing_at_open` in `vector_heads` (heads.rs:1277), `the_open_issue_gives_the_counts_and_at_most_sixteen_hashes` (`crates/engine/src/tests.rs:298`), `a_restart_rebuilds_an_equal_view_and_shows_checking` (tests.rs:444), `a_folder_whose_records_lie_more_than_a_year_ahead_stays_closed_and_opens_by_itself` (`crates/engine/src/rules.rs:320`), `a_bit_flipped_inside_a_pushed_body_is_forged_and_closes` and `a_body_signed_with_another_folders_key_is_forged` (`crates/engine/tests/adversary.rs:212`, :225); the oracle checks every start showed Checking (`crates/sim/src/oracle.rs:240`). No key field exists in any message or record (`crates/protocol/src/messages.rs`; keys come only from `EngineConfig`) | "No record carries key material" holds by schema, with no test; acceptable as structure |
| TM-10 | Fail closed | ENFORCED | `crates/protocol/src/rules.rs` maps every section 5 cause to close, keep or issue-against-the-record, tests `the_table_of_section_5` (:314) and `every_outcome_leaves_a_trace` (:362); `judged_closes_on_the_first_refusal_that_closes` (`connection/tests/exchange.rs:1466`); held opaque with an issue naming the record and no blame (`a_garbage_seal_is_stored_opaque_everywhere_and_names_the_record`, adversary.rs:232); chunk corrupt for its record (`a_chunk_whose_seal_will_not_open_is_corrupt_for_its_record_and_never_fetched_again`, :251); uniform REJECTED for a reflected, replayed, bad-seal, out-of-range-tier or paused-folder proof with the connection kept (`folder_proof_verification_steps`, `connection/tests/handshake.rs:351`); no key type implements `Default`; `unwrap_used`, `expect_used` denied | "A message for a folder not open here" is tested only for folders not held: finding S1. NIT N6 (issues carry no path where TM-10 says "and by path where its seal opened") |
| TM-11 | One label per purpose key; AD binds every ciphertext | ENFORCED | Private label constructors and registry (`crates/keys/src/labels.rs:93-221`), tests `registry_matches_keys_md_section_10_exactly` and three more in `crates/keys/tests/registry.rs:102-152`, `registry_has_no_duplicates_and_every_label_is_well_formed` (labels.rs:360), `derivations_use_one_label_each` (secret.rs:351), 16 `vector_derive_key_*`; chunk AD = folder ID (`chunk.rs:328`, :364), test `different_plaintexts_get_different_nonces_and_folders_separate` (chunk.rs:567); sealed metadata AD = `folder_id \|\| path_tag`, cleanup AD = folder ID (`sealed_meta.rs:249-255`), test `a_seal_is_bound_to_its_folder_its_path_tag_and_its_record_type` (:531) plus `vector_index_record` moves; handshake payload AD = hint, test `a_proof_opens_only_for_the_same_folder_transcript_and_role` (`handshake.rs:291`) | — |
| TM-12 | Fresh nonce per write | ENFORCED | 24-byte random nonces through the caller's `RandomFill` for sealed metadata (`sealed_meta.rs:335-336`) and proofs (`handshake.rs:145-146`), tested at sealed_meta.rs:531 and handshake.rs:291 (nonce equals the draw, two seals differ); chunk nonce keyed from the padded plaintext (`chunk.rs:323-324`), pinned by `vector_chunk`; the engine cannot encrypt on its own (chacha20poly1305 confined to keys by `deny.toml`) | — |
| TM-13 | Each file record signs its full chunk list | ENFORCED | Ordered `(cipher_hash, stored_len)` list in the signed body (`messages.rs:304`, parsed `record.rs:153-171`), hash count must equal chunk count (`record.rs:779`); reply checked against the requested hash (`connection/chunks.rs:377`); engine judges each (record, position) by stored length and plaintext hash (`crates/engine/src/chunks.rs:446-482`), reassembles in record order with the size checked (`inspect.rs:340-352`). Tests: `replies_that_close` (`connection/tests/chunks.rs:176`, a substituted chunk closes as forged), adversary.rs:251, :302, :324, :492, `signing_and_verifying_under_the_folder_key` (`crates/keys/src/records.rs:479`) | Reorder and duplicate have no test of their own; they are impossible by construction (chunks are fetched by hash from a signed, ordered list) |
| TM-14 | Keyed chunk hashes; have-queries only inside the folder | PARTLY ENFORCED | `plain_hash` keyed under `hk` (`chunk.rs:206`), cipher hash labelled (`chunk.rs:120`), path tag keyed under `tk` (`sealed_meta.rs:243`), tests `vector_chunk`, `path_tags_are_byte_for_byte` (sealed_meta.rs:650), `vector_path_tags`, `the_gear_table_is_the_folders_and_only_the_folders` (chunk.rs:453); `deny.toml` confines blake3 to keys; Semgrep tripwire (`.semgrep/project.yml:17-64`) and its cases run in `gate.sh:212`; chunk requests refused unless the folder is open on the connection (`connection/chunks.rs:334`, :269) | **Finding S1**: no test sends a have-query (or any folder-scoped message) for a folder the device holds but that is not open on the connection. Keyed FastCDC: phase 1 (phase 0 cuts fixed-size chunks, stated in TM-14) |
| TM-15 | Padmé padding; the volume leak documented | ENFORCED | Padmé as under TM-5; `seal_chunk` refuses more than `MAX_CHUNK_PLAINTEXT` (`chunk.rs:315`), test `writer_bounds_and_the_largest_chunk` (:634); the engine's `chunk_size` refused above it (`crates/engine/src/config.rs:192`), test `each_bad_setting_is_refused_with_its_reason` (config.rs:259: 0, 1, the maximum and one over); phase 0 compresses nothing | FastCDC's maximum: phase 1 |
| TM-17 | Persist and refuse regressions | ENFORCED | Drops only by a held record or cleanup (`crates/index/src/state.rs:388-419`, :461-473); a sealed peer drops only by a name or an applying cleanup group (`state.rs:263-268`, :404-416; expiry returns early at a sealed holder, `index.rs:796`); stale snapshots obsolete (`index.rs:611-621`); forgetting by the folder's own time (`index.rs:677-688`). Tests: the `check_drops` audit (`tests/kit.rs:802`) asserted empty in `histories_keep_claims_a_b_c_f_j_k` (`tests/properties.rs:640`), `pruning_takes_entries_out_only_c` (:687), `every_step_rolls_back_exactly_and_holders_agree_k1_k2_k3` (:1059); property (f) at :646; `cleanup_group_acts_only_while_its_because_is_held_r1_b1` (`tests/cleanups.rs:590`); `expiry_by_the_folders_own_time_b1` (heads.rs:1309) | — |
| TM-18 | Invite secrets only after `#`; no landing page | PARTLY ENFORCED | Link parser accepts only `https://licketysync.app/join#` (`crates/keys/src/keystring.rs:187`, :329); tests `tm_18_links_on_other_domains_are_refused` (:772), `tm_18_link_and_file_forms` (:616), `link_rejections` (:658) | `web` (the client origin serving nothing else) and `site`: other repositories, phases 6 and 3; not reviewed here |
| TM-20 | Peer strings render as text only | NOT YET APPLICABLE | Phase 0 renders nothing; the protocol keeps peer strings to their grammar and marks a Close detail that breaks it as not shown (`connection/mod.rs:493`) | `app`, `web` and the CLI's terminal output: phases 1 (CLI), 3 (app) and 6 (web) |
| TM-21 | Local API checks Host, Origin and token | NOT YET APPLICABLE | `crates/daemon` is a placeholder | Phase 3 |
| TM-22 | Bounded per-peer tables | PARTLY ENFORCED | Each bound defined in `crates/protocol/src/limits.rs` and tested: `MAX_PEER_STATES` (`index.rs:917`; `stored_per_peer_state_is_clamped_to_the_clock_and_capped`, `tests/open.rs:547`; `vector_digests`), `MAX_FUTURE_KNOWN` (`connection/index.rs:238-247`; `the_memories_of_a_connection_are_bounded`, exchange.rs:2444), `MAX_NOTE_VERIFICATIONS` per 10 s shared by every folder (`connection/index.rs:211-226`; `one_note_budget_per_connection_ps1`, exchange.rs:2472; `a_connection_past_max_note_verifications_notes_nothing_more_this_window`, `tests/bounds.rs:140`), `MAX_PEER_NAMES` (bounds.rs:52, :80, :106), `MAX_CLEANUP_ENTRIES` (parse and draft, `cleanup_record_step_one`, `a_rounds_cleanups_are_paged_by_groups_and_names`), the 1 921-prefix work list (`children_for_a_full_key_is_a_sender_violation_and_the_work_list_holds_1921`, exchange.rs:565), `MAX_PASS_REQUESTS` (`a_pass_stops_at_max_pass_requests`, exchange.rs:888), requests in flight both ways (`in_flight_limit_on_the_requester`, `a_peer_that_floods_requests_and_never_reads_is_bounded`, `connection/tests/chunks.rs:665`, :948; adversary.rs:336), `MAX_SEND_QUEUE` (`sending_rules`, `busy_at_dispatch_exactly_at_half_the_queue`), `REPLY_PAGE_TIMEOUT` (`the_reply_deadline`, exchange.rs:1962), proof hints (`proof_envelopes_and_results_that_close`, handshake.rs:420; `the_open_folder_bound_rejects_the_65th`), digest-cache leaves of at most 64 and at most 128 nodes per change (`vector_digests`, digests.rs:503); duplicates, obsolete and expired ignored unverified (`vector_outcomes`); tables freed on close (`finish_tables`, `connection/mod.rs:1378`) and the engine's per-connection state dropped on disconnect (`crates/engine/src/engine.rs:652-654`) | libp2p connection, stream and transient limits, the flood test "in sim", QUIC anti-amplification and the phase 1 connection limit: `net`, phase 1. NIT N7 (sub-rules held by structure only) |
| TM-23 | No `unwrap`, `expect`, `panic` or unchecked index on untrusted input | ENFORCED | `Cargo.toml:25-28`; `gate.sh:194` and CI run clippy with `-D warnings`; the three non-test `indexing_slicing` allows are provably in range (`crates/index/src/trie.rs:257`, nibble `& 0x0f` into 16 children; `crates/keys/src/chunk.rs:154`, a `u8` into 256 entries; `crates/engine/src/issues/mod.rs:362`, a `const` check); no `unwrap`/`expect`/`panic` allow outside tests; every non-test `assert!` is compile-time; Semgrep `no-expect-on-remote-data` with cases at `.semgrep/tests/project.rs:131-150` | — |
| TM-24 | DHT: daily hash, client mode | NOT YET APPLICABLE | The daily discovery hash derivation exists in `crates/keys/src/discovery.rs`; nothing announces | `net`, phase 2 |
| TM-25 | Relays | NOT YET APPLICABLE | — | `net`, phases 2 (peer relay) and 7 (relays) |
| TM-26 | Port mapping | NOT YET APPLICABLE | — | `net`, phase 2 |
| TM-27 | Tauri isolation, CSP, capabilities | NOT YET APPLICABLE | — | `app`, phase 3 |
| TM-28 | Signed manifest of the browser bundle | NOT YET APPLICABLE | — | `web` and the release workflow, phase 6 |
| TM-29 | Updates via channels; signed releases with SBOM and provenance | NOT YET APPLICABLE | `.github/workflows/release.yml` builds, makes SBOMs and attests provenance, publishes nothing; the binaries do nothing an update would | Packaging and store channels: phases 3, 4 and 7; nothing is released before 1.0 |
| TM-30 | Suite lists bound to the transcript | PARTLY ENFORCED | Both Hellos, byte for byte, and the protocol ID in `th` (`crates/protocol/src/hello.rs:55-80`), test `roles_and_the_transcript` (hello.rs:281: identifiers, protocol ID, Hello boundaries); the DeviceProof signs `th \|\| role`, test `the_device_proof_binds_the_transcript_and_the_role` (`crates/keys/src/device.rs:398`); no common suite closes, test `hello_check_failures_close_with_their_reasons` (`connection/tests/handshake.rs:271`); the folder ID hashes the suite and a record of another suite is refused, tests `the_derivation_tree_of_keys_md_1_2` (folder.rs:621), `step_one_binds_the_record_to_the_open_folder` (`record/tests.rs:270`) | Newest-common-version choice is multistream-select's (`protocol.md` 1): `net`, phase 1; phase 0 has one identifier. Outside phase 0 |
| TM-31 | No host outside `allowed-hosts.txt` | ENFORCED | `spec/allowed-hosts.txt` is empty (phase 0 contacts nothing; no network code exists); `ci/no-hostnames.sh` with `ci/test-no-hostnames.sh`, in `gate.sh:222-223` and the CI job, green | — |
| TM-32 | Proof of a key without sending it | ENFORCED | Hint and sealed payload bound to `th` and role (`crates/keys/src/handshake.rs:108-175`); hint lookup before any AEAD work, uniform `ProofResult` (`connection/handshake.rs:194-246`, :258-278); device ID = labelled hash of the canonical, not-small-order key, proven by the DeviceProof (`device.rs:93-133`). Tests: `folder_proof_verification_steps` (handshake.rs:351: reflected, replayed, bad seal, tiers 0 and 4, paused folder), `a_folder_the_peer_lacks_is_rejected_and_proof_timeout_closes` (:124), `the_proof_is_bound_to_the_transcript_role_and_folder` (`proof.rs:198`), `non_canonical_and_small_order_device_keys_are_refused` (hello.rs:264), `outsiders_are_refused_and_see_nothing_of_a_folder_they_do_not_hold` (`crates/engine/tests/outsider.rs:54`) | The proof itself is enforced; that a peer which opened nothing is then refused service is finding S1 |
| TM-33 | Symmetric encryption before content leaves; Ed25519 stated | PARTLY ENFORCED | Every AEAD call is in keys under data-key-derived keys (`crates/keys/src/aead.rs:57-97`, chunk.rs, sealed_meta.rs); no message carries folder key material (`messages.rs`); signatures Ed25519 `verify_strict` only (`sig.rs:89-106`), tests in sig.rs and `vector_ed25519_rfc8032` (`crates/keys/tests/kat.rs:38`) | Linked devices over TLS 1.3 with X25519MLKEM768: phase 5. Outside phase 0 |
| TM-35 | Atomic writes; destruction reversible | NOT YET APPLICABLE | No disk, no temporary file, archive or brake in phase 0 (`crates/engine/src/lib.rs:13-16`, `write.rs:7`, `sync/disk.rs:25`); peer deletions are applied without a brake, as TM-35 says | Atomic writes and the deletion brake: phase 1 (scan and watch); the archive (versioning, Trash can): phase 5 |
| TM-37 | Key strings carry only key and checksum; bare invites | PARTLY ENFORCED | Payload `be16(suite) \|\| key material` with exact lengths (`crates/keys/src/folder.rs:510-541`); `Link::bare` adds nothing (`keystring.rs:260`); tests `key_strings_round_trip_in_both_cases` (:412, exact lengths), `key_string_rejections` (:436), `vector_key_string`, the bare link's exact length (keystring.rs:653-654) | What the CLI, app and web offer: phases 1, 2, 3 and 6 |
| TM-39 | Keys leave a device only by the person's action | NOT YET APPLICABLE | No export path exists (daemon, cli, app are placeholders); phase 0 stores no key (`crates/engine/src/store.rs:28-29`) | Phase 3 (daemon, CLI commands, app), phase 5 (linked-device transfer) |
| TM-40 | Version vectors, never clocks; folder's own time; the clock rule | ENFORCED | Display-order tie-break only (`crates/index/src/views.rs:173-180`); clock floor `max(hw + 1, min(clock, CLOCK_FLOOR_MAX))` (`index.rs:424-432`); folder's time = greatest applied counter (`state.rs:240-242`); horizons 365 and 30 days (`limits.rs:124`, :129); Hello clock rule when the first folder opens (`connection/handshake.rs:313-330`); record more than a year ahead refused once per connection (`index.rs:623-633`); a day ahead warns (`index.rs:756-759`). Tests: `coverage`, `display_order`, `arrival_order` and `the_spread` in `vector_heads` (the spread fails without the clock floor), `order_and_clock_do_not_matter_d` (properties.rs:715), `expiry_by_the_folders_own_time_b1`, `the_clock_rule_closes_both_sides_when_the_first_folder_opens` (handshake.rs:795: 365 days syncs, 366 closes both sides, a stranger only counted), `vector_outcomes` cases at outcomes.rs:201-274, `a_record_from_the_future_is_refused_with_the_issue_naming_its_device` (`crates/engine/src/rules.rs:277`), gate scenarios `skew` and `clock_ahead` | NIT N8 (boundary cases) |
| TM-41 | Concurrent versions kept; peers converge; sealed peers lose nothing | PARTLY ENFORCED | Index property tests of `protocol.md` 8 item 7: (a), (b), (f), (j) `histories_keep_claims_a_b_c_f_j_k` (properties.rs:640), (c) :687 and :1100, (d) :715, (e) and (g) `caught_up_holders_agree_e_g` (:754), (h) :788, (i) `two_records_with_one_dot_i` (:818), (j) :850, (k) in `World::write` (:210-243) and K1-K3 at :1059, (l) and (m) in `tests/structures.rs` and `tests/digests.rs`; equivocation (adversary.rs:437, gate scenario `clones`); writer faults held opaque (`vector_outcomes`); a local write built only from bases (`the_lost_update_r1_b2_s1`, heads.rs:1304; `crates/engine/src/rules.rs:172`; note of 2026-11-08: since the identical-heads fix, from the bases and their twins, the concurrent heads of a base's content that, for the base at the path, come after it in display order, and never the first head in display order, `crates/index/src/tests/identical.rs`); the exchange compares set digests over record hashes (`the_cache_is_the_digest_m`, digests.rs:558); the 17 gate scenarios and the oracle (below) | The archive that holds what a remote change replaced: phase 5. NIT N9 (three property tests weaker than their letters) |
| TM-42 | Removing someone is unlinking and sharing again | NOT YET APPLICABLE | Nothing in the protocol moves a key or history between folders (no key field anywhere) | What the app and CLI say and offer: phases 1 and 3 |
| TM-43 | Pruning and expiry never silently lose | ENFORCED | Pruning (`crates/index/src/write.rs:216-247`); tests `pruning` in `vector_heads` (a holder of the 5th of 40 keeps two heads, nothing dropped), `pruning_keeps_the_mandatory_then_the_greatest` (properties.rs:1100), properties (a) and (c) at caps 2 and 3, a deleted file reappearing after its tombstone expires (heads.rs:900-922), the `check_drops` audit | — |

Retired and not walked: TM-16, TM-19, TM-34, TM-36, TM-38 (no code or test in `crates/` cites them).

Counts over the 38 live requirements: 16 ENFORCED, 10 PARTLY ENFORCED (each gap outside phase 0's
scope except TM-14's, finding S1), 12 NOT YET APPLICABLE.

## The gate's own evidence

- `crates/engine/tests/converge.rs:92-110` runs 17 scenarios (`clean`, `drops`, `reconnect`,
  `cross_reorder`, `partition`, `crash`, `skew`, `clock_ahead`, `disk_full`, `sealed_relay`,
  `late_joiner`, `pacing`, `clones`, `chaos`, `tree_delete`, `sealed_cleanup`, `expiry`), each over
  seeds 0 to 4, each with `Run::check` (`crates/sim/src/scenarios/engine.rs:123`): converged,
  quiescent, not exhausted, the full oracle, the scenario's own check, then 60 s more with the state
  digest and the issue count unchanged. `the_gate_runs_every_engine_scenario_but_the_stress_run`
  (:116) keeps the list complete. Nothing is `#[ignore]`d or feature-gated; CI runs it on three
  systems. All passed here.
- The oracle (`crates/sim/src/oracle.rs:172-464`) checks per folder: the same record-hash set on
  every member, every record applied (sealed at a sealed member), the same paths and heads in
  display order on read and write holders, disks matching heads on every non-sealed member, every
  file head reassembled to the ledger's bytes, no unnamed blob, a sealed member's blobs hashing to
  their names; and over the run no issue that blames or is unexpected, no blaming close, no
  internal error, no high-water mark that fell, no counter reused, no overflowed connection, and
  Checking at every start. Exemptions are only the three `Expect` flags, each used by the
  scenario that provokes it.
- Gap: the oracle never reads `ledger.refused` (finding S2). The probe found it 0 in every
  scenario for seeds 0 and 1 but `sealed_relay` (21, which that scenario's own check requires), so
  today's runs did all their writes.

## Findings

No BLOCKER: nothing found lets a peer get past a check on the code at 55ddfb4.

### SHOULD FIX

**S1. No test separates "folder held here" from "folder open on this connection" (TM-14, TM-32,
TM-10's "a message for a folder not open here").**
- Where: `Connection::is_open` (`crates/protocol/src/connection/mod.rs:904-906`) guards incoming
  ReconcileRequest (`connection/index.rs:1258`) and ChunkRequest (`connection/chunks.rs:334`), and
  the outgoing pages and replies (`connection/index.rs:629`, :979, :1029; `chunks.rs:269`).
  IndexRequest, pages and pushes check `open` directly or through `open_mut`
  (`connection/index.rs:1219-1226`, `mod.rs:1404`). The
  connection's folder map gets an entry for every folder this device proves on the connection
  (`connection/handshake.rs:174`), so an outsider who learned a folder ID (LAN beacon, DHT, relay)
  is talking to a connection that has an entry for it, with `open` unset.
- What: every "not open" test uses a folder ID the device does not hold (`FolderId([9; 32])`,
  `[0x77; 32]`: `connection/tests/chunks.rs:216-222`, :257-272; `connection/tests/exchange.rs:1248-1310`,
  :2100-2127); `crates/engine/tests/outsider.rs` has honest outsiders that never send a
  folder-scoped request.
- How verified: in the scratch copy I made two separate changes, and after each all 314 protocol and
  engine tests outside `converge` still passed:
  - Changing `is_open` to `self.folders.contains_key(folder)`. With this change, a peer for which
    the folder is not open could fetch its chunks by cipher hash: the engine serves by folder and
    hash and does not check the connection itself (`crates/engine/src/engine.rs:310-315`,
    `transfer.rs:251-272`). Index and reconcile requests would still be refused by the second
    check, `open_mut` in `begin_serving` (`connection/index.rs:1187`) and `on_index_request`
    (:1219-1226).
  - Changing only the inbound ChunkRequest check.

  The code at 55ddfb4 is correct, but no test would notice if this check stopped working.
- Smallest fix: one protocol test where both sides hold folder A, B also holds C, and A's proof of
  C is rejected or never answered (C held, not open). Then each of IndexRequest, ReconcileRequest,
  IndexRecords, ChunkRequest and Status for C closes with `PROTOCOL_ERROR`/`Malformed`, and each
  of `reply_chunk`, `send_reconcile_reply` and `page_folder` for C returns `FolderNotOpen`.
  Optionally, one engine adversary test where an outsider sends a ReconcileRequest and a
  ChunkRequest for the main folder and receives nothing of it.

**S2. The convergence oracle accepts a run in which writes were refused (the gate's evidence).**
- Where: `crates/sim/src/member.rs:305-311` counts every `WriteFailure` other than Paused and Store
  (UnknownFolder, NotWriteKey, NotUsable, Path, NoSuchPath, TooLarge) in `ledger.refused`, and the
  workload moves on. Neither `oracle::check` nor `check_ledger` (`crates/sim/src/oracle.rs:172-246`)
  reads `refused`; only `sealed_relay` checks it (`scenarios/engine.rs:631-634`). The ledger's own
  comment (member.rs:106) says it counts refusals for a read or sealed key, which is narrower than
  what it counts.
- What: an engine change that refused writes (say NotUsable after a restart, or NoSuchPath on a
  rename racing a delivery) would pass `clean`, `drops`, `reconnect`, `cross_reorder` and `chaos`,
  whose only check is the oracle: fewer writes still converge.
- How verified: read the code; the probe above shows today's runs refuse nothing, so today's
  result stands and the fix cannot break the gate.
- Smallest fix: add `refused` to `Expect` (default 0, `sealed_relay` 21) and check it in
  `check_ledger`; correct the comment at member.rs:106.

**S3. The Semgrep rule `no-follow-symlinks` misses the method forms (TM-4).** Outside phase 0's
scope; fix before or with phase 1's resolver. Not counted in this gate's verdict.
- Where: `.semgrep/project.yml`, rule `no-follow-symlinks`, patterns `std::fs::canonicalize($P)`
  and `std::fs::read_link($P)`.
- What: TM-4 says the rule forbids `canonicalize` and `read_link` throughout the workspace. On a
  scratch file it flags `std::fs::canonicalize(p)`, `fs::canonicalize(p)` after `use std::fs`, and
  the same two forms of `read_link`, but not `p.canonicalize()` or `p.read_link()` (the
  `Path`/`PathBuf` methods, the usual Rust spelling). Phase 0 has no disk code, so nothing escapes
  today.
- Smallest fix: add `$P.canonicalize()` and `$P.read_link()` (and `std::path::Path::canonicalize`)
  to the rule, with `ruleid` cases in `.semgrep/tests/project.rs`.

### NIT

- **N1 (TM-2).** `SealedMeta.path` and the device-ID fields are read with limit `usize::MAX`
  (`crates/protocol/src/parse.rs:535`, :560, :574, :602), so a path is copied before
  `MAX_PATH_BYTES` is checked at step 7 (`record.rs:578`). The copy is bounded by the opened seal,
  at most `MAX_SEALED_BYTES`, so memory stays bounded. It is a deliberate choice (an over-long
  path is a writer fault, not malformed), but TM-2's letter says before. Either pass the field's
  own limit plus one, or note the enclosing-buffer bound in TM-2.
- **N2 (TM-3).** The engine's store decoders (`crates/engine/src/store.rs:134`, :158, :225-233,
  :196, :274) have no fuzz target; they are fixed-length `get()`-based readers of the device's own
  store, and record envelopes go through the fuzzed `SignedRecord::from_bytes`. Add them when
  SQLite lands (phase 1) or say why not. `ci/fuzz-targets.sh` lists targets and checks nothing
  about coverage, so "a decoder without a target does not merge" rests on review.
- **N3 (TM-3).** The last green nightly ran at 5593b8d. `index_ops` and `reconcile` are new in this
  gate and have never run in CI, and the decoders the latest-only index rewrote have had no CI
  fuzzing. They built and ran 120 s each here with no crash. Confirm the first nightly at 55ddfb4
  is green.
- **N4 (TM-5).** Test-only generators besides SplitMix64 (`crates/protocol/src/testkit.rs:105-116`,
  `crates/engine/src/testkit.rs:280-289`, `crates/index/src/tests/kit.rs:81`,
  `crates/engine/src/runtime.rs:690`) feed nonces in unit tests. They reach no production build,
  but TM-5 says "the one generator written here". Reword TM-5 to "outside test code".
- **N5 (TM-7).** `fuzz/Cargo.toml` is its own workspace with no `[lints]`, so `unsafe_code =
  "forbid"` does not reach the fuzz targets (none uses `unsafe`). Add `#![forbid(unsafe_code)]` or
  a lint table.
- **N6 (TM-10, spec and code disagree).** `protocol.md` section 5 and TM-10 say an issue names the
  record "by hash, and by path where the seal opened". The engine carries no path in any issue,
  citing TM-6 (`crates/engine/src/issues/mod.rs:22`), but TM-6 does not make paths secret. Settle
  which one is meant: the UI resolving the path from the hash in phase 3 would satisfy both.
- **N7 (TM-22).** These hold by structure, with no test: a queued chunk request holds only its
  hash (`crates/engine/src/conn.rs:36`), one `CHUNK_BUSY` timer per connection, and the tables
  emptied by `finish_tables`. Fine for now; worth a line each in phase 1.
- **N8 (TM-40).** No exactly-30-days-kept boundary case for the cleanup horizon (tombstones have
  both sides); the record-from-the-future refusal is tested at write holders only (the code path is
  the same for read holders).
- **N9 (TM-41).** Three property tests are weaker than `protocol.md` 8 item 7 reads:
  - (c) checks each written vector is the full join less entries (`check_c`, properties.rs:431),
    not the dropped-subset comparison on the same history.
  - (g) does not test the clause after a cleanup is forgotten (properties.rs:754-783).
  - (k) almost never generates its case, since `World` puts heads on disk before every write
    (properties.rs:283-319). Its property is covered by `the_lost_update_r1_b2_s1`,
    `base_failing_at_open` and `crates/engine/src/rules.rs:172`.
- **N10 (engineering practice, not a TM).** `#[ignore = "100 000 signed records: release builds
  only"]` at `crates/index/src/tests/cleanups.rs:244` cites ruling Q7 but no issue link, which the
  plan's Tests rule asks for.
- **N11 (process).** The plan's Roadmap paragraph (rev 398) already reads "Phase 0 is done: its gate
  ... passed on 2026-11-02, at core main 55ddfb4", written before this record. Change it to match
  this record's verdict.

## For the owner

Phase 0's code is the keys, protocol, index and engine crates running on a simulator. I checked it
against all 38 rules in the threat model that are still in force. Sixteen are fully in force with
tests. Ten are in force for the parts that exist; the rest of each waits for networking, the real
disk, the local service or the apps. Twelve belong entirely to later phases. I found
nothing a peer can use against the code as it stands: all 654 tests pass, CI is green, and the fuzz
targets ran clean here. Two things should be fixed before phase 0 is called done. First, no test
would notice if the check that a folder is actually open on a connection, rather than merely held
by this device, were weakened. I weakened it on purpose and every test still passed, and with it
weakened, a peer that never proved a key could fetch a folder's encrypted chunks if it knew their
hashes.
Second, the convergence check that is the gate itself would not notice if writes were silently
refused; today none are, but nothing guards that. To try it by hand, run `core/gate.sh` and
`cargo nextest run -p licketysync-engine --test converge` and watch the 17 scenarios pass, then make
the one-line change in finding S1 in a scratch copy and see that nothing fails.

Verdict: gate blocked by 2

## Addendum: re-review of the fix, 8494dc3 (branch `wip/gate0-tests`, parent 55ddfb4)

The fix changes only tests, the simulator's oracle, comments, one Semgrep rule and the changelog.
No non-test code in keys, protocol, index or engine changes. Checked in scratch copies of 8494dc3
and 55ddfb4, both since deleted.

- Full `cargo nextest run --workspace` at 8494dc3: **656 passed, 1 skipped** (the 654 before plus
  the two new tests). The 17 gate scenarios pass on seeds 0 to 4.
- **S1: fixed.** The new test is `a_folder_held_and_proven_but_not_open_is_refused_both_ways`
  (`crates/protocol/src/connection/tests/handshake.rs`).
  - It covers three ways a folder can be held and proven but not open: rejected, answer lost,
    peer's proof lost. Its setup reads `open_folders()`, not `is_open`.
  - It sends 10 folder-scoped inbound messages; each must close `PROTOCOL_ERROR`/`Malformed` with
    no event but the close. It makes 9 sends, each refused with `FolderNotOpen`.
  - Undo-checked here:
    - With `is_open` answering "held", this test fails and the other 314 protocol and engine tests
      pass.
    - With only the inbound ChunkRequest check answering "held" (the mutant that survived at
      55ddfb4), it fails.
  - The two mutants the author could not catch are equivalent, and I agree:
    - A folder never stops being open on a live connection (nothing resets `open` but
      `finish_tables`), so `chunks.ours` holds only requests for open folders, and
      `on_chunk_reply`'s `is_open` follows the unsolicited check.
    - `on_reconcile_request`'s check is made again by `begin_serving`'s `open_mut`, with the same
      close.
- **S2: fixed.** `Expect.refused` defaults to 0, `sealed_relay` sets 21, and `check_ledger` fails
  on any other count. The new test is `a_run_with_a_write_refused_unexpectedly_fails_the_oracle`
  (`crates/sim/src/scenarios/engine.rs`). Undo-checked here: with the check disabled the test
  fails. The other scenarios expect 0, which matches the probe in this record.
- **S3: fixed.** The rule now also flags `std::path::Path::canonicalize`/`read_link`,
  `$P.canonicalize()` and `$P.read_link()`.
  - `semgrep --test`: all rule tests pass.
  - The project-rule scan over the workspace finds nothing.
  - My scratch probe flags `p.canonicalize()`, `buf.canonicalize()`, `Path::canonicalize(p)` and
    `p.read_link()`, and leaves `symlink_metadata` alone.
  - New cost: `$P.canonicalize()` matches a method of that name on any type. That is acceptable
    for a tripwire; a false hit takes a `nosemgrep` with a reason.
- **Nothing new in code.** One new NIT, N12: the changelog entry of 8494dc3 calls protocol
  96.92% and index 96.95% "line coverage". Those figures are llvm-cov's **region** column. On this
  machine, with `gate.sh`'s command, the coverage is:

  | Crate | Commit | Lines | Regions |
  | --- | --- | --- | --- |
  | protocol | 55ddfb4 | 98.30% | 96.89% |
  | protocol | 8494dc3 | 98.32% | 96.92% |
  | index | 55ddfb4 | 97.66% | 96.95% |
  | index | 8494dc3 | 97.66% | 96.95% |

  - The apparent drop is an artefact of comparing the two columns. Coverage did not fall: index is
    byte-identical between the commits, and protocol rose by one line.
  - Fix the changelog's figures before the commit lands, and check its keys and engine figures the
    same way. The changelog's "Reviewed: pending" also needs the reviewers' names.
- **Still open, not blocking:** NITs N1 to N11 above. N3 (confirm the first nightly fuzz run at
  the gate commit is green) and N11 (the plan already says phase 0 passed) stand.

Verdict on 8494dc3: gate passes, once 8494dc3 lands on main with its reviewers named.

Verdict: gate passes
