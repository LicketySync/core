# Changelog

All notable changes to Lickety-Sync are recorded here. Each entry says what
changed and names the agents that reviewed it; anything touching keys, protocol,
paths or the API also names the security-reviewer pass.

## Unreleased

- Index: remove by simpler code the two equivalent mutants that the second batch's tests left
  (`serve.rs` 123:56 and `index.rs` 964:44, equivalent by both reviews of that batch; the
  coordinator's ruling 5), rather than skip them.
  - `Index::since_plan` (`protocol.md` §4.5, "Serving an `IndexRequest`"): a reset's `redraw` is
    now `epoch == self.epoch()` alone. The reset is served only when the epoch is another's or
    `since` is above the local sequence, so with this side's epoch `since > local` already held,
    and its `>` with `>=` changed nothing. No behaviour changed.
  - `Txn::cursor_advanced` (§4.5, "Per-peer state" and "Cursors": a round's end sets the cursor
    and its epoch, and pushes move it on from there): a counted push now acts only on per-peer
    state already held for its epoch, raising the cursor to its `through` with `max` (a state left
    as it was is neither logged nor stored, as before). A push for a peer without state creates
    none. Before, one of epoch 0 made `{epoch 0, cursor through}`, a cursor no round's end set,
    and at `MAX_PEER_STATES` it could evict a real peer's state (TM-22); for any other epoch it
    did nothing, as now. No caller relied on it: the wire refuses epoch 0 (`IndexRequest`,
    `ReconcileReply`, `IndexRecords`), the connection counts pushes only from a round's end, and
    the engine applies that round's `RoundCompleted` before the `CursorAdvanced` it leads to, in
    one queue per folder; the fuzz target `index_ops` pushes only with epoch 1, which made no
    state before either, and the other tests push after a round's end.
    `a_counted_push_for_a_peer_without_state_creates_none_whatever_its_epoch` fails
    without the change (epoch 0, `through` 1, and at the cap);
    `a_counted_push_raises_the_cursor_of_its_epoch_and_never_lowers_it` holds the new form to
    what the old guard did.
  - Mutants (cargo-mutants 27.1.0 under `ci/mutants.sh`'s caps, `--timeout-multiplier 2
    --minimum-test-timeout 300`), `-f` on `serve.rs` and `index.rs` with `-F` on `since_plan` and
    `cursor_advanced`, 16 mutants (the two files' field deletions included, whatever the `-F`),
    on 32321a2 with this change: 11 caught, 5 unviable, none missed or timed out; with
    `--cap-lints true`, 15 caught, 1 unviable (`since_plan` replaced with `Default::default()`:
    `SincePlan` has none), none missed or timed out. On eedfd6d, without batch 2's tests, each run
    also missed `index.rs` 560:34 (a field deletion in `Txn::renumber`), which those tests kill.
    `since_plan`'s new `==` with `!=` (124:31) is caught by `vector_digests` and
    `a_request_for_another_epoch_is_reset_without_a_new_epoch_whatever_its_since`;
    `cursor_advanced`'s `==` with `!=`, its body replaced with `()` and its `cursor` field
    deleted are caught by `vector_digests` and the second test above, the last two unviable
    without `--cap-lints true` (they leave a binding unused, which the workspace lints deny).

- CI: cap the lints in every cargo-mutants run, so that the mutants the workspace's denied lints
  hid are tested, under the owner's mutation-testing mandate of 2026-11-08 ("It's a mandate that
  we must be safe and secure."). `Cargo.toml` denies the `dead_code` and `unused` lints, and
  `ci/mutants.sh` did not tell cargo-mutants 27.1.0 to cap them, so a mutant that leaves a
  parameter, binding, import or item unused, as many replacements of a whole function body do
  (`replace State::replaces_any -> bool with false`) and some deletions of a struct field and
  replacements of a match guard, failed to build and was counted unviable, its tests never run.
  The run of 2026-11-12 (43341050834, on 59783b1) counted 1,400 of its 3,296 mutants so (1,320
  of them whole-body replacements, 16 match-guard replacements), against 1,705 caught and 154
  missed, so an unknown share of the mandate's backlog was hidden. Both reviews of index
  mutants batch 2 found it; one ran 31 such index mutants with `--cap-lints true`: 30 caught, 1
  missed (`state.rs:975:41`, match guard `*s == now.seq` replaced with false in `State::changes`).
  - `.cargo/mutants.toml` (new) sets `cap_lints = true`, the key cargo-mutants 27.1.0 reads from
    the workspace root's `.cargo/mutants.toml` (its `src/config.rs`; with it, `src/cargo.rs` adds
    `--cap-lints=warn` to the rustc flags of every build and test it runs, the unmutated tree's
    included). So the weekly job and any run by hand, an author's or a reviewer's, cap them, with
    no flag to remember; `--cap-lints false` or `--no-config` turns it off. Only the cargo
    processes cargo-mutants starts are capped; cargo never reads the file, so `gate.sh` and CI
    still deny the lints. The file says why, and `ci/mutants.sh`'s header and `CONTRIBUTING.md`
    point to it.
  - `ci/test-mutants.sh`: the stand-in cargo now records whether cargo-mutants 27.1.0 would cap
    the lints, by its rules. It reads its config file first, whatever the command line says of
    the cap: the file `--config` names, none with `--no-config`, or else the workspace root's
    `.cargo/mutants.toml`, which may be absent. A missing `--config` file stops it, and so does a
    file that is not TOML, holds a key it does not know (its `Config` is `deny_unknown_fields`;
    the stand-in lists 27.1.0's keys) or a `cap_lints` that is not a boolean. Then `--cap-lints`
    on the command line wins over the file (the real cargo-mutants 27.1.0, run with `--list
    --config`, exits 1 on an unknown key, a `cap_lints` that is a string and a missing file, and
    takes `test_tool` and `sharding`). 17 rows check the stand-in against those rules,
    `--config` replacing the tree's file both ways among them; breaking the stand-in four ways
    (unknown keys accepted, a missing `--config` file ignored, `--config` not replacing the
    tree's file, the command line not winning) fails them. Each case's root gets a copy of the
    repository's `.cargo/mutants.toml`, and a new check fails unless the listing and the run both
    cap the lints. Without the file, or with `cap_lints = false` in it, the check fails (run by
    hand on copies of `ci/`); `--cap-lints true` from `ci/mutants.sh` would satisfy it too. The
    script needs python3 3.11 or later (tomllib) and now checks for it first, saying so.
  - Measured on the keys crate, the smallest (unchanged since 59783b1), with cargo-mutants 27.1.0
    under `ci/mutants.sh`'s caps and limits on the development machine (8 cores), 564 mutants:
    without the cap 255 caught, 3 missed, 0 timed out, 306 unviable, as on 2026-11-12, in 18
    minutes; with it 414 caught, 3 missed (the same three), 0 timed out, 147 unviable, in 31
    minutes. All 159 that the cap made viable (158 whole-body replacements of 296, 1 match-arm
    deletion of 10 other mutants) were caught, 4.2 s each. Their logs without the cap show the
    159 failed on lints alone (unused variables and imports, items never used or read); the 147
    still unviable fail on compile errors no cap turns off (a missing trait or method, mostly; 9
    a constant evaluated at compile time).
  - The estimate for the weekly run (`mutants.yml`'s comment has the arithmetic): at keys' rates,
    with every unviable guard replacement or field deletion building (as did all 6 of an index
    sample that were unviable without the cap: 4 guards, 2 field deletions), some 730 of the
    1,400 are tested (engine 199, index 188, protocol 184, keys 159); at what a tested mutant of
    each crate cost on 2026-11-12 (engine 57 s, index and protocol 22 s, keys 5 s, hangs
    included), about 5.4 hours more over the run, 20 minutes a shard: shards of 57 to 104 minutes
    against the 38 to 87 of 2026-11-12, about two and a half hours in all; about 120 for the
    slowest were all 1,400 tested. Each shard keeps an hour of its 180-minute budget (a mutant
    that hangs costs its build and its test limit, twice its shard's baseline test time and at
    least 300 s: under 10 minutes on 2026-11-12; the job's `timeout-minutes` is 210, GitHub's
    limit 6 hours), so the 16 shards, the budget and the job's limit stay.
  - The backlog (139 missed and 30 timed out on 2026-11-07; 154 and 37 on 2026-11-12) will be
    re-counted by the next baseline run, which should report more missed: of the mutants the
    cap makes viable, those the tests do not catch (none of keys' 159; 1 of the index sample's
    31).
  - Reviewed 2026-11-13 by a1dcd7b1828867f62 (clean; nits taken; confirm: clean, checked against
    the real cargo-mutants 27.1.0 on all 17 rows) and ae3cd57c8275dd10c (blocked by two, a sample
    size and an override claim, now fixed; confirm: clean). Author a7ed89912312928bc. Landed as one
    squashed commit.

- Index: tests that catch 28 of the 30 mutants of the index crate's second batch that the Mutants
  run of 2026-11-12 on 9349d4f found surviving (all 30 still survived on eedfd6d), under the
  owner's mutation-testing mandate of 2026-11-08 ("It's a mandate that we must be safe and
  secure."). Tests only; no production behaviour changed. Each test checks what the spec states,
  and each kill was shown by cargo-mutants on its functions under `ci/mutants.sh`'s caps.
  - Step 3 (`protocol.md` §4.4; TM-22): a record that something held names, covers or forgets is
    obsolete only when it replaces nothing held, and is then ignored unverified. A cleanup that a
    held cleanup forgets, whose own groups forget nothing held, and a version covered at its tag,
    whatever its vector covers beneath its path (only a tree delete is judged by what lies beneath
    it), are judged obsolete with a garbage signature. A cleanup that a held cleanup forgets but
    whose own group forgets a record held, and a version that a held record names but that covers
    a version held at its tag, are verified, drop what they replace (step 6) and are not held.
  - Phase 0's expiry by the folder's own time on arrival, until the signed watermark (spec
    59783b1) replaces it in phase 1: a tombstone or a cleanup exactly its horizon behind `G` is
    held, one a microsecond older is expired.
  - The local sequence (§4.5): a record takes `MAX_LOCAL_SEQ` itself, nothing numbered afresh and
    the epoch kept; the next numbers every record held afresh from 1 in its order under a new
    epoch, records that were not numbered 1, 2, … before, and the store keeps the new numbers.
  - Serving (§4.5): a Since reply is done at its last page and not before; a request for another
    epoch is reset without drawing a new epoch, whatever its `since`.
  - Per-peer state (§4.5): a state exactly `PEER_STATE_HORIZON` old stays at a round's end and goes
    a microsecond later, as at the open; a peer's `MAX_PEER_NAMES` window ends exactly 30 days
    (`PEER_NAMES_WINDOW`) after it began, alike when a copy is judged and when the round's end
    counts names.
  - The store (§4.7 item 1): a change set of any one persisted part alone is not empty; a record
    kept only as a base leaves the store with its last base slot, so a reopen has nothing to
    repair; the memory store counts what it holds; an index is empty until it holds a record; a
    sealed holder keeps no high-water mark whatever its store holds (§4.4, "Opening a folder":
    "Sealed peers keep no mark").
  - Spec questions raised, for the coordinator's queue (no test pins an answer):
    - What a sealed holder's open does with a stored high-water mark, since §4.4's check of the
      stored mark ("Opening a folder") names no tier: one within the bounds a key holder's open
      accepts, one above what the records held and the clock floor justify, and one above
      `MAX_COUNTER`; and whether it reports any of them as corrupt. The code keeps none of them
      and reports none; the test pins only that no mark is kept (review A's F-1).
    - `Judgement::Obsolete`'s doc in the protocol crate ("Something held replaces it and it
      replaces nothing held: ignored") does not fit the label the index gives a record that is
      verified, drops what it replaces (step 6) and is then not held because something held names
      or forgets it (its rows are `ReplacesHeld`, then `Obsolete`). Queued for the protocol crate;
      the tests assert that such a record is not held and that its rows carry `ReplacesHeld`, not
      its label (review A's F-2).
    - `PEER_NAMES_WINDOW` (§4.5, "Stale copies"; §4.4, "at most `MAX_PEER_NAMES` … in any
      `PEER_NAMES_WINDOW`"): which end of a window is included (the code, and the test that pins
      it, take 30 days from its start, the start included and the end not); and whether "in any"
      means every window of that length, which the code's fixed windows, one after another, do
      not keep: up to twice `MAX_PEER_NAMES` across one boundary (predates this change; review
      B's N-2).
  - Equivalent, not skipped (for the reviewers and the coordinator): `serve.rs` 123:56, `replace >
    with >= in Index::since_plan` (where the reset's `redraw` is computed, the request's epoch
    being this side's already means its `since` is above the local sequence); and `index.rs`
    964:44 (958:44 in the run), `replace > with >= in Txn::cursor_advanced` (raising a cursor to
    the value it has writes the same state, which `State::set_peer` does not even log; without
    state for the peer the mutant differs only for epoch 0, which the protocol refuses on the
    wire and never counts).
  - Mutants (cargo-mutants 27.1.0 under `ci/mutants.sh`'s caps, `--timeout-multiplier 2
    --minimum-test-timeout 300`), every mutant of the covered functions, one file at a time:
    `index.rs` with `-F` on `Index::is_empty`, `Index::key_holder` and `Txn`'s `next_seq`,
    `renumber`, `expired`, `peer_names`, `cursor_advanced` and `forget_peers`, 44 tested (the
    file's field deletions included), 32 caught, 11 unviable, 1 missed (964:44, above); `serve.rs`
    with `Index::since_plan` and `SinceReply::is_done`, 11 tested, 9 caught, 1 unviable, 1 missed
    (123:56, above); `state.rs` with `State::replaces_any` and `State::changes`, 24 tested, 19
    caught, 5 unviable; `store.rs` with `ChangeSet::is_empty`, `MemoryStore::len` and
    `MemoryStore::is_empty`, 12 tested, 12 caught; none timed out. `index.rs`'s lines are the
    run's plus 6, moved by the F-1 and F-2 fix. The two equivalent mutants go in the change that
    follows, which writes both comparisons more simply (the coordinator's ruling 5).
  - Reviewed 2026-11-13 by a7222cd089df59e4c (blocked by two, a sealed holder's report and a
    judgement's label pinned where the spec says neither, now fixed; confirm: clean) and
    a23e89878894b04ba (clean; two nits taken; confirm: clean). Author ae0d453c2ab4bc489. Landed
    as one squashed commit.

- Index: fix the two bugs the mutants of the first batch found (F-1, F-2; both Low, confirmed by
  both reviews of that batch, the coordinator's ruling 7), each with a regression test named after
  it that fails without its fix.
  - F-1, an empty batch raised the high-water mark (`protocol.md` §4.4, "The writer's rule": the
    mark is the greatest counter of a record held or written). With the clock ahead of the mark,
    `Txn::write` of no change raised the mark to the clock less one, a counter no record holds, and
    staged it; at the counter ceiling it was refused with `CounterExhausted`. That could raise a
    false "corrupt high-water mark" at the next open after the clock was set back by more than a
    day, and carried a briefly fast clock into the counters written after it (TM-40). An empty
    batch now returns at once after the write-key check, signs nothing, stages nothing and is no
    error, at the ceiling too; a read or sealed holder's is still refused. The explicit raises of
    the mark after a write's records and a round's end's cleanups are gone, since holding each
    record already raises the mark to its counter (they were the equivalent mutants `write.rs`
    851 and 998), and so is the `total > 0` guard of the batch's ceiling check, which the early
    return made dead (the check now subtracts with saturation, as the round's end's does); the
    round's end's cleanups take their counters from a range zipped with them, the raise having
    been the only reader of its counter after the loop. The engine never writes an empty batch,
    and no caller relied on the raise.
  - F-2, an open that found entries the store could not decode drew no new index epoch, though
    §4.4 ("Opening a folder": such bytes are dropped as a record that fails its checks is), §4.5,
    §4.7 item 8 ("An open that dropped anything draws a new index epoch, once") and TM-9 say it
    must, so that every peer reconciles and sends again what the store lost. It applies today: the
    engine's store already counts such entries. The open now draws one, once, and reports it in
    `epoch_redrawn` (a store with no epoch, its metadata among the entries it could not decode
    included, gets its first epoch instead, and the flag stays false). For phase 1: the store
    leaves the entries it cannot decode in storage, of every kind (per-peer state and the markers
    of chunks to free too), so one that stays damaged redraws the epoch at every open, once each
    open, a cost TM-22 already bounds; phase 1's store, its damaged-store problem code and
    `licketysync doctor` should repair or remove them, and count the entries that carry records
    apart from the others.
  - Every record this device signs is held: a write's records and cleanups, and a round's end's
    cleanups, each come back held with its local sequence number, which the `.ok()` on holding
    them relies on and the removed raises had hidden. `sign_and_hold` and `end_round` now state
    it and why (the signed record passed a reader's steps 1 and 7 before signing returned it;
    step 7 keeps an applied held record's vector entries below its counter, at most the mark, so
    nothing held covers a fresh counter, and a cleanup has no path tag or path to be covered at;
    nothing can name a hash that did not exist). The test kit checks it after every write and
    round's end, with the mark at the last counter written, and
    `every_record_this_device_signs_is_held` runs it over random histories that each start with a
    round's end that has a note to clean up.
  - Mutants (cargo-mutants 27.1.0 under `ci/mutants.sh`'s caps, `--timeout-multiplier 2
    --minimum-test-timeout 300`): `write.rs` with
    `-F 'sign_and_hold|sign_plans|end_round|Txn<.*>::write'`, 28 tested, 19 caught, 9 unviable,
    none missed or timed out (851 and 998 gone with the code, and the guard's 741 with it);
    `open.rs`, 60 tested, 53 caught, 7 unviable, none missed or timed out, `replace > with <` in
    the new condition caught by the F-2 test alone.
  - Reviewed 2026-11-13 by a1292c2a800f8e08e (clean) and ab5b4ed68dcfa1e19 (clean), and for
    security by ac6435a24f7f0a627 (clean; its recommended test and the reviewers' doc points
    taken, then blocked by two doc points, now fixed; confirm: clean). Author a227cffbad659a18e.
    Landed as one squashed commit.

- Index: tests that catch 31 of the 33 mutants of the index crate's first batch that the Mutants
  run of 2026-11-12 (43341050834, on 59783b1) found surviving, under the owner's mutation-testing
  mandate of 2026-11-08 ("It's a mandate that we must be safe and secure."). Tests, and one count
  kept for them; no production behaviour changed. Each test checks what the spec states, and each
  kill was shown by cargo-mutants on its function under `ci/mutants.sh`'s caps.
  - The trees by path (`protocol.md` §4.4, "Judging a tree delete without a walk") are AVL trees:
    after every record held or dropped, no higher than an AVL tree of as many records can be (the
    Fibonacci trees' bound; the old check let one record stand three high), in five orders of
    holding and dropping, in random ones, and in the four rebalancing cases that random orders
    rarely reach (a node one higher on either side stays as it is; a drop over a balanced child
    takes one rotation), each found by a search over random orders against the mutated code. The
    count of nodes a query reads counts every node: a query that finds nothing reads at least the
    five nodes any correct search of its two runs reads, so that the cost bounds the tests put on
    the count cannot hold for a query that counts nothing. The trie of held tree deletes (§4.4
    step 3) finds those at and above a path as their definition does after any holds and drops:
    dropping one at a directory loses none beneath it.
  - Opening (§4.4, "Opening a folder"; §4.5; §4.7 item 8; TM-9): the open verifies the stored
    signatures across the threads it is given, and opens as on one thread (a count of the worker
    threads it spawns, kept per calling thread and only in test builds, shows it); the count of
    entries a store could not decode is reported; a record stored under `MAX_LOCAL_SEQ` itself is
    kept, not renumbered; per-peer state exactly `PEER_STATE_HORIZON` old stays and goes a
    microsecond later; a base whose record the store lost is cleared under a new epoch.
  - Writing and the round's end (§4.4, the writer's rule, "Its names", "Cleanup", the counter
    ceiling): an empty batch signs no record and drops none; the records of one write take
    consecutive counters, its cleanups last, and the high-water mark ends at the last; a round's
    end gives each cleanup its own counter, may take every counter up to `MAX_COUNTER` and refuses
    whole past it, its notes kept and its mark where it was; a write names only the noted copies
    its vector covers; a round's end pages its names by the record across groups.
  - Equivalent, not skipped: `write.rs` 851 and 998, the deletion of the high-water mark's raise
    after a write's and a round's end's records (holding each record already raises the mark to
    its counter), except, for 851, an empty batch. The change that follows removes both raises.
  - Two bugs found, both confirmed by the reviews and fixed in the change that follows: an empty
    batch raises the high-water mark to the clock less one when the clock is ahead of it, stages
    that, and is refused at the counter ceiling (F-1); an open that counts entries the store could
    not decode draws no new epoch, though §4.4 and §4.7 item 8 say an open that dropped anything
    draws one (F-2).
  - Reviewed 2026-11-12 and 2026-11-13 by aa7f4f11073e67597 (blocked by two, checks made after the
    transaction was undone and an empty batch's comment, now fixed; confirm: clean) and
    a72b69d321b34b4e7 (blocked by two, `verify.rs` 70:19 killable and a node-count test a correct
    refactor would break, now fixed; confirm: clean; a wording nit taken). Author
    aa9752a99cf60b7ae. Landed as one squashed commit.

- Spec: count the six connectivity switches in TM-25, and say what a folder keeps once deletions
  stop. Spec text only. TM-25 listed "the first five" of the plan's per-folder switches; it now says
  the plan lists all six (the hole-punch level too) and that a new folder starts from the
  device-wide settings (the owner's decisions of 2026-11-10 and 2026-11-11). `protocol.md` §4.4
  ("Cleanup") and §9 said a folder in which nobody writes forgets its deletions too, which the
  coordinator's ruling of 2026-11-12 contradicts: a write holder signs only when its candidate
  passes a deletion or a cleanup with a `because`, so once deletions stop no one signs, and the
  watermark-only and case-(c) cleanups of the last year stay held at every tier until the next
  deletion's watermark. Both now say so, and that it costs storage, never a file; TM-40 lists it
  with the other ways forgetting comes late; the §8 vector of a folder in which nobody writes
  says its watermark was signed earlier, and TM-22 and the other §8 vectors already agreed.
  - Reviewed 2026-11-12 by a3748f41ed973e0ea (blocked by one, a line width, now fixed; a nit taken)
    and a0e386c3000d820df (blocked by one, the entry's place, now fixed; confirm: clean). Author
    a0e9f6d9ef6b17df4. Landed as one squashed commit.

- Spec: forget deletions by a signed watermark, and drop the clock rule and expiry by the folder's
  own time (the owner's decisions of 2026-11-08, after the research on removing the protocol's
  dependence on clocks: "Switch", "After 365 days" and "Loose 10,000-year limit"; their answers
  of 2026-11-12: "A year after arrival, together", cleanups by "the same logic as the deletion of a
  file", and "a fixed ceiling"; and their decisions of 2026-11-12 on the questions and reviews of
  this change: on the ceiling's risk, "Accept, documented"; on late deletions, "OK, file comes
  back"; on a clock that jumps, "Accept, documented"; on the candidate, "Wait, never early"; on a
  faked date, "Still accept, documented"; and on a slow release, "Accept, documented"). Spec text
  only, the first spec change of phase 1: the index, the engine and the simulator implement it in
  their own changes. Until then the code does what phase 0 built: the clock rule (Hello's
  `clock_days`, `Close(CLOCK_OUT_OF_RANGE)` when the first folder opens, records from the future
  refused with `MAX_FUTURE_KNOWN`, a folder kept closed after its clock was set back), expiry by
  the folder's own time with `TOMBSTONE_HORIZON` and the 30-day `CLEANUP_HORIZON`, the fast-clock
  issue at `CLOCK_AHEAD_WARNING`, `MAX_COUNTER` at 2^62 and `CLOCK_FLOOR_MAX` at 2^61; the
  README's crate rows say so until those changes. TM-9, TM-17, TM-22, TM-40, TM-41 and TM-43, and
  `threat-model.md` §3.1, §3.2, §3.3, §3.6, §3.10, §3.12 and §5.
  - The watermark (`protocol.md` §4.4, "Expiry by the watermark", and "Cleanup", case (d)). A
    deletion is forgotten only by a write holder's signed decision: a counter, `forget_before`, in a
    cleanup's sealed part, below the cleanup's own counter (a writer fault otherwise), which every
    cleanup carries at the greatest value its writer holds. Every read and write holder forgets
    every tombstone, tree delete and cleanup at or below the greatest watermark it holds (`H`), in
    the commit that raises `H`, at open and on arrival, unverified; no version of a file or
    directory expires, live, archived (no horizon) or kept only as a base. `H` is a function of the
    records held and never falls while its cleanup is held, since no watermark at most `H` expires
    that cleanup and no honest cleanup case names it, so holders of the same records expire the
    same ones whatever their clocks, and exchanges converge (`protocol.md` §4.5); a commit that
    raises `H` and expires a record, or lowers `H`, owes a round on every connection where the
    folder is open, at once toward a peer that reports the read or write tier and at most once a
    day toward one that reports the sealed tier. A
    write holder keeps each deletion's and cleanup's arrival by its own wall clock, checks when the
    folder opens, when the device resumes from sleep and at least once an hour while it is open,
    and signs, at most once a day (within one opening by a monotonic clock that counts time asleep,
    across openings by its wall clock), its candidate: the greatest counter of a record it has held
    365 days that lies below every record it has held less ("Wait, never early"), when that is
    above `H` and passes a deletion or a cleanup with a group whose `because` is not empty, in a
    cleanup with no group unless
    another cleanup goes in the same commit. So a deletion is forgotten once
    some write holder has held it a year, and no younger one dated below it, whether or not it was
    online all year, and then on every device together; a replay at or below `H` is ignored for as
    long as `H` stands. A late arrival holds back its write holder's forgetting of the records dated
    above it for a year, and a dishonest writer, a peer that is a write holder's only link or a
    network attacker that cuts one off can hold forgetting back without bound: storage, never files.
    Cleanups follow the same rule, which replaces `CLEANUP_HORIZON`: the 100 000-file tree delete's
    3.4 MB of cleanups is kept a year or more, not 30 days. Sealed peers read no watermark and
    forget, as before, only by names (case (c)); they also hold the cleanups with no group until a
    write holder names them. A wrong or faked clock costs at most deletions forgotten early, never a
    version: a signer whose clock gains time signs early by as much; in the worst case one write
    holder whose clock jumps a year or more ahead (a mistyped year, a new device first synced with a
    wrong clock then corrected, a machine back after a year that boots with a wrong clock before its
    time is synced, or an outsider faking its date through unauthenticated network time or a fake
    cell tower) makes every device forget every deletion at once and undoes the deletions on their
    way; a device whose clock reads behind with little of the folder held dates its deletions below
    a watermark, which undoes them on arrival; and a fast clock's lead, carried forward, moves the
    watermarks ahead with the counters. Each way a deleted file comes back wherever a copy survives,
    at a device that never saw the deletion, at a sealed peer, or with a key holder that kept it.
    Arrivals at open, and on a device restored from a backup, are as the spec author chose (below).
  - Removed (`protocol.md` header, §3.1, §3.2, §3.5, §4.2, §4.4, §4.5, §4.7 items 2, 6, 7 and 8,
    section 5, §7, §8, §9): the clock rule's checks of the Hello (`clock_days`, Hello field 11, now
    reserved), of each record (step 4, records from the future, `MAX_FUTURE_KNOWN`) and of the store
    at open ("A clock set back"), with `CLOCK_RULE_LIMIT`, `CLOCK_OUT_OF_RANGE` (`CloseReason` 13,
    now reserved), the clock-rule issue and its remedy and the residuals the remedy left ("What
    adding the folder again leaves", and with it the open question of a per-folder writer generation
    for phase 1); the fast-clock issue and `CLOCK_AHEAD_WARNING`; expiry by the folder's own time
    `G`, `CLEANUP_HORIZON`, and what existed only for them (a cleanup raising the folder's time, "a
    folder nobody writes to forgets nothing"). The notes on main that said these stood "until the
    watermark change" are gone. The stored high-water mark's check at open keeps its day of slack as
    `MARK_SLACK`; `MAX_PEER_NAMES`'s 30-day window is `PEER_NAMES_WINDOW`.
  - Kept: version vectors and Lamport counters; the clock floor, a protection of the writer's own
    (the research's recommendation, kept by the coordinator); elapsed-time timeouts and the
    discovery windows; the display order. A key holder's views show a version's write time from
    `written_at`, never from its counter (`protocol.md` §4.4, §4.7 item 6).
  - The counter ceiling (`protocol.md` §4.4, "The counter ceiling"). `MAX_COUNTER` is 10 000 years
    of microseconds after 1970, 315 569 520 000 000 000, a constant every read and write holder
    checks alike with no clock (step 7, as before); `CLOCK_FLOOR_MAX` is half of it. A write holder
    that signs a counter at or just below the ceiling still exhausts the folder's counters: a stated
    dishonest-writer residual (the research's S2; `threat-model.md` §3.6; the owner's "Accept,
    documented"), which the clock rule kept out of reach until now. A stored high-water mark at
    `MAX_COUNTER` is accepted like any mark within `MARK_SLACK` of what the records held justify.
  - On the wire, within major 1 since nothing has been released (`protocol.md` §4.4 and section 6):
    `CleanupMeta.forget_before` (field 3); cleanups with no group, so step 1 takes 0 to
    `MAX_CLEANUP_GROUPS` groups and at least one name only when there is a group; a step-7 check
    that `forget_before` lies below the cleanup's counter; Hello field 11 and `CloseReason` 13
    reserved; step 4 left empty, the later steps keeping their numbers. Section 6 adds the watermark
    to what never changes within major 1. The largest Hello is now a 2 664-byte frame. `suites.md`
    records why the cleanup record keeps its label, `sig/cleanup`, though its layout changed:
    nothing had been released, a cleanup encoded before decodes as one with no watermark, and one
    with no group was malformed before; it uses no clock, and `CleanupMeta` still fits the 256-byte
    bucket.
  - Proofs (`protocol.md` §4.4, "Why it is safe"): 6, 10, 11 and 12 forget by the watermark, 10's
    empty-`because` groups justified by the watermark the cleanup itself carries; 8(c) loses the
    remedy's case; a new item 14, forgetting only by a signed decision, which costs reappearance
    only and no lost update, with what arrival order changes and the round a rise of `H` owes; §4.5
    "Why it converges" loses its exception for records from the future, and the layer's guarantee
    its "short of records from the future".
  - Tests (`protocol.md` §8): item 2 (the largest Hello, a Hello carrying field 11); item 6
    (cleanups with a watermark and with no group, with no group and no watermark, `forget_before` at
    and below the counter, the old 2^61 and 2^62 now writer faults, records far ahead of or behind
    the clock judged as any record); item 7 (a store years ahead of the clock opens; expiry by the
    watermark: a watermark arriving before and after the deletions it forgets, two concurrent
    watermarks, a replayed old deletion after a watermark, the cleanup carrying `H` lost at rest, a
    folder nobody writes to, the counter ceiling; properties (d), (e) and (g) lose the clock rule,
    and new (n), (o) and (p); a stored mark at `MAX_COUNTER` at reopen); item 8 (the round a rise of
    `H` owes); item 12 (a cleanup with no group at a sealed holder; a forgotten-record note above
    the watermark of the round's cleanup); and item 13, which was the clock rule at the handshake
    and is now the watermark's policy (the candidate, the old-record test without overflow, what
    holds forgetting back, the checks and the interval, arrivals at open, a device with a wrong
    clock, the worst case of a jump, a new device first synced with a wrong clock, a machine back
    after a year, a restored backup and the floor). "Who checks what" says so.
  - Threat model: TM-40 rewritten (versions by vectors, deletions forgotten only by a signed
    watermark, nothing refused for a clock, the worst case of a wrong or faked clock and its
    triggers, forgetting held back, the fixed ceiling); §3.1 (a network attacker can move a write
    holder's clock through unauthenticated time sync, and delay forgetting by cutting it off); §3.2
    (a read-key holder can hold forgetting back as a write holder's only link); TM-9 and §3.12 (no
    folder kept closed for its clock; arrivals a store changed at rest can bring forward); TM-17;
    TM-22 (no record from the future to verify; the life of a cleanup at least a year; up to one
    watermark a day per write holder and its cost; the index by counter and the cost of each rise of
    `H`; forgetting held back); TM-41 and TM-43 (the clock rule's exception and remedy gone; a wrong
    clock forgets early, every deletion at once in the worst case; a rise of `H` that expires a
    record owes a round); §3.3 (a sealed peer withholds or replays, reads no watermark, cannot make
    a holder take an expired deletion back, can hold forgetting back as a write holder's only link);
    §3.6 (exhaustion as a residual; signing a watermark; holding forgetting back); §3.10; §5 (no
    clock in the Hello; what case (c) and case (d) show a sealed peer; what a key holder reads from
    `written_at` and the watermarks). `keys.md` §0 (the clock floor stops at `CLOCK_FLOOR_MAX`),
    §3.4, §8.1 and §9 item 8, and its status line; `suites.md`'s signatures and status line.
  - The engine entry's spec question about a folder that becomes provable during a connection loses
    its clock-rule case (no folder is kept closed for its clock); the rest of it stands.
  - Fix round (2026-11-12), after the correctness, second and security reviews of the first draft
    and the coordinator's rulings on them: the owner's six decisions of 2026-11-12 written in as the
    owner's (the candidate rule is now "Wait, never early", no longer the spec author's choice); the
    worst case of a wrong or faked clock, and its triggers, stated plainly in §4.4, TM-40, §3.1,
    TM-43 and §9, the overclaims corrected ("Stops clock-skew attacks", "nothing left to protect",
    "comes back only where …"), and its vectors (§8 item 13); what holds forgetting back, the late
    arrival's delay and the three residuals (a dishonest writer, a peer that is the only link, a
    network attacker), with every "about a year" made "at least a year"; the round a rise of `H`
    owes (§4.5, "Round owed", "Cursors", "Why it converges"; §8 item 8); the checks at open and once
    a day of monotonic time, the interval by the wall clock and, when the clock reads earlier, by
    the monotonic clock within an opening (both changed in fix round 2, below), and the candidate
    and its cleanup in one commit; the rate
    and its cost (up to one watermark a day per write holder; 64 write holders: about 23 000 a year,
    9 MB, 1.4 s at open); the index by counter and the cost of each rise of `H`; case (c) judging
    each note again against its cleanup's watermark; a stored mark at `MAX_COUNTER` no longer
    corrupt; why `sig/cleanup` keeps its label (`suites.md`); the old-record test without overflow;
    and the nits: a version, not a tombstone, never expires; how `H` falls by a dishonest name; the
    owner's follow-ups cited and the arrival question quoted verbatim; what a quiet folder signs
    (stated then as about once a year, which was wrong: corrected in fix round 2, below); what a
    sealed peer learns from case (c) and (d), no longer overstated; a cleanup
    with no group and no watermark; a restored device's file missing until the watermark comes; the
    marks below added; "stamps" gone from §9; the clock floor's cap in `keys.md` §0; and history in
    parentheses trimmed where it was only history. Finished by a second author after the first was
    paused: a slow release needs no order of counters, which a sealed peer cannot read (§4.4, "What
    holds forgetting back"; `threat-model.md` §3.3); a holder of the read key can hold forgetting
    back too (`threat-model.md` §3.2); files forgotten early come back from a key holder's kept copy
    as well (`threat-model.md` §3.6); TM-40's closing claim made exact (it stops a clock from
    ordering versions and from having anything refused, and no longer claims that no clock decides
    what a device keeps); TM-41's rounds owed include a rise of `H`; §9's last "about a year or
    more" made "a year or more"; §4.7 item 6 hands the index the readings its interval needs; a
    write holder that keeps the folder open while it sleeps, where its monotonic clock stops, checks
    less often by the calendar and signs later (storage only), with its vector (a residual that fix
    round 2 removes, below); a clock that steps
    forward between opens, not only one set back, adds at most one watermark per open; and a new
    device first synced with a wrong clock and then sent a new deletion, whose counter is above
    every one it held, still forgetting every deletion it held (§8 item 13).
  - Marked as the spec author's choices, for the owner's review (all listed): the watermark as a
    field of a cleanup, not a record type of its own, with a cleanup of no group to carry it alone
    (case (d)), and what that shows a sealed peer; a cleanup with no group and no watermark valid
    and harmless, not a writer fault; every cleanup carrying its writer's greatest watermark; a
    `forget_before` at or above its cleanup's counter a writer fault; only write holders keeping
    arrivals (the owner asked "Can all devices track the arrival of the deletion record …?"); a
    record dropped and held again arriving again; the index by counter; the interval between
    watermarks a day; the monotonic clock for that interval one that counts time asleep, named per
    platform (`CLOCK_BOOTTIME`, `mach_continuous_time`, `QueryInterruptTime`), with the residual
    where none exists (fix round 2); no step between watermarks; the round owed when an expired
    cleanup drops a group `because` it, as for a deletion; arrivals at open checked against nothing,
    a missing one taking the open's reading, one later than the clock kept and young; a restored
    device keeping its backup's arrivals and records fetched again arriving anew; `MAX_COUNTER` at
    10 000 years of 365.2425 days and `CLOCK_FLOOR_MAX` at half of it; `MARK_SLACK` keeping the day
    of slack at open; `PEER_NAMES_WINDOW` keeping 30 days; step 4 left empty rather than renumbered;
    `TOMBSTONE_HORIZON` keeping its name with its new meaning, and §8 item 13 reused; and the
    reading in `suites.md` of why `sig/cleanup` keeps its label.
  - Marked as the coordinator's rulings of 2026-11-12, for the owner's review (all listed): a commit
    that raises `H` and expires a record owes a round (the first fix round); from fix round 2, a
    commit that lowers `H` owes a round too; a stored high-water mark at `MAX_COUNTER` accepted like
    any within `MARK_SLACK`; and the checks at open, on resuming from sleep and at least hourly,
    with the interval between watermarks counted within one opening by the monotonic clock alone and
    across openings by the wall clock, a reading earlier than the last signing's counting as passed;
    and, from fix round 3, a check that signs only when its candidate passes a tombstone, tree
    delete or cleanup with a group whose `because` is not empty (replacing fix round 2's "with a
    group"); a change of `H` owes a round toward a peer that reports the sealed tier at most once
    per `WATERMARK_INTERVAL` (replacing fix round 2's "none"), so that the reported tier, until then
    shown only, decides how soon; and the clock that counts time asleep read in phase 1 through a
    reviewed platform dependency or a platform-FFI crate.
  - Fix round 2 (2026-11-12), after the confirm review of the first fix round (K-1 to K-6) and the
    coordinator's rulings on it (1 to 6), each rule it adds marked as the coordinator's ruling of
    2026-11-12, for the owner's review; the owner's decisions are unchanged.
    - No echo (ruling 1, K-1; `protocol.md` §4.4, "When a write holder signs one", "Finding what
      expires", "How many", "How it is forgotten"; §9; TM-22): a write holder signs only when its
      candidate passes at least one tombstone, tree delete or cleanup with a group, so a check never
      signs only to forget earlier cleanups with no group (a cleanup with no watermark either
      counted with them, the spec author's reading). Before, each watermark-only cleanup, once a
      year old, became the next candidate, and a write holder that had signed daily kept signing
      daily for ever after deletions stopped (64 write holders: about 23 000 cleanups a year in a
      folder with no deletions). (Partly wrong, corrected in fix round 3, below: a case-(c)
      cleanup restarted the echo, and the quiet-folder figures in this item are superseded
      there.) What it leaves held: the watermark-only cleanups of about the last year, at most one
      per write holder per day, until the watermark that the next deletion, or cleanup with a group,
      brings. The
      first fix round's "a folder in which nothing more is deleted still signs about once a year"
      and "costs about one watermark-only cleanup a year" are corrected; where a sealed peer is met,
      a quiet folder costs about one case-(c) cleanup a year per write holder that meets it, and the
      watermark that forgets it. Vectors (§8 item 13, and item 7's property (p)): candidates passing
      only cleanups with no group, with and without a tombstone among them; a write holder that
      signed daily for a year and then holds no new deletion for two years, and the same with a
      later deletion, whose watermark forgets them all; the three-year quiet folder now signs once.
    - No round toward sealed peers for a change of `H` (ruling 2, K-2; `protocol.md` §3.5, field
      `ProofPayload.tier`, §4.4 "Expiry by the watermark", "How many", "How it is forgotten", §4.5
      "Rounds", "Cursors", "Round owed", "Why it converges", "Why it is safe" 14, step 6, §4.7 items
      4 and 6, "A device restored from a backup"; `keys.md` §4; TM-22, TM-32, TM-41): the round a
      rise of `H` owes is owed only on connections to peers that report the read or write tier (fix
      round 3, below, adds at most one a day toward a sealed peer), since the divergence it mends
      arises only between them, and a sealed peer's case-(c) cleanups come in rounds that happen
      anyway. The reported tier, until now shown only, decides this; a false report gains a peer
      nothing it could not have by withholding records or by opening the folder again on a new
      connection. The cost left, stated with a figure: 64 write holders each running one round a day
      with a sealed peer add at most 64 case-(c) cleanups a day, about 23 000 a year, 9 MB and 1.4 s
      at each open, as much again as the watermarks. Vector (§8 item 8): three write holders, a NAS
      and a rise of `H` (no round owed toward the NAS; one case-(c) cleanup at its next ordinary
      round), and the NAS reporting the write tier.
    - A cleanup's life of "at least a year" qualified wherever it bounds something (ruling 3, K-6):
      "(sooner while a write holder's clock is wrong or faked, TM-40)" in TM-22 (three places),
      `threat-model.md` §3.3, `protocol.md` §4.4 "Cleanup" (b) and (c), "How it is forgotten",
      "Stale copies at a sealed peer, and their bound" (twice), §4.5 "Stale copies" (twice) and
      §9; and in TM-22 and "Stale copies at a sealed peer, and their bound", that a clock faked
      forward again each day shortens every cleanup's life to a day, and with it the stale-copy
      bound, with its vector (§8 item 13: a clock set a year further ahead before each day's first
      check).
    - A fall of `H` owes a round too (ruling 4, K-3; `protocol.md` §4.4, §4.5 "Cursors", "Round
      owed", "Why it converges", "Why it is safe" 14; `threat-model.md` §3.6, TM-22, TM-41), on
      connections to read and write holders, since a deletion a peer pushed and this side ignored
      as expired is expired no longer. Vector (§8 item 8): Q and Z, a watermark W, a tombstone T
      below it, and a dishonest write holder's cleanup C naming W's cleanup (Z owes Q a round,
      which brings T); item 7's property (e) counts the rounds a fall owes.
    - A stored high-water mark at `MAX_COUNTER` is accepted like any mark within `MARK_SLACK` of
      what the records held justify (ruling 5, K-4; `protocol.md` §4.4, "Opening a folder"); the
      sentence that read two ways is gone. Vector (§8 item 7): a greatest held counter of
      `MAX_COUNTER` − 5 beside a mark of `MAX_COUNTER` (accepted, no report).
    - The checks and the interval (ruling 6, K-5 and the coordinator's amendment; `protocol.md`
      §4.4, §4.7 item 6, section 5's "Time" and constants, §8 item 13; TM-22): a write holder
      checks when the folder opens, when the device resumes from sleep, and at least once per
      `WATERMARK_CHECK_INTERVAL` (1 hour, a new constant) while the folder is open; within one
      opening the interval between watermarks is counted by the monotonic clock alone, across
      openings by the wall clock, a reading earlier than the last signing's counting as passed, and
      signing stays at most once per `WATERMARK_INTERVAL`. The monotonic clock for that interval
      counts time asleep (the spec author's choice, for the owner's review, which the coordinator
      asked to be made concrete): `CLOCK_BOOTTIME` on Linux and Android, `mach_continuous_time` on
      macOS and iOS, `QueryInterruptTime` on Windows (which includes time asleep, unlike
      `QueryUnbiasedInterruptTime`). So the residual of a device that sleeps with the folder open
      and signs late is removed where such a clock exists; where none does (a browser, phase 6:
      `performance.now()` may pause while the device sleeps), signing after a sleep can come late,
      which costs storage only. The two-hours-a-day vector is reworded (a device that opens at 8:30,
      after signing at 9:00 the day before, signs at its 9:30 check), the sleeping device's vector
      now signs about once a day, and the table's row no longer has an "otherwise passed" case.
  - Fix round 3 (2026-11-12), after a narrow check of fix round 2 (L-1 to L-5) and the
    coordinator's rulings on it, each rule it adds marked as the coordinator's ruling of 2026-11-12,
    for the owner's review; the owner's decisions are unchanged.
    - The echo through case (c) stopped (L-1; `protocol.md` §4.4, "When a write holder signs one",
      "Finding what expires", "How many", "How it is forgotten", §4.7 item 6, §9; TM-22): a case-(c)
      cleanup has a group, with an empty `because`, so under fix round 2's rule it made a write
      holder sign a year later, which forgot it at read and write holders while a sealed peer still
      held it, and the next round named it in a new case-(c) cleanup, for ever wherever a write
      holder meets a sealed peer. Condition (2) now counts only tombstones, tree deletes and
      **cleanups with a `because`**, with at least one group whose `because` is not empty (cases (a)
      and (b)); case-(c) and watermark-only cleanups never make a write holder sign. The five
      statements are corrected: once nothing more is deleted, the last year's watermark-only and
      case-(c) cleanups stay held at every tier until the watermark that the next deletion, or
      cleanup with a `because`, brings, and no case-(c) cleanup follows them. Vectors (§8 item 13):
      a case-(c) cleanup among those that sign nothing and a case-(b) one among those that sign; a
      write holder with a daily round with a sealed holder, daily deletions for a year and then none
      for two years (nothing signed after the watermark that passes the last deletion); property (p)
      extended.
    - Rounds toward sealed peers bounded (L-2; `protocol.md` §3.5, §4.4 "Expiry by the watermark",
      "How it is forgotten", "How many", step 6, "A device restored from a backup", §4.5 "Rounds",
      "Cursors", "Round owed", "Why it converges", §4.7 items 4 and 6, section 5's
      `WATERMARK_INTERVAL` row; `keys.md` §4; TM-22, TM-32, TM-41): a change of `H` owes a round
      toward a peer that reports the sealed tier at most once per `WATERMARK_INTERVAL`, a later
      change waiting until that interval has passed (one more bit and one monotonic time per folder
      per connection), so what such a change leaves at a sealed peer waits at most about a day, and
      the "64 a day" case-(c) figure is a bound for those rounds, with at most one more per round
      that comes for another reason. Vectors (§8 item 8): the three write holders and the NAS, with
      a second watermark an hour later whose round toward the NAS waits for the interval; the fall
      of `H` toward a sealed peer.
    - Wording (L-3): threat-model §3.6 and TM-32 say "a peer that reports the read or write tier";
      TM-32's "Enforced by" adds `engine`; step 6 says "a commit that lowers `H`".
    - Wording (L-4): §9 says no device signs only to forget earlier watermark-only cleanups, its
      own or another's; the "at most one per write holder per day" bounds (the Cleanup bullet, "How
      many", TM-22) add the one more per open that a wall clock stepping between opens allows.
    - L-5: a vector (§8 item 8) for the other false report, a read or write holder that reports
      the sealed tier (its round comes within the interval, nothing is dropped, both converge); the
      browser's late signing after a sleep among TM-40's causes of late forgetting; and a line in
      §4.7 item 6: the named clocks are not `std::time::Instant` on Linux (`CLOCK_MONOTONIC`) or
      macOS (`CLOCK_UPTIME_RAW`), so phase 1 reads them through a platform dependency that enters
      by a reviewed change (TM-8) or a platform-FFI crate under TM-7's exception.
  - Reviewed 2026-11-12 by afcb382db6ef4775f (correctness: blocked by four, now fixed),
    af68ac480b2578204 (second: one should-fix, now fixed) and a07fe659f19647435 (security: blocked
    by two, now fixed); the owner decided C-1, F-1, S-1 and S-2. Confirm a4aa1b35e5000b4d4 with the
    correctness and security passes: blocked by three, now fixed; check adf3d98e7e23c83ce: blocked
    by one, now fixed, then clean. Authors a1ae674b2ad1cf237 (paused) and a8c7f67f79e4fe833; fixes
    by a68ce86b3b09eec52 (paused), a64007399e63a4909 and a1260e098fe64bf5d. Landed as one squashed
    commit.

- Spec: make relays public only, let devices whose persons turn it on coordinate hole punches, and
  archive copies a device can no longer read (the owner's answers of 2026-11-03, "Yes, remove the
  old copy" and "drop the private/protected relay idea and only work with public relays"; of
  2026-11-04, to the spec author's questions on relays, "All three"; of 2026-11-08, on hole
  punching, its defaults and relayed connections, and on TM-22's "QUIC stream memory"; and of
  2026-11-10, on the reviews of this change). Spec text only: the engine implements the archive
  rules in a later change, and `net` the rest (hole-punch
  coordinators in phase 2, public relays in phase 7). Nothing on the wire changes; the protocol
  stays major 1. TM-1, TM-22, TM-25, TM-35, TM-41 and TM-42, and TM-9, TM-10, TM-14, TM-17 and TM-32
  for the relay wording; `suites.md` for the security protocol of a circuit.
  - Unreadable records (`protocol.md` §4.4, "A path with no heads"). A path all of whose live
    records are opaque (writer faults, or a newer release's version of an unknown `kind`) has, like
    a path whose versions a tree delete took, one base, at the path: the greatest tree delete held
    at its tag by record hash, or none. So a device that held the version such a record replaces
    takes its outdated copy off its disk, to the archive (phase 1), with each conflict copy of it
    that has not become a version at its own path, and every device on one release that holds the
    same records keeps the same disk there. A twin, or a head of a conflict, that the record does
    not name keeps the path's heads and its file. This removes the stated residual of the engine's
    fourth review round (S3-A, recorded in the engine entry below for the owner's review): such a
    path no longer keeps whatever its disk had, so two devices can no longer differ there. The
    device remembers the versions it so archived, as archived versions in the slots their bases
    held, and its next write at the path, or a tree delete above it, covers and names them, so that
    a device or sealed peer that missed the unreadable record drops the old version instead of
    bringing it back beside that write (the owner's decision of 2026-11-10, "Also what was
    archived"); a version it never had still stays beside the write as a conflict, by design. The
    copies stay in the archive until a version the device reads covers theirs, a head that does not
    cover it leaving them, past the archive's retention, now a
    setting (30 days by default), and with versioning off, and the engine raises a warning that says
    what the device can and cannot do (the owner's decision of 2026-11-10, "Until fixed. Warning
    notification. On desktops with a gui, a status bar indication and a system message. 30 days
    should be configurable."); the residuals are stated: the archive holds the only copy on each
    device that had it, a record of a kind no release knows takes the file off the disks until
    someone saves it and stays beside it for good, and a read holder cannot clear a fault. TM-35,
    TM-41 and §9 say so; §8 items 7 and 14 gain the vectors. The engine's
    `sync/disk.rs` and its module documentation, and the documentation of the `WriterFault` issue in
    `issues/mod.rs`, still carry the old rule until the engine change; so does the note there and in
    `crates/sim/src/oracle.rs` that a scenario planting opaque records must make the oracle's check
    (b′) skip such a path, which goes with the engine change, once these vectors run (the
    coordinator's ruling of 2026-11-10).
  - Relays (`threat-model.md` §2, §3.3, §3.9, §3.10, TM-25, §5; `keys.md` §2.1; `protocol.md` §3.1,
    §4.1, §4.4 and §9). Only public relays exist; no device relays for others, and none uses a
    relay, unless its person turned it on (serving per device, on computers only, never a phone;
    using per folder). TM-25 drops Private mode and states the limits a relay enforces, as
    requirements: a rate schedule by time of day and day of week, a cap on open circuits with a
    bounded queue (the plan's "Volunteer relay scheduling": busy, a time to retry and a place in the
    queue), a minimum transfer rate below which an idle circuit is closed when someone waits or
    after an idle time, caps per requester by peer ID and by source address, fair shares by deficit
    round-robin with the plan's yield when others wait, a cap on reservations of its own, and
    bounded state per requester in fixed-size tables that outlive a connection and never evict a
    live entry; reservations only on direct connections; a reservation names no folder, so a relay
    learns no folder ID; a relay never receives Hello; and relay control is the relay protocol's
    own, versioned with it (the plan), so `protocol.md` §4.1 reserves no range for it.
  - Hole-punch coordinators (`threat-model.md` TM-25, §2, §5, TM-42; `protocol.md` §3.1, §4.5 and
    §9; `keys.md` §2.2, §6.3; the owner's decision of 2026-11-08, which replaces their decision of
    2026-11-04, "Folder peers time punches", and its requirement that the device timing a punch
    prove a key to the folder). Any computer may coordinate punches once its person turns that on,
    off unless turned on, and never a phone (the owner's decision of 2026-11-10, "Computers only
    (Recommended)"). Every connectivity switch is a device-wide default that each folder may
    override, the hole-punch level among them, and a punch serves a folder only where, on both
    sides, its direct-connections switch is on and its level allows the coordinator (the owner's
    decision of 2026-11-10, "Both must allow ... Folders can override."). The levels, never, through
    peers of a shared folder (the default), through devices it is connected to directly, and through
    any device it knows and any public relay its person turned on, are cumulative and defined. The
    device to be reached keeps reservations with up to three coordinators and lists them only to the
    peers of its folders and in invites, never in the DHT (the owner's decision of 2026-11-10,
    "Peers now, alias later", with a phase 2 item for a rotating alias). Counting only the folders
    whose settings allow a punch through that coordinator, it takes a punch only from
    a peer of a shared folder, known by the peer ID that per-peer state now keeps, or from a
    requester that proves a key to one of its folders over the coordinator's circuit with the
    handshake up to the folder proof; it sends no address before that, and a removed person learns
    nothing through a punch (the owner's decision of 2026-11-10, "Known peers or key holders").
    Bounds: at most 64 KiB and 60 s a circuit; 4 at once and 10 in any minute for each requester and
    to each reserved device; 64 at once and 120 in any minute in all, about 7.5 MiB a minute and at
    most about 11.5 MiB in any one; reservations 2 for each requester by peer ID, 8 by source
    address and 128 in all, the longest idle dropped when others wait; reservations and punch
    requests only on direct connections; each side takes at most 8 global unicast addresses from
    the other, judged by the IANA special-purpose registries, an IPv6 one only within 2000::/3 or
    under 64:ff9b::/96, with the IPv4 address an IPv6 one carries judged too or the address refused,
    and takes part in a bounded number of punches; residuals stated.
  - Relayed connections (`protocol.md` §3.1, the coordinator's rulings of 2026-11-08 and
    2026-11-10). A side runs the sync protocol over a relayed connection only through a public relay
    it chose as a relay, only for the folders whose public-relays switch is on, and never on a
    punch-only circuit: one through a device it reserved with, or dialed through, only for a punch
    (S2-1 of the second review, confirmed by the owner on 2026-11-08: "I don't want random connected
    clients used as relays without the operator's consent"), or one whose stated limit is at most a
    coordinator's bounds, whatever the device in the middle says. A punch-only circuit carries only
    the channel set-up, identify, DCUtR and the admission handshake. A side closes a relayed
    connection when a folder's switch is turned off or a direct connection to the peer takes its
    place, and backs off after a refused or cut relayed session.
  - Circuits' security protocol (`suites.md` §2.6 and §3.1's rows, TM-1, §5's quantum entry;
    `keys.md` §2.1): TLS
    1.3 with X25519MLKEM768 between native ends, Noise only where a browser client is one end, a
    native dialer offering exactly one.
  - TM-22's residual (h), the owner's decision of 2026-11-08 on spike B's proposed phase 1 item
    ("Yes go with proposal for QUIC stream memory. 2.9 GiB in memory seems like a tremendous ask,
    especially for a browser. I'm concerned about this figure."): the sentence after (g) on QUIC's
    windows, which bound bytes and not memory, is now residual (h), **required before 1.0**, phase 1
    item "QUIC stream memory" beside (a) to (c), no longer proposed; TM-22 counts eight residuals,
    and §3.10 lists (h) among what an attacker can still do to the transport. (h) concerns the
    native program, whose QUIC connections, accepted and dialed, run on quinn, not the browser
    client, whose QUIC is the browser's own; the datagrams need only arrive back to back for GRO to
    coalesce them, with or without GSO. Beside (e)'s and (h)'s upper
    bounds (from quinn's 94 208-byte buffer: about 184 MiB, 5.75 GiB and 2.9 GiB), TM-22 gives the
    figures at 64 KiB a read as the realistic bound, since quinn copies only the bytes a read
    brought (about 128 MiB a connection for
    datagrams, 128 MiB a stream, 4 GiB across 32 streams and 2 GiB across 16), neither set measured;
    and (e)'s phase 6 item notes that a panic in the contained handshake task and an aborted
    handshake future also leave the QUIC connection open, which "closed explicitly on every failure
    path" already covers. TM-22 and §3.10 now name the per-requester tables of relays and
    coordinators, the lookup of per-peer state by peer ID and a device's punch counters, beside
    per-peer state, as the tables that outlive a connection, each of a fixed
    size. The plan's phase 1 work list and 1.0 gate are the plan scribe's to update.
  - Relay wording. A relay sees no record, so "a sealed peer or relay" of records is now "a sealed
    peer" (TM-9, TM-17, TM-41, `protocol.md` §4.4 and §9, where "Through sealed relays" is "Through
    sealed peers"); TM-32 no longer says a folder ID can come from a relay; `keys.md` §1.3's sealed
    tier and TM §3.2 forward ciphertext rather than relay it; TM-10's honest sender is a forwarder;
    TM-14 and `keys.md` §3.2 no longer say a relay sees chunk hashes; `keys.md` §4 and `suites.md`
    no longer say every relay knew the folder ID; the glossary's relay is used only for folders
    whose public-relays switch is on; TM §3.3 says a relay can cut a connection at a moment it
    chooses. The phase 0 gate record keeps what its reviewer checked, with dated notes that phase
    2's peer relay is now hole-punch coordinators. The status lines of the four specs say what
    changed.
  - Two corrections of main's own text, found while reviewing the clock repair this change no longer
    carries and kept: a write holder also issues a cleanup with a write whose faults do not fit
    (`protocol.md` §4.4, Expiry), and a cleanup is paged by both `MAX_CLEANUP_ENTRIES` and
    `MAX_CLEANUP_GROUPS` (Cleanup, and 4.7 item 6).
  - The clock repair of this change's drafts is withdrawn, by the owner's decision of 2026-11-08
    after the research on removing clock dependence: a signed watermark replaces expiry by the
    folder's own time, and the clock rule and its repair go, in a later change, the first spec
    change of phase 1. Until then the clock rule, "A clock set back" and expiry stay as they are,
    each with a note saying so (`protocol.md` §4.4, `threat-model.md` TM-40).
  - Ported onto 9a090fe (wip/spec-1103b, the owner's order of 2026-11-09: no rebase, so a
    cherry-pick of 2b44ab0) over the identical-heads fix (ebb6a67), the download retry (598e58a) and
    the small follow-ups (9a090fe). Conflicts: `protocol.md` §4.4 "Why it is safe" 8(a) (main's text
    kept, with "a sealed peer that withholds" for "a relay that withholds"), §8 item 7 (main's twins
    list kept, and the drafted "no heads from opaque records" cases added after the clock cases), §9
    "What can still go wrong" (main's two bullets, with the drafted archive clause in the first and
    "a NAS that holds back" in the second), `threat-model.md` TM-41 (main's residuals, with the
    drafted sentence on unreadable paths before them), and this file (both entries kept, this one
    first). The port's own changes, to make the two sets of rules agree: `protocol.md` "Why it is
    safe" 9 says that a record this release cannot read drops a version only by a name and that a
    path has no heads only when no live version is left, twins included, so an unnamed twin keeps
    the file and the file that leaves the disk is a copy whose version a named record has replaced;
    "A path with no heads" says that conflict copies leave with the file and that an unnamed twin
    keeps the path's heads; 4.7 item 6 tells the engine so; the drafted text's last "sealed peer or
    relay" in TM-41 (about withholding records) is "sealed peer", a relay reading no record;
    `crates/net/src/limits.rs`'s module doc names TM-22's residuals (a) to (h) and calls (h), "QUIC
    stream memory", required before 1.0 by the owner's decision of 2026-11-08, which main's TM-22
    had still called proposed (a doc comment only).
  - Fix round of 2026-11-10, on the three reviews of the port (correctness, fidelity, security; the
    coordinator's rulings 1 to 28, but 19, the plan's): the owner's four decisions of that day above
    and "Computers only", recorded as the owner's; C-1, archived versions; C-2, a conflict copy that
    has become a version at its own path stays (vectors for both orders); C-3 and S-6, punch-only
    circuits by stated limit, the middle's claim only turning sync off, the backoff, the SHUTDOWN on
    a switch turned off and the close once a direct connection exists, and only identify, DCUtR and
    the admission handshake on such a circuit; C-4, S-7 and F-8, the coordinators' list only to
    peers and in invites, and what each party learns (§3.9, §5); C-5, the levels made implementable;
    C-6, relay control the relay protocol's own and no Hello to a relay; C-7 and S-8, the §8 vectors
    (twin, one head of a conflict, both heads with the copy at its own path in both orders, the
    returning device with the same and changed content, an old release's tree delete over an
    opaque-only subtree), and a new §8 item 15 for relayed connections; F-1, the defaults stated
    (asking for punches on through peers of a shared folder, coordinating and relays off); F-2,
    coordinators take reservations and punch requests only on direct connections; F-3, "a public
    relay coordinates too" and 3.1's first ruling marked as readings; F-4, `suites.md`'s folder-ID
    wording; F-5, line widths; F-6, "all of whose"; F-7, phase 2's timing attributed to Q4 of
    2026-11-04; F-9, a note at "A clock set back"; S-1, the addresses a punch accepts and the caps
    on punches, with the residual; S-2, known peers or key holders; S-3, reservations capped apart,
    the idle dropped first, live entries pinned, the plan's yield, the denial-of-service residual;
    S-4, circuits' security protocol; S-5, the archive and warning rules with residuals (i) to
    (iii); and the nits of both lists (C N-1 to N-8, S N-1 to N-7): cleanup paging by both bounds in
    4.7, "Why it is safe" 9 and 10 on names this release cannot read, 8(a) "or could not read",
    unreadable records keeping no directory, "on one release", TM-22 (h) for dialed connections and
    GRO without GSO, no FolderProof for folders paused on a relayed connection, a relay cutting a
    reconciliation midway, the coordinator's view of peer IDs in §9, and a phase 7 note on relays
    that announce a low load. The phase 0 gate record's two rewrites of what its reviewer checked
    are back, with dated notes. The plan passages that the fidelity review found stale (old Q4, the
    clock repair) are the plan scribe's to update.
  - Fix round 2 of 2026-11-10, on the confirm review of the first (the coordinator's rulings on its
    findings K-1 to K-18, all taken). K-1: the copies archived on a fault are kept, past the
    retention and with versioning off, until a record this release reads covers or names their
    version (this device's next save, which covers it as an archived version, a save elsewhere made
    over it, or the record that took it, once read), until the version is a base here again, or, for
    one whose archived version failed its check at open, until this device next saves there; a head
    that does not cover it leaves the copy and the warning, and shows as a conflict as usual; the
    warning says that saving ends the keep, so restore first (`protocol.md` §4.4, 4.7 item 6, §9;
    TM-35, TM-41). K-2: a punch's addresses judged by the IANA special-purpose registries, an
    IPv4-mapped address as its IPv4 address (superseded in fix round 3: such an address is refused
    outright), one under 64:ff9b::/96 by the IPv4 address it carries,
    64:ff9b:1::/48, 6to4 and Teredo refused, 0/8 and 240/4 named, and a `net` test for each block
    and range (TM-25, §8 item 15). K-3: at admission only the folders whose own settings allow a
    punch through that coordinator count, for the lookup of a peer as for a key proof, every other
    folder paused in the admission handshake, and the public-relays switches play no part on a
    punch-only circuit; each coordinator is listed only over connections where such a folder is
    open, and in invites to such a folder (`protocol.md` §3.1, §3.5 step 2, §9; TM-25, §3.10, §5;
    `keys.md` §6.3). K-4: archived versions stay beside the base a slot takes later, bounded by the
    records that take a path's heads (TM §3.6), and one is dropped when the same record is held
    again or becomes a base again; `S` is a set (`protocol.md` §4.4, "Bases" and "What a device
    remembers"). K-5: `suites.md` §3.1's `rustls` and libp2p rows name circuits, native Noise on a
    circuit allowed only from phase 6 with a browser end, and §2.6 counts six TLS configurations
    from phase 2. K-6: §9 says what a punch can still send at someone else, at most 160 short bursts
    a minute. K-7: §8 item 7 gains a tree delete taking archived versions and its cleanup naming
    them, an archived version dropped by a name and by a tree delete, one failing its check at open,
    the returning device in the other order, an archived version held again, a second loss of heads,
    and the cases of K-1 and K-14; item 15 gains the two sides judging punch-only differently, the
    backoff back to 1 minute after a completed round, and the cases of K-3, K-8 and K-15. K-8: the
    admission handshake runs on a stream only the device to be reached opens, and only for a
    requester it does not know; the requester pauses every folder there and answers a FolderProof
    REJECTED; 3.5 step 6 and `PROOF_TIMEOUT` are qualified, the punch attempt's 10 s bounding
    admission and punch. K-9: the device in the middle receives no Hello as relay or coordinator,
    and one that is also a folder's peer syncs over a connection of its own (`protocol.md` §3.1,
    TM-25). K-10: losing per-peer state also loses admission by peer ID (4.5). K-11: TM-42, unless
    they still share another folder; TM-41, on a device with the write key. K-12: §8 "Who checks
    what" gives item 7's engine cases to the engine. K-13: the §3 diagram shows circuits. K-14: a
    stated residual, an archived version beneath a tree delete that the pruned vector leaves
    uncovered gets no tombstone (`protocol.md` §4.4 "A tree delete", 4.7 item 6). K-15: a circuit
    refused at admission counts toward the device's caps through its coordinator, not those in all,
    with the cost stated (TM-25, §3.10). K-16: `suites.md` "Circuits": phase 6 takes the browser
    mark only from sources the device in the middle cannot alter; `keys.md` §2.1 points to the
    quantum caveat. K-17: TM §3.6, faults let a write holder keep copies past the retention,
    bounded, nothing amplified. K-18: `keys.md` §2.2, the relays a device keeps reservations with
    are not in the DHT either.
  - Marked as the spec author's choices, for the owner's review (all listed): the relay's schedule
    read in its local time; the connection cap counting circuits, with reservations capped apart (2
    by peer ID, 8 by source address, 256 in all at a relay; 128 in all at a coordinator), the
    idle-longest reservation dropped, and the queue's bound; a source address as an IPv4 address or
    an IPv6 /64; least-recently-active eviction of unpinned entries, in tables of 4 096; the levels'
    names and meanings (cumulative; a peer of a shared folder by the peer ID per-peer state keeps,
    any folder still held; "connected directly" as dialed by this device or with a folder open;
    "knows" by the sources a device's settings allow; a public relay as a coordinator only at the
    fourth level, for folders whose relay switch is on); the announcement by registering the punch's
    relay protocol, seen through identify; up to three reservations, their renewal, a requester
    reading three coordinators and trying two at once; at most four FolderProofs on a punch-only
    circuit, counted by the device to be reached (fix round 3); on every circuit, only the side the
    circuit reached opening a stream of the sync protocol (fix round 3); a refused requester sent
    `Close(NO_COMMON_FOLDER)` once the handshake's stream is open (fix round 3); in fix round 4, the
    FolderProofs past the fourth answered REJECTED, not closed, the caps in all checked at the
    moment of admission, the dialing side closing a public relay's circuit that brings no stream
    within `HELLO_TIMEOUT`, and the side's own and anycast addresses refused, with no SO_BROADCAST
    on a punch's sockets; the admission handshake on a stream that only the device to be reached
    opens, and only for a requester it does not know, the requester pausing every folder there, the
    punch attempt's 10 s bounding admission and punch in place of `PROOF_TIMEOUT` (fix round 2); the
    relayed-session backoff (1 minute, doubling to an hour); the punch caps (8 addresses; 2 at once
    and 6 a minute through one coordinator; 4 and 20 in all; 10 s an attempt; 64 coordinators'
    counters; 4 and 10 to one reserved device) and every other bound, starting values fixed in phase
    2; the addresses a punch accepts, judged by the IANA special-purpose registries with embedded
    IPv4 judged too (fix round 2), IPv4-mapped addresses refused outright, an address under a NAT64
    prefix that a side knows for its own network judged by the IPv4 address RFC 6052 places in it,
    and 192.0.0.0/24, 192.88.99.0/24 and 2001::/23 refused whole (fix round 3); a circuit refused at
    admission counting toward the caps through its coordinator and not those in all, with its cost
    (fix round 2); the archived versions' order in `S` (last, by the display order's rule), their
    being taken by a tree delete too, and when they are dropped (a write, an applied record covering
    or naming them or an applied tree delete covering them, or the same record held again or a base
    again; no longer at the deletion horizon after archiving, which fix round 2 removed, since a
    copy's keep now ends only when its version is covered); the copies' retention once the keep ends
    (the archive's retention from then, none with versioning off); a tree delete that covers an
    archived copy's version ending its keep (a reading, fix round 2); unreadable records keeping no
    directory; and circuits' security protocol (TLS between native ends, Noise only with a browser
    end, a native listener taking Noise on a circuit only from phase 6). Marked as readings for the
    owner's review: "a public relay coordinates too" and 3.1's first ruling (a folder syncs over a
    relayed connection only where its relay switch is on, others paused there).
  - Fix round 3 of 2026-11-10, on the re-confirm review of fix round 2 (its findings Q-1 to Q-8, all
    taken; the coordinator's brief chose the simpler safe answer for each of Q-3's three). Q-1: at
    open, the archived versions count with the bases, both for "A clock set back" and for the stored
    high-water mark, so that a mark cannot be lowered below an archived version from a fast clock,
    which would have made the next write carry that version's dot at or above its own counter, a
    writer fault on every device (`protocol.md` §4.4 "Opening a folder"; §8 item 7's new vector, and
    property (m)). Q-2: an IPv6 address a punch takes must also lie in 2000::/3, unless it is under
    64:ff9b::/96, so fec0::/10, ::/96 and the rest of ::/8 are refused (TM-25; `net` test lines in
    §8 item 15). Q-3: an IPv4-mapped address is refused outright; an address under a NAT64 prefix
    that a side knows for its own network, from its network's announcement (PREF64) or its system
    and never from a DNS lookup, is judged by the IPv4 address RFC 6052 places in it, and one under
    a prefix it cannot know is a stated residual (TM-25, §3.10, `protocol.md` §9); 192.0.0.0/24,
    192.88.99.0/24 and 2001::/23 are refused whole, their anycast addresses reaching a service near
    the sender (the 6to4 relay block beside the review's two, by the spec author); and the residual
    of the addresses names the device's own network's public ones. Q-4: a device takes a STOP only
    from a device in the middle it holds a reservation with, answering any other NO_RESERVATION, and
    an attempt counts toward its caps in all only once it admits the requester (TM-25, `protocol.md`
    §3.1). Q-5: on every circuit only the side the circuit reached opens a stream of the sync
    protocol, and refuses one the other side opens; the fifth FolderProof is counted by the device
    to be reached, the requester answering the other side's proofs REJECTED up to
    `MAX_PROOFS_PER_CONNECTION`; a requester refused once the handshake's stream is open gets
    `Close(NO_COMMON_FOLDER)`, one refused before it no Close; `PROOF_TIMEOUT`'s constants row, the
    Close code's comment and section 5's rows say so (`protocol.md` §3.1 and its summary of
    2026-11-10, §4.2, section 5; §8 item 15). Q-6: once no record this release cannot read is left
    at the path (a save made elsewhere named the fault without covering the version), the warning
    names none and says that the file at the path was not made from the archived copy; a device that
    still holds that version as a head shows the conflict (`protocol.md` §4.4; §8 item 7's engine
    vector). Q-7: a sealed peer can replay a fault, or a record of an unknown kind, after the
    version it names came back from a forgotten deletion, to have it archived and kept past the
    retention again, bounded by the folder's history (TM §3.3 and §3.6). Q-8's two corrections are
    to fix round 2's commit message, for the coordinator's squash message: K-4's bound is the
    records this release cannot read that write holders sign, not only faults, and K-1's keep also
    ends, for a copy whose archived version failed its check at open, when this device next saves at
    the path.
  - Fix round 4 of 2026-11-11, on the narrow check of fix round 3 (its findings R-1 to R-5 and one
    observation, all taken; spec text only, nothing on the wire changes, protocol still major 1).
    R-5: fix round 3's paragraph rewrapped to 100 columns. R-1: the caps in all are checked at the
    moment of admission, counting the attempts already admitted, so attempts that began below the
    caps cannot all finish above them (6 at once against a cap of 4): a requester whose admission
    would exceed 4 at once or 20 in a minute gets `Close(NO_COMMON_FOLDER)` when the handshake's
    stream is open, else no Close, and counts toward the caps through its coordinator only
    (`protocol.md` §3.1, TM-25; the item 15 vector). R-2: (a) and (b), a side refuses its own global
    IPv6 and public IPv4 addresses and, in each of its own /64s, the subnet-router anycast address
    (interface identifier 0, RFC 4291) and the RFC 2526 anycast identifiers; (c) named as a stated
    residual, a publicly numbered network behind a non-default route (a split-tunnel VPN); (d) `net`
    never sets SO_BROADCAST on a socket a punch uses, with a test line in item 15; (e) the NAT64
    residual reworded to "a translator on its network whose prefix or mapping the side cannot
    learn", in TM-25, §3.10 and `protocol.md` §9. R-3: on a circuit the dialing side takes for a
    public relay's, it closes the circuit, with no Close, when no stream of the protocol comes
    within `HELLO_TIMEOUT` of the channel's set-up, and counts it as refused for the backoff
    (`protocol.md` §3.1; vector). R-4: the device to be reached examines four FolderProofs on a
    punch-only circuit and answers each one past the fourth REJECTED (up to
    `MAX_PROOFS_PER_CONNECTION`), not `Close(PROTOCOL_ERROR)`, so that a requester that takes the
    circuit for a relay's and proves more folders is not closed (§3.1; vector). Observation: fix
    round 2's K-2 line says its mapped-address rule was superseded, and the rules as they stand
    after this round are the ones TM-25's "What a punch may be aimed at" and `protocol.md` §3.1
    state: addresses by the IANA registries with 192.0.0.0/24, 192.88.99.0/24 and 2001::/23 refused
    whole, 2000::/3 or 64:ff9b::/96 only, mapped addresses refused, embedded and known-NAT64 IPv4
    judged, the side's own and anycast addresses refused; four FolderProofs examined; caps in all
    checked at admission. New choices marked for the owner's review, all listed here: the caps in
    all checked at admission with the refusal's Close and its counting; the side's own addresses and
    anycast addresses refused; SO_BROADCAST never set; the split-tunnel residual left stated, not
    refused; the dialing side's close after `HELLO_TIMEOUT` and its backoff; proofs past the fourth
    answered REJECTED.
  - Fix round 5 of 2026-11-11, on the narrow check of round 4 (S-1, N-1 to N-3; spec text only): the
    section 5 Malformed row no longer lists more than 4 FolderProofs at a punch-only circuit (only
    the 257th is malformed; the REJECTED row notes that proofs past the fourth there are REJECTED
    unexamined); TM-25 names two more stated residuals, the side's NAT-mapped public address and
    circuits still in admission (up to 128 handshakes); stray short lines rewrapped.
  - Reviewed 2026-11-10 and 2026-11-11 by a2f6a3d1fb7a4370e (correctness: blocked by seven, now
    fixed), aa3ce120d36a5fcaa (second: three should-fix, now fixed) and abc8ccb900cb0c13b
    (security: blocked by two, now fixed; the owner decided S-2 and S-5); confirm
    a5436b306f70be84a with the security and cryptography passes: blocked by seven, now fixed;
    re-confirm ad7e66756969c339a: blocked by two, now fixed; checks afccc6635dc19d70b and
    af286ce2d4b5dfa87: blocked by one each, now fixed, then clean. Earlier drafts were reviewed
    on 2026-11-08 by a32f6c9420d253990 and a88b4eaa1949166c3. Authors aad961f7ff11fbb26 and
    a0a7654b30001d097 (drafts) and a47df1b19e6cfbd4a (port); fixes by af8722e3b7f720339,
    a6a4a0f9a544befaa, a8e20472fabee030f, a25b6bdfddc4e195a and a08bf8f70d2be78c0. Landed as one
    squashed commit.

- Clean the stale coverage binaries inside `gate.sh`, bring the gate list in `CONTRIBUTING.md` up
  to date, and settle five small follow-ups (the coordinator's brief of 2026-11-09): three of the
  download retry's re-confirm review, one doc comment of `net`, one note on the upstream pull
  request that unpins the vendored crate. Docs, gate wiring and one test script; no keys,
  protocol, paths or API, so no security pass.
  - **`gate.sh` cleans `target/llvm-cov-target` before the coverage loop** (`cargo llvm-cov clean
    --workspace`, gate.sh:292). The bug: cargo-llvm-cov reports on every test binary of a
    workspace crate in that directory, and before a run removes only the crate it measures, so a
    binary left by an earlier gate run in another crate stays. Engine's links the index; with the
    index changed, its coverage map still holds the old index code and the index measurement
    failed for no reason, twice on 2026-11-08 (`write.rs` and `views.rs` at about half). The
    workaround was to run the clean by hand before `gate.sh`; the gate does it now. The choice
    among removals: `cargo llvm-cov clean --workspace` (every workspace crate's artifacts and the
    profile data, the dependencies' build kept), a plain `cargo llvm-cov clean` (the whole
    directory) or deleting the test binaries by hand. The first, because the second adds the
    dependencies' rebuild and the third copies cargo-llvm-cov's rules for which files belong to a
    crate. Cost, measured here on 2026-11-09 with cargo-llvm-cov 0.9.1: the clean takes under a
    second and cuts `target/llvm-cov-target` from 1.9 GB to 247 MB; the four measurements take 229
    s on a warm directory (keys 5, protocol 10, index 24, engine 190) and 230 s after the clean
    (8, 10, 24, 188); on an empty directory, as a plain clean would leave it, 251 s. CI is not
    changed: its coverage job runs `cargo llvm-cov nextest --workspace` before the loop, which
    cleans every workspace member itself.
  - **`CONTRIBUTING.md`'s "Local checks"** listed 26 commands and left out the pins, the browser
    test crate's checks, `cargo audit` on `fuzz/`, and the checks of the CI scripts added since
    (check-pins, vector line endings, check-netlog, check-wasm-bindgen, check-vendored,
    test-download, check-downloads). It now says that `gate.sh` is the list, then names eight
    groups in `gate.sh`'s order, each with its scripts, and gives the reason for the clean. Why
    groups: a list of commands had fallen behind `gate.sh` more than once, and the groups change
    only when a kind of check is added; the section says that `gate.sh` is right when they
    differ. Checked with a loop over `gate.sh`: every `ci/` script it runs is named in the
    section.
  - **`crates/net/src/limits.rs` module doc**: "TM-22 states the four residuals" was out of date.
    TM-22 lists seven residuals, (a) to (g), (e) to (g) of the WebTransport listener, and the
    phase 1 item "QUIC stream memory". The doc now says that TM-22 is the list (so a new residual
    is added there and the doc is not wrong), that its bullets are the ones that bear on the
    swarm's QUIC and TCP bounds with TM-22's letters ((a), (b), (c), (d)), and adds the bullet it
    lacked: the receive window counts bytes, not the memory behind them. A doc comment only.
  - **`browser-tests/webtransport/vendor/README.md` and `Cargo.toml`** name the owner's pull
    request rust-libp2p #6747 beside #6446 and #6671: what it does (removes the exact
    `wasm-bindgen-futures` pin for `0.4.80`, requires futures-timer 3.0.4, wraps the wakers in
    `AssertUnwindSafe` in two crates, adds a browser timer test, bumps
    libp2p-webtransport-websys to 0.6.1), that it is open and waits for a gloo-timers release, and
    that taking its release will move this crate's own wasm-bindgen pins. Read from the public
    pages; nothing posted.
  - **`ci/test-download.sh`** (132 cases, 122 before). D1: the failure dump prints the first line of
    `curl --version`, and the header says that the `late` case needs a curl with the Retry-After
    check. D3: the cases run under `/usr/bin/timeout`, else the `timeout` on PATH, as
    `ci/mutants.sh` finds it; `failed_by_itself` no longer counts the statuses of timeout(1)
    itself (125, 126, 127, 137, besides 124) as the helper's failure, so a missing timeout (127)
    cannot pass the `late` check. D2 is the fix of the entry below ("each fail at least one case"),
    which also gains the D1 sentence. The sentences about curl's Retry-After say what its source
    (`tool_operate.c` at the release tags) shows: curl 7.74.0 honours a Retry-After and sleeps the
    whole 100000 s, and the check against `--retry-max-time` came with 7.79.0. That bears on
    `ci/download.sh` too: on a curl before 7.79.0 a long Retry-After is waited out, not cut at the
    retry window (ubuntu-latest's 8.5.0 has the check), so its 878 s bound needs 7.79.0 or later;
    the header of `ci/download.sh` says so (the minimum for its options stays 7.71.0).
  - **Without the change** (mutants of the new test script, made by hand): the dump without the
    curl line fails the dump case; the old `failed_by_itself` fails four cases (125, 126, 127, 137);
    no fallback for timeout(1) fails two; a missing timeout fails 17 cases, and with the old
    predicate that missing timeout passes the two `late` cases that look at the status and the
    file (the request count still fails). The stale-binary case: with the index of ebb6a67^ put
    back in the tree and the engine binaries of 598e58a in `target/llvm-cov-target`, the index
    measurement fails (75.10% of lines, `views.rs` 52.23%, `write.rs` 45.41%) and passes after
    `cargo llvm-cov clean --workspace` (97.66%, 98.47% and 97.60%); the index was restored
    afterwards. A second stale state, made with engine's tests built against an index that held a
    harmless probe (an unused function and 40 comment lines, then removed): the index measurement
    alone fails without the clean (76.49%, exit 1), and `./gate.sh` run from that state passes
    (1236 s, the index at 97.80%).
  - **Review round** (two reviews of the first commit, both clean; the reviewers are named at
    landing). The nits taken are documentation only, with no change in behaviour. The header of
    `ci/download.sh` says that its 878 s bound needs curl 7.79.0 or later, because an older curl
    waits out a long Retry-After, that 7.71.0 stays the minimum for the options themselves, and that
    CI's curl (8.5.0) and the development machine's (8.18.0) are both past 7.79.0. The `limits.rs`
    doc no longer says that TM-22 states the bound that item requires, since TM-22 gives only the
    figure of about 2.9 GiB and "then bound it"; "all required before 1.0" stays, being the owner's
    decision of 2026-11-08, and main's TM-22 still says "proposed ... pending the owner's word"
    until wip/spec-1103, which lands next, rewrites it to "Required before 1.0 (owner, 2026-11-08)".
    `CONTRIBUTING.md` says that the `== <command>` lines start after group 1, the pins, which print
    none. `vendor/README.md` says "the owner's fork" and not the account's name, "bumps
    libp2p-webtransport-websys to 0.6.1", and "gets the fix for the `panic = "unwind"` build", and
    names ranile/gloo#587, the open pull request of 2026-11-08 that prepares the gloo release (read
    from the public page; nothing posted). A confirm review then found the README's claim that
    gloo-timers 0.4 is the line with the `panic = "unwind"` fix false, and the README now says what
    the public pages show (read with `gh`; nothing posted): futures-timer 3.0.4 and its master
    require gloo-timers 0.4.0, which was released on 2026-03-25 without the fix (ranile/gloo#562,
    merged on 2026-05-16, in no release), and #587 sets gloo-timers to 0.5.0, which that
    requirement does not accept, so a gloo-timers release alone does not fix the emscripten build
    through futures-timer 3.0.4 and it also needs a futures-timer release that takes gloo-timers
    0.5 or a gloo-timers 0.4.x patch. The `ci/test-download.sh` bullet above is reworded and
    rewrapped to 100 columns.
  - Reviewed 2026-11-09 by a2cd936bf7be06fdb (first review: clean, five nits, taken) and
    a31bae1614414701a (second review: clean, six nits, taken); confirm ab9f3d48c7a239370: blocked by
    one (the README's gloo-timers sentence), now fixed; confirm a426db48eecc921dc: clean. Docs, gate
    wiring and one test script, so no security pass. Author a7178481ac635223c; fixes by
    a87237740ed18dcb4 and a43b116d2c83d809a. Landed as one squashed commit.

- Retry the CI scripts' downloads, so that a short outage at a download host does not turn `main`
  red (the owner's approval of 2026-11-09: "Go ahead with the download retry change"). The push of
  ebb6a67 failed CI run 42568260092: the gitleaks job's `ci/gitleaks-install.sh` got `curl: (22) The
  requested URL returned error: 504` from GitHub's release download, on three tries (05:36, 05:48
  and 05:49 UTC on 2026-11-09), and passed on a manual rerun at 12:19. The code was never at fault.
  - **The change.** `ci/download.sh <https URL> <output file>` holds the curl options of a
    download. `ci/gitleaks-install.sh` (the `gitleaks` job of `ci.yml`, and the local setup of
    `gate.sh`'s gitleaks step) and `ci/chrome-install.sh` (two zips, the nightly
    `webtransport-chrome` job) call it where they called curl; the SHA-256 checks after the
    downloads are as they were. The helper keeps `--proto '=https' --tlsv1.2` and `-fSL`, with
    `--no-progress-meter` in place of `-s` so that the CI log shows the notice of each retry, and
    adds `--retry 8 --retry-all-errors` (curl's own backoff, 1 s then 2, 4 and on to 128, 255 s in
    all, after any failure: a timeout, an HTTP error of any kind, a connection refused, reset or
    closed with no reply, a failed TLS handshake, a body cut off), `--retry-connrefused`,
    `--connect-timeout 30`, `--max-time 300` and `--retry-max-time 450`. It needs curl 7.71.0
    (2020): Ubuntu 22.04 has 7.81.0 and 24.04 has 8.5.0 (neither was run), the development machine
    8.18.0; `ci/test-download.sh` also passes with 8.15.0 and 8.21.0 (the Flatpak runtimes' curls).
    The notice of a retry is worded "Will retry in N seconds" by 8.15.0 and 8.18.0 and "Retrying in
    N seconds" by 8.21.0, and the test accepts both.
  - **The cost.** curl cannot tell a failure that no retry cures from an outage (a host in trouble
    answers 404 and refuses connections too), so `--retry-all-errors` makes every permanent failure
    be reported after the 255 s of backoff (about four minutes) instead of at once: a 404 from a
    wrong pin, a connection refused for good, an output file that cannot be written (curl's exit
    status 23, retried all the same: measured with 8.18.0 and 8.21.0). That is acceptable: the job
    fails either way, so what is lost is four minutes of a run that was going to be red, and the
    878 s bound below still holds; a wrong pin comes only with a commit that changes a pin, and
    such a commit is reviewed anyway. The plain `--retry` would have left out a connection reset
    or closed with no reply, a failed TLS handshake and a body cut off, which is what a download
    host in trouble often does.
  - **Time.** `--max-time 300`: the largest download, Chrome for Testing 156.0.8078.80's
    `chrome-linux64.zip`, is 201,329,937 bytes (a HEAD request; `chromedriver-linux64.zip` is
    11,898,387), which needs 0.67 MB/s (the 180 s first chosen needed 1.12 MB/s and cut a slow
    download that was progressing). A stuck download ends in 878 s (14.6 minutes) at most: the
    window (450 s), the longest wait (128 s) and one more try (300 s). The Chrome job's two take
    29.3 of its 45 minutes. The `gitleaks` job had no `timeout-minutes` (the default is 6 hours,
    which a curl that sleeps a whole Retry-After could use up); it has 25: the 14.6 minutes and 10
    for the checkout and the scans (about 6 s of scanning here). The `ci-scripts` job, which runs
    the test of the helper, had none either; it has 10: its steps take about 10 s together here,
    and the real-curl cases of the test end after 60 s at most (below).
  - **What it leaves behind.** The helper removes the output file before curl runs, and again when
    curl gives up (curl leaves the part it got: 5946 bytes after a body cut off), and fails (exit 1,
    naming the URL) when curl exits 0 and the file is missing or empty; it removes the file with
    `rm -f --`, so that an output file named like an option goes too. That happens: curl 8.15.0,
    8.18.0 and 8.21.0 exit 0 with no file when a 503 carries a Retry-After that would end after the
    window ("The Retry-After: time would make this command line exceed the maximum allowed time for
    retries"; measured). A retry cannot leave a bad file that passes: curl truncates the one `-o`
    file before each try (measured: a body cut off after 5946 of 11892 bytes, then a whole one,
    left the 11892-byte file, not 17838), nothing resumes with `-C`, and the SHA-256 check passes
    only for the pinned file whatever the file holds.
  - **What it leaves out.** An outage longer than about four minutes: the 504 came back on the
    three tries of 2026-11-09 over 13 minutes, so this might not have kept that run green. Raising
    `--retry` and `--retry-max-time` in `ci/download.sh` is the knob; the two jobs' timeouts would
    then need raising too, and `ci/test-download.sh` fails until they are.
  - **Other downloads, checked and not changed.** No other download changes. `cargo install`: cargo
    retries 3 times (cargo 1.99.1 asked a registry that answered 504 four times in all), so a
    longer outage can still fail it. `taiki-e/install-action` v2.88.0: its `main.sh` tries each
    download 10 times and gives curl `--retry 10` (read through a web summary). The Codecov upload:
    its job has `continue-on-error: true`. Semgrep 1.182.0 fetches the rules of `semgrep scan
    --config p/rust` with 3 retries (up to 4 attempts) on HTTP 413, 429 and 5xx, and
    `dtolnay/rust-toolchain` runs rustup, which retries a download `RUSTUP_MAX_RETRIES` times (both
    from the reviews). The advisory-db fetch from github.com (the incident's host) by `cargo deny`
    and `cargo audit`, and `cargo vet`'s imports from raw.githubusercontent.com: not checked (a
    search of cargo-deny 0.20.2's, cargo-audit 0.22.2's and cargo-vet 0.10.3's sources for "retry"
    finds none; the libraries under them were not read). The Semgrep container image pull: not
    checked. `bootstrap.sh`, outside this repository, is a one-time local setup.
  - **The check and the tests.** `ci/check-downloads.sh` fails on a line that calls `curl` or `wget`
    in `ci/*.sh` (not `ci/download.sh` or `ci/test-*.sh`), `gate.sh` or a workflow, comment lines
    aside, so that a future download script uses the helper. `ci/test-download.sh` (122 cases,
    about 2 s; needs python3 and openssl) runs: the options `download.sh` gives a stand-in curl;
    the longest stuck download against the `timeout-minutes` it reads from `ci.yml` and
    `nightly.yml`, and that the `ci-scripts` job of `ci.yml` has one (at most an hour, and enough
    for the 60 s below with 5 minutes to spare); what the helper leaves when the stand-in fails
    after writing part of a file, exits 0 with no file or an empty one, or finds a file from
    before, also for an output file named `-out` (each of the three removals needs the `--`); the
    two install scripts on the stand-in (their pinned URLs, `--retry`, and each SHA-256 check still
    refusing another file); the real curl against an HTTPS server on 127.0.0.1, where a 504, a
    404, a body cut off half way and a connection closed with no reply are each retried and the
    file arrives whole (a plain curl is shown to keep the cut-off part, so the whole file is not
    the part and the file appended), with the notice of the retry in the log, and a 503 with
    `Retry-After: 100000` is a failure with no file after one request; and `check-downloads.sh` on
    this repository and on trees made for each case. The six real-curl cases run at the same
    time, so the one second that curl waits before a retry is spent once and nothing in the test
    sleeps; a failure no retry cures, such as a 404 for 255 s, is tested on the stand-in. Each
    real-curl case runs under `/usr/bin/timeout 60` (by full path, as `ci/webtransport-chrome.sh`
    does), so that a curl without the Retry-After check, which would sleep the 100000 s, fails the
    case instead of holding the job; the 503 must fail by itself, not by the timeout's kill
    (status 124), and the test checks that predicate on made-up statuses. The `late` case needs a
    curl that honours a Retry-After by giving up when it would end after `--retry-max-time`, which
    curl has done since 7.79.0 (read from `tool_operate.c` at the release tags, not run: Ubuntu
    22.04's 7.81.0 and 24.04's 8.5.0 have it; 8.15.0, 8.18.0 and 8.21.0 were run); curl 7.74.0
    (Debian 11) sleeps the whole Retry-After, so there the timeout kills the case and it fails. The
    test's failure dump names the curl for that reason.
  - **Without the change.** The check fails on the install scripts of ebb6a67 (their two `curl`
    lines); with the first version of this change (an `exec curl` with `--retry 8
    --retry-connrefused`, no `--retry-all-errors`, no `timeout-minutes` on the `gitleaks` or
    `ci-scripts` job), 32 of the 122 cases fail. 27 mutants of the helper and of the two jobs'
    timeouts, made by hand against the previous version of the tests, each failed a case; nine
    more, made against this version, each fail at least one case: the old `'Will retry'` check on
    curl 8.21.0; a curl that asks once for the 503 and then sleeps (under a 3 s limit); the
    `ci-scripts` job with no `timeout-minutes`, with 5 and with 360; each of the three `rm -f --`
    without `--`; and the 503's check accepting the status 124. With that sleeping curl and the
    503's old check (a failure of any kind, which a kill by the timeout also is), no case fails:
    the hang would go unseen. `gate.sh` and the `ci-scripts` job of `ci.yml` run both scripts;
    `CONTRIBUTING.md` names python3 and openssl and says where the helper is.
  - **The confirm review's round** (2026-11-09; every ruling taken, the coordinator's squash at
    landing aside). The review found that the log case failed on curl 8.21.0, whose retry notice
    reads "Retrying in" (the test now accepts both wordings); that the 503 case could hang for
    hours on a curl without the Retry-After check, under a job with the 6-hour default (each
    real-curl case now has a 60 s limit, the 503 must fail by itself, and the `ci-scripts` job has
    `timeout-minutes: 10`); and four smaller points: the cost now names every permanent failure,
    the wording of the other downloads is exact (Semgrep: 3 retries), the Chrome zip's size in
    `ci/test-download.sh` is in the pin-bump steps of `ci/chrome-install.sh`, and the helper's `rm`
    takes `--`.
  - Reviewed 2026-11-09 by a7edf7cec93922127 (first review, on 9e9eceb: blocked by two, now
    fixed) and a3433b29f0e90ae60 (second review: one should-fix and three nits, now fixed); confirm
    aa61d66f62df8b7b8 on 3dc2794: blocked by two, now fixed; re-confirm aca11784548bdc137 on
    04a5b18: clean, with three nits left as follow-ups. CI scripts only, no keys, protocol, paths
    or API, so no security pass. Authors a480f78b3db51b6a5 and af6667d10501e6430; fixes by
    a2975bcf2abdd691c and a77a3871a3985c011. Landed as one squashed commit.

- Cover every identical concurrent head when writing over a path (the identical-heads bug, found
  and confirmed on 2026-11-08): when two devices wrote the same bytes at one path apart, the next
  save, delete, rename or tree delete covered one of the two versions, and the other stayed on every
  device. A folder linked on two devices that already hold it makes every file such a pair.
  - **The bug.** Two heads whose content does not differ (two files with the same `plain_hashes`,
    two directories, two tombstones) show as one file with no conflict copy, so the engine names
    one of them, the first in display order, as the path's base (4.4, "Bases"; `apply_path` in
    `crates/engine/src/sync/disk.rs`). `Txn::s_at` built `S` from the bases alone, and
    `Txn::plan_tree_delete` its join, so a write covered that head only, and every other twin stayed
    live on every device: after an edit, a conflict copy of the old content; after a delete or a
    rename, the old file back at the path; after a tree delete of two identical directories, the
    directory back; after a new version over two tombstones, a second head. The editing device's own
    twin was left whenever the other's sat at the path. The spec contradicted itself: section 9
    ("Two devices create the same file independently") and 4.4's "the write covers every head it
    holds" said the next save covers both, while 4.4 "Bases" kept one base per path.
  - **The fix**, in the index alone, with no store-format or engine change. A base's **twins** are
    the other live heads at its path that hold its content and are concurrent with it
    (`write::twin_of`): their content does not differ (`views::same_content`: two tombstones
    whatever their kinds, two directories, two files with the same plaintext hashes; never a tree
    delete), their vector does not cover the base's dot, for the base at the path itself they come
    after it in display order, and none is the first head in display order at the path, the record
    the engine puts there (`Txn::twins_at`). `S` (`Txn::s_at`, `Txn::twins_at`,
    `Txn::first_in_s_order`) is the bases and their twins, at most 32: the bases first, then the
    twins, the device's own records first within each, then display order, so a twin never takes a
    place a base would have had. The twins are named in `replaces` like any member of `S`. A tree
    delete (`Txn::plan_tree_delete`, `Txn::twins_beneath`) joins the twins of the bases at or
    beneath its directory with the bases; it names the first 32 of the bases and twins at its own
    tag, in `S`'s order, their devices mandatory in its prune, so that its vector covers every
    record it names; and it writes the tombstone that follows it for a twin its pruned vector
    misses, as for a base.
  - **The reviews' round** (2026-11-08: two reviewers and the security pass, every ruling taken).
    - *What a twin is not* (R2-1, the security review's F1, R1-3). Twins were first every head of a
      base's content. A later version of the base that changed only its mode or time, held but not
      yet on the disk, was then a twin, and a local edit or delete covered it with no conflict copy
      and nothing shown, against 4.7 item 6 ("never one over the other"); so was a concurrent
      version of the content that comes first in display order, which the engine has yet to put at
      the path, its time and mode not on the disk. Now a twin is concurrent with its base (its
      vector does not cover the base's dot, for a conflict copy's base too) and, for the base at the
      path, comes after it in display order. Neither condition implies the other (a concurrent
      version with a later `mtime_ns` comes first; a later version with the same `mtime_ns` can come
      after), so both are kept. Every case the fix was made for is one of concurrent twins, and all
      still pass. Between concurrent twins, times and modes are still not compared (below, "For
      phase 1").
    - *The order of `S`* (F5). With the device's own records first, 32 records signed under its own
      device ID with its base's content (a cloned image, or a write holder writing under its ID,
      "Why it is safe" 8(b)) took every place of `S`, and a save did not cover the version it was
      written from, another device's. The bases now come first.
    - *A tree delete's names at its own path* (R1-1, R2-3, F2, F4). It named the bases there, then
      their twins up to 32, and pruned its vector with no mandatory entry, two choices made apart:
      with 40 identical directories it named records its vector missed (eight in the first author's
      fixture, against 4.4 "Names" and "Why it is safe" 10), or left records neither named nor
      covered (seven or eight in the reviewers' fixtures, the directory back, unstated). Now its
      names are a subset of what its vector covers. R1-1's proposal, to name first the twins the
      vector misses, would have named records the vector does not cover, so the security review's
      rule was taken. The residual, stated in 4.4 ("A tree delete"), section 9's list,
      `threat-model.md` §3.6 and TM-43: records at the directory's own path past the 32 named, of
      more devices than the vector holds, stay heads, the directory (or a file at its name and its
      conflict copies) back, until the next delete there takes them (40 identical directories: eight
      left, whatever the display order).
    - *A directory with 64 or more conflict copies at its path could not be deleted* (R1's finding
      outside the fix, folded in because the same cap fixes it). A tree delete named every base at
      its own tag with no cap, and past `MAX_REPLACES` the write was refused (`Draft(Replaces(72))`
      with 71 copies), so the directory could not be deleted from that device. Its names there are
      now at most 32; the copies past them that its vector does not cover stay heads until the next
      delete there. Regression test
      `a_directory_with_64_or_more_conflict_copies_at_its_path_can_be_deleted`.
    - *A folder delete over a file still arriving* (R2-2, F3, R1-4; the owner's decision of
      2026-11-08, "Delete it, archive (Recommended)"). A tree delete's join takes the dot and vector
      of a base or twin beneath its directory, which can cover an earlier version of the same device
      at another path beneath it that the deleter holds but has not yet put on its disk. Before the
      fix this happened through bases; the fix made it happen through twins too, whatever the
      display order. The owner chose the spec's option: a folder delete takes what is inside it, a
      file still on its way included, which goes to the archive on the device that had it (TM-35).
      "Why it is safe" 8(a) now covers versions held but not yet on the disk, reached through a
      base's or twin's dot or vector; 9 has that exception for tree deletes; section 9's list,
      TM-41's residuals and property (k)'s text (with the later-record clause its test checks) say
      so; and `threat-model.md` §3.6 "forge twins" gives the two reasons a forged twin gains nothing
      (a forged version with a later `mtime_ns` becomes the base anyway; a write holder can sign any
      tree delete). No code change.
    - *Wording* (R1-2, R2-4, F6): the rename rule's `S` (the bases at each path and their twins);
      "Why it is safe" 3 and 10; 8(b)'s "clone", so that "twin" has one meaning in the spec;
      section 6 (the twin rule never changes within major 1); 4.7 item 6; the comments of
      `heads.rs`'s lost update and of `crates/engine/src/rules.rs`'s conflict test; and a dated note
      in `gates/phase-0.md`'s TM-41 row.
  - **The confirm review** (2026-11-08, with a security pass; every ruling taken).
    - *A twin is never the first head* (C1). The display-order condition compared a twin with its
      base, not with the path's heads, so it kept the head the engine has yet to put at the path out
      of the twins only while the base at the path was itself the first head. Once a later version
      still arriving had replaced the base (B's Y over A's X, other content or a mode change of X's
      bytes), a concurrent record of X's bytes that sorts after X but first among the heads (C's Z)
      counted as X's twin, and A's edit covered it, its mode and time gone with no conflict copy;
      so did a record of a conflict copy's content first in display order, a copy's base having
      twins whatever the display order. No bytes were lost (a twin's are a base's, on the disk),
      and peers converged. Now `Txn::twins_at` also leaves out the first head in display order at
      the tag (never a tree delete), the record the engine puts at the path, which counts only once
      it is a base; both earlier conditions are kept, and a tree delete finds the twins beneath it
      through `twins_at` too. 4.4 "Bases" says so ("a twin is never the first head in display order
      at its path"), and "Why it is safe" 9, 4.7 item 6, sections 6, 8 item 7 and 9, TM-41,
      `threat-model.md` §3.6's "forge twins", the TM-41 note in `gates/phase-0.md`, `on_disk` in
      the property tests and the doc comments of the index's `write.rs` and `lib.rs` and the
      engine's `write.rs` follow. Section 9's "one the device has yet to put on its disk" now reads
      "at the path", as 4.4 and 4.7 item 6 say (below, "For phase 1": a twin of a conflict copy's
      base that is not the first head is still covered, though the engine would write it beside
      the path as a copy of its own).
    - *Wording* (C2, C3). Section 6 and the TM-41 note in `gates/phase-0.md` give the display-order
      condition for the base at the path alone. Section 9's list, §3.6 and TM-43 give the tree
      delete's residual as records at the directory's own path from more than 32 devices, identical
      directories or conflict copies (the reviewer deleted a directory with 63 file conflict copies
      at its path from 63 devices: 32 named, `d` back as a file with 31 copies, alike on the
      deleter, a read holder and a sealed holder), and TM-43 says "None ever lets…".
    - *Tests* (C1, C4), each named after the behaviour, the reviewer's three probes among them; the
      first five fail on 7105352 (its `write.rs` with these tests) and pass after:
      `a_twin_first_among_the_heads_once_its_base_is_replaced_by_other_content_stays_a_conflict`
      and `..._by_its_content_stays_a_conflict` (the edit named X and Z, and Z was gone on every
      device; now X alone, and Z and Y are conflict copies on A, B and C),
      `a_twin_of_a_conflict_copy_first_in_display_order_stays_a_conflict` (the edit named T with X
      and the copy; now T is a conflict copy on A, C and E),
      `a_tree_delete_leaves_a_twin_first_among_the_heads_beneath_it_once_its_base_is_replaced` (the
      tree delete's join took Z's dot), and in `properties.rs`
      `a_write_beside_a_twin_first_among_the_heads_leaves_it_k`, a fixed history in which (k)
      failed, `on_disk` stating the first-head rule apart from the index's;
      `a_concurrent_record_of_the_bases_content_ahead_of_it_but_not_first_stays_a_conflict` passes
      before and after: it pins the display-order condition, which the first-head rule made
      redundant in the round's test of it. `properties.rs`'s 114-character doc line is wrapped, and
      `twins()` now makes the directory again over its twins in three of four histories that make
      directories, by the device the history picks (before, only their tree-delete quarter met
      directory twins): over 200 fixed-seed cases of `histories_keep_claims_a_b_c_f_j_k`, the cases
      with a write made with a twin on the disk where it wrote went from 58 to 79 (93 such writes
      to 123).
  - **Past 32.** Twins compete for `S`'s 32 places. With 40 identical heads, a write covers 32, and
    those last in `S`'s order stay heads: after an edit, conflict copies of the old content; after a
    delete, the file back at the path; until the next write there, made with them on the disk,
    covers them. Nothing is lost; 40 twins take two writes (tested below). The same holds for the
    tombstone a tree delete writes at a path whose twin its pruned vector misses, and for a tree
    delete's own path (above).
  - **The spec.** `spec/protocol.md` 4.4: "Names"; "Bases" (the twins defined, and why); "The vector
    and names of a new record" (`S` is the bases at `p` and their twins, the bases first; what
    happens past 32; pruning; the rename; the tree delete's join, names, mandatory entries, residual
    and tombstones); "A newer release's version"; "Heads" ("a write covers every head whose content
    is on its writer's disk, at the path, as a conflict copy, or as a twin of either, up to 32");
    "Why it is safe" 2, 3, 8, 9 ("A local write never replaces a version whose content its device
    has not had on its disk, short of 8a for a tree delete") and 10. 4.7 item 6 ("The current
    version", "Tree deletes", "Names and cleanups"). Section 6: the twin rule is fixed for major 1.
    Section 8 item 7: the twins vectors and property (k). Section 9's list gains records at a
    directory's own path from more than 32 devices and the file still arriving, and its rejected
    alternatives the bases-only rule. Section 9 "Two devices create the same file independently" is
    unchanged: its "The next save covers both" now holds. `spec/threat-model.md` §3.6: "flood heads"
    with twins and the tree delete's residual, and "forge twins"; TM-41 (an edit is built from the
    versions on the disk and their twins; the residual of 8(a)); TM-43 (the tree delete's names).
  - **Tests.** The 14 tests that confirmed the bug, written first and committed with the fix, each
    named after the behaviour: 8 at the record level in `crates/index/src/tests/identical.rs` (two
    and three devices; the editor's own twin at the path or the other's; equal and different
    `mtime_ns`; a delete; a rename; two directories under a tree delete; two tombstones under a new
    version) and 6 in `crates/sim/src/scenarios/engine/identical.rs` (real engines apart until 10 s,
    the twins written at 1 s, member 1's at 3 s in two variants, a probe at 45 s that every member
    shows every twin and no copy, the change at 50 s, then the full oracle and a check that only the
    change is left; five seeds each). Before the fix all 14 failed (`cargo nextest run --run-ignored
    ignored-only`: 8 of 8 in the index, each on every editor; 6 of 6 in the simulator, every seed
    passing the oracle and failing the check: every member agreed on the wrong result); after it all
    pass. New with the fix: 40 twins and a conflict copy under a save by the device whose own twin
    is last in display order (`S` its two bases, then its own twin, then the next 29 twins; nine
    left, conflict copies of the old content; the next save covers them), and 40 twins under a
    delete (32 covered, the file back, the next delete covers the rest, and a save then covers the
    two tombstones, twins); a tree delete whose vector, pruned past 32 device IDs, keeps a base and
    misses its twin (the tombstone after it, at the twin's path, covers it; a path whose twins the
    vector covers gets none); a tree delete held beside a tombstone base, no twin of it (the
    directory made again names the tombstone alone, and the tree delete stays held); the vector
    `twins` in `crates/index/tests/vectors/heads.json` (entries added; none of the other vectors
    changed). The seven simulator runs are gate scenarios, `engine-identical-edit-0`, `-edit-1`,
    `-later-edits`, `-earlier-edits`, `-three`, `-delete` and `-directories`, in `engine::ALL`,
    `scenarios::engine_scenarios` and `crates/engine/tests/converge.rs`: about 0.1 s each over the
    gate's five seeds.
  - **Tests of the reviews' round**, in `identical.rs`, each named after the behaviour, the
    reviewers' probes among them. Eleven fail on the code before the round (575ad50's `write.rs`
    with these tests: 11 of the 16 new or corrected tests fail, and so do property (k) and
    `vector_heads`), and pass after it:
    `a_later_version_that_changed_only_the_mode_at_the_same_mtime_stays_a_conflict`,
    `..._at_a_later_mtime_stays_a_conflict` (R2-1's scenario and P3: both heads on both devices; one
    head before), `..._at_an_earlier_mtime_stays_a_conflict` (after its base in display order, so
    concurrency alone tells it from a twin),
    `..._outlives_a_delete_made_before_it_reached_the_disk`,
    `a_concurrent_twin_the_engine_has_yet_to_put_at_the_path_stays_a_conflict` (the second
    condition alone: it fails with the first condition only),
    `a_later_version_of_a_conflict_copy_with_its_content_stays_beside_an_edit`,
    `records_under_the_writers_own_id_cannot_push_its_base_out_of_s` (P6),
    `a_tree_delete_names_at_its_own_path_only_what_its_vector_covers` (P7, over the first author's
    fixture, R1-1's mirrored one and R2-3's, P1's),
    `forty_identical_directories_a_tree_delete_names_its_own_twin_first` (its doc comment and
    assertions corrected: 32 go, eight are left, the next delete takes them),
    `forty_identical_directories_in_any_display_order_go_within_two_tree_deletes` (R1-1's and
    R2-3's fixtures) and `a_directory_with_64_or_more_conflict_copies_at_its_path_can_be_deleted`.
    Five pin what the rulings keep and pass before and after:
    `a_folder_delete_takes_a_file_beneath_still_arriving_through_a_twins_dot` and
    `..._through_a_bases_dot` (P2, P2b and R2-2's probe: the file goes, on the deleter and on the
    device that had it),
    `a_twin_arriving_after_the_write_stays_a_head_a_conflict_copy_of_the_old_content` (P4, on all
    three devices), `a_tombstone_beside_a_live_base_and_its_twin_is_no_twin_and_stays_a_head` and
    `three_twins_and_two_identical_conflict_copies_go_with_one_save` (P5), and in `rules.rs`, for
    two mutants of `plan_tree_delete`'s unchanged lines that survived both rounds,
    `a_tree_delete_names_the_shared_faults_at_its_tag_up_to_max_replaces_and_its_cleanup_the_rest`
    and `a_tree_deletes_cleanup_names_no_base_kept_outside_its_directory`. The vector `twins`
    gains a later version of the base's content under a save and 40 directories under two tree
    deletes, and its 40-twin `S` is listed in the new order. The property tests (R1-5) now meet
    twins: files take one of three contents, histories make directories at `d` and `d/e`, write
    while a version of the path is still arriving (`Op::Edit`), and a third of them start with
    every writer writing one path apart (`twins()`); `on_disk` states the new twin rule apart from
    the index's. Over 200 fixed-seed cases of `histories_keep_claims_a_b_c_f_j_k`, the cases with a
    write made with a twin on the disk where it wrote went from one to 58 (93 such writes), and with
    575ad50's `write.rs` property (k) now fails at the gate's 12 cases (a later version of a base's
    content covered); `a_history_of_twins_meets_them_c_k` pins a fixed history. The index suite
    takes about 9 s, 1 s more.
  - **Mutants** (cargo-mutants 27.1.0, `-p licketysync-index -F` on the changed functions, under
    `ci/mutants.sh`'s caps). With the fix: the first run left eight survivors in new code, which
    three tests added since kill (`same_content`'s `||` made `&&`, the order of the twins a tree
    delete named at its own tag, and the tombstone for a twin its pruned vector misses); the second,
    33 caught, 11 unviable, 6 missed, none in new code. With the reviews' round, on `twin_of`,
    `s_at`, `first_in_s_order`, `twins_at`, `twins_beneath`, `plan_tree_delete` and
    `same_content`: 55 mutants, 34 caught, 15 unviable (a body replaced by a constant leaves its
    arguments unused, which the workspace's `--deny=unused` refuses), 6 missed, none in new or
    changed lines. Two are in lines of `plan_tree_delete` that neither round changed (`<` made
    `<=` where shared writer faults fill `replaces` up to `MAX_REPLACES`, and `&&` made `||` in the
    filter of the bases kept only as bases that its cleanup names); the two `rules.rs` tests above
    kill them (checked by applying each by hand: its test fails). Four delete a field of a struct
    update in other functions (`Txn::renumber`, `open`, `Txn::sign_and_hold`, `Txn::end_round`),
    which cargo-mutants lists whatever `-F` says; they are the weekly run's to judge. `twin_of`
    compares display ranks with `cmp(..).is_lt()`, since `<` made `<=` would be an equivalent
    mutant: two records' ranks are never equal, the record hash ending them. Taking out either of
    `twin_of`'s last two conditions by hand fails tests of its own (the concurrency: the mode change
    at an earlier `mtime_ns`, the delete and the conflict copy; the display order: the concurrent
    twin not yet at the path, and property (k); since the confirm review, whose first-head rule
    keeps that twin out too, the record ahead of the base but not first, and property (k)). With
    the confirm review, on `twin_of`, `twins_at` (the one function changed) and `twins_beneath`, in
    6 minutes: 14 mutants in those three, 8 caught and 6 unviable, none missed, the new lines' among
    the caught (`!` deleted in `!m.tree`, which seeks the first head among the tree deletes, and
    `!=` made `==` in `Some(*h) != first`); and 13 struct-update field deletions in other functions,
    which cargo-mutants lists whatever `-F` and `-E` say: 7 caught, 2 unviable, and missed the four
    above. Taking out the first-head rule by hand fails the five tests of C1 that fail on 7105352.
  - **For phase 1** (R1-3 as R2-1 rewords it, and R1-6):
    - *Modes between concurrent twins.* Twins compare no time or mode: of concurrent twins that
      differ in mode, one is on the disk (at the path, the first in display order; beside it, the
      conflict copy the engine wrote), and a write covers the others with no conflict copy, a twin
      of a conflict copy's base that the engine would have written beside the path as a copy of its
      own included. Phase 0's engine writes mode 0 everywhere, so nothing shows today. Once modes
      are recorded, is that right, or should a twin that differs in mode be a conflict copy? Before
      1.0 it can change; after, section 6 makes it a new major.
    - *Cost.* Finding twins compares every applied record at a tag with every base there, plaintext
      hash by plaintext hash: heads times bases times chunks per write, and per path beneath a tree
      delete. Write holders control both counts (flood heads; a conflict copy on the disk per head
      of other content). Bound it with TM-22's phase 1 bounds, for example by comparing against the
      distinct contents of the bases.
  - **A follow-up, not in this change.** Identical conflict copies of a third head still make one
    copy file each, with the same bytes: two twins concurrent with a head of other content that sits
    at the path are two conflict copies of one content (the three-twin test showed it before the
    fix, and the twins left past 32 after an edit are such copies). Showing them as one copy is a
    change to the views and the engine's copy names.
  - Reviewed 2026-11-08 by a180da590c6353049 (first review: blocked by two, now fixed),
    a85f0a2b23241ead1 (second review: blocked by two, now fixed) and a2dd99da5bd378a17 (security:
    blocked by six, now fixed); confirm with the security pass af561b996e0e3da72: blocked by C1,
    then clean. Author ab584c2f42dfde15b (tests by a5e7cfc66aa437aee); fixes by a87514402d93f94f2
    and a5383171d1976046e. (Filled in 2026-11-09 from the commit message of ebb6a67.)

- Spike B's follow-ups, from its final confirm review (2026-11-04) and the reviews of this change: a
  test that holds `ci/check-wasm-bindgen.sh`'s lock branch; TM-22's residual (e) with its
  pre-authentication byte figure, which is not a memory bound, and the memory a connection can keep
  alive, with what that adds to phase 6 and, proposed, to phase 1; the browser crate's build output
  ignored; and the reviews' wording nits.
  - **The lock branch, tested.** No case of `ci/test-check-wasm-bindgen.sh` failed on the lock
    alone, so the branch that compares `browser-tests/webtransport/Cargo.lock` with
    `WASM_BINDGEN_CLI` could be deleted with every case passing. The new case, "the lock moved
    alone", keeps the pin and the exact requirement at 0.2.129 and moves the lock to 0.2.130. With
    the lock branch deleted from a scratch copy of the script, it fails and the other five pass.
    6 cases now, as spike B's entry says.
  - **TM-22 (e), the byte figure.** Before authentication a connection can hold one datagram more
    than quinn's 64 KiB buffer: `wtransport` 0.7.2 moves each into a channel for the connection, a
    `tokio` `mpsc` of capacity 1 (`src/driver/mod.rs`, line 54, and `accept_datagram`, lines
    531-558, which reserves the slot before it reads), and `net` never reads it. The residual says
    so, and that its "about 4.06 MiB" holds while that datagram is a packet within the 1 472 bytes
    quinn advertises, and "under 4.125 MiB" whatever its size: quinn-proto 0.11.19 refuses a
    DATAGRAM frame larger than its 64 KiB buffer (32 bytes of overhead counted with each,
    `src/connection/datagrams.rs` lines 138-141) but not a packet larger than it advertises, and
    quinn 0.11.12 reads each UDP datagram into 64 times that room where the system offers GRO, as
    Linux does (`src/endpoint.rs` lines 754-758). That is the byte figure, not a memory bound.
  - **TM-22 (e), the memory** (the security review's blocker). The residual now says that the figure
    bounds bytes, not memory, and why, by reading, not measured. quinn 0.11.12 copies each UDP read
    into one `BytesMut` and splits it into packets without copying (`src/endpoint.rs` lines
    798-800), and quinn-proto 0.11.19 keeps each frame's data as a `bytes` slice of it
    (`src/frame.rs`'s `take_len` and `take_remaining`), so one frame keeps the whole read alive: up
    to 94 208 bytes, quinn's buffer for a read (1 472 bytes times 64, the segment count quinn-udp
    0.5.16 gives on Linux, Android and Windows, `src/unix.rs` line 1026 and `src/windows.rs` line
    292; 1 472 bytes on macOS and iOS). Datagrams: up to 2 048 buffered, since an empty one that
    ends its packet is counted as 32 bytes and still holds its slice (`bytes` 1.12.1's `split_to`
    and `advance` leave an empty `Bytes` its reference), and the one in the channel: up to about
    184 MiB a connection. Streams: the over-allocation check counts each frame's packet payload
    (`src/connection/mod.rs` line 2755, `src/connection/streams/recv.rs` line 82), not the read it
    shares, and compacts otherwise only above 2 048 chunks (`src/connection/assembler.rs` lines
    204-216): up to about 184 MiB a stream, about 5.75 GiB across the listener's 32. The security
    review's figures (about 124 MiB, 4 GiB and, for the swarm's QUIC below, 2 GiB) took one-byte
    datagrams and reads of 64 KiB; these take quinn's own bounds. Phase 6's "WebTransport limits"
    adds the memory a connection keeps alive (datagrams read and dropped or copied, or their buffer
    made small; shared stream buffers counted or copied, upstream or in `net`; a memory test with
    one-byte frames in large UDP datagrams and in GRO batches) and, from the same review, the QUIC
    connection closed explicitly on every failure path and counted in place of sessions: a step that
    fails before Noise (`net`'s `webtransport::Listener::handshake`) drops the session without
    closing the connection, and the tasks `wtransport` spawns for the dialer's streams hold streams
    that keep it open (quinn's `ConnectionRef`).
  - **The swarm's QUIC, a proposed phase 1 item.** The same stream effect applies to spike A's QUIC
    (`libp2p-quic` 0.14: datagrams off, 16 bidirectional streams): by reading, up to about 2.9 GiB
    kept alive a connection against the 1 GiB process limit, which only refuses new connections.
    TM-22 says so where it says QUIC's windows are set, after residual (g), and records a phase 1
    item, "QUIC stream memory", beside residuals (a) to (c): confirm it with a raw quinn client that
    sends GSO batches, then bound it. The coordinator's routing, pending the owner's word.
  - **Ignored.** `.gitignore` has `/browser-tests/webtransport/target`, where `gate.sh`'s clippy on
    the browser crate, and cargo run by hand on that manifest, build (`ci/webtransport-chrome.sh`
    builds into the root `target/`), as it has `/fuzz/target` for the other workspace of its own;
    that directory showed as untracked after a gate run.
  - **Wording.** `CONTRIBUTING.md` says what `ci/check-wasm-bindgen.sh` checks: that the test
    crate's `Cargo.toml` requires exactly the CLI's version of `wasm-bindgen` and its `Cargo.lock`
    holds it (it said the check fails a change "that moves one without the other"). The comment on
    `ci.yml`'s `ci-scripts` job names every test the job runs, now with those of
    `ci/check-wasm-bindgen.sh`, `ci/check-vendored.sh` and `ci/check-pins.sh`, and the job's name
    is now "tests of the CI scripts and .gitattributes; the toolchain check" (safe: no check is
    required); `gate.sh` names the first two in its comment on the same steps and gives
    `ci/test-check-pins.sh` a comment of its own. TM-22 from residual (e) to the sentence after (g)
    is rewrapped to 100 columns, (f) and (g) in whitespace only. Spike B's entry has its three
    lines over 100 columns and five short ones (one in the "Found, not fixed" bullet) rewrapped,
    whitespace only: `git diff --word-diff` shows no word changed in it but the count above.
  - Reviewed 2026-11-08 by abc56f7cac6eb239a (first review, on 60f640a: approve once F1 is fixed;
    F1 and N2 to N4 fixed) and a949dd505aea3709c (security review, on 60f640a: blocked by S1, the
    figure bounds bytes, not memory; S1, S2, N1 and O1 fixed); final confirm with the security pass
    a6f8511513813ca67 on 5beecf9: clean. Author a7a54b360044f091c, from `brief-spikeB-followups.md`;
    fixes by aa03ae809aabe2946, from `rulings-spikeB-followups.md`.

- Fix the weekly Mutants workflow, red every week since it was added: in runs 40112234775
  (2026-10-24), 41225873013 (10-31) and 42399213062 (11-07, on b9f72b8) 3 to 5 of the 16 shards
  died 7 to 73 minutes in with "The runner has received a shutdown signal" (or "lost communication
  with the server"), in the middle of a mutant's tests, and uploaded nothing. Missed and timed-out
  mutants do not fail a shard (the 2026-10-22 rule, unchanged), so the dead runners were the only
  red.
  - **The cause, confirmed in every dead shard traced: mutants whose tests allocate without end**
    until the 16 GiB runner dies, a minute or three in, before the 300 s test limit can stop them.
    Each dead shard of 11-07 was named from its order (`cargo mutants --list` with the same
    selection) and the time since its last printed outcome: shard 2
    `crates/protocol/src/connection/mod.rs:934:13: replace < with == in Connection::has_room`, shard
    3 the same with `>`, shard 5 `crates/protocol/src/connection/index.rs:1079:12: delete ! in
    Connection::serve_frame`, shards 9 and 10 `crates/index/src/trie.rs:322:36: replace || with &&
    in build` and `322:14: replace <= with > in build` (every small or empty subtree built 16
    children wide down to the trie's full depth). Run locally under the caps below, each reached 6
    GiB in 56 to 70 s and was caught. On 10-31 shards 2 and 3 died on the same two `has_room`
    mutants; the other dead shards of 10-31 and 10-24 were not traced (two of 10-24's logs are
    gone).
  - **The caps.** `ci/mutants.sh` sets cargo's runner for the host's target
    (`CARGO_TARGET_<TRIPLE>_RUNNER`, the triple from `rustc -vV`) on any Linux host to `prlimit
    --data=6442450944 --fsize=1073741824 --core=0 --`, so cargo starts every test binary and
    doc-test (`--test-runtool`) under them, and no rustc or build script. Data 6 GiB (heap and other
    private writable memory): the unmutated tests of the four crates peak at 1.85 GiB, in engine's
    converge test, measured 2026-11-08 with 4, 8 and all 20 of its tests at once (1.65, 1.73 and
    1.85 GiB; index 0.28, protocol 0.18, keys 0.10), so three times that, leaving 10 GiB of the
    runner's 16. Not the address space: converge reserves 2.8 GiB of it with 4 test threads, 4.3
    with 8 and 5.3 with 20 (malloc's per-thread arenas), so it grows with the core count. File size
    1 GiB: the tests write only the test vectors (under 200 kB, when told to regenerate), and a test
    process's output goes straight into its mutant's log, which the cap so bounds. No core dump of a
    capped process. A test process past a cap dies (Rust aborts on a refused allocation; SIGXFSZ
    past the file cap), cargo test fails, and cargo-mutants 27.1.0 counts the mutant caught (its
    rule: a failed test phase is caught; checked in its source and with the five mutants above). The
    baseline runs under the same caps, so tests that outgrow them fail it (exit 4) rather than have
    every mutant counted caught, and the error then names the cap (below). prlimit is Linux only: on
    another host the log says the tests run uncapped and nothing more of caps, and the script fails
    if rustc cannot name the host.
  - **Caught by a cap, counted.** After the counts, and in the job summary, the log says "N of the
    caught were stopped by a cap (memory or file size)": the caught mutants whose log in
    `mutants.out/log/` carries a cap's sign. For the data cap, Rust's "memory allocation of <n>
    bytes failed"; for the file cap, SIGXFSZ, which cargo 1.99.1 gives by its number only for a
    test binary ("process didn't exit successfully: `...` (signal: 25)"; it names SIGABRT but not
    SIGXFSZ) and rustdoc 1.99.1 by its name as well for a doc-test ("Test executable failed
    (signal: 25 (SIGXFSZ))."), as a toy crate of the workspace's edition (2021, each doc-test its
    own process) showed under the caps on 2026-11-08. Only caught mutants count: not the logs of
    the missed, timed-out or unviable ones, nor the baseline's. The count is approximate both ways:
    Rust prints the same message for any refused allocation, cap or not, and a test process past a
    cap that fails some other way (a thread refused its stack) leaves no sign. A rising count means
    tests drifting toward a cap. On the logs of the local runs above it counts the five runaway
    mutants and none of the 13 caught by their assertions.
  - **The time limits.** cargo-mutants 27.1.0 gives an explicit `--timeout` to the unmutated tree's
    tests as well as to each mutant's (`Timeouts::for_baseline`, `src/timeouts.rs`) and, when they
    run past it, ends with exit 4 as if they had failed (shown on a toy crate: a 3 s test under
    `--timeout 2`). The `--timeout 300` of the runs to 11-07, whose baselines tested for 143 to
    295 s, was a slower runner or a few more tests from failing every shard. Now
    `--timeout-multiplier 2 --minimum-test-timeout 300` and no `--timeout`: the unmutated tree's
    tests have no limit but the budget, and each mutant's limit is twice their time, rounded up, at
    least 300 s (logged as "Auto-set test timeout to <n>s"; 300 to 590 s for 11-07's baselines).
    Twice: a mutant's tests are its own crate's, and the engine crate's, the slowest, took 89 to
    98 % of each shard's baseline on 11-07 (its surviving mutants), so an engine mutant may run its
    tests about twice as slowly as unmutated before it counts as timed out; the fixed 300 s gave
    them 1.13 times on the slowest runner (265 s in a baseline of 295). A mutant that hangs costs
    twice the baseline's test time (about 30 did on 11-07, across the 16 shards). At least 300 s: no
    mutant times out sooner than before. A shard whose budget runs out before any mutant is tested
    says that the unmutated tree's build and tests took it, or all but what the first mutant used
    (its build has no limit either); at worst, unmutated tests that hang cost every shard its whole
    180 minutes. Exit 4 can no longer mean that the unmutated tree timed out, and its error names a
    cap when the baseline's log carries the cap's sign ("...; a test process of the unmutated tree
    went past the data cap (6 GiB), set in ci/mutants.sh", or the file-size cap, or both).
  - **Diagnosable next time.** Every outcome is printed as it ends (`--caught --unviable` beside
    the missed and timed-out ones printed already), and before the run the log lists the shard's
    mutants, numbered in the order they are tested (folded on GitHub; the script fails if the
    listing does). The mutant a dead runner was testing is the one after the last outcome.
  - **Tests.** `ci/test-mutants.sh` (run by `gate.sh`, `ci.yml` and `mutants.yml`), 26 cases and 10
    checks after them now. A stand-in rustc names each case's host. The stand-in cargo records the
    runner variables it is given and, where a case asks, either runs the unmutated tree's test
    processes and then each mutant's through its host's runner and logs them as cargo-mutants, cargo
    (a test binary) and rustdoc (a doc-test) do, or reckons the unmutated tree's test time against
    its arguments as cargo-mutants 27.1.0 does. A stand-in test process (`hog`, its Python run with
    `-I`) that maps 64 MiB more than the data cap, or makes a sparse file one byte past the file
    cap, fails as a Rust test binary would, and its mutant is caught by a cap; one 256 MiB under the
    data cap, or exactly at the file cap, passes and is missed; one that fails an assertion is
    caught, not by a cap; a doc-test past either cap is caught by a cap. A missed mutant whose log
    carries the data cap's sign (a passing test that prints it) is not counted, nor is the
    baseline's log. Unmutated tests past the data cap, the file cap, or (two doc-tests) both fail
    the shard with an error that names them; one that fails an assertion, with the error as before.
    Unmutated tests of 400 s pass, with each mutant's limit 800 s; of 143 s, they give 300 s. Also
    the counts and lists as before, the listing (numbered, folded), a failed listing (exit 1, no
    run), the exact runner on x86_64 and aarch64 Linux, none on macOS, rustc failing, the budget
    running out in the unmutated tree, a module planted where the tests run (ignored under `-I`),
    and the arguments of both calls. `hog` names `MAP_NORESERVE` by its Linux value where Python
    lacks the name (3.12 does): without that the test failed on Python 3.12, as on Ubuntu 24.04. On
    the old script (b9f72b8) 16 of the 26 cases and 7 of the 10 checks fail; without the second
    review's fixes, 5 cases (the caps named, rustdoc's SIGXFSZ counted, the new wording); without
    the filter on caught mutants, 2.
  - **Baseline, 11-07** (the 11 shards that finished, 2,247 of 3,269 mutants): 1,176 caught, 98
    missed, 26 timed out, 947 unviable. The 5 dead shards printed 41 missed and 4 timed out before
    they died, and left 418 mutants untested. The missed and timed-out mutants printed by all 16
    shards, by crate: engine 45 missed and 6 timed out, index 63 and 0, keys 3 and 0, protocol 28
    and 24; 139 and 30 in all.
  - `mutants.yml`'s and `CONTRIBUTING.md`'s text say so; the shard sizes in `mutants.yml` are
    11-07's (about 204 mutants, 40 to 65 minutes).
  - Reviewed 2026-11-08 by a87479f2772495526 (first review, on 53bd222: approve once F1 is fixed;
    F1 to F4 and O1 fixed) and aa1c9cc96911eda05 (second review, on 077f376: approve; N1 to N6
    fixed, N7 informational); final confirm a9af5e987b177bbe1 on 55131c6: clean. Author
    a9d70161613f58de3, from `brief-mutants-runner.md`; the fixes of the first review's findings by
    a54ad0563a42d0acf, from `rulings-mutants-runner.md`; those of the second review's by
    aed807711963e8416, from `rulings-mutants-runner-r2.md`.

- Add the WebTransport native-side spike to `net`, off by default (spike B of the phase 0 spikes;
  pass conditions B1 to B3 of the spike brief). Every finding of the reviews is fixed; the review
  record is the last item.
  - **What it does.** `licketysync-net`'s feature `webtransport` (off by default) adds
    `webtransport`: a listener on `wtransport` 0.7.2 with a rustls configuration of `net`'s own
    (`builder_with_provider` on `aws_lc_rs::default_provider()` with its groups and suites replaced,
    TLS 1.3 only, 0-RTT off), `net`'s QUIC windows and stream limit (16 streams each way, 4 MiB a
    stream and a connection; datagrams advertised, 64 KiB of them buffered), and a fresh self-signed
    ECDSA P-256 certificate valid from 1 to 14 days (`bind` refuses 0 and more); the session only at
    `/.well-known/libp2p-webtransport?type=noise` (another path gets a 404 bounded by the step, and
    `WrongPath`); Noise XX (`libp2p-noise`) on the first stream, reporting the served certificate's
    hash, and the dialer's peer ID checked; then one stream per protocol, multistream-select
    offering only `/licketysync/sync/1`. It records, as evidence, the outer group rustls chose and
    the groups the dialer offered (`HandshakeFacts`).
  - **B1, the answer** (`spec/suites.md` 2.6, proposed): Chrome 156, given only the multiaddr
    (address, certhash, peer ID), connects. **The dialer's preference decides the key exchange**:
    rustls's server takes, among the groups it offers, the one the dialer lists first.
    `KxPolicy::PreferPq` permits X25519MLKEM768 and X25519, so an X25519-first dialer gets X25519;
    `KxPolicy::PqOnly` enforces the hybrid by refusing a dialer without it. Chrome 156 lists
    X25519MLKEM768, X25519, secp256r1, secp384r1, so it gets X25519MLKEM768 (rustls on our side,
    the ServerHello in Chrome's net log), with `TLS13_CHACHA20_POLY1305_SHA256`, where the
    listener's suite order does win. Limits: at most 14 days of validity, P-256, a UDP port of the
    listener's own, `not_before` not back-dated, Chrome's local-network prompt not covered by a
    loopback test.
  - **B2, the tests.** `crates/net/tests/webtransport.rs` (18, `--features webtransport`, so in
    `--all-features` on every push): the 1 MiB echo with each side seeing the expected peer ID and
    X25519MLKEM768 recorded; under `PreferPq` an X25519-first dialer gets X25519, under `PqOnly`
    it gets X25519MLKEM768 and an X25519-only dialer is refused; a classical-only listener records
    X25519; a wrong certificate hash refused by the outer TLS; certhashes that do not match in Noise
    refused both ways; a wrong peer ID refused both ways; another path refused; validity 1 and 14
    bound, 0 and 15 refused; an echo past its limit stopped; the certhash's form; and the three
    TM-23 tests below. They take a lock, one session at a time, since the recorded group is
    process-wide (TM-22's residual (g)) and `cargo test` runs them side by side. The headless-Chrome
    test, `browser-tests/webtransport` (a workspace of its own, since `libp2p-swarm` 0.48.0 pins
    wasm-bindgen 0.2.108 into core's lock; every dependency wasm32-only), run by
    `ci/webtransport-chrome.sh` against `crates/net/examples/webtransport_listen.rs`: 9 tests in
    Chrome; then the listener's reports (the echo on X25519MLKEM768, the classical-only listener on
    X25519, the unexpected browser refused, and Chrome's CERTIFICATE_VERIFY_FAILED for the wrong
    certhash and the 15-day certificate), and `ci/check-netlog.py --expect-pq` on Chrome's net log
    (a session on X25519MLKEM768 with `TLS13_CHACHA20_POLY1305_SHA256`, and no packet off loopback,
    unconnected UDP sends included). The script builds the browser test crate before it starts the
    listener (a cold build took over 4 minutes against the listener's old 280 s deadline, now
    600 s as a backstop). Nightly, as `nightly.yml`'s `webtransport-chrome` job, on Chrome for
    Testing 156.0.8078.80 and its chromedriver (`ci/chrome-install.sh`, each zip against its
    SHA-256 in `ci/pins.env`; Google publishes none, so the values were taken after the download's
    MD5 matched Google's `x-goog-hash`), and wasm-bindgen-cli 0.2.129 from crates.io; `gate.sh`
    checks that install line and that the test crate's `wasm-bindgen` is the same version.
    `ci/test-check-netlog.sh` (16 cases on made-up net logs), `ci/test-check-wasm-bindgen.sh` (6)
    and `ci/test-check-vendored.sh` (6) run in `gate.sh` and CI's `ci-scripts` job; the browser
    crate's `cargo fmt --check` and clippy pedantic on wasm32 run in `gate.sh` and CI's `fmt` and
    `clippy` jobs.
  - **TM-23, contained.** `wtransport` 0.7.2's `Endpoint::accept` holds `expect("Endpoint cannot be
    closed")`, which panics once quinn's `accept` returns `None` (after `Endpoint::close`, or once
    quinn's driver has ended on a socket error other than `ConnectionReset`; quinn 0.11.12,
    `src/endpoint.rs` lines 401-410, 647-675 and 843-850); and when `wtransport`'s per-connection
    worker panics, whoever awaits that connection next panics too (`Driver::result`, its
    `src/driver/mod.rs` lines 230-234). `Listener::accept`, `Listener::handshake` (the session
    request through Noise) and `Session::accept_stream` each run in a task of their own with
    abort-on-drop, returning `EndpointClosed` or the new `Panicked`; the Noise configuration is
    built before the handshake's task, so the task holds the identity's public half and signature,
    not another copy of its secret key. Tests:
    `accept_on_a_closed_endpoint_is_an_error_not_a_panic`, `a_dropped_accept_loses_no_connection`,
    and `a_panicking_session_request_is_contained`, a raw QUIC client that sends the QPACK input
    below as its CONNECT request's HEADERS: the worker panics, the handshake returns `Panicked`,
    and the listener serves the next dialer. The recording key-exchange groups are statics, which
    delegate every call (`usable_for_version` and `ffdhe_group` too), so a listener leaks nothing.
  - **Found, not fixed** (TM-23's residual (a), required before 1.0, phase 6): `wtransport-proto`
    0.7.2's QPACK integer decoder overflows a shift (`src/qpack.rs`, line 173) on the CONNECT
    request's HEADERS, before authentication: a panic where overflow checks are on (debug and test
    builds); in a release build the shift wraps, decoding fails on the recorded input, and in
    general it yields a wrong value, harmless because every decoded value is checked before use.
    The fuzz target and the 18-byte input are in `fuzz/known-crashes/`, outside the nightly fuzz
    list, with how to reproduce; a vendored fix is not made now (feature off, in no shipped build;
    the owner decides whether to report it upstream).
  - **Required before 1.0, phase 6 (browser client)**, TM-22's residuals: (e) sessions not counted
    (each held to net's QUIC limits, at most about 4.06 MiB unread before authentication, but no
    count per listener or address, outside the swarm's limits); (f) no certificate rotation; (g) the
    handshake facts are per process, not per connection, and not shared with spike A's QUIC and
    TCP. Also phase 6: a test that the wrong-path 404 is bounded against a dialer that withholds
    flow-control credit (a raw client with a stream receive window of 0 never gets its session
    request past wtransport, whose driver must first write its own SETTINGS: the session request
    timed out; a client that withholds acknowledgements instead needs a QUIC test harness), a
    native assertion of the negotiated cipher suite (asserted from Chrome's net log now; quinn does
    not expose the rustls session to a native test), and the spike's public test knobs
    (`allow_long_validity`, `noise_hashes_override`, `KxPolicy::ClassicalOnly`) behind a test-only
    interface. TM-6 and `suites.md` 4.1 record a second zeroization deviation: the listener's
    certificate key is copied through `wtransport` and rustls types not wiped on drop.
  - **Supply chain** (proposed): `deny.toml` and `deny-production.toml` wrappers for the
    feature's crates, and closing entries for each crate they admit (`wtransport` beneath
    `licketysync-net`, `wtransport-proto` beneath `wtransport`, `libp2p-noise` beneath `net`, the
    browser crate and the vendored websys, `snow` and `x25519-dalek` beneath `libp2p-noise`,
    `aes-gcm` and `blake2` beneath `snow`, `aes`, `ctr` and `ghash` beneath `aes-gcm`, `polyval`
    beneath `ghash`): a first-party crate depending on `aes-gcm` or on `x25519-dalek` now fails
    `cargo deny check bans` (probed in a scratch copy, adding each to `crates/engine`); the der,
    pkcs8, spki, sha1 and md5 bans hold. 41 cargo-vet exemptions for core's new crates;
    `browser-tests/webtransport` has its own `supply-chain/` store (150 exemptions, each with its
    role in that graph: what it sits beneath, at build time or on which targets), so `cargo vet
    prune` in one store cannot drop the other's, and vets the vendored `libp2p-webtransport-websys`
    as its crates.io release (`audit-as-crates-io`); since that keys on the version and would not
    see an edit (probed), `ci/check-vendored.sh` holds the copy to `vendor/SHA256SUMS` and refuses
    any entry that is not a regular file (its tests: an edit, an extra file, a missing file and a
    symbolic link fail it). The vendored copy changes one line of the published 0.6.0
    (`wasm-bindgen-futures` `=0.4.58` to `0.4.79`), with rust-libp2p's MIT `LICENSE` and
    `vendor/README.md`; the owner, 2026-11-04: "Yes, keep the patched version until upstream
    releases the fix." It goes once such a release has been out 7 days. Dependabot has a cargo entry
    for the browser workspace (7-day cooldown) that skips `wasm-bindgen`, `wasm-bindgen-*`, `js-sys`
    and `web-sys`: the weekly refresh moves them in one change with `WASM_BINDGEN_CLI`
    (CONTRIBUTING), and `ci/check-wasm-bindgen.sh` (gate.sh and CI's `deps` job, every push) fails a
    change that moves the test crate's wasm-bindgen without the CLI the nightly installs, so no pull
    request can turn the nightly red that way. CONTRIBUTING's weekly refresh lists the browser
    workspace and the Chrome for Testing pins. `spec/suites.md` 3.1 has rows for `wtransport`
    (naming the delegating key-exchange group and the recording resolver as first-party code it
    admits, and `quinn-proto`'s `ring` role beneath it) and `libp2p-webtransport-websys` (Noise's
    Diffie-Hellman on `x25519-dalek` 3 beneath `libp2p-noise`, `snow`'s other primitives wasm32-only
    and unselected).
  - **Unsafe code under the feature.** `ci/geiger-baseline.txt` counts each crate with default
    features, so it is unchanged. Measured by hand with the feature on (cargo-geiger 0.14.0), net
    would be `277 21323 375 32 583` against its baseline `261 20643 336 22 574`; within that,
    `wtransport` 5 expressions, `wtransport-proto` 11 expressions and 2 methods.
  - **Default builds.** With default features, `cargo tree --workspace -e normal,build` on this
    branch differs from cfb8230 by one edge on each of x86_64-unknown-linux-gnu,
    aarch64-linux-android, aarch64-apple-ios, x86_64-pc-windows-msvc, aarch64-apple-darwin and
    x86_64-apple-darwin: `data-encoding-macro-internal` 0.1.19 (a proc macro beneath multiaddr)
    now builds on `syn` 3.0.9 instead of 2.0.119, both already in the tree and vetted, which
    cargo's resolution chose when the feature's crates entered `Cargo.lock`. Nothing else in a
    default build changes. CI's test job runs `--all-features` on Windows and macOS, so the feature
    and its tests build and run there, which this machine cannot check.
  - Reviewed 2026-11-04 by a0853f1b760cf7422 (correctness: blocked by 1, the post-quantum claim,
    now fixed; confirm clean, its SHOULD FIX on the Dependabot `wasm-bindgen` pin fixed in the final
    round), a76f6f2af06334a1d (second: blocked by 6, the deny wrappers among them, now fixed;
    confirm clean) and aff627ebe87ddd091 (security, the security-reviewer pass: blocked by 1, the
    QPACK panic reaching the handshake, now fixed by containment, TM-23; confirm clean). The final
    round (R1 to R7, ruled from the three confirms) was confirmed by a3735501c4c400d71. The owner's
    decisions: the browser route is "own WebTransport" (2026-11-03), and the vendored
    `libp2p-webtransport-websys` patch is kept until upstream releases the fix (2026-11-04).
    TM-22's residuals (e) to (g) and TM-23's QPACK residual are required before 1.0, phase 6 (the
    coordinator's ruling, for the owner's review). Author ab821d0944d7e4dc1; the merge agent wrote
    this line.

- Fix the red `main` left by b550c02: `licketysync-net` builds for `aarch64-apple-ios` again (CI
  run 41744692314, job "net builds for aarch64-apple-ios"; every other job was green), without its
  memory limit, and so refuses to start there until phase 4 brings one. Cause:
  `libp2p-memory-connection-limits` 0.6.0 requires sysinfo `^0.38`, and sysinfo 0.38.4, the newest
  0.38, uses four libc items on iOS (`RTM_IFINFO2`, `proc_pidinfo`, `PROC_PIDLISTFDS`,
  `proc_fdinfo`) that libc 0.2.190 (2026-10-02, rust-lang/libc#5158) removed from iOS as macOS-only;
  the lock's libc is 0.2.191, the newest. No qualifying release fixes it: 0.6.0 is the newest
  `libp2p-memory-connection-limits` and takes no sysinfo but 0.38 (rust-libp2p's open Dependabot
  pull request #6735 moves it to 0.40.0), and sysinfo's iOS changes are in 0.40.0 (2026-10-28),
  under 7 days old.
  - `libp2p-memory-connection-limits` is a dependency on every target but iOS
    (`[target.'cfg(not(target_os = "ios"))'.dependencies]`). Every other target builds, and
    refuses connections above the memory limit, as before; `Cargo.lock` is unchanged.
  - `net` refuses to start where it has no memory limit, by the owner's answer of 2026-11-03 on
    the iOS gap. `node::build` asks the new pure function `limits::has_memory_limit` about
    `std::env::consts::OS` before it does anything else, and returns the new
    `BuildError::NoMemoryLimitOnThisPlatform` unless the answer is yes; it is yes for Linux,
    Android, macOS and Windows only, so iOS is refused, and so is every OS the project neither
    builds nor tests (on most of them `memory-stats` reads nothing and the limit would refuse
    nothing). On iOS the behaviour's memory-limit slot is `libp2p-swarm`'s `dummy::Behaviour`, so
    that the crate compiles; no node is ever built with it.
  - TM-22 gains residual (d), "No process-memory limit on iOS, so no node on iOS": required before
    1.0, fixed in phase 4, and `net` refuses to start on iOS until then (the owner's answer of
    2026-11-03 on the iOS gap, under the same 1.0 safety-limits rule as (a) to (c)), with the
    phase 4 item "iOS memory limit": an iOS memory check of `net`'s own, or an upstream release of
    `libp2p-memory-connection-limits` on a sysinfo that builds for iOS. The threat model's 3.10,
    `limits.rs`, `node.rs`, `Cargo.toml` and the README say so.
  - The test that fails without the build fix is CI's iOS build. On Linux, type-checking the crate
    for `aarch64-apple-ios` (with the C build scripts of aws-lc-sys, ring and blake3 bypassed,
    since there is no iOS SDK) gives sysinfo's four errors on b550c02 and none with the change,
    for the library, tests and examples (clippy clean too); `aarch64-linux-android` still
    type-checks the same way. The guard's tests: `ios_has_no_memory_limit_so_no_node_is_built_there`,
    `linux_android_macos_and_windows_have_the_memory_limit` and
    `every_other_os_has_no_memory_limit` (the function), and
    `a_node_on_ios_is_refused_for_want_of_a_memory_limit`, which calls `build`'s body (`build_on`)
    with `"ios"` on any OS, so that it fails if the guard is removed from the build path (checked
    by removing it, and by making the function say yes for every OS). `build` itself only passes
    `std::env::consts::OS` to `build_on`, and every other test of the crate builds its nodes
    through it. Also `memory_limit_off_ios_takes_its_bound_from_limits`;
    `connections_are_refused_above_the_memory_limit` runs on every target but iOS, where it is
    compiled out.
  - Reviewed 2026-11-03 by a1e1890792146b04a (blocked by 1, residual (d)'s owner attribution, now
    fixed; clean) and a7ca0582b9e6197af (security, the security-reviewer pass: clean; its note that
    a `memory-stats` that fails from the start leaves the memory limit open, TM-10, is pre-existing
    and goes to phase 1). The owner's answer of 2026-11-03 on the iOS gap: the memory limit on iOS
    is required before 1.0 and fixed in phase 4, and `net` refuses to start on iOS until it exists.
    Author a45d07e17f1e2bd00; the merge agent wrote this line.

- `licketysync-net`, spike A of the phase 0 spikes (`brief-phase0-spikes.md`, pass conditions A1 to
  A4): two peers connect over QUIC and over TCP, each connection TLS 1.3 on `aws-lc-rs` with
  X25519MLKEM768 offered first (`suites.md` 2.6), each side's peer ID the one derived from its
  device seed and proved in the handshake, both agree on `/licketysync/sync/1`, and a byte stream
  goes through in order. The engine is not wired to it and no daemon runs (phase 1).
  - The crate: `identity` (the keys crate's `Libp2pIdentity` as a libp2p keypair and peer ID, never
    generated from randomness: `libp2p-identity`'s `rand` feature is off, so its generators do not
    exist in this build, and `check_peer`, which refuses a peer whose identity key is not canonical
    or is of small order, through the keys crate's new `device::check_peer_identity_key`);
    `provider` (installs `aws_lc_rs::default_provider()` as the process default, or accepts an
    installed one only when its key-exchange groups and cipher suites are that provider's own,
    compared by address, not by name);
    `limits` (every bound in it set explicitly and checked, TM-22, its defaults pinned by a test; the
    library defaults left in place are TCP's listen backlog, 1024, QUIC's keep-alive, 5 s, the
    swarm's event buffers and its dial concurrency, 8, and a stream's protocol negotiation timeout,
    10 s, `libp2p-swarm`'s `SubstreamProtocol` default, which `sync` keeps);
    `node` (the swarm: QUIC through `libp2p-quic`, its configuration built in a function of its own
    whose test checks that each QUIC bound comes from `limits`, and TCP with exactly one security
    protocol, `/tls/1.0.0`, and one muxer, yamux, with a handshake timeout that `libp2p`'s
    `SwarmBuilder` does not set, so an idle connection cannot hold a pending slot for ever; the
    connection limits, a process-memory limit, and the sync behaviour; it refuses to build while
    `SSLKEYLOGFILE` is set, since `libp2p-tls` gives every configuration rustls's `KeyLogFile`,
    TM-6); `sync` (a behaviour of its own, not the alpha `libp2p-stream`: it opens and accepts
    streams of the protocol IDs it speaks, newest first, today only `/licketysync/sync/1`, at most
    one inbound stream over a connection's life, refused in negotiation past it; it refuses a
    connection whose peer fails `check_peer`, and answers a request on a connection that is not
    established at once); `pieces` (a stream read as the engine's runtime contract hands bytes over:
    in order, at most `MAX_CHUNK`, 64 KiB, imported from the engine, and the end reported).
    `examples/spike.rs` is A1's check by hand on 127.0.0.1, with a reasoned allow for printing; it
    dials exactly `/ip4/127.0.0.1/tcp/<port>/p2p/<peer ID>` or
    `/ip4/127.0.0.1/udp/<port>/quic-v1/p2p/<peer ID>` and nothing else (its parser's tests run with
    the crate's).
  - Tests that fail without the change, all with deadlines and no sleeps (`tests/transport.rs`,
    `tests/tcp_flood.rs`, `tests/provider_conflict.rs`, `tests/key_log.rs`, and unit tests). A4's
    loopback condition: every socket that stays bound is on 127.0.0.1; quinn-udp's GSO and GRO
    checks open and close `[::]` sockets without sending. The tests: A1's
    exchange over QUIC and TCP; A2 (a) `libp2p-tls`'s own configurations negotiate X25519MLKEM768
    and `TLS13_CHACHA20_POLY1305_SHA256`; (b) the installed default is `aws-lc-rs`'s with
    X25519MLKEM768 first, rustls is built with TLS 1.3 only, and a default installed first without
    it stops the build, as does a look-alike group under the hybrid's name; (c) a TCP dialer offering `/noise` or `/plaintext/2.0.0` is answered `na`
    and gets no connection (`/tls/1.0.0` is the control); (d) a dial expecting another identity
    fails with `WrongPeerId` on both transports, and a peer whose identity is the small-order identity
    point (`12D3KooW9tGaPdJo5jmCpadQ971nfiq4kLcQjeBPYTfutBTtckPH`) is refused both ways; (e) a
    connection past the established limit and one past the pending limit are refused by the limit;
    a TCP socket that never speaks ends at a 1 s handshake timeout with the transport's timeout error,
    after at least that and before the default 10 s, and its pending slot is free again;
    in a test binary of its own, 513 idle TCP connections past a pending limit of 4 add less than
    the stated bound of 16 MiB of resident memory (`FLOOD_MEMORY_BOUND`; measured about 0.5 MiB)
    with never more than 4 pending, and a real peer connects afterwards; connections are refused
    above the memory limit; a second sync stream on one connection is refused; (f) 3 MiB arrive in order in pieces of at most 64 KiB with a clean end,
    and a connection that ends under an open stream is reported by the reader and the swarm; (g)
    the peer ID of the keys crate's test seed is its vector, `12D3KooWLbwYSoxYfCSHg726dZA3cCSdzeMG18brSyhACQ2mo24f`.
  - Dependencies (TM-8; each the newest release out at least 7 days on 2026-11-03T17:58Z, from the
    crates.io API): `libp2p-core` 0.44.0, `libp2p-swarm` 0.48.0 (`macros`, `tokio`), `libp2p-tcp`
    0.45.0, `libp2p-quic` 0.14.0, `libp2p-tls` 0.7.0, `libp2p-yamux` 0.48.0,
    `libp2p-connection-limits` 0.7.0, `libp2p-memory-connection-limits` 0.6.0 (all 2026-09-11),
    `libp2p-identity` 0.3.1 (2026-10-27T15:36Z; `ed25519` and `peerid`), `rustls` 0.23.46 (no
    default features: `aws-lc-rs`, `prefer-post-quantum`, `std`, so no `tls12`), `futures` 0.3.34;
    dev-only `tokio` 1.54.1, `multistream-select` 0.14.0, `memory-stats` 1.2.0, and the workspace's
    `serde_json` and `hex`. Individual crates rather than the `libp2p` 0.57.1 facade, whose weak
    `tokio` feature puts `libp2p-dns`, `libp2p-mdns`, `libp2p-upnp` and the hickory DNS crates into
    `Cargo.lock` though nothing builds them. 192 new crates in `Cargo.lock`; held back in it to the
    newest qualifying release: `aws-lc-rs` 1.18.2 (1.19.0 is from 2026-10-28), `aws-lc-sys` 0.46.0,
    `log` 0.4.34 and `utf8_iter` 1.0.4. Held back by a requirement, not by choice: `libp2p-swarm`
    0.48.0 requires `wasm-bindgen-futures` `=0.4.58` on wasm targets only, so `wasm-bindgen` and its
    family stay at 0.2.108 and `js-sys` and `web-sys` at 0.3.85 (no native build compiles them;
    `CONTRIBUTING.md`'s refresh note says so, and phase 6's browser build must settle it against
    the 0.2.129 of the app's web UI). `idna_adapter` is 1.0.0, idna's ASCII-only back end, which
    idna selects by this crate's version (1.0.0, 1.1.0 and 1.2.0 were published the same day as
    back ends, not as successive releases): `url`, beneath `multiaddr`, needs no Unicode host names
    here, and 1.2.2's ICU4X back end brings twenty crates and baked data with unsafe code that
    cargo-geiger cannot scan. The owner approved this on 2026-11-03 as an exception to the "Stay
    current" rule ("Keep 1.0.0. Record this decision as an exception to the rule, but we would
    upgrade to 1.0.* if that ever appears."): `licketysync-net` requires `idna_adapter = "~1.0"`, so
    `cargo update` takes any 1.0.* release and no other; `deny.toml` bans `icu_normalizer` and
    `icu_properties`, `.github/dependabot.yml` skips 1.1 and later, and `CONTRIBUTING.md` names the
    exception. Licences all within `deny.toml`'s list.
  - `deny.toml`: `ring` gets the wrappers `cargo tree -e no-dev -i ring` shows (`libp2p-tls`, `rcgen`,
    `quinn-proto`, `libp2p-quic`); `rand` those of the libp2p crates and `quinn-proto` (and
    `deny-production.toml` the same without `proptest`, replacing its outright ban); `chacha20` gains
    `rand` (rand's ChaCha12 generator); `ed25519-dalek` and `sha2` gain `libp2p-identity`; `ctutils`
    gains `digest` (hmac's tag comparison); new wrapper entries for `rustls`, `aws-lc-rs`,
    `aws-lc-sys`, `rustls-webpki`, `rcgen`, `hkdf`, `hmac`, `rand_pcg`, `libp2p-tls`, `quinn` and
    `quinn-proto`; the bans on `der`, `pkcs8`, `spki`, `sha1`, `md5` and `openssl` hold, and no Noise,
    plaintext, pnet, DNS, mDNS, UPnP, Kademlia, relay or AutoNAT crate is in the graph. One advisory
    ignored with its reason: RUSTSEC-2024-0436, `paste` unmaintained, a build-time proc macro beneath
    `if-watch`'s netlink crates with no maintained path yet. `supply-chain/`: 162 new exemptions, each
    with its reason, and 8 dev-only exemptions raised to safe-to-deploy now that net ships them;
    `imports.lock` refreshed. `ci/geiger-baseline.txt`: net's line (aws-lc-rs, ring, quinn, tokio
    and the rest of the tree), and two generated files read and accepted (`thiserror`'s
    `private.rs`, `oid-registry`'s `oid_db.rs`, neither with unsafe code); `ci/geiger.sh` accepts
    unscanned `.der` files of `ring`, `rustls-webpki` and `rustls-pki-types` only (the DER data
    they embed with `include_bytes!`), and only in those packages' own directories in the registry
    (`$CARGO_HOME/registry/src/<index>/<package>-<version>/`, `<version>` a semver version, three
    numbers and an optional pre-release or build suffix, `CARGO_HOME` defaulting to `~/.cargo`),
    and `ci/test-geiger.sh` has that case (and the default `~/.cargo`, `ring-0.17.14` and the
    pre-release `rustls-webpki-0.103.0-alpha.1`), another package's `.der`, look-alike package
    names (`ring-compat-0.8.0`, and `ring-0x-1.0.0` and `ring-0-1.0.0`, which the semver anchor
    refuses: the automated commit security review's finding, a test case each that fails without
    the anchor), a `ring` directory nested in another package and one outside the registry
    refused, and ICU4X's `.rs.data` refused.
  - `rust-version` 1.85 to 1.88 (libp2p 0.57's), which turns on clippy's `manual_is_multiple_of` and
    `chunks_exact_to_as_chunks` for the workspace: the same arithmetic as `is_multiple_of` in
    `protocol`, `index`'s tests and `sim`, and `as_chunks::<8>` in `sim`'s toy decoder (no
    behaviour change).
  - CI: a `net-cross` job builds net for `aarch64-linux-android` (ubuntu-latest, NDK 30.0.16248370,
    r30 of 2026-09-08) and `aarch64-apple-ios` (macos-latest, Xcode 26.6); `ANDROID_NDK` and `XCODE`
    are new `ci/pins.env` keys that `gate.sh` checks against the job. `spec/allowed-hosts.txt` stays
    empty. `spec/suites.md` 3.1: the rows of `libp2p-identity` (0.3.1, `peerid`, and
    `libp2p-quic`'s HKDF-derived stateless-reset key), `aws-lc-rs` and the transports.
  - The security review's rulings (`rulings-spikeA.md`, 2026-11-03), recorded where they apply:
    - SA-B1, QUIC Initials: `libp2p-quic` 0.14 accepts every Initial before the swarm's limits are
      asked, so each costs a QUIC connection and a TLS server handshake whatever the pending limit,
      at the attacker's rate (the review measured 10 000 Initials at about 412 MB, about 41 KB
      each, and seconds of CPU). quinn's Retry and incoming cap are not reachable through
      `libp2p-quic` without a fork. `limits.rs` no longer claims a bound for it; TM-22 and the
      threat model's 3.10 state the residual and its phase 1 item. A2(e) is met for TCP only: the
      owner deferred the QUIC half to phase 1 and made it required before 1.0 ("I want safety
      limits in version 1.0, no matter what. It is fine to pass until phase 1, but it must not get
      lost.", 2026-11-03), so the QUIC Initial limit (Retry under load or a lower incoming cap) and
      its flood test with a stated bound are not in this change, and TM-22 marks the residual
      "required before 1.0 (owner, 2026-11-03)" with its phase 1 item named.
    - SA-S1: one pending counter for every source, so 32 handshakes that never finish lock every
      inbound peer out for the 10 s handshake timeout, renewably; SA-S2: yamux's connection window
      on TCP auto-tunes from the round trip its pings measure, so a remote that delays them can grow
      it toward 1 GiB (the old `limits.rs` text, "grows only as fast as this side reads", was
      wrong). Both are stated in `limits.rs`, TM-22 and 3.10, with their phase 1 items ("pending
      lockout", "yamux window"), and both are required before 1.0 by the same decision of the owner.
    - SA-S3: `libp2p-identity` 0.3.1 verifies the TLS extension's Ed25519 signature with
      `ed25519-dalek`'s non-strict `verify` and accepts small-order keys, so a forged extension
      verifies under the identity point; `net` now refuses such a peer (tests above), and both
      `suites.md` 3.1 rows and 2.6 record the deviation (the Hello's check of the libp2p identity
      key is phase 1).
    - SA-S4: the libp2p identity's secret key is not wiped beneath `libp2p-identity` (its plain
      `SecretKey`, `derive_secret`'s copies, the `Keypair` clones in the TLS and QUIC
      configurations): a deviation named in `suites.md` 4.1 and TM-6, to raise upstream once the
      owner approves posting it.
    - NITs: the TCP flood in its own test binary with the bound above; the example's exact address
      forms; `provider::check` by identity; `suites.md` 2.6 says what the TCP listener does when
      offered Noise (answers `na`; the connection ends unestablished); the dialer's identity goes to
      whoever answers at the address it dials, before it compares the identity with the one it
      expected (threat model 3.1; phase 1 item: give `libp2p-tls`'s verifier the expected peer);
      `sync::Behaviour::open` on a connection that is not established answers `ConnectionClosed` at
      once (test); `suites.md` 3.1's closing paragraph lists `ring`'s six roles (`libp2p-quic`'s
      reset HMAC key among them) and its wrappers as they are, and 2.6 records the identity's
      HKDF-derived reset key against its "nothing but"; on Windows, `aws-lc-sys` uses the prebuilt
      NASM objects it ships (rustls's `aws_lc_rs` feature turns on `prebuilt-nasm`), recorded in
      `suites.md` 3.1 with an item to build them with a pinned NASM before any Windows release;
      `ci/geiger.sh`'s `.der` acceptance scoped as above.
  - The correctness review's rulings and the security re-review's (`rulings-spikeA.md`,
    2026-11-03): CA-B1, the TCP handshake timeout had no test that failed without it: the timeout
    test above fails, at its deadline, when `.timeout(limits.handshake_timeout)` is taken off the
    TCP upgrade. QUIC's configuration is a function of its own (`node::quic_config`) with a unit test
    that its handshake timeout, idle timeout, stream limit and connection and stream windows come from
    `Limits`, and a unit test pins every default of `Limits` (the 32 pending, 10 s and 4 MiB that
    TM-22 and 3.10 quote among them) and `YAMUX_MAX_STREAMS` as 1 GiB over 256 KiB. NITs:
    `ci/geiger.sh`'s `.der` acceptance anchored to the registry as above; `Pieces::get_mut`, which
    nothing called, removed; the keys crate's `vector_device` names the net test that checks its
    peer ID (`peer_id_of_the_keys_test_seed_is_the_keys_vector`); `suites.md` 2.6 says `net` tests
    the Noise and plaintext refusals and the handshake timeout; `FLOOD_MEMORY_BOUND`'s comment says a
    leak of 32 KiB an attempt would exceed it, failing the test.
  - The second review's rulings (`rulings-spikeA.md`, 2026-11-03; CA-B1 confirmed):
    - SR-1: `libp2p-quic` turns on `quinn-proto`'s `ring` feature, which takes precedence over its
      `aws-lc-rs` one, so all of `quinn-proto`'s own cryptography runs on `ring`: the
      stateless-reset HMAC-SHA256, the token keys (HKDF-SHA256, AES-256-GCM) and the Retry integrity
      tag (AES-128-GCM); `aws-lc-rs` is linked beneath `quinn-proto` but not called there (QUIC's
      packet protection is rustls's, on `aws-lc-rs`). `suites.md` 3.1's `aws-lc-rs` row, its count
      of `ring`'s six roles (four in the graph) and `deny.toml`'s `ring` and `aws-lc-rs` comments
      now say so.
    - SR-2: the wasm-only hold-back of `wasm-bindgen` at 0.2.108 above, in `CONTRIBUTING.md`'s
      refresh note too, with the phase 6 heads-up.
    - SR-3: a QUIC dial from a swarm with no QUIC listener of that address family makes
      `libp2p-quic` bind a dialing socket of its own on every address (`0.0.0.0` or `[::]`, port 0).
      Every QUIC dialer in `tests/transport.rs` and `examples/spike.rs`'s dial now listens on
      `/ip4/127.0.0.1/udp/0/quic-v1` first, so that `libp2p-quic` dials from that loopback endpoint.
      Under strace, `tests/transport.rs` bound nine dialing sockets on `0.0.0.0` before and none
      after; of its sockets and the example's, every socket that stays bound is on 127.0.0.1
      (TM-31); quinn-udp's GSO and GRO checks open and close `[::]` sockets (port 0, one option
      set, two per endpoint) without sending; a TCP dial binds nothing. `node.rs` states the
      behaviour and the phase 1 item for real dials.
    - NITs: the vet notes of `ring` (the six roles), `displaydoc`, `smallvec` and `syn` 3 (no
      ICU4X in the graph) and the Windows bindings (the crates each is really beneath);
      `deny.toml`'s `pkcs8`, `der` and `spki` bans say "no first-party key", and `suites.md` 2.6
      describes the certificate key, the one PKCS#8 key, which `ring` writes and `aws-lc-rs` reads;
      the stream negotiation timeout listed above among the library defaults; doc comments in
      `identity.rs` and `node.rs` (the expected peer ID is compared after the handshake, its earlier
      use a phase 1 item paired with the threat model's 3.1); TM-22 says the limits are flood-tested
      on TCP, and on QUIC points to residual (a).
  - Line coverage at this change's gate (`gate.sh`'s Lines column): keys 99.37% (4585 lines), protocol
    98.32% (8374), index 97.66% (3165), engine 96.94% (6790); each at least the 90% gate.
  - Reviewed 2026-11-03 by a7ca0582b9e6197af (security, the security-reviewer pass: two rounds,
    clean), afffc29a7492db35a (correctness: blocked by 1, CA-B1, fixed) and a1e1890792146b04a (a
    second review: blocked by 3, SR-1 to SR-3, fixed, clean; it also confirmed CA-B1's fix); the
    `ci/geiger.sh` semver anchor, from the automated commit security review, glanced by
    a1e1890792146b04a. The owner's decisions in it, both of 2026-11-03: the `idna_adapter`
    exception to the "Stay current" rule (1.0.0 kept, any later 1.0.* taken), and A2(e)'s QUIC
    half deferred to phase 1 and required before 1.0. Author ae906fe3f3104fa7a, with fixer
    a68835e6737c85420; the merge agent wrote this line.

- The weekly stay-current refresh of 2026-11-02, under the owner's "Stay current" rule of 2026-10-25
  (quoted in the project's CLAUDE.md; TM-8, TM-29): every pin is the newest release that had been
  out for at least 7 days at 2026-11-03T02:20Z (published on or before 2026-10-27T02:20Z), or a
  younger one that fixes a critical or high vulnerability or, on the owner's ruling of 2026-11-03,
  holds only the data needed to install such a fix. Dates come from the crates.io API, `gh api
  .../releases` (each tag resolved to its commit, an annotated tag dereferenced), Docker Hub, PyPI
  and static.rust-lang.org, read under a User-Agent with no personal data. Moved, by
  `CONTRIBUTING.md`'s procedure (`ci/pins.env`, then the workflow copies, then `git grep -F` for
  each old version):
  - Rust nightly `nightly-2026-10-18` to `nightly-2026-10-27` (rustc 1.101.0-nightly, 16d1ffac1
    2026-10-26; its manifest was published 2026-10-27T01:13Z and has miri and rust-src), in
    `pins.env` and the four nightly jobs (`ci.yml`'s `udeps`, `nightly.yml`'s `fuzz`, `careful` and
    `miri`). `gates/phase-0.md` still names `nightly-2026-10-18`: it records what the gate ran.
  - cargo-nextest 0.9.148 to 0.9.150 (crates.io, 2026-10-26T18:33Z), which fixes GHSA-vc25-qg58-w57c
    (High, CVSS 7.8): from 0.9.125 to 0.9.149, `cargo nextest run --rerun` with a crafted portable
    recording could run code during the build. Nothing here records or reruns runs, but the pinned
    release was in the affected range.
  - taiki-e/install-action `v2.87.29` to `v2.87.33` (`645d1ab48b3cb8591684a8b730b2ccf4cb3f9568`,
    2026-10-28T12:37Z), taken six days old on the owner's ruling, since it is what lets CI install
    the fix above. It fixes no vulnerability itself, so the review put it to the owner, who on
    2026-11-03 chose "Take it now (Recommended)", the reading: "a release under 7 days old may be
    taken when its only change is the data needed to install a critical or high fix". It is the
    first release whose manifest lists cargo-nextest 0.9.150 (`v2.87.32`, of 2026-10-26 and the
    newest that is 7 days old, lists 0.9.149 at most), and every install here has `fallback: none`,
    which fails on a version the manifest lacks. Its diff from `v2.87.32` is manifest files and its
    changelog only (cargo-about, cargo-nextest, espup, kingfisher, mise, release-plz, tombi, trunk,
    uv, vacuum), and its manifests list every version the workflows install (cargo-nextest 0.9.150,
    cargo-llvm-cov, cargo-udeps, cargo-deny, cargo-audit, cargo-machete, typos, cargo-mutants,
    cargo-careful, cargo-auditable, cargo-cyclonedx). Its SHA-256 for 0.9.150's x86_64 Linux
    archives (gnu `b0959bc64232974224cf9fb22c915845398c0e8668fa7831eb5b43fb1eef781f`, musl
    `84f0f9ba75d0b6fa117bc418d49747ba78e20e4583057f6fa628f1b17c17234d`) equals the digests of
    nextest's GitHub release assets. It is 7 days old from 2026-11-04T12:37Z.
  - semgrep 1.181.0 to 1.182.0 (GitHub 2026-10-20T20:27Z, PyPI 20:32Z; features and fixes), and its
    image digest to `sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af`
    (Docker Hub's API and the registry's `Docker-Content-Digest` agree; the tag was pushed
    2026-10-20T20:26Z).
  - The Codecov CLI `v11.3.1` to `v11.3.2` (2026-10-28T17:37Z), taken five days old under the
    critical-or-high exception, as cargo-vet 0.10.3 was on 2026-10-25. The advisory that reaches the
    codecov job is GHSA-6q48-6c7w-9gw2 (Critical: certifi bundles emSign root CAs whose intermediate
    CA keys were compromised; fixed in certifi 2026.10.18): 11.3.1's lockfile (`uv.lock`) has
    certifi 2024.12.14 and 11.3.2's has 2026.10.23, and the CLI checks Codecov's TLS certificate
    against certifi's roots when it uploads. Its urllib3 moves from 2.6.3 to 2.7.0 as well, past
    GHSA-mf9v-mfxr-j63j and GHSA-qccp-gfcp-xxvc (both High), which the security review found do not
    reach the job; urllib3 2.7.0 is still in the range of GHSA-vxq7-64xx-v4gw and
    GHSA-8988-9cw3-xx77 (High, fixed in 2.8.0), which no Codecov CLI release has yet. The Linux
    `codecov.SHA256SUM` on cli.codecov.io names the digest of the GitHub release's
    `codecovcli_linux`, `8e1bfb71661378530f6ea21e82b414095899e565cbb4cf555c613064be17b973`, and its
    signature verifies with Codecov's key as codecov-action fetches it from keybase.io (fingerprint
    `2703 4E7F DB85 0E0B BC2C 62FF 806B B28A ED77 9869`): the checks codecov-action makes in CI; and
    `.typos.toml` lists `certifi` as a word, which typos took for a misspelling of "certify".
  - github/codeql-action `v4.39.0` to `v4.39.1` (`9b3254085494b55a0f7c4c2b3d2d52cc712ce370`, an
    annotated tag dereferenced, 2026-10-21), for `init`, `analyze` and `upload-sarif`: its default
    CodeQL bundle moves from 2.27.2 to 2.27.3, whose Rust extractor's `FIXED_RUST_TOOLCHAIN` moves
    from 1.98.1 to 1.99.0, and its `action.yml` files differ only in `init`'s description of
    `trap-caching`. This is the release the pin-all series passed over as too young.
  - Swatinem/rust-cache `v2.9.2` to `v2.9.3` (`d1527c8f67ef9af357290475d4af4b0fab8f12e0`, an
    annotated tag dereferenced, 2026-10-20), which the pin-all series also passed over: its
    timestamp pruning no longer stops after the first entry, two calls in its target cleanup gain
    their missing `await`s, a failed `rustup toolchain list` is logged as info instead of a warning,
    and its bundled dependencies move (`@actions/cache` 6.3.0, `smol-toml` 1.9.1, with `dist/`
    rebuilt).
  - `Cargo.lock` and `fuzz/Cargo.lock`, the same five crates in each, by `cargo update` and then
    `cargo update --precise` for the two whose newest release is too young: cc 1.8.0 to 1.10.0
    (2026-10-23), ctutils 0.4.4 to 0.4.6 (2026-10-25T23:01Z), find-msvc-tools 0.1.14 to 0.1.15
    (2026-10-19), inout 0.2.4 to 0.2.5 (2026-10-19) and libc 0.2.190 to 0.2.191 (2026-10-16), each
    lockfile checksum equal to the one crates.io publishes; no package is added or removed, and no
    manifest changes. `supply-chain/config.toml` moves the five exemptions to the new versions with
    the same criteria, safe-to-deploy, since no imported audit set covers them (`cargo vet` unlocked
    left `imports.lock` unchanged), and each note says what the diff holds, read with `cargo vet
    diff`: for ctutils, the constant-time comparisons keep their formulas on every target but
    Thumb-1, and the crate still forbids unsafe code; inout's `into_padded_blocks` returns
    `PadError` where it had a debug assertion; cc's new unsafe code is in its build-time jobserver
    polling. `ctutils` is still reached only beneath `universal-hash`, as `deny.toml` requires.
  - Unchanged, each the newest release and old enough: Rust stable 1.99.1 (the stable channel's
    manifest is still that of 2026-10-15), cargo-llvm-cov 0.9.1, cargo-udeps 0.1.61, cargo-deny
    0.20.2, cargo-audit 0.22.2, cargo-machete 0.9.2, cargo-vet 0.10.3, cargo-mutants 27.1.0,
    cargo-fuzz 0.13.2, cargo-careful 0.4.10, cargo-geiger 0.14.0, cargo-auditable 0.7.7,
    cargo-cyclonedx 0.5.9, cargo-semver-checks 0.51.0, typos-cli 1.51.1, gitleaks 8.30.1, site's
    zola 0.23.6; checkout `v7.0.1`, upload-artifact `v7.0.2`, download-artifact `v8.0.2`,
    attest-build-provenance `v4.2.2`, codecov-action `v7.1.1`, scorecard-action `v2.5.0`;
    rust-toolchain `v1` (still `683b588c487a69d01f6c6ddf40f036ff682cc2c8`, of 2026-10-16) and
    clusterfuzzlite `v1` (still `884713a6c30a92e5e8544c39945cd7cb630abcd1`, of 2023-08-09).
  - Held back, younger than 7 days and fixing nothing critical or high: cargo-nextest 0.9.151
    (2026-11-03; two bug fixes; no install-action release lists it yet). Its lockfile moves
    pulldown-cmark from 0.13.4 to 0.13.5, past RUSTSEC-2026-0414 (CVSS 7.5), which, like
    RUSTSEC-2026-0433 (fixed in 0.13.6, so in both releases), only the `ENABLE_WIKILINKS` option
    reaches, set alone or through `Options::all()`; in 0.9.150 neither crate that parses with it
    sets it (`nextest-runner` 0.128.0's `help_render.rs` sets `ENABLE_DEFINITION_LIST |
    ENABLE_STRIKETHROUGH`, `clap_derive` 4.6.7's `doc_comments.rs` `ENABLE_STRIKETHROUGH`). Both
    releases also hold quick-xml 0.38.4, in the range of RUSTSEC-2026-0194 and RUSTSEC-2026-0195
    (CVSS 7.5, fixed in 0.41.0), beneath `self_update` alone, which only `cargo nextest self update`
    runs, and nothing here does. Also held back: typos-cli 1.52.0 (2026-11-02; the dictionary);
    semgrep 1.183.0 (2026-10-29; features and fixes); install-action `v2.88.0` to `v2.89.1`
    (2026-10-28 to 2026-11-02; manifests and new tools); cc 1.11.0 (2026-11-02); ctutils 0.4.7
    (2026-10-29) and 0.4.8 (2026-11-02), whose "Security" entries harden Thumb-1 (Cortex-M0) and
    32-bit RISC-V code, targets nothing here builds, with no advisory (RustSec lists only
    RUSTSEC-2026-0385 for ctutils, fixed in 0.4.4); and the nightlies after 2026-10-27.
  - `gate.sh` passes on bdb7d18 with this change, run with the user's cargo-nextest 0.9.150 and
    semgrep 1.182.0: 656 tests, 1 skipped; line coverage keys 99.37%, protocol 98.32%, index 97.60%,
    engine 96.94% (the runs before the rebase gave the same, but index 97.66% on the first of them,
    when llvm-cov counted 3,165 lines and not 3,167); `cargo deny`, `cargo audit` (both lockfiles),
    `cargo vet --locked` and cargo-udeps on `nightly-2026-10-27` pass, and every cargo-geiger count
    equals `ci/geiger-baseline.txt`, which does not change. With `nightly-2026-10-27`, `cargo fuzz
    build` builds all 19 targets, a 5-second `cargo fuzz run frame_decode` from its seeds runs
    clean, `cargo careful test --workspace` passes (658 passed, 1 ignored) and `cargo miri
    --version` answers.
  - On the dev machine: `nightly-2026-10-27` installed with miri and rust-src (rustup checks each
    component's SHA-256 against the manifest). cargo-nextest 0.9.150 (crates.io, `cargo install
    --locked`) and semgrep 1.182.0 (PyPI, through pipx) were first installed beside the pinned ones,
    under the refresh's scratch directory, so that worktrees still on `main`'s pins kept passing
    their gate, and then for the user, over 0.9.148 and 1.181.0, before the merge agent's gate run
    (`cargo install --locked cargo-nextest --version 0.9.150`, `pipx install --force
    semgrep==1.182.0`, as `gate.sh` prints).
  - Reviewed 2026-11-03 by a4ee053f5f0941bb0 (pins) and a1ae94e8e32a1fe4a (supply-chain security),
    both clean once the rulings were applied: SC-1, install-action `v2.87.33` taken six days old,
    approved by the owner on 2026-11-03; SCS-1, the Critical certifi advisory named as the one that
    reaches the codecov job; and their NITs on the cc, libc, rust-cache and held-back nextest notes.
    Author aa4eaa4a25e86b635; the merge agent wrote this line.
- Docs: phase 0 is current again, the Risks page records two of the owner's decisions, and the
  relay sentences follow the owner's answer that only public relays exist. Docs only; no code
  changes.
  - Phase 0. Of the plan's phase 0 work list (the libp2p transports, the phone shells and the
    WebTransport native-side check), the owner decided on 2026-11-02: "I wanted phase 0 completed.
    Get this done as part of phase 0." Phase 0's gate (simulated peers converge; spec published)
    passed on 2026-11-02, its threat-model §6 review recorded in `gates/phase-0.md`, but the phase
    is not finished until that work is done. The README's Status now opens with "Now: phase 0,
    spikes and the protocol" (the plan's name for it): what main holds (as before), that phase 0
    is not finished, that its gate passed with its review in `gates/phase-0.md`, and those three
    items as still to do, also in plain words; phase 1, "LAN sync from the command line", with its
    gate (two Linux machines pass the fault-test suite) and what it brings, follows as "Next", in
    place of "Now: phase 1".
  - The Risks page. Its two design choices marked as awaiting the owner's review (sealed
    metadata's size classes rounded up to a power of two; cleanups that show which records were
    folder deletions or deletions more than a year old), which the owner approved on 2026-11-02
    ("Okay"), are now marked as the owner's decision, in the site repository's own commit.
  - Relays. The owner's answers: "Only relay when configured to do so. By default, we do not relay
    publicly but it could be enabled." (2026-11-02) and "I think we should drop the
    private/protected relay idea and only work with public relays." (2026-11-03). The README's
    opening says "no relay is used, and your devices relay for no one, unless you turn that on",
    and what a relay is, in place of "your own devices may relay for each other; no other relay is
    used unless you turn it on". The Risks page says the same in its glossary and its relay item;
    the glossary adds that every relay is a public one, which may belong to anyone, and both add
    that any of your computers can be set up as a public relay, with limits on rate and open
    connections, and a minimum transfer rate below which a connection can be dropped.
    `threat-model.md` §2, §3.9 and TM-25, and the plan's summary and comparison tables, still
    describe private or own-device relays; the relay design change that follows rewrites them,
    with the protocol spec's relay text.
  - Reviewed 2026-11-03 by a27c3602c6374ec6f (accuracy, clean on the final text) and
    a9625fde653494bc0 (clarity, its findings fixed as ruled), with the site's Risks page. Author
    a94ccee62e12b9dfd; the merge agent wrote this line.
- The docs now describe phase 1, "LAN sync from the command line", since phase 0's gate (simulated
  peers converge; spec published) passed on 2026-11-02, its review recorded in `gates/phase-0.md`
  (the owner's rule of 2026-10-25: the docs describe the current phase and the phases ahead, and
  phase history lives here and in git). The README's Status opens with phase 1, its gate (two Linux
  machines pass the fault-test suite) and what it brings, from the plan's roadmap, with SQLite (the
  plan's decision of 2026-10-14) and FastCDC or another keyed chunker (`keys.md` §3.2); then it says
  what main holds (the four specifications, the simulator, and the keys, protocol, index and engine
  crates), that every gate scenario ends with the same records on every peer and the same files on
  every read and write peer, that phase 0's gate passed with its record in `gates/phase-0.md`, and
  that nothing syncs on a real disk or over a real network yet. In the crate table, the engine's row
  describes what the engine holds now and what phase 1 and later add, in place of FastCDC, scanning,
  versioning and the deletion brake, which it does not hold yet; the simulator's row no longer says
  "phase 0's gate"; and `net`, `daemon`, `cli` and `decrypt` are marked as placeholders. The
  engine's row cites TM-41 (conflict copies) and the sources of FastCDC or another keyed chunker
  (`keys.md` §3.2) and SQLite (the plan's decision of 2026-10-14); the simulator's row says what its
  oracle checks (the same records on every peer, the same files on every read and write peer); the
  keys row names the libp2p identity and DHT key, discovery hashes and the linked-device code and
  proof, which the crate holds. The README's opening says that the program contacts no server you
  did not turn on, that "your own devices may relay for each other; no other relay is used unless
  you turn it on" (`threat-model.md` §2), that only devices holding one of a folder's keys can join
  it, and that anyone who holds a key can pass it on, in place of "never contacts a server", "no
  relay you did not turn on" and "only the people you give a folder's key". The
  specification bullet, and `SECURITY.md`, count TM-1 to TM-43, as `spec/threat-model.md` does since
  TM-43 was added on 2026-10-25. `SECURITY.md` takes reports through GitHub's private vulnerability
  reporting only, since licketysync.com receives no mail, and says an address will be listed once
  one exists. The engine crate's doc (`crates/engine/src/lib.rs`) gives the same status in place of
  "Status: phase 0."; the simulator's doc and its `Cargo.toml` description say that its gate
  scenarios check that simulated peers converge, in place of "Phase 0's gate"; and the command
  line's planned commands (`crates/cli/src/main.rs`) no longer list `owner`, since there has been no
  owner key since 2026-10-18. The documentation site's new page, "Risks of using Lickety-Sync", is
  in the site repository's own commit. Comments and docs only; no code changes.
  - Reviewed 2026-11-02 by a053ca395ad2a83f3 (accuracy) and a759a3e97142a0717 (clarity and the
    docs rule), with the site's risks page, over three rounds; every finding fixed, and both clean
    once the merge agent removed a stray rebase line and set the relay wording to
    `threat-model.md` §2. Author af0eea5d74ac27f5b; the merge agent wrote this line.
- Phase 0 gate review: its record, and the tests and the rule its findings ask for. The phase 0
  gate record of 2026-11-02, added as `gates/phase-0.md` (the threat-model §6 walk and
  security-reviewer pass over 55ddfb4, and its re-review of this change), found no blocker and two
  SHOULD FIX findings that block the gate, S1 and S2, both missing tests; S3 is phase 1's, and
  cheap. Its verdict on this change: the gate passes. Tests, the simulator's oracle, comments, a
  Semgrep rule and the record: the code of the keys, protocol, index and engine crates is
  unchanged.
  - S1 (TM-10, TM-14, TM-32): every "not open" test used a folder the device does not hold, so
    none would notice `Connection::is_open` answering "held". The new test
    `a_folder_held_and_proven_but_not_open_is_refused_both_ways` (`connection/tests/handshake.rs`)
    opens one folder and leaves a second, which A holds and has proven, not open in three ways: B
    lacks it and answers REJECTED; B's answer to A's proof is lost; B's own proof is lost. For the
    second folder, each of IndexRequest, ReconcileRequest, a reply page, a push with one of its
    records, an empty push, ReconcileReply, ChunkRequest, ChunkReply, a Status naming it and one
    naming both folders closes `PROTOCOL_ERROR` (`Malformed`) with no event but the close, and
    each of `send_request`, `push`, `send_page`, `send_reset`, `send_reconcile_reply`,
    `chunk_position`, `request_chunk`, `reply_chunk` and `send_status` returns `FolderNotOpen`.
    Undo-checked: it fails, and no other test does, with `is_open` answering "held"
    (`self.folders.contains_key(folder)`; the inbound ChunkRequest is then served); with the
    inbound ChunkRequest's check, the inbound Status's, `reply_chunk`'s, `page_folder`'s,
    `send_reset`'s or `send_reconcile_reply`'s alone changed to "held"; and with `is_open`
    counting a folder open on either side's ACCEPTED alone. The two checks it cannot see are
    repeated ones: `on_chunk_reply`'s follows the unsolicited check, which refuses first since no
    request goes out for a folder not open, and `on_reconcile_request`'s is made again by
    `begin_serving`.
  - S2: the oracle's `Expect` has `refused`, the writes the engine refuses (0 by default), and
    `check_ledger` fails a run whose `Ledger::refused` differs ("N writes refused, not M"). Fewer
    writes still converge, so before this an engine that refused writes would have passed
    `clean`, `drops`, `reconnect`, `cross_reorder` and `chaos`, whose only check is the oracle.
    `engine-sealed-relay` expects 21, the default workload's seven writes for each of its read
    holders 1 and 3 and its sealed holder 4, in place of its own check; no other gate scenario
    gives a read or sealed holder a write (`engine-late-joiner`, `engine-chaos` and
    `engine-sealed-cleanup` give theirs no workload), so each expects 0. `Ledger::refused`'s
    comment says what it counts: every `WriteFailure` but `Paused` and `Store`, which are tried
    again. Test `a_run_with_a_write_refused_unexpectedly_fails_the_oracle`
    (`scenarios/engine.rs`): a read holder's one write fails the oracle expecting 0 or 2 and
    passes it expecting 1; with the check removed, the run expecting 0 passes.
  - S3 (TM-4): `no-follow-symlinks` also flags `Path::canonicalize` and `Path::read_link` called
    as methods (on a `Path`, a `PathBuf` or any expression) or by path
    (`std::path::Path::read_link(p)`, `Path::canonicalize(p)`), and, folding in the fresh
    reviewer's tested NIT, names the `std::fs`, `Path` and `PathBuf` forms as bare paths, so a
    function value such as `.map(fs::canonicalize)` is caught too; eleven more `ruleid` cases in
    `.semgrep/tests/project.rs`, nine of which the rule before this missed (the import forms
    `fs::canonicalize` and `fs::read_link` it already flagged). `symlink_metadata`, which does not
    follow, stays allowed, now in its method form too. Nothing in the workspace calls either
    today.
  - `gate.sh` passes: 656 tests, 1 skipped; line coverage keys 99.37%, protocol 98.32%, index
    97.66%, engine 96.94%. The 17 gate scenarios converge and pass the oracle on seeds 0 to 49 on
    the release simulator.
  - Reviewed 2026-11-02 by a67a2d4f536955fe3 (the phase 0 gate reviewer, security: its own
    findings S1 to S3 re-reviewed and undo-checked, and its NIT N12, the coverage figures, fixed
    here) and ac98c5b168abe9156 (a fresh review: one NIT, tested, folded in), both clean. Author
    aec20e1fe952da578; the merge agent wrote this line.
- The engine on the latest-only index, and the phase 0 gate: simulated peers converge.
  `licketysync-engine` now has `Engine` (`runtime::Peer`) and `EngineConfig` (device seed and folder
  keys given at every start, none stored, `keys.md` 8.2; at most `MAX_FOLDERS`, 256, folders, the
  most proofs one connection carries): one protocol `Connection` per peer, driven with a fresh
  `Tick` per call and every `Output` applied in order (frames, wake-up, events, close), every
  credentialed folder proven on connect and on every connection when it opens, and only the `Closed`
  outcome recorded once a connection has closed (the clock rule's events, which come in the output
  that closes it, are taken first). Every handler runs in three phases (`work.rs`): A decides
  (chunks judged and staged, the index exchange's events queued as index work), B commits
  (`sync/commit.rs`: one `licketysync_index::Txn` per folder with work, the local writes, the pages
  of records judged record by record with the connection's own memories and verification budget, the
  ends of rounds with their cleanups, the cursors, an epoch drawn for a reset, the chunk frees due
  and the bases of every path whose content is now on the disk; each change set staged with the
  handler's blobs, then one storage commit, then each transaction committed or, if the commit
  failed, dropped), C sends (judgements for every page, pushes of what is newly held to every
  connection but the one it came on, requests from the committed index, replies page by page under
  the send budget, the subtrees a `RECORDS` reply ends with), so durability comes before
  transmission (`protocol.md` 4.5); what phase C brings that changes the index (a round that ended,
  a cursor a counted push raised) waits for the next commit, a handler of its own at once, so a
  handler commits at most once. The exchange (`sync/`): rounds of Since and the root check with
  reconciliation, served from the committed index (`since_plan`, `since_page`, `reconcile_reply`,
  `records_page`, `push_pages`, `subtree_pushes`), with the rules kept from the old exchange: a
  record not judged is `Judgement::Skipped`, a reply whose page was skipped is void to its last
  page, no round of a folder held paused, resuming owes a round on every connection, and a
  connection is caught up only when its last round ended at `EQUAL` or after a quiet pass. A put or
  commit that fails rolls back and pauses every folder the handler meant to change (`pause.rs`): the
  dropped transactions undo it exactly, with nothing rebuilt; the folder judges no record (its pages
  answered skipped, TM-22), stores no chunk, refuses local writes, stays proven and serving, is held
  paused on every connection (`Connection::set_paused`: no round, its pushes not counted), and a
  resume probe (`e/probe`, every `resume_probe`, 1 s, staged for its handler's one commit) ends the
  pause and owes each connection a round, what the folder left waiting committing in a handler of
  its own at once; every other folder whose records the handler skipped is owed a round too. A
  handler whose change sets are all empty commits nothing. Storage layout (`store.rs`):
  `e/r/<f>/<record hash>` (the local sequence number, then the envelope as received),
  `e/b/<f>/<record hash>` for bases kept only as bases, `e/s/<f>/<path tag><place>` base slots,
  `e/m/<f>` (high-water mark, next local sequence number, epoch), `e/p/<f>/<device>` per-peer state,
  `e/c/<f>/<cipher hash>` and `e/h/<f>/<cipher hash>` markers, `e/f/<f>/<cipher hash>` the
  pending-free list, `e/probe`, and `w/` for the harness. At start each folder shows Checking while
  the index opens it (`open.rs`; `Index::create` for a folder with nothing stored), undecodable
  entries are counted (gap G6), one issue gives what the open found (records dropped, undecodable
  entries, a corrupt high-water mark, records numbered afresh, misplaced bases, at most 16 hashes),
  a store in which nothing passes is Misconfigured and never proven, one that cannot be read is
  Unreadable, and a folder whose records lie more than a year ahead of the clock is Closed until the
  time the open gave (4.4, "A clock set back"): not proven to peers (their proofs answered
  REJECTED), judging and writing nothing, with the clock-rule issue (`KeptClosed`) and the open
  report saying so (`OpenCounts::kept_closed`); every handler compares that time with the wall
  clock, and a timer looks at least once a minute, so it opens, its credential back, and is proven
  on every connection, once the clock passes it, a clock set right by a step forward included. What
  the open changed is staged with the folder's first transaction and kept until a commit carries it,
  so a failure there pauses the folder and loses nothing. The disk (`sync/disk.rs`): phase 0's disk
  is the bases the engine names to the index; a version is on the disk while every chunk it names is
  stored and has verified for it and its size checked (a chunk stored for another record it fails
  for puts nothing of it in place), and only then is it the base at its path (the first head in
  display order) or at a conflict copy beside it
  (`{path} (conflict {first eight hex digits of the record})`), so the old file stays until the new
  content is there and a local write made meanwhile is a conflict with the version still arriving; a
  path left with no heads (a tree delete's directory, or a path where one dropped records) has one
  slot, its own, holding the greatest, by record hash, of the tree deletes held at its tag
  (`PathView::trees`, new in the index), or none, unless its live records are all opaque, when its
  disk is left as it is (4.4; a stated residual below): a function of the records held, so every
  device that holds the same records keeps the same disk there whatever order they came in, a
  received record, a local write and a tree delete's own directory alike, and every other path
  beneath, a concurrent edit's say, keeps its disk; holding a tree delete reads nothing but the
  paths where it changed heads or cleared a slot, and their slots (holding it costs what it drops,
  however many files lie beneath it, TM-22). A conflict copy keeps its slot while its chunk is
  forgotten and loses it only once its record is no conflict copy; a new copy slot is added once its
  record is on the disk. Local writes (`write.rs`): fixed-size chunks sealed by the keys crate,
  `write_file`, `delete` (a directory's is one tree delete), `rename` (a put and a tombstone in one
  commit) and `mkdir` as `Change`s to the index, which builds vectors and names from the bases; a
  write over a conflict first turns each copy on the disk into an ordinary file at the copy's name
  (`Change::Promote`); refused up front for a read or sealed key, a pause or a bad path, and a
  write's blobs staged only once its records are signed. Chunks (`chunks.rs`, `transfer.rs`,
  `inflight.rs`): what a folder lacks is what `Index::wanted` names, every held record with chunks,
  conflict heads and opaque records included (an opaque record's chunk checked by its ciphertext
  hash and stored length alone, 4.7 item 5); per-record judging of each chunk (corrupt for that
  record alone and never fetched again, TM-13), the size check at reassembly, passes in ascending
  hash order with one request per hash across connections until its patience runs out, serving that
  reads the blob only as it is sent, `chunk_stored` on every connection for every chunk newly
  stored, a write's included. A stored blob is this device's own: before it is judged for any record
  its ciphertext hash is computed again, and one that changed or is gone at rest is forgotten,
  fetched again (or staged again by a write) and raises `LocalChunkCorrupt`, never a record's issue
  (TM-10); its deletion, with its marker, rides the next commit a handler makes anyway. A blob that
  cannot be read is only forgotten, fetched again and counted, and read again, hash-checked, on the
  free tick, so that its only holder serves it again. The chunks a change leaves unnamed
  (`ChangeSet::freed`) go on the durable pending-free list in its commit and are freed at the end of
  the next round on any connection where the folder is open, or once a minute while none is, each
  one a held record names again staying; an open finishes the list. The clock (`runtime.rs`,
  `Clock::wall_time_us`): counters come from the index's writer's rule over it, Hello's `clock_days`
  from it (`Config::new`), and a peer out of the clock rule is refused with an issue naming its
  device and both readings (`ClockOutOfRange`; a stranger's is only counted). Folder state
  (`folder.rs`): Checking, Misconfigured, Unreadable, Closed, Paused, Syncing (naming what it waits
  for), Up to date, with a bounded transition log that keeps Checking. Issues (`issues/`): a list
  naming a peer only for its own fault, a record never a device (ruling S-4), no path and no secret
  (TM-6), a counter per section 5 cause, closes counted per defined reason with one count for every
  number a peer invents (TM-22), each reason's slot found by its place in `CloseReason::ALL` rather
  than its wire number, since `CLOCK_OUT_OF_RANGE` (13) comes after 11, with a build-time check that
  the wire numbers are distinct; the informational issues of 4.7 item 7: the own-ID hint
  (`OwnCounterAhead`: a record under this device's ID above its high-water mark, a restored or
  cloned device), `ClockAhead` (a record more than a day ahead of this device's clock, with the lead
  and the device it claims), `FromTheFuture` (a record past the clock rule, refused, naming its
  device), `WriterFault { shared }` naming an opaque record (`shared` when every release finds it
  faulty, so that saving the file again clears it), `KeptClosed`; "still waiting" is gone; and a
  folder whose proof a peer refuses while 64 folders are open on the connection is counted and named
  in a local issue, as possibly the open limit. Pacing (`pacing.rs`): a 16 MiB send budget for reply
  pages and `CHUNK_OK`, polled every 50 ms. Timers (`timers.rs`): ids below 2^63 are the engine's,
  from a counter that never repeats; the harness's are ignored. Status (`status.rs`):
  `extra_versions`, `paused` for a folder held paused. Views (`inspect.rs`): `folder` (each record's
  state, cleanup flag, dot and chunks; `extra_versions`, `hw`, `folder_time`, the pending-free
  list), `files` (heads in display order, the current version, conflict copies, deletion, opaque
  records, bases; `Debug` without paths or copy names), `read_file` (any head; `ReadError` displays
  and is an error), `fingerprint` (the root set digest, then each path's heads), `high_water`,
  `dot`, `stored_blob`.
  - Bugs the reviews found and this fixes (each with a regression test named after it in
    `src/regressions.rs`): a blob changed at rest blamed its record and was never fetched again; one
    key holder could keep a hash from every other connection for ever; `closes_received` grew with
    every reason number a peer chose; a peer with only a device proof counted as proven and could
    evict key holders' issues; a pause that ended during a reply judged its later pages, closed the
    honest peer and blamed it; a failed handler skipped other folders' records silently, and a
    resumed folder read Up to date before its owed round; void pages arriving after a resume kept
    another connection's owed round from ever counting, so the folder read Syncing for ever; a
    storage read error deleted a good blob; the deletion of a changed blob took a second commit; a
    refetch whose commit failed left a blob changed at rest counted as stored and good. The rebuild
    after a failed commit, with the back-off of its probe (a recorded deviation from TM-22, now
    retired) and the guards against a folder made Unreadable after its open, is gone with the staged
    store it repaired. Found in the port and fixed, with tests named after them: the clock rule's
    events came in the output that closed the connection and were dropped with it, so no clock issue
    was ever raised and no stranger counted
    (`rules::the_clock_rule_issue_is_raised_though_the_close_comes_with_it`,
    `rules::a_stranger_out_of_the_clock_rule_is_only_counted`); a key holder judged an opaque
    record's chunk against a plaintext hash it was never given, found it corrupt and never kept it
    (`chunks::tests::a_key_holder_keeps_an_opaque_records_chunk_by_its_stored_length`);
    `licketysync-sim list` printed a heading line whose first word the nightly job took for a
    scenario (`cli::tests::list_starts_every_line_with_a_scenario_name_for_the_nightly`); the
    oracle's state digest left out every chunk on the pending-free list, so one named again while
    listed entered the state at the next round's end and the recheck failed (`engine-expiry` seed 6;
    `converge::a_pending_free_chunk_named_again_is_no_change_of_state_at_the_recheck`).
  - What the port's reviews found and this fixes, each with a test named after it that fails without
    it (`src/rules.rs` unless said): a folder kept closed by the clock rule opened only by a
    monotonic delay, so a clock set right by a step forward left it closed
    (`a_closed_folder_opens_when_its_wall_clock_steps_forward_without_monotonic_time`), was proven
    to peers against 4.4 (`a_closed_folder_is_not_proven_to_peers_and_is_proven_once_it_opens`), and
    raised no issue
    (`a_folder_whose_records_lie_more_than_a_year_ahead_stays_closed_and_opens_by_itself`); the
    gate's oracle never looked at the disk (check (b′) below); a received tree delete clearing the
    bases beneath it, and a failed commit reporting its held records skipped, were pinned by no test
    (`a_tree_delete_received_clears_the_bases_beneath_its_directory`,
    `a_failed_commit_reports_held_records_skipped_and_its_round_is_not_caught_up`); a version whose
    chunk fails for it counted as on the disk when another record kept the chunk (adversary test
    `a_version_whose_chunk_fails_for_it_is_never_on_the_disk_though_another_record_keeps_the_chunk`);
    a blob forgotten after a read error was never read again before a restart
    (`a_blob_forgotten_after_a_read_error_is_read_again_and_served`); a failure staging the open's
    changes paused no folder, and the resume probe committed apart from phase B
    (`a_failed_first_commit_pauses_the_folder_and_its_probe_handler_commits_once`); a reset for a
    folder held paused claimed a redraw that its dropped transaction never made (now claimed only
    for a folder that runs one; `a_paused_folder_serving_a_reset_claims_no_redraw`); holding a tree
    delete walked every path of the folder, 51 ms a tree delete at 20 000 paths, then (the first
    fix) every path and slot beneath its directory, 260 ms at 20 000 files it does not cover
    (`holding_a_tree_delete_reads_what_it_drops_not_the_twenty_thousand_files_left_beneath_it`), and
    cleared the base of a concurrent edit beneath it too, taking the old file away before the edit's
    content arrived and building the path's next edit from nothing
    (`a_tree_delete_leaves_the_disk_of_a_concurrent_edit_beneath_it_and_its_next_edit_covers_it`),
    or of a nested tree delete made at once, so two holders' disks differed by the order of arrival
    (`nested_tree_deletes_made_at_once_leave_the_same_disk_in_either_order`). And their confirms: a
    version whose chunk was forgotten after it verified (changed at rest, unread, rolled back) still
    counted as on the disk
    (`chunks::tests::a_version_is_ready_only_while_its_verified_chunks_are_stored`,
    `a_version_whose_chunk_a_failed_commit_rolled_back_is_not_on_the_disk`); a failed commit did not
    put back the paths its transaction had taken off those to apply, so a base stayed old for good
    (`a_failed_commit_never_leaves_a_paths_base_old_for_good`); a blob found changed when read again
    was only dropped, now changed at rest (`chunks::tests::reading_a_blob_again_checks_its_hash`,
    `a_blob_found_changed_when_read_again_raises_the_local_issue_and_is_deleted`); and tests for
    what had none: a folder kept closed that opens before the peer's proof arrives syncs on that
    connection
    (`a_closed_folder_that_opens_before_the_peers_proof_arrives_syncs_without_a_reconnect`), a page
    of duplicates commits nothing (`a_page_of_duplicates_commits_nothing`), and a version whose
    chunks do not add up to its size is not on the disk (adversary test
    `a_version_whose_chunks_do_not_add_up_to_its_size_is_never_on_the_disk`). And the third round's:
    two devices that deleted one directory apart each kept its own tree delete as the directory's
    base, so their disks differed with the same records
    (`two_devices_deleting_one_directory_apart_keep_the_same_disk`), as did nested tree deletes held
    in another order, by three devices or around a file at the inner path
    (`three_devices_holding_nested_tree_deletes_keep_the_same_disk`,
    `a_tree_delete_that_drops_a_record_at_a_nested_tree_deletes_path_keeps_the_disk_the_same`,
    `a_file_and_two_nested_tree_deletes_in_either_order_leave_the_same_disk`), and nested tree
    deletes arriving in one handler named one the other dropped as a base, an internal error
    (`nested_tree_deletes_arriving_in_one_handler_count_no_internal_error`): the rule above for a
    path with no heads fixes all four and replaces the clearing of slots by each tree delete held; a
    conflict copy lost its slot while its chunk was forgotten, so a write over the conflict did not
    turn it into a file
    (`a_conflict_copy_keeps_its_place_on_the_disk_while_its_chunk_is_forgotten`); a blob this device
    freed after a read error was found gone on the free tick and taken for one changed at rest,
    raising `LocalChunkCorrupt`
    (`a_blob_this_device_freed_after_a_read_error_raises_no_corruption`); every page, duplicates
    too, marked the chunk book for a full recompute, now only one that held or dropped a record
    (`a_page_of_duplicates_commits_nothing`); and a folder both devices kept closed by the clock
    rule, each refusing the other's proof, opened on the connection only because the device whose
    folder opens proves it on every connection
    (`a_folder_both_devices_kept_closed_opens_when_the_second_proves_it`). And the fourth round's: a
    local tree delete whose vector, pruned to 32 entries, misses a tree delete held beneath its
    directory cleared that one's slot and left it held without reporting its path, so that device's
    disk lost it there while every other kept it; the index now reports each slot a write clears
    among the write's paths
    (`a_local_tree_delete_with_a_pruned_vector_keeps_the_disk_of_a_tree_delete_it_leaves`, the
    index's `a_tree_delete_reports_the_path_of_a_slot_it_clears_and_leaves_held_r3_1`); a round's
    end whose cleanup expired the greater of two tree deletes held at a path reported no paths, so
    that device left the path with no base while one that expired it accepting the cleanup made the
    other its base; `Txn::end_round` now reports the paths of what its cleanups drop, sorted and
    each once as a write's
    (`a_rounds_end_cleanup_that_expires_the_greater_tree_delete_leaves_the_other_as_the_base`, the
    index's `a_rounds_end_reports_the_paths_of_what_its_cleanup_expires_s3_c`); and the chunk book's
    two marks that no test held now have one each: a write's, for a rename that stages no blob
    (`a_write_that_stages_no_blob_has_its_version_judged_in_its_own_handler`), and a page's that
    only drops, a record that replaces one held but that a held tree delete covers
    (`a_page_that_only_drops_a_record_stops_wanting_its_chunks`). The index's
    `Txn::clear_bases_beneath` and `Index::paths_at_or_beneath`, which the engine stopped using, are
    removed with their tests.
  - Runtime contract (`runtime.rs`): `Clock::wall_time_us`, the wall clock in microseconds, by
    default `wall_time` times a million (a runtime with a finer clock gives it);
    `Clock::wall_time`'s doc no longer speaks of expiry; `Randomness`'s doc names the secrets and
    nonces drawn through it; `MAX_SEND_QUEUE` is
    `pub use licketysync_protocol::limits::MAX_SEND_QUEUE` (one definition, `protocol.md` 5).
  - Simulator: `world.rs` (seeds and keys per peer from fixed bytes, clones), `member.rs` (the
    engine plus a scripted workload on the harness timer, its step committed with the engine's
    write; the shared `Ledger`, which also keeps each member's high-water mark after every handler
    and the counter of each record it wrote, over every instance; a member can be cut from peers it
    never meets), `oracle.rs` (a cheap predicate over the root digest and heads, and the full check:
    (a) the same record hashes on every member, (b) the same paths and heads, no opaque record, (b′)
    what every read and write holder has on its disk matching its heads, each path's base its first
    head, each conflict copy in its copy slot, no base at a path without heads but a tree delete's
    own (nothing beneath a tree delete keeps a base unless live), the same on every one of them,
    every path checked ((b) refuses opaque records in every gate scenario, so (b′) needs no
    carve-out; a future scenario that plants them must make (b′) skip each path with no heads and an
    opaque record, the 4.4 residual below, where the engine keeps such a path's disk), (c) every
    head reassembled to the ledger's bytes, every stored blob named by a held record or pending its
    free, and every sealed blob checked, (d) only the issues a scenario expects, no blaming close,
    no internal error, every start shown as Checking, and no high-water mark that fell and no
    counter given to two records, over every instance; a stored chunk no held record names, which
    waits on the pending-free list for a round, is left out of the state digest, and one named again
    is in it at once), `Run`'s probes (looks taken on the way), `Fault::ClockStep` (a wall clock set
    forward, with its trace event), and seventeen gate scenarios plus `engine-drops-stress`, all
    listed by `licketysync-sim list` one name to a line: the toy's eight engine counterparts
    (`engine-clean`, `engine-drops` at the gate's drop rate of 0.1, `engine-reconnect`,
    `engine-cross-reorder`, `engine-partition` with its cut from 45 to 65 s so that both sides edit
    over versions on their disks, `engine-crash`, `engine-disk-full`, `engine-chaos`), `engine-skew`
    (5 min, 1 h and 23 h ahead, no clock warning) and `engine-clock-ahead` (two days ahead: the
    warning, and convergence), `engine-sealed-relay`, `engine-late-joiner` (back with per-peer state
    after 360 records, at least five Since pages of 64 on one connection), `engine-pacing`,
    `engine-clones` (concurrent heads under one device ID, one conflict at the shared path, the
    own-ID hint at both clones, nobody blamed; peer 0's last file moves to about 31 s and peer 5
    writes once more at about 45 s, so that each clone receives a record under its ID above its
    mark), `engine-tree-delete` (a directory of 200 files deleted while a file in it is edited and a
    third member deletes a directory in it, and another directory deleted by two members apart: the
    edit its only live content, the four tree deletes held, the same disk on every member),
    `engine-sealed-cleanup` (a sealed peer back after V1 to V3 holds V1 and V3, then drops V1 at a
    write holder's round-end cleanup), `engine-expiry` (a tombstone past the deletion horizon in
    folder time forgotten by every key holder, and the old file brought back by a device that kept
    it).
  - The gate (`crates/engine/tests/converge.rs`): one test per gate scenario over seeds 0 to 4
    (`LICKETYSYNC_ENGINE_SEEDS` for another count), the seeds on threads of their own, and the proof
    for gap G2 (a crash-and-restart run twice in one process replays exactly). Every gate scenario
    converges and passes the oracle on seeds 0 to 299 (`engine-drops` too, at 0.1);
    `engine-drops-stress` (0.2) converges on none of seeds 0 to 9 within 600 s, its connections
    dropping faster than a handshake and a first round get through (the engine before the port: one
    in ten). R1's four mutants of the disk model (no copy bases, a path base that never moves, no
    clearing beneath a received tree delete, no disk applied at all) each fail the gate scenarios.
    The nightly job runs `engine-late-joiner` for 100 seeds and every other gate scenario for 300,
    about 25 minutes at the per-seed times measured in release on the idle development machine (4.3
    s for late-joiner, 1.3 s for clean, 1.1 s for pacing, 1.2 s for the other fourteen together).
    The test profile optimizes the dependencies (`[profile.dev.package."*"] opt-level = 3`, the
    workspace's own crates not, so coverage is measured as before): the gate took 389 s and 41
    CPU-minutes without it, 185 s and 21 with it.
  - Tests: unit tests over fake contexts (`src/tests.rs`, `testkit.rs`) and per module;
    `src/rules.rs`, one test for each rule of `protocol.md` 4.7 the others leave (the pending-free
    list freed at a round's end, within a minute with no connection, kept when named again, and
    finished at open; a version still arriving left a head beside a local write with the old file in
    place; a write over a conflict promoting its copies; the clock rule, a record from the future, a
    folder kept closed that opens by itself, unproven meanwhile, after a step of the wall clock too;
    a tree delete received clearing the bases beneath, and a path with no heads keeping the same
    tree delete on every device whatever the order; a conflict copy keeping its slot while its chunk
    is forgotten; a blob freed after a read error raising no corruption; a folder both devices kept
    closed opening; a failed commit reporting skipped; a blob read again after a read error; the
    open's changes and the probe's one commit); `src/regressions.rs`; integration tests:
    `adversary.rs` (a flipped body and another folder's key are forged; a counter jump is no gap; a
    garbage seal is opaque and its chunk kept; a chunk that will not open and a wrong stored length
    are corrupt for their record, and a version whose chunk another record keeps is not on the disk;
    an unsolicited reply and too many chunk requests close; a write holder under an honest device's
    ID is equivocation, concurrent heads and the own-ID hint, nobody blamed; a record naming a chunk
    nobody holds is held and waits with no issue; a page of forged records at the deepest path costs
    a read holder one bounded check and closes; a replayed expired tree delete is ignored,
    unverified at a read holder and noted by a write holder; a sealed peer replaying history grows
    another only by genuine records, until a cleanup; a sealed peer that takes chunk requests and
    never answers pins no hash), `outsider.rs` (REJECTED, `NO_COMMON_FOLDER`, nothing of folder A
    crosses, folder B syncs over the same connection), and `converge.rs`. Line coverage as the gate
    measures it (lines): keys 99.4%, protocol 98.3%, index 97.7%, engine 96.9%.
  - Decisions for the plan: fixed-size chunks in phase 0 (FastCDC is phase 1), 1 MiB by default;
    engine timer ids below 2^63, the harness's from 2^63; no secret in storage in phase 0; the
    storage layout above; durability at the handler's one commit, the index's transactions committed
    after it or dropped if it fails, and index work from phase C deferred to a commit of its own at
    once; a store-failure pause keeps the folder proven and serving (G4), ends on a probe every
    second and owes a round (G3), with no back-off, since nothing a peer does costs a check of every
    stored record any more; the void rule kept, and beside it its residual: on a nearly full store,
    a large genuine record that fails to store voids the rest of its reply, so forged records in the
    reply's later pages go unjudged and unblamed (nothing of them is stored or served, and the owed
    round judges them again); Checking is synchronous in `on_start` in phase 0 (G5); undecodable
    stored bytes count toward Misconfigured (G6); phase 0's disk is the bases, a version on it once
    every chunk it names is stored and has verified for it and its size checked, and a path with no
    heads holding the greatest tree delete held at its tag, or nothing; a conflict copy's name is
    the path, then ` (conflict `, the first eight hex digits of its record hash and `)`; Unreadable
    only at the open, never retried within an instance; the wall clock in microseconds through
    `Clock::wall_time_us`, whole seconds by default (a deviation in resolution only: the simulator
    and the fake contexts tick in seconds); NFC is the caller's duty in phase 0 (G8); the engine
    does not replay `protocol.md` section 8's connection vectors byte for byte, since its frame
    timing differs, and tests the engine-owned outcomes instead (G12); a config holds at most 256
    folders (`MAX_FOLDERS`), but a connection opens at most 64 (`MAX_OPEN_FOLDERS_PER_CONNECTION`, a
    proof past them answered REJECTED with no retry, and one connection per peer), so a device that
    shares more than 64 folders with one peer syncs only 64 of them with it, each refusal counted
    and named in a local issue that names no peer and stays for the instance (follow-up for the
    protocol spec: raise the limit or allow more connections); the Issues list keeps four classes
    that never evict each other's entries, each repeat merged with a count and whatever a bound
    keeps out counted in its class's overflow (TM-22, TM-10): local folder health (one entry per
    folder and kind; `MAX_LOCAL_ISSUES` = `MAX_FOLDERS` × 12), remote records (at most 16 per
    folder, the oldest evicted), peers that proved a key of a folder this device holds (at most 16,
    the oldest evicted; the residual: a key holder minting device IDs can evict other key holders'
    entries, counted), and every other peer (one entry per cause); a hash asked of one connection
    may be asked of another once it has waited twice the Status interval (60 s) with no answer, the
    slow request staying outstanding and a late chunk dropped and counted; `free_disk_bytes` 0; a 16
    MiB send budget and a 50 ms poll; pushes are not budgeted; issues never carry paths; a restart
    judges every wanted stored chunk again, once; a member cut from a peer stands in for a partition
    that would never end; the engine scenarios' time: a chunk pass that met a `CHUNK_NOT_FOUND`
    waits for a trigger evaluated at most once per `STATUS_INTERVAL` (30 s, 4.6), so in a five-peer
    mesh writing at once every chunk is on every disk some 35 s in, and a scenario whose edits must
    be made over versions on the editor's disk makes them after that.
  - Spec questions raised: rounds start only at open and when owed (4.5), so on a connection whose
    rounds all ended caught up the pending-free list (4.7 item 1) and a write holder's notes of
    stale copies pushed to it (case (b)) wait for the next round, which may not come before a
    reconnect: should a write holder owe a round when it notes a copy, and should frees also run
    once a minute while no round is under way? And should a `ChunkRequest` have a reply deadline?
    And a folder that becomes provable during a connection (one kept closed by the clock rule,
    opening): it is proven on every connection, but a peer that proved it there already, and was
    answered REJECTED, does not prove it again (3.5), so it opens with that peer only on the next
    connection; should a late ACCEPTED, or a repeated proof, open it?
  - For phase 1 (the security review's notes): every handler that runs a folder's transaction
    applies every path still waiting for its chunks again, on top of the chunk book's full recompute
    (round 1's #8), so a folder with many such paths pays per page and per chunk; and a counted
    push's cursor is committed in a handler of its own, so small pushes can each cost a commit:
    coalesce cursor writes when the store makes a commit costly. And (the third round's ruling) a
    concurrent tree delete held at a tag but not its base is not covered by this device's next tree
    delete there; it stays until a cleanup or its horizon. And, for the owner's review (the fourth
    round's S3-A, kept as the spec's carve-out, no spec change in phase 0): a path whose live
    records are all opaque keeps whatever its disk had (4.4, "leaves the path on disk as it is",
    never removing what the device cannot judge), so two devices that held the same records in
    another order can differ there; should such a path follow the rule for a path with no heads?
    The oracle's (b′) needs no carve-out for it, since (b) refuses opaque records in every gate
    scenario; a future scenario that plants them must make (b′) skip each path with no heads and an
    opaque record. And the identical-heads fix's two (its entry, "For phase 1", 2026-11-08): modes
    between concurrent twins, and the cost of finding twins beside TM-22's bounds.
  - Dependencies: none new; the engine depends on the workspace's keys, protocol and index crates,
    dev-depends on the simulator and `proptest`; the simulator depends on the keys crate;
    `ci/geiger-baseline.txt`'s `engine` and `sim` lines now count the keys crate's dependencies.
  - Reviewed 2026-10-25 to 2026-11-02; every finding fixed, every reviewer clean. First review: R1
    acf6ea7dba91f39c4, R2 a4f2f0d74454fa1c9, security adcf4c0407088278e. Confirms (correctness,
    security): ac5dd0f5520c255dc, ae2833fe6dcdb51d0 (round 1); a1fe4c708a703b44c,
    a687b7d0e9e815b1a (rounds 2-3); a26a5d8d6929e1725, ac33792ec54cf90db (round 4), the last check
    clean on 3797195. Author ae57b9dfb714d8e6f; the merge agent wrote this line.
- The protocol and index crates on the latest-only index of the commit before (`protocol.md` §4.4
  to §4.7), and the keys crate's retired layout removed. On main the engine is the runtime only and
  the simulator depends on nothing of these crates, so both are unchanged; the engine's port
  follows (`wip/engine`), against the index API of brief R1 to R14.
  - The protocol crate (`licketysync-protocol`):
    - Records (§4.4): `Record` is an index record or a cleanup past step 1 (the envelope as
      received, its record hash, its clear fields typed: `path_tag`, `replaces`, chunks, or the
      cleanup's groups; its 64-byte key in the set digests, the path tag then the record hash, a
      cleanup's record hash twice; its decoded body is crate-private). `Record::verify` is step 5
      under the label of its type; `Record::open` is step 7 for read and write holders: the seal
      under its aad, the metadata, the path and its tag, the dot, the vector and the deletion marks,
      one `WriterFault` variant per check, the `kind` after every check that does not depend on it
      and before the two that do, so that a record opaque only for an unknown kind is told apart
      from a shared writer fault (`WriterFault::is_shared`), pinned by a row per later
      kind-independent fault (the review's P-1). `Dot`, `Vector` (coverage reads one entry), `Meta`
      (`written_at` in microseconds since the Unix epoch), `Applied`. `IndexDraft` and
      `CleanupDraft` encode, seal and sign what the index decided and run a reader's steps 1 and 7
      on the result before returning it, so a writer never emits what a reader refuses.
    - Messages and decoders (§3.2, §4.1, §4.2, §4.5): Hello `clock_days` (at most 2 097 151) and
      `CLOSE_REASON` 13 `CLOCK_OUT_OF_RANGE`; `IndexRecord` (fields 1, 2, 3, 12, 13, 15, 17),
      `SealedMeta` (1 to 12, lax on what step 7 judges: entries past the 33rd are skipped),
      `CleanupRecord` (at most 16 384 names across its groups, pinned at 16 385 over two groups,
      P-4), `CleanupGroup`, `CleanupMeta`, `VectorEntry`; `IndexRequest` with `epoch` and `since`;
      `IndexRecords` with `epoch`, `through` and `reset`; `ReconcileRequest` (a prefix of up to
      128 nibbles) and `ReconcileReply` (0x800B, 0x800C); `FolderStatus.extra_versions`. `Cursor`,
      the range and listed scopes and the round split are gone; 0x8006 and 0x800D to 0x800F are
      reserved.
    - The exchange (§4.5): `Prefix` (0 to 128 nibbles of a record's key, packed two to a byte, 65
      bytes), the three conditions of a reply (`reconcile_outcome`), `IndexView`, pages with `epoch`
      and `through` and `reset_page`. On a connection: rounds of Since, then the Check and up to
      four passes of reconciliation over the trie with a depth-first work list (at most 1 921
      prefixes) and `MAX_PASS_REQUESTS`; quiet, cut and skipped passes, a round that skipped a
      record never caught up (P-2); resets and the epoch redraw at most once per connection, a
      second claimed one refused (`SendError::RedrawSpent`); `RoundCompleted { caught_up, cursor }`;
      the counting of pushes into the cursor (`CursorAdvanced`), stopped by an empty push, a push of
      another epoch, which owes a round (P-3), or a skipped record, pushes numbered
      (`Page::Push { push }`) so that a judgement finds its own pending entry, and a judgement that
      finds an earlier entry still waiting stops the counting (it fails closed), while one whose
      entry was forgotten leaves the later ones, at most `MAX_PENDING_PUSHES` (4 096, in `limits`)
      waiting; the round owed (`owe_round`) and `set_paused`; one request per folder each way across
      both kinds; `INDEX_REQUEST_MIN_INTERVAL` for `IndexRequest`s and root `ReconcileRequest`s
      only; every sender violation of a reconciliation; the pushes of what a `RECORDS` reply lacked
      (`PushSubtree`); the reply deadline and its restarts; no `through` above `MAX_LOCAL_SEQ` ever
      sent (`send_page`, `send_reconcile_reply` and `push` refuse it, the review's IS-3); the
      connection's memories (ruling Q3): `FolderMemory`, per folder, the records from the future
      refused on it, and one `NoteBudget` for the connection, move-only (neither `Clone` nor `Copy`)
      and made only by the connection (and `NoteBudget::for_tests`, hidden),
      `MAX_NOTE_VERIFICATIONS` per window of `INDEX_RESYNC_INTERVAL` across every folder open on it
      (`Connection::memories_mut`, the coordinator's ruling PS-1); and the clock rule when the first
      folder opens (TM-40), both sides closing before anything of the folder crosses
      (`ClockOutOfRange`, and `StrangerClockOutOfRange` for a connection that opened none, counted
      also when the transport drops, `Connection::disconnected`). `Config::new` takes `clock_days`.
    - Rules and limits (§5): one `Cause` per row, 30, among them Expired, Obsolete, Replaces held
      records, Cleanup group waiting, From the future, Clock out of range, Reset, Digest differs,
      Own counter ahead, Counter ahead of the clock and Counter exhausted; the six rows of the
      cursor exchange gone. Every constant of §5's "Time" table defined once, with the horizons in
      counter units (microseconds) and the clock rule in days and in microseconds; `KEY_BYTES`
      (64) and `MAX_PREFIX_NIBBLES` (128).
    - Vectors (§8 items 1 to 5, 10, and the decoder vectors of 6, 8, 9, 11, 12 and 13): canonical
      index records and a cleanup with their sealed parts and aads, every step-1 variant of both
      record types, every writer fault inside the seal beside the edge it is checked against, and
      the forged cases; the `IndexRequest`, `ReconcileRequest` (128 nibbles accepted, 129 bytes
      malformed), `ReconcileReply` and `IndexRecords` decoder vectors, `exchange.json` naming the
      two `through` cases the connection judges; Hellos with `clock_days` and the largest Hello
      (2 587 bytes, 2 591 with its length field); Status with `extra_versions`. The seal nonces of
      the record vectors begin with a zero byte, so the fuzz seeds they write stay binary to the
      typos check. Connection vectors are the engine's (§8, "Who checks what"); the connection's
      unit tests cover rounds, passes, quiet, cut and skipped passes, every sender violation
      (more than 64 records at a 64-nibble prefix answering a digest that is not zero among
      them: only a full key may carry more), resets, counting (pushes with `through` 0
      uncounted, an empty push uncounting what waits, a judgement out of order stopping it, the
      bound on waiting pushes), the round owed, one request at a time (a request ID reused
      across folders closes, messages for a folder not open close, a page after the last page
      is malformed), which cursor a round keeps, the serving interval, the reply deadline, the
      note budget across folders and windows, and the clock-rule close, with a toy index in the
      testkit; property tests that a pass never sends more than its cap and its work list never
      passes 1 921 whatever the responder answers, that every message round-trips, and that a
      draft never emits what step 1 or step 7 refuses. The committed proptest-regressions seeds
      are two failures of the pass-bound property shrunk during development; the named pass-cap
      tests cover the same bug.
  - The index crate (`licketysync-index`), written anew (`heads.rs`, the cursor digests and the
    waiting records are gone):
    - `Index`, `Txn` and `Pending` (rulings Q2 and I-8): every change of an engine handler is
      staged in one transaction over an undo log; `Txn::finish` gives the `ChangeSet` to persist
      in its one commit and a `Pending` that keeps the index borrowed until the commit's outcome
      is known, `Pending::commit` keeping the changes and dropping it undoing them exactly,
      nothing rebuilt, so the committed index never serves what is not yet durable; the
      handler's own reads see its staged changes (`Txn::index`, the whole index, its serving
      methods included), and serving only after the commit is the engine's duty; on any error a
      method returns, the handler drops the transaction. `Index::create` returns the change set
      that persists the first epoch (I-9). `Store`, `Stored`, `ChangeSet` (puts with local
      sequence numbers, removals, records kept only as bases, base slots, metadata, per-peer state
      and the chunk hashes freed) and `MemoryStore`, which can also refuse every commit or crash
      between a change's records and its removals, writing the base slots with the metadata as a
      store that cannot stage atomically does (the spec's twelfth fixup); such a store is reopened
      before its folder resumes after a store failure.
    - Arrival (`Txn::accept`, steps 2 to 9): a duplicate is ignored unverified; at a read or
      write holder the seal is checked first, then expiry (before anything the record replaces is
      looked at, the review's IS-1(a)); a record that replaces nothing held and that something
      held names or covers is obsolete; both ignored unverified unless a write holder would note
      it, which verifies it first; a record from the future is verified, refused and remembered
      on the connection; everything else is verified, then held, held opaque or dropped at once
      beneath a tree delete, dropping what it replaces, the groups whose `because` it is then
      applying. `Accepted` gives the judgement, the rows, the records dropped, the paths whose
      heads changed, whether the chunks wanted changed, the local sequence number and the issue
      inputs, and why a record a write holder would have noted was not (`NotNoted::PeerNames`,
      `NotNoted::Verifications`, the review's N9).
    - Latest only (§4.4): coverage between applied records only, by tag and beneath tree deletes
      (covered only by later tree deletes); names at the tag; cleanup groups that act only while
      their `because` is held, with no memory of having acted; the sealed-peer rule; expiry by the
      folder's own time `G`, strictly more than the horizon, tombstones and tree deletes after 365
      days and cleanups after 30, records kept only as bases included; opaque records held,
      counted and served, covering nothing, going only by a name.
    - Judging a tree delete without a walk (the coordinator's ruling IS-1(b)): per device, the
      applied records held in an AVL tree by path with least counters (`bypath.rs`), so that a
      tree delete is judged with at most two queries per vector entry, `O(L log n)` each for paths
      of `L` bytes, whatever lies beneath its directory (the runs compared in place, no path
      copied), and holding it costs `O(log n)` per record it drops, at open as
      on arrival and in a local tree delete. Whether a record lies beneath a held tree delete
      that covers it is found in one pass down a trie of the held tree deletes by path component
      (`dirs.rs`), `O(L)` for a path of `L` bytes up to the logarithm of the trie's fan-out (the
      spec's thirteenth fixup).
    - Writing (`Txn::write`, `Change`): `S` from the path's bases, never a tree delete, at most the
      vector cap, its own records first; the vector its join pruned with `S`'s devices mandatory
      (a vector that could not be one refuses the write rather than falling back silently); the
      names `S`, then the shared writer faults no held cleanup names, then the noted stale copies
      the vector covers, up to 64, while their peers are within `MAX_PEER_NAMES` (writes and
      cleanups counted together, N10), the faults left over in a cleanup `because` the write;
      renames, tree deletes with the tombstones their pruned vector leaves, one per path of the
      kind of the base at the path itself (the review's IR-3), and their cleanup; conflict copies
      made ordinary files (`Change::Promote`); consecutive counters from one reading of the clock
      in the writer's order; `written_at` the clock in microseconds; each record the base of its
      path. Bases (`Txn::set_base`, `Index::current`, `Index::bases`), kept only as bases once
      replaced.
    - Stale copies and the end of a round (`Txn::end_round`): notes made only after the signature
      verifies, never of a record a held record names at its tag or a held cleanup names in any
      group, at most `MAX_STALE_KNOWN` (the oldest dropped first), within the connection's
      `MAX_NOTE_VERIFICATIONS` and the peer's `MAX_PEER_NAMES`; at a round's end every note, from
      any peer, judged again and named in a group `because` what replaces it then, or with
      `because` empty for a forgotten record, paged by `MAX_CLEANUP_GROUPS` and
      `MAX_CLEANUP_ENTRIES`.
    - Set digests (§4.5; the coordinator's ruling IS-2): a 16-way trie over the records' 64-byte
      keys down to 128 nibbles, whose nodes cache their digests; the leaf form begins at the
      shortest prefix whose subtree holds at most 64 records, beneath a file ID by the record-hash
      nibbles, so a change rehashes one leaf of at most 64 record hashes (65, spread over new
      leaves, when a subtree splits) and at most 128 nodes, however many records one file ID
      holds. Serving from committed state, lazily: Since replies page by page, `ReconcileReply`
      from the cache, and `RECORDS` pages in ascending key order from the last key sent (the
      spec's fifteenth fixup, CR-1): the subtree is a range of the trie's keys, so a page reads
      the keys it sends and the one that did not fit, `O(page · log n)`, in constant memory, with
      nothing sorted, cached or held between pages; pushes with `through`, a reconciliation's
      pushes without; `IndexView` for the connection. A change rehashes its path in one walk of
      at most 129 levels.
    - Opening (§4.4 "Opening a folder"; TM-9): every stored record and base kept only as a base
      checked again across the cores, the same on any number; held again in its stored order, a
      record another stored record replaces dropped without a report (the ordered crash
      repaired); two stored copies of one record taken as one, at the first of their numbers;
      stored local sequence numbers of 0, above `MAX_LOCAL_SEQ` or repeated, or a next
      one past `MAX_LOCAL_SEQ + 1`, renumbered from 1 in stored order under a new epoch and put
      again (`OpenReport::renumbered`, the review's IS-3), and dropping a record removes only its
      own sequence entry; the high-water mark checked; a stored base whose record lies at another
      file ID dropped and reported (`OpenReport::misplaced_bases`); per-peer state clamped to the
      clock, capped at `MAX_PEER_STATES` and dropped past `PEER_STATE_HORIZON`; a new epoch once
      if anything was dropped; and a store whose newest applied record lies more than a year ahead
      of the clock kept closed (`OpenReport::opens_at`), nothing removed for its counter.
    - Views (R10 to R12): heads in display order (one ordering function for heads and `S`) with
      conflict copies, opaque records and the tree deletes held at the path's tag
      (`PathView::trees`, added with the engine, ascending by record hash), record views, file
      content, `wanted` chunks per tier, `names_chunk`, `extra_versions` (heads beyond one per path
      at a key holder, every head counted, records beyond one per file ID at a sealed holder), and
      the fingerprint the simulator compares. `Index::bases_beneath(dir)` gives the base slots at or
      beneath a directory read-only, in path order, each with its base record's path, its place and
      its record, whether or not the path has heads, so that the engine's oracle can see a base
      without a head, from a path-ordered index of the slots: two ranges by path (`dir` itself, then
      `dir/` up to `dir0`), never a walk of every slot (TM-22; the engine port's security review,
      EP-S1); the root, `""`, is every slot. (The range over the paths beneath a directory and
      `Txn::clear_bases_beneath` that this commit first carried went with the engine commit that
      orphaned them: the engine holding a tree delete reads only the paths where it dropped
      records.)
    - Tests: the index's vectors of §8 item 6 (`outcomes.json`, a forged writer fault among them),
      item 7 whole (`heads.json`: every case that shows a write holder's heads checked on a read
      holder, the display-order pairs on a write holder too; the tree delete over 20 000 held files
      judged by the index with at most two queries, the held records it reads while judging metered
      and far below the files beneath (CS-1), and the same verdict as a walk, the one at `d` beside
      `d-x`, `d.x`, `d0` and `d/x`, the one covering only an earlier tree delete; expiry at exactly
      the horizon; the open-time check of the stored mark), item 8 (`digests.json`: 65 records at
      one tag, a 128-nibble prefix, a cleanup's key, 8 000 records at one tag held and dropped by
      one cleanup with each change's cost counted) and item 12 (`cleanups.json`: a waiting group
      whose `because` names nothing, the replayed old tombstone to its end, named again and the
      version back, I-1); properties (a) to (m) over random histories by five writers, a reader and
      a sealed peer at every tier, half of them lines of versions through more writers than the
      vector cap, lowered to 2 and 3 (ruling Q7): no change drops what nothing explains (f, at every
      tier), (k) against the bases at the path as `bases.py` states it, (l) the index by path
      against a walk, (m) the cached digests against fresh ones, and, at every step, a dropped
      transaction giving back the whole state, then K2 on every device, every store opening to what
      memory holds and strict K3 (IR-6); drops by expiry checked against the horizon by the folder's
      time after the change, and (e) run with the history's one shared clock ((d) is the test of
      clocks apart); run from a fixed seed, 12 cases each for the histories, 64 and 48 for the
      structures against their definitions and 24 for (m) on the index, in the gate,
      `PROPTEST_CASES` and `LICKETYSYNC_PROPTEST_SEED=random` for longer runs (IR-4); the index by
      path and the trie of tree deletes against definitions (`structures.rs`, the 4 096-byte path
      walked once); the views (I-2), the write refusals (I-3), the lowered bounds reached
      (`bounds.rs`, I-4), `RECORDS` pages by key at 1-, 2- and 3-nibble prefixes and below the root,
      across page boundaries at page sizes of one record and the default, with the keys read per
      page bounded (CR-1, CR2-1), over records that share file IDs and over cleanups, at 63 to 66,
      127 and 128 nibbles, with records held and dropped between pages (FC-2), and over one-record
      pages at the 64- and 65-nibble prefixes of one file ID holding 300 records (item 8's case of
      the fifteenth fixup); a reconciliation's pushes kept to their subtree (FC-2);
      `Index::bases_beneath` with heads and without, at the root and beside `dir-x`; the base slots
      beneath a directory among 20 000 metered, read by range and equal to what a walk finds
      (EP-S1); a round's cleanups paged by groups alone; one test per rule the review's IR-1 named,
      and regressions named after the findings
      (`cleanup_group_acts_only_while_its_because_is_held_r1_b1`, `the_lost_update_r1_b2_s1`, the R2
      S-B step-7 vector in both orders, `expiry_by_the_folders_own_time_b1`,
      `a_stale_copy_is_verified_before_it_is_noted_c1_sc1`, the SC-2 and SR-1 cases, the IS-3, IR-3
      and IR-5 tests). The committed proptest-regressions seeds are failures shrunk during
      development, replayed first; their strategies have moved since, so they stand as extra cases.
    - Found by these tests and fixed here: a Since reply with nothing to send built an empty range
      whose start passed its end, which panics
      (`a_since_reply_with_nothing_to_send_is_one_empty_page`); a note was named only at the end
      of a round with the peer that offered it, while §4.4 (b) names every note at a round's end
      (`a_note_from_a_peer_that_never_ends_a_round_is_named_at_another_peers_r7`); per-peer state
      made by the names count at a round's end carried no round end, so the next open dropped it
      (`per_peer_state_made_by_a_names_count_survives_a_reopen_round_ended_us`); undo did not
      restore the note number; and the index by path took an empty run for a match at a counter
      of `u64::MAX`.
  - The keys crate: what the commit before kept for one commit is removed: `seal_meta`,
    `open_meta`, the old `MAX_SEALED_BYTES` and `MetaError::TooShort` (`MetaError::is_malformed` is
    now `SealedLength` alone), `WriterDigest` and the crate-private `HASH_WRITER_DIGEST` (so
    `labels::REGISTRY` lists every label in use), the writer-digest entries of
    `index_record.json`, and `bytes::join3`, which only the old aad used. `RecordKey` and
    `DataKey::record_key` are crate-private; `Malformed::RecordType` reads "record type N is not
    the type being signed or read"; `MIN_SEALED_BYTES` is documented as the nonce and tag a seal
    adds; the gear table uses its imported hash function, and the crate and folder docs name
    `RecordKeys` (the reviews' K-8).
  - Fuzzing (TM-3): `index_record` takes both record types through step 1 and step 7 for a write
    holder; `index_records` the new page fields with its decoder-agreement check; `sealed_meta` the
    new fields, sealing what parses at its own path and opening it through step 7;
    `sealed_meta_open` the one reader under both aads (its old-layout seeds deleted);
    `message_parse` the 13 message types and `CleanupRecord`, `CleanupGroup`, `CleanupMeta` and
    `VectorEntry`; `hello_check` checks `clock_days`; `handshake` drives the new exchange, its six
    seeds that start inside it written and checked by `vector_exchange_fuzz_seeds` (the review's
    PS-3) through the one harness both include (`vectors/handshake_harness.rs`); `reconcile` checks
    the prefix and children rules of both reconcile messages; and the new `index_ops` drives the
    index itself (the index security review's NIT 9): an index opened from fuzzed stored state at
    every tier, fed signed, forged and garbage records, writes, bases, round ends, crashes and
    reopens, asserting exact rollback, the same index after a reopen and the local-sequence bound
    and order, its nine seeds written and checked by `vector_index_ops_fuzz_seeds`;
    `fuzz/Cargo.lock` adds only the workspace's own index crate.
  - Decisions for the plan (the author's, for review):
    - The index API is a transaction overlay over an undo log, finished into a change set and a
      `Pending` that keeps the index borrowed until the commit's outcome (Q2, I-8): the engine's
      decide, commit and send phases. The borrow checker keeps everything outside the handler from
      reading or serving the index until then; the handler's own reads (`Txn::index`) see staged
      state, serving methods included, so sending only after the commit is the engine's duty, not
      the types'.
    - Base slots are keyed by file ID and place, `(PathTag, Place::Path | Place::Copy(name))`,
      persisted as their own list in `Stored` and `ChangeSet` (Q8 said "with the store's
      metadata"; a store that cannot stage atomically writes them with the metadata).
    - Tombstones carry the kind the caller gives (the deleted version's), size 0, mode 0; a
      rename's tombstone takes the new version's kind; a tree delete is kind 2 (directory), size
      0, mode 0; the tombstones a pruned tree delete leaves take the kind of the base at the path
      itself.
    - The wanted set at a key holder is every held record with chunks, every conflict head and
      opaque record included, the plain hashes withheld for opaque records.
    - `written_at` is the writer's clock in microseconds (the owner's choice; spec fixup 9).
    - The connection keeps the per-folder memory of records from the future and one note budget
      per connection, refilled per fixed window of `INDEX_RESYNC_INTERVAL` (Q3, PS-1).
    - The vector cap, the names and groups of one cleanup, the notes kept and the names per peer
      are crate-private test parameters (Q7); the tests at the real bounds are item 7's vectors,
      the paging test, the note-verification test and the ignored 100 000-record tree delete
      (`cargo test --release -p licketysync-index -- --ignored`).
    - The O(L) ancestor lookup is the spec's trie by path, not a one-pass keyed hasher, which
      would need the path-tag key outside the keys crate.
    - A tree delete with no base at or beneath its directory is written with an empty vector,
      covering nothing (documented, not refused).
    - Property tests run from the fixed seed `0x6c69_636b_6574_7379` unless
      `LICKETYSYNC_PROPTEST_SEED` names another or `random`, in the keys crate's eight
      `proptest!` blocks too (256 cases each, as before).
  - Spec points raised with this change, none blocking: §2 gives the largest Hello as 2 668 bytes
    (2 672 with its length field), 81 more than this release's largest; §4.4's text allows a
    cleanup group with no names beside one with names, and one name in two groups (both accepted
    here, as written); an opaque cleanup is never forgotten at a key holder (no counter to expire
    it by); two records that name each other, from a dishonest write-key holder, make a sealed
    peer's outcome depend on their order of arrival; §8 item 8 says a change rehashes one leaf of
    at most 64 record hashes, while a split reads 65 into new leaves; `extra_versions` at a key
    holder counts a tombstone beside a version and two heads of one content as extra heads.
  - Dependencies: none new.
  - Reviewed 2026-10-26 to 2026-10-31; every finding fixed, every reviewer clean. Protocol: R1
    aaed68195a3ce5865, R2 a94d1733f363aed1b, security a81b056d67f1bad40. Index: R1
    a7e0193629e57048e, R2 a91ff989482b809b8, security a9d1b8d0ad69e901a (last checks clean on
    e9e38ad). Author af36a5e76af7d9dbc; the merge agent wrote this line.

- Spec: the index keeps only the latest versions of each path, ordered by version vectors of at most
  32 entries that only read and write holders can read; sealed peers see almost nothing and replace
  a version only when a signed record or cleanup names it; deletions are forgotten by the folder's
  own time; and devices whose clocks are more than a year apart do not sync (the owner's decisions
  of 2026-10-25: "version vectors, latest only", growth bounded, "one record for a whole folder
  tree", "sealed peers see almost nothing", "use the folder's own time", and the clock rule). This
  replaces ruling R-K6 (`supersedes`, keep every record) and the per-writer cursors, digests, ranges
  and marks of rulings R-K4 and R-K5. The keys crate implements the spec's `keys.md` part in this
  same commit, so that the gate passes (the registry test reads 29 labels in the spec and 29 in the
  crate); the protocol and index crates follow in the next commit of this series, and the engine's
  port after them.
  - `protocol.md` §4.4 rewritten. An `IndexRecord` carries in the clear only the file ID
    (`path_tag`, a keyed hash of the path), `replaces` (the fingerprints of the versions it
    replaces, at most 64), the chunk IDs with their Padmé-padded sizes and the signature; the
    writer's device ID and counter (its dot), the version vector, the deletion and tree-delete
    marks, sizes and times are inside the seal (`SealedMeta` fields 8 to 12), under an aad of
    `folder_id || path_tag`, padded to the least power of two of at least 256 bytes. Read and write
    holders order versions by vectors (dotted version vectors: `V` covers `U` when
    `V.vector[U.device_id] ≥ U.counter`), with device-wide Lamport counters floored at the writer's
    wall clock in microseconds, and keep per file ID only the records nothing they hold replaces.
    Coverage holds only between applied records: a seal is checked before its vector is used, and an
    opaque record covers nothing and goes only by a name; the next write at a path names the records
    there that every release judges writer faults, never one opaque only because its kind is
    unknown, which may be a newer release's version and which no release silently replaces. A
    write's vector is the join of the path's bases (the versions on the writing device's disk, kept
    until a newer one is applied, so that an edit made while a newer version is still downloading
    never replaces it) pruned to 32, the least recently active writer dropped first (the owner's
    choice), and its names are those bases and the stale copies it covers. The sealed-peer rule: a
    sealed peer drops a version only when a held signed record names it or a held cleanup names it
    in a group whose `because` it holds, keeps both otherwise, and never expires anything. Files are
    deleted by tombstones, directories by one tree delete, with which the writer issues a signed
    cleanup (record type 17, label `sig/cleanup`): "forget these records", exact fingerprints in
    groups `because` the record that replaces them, at most 16 384 per record, held by every tier
    and forgotten by read and write holders after 30 days of the folder's time. A group acts only
    while its `because` record is held, on every tier, and no device remembers that it once acted,
    so what each tier holds and refuses depends only on the records it holds. Cleanups also carry
    stale copies a write holder learns of from a peer and deletions it has forgotten that a peer
    still offers, each verified once and named only once its signature has verified, never when a
    record the write holder holds names it or a cleanup it holds names it in any group, and at most
    `MAX_PEER_NAMES` (1 048 576) a 30-day window for one peer identity; they replace the earlier
    drafts' sealed-peer expiry, `Covered` messages and hierarchical tag chains, which are gone. A
    deletion is forgotten once the folder's own time, the greatest counter of an applied record a
    read or write holder holds, passes it by the 365-day deletion horizon. The clock rule: a device
    does not sync with a peer whose Hello `clock_days` is more than 365 days off its own, judged
    when the first folder opens on the connection (`Close(CLOCK_OUT_OF_RANGE)`; a stranger raises no
    issue), and a read or write holder neither holds nor relays a record whose counter is more than
    365 days ahead of its clock when it arrives (the coordinator's reading of the owner's rule,
    shown to the owner on 2026-10-25), while a store whose records lie more than 365 days ahead
    keeps its folder closed, so that a clock set back never undoes the device's own unsynced edit;
    both raise an issue that blames no device, with the remedy (stop syncing the folder, fix the
    clock, add the folder again, which starts its index afresh) and the remedy's own residual (its
    records from the wrong-clock time can later reappear or cover its later edits); the spread of a
    fast clock through correct devices to a slow one, and the partition it makes, are stated. The
    proofs ("Why it is safe", 1 to 13): coverage means "after", so an older version never replaces a
    newer one, whatever was pruned; pruning costs spurious conflicts only; nothing is dropped but by
    a later signed record or by forgetting a deletion; an edit beats a delete; a local write never
    replaces a version its device has not had on its disk; a name or cleanup says no more than
    coverage and expiry; a sealed peer loses nothing silently; a replayed cleanup removes no later
    version; equivocation (two records with one dot) is a conflict on every tier and reconciliation
    finds it; and the residuals are stated, among them that a replayed old deletion can take a
    version that came back after it was forgotten from a sealed peer until a write holder meets it.
    Stale copies at a sealed peer have no per-file bound: a holder of the sealed or read key that
    kept a folder's history can replay it, and the growth is bounded only by that history, content
    included, once per `CLEANUP_HORIZON` of the folder's time for each record, and for good in a
    folder nobody writes to. The next write at a path names its shared writer faults; one at a file
    ID nobody writes again, and a faulty cleanup, stay, and the writer-fault issue says that saving
    the file again clears it. §6 promises that step 7's checks other than `kind` never change within
    major 1, with a compatibility case in §8 item 14.
  - `protocol.md` §4.5: per-peer local sequences with an index epoch, set digests over record hashes
    in a 16-way trie of keys, the file ID then the record hash (a cleanup's record hash twice), so
    that no leaf holds more than 64 records, `ReconcileRequest` and `ReconcileReply`; a round ends
    caught up at `EQUAL` or after a quiet pass, one that ran to its end and brought nothing, the one
    meaning of "caught up", so a sealed peer's stale copies or a refused record cost one re-sending
    per round, not a storm; write holders note stale copies and forgotten records (each verified
    once, at most `MAX_NOTE_VERIFICATIONS` (4 096) verifications per connection per 10 s, one budget
    for every folder open on it, the notes kept across connections, each re-judged when it is named)
    and name them at the round's end, and a round with a cleanup owes another. The convergence
    argument: read and write holders that exchange hold the same records whatever their clocks
    within the clock rule; a sealed peer holds the same once a write holder has met it and the
    rounds its cleanups owe have run. §3.2 and §4.2 add the Hello `clock_days` (at most 2^21 − 1, so
    that the largest Hello stays 2 668 bytes) and the close reason `CLOCK_OUT_OF_RANGE`; a pass or
    reply whose records were skipped (a store failure, a paused folder) moves no cursor and is not
    quiet; cleanups take local sequence numbers like records; key holders fetch the chunks of every
    head and of opaque records; bases are kept per file ID with the store's metadata, a conflict
    copy's record a base once the copy is on the disk; the clock rule judges records on arrival
    only, and a store whose records lie more than a year ahead of the clock keeps its folder closed,
    re-checked as the clock moves on, until the clock is within a year of them; no round of a folder
    paused for a store failure starts; a tree delete has `kind` 2 and `size` 0; §4.1 drops `Covered`
    (0x800D reserved); §4.7, "What the engine needs", §5 (limits, the rules table, constants:
    `CLEANUP_HORIZON`, `CLOCK_RULE_LIMIT`, `MAX_REPLACES`, `MAX_CLEANUP_ENTRIES`,
    `MAX_CLEANUP_GROUPS`, `MAX_STALE_KNOWN`, `MAX_NOTE_VERIFICATIONS`, `MAX_PEER_NAMES`,
    `MAX_FUTURE_KNOWN`; `MAX_PROOF_COMPONENTS` gone), §2 (record sizes, about 520 bytes typical),
    §6, §7, §8 (items 6, 7 and 12 rewritten, 13 and 14 added) and §9 (in plain words: the sealed
    tier, what each kind of holder sees, the deletion horizon, the clock rule and its costs,
    conflict-copy growth in the hourly-log case) follow. No major bump: nothing was released.
  - `keys.md`: the path-tag key `tk` and flat file IDs (§1.2, §3.1, §3.5), the chunk gear key `gk`
    and FastCDC's gear table derived from the data key, with the length leak that remains and phase
    0's fixed-size chunks (§3.2), sizes (§0.1), three signature labels (§0.2), the clock comparisons
    the index makes (§0), what chunk padding costs and leaves visible (§3.3), sealed metadata with
    the dot, vector and deletion marks under the 64-byte aad and cleanup metadata under the folder
    ID, padded exactly to the least power of two that holds it (§3.4), two record types (§1.3, §5,
    §5.1, §5.3), fingerprint lists in the canonical encoding (§5.2), dots (§8.1, with the warning
    against device seeds shared by machines that can run at once), first records (§7.2), test
    vectors, items 1, 6, 8 and 13 (§9, the path-tag vector naming `docs/notés` composed and
    decomposed), and the registry (§10): `data/path-tag-key`, `data/chunk-gear-key`,
    `hash/set-leaf`, `hash/set-node` and `sig/cleanup` added, `hash/writer-digest` removed.
    `suites.md` §2.2 (the cleanup label), §2.3 (the aad and the padding schemes with their cost),
    §2.4 (the registry copy and the new uses) and §4.2 (public values compared with `==`).
  - `threat-model.md`: vocabulary, the index asset, §3.2, §3.3 (rewritten: what a sealed peer sees,
    stated in full; stale copies, their replay and the names they cost write holders; a version a
    replayed deletion takes away; forgotten deletions brought back; the rename residual; records
    from the future it relays; the chunk-length residual), §3.6 (vector churn, head floods,
    cleanups, counter exhaustion, future counters), §3.10, §3.12, TM-9, TM-10, TM-11, TM-14, TM-16,
    TM-17 (sealed peers drop only on signed names), TM-22 (cleanups, the names a write holder issues
    and their bounds; the stale copies bounded by the folder's history), TM-40 (the folder's own
    time and the clock rule, kept apart from the deletion horizon, with the remedy's residual and
    the spread through correct devices), TM-41 (sealed peers, cleanup groups that act only while
    their `because` is held, and equivocation), the new TM-43 (pruning and expiry may cost spurious
    conflicts or reappearance, never silent loss), §5 (to a sealed peer, in full, including arrival
    times, the sealed part's size class, chunk lengths and the old deletions a case-(c) cleanup
    names; to a key holder, including microsecond write times; the Hello's clock to anyone who
    connects) and the appendix's sources.
  - Prior art read on 2026-10-25: Syncthing BEP v1 and `lib/protocol/vector.go`; Preguiça et al.
    2010 (dotted version vectors) and Riak's causal-context page; Sheehy 2010 on pruning; Almeida,
    Baquero and Fonte 2008 (interval tree clocks, rejected: identities need a live participant to
    fork from and a join to retire); Kleppmann 2022 (reconcile by hashes, never by vectors); Lamport
    1978 (the counters' rule); Alexeev, Percival and Zhang 2025 and Truong, Merz, Scarlata, Günther
    and Paterson 2025 (attacks on keyed content-defined chunking).
  - Models (scratch, not committed): random runs of the coverage rules with pruning to 3 entries
    (claims 3 and 4, and convergence of two key holders within 2 passes), of bases (claim 9), and of
    the sealed tier with names and cleanups (claim 11), 20 000 runs each; the comparison of a count
    cap with time windows for the owner; and a model of the cleanup rule with several paths, tree
    deletes, expiry by the folder's time, pruning to 3 entries, download lag, replays of old records
    and read, write and sealed holders, 10 000 runs: with no applied bit, key holders that end
    caught-up rounds with each other always hold the same records, a key holder's holdings and
    refusals depend only on what it holds, and a sealed peer holds what a write holder holds within
    4 of the write holder's rounds; with the earlier draft's applied bit, 9 of 3 000 runs left key
    holders apart after caught-up rounds and 116 left a sealed peer apart, and a scripted case in
    which the bit leaves two key holders apart reproduces. The same model with the rule that a write
    holder notes no record that any group of a cleanup it holds names, 10 000 runs: key holders
    never apart, and a sealed peer holds what a write holder holds within four rounds, or, in the
    304 runs where a stale copy waited for the write holder to forget the cleanup that named it,
    within two rounds once the folder's time had passed that cleanup by `CLEANUP_HORIZON` (one such
    wait at most).
  - The keys crate (`licketysync-keys`), in this commit:
    - Labels (`keys.md` §10): `data/path-tag-key`, `data/chunk-gear-key`, `hash/set-leaf`,
      `hash/set-node` and `sig/cleanup` registered, `hash/writer-digest` taken out of `REGISTRY`,
      and the `sig/index` row's input read as §10 has it ("index record body"); 29 labels.
    - The chunk gear key `gk` and the path-tag key `tk`, derived from the data key, crate-private,
      zeroized and in the compile-time `ZeroizeOnDrop` guard (TM-6). `ChunkKeys::gear_table`
      gives the keyed gear table (§3.2) as a `GearTable` that zeroizes on drop and prints
      `[redacted]`; phase 0's fixed-size chunks do not call it.
    - `RecordKeys`, made only from a write or read key: the record key, the path-tag key and the
      folder ID together, with `path_tag` (§3.5, byte for byte, no normalisation) and the sealing
      and opening of index-record metadata under `folder_id || path_tag` and of cleanup metadata
      under `folder_id` (§3.4), each by its own function so that no caller passes the other's aad,
      padded to exactly the least power of two of at least 256 bytes. A sealed part of any other
      length is malformed (`MetaError::SealedLength`); the seal not opening, the length field not
      fitting, padding past the least bucket (`MetaError::OverPadded`) and a non-zero padding byte
      are writer faults, each its own variant (`MetaError::is_malformed` tells the two classes
      apart); a writer past the cap (`MAX_INDEX_SEALED_BYTES`, 2 097 192; a cleanup's 1 064) gets
      `MetaError::TooLong`, never a panic.
    - Signed records (§5): `RecordType` (16 index, 17 cleanup), which `SignedRecord::from_bytes`
      now reads from the body's prefix (every other value is malformed) and
      `SignedRecord::record_type` exposes; `WriteKey::sign_cleanup_record`; and
      `FolderVerifier::verify_record`, which takes the label from the record's type, so a cleanup
      body signed under `sig/index`, or the reverse, is forged. It replaces `verify_index_record`,
      whose one call in the protocol crate and the `index_envelope_parse` fuzz target follow. Both
      signing functions now read the body's common prefix with the decoder `from_bytes` uses and
      refuse (`Result<SignedRecord, Malformed>`) a body that does not decode, declares the other
      record type, or would pass `MAX_INDEX_RECORD_BYTES`, so every `SignedRecord` declares the
      type it was signed for and reads back as itself (the reviews' K-3); the callers in the
      protocol and index crates follow, and the protocol vector `record-type-1`, whose body a
      signing function now refuses, is built with a zero signature (step 1 refuses it before any
      signature is read; that one entry of `index_record.json` and its fuzz seed change).
    - `PathTag` and `SetDigest` (32-byte public IDs, compared with `==`, `suites.md` §4.2) and the
      set-digest helpers of `protocol.md` §4.5: `SetDigest::leaf`, which returns
      `SetDigest::EMPTY` (32 zero bytes) for no records so that no caller hashes an empty leaf, and
      `SetDigest::node`.
    - Vectors (§9): `gk` and `tk` in `folder.json` (item 1), the gear table's entries 0, 127 and
      255 in `chunk.json` (item 6), `index_record.json` rewritten for item 8, `labels.json` with
      the two new `derive_key` labels (item 10), and the new `path_tag.json` (item 13), which the
      protocol and index vectors will share (next commit). Unit and property tests: the bucket
      boundaries, round trips in the least bucket under both aads, every reader rejection, path
      tags byte for byte, the gear table's determinism and difference between folders, both
      record types through `from_bytes`, and `sig/cleanup` against `sig/index`.
    - Fuzzing (TM-3): `sealed_meta_open` opens every input with the new reader too, as an index
      record's sealed part at the vectors' path tag and as a cleanup's: a length its kind does
      not allow is refused before decryption, and what opens fills exactly its least bucket, does
      not open as the other kind and seals again, under its nonce, to the same bytes. Six seeds
      written by the keys vectors (`LICKETYSYNC_REGENERATE_VECTORS`).
    - Kept for this one commit, unchanged, because the protocol and index crates still call them,
      each documented as retired by `keys.md` on 2026-10-25 and removed in the next commit of this
      series: `sealed_meta::seal_meta` and `open_meta` (Padmé padding, the 72-byte aad) with the
      old `MAX_SEALED_BYTES` (1 572 864) and `MetaError::TooShort`; `WriterDigest` and its `then`,
      with the crate-private `HASH_WRITER_DIGEST`, which is no longer registered (so
      `labels::REGISTRY` lists every label in use but that one, until then), and the
      writer-digest vectors of `index_record.json`; the old reader's part of the
      `sealed_meta_open` fuzz target; and the "not an index record" wording of
      `Malformed::RecordType`, which the protocol crate's vectors quote.
  - Decisions for the plan (the owner's where marked; the coordinator's rulings, awaiting the
    owner's review, where marked; the rest are design choices of this change, for the owner's
    review):
    - The index keeps only the latest versions of each path (the owner's decision of 2026-10-25,
      "version vectors, latest only"; replaces ruling R-K6).
    - Read and write holders order versions by version vectors compared by the replaced record's
      dot; a vector has at most 32 entries and drops the least recently active writer first (the
      owner's choice of 2026-10-25, a count over a time window); a write covers and names at most 32
      heads.
    - Sealed peers see only file IDs, replaced fingerprints, chunk IDs with padded sizes and
      signatures (the owner's decision of 2026-10-25, "sealed peers see almost nothing"), and drop a
      version only when a signed record or cleanup names it.
    - Write holders issue signed cleanups naming exact record fingerprints, with tree deletes, for
      stale copies and for forgotten deletions (the owner's decision of 2026-10-25, that sealed
      peers drop only what a write holder's signed list names).
    - Contents are never merged: concurrent versions are kept as conflicts, shown as conflict copies
      (the owner's decision of 2026-10-25).
    - A cleanup group acts only while its `because` record is held, on every tier, with no memory of
      having acted (the coordinator's ruling of 2026-10-25, for the owner's review); its cost is
      that a stale copy can return to a sealed peer once the record it was named for is replaced.
    - A write holder verifies a stale copy before it notes it, never verifies a noted one again,
      verifies at most 4 096 for notes per connection per 10 s, one budget shared by every folder
      open on it (`MAX_NOTE_VERIFICATIONS`; the sharing is the coordinator's ruling of 2026-10-26,
      for the owner's review; at most about 2.4 % of one core per connection opened), and never
      notes one that a record it holds names or that a cleanup it holds names in any group, whether
      or not that group still applies, so each old record is named at most once per 30 days of the
      folder's time, however often its file is written; it names at most 1 048 576 for one peer
      identity per 30 days (`MAX_PEER_NAMES`). All of this is the coordinator's ruling of
      2026-10-25, for the owner's review, and the cap's value the author's; the cost is that a stale
      copy replayed after an edit stays at a sealed peer until the cleanup that named it is
      forgotten.
    - The next write at a path names the records there that every release judges writer faults,
      after its bases, the rest in a cleanup `because` the write; a record opaque only because its
      kind is unknown is never named, and no release silently replaces a newer release's version
      (the coordinator's ruling of 2026-10-25, for the owner's review).
    - Counters are device-wide and Lamport, floored at the writer's wall clock in microseconds
      (capped at 2^61), at most 2^62, sealed. That read and write holders learn microsecond write
      times from them is the owner's decision of 2026-10-25: "Make sure this is documented - do not
      hide this detail", and, for microseconds over minutes, "I can work on files in multiple
      locations nearly simultaneously and the per-minute version resolution is not accurate enough".
      Sealed peers learn nothing of them.
    - `written_at` is the writer's wall clock in microseconds since the Unix epoch, the unit of
      `clock_us` (the coordinator's ruling of 2026-10-26, for the owner's review, in keeping with
      the owner's decision that key holders see write times to the microsecond).
    - One record a write holder signs near `MAX_COUNTER` makes the folder unwritable until it is
      shared again (write holders only; a stated residual).
    - Deletions are forgotten by the folder's own time, the greatest counter held, after a fixed
      365-day deletion horizon, the same on every device (the owner's decisions of 2026-10-25, "use
      the folder's own time", replacing the plan's "configurable, zero meaning never"); sealed peers
      forget only by cleanup.
    - A file deleted and forgotten reappears when a device or relay that kept it offers it again
      (the owner's decision of 2026-10-25); the plan's snapshot rule for returning devices is
      dropped.
    - The clock rule (the owner's decision of 2026-10-25): devices whose clocks differ by more than
      365 days do not sync; that read and write holders also refuse records arriving more than 365
      days ahead of their clock is the coordinator's reading of the owner's rule, shown to the owner
      on 2026-10-25; the remedy is to stop syncing the folder on the wrong device, fix its clock and
      add the folder again, which brings back what it deleted meanwhile and turns its edits into
      conflict copies to settle. Judging it when the first folder opens on a connection, and an
      issue that blames no device, are the coordinator's rulings of 2026-10-25, for the owner's
      review. The remedy's own residual is stated (a per-folder writer generation is an open
      question for phase 1); a clock up to a year ahead can still make deletions be forgotten early
      (files come back, never lost) and can cut off a device whose clock is behind. Hello carries
      the clock to the day.
    - A device whose clock runs ahead raises every later counter in the folder while it writes; a
      counter more than a day ahead raises an issue saying the folder's time is ahead, pointing to
      the device ID the record claims as where it was first seen.
    - Local writes and a scan's tree deletes are built from the versions on the device's disk (its
      bases), never from records held but not yet applied.
    - File IDs are flat keyed hashes of paths under `tk`, derived from the data key.
    - FastCDC's gear table is derived from the data key under `data/chunk-gear-key` (the
      coordinator's ruling of 2026-10-25, for the owner's review); published attacks recover such
      keys from known files, so which keyed chunker phase 1 adopts is phase 1's question; phase 0
      cuts fixed-size chunks.
    - A directory is deleted by one tree delete whose vector covers the tree it deletes (the owner's
      decision of 2026-10-25, "one record for a whole folder tree"), a later tree delete covers an
      earlier one beneath it, and a file is deleted by a tombstone; a rename is a version at the new
      path then a tombstone.
    - A conflict copy becomes an ordinary live file, which the person deletes, when a device writes
      over the conflict; in the hourly-log case that is up to 3 files an hour, about 26 000 a year
      and about 300 MB of index a year until they are deleted.
    - Index sync is per-peer local sequences with an index epoch, then a set-digest check and
      reconciliation over file IDs; a round ends caught up at equal digests or a quiet pass.
    - Per-peer state is kept 90 days, at most 4 096 per folder.
    - Chunks no held record names are freed at the end of the next round, from a durable list.
    - Sealed metadata is padded to the least power of two of at least 256 bytes that holds it (the
      coordinator's ruling of 2026-10-25, for the owner's review), so that sealed peers cannot read
      the number of writers or the path length from its size; chunks keep Padmé. The cost is up to
      half the sealed part, about a quarter on average.
    - Record sizes, for a path of about 90 bytes: about 520 bytes for a one-chunk file whose record
      names one or two devices, 780 with three to seven, 1.3 KB with eight to eighteen and 2.3 KB
      with more; each further chunk adds about 75 bytes. The plan's budget becomes "typically under
      1 KB per file; files written by many devices up to about 2.3 KB" (the coordinator's ruling of
      2026-10-25, for the owner's review).
    - No bound on the stale copies a sealed peer keeps per file ID (the coordinator's ruling of
      2026-10-25, for the owner's review, option A): they are bounded only by the folder's history,
      since a version a held cleanup names is refused; a sealed peer shows its records beyond one
      per file ID in `FolderStatus` (`extra_versions`, field 7).
    - TM-43, its own requirement: pruning and expiry may cost spurious conflicts or reappearance,
      never silent loss (the coordinator's ruling of 2026-10-25, for the owner's review).
    - `CLEANUP_HORIZON` is 30 days of the folder's time (the coordinator's ruling of 2026-10-25, for
      the owner's review).
    - A pass or reply whose records were skipped (a store failure, a paused folder) moves no cursor
      and is not quiet; cleanups take local sequence numbers like records; key holders fetch the
      chunks of every head and of opaque records; bases are kept per file ID with the store's
      metadata; the clock rule judges records on arrival only, and a store whose records lie more
      than a year ahead of the clock keeps its folder closed rather than drop them; no round of a
      folder paused for a store failure starts; step 7's checks other than `kind` never change
      within major 1; a note is re-judged when it is named; the rule against naming what a held
      cleanup names covers shared writer faults; Hello `clock_days` is at most 2^21 − 1; a tree
      delete has `kind` 2 and `size` 0 (the coordinator's rulings of 2026-10-25, for the owner's
      review, some from gaps the engine's brief found).
    - Consequences of the owner's clock rule, stated in §9 (the coordinator's ruling of 2026-10-25,
      for the owner's review, that they need no question for the owner): a device whose clock is
      unset cannot sync until it is set; the remedy does not recall records already sent with
      far-future dates, which read and write holders refuse and sealed peers relay until the real
      date comes within a year.
    - A sealed peer learns, from a cleanup group with an empty `because`, that the index records it
      names were deletions more than a year old in the folder's time; this leak is stated, not
      removed (the coordinator's ruling of 2026-10-26, for the owner's review).
    - The note-verification budget's window is fixed, so a peer can spend up to two windows' budget
      in a short burst across a boundary, and the 2.4 % bound is an average (the coordinator's
      ruling of 2026-10-26, for the owner's review).
    - A folder's notes are shared by every connection and dropped oldest first, so a hostile peer
      with several connections and genuine old records can push an honest peer's notes out before
      they are named, which costs an honest sealed peer a slower cleanup and never a loss; per-peer
      shares are a phase 1 follow-up (the coordinator's ruling of 2026-10-26, for the owner's
      review).
    - A tree delete is judged without a walk, through a per-device index of held records ordered by
      path that keeps least counters, at most two queries per vector entry; and set digests key
      records by file ID then record hash, so that no leaf holds more than 64 records and a change
      rehashes at most one leaf and 128 nodes; a store that cannot stage atomically writes the base
      slots with the metadata and is reopened before its folder resumes after a store failure, which
      a peer that fills the disk can trigger once per failure; step 3's ancestor lookups cost `O(L)`
      work per path; `RECORDS` replies page in ascending key order, keeping only the last key sent
      (the coordinator's rulings of 2026-10-26, for the owner's review).
    - Plan bullets made stale: Sync engine "Index" (.48214), "Sealed peers" (.48654), "Nothing
      stalls on one file" (.122706, ordering by supersedes), "Concurrent versions are kept, and
      nothing rolls back" (.140303) and Folder features "Index growth" (.55484, the horizon and the
      snapshot rule).
    - The keys crate's choices (the author's, for review): the verifier takes the signature label
      from the record type the body declares, and signing refuses a body of another type;
      `SetDigest::leaf` gives the digest of the set, sorting and deduplicating hashes given out of
      order; and the gear table is kept like key material, zeroized on drop and in the compile-time
      guard.
  - Dependencies: none new.
  - Reviewed 2026-10-25 to 2026-10-26; every finding fixed, every reviewer clean. Spec: R1
    ae9dc383f7e161385, R2 a281dc7dff3a4e55b, security afc014fc508deffae (16 fixups, clean on
    155511d). Keys code: R1 a1c31b0383a318706, R2 a6324b4a6eb8a9464, security ae88535b041666d4f.
    Authors ad9009b3b0a0d5112 (spec) and af36a5e76af7d9dbc (keys); the merge agent wrote this line.
- cargo-vet 0.10.3, and the review's last findings (TM-8). The owner's rule takes a release at once
  when it fixes a critical or high vulnerability (the owner's messages of 2026-10-25, quoted in the
  project's CLAUDE.md: "or that has critical vulnerabilities fixed." and, the same day, ""Critical
  or high vulnerabilities" works for me."); the wording is now exactly that in `ci.yml`,
  `CONTRIBUTING.md`, `.github/dependabot.yml` and here. cargo-vet moves from 0.10.2 to 0.10.3
  (crates.io, 2026-10-22), under 7 days old: `cargo audit --file` on each release's published
  `Cargo.lock` finds 13 vulnerabilities in 0.10.2's, among them RUSTSEC-2024-0336 (rustls 0.20.6,
  7.5, high) and RUSTSEC-2023-0052 (webpki 0.22.0, 7.5, high), and RUSTSEC-2026-0067 and
  RUSTSEC-2026-0068 (tar 0.4.38, 5.1, medium), and none in 0.10.3's (five warnings: unmaintained
  crates, and bumpalo and tokio unsound). `CARGO_VET` and `ci.yml`'s install line say 0.10.3; with
  it, `cargo vet --locked` passes ("Vetting Succeeded (16 fully audited, 55 exempted)") and `cargo
  vet fmt` leaves `supply-chain/` unchanged. cargo-nextest 0.9.149 still waits for its 7 days: its
  fix concerns only the CA list of `cargo nextest self update`.
  - `ci/pins.env` can set only its own keys (security N1): the new `ci/check-pins.sh` lists them
    and refuses any line but a comment, a blank or `KEY=value` with a listed key, set once, and a
    plain value, so sourcing the file can never set `PATH`, `HOME`, `IFS`, `LC_ALL`, a `CARGO_` or
    `RUSTUP_` setting, or run anything. `gate.sh`, `ci/toolchains.sh`, `ci/gitleaks-install.sh`
    and `bootstrap.sh` run it before sourcing the file, in place of the pattern each had;
    `ci/test-check-pins.sh` has 25 cases (the real file, and `PATH`, `HOME`, `IFS`, `LC_ALL`,
    `CARGO_HOME`, `RUSTUP_TOOLCHAIN`, an unknown key and a key set twice among the refused), run by
    `gate.sh` and CI's `ci-scripts` job; eight of them fail against the pattern before it.
  - `ci/pinned-actions.sh` refuses an alias as a key (security N2), `- *k : ...` where the anchor
    holds `uses`, in block and flow style; 50 cases, the two new ones failing against the script
    before it, and an alias as a value and a cron schedule's stars still pass.
  - `fuzz/Cargo.lock` (security N3, quality NIT 3): `gate.sh` and `nightly.yml`'s audit job run
    `cargo audit --file fuzz/Cargo.lock`, and `.github/dependabot.yml` gains a cargo entry for
    `/fuzz` with the same 7-day cooldown. cargo-deny and cargo-vet still read the root workspace
    only; `CONTRIBUTING.md`'s residuals say so.
  - `ci.yml`'s header says the versions are written once, in core, in `ci/pins.env`, with site's
    zola the exception; `CONTRIBUTING.md` says which tools `bootstrap.sh` installs that the gate
    does not check here (cargo-auditable, cargo-cyclonedx, cargo-semver-checks), and that gitleaks,
    which it does not install, only draws a warning; core says "the project's CLAUDE.md"; and
    `gate.sh`'s header is rewrapped.
  - On the dev machine: cargo-vet 0.10.3 installed from crates.io with `cargo install --locked`.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security) over three rounds; every finding fixed and confirmed clean on
    5753ddd. Author ac59cb154860b67dc; the merge agent wrote this line.
- The pin-all series brought under the owner's "Stay current" rule of 2026-10-25, and its reviews'
  findings fixed (TM-8, TM-29). The owner: "We'd like to always use the latest version for tooling,
  libraries, CI, etc. Upgrade to anything that's been released for over 1 week (avoiding supply
  chain attacks) or that has critical vulnerabilities fixed." and, the same day, ""Critical or high
  vulnerabilities" works for me." (the owner's messages of 2026-10-25, quoted in the project's
  CLAUDE.md), so a release that fixes a critical or high vulnerability is taken at once. Every pin
  is now the newest release that has been out for at least 7 days on 2026-10-25 (published on or
  before 2026-10-18T20:55Z), dates read with `gh api .../releases` and the crates.io API under a
  User-Agent with no personal data. Moved back, since the pinned release was younger: install-action
  `v2.87.31` (2026-10-23) to `v2.87.29` (`8cca0918f8471c33515202b73f56ab27f2bed283`, 2026-10-16), in
  core and in site; rust-cache `v2.9.3` (2026-10-20) to `v2.9.2`
  (`6323deb102c322ba6fcbdcafc7e3dddab59af2b6`, 2026-08-06, an annotated tag dereferenced); and
  codeql-action `v4.39.1` (2026-10-21) to `v4.39.0` (`6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee`,
  2026-10-15, annotated) for `init`, `analyze` and `upload-sarif`, whose `action.yml` files differ
  between the two only in one input's description. None of the three younger releases fixes a
  vulnerability (their notes: tool-manifest updates; a cache-cleanup fix and a log level; a CodeQL
  bundle update). Unchanged, each the newest and old enough: checkout `v7.0.1` (2026-07-20),
  upload-artifact `v7.0.2` and download-artifact `v8.0.2` (2026-10-07), attest-build-provenance
  `v4.2.2` (2026-08-06), configure-pages `v6.0.0` (2026-03-25), upload-pages-artifact `v5.0.0`
  (2026-04-10), deploy-pages `v5.0.1` (2026-09-01), codecov-action `v7.1.1` (2026-09-17),
  scorecard-action `v2.5.0` (2026-10-12), rust-toolchain `v1` (its commit of 2026-10-16) and
  clusterfuzzlite `v1` (2023-08-09). The tools stay where they were, each the newest crates.io or
  GitHub release that is old enough: cargo-nextest 0.9.148 (2026-10-08), cargo-llvm-cov 0.9.1
  (2026-09-06), cargo-udeps 0.1.61 (2026-04-29), cargo-deny 0.20.2 (2026-07-09), cargo-audit 0.22.2
  (2026-06-05), cargo-machete 0.9.2 (2026-04-15), cargo-vet 0.10.2 (2026-01-13), cargo-mutants
  27.1.0 (2026-06-02), cargo-fuzz 0.13.2 (2026-06-09), cargo-careful 0.4.10 (2026-04-01),
  cargo-geiger 0.14.0 (2026-10-12), cargo-auditable 0.7.7 (2026-10-02), cargo-cyclonedx 0.5.9
  (2026-03-19), cargo-semver-checks 0.51.0 (2026-10-03), typos-cli 1.51.1 (2026-10-06), semgrep
  1.181.0 (2026-10-14), gitleaks 8.30.1 (2026-03-21), the Codecov CLI v11.3.1 (2026-07-09) and zola
  0.23.6 (2026-09-12). Three younger releases were read and passed over: cargo-nextest 0.9.149
  (2026-10-20), whose security fix is in `cargo nextest self update` alone, which nothing here runs,
  with no advisory published; cargo-vet 0.10.3 (2026-10-22), wrongly passed over here as naming no
  severity, and taken at once by the entry above, since 0.10.2's published lockfile has two High
  advisories; and semgrep 1.182.0 (2026-10-20), features only. Rust: stable 1.99.1 (released
  2026-10-15; the security review's S1) and nightly-2026-10-18 (rustc 1.101.0-nightly, 8006091eb
  2026-10-17), the newest dated nightly at least 7 days old, whose manifest has miri and rust-src.
  On the dev machine, with that nightly and both components installed, cargo-udeps passes,
  `cargo fuzz build` builds all 17 targets, a 5-second `cargo fuzz run frame_decode` runs clean,
  `cargo careful test --workspace` passes and `cargo miri --version` answers.
  - One source of truth (quality SF2, as ruled): the new `ci/pins.env` holds every tool and
    toolchain version as `KEY=value` (`RUST_STABLE`, `RUST_NIGHTLY`, a key per cargo tool, `TYPOS`,
    `SEMGREP` and `SEMGREP_IMAGE_DIGEST`, `GITLEAKS` and `GITLEAKS_LINUX_X64_SHA256`,
    `CODECOV_CLI`). `gate.sh`, `ci/toolchains.sh`, `ci/gitleaks-install.sh` and `bootstrap.sh`
    source it, each refusing first any line that is not a comment or `KEY=value` (so it cannot run a
    command), and `ci/gitleaks.sh` reads its `GITLEAKS` for the warning it gives when the installed
    gitleaks is another. `gate.sh` checks each workflow copy against it: `need_tool` for every cargo
    tool and typos (the installed version and the workflows' install lines), `need_installs` for
    cargo-auditable and cargo-cyclonedx in `release.yml`, and `need_line` for the `cargo-geiger`
    line of `ci/geiger-baseline.txt`, the semgrep image and the Codecov CLI version in `ci.yml`.
    Comments name keys, not versions: the workflows', `gate.sh`'s, `ci/gitleaks-install.sh`'s and
    the geiger baseline's header, and `ci/test-geiger.sh`'s and `ci/test-pinned-actions.sh`'s
    fixtures use versions no tool has (9.8.7, v1.2.3), so that `git grep -n -F <old version>` finds
    only the copies and the CHANGELOG (and text about other software). `CONTRIBUTING.md` ("Pins and
    the weekly refresh") states the procedure once: edit `pins.env`, edit the workflow copies
    `gate.sh` names, then grep until only the CHANGELOG matches.
  - Toolchain coverage (quality SF3, security N3): the check moves from `gate.sh` into
    `ci/toolchains.sh`, run by `gate.sh` before its first step and by CI's `ci-scripts` job, with
    26 cases in `ci/test-toolchains.sh`. Besides the names, it now fails a job whose `run:` steps
    call cargo, rustc or rustup, or a `ci/` script that does, with no `RUSTUP_TOOLCHAIN` for the job
    or the workflow. CodeQL's Rust extractor honours no `RUSTUP_TOOLCHAIN` of ours: it sets its own
    (`get_extra_env` in `rust/extractor/src/config.rs` of github/codeql, to `FIXED_RUST_TOOLCHAIN`,
    1.98.1 in `codeql-cli/v2.27.2`, the bundle that codeql-action `v4.39.0`'s `defaults.json`
    names), so `codeql.yml` sets none and its toolchain moves only with the codeql-action pin; and
    ClusterFuzzLite builds in its own image. The pinning claims in `ci.yml`'s header and
    `CONTRIBUTING.md` say so.
  - `ci/pinned-actions.sh` (security N1) refuses any line that writes a `uses` key in a form it
    does not read: a space before the colon, a quoted key, a key with an escape, a flow mapping, an
    explicit `?` key, an anchored or tagged key; and it refuses local actions (`./...`). Its error
    names the form wanted, the `gh api` command that finds a tag's commit, and where the rule is.
    `ci/test-pinned-actions.sh` has 46 cases, each named for its result; 15 of them fail against
    the script before this change. Remaining limits, in its header: it reads lines, so `uses`-like
    text in a script or a trailing comment is refused too, and a value on the next line is
    refused.
  - typos (security N2) is installed by install-action as `typos@1.51.1` with `fallback: none`,
    which checks the archive's SHA-256 (the manifest's
    `93c301fd4120ff076e2cc2a6d6a61cab4a4bdb81899287c0938b452e56d1f454` for x86_64 musl equals the
    GitHub release asset's digest), then `run: typos`; `crate-ci/typos`, which downloaded its
    release unchecked, is gone, and `gate.sh` checks typos with `need_tool typos-cli`. The semgrep
    image (security N4) is pulled by digest,
    `semgrep/semgrep:1.181.0@sha256:81474464c1f07483ba0682a44787fd93c91397419762a04abe2bafaae396304b`
    (Docker Hub's API and the registry's `Docker-Content-Digest` agree; the tag was last pushed on
    2026-10-14).
  - `installs()` reads install-action's aliases, `nextest` and `typos`, as cargo-nextest and
    typos-cli, so a workflow that spells one that way, or uses `taiki-e/install-action@nextest`,
    fails the gate (correctness NIT 1); `need_tool` reads typos's version from `typos --version`.
  - `fuzz/Cargo.lock` is committed: 58 packages, made from the root lockfile so that the crates the
    two share keep its versions, plus arbitrary 1.5.0 (2026-10-06), jobserver 0.1.35 (2026-07-06)
    and libfuzzer-sys 0.4.13 (2026-06-04). cargo-fuzz has no `--locked`, so `cargo fetch --locked
    --manifest-path fuzz/Cargo.toml` runs before the fuzz targets are listed and before each fuzz
    run in `nightly.yml`, in CI's `deps` job, and in `gate.sh`.
  - `.github/dependabot.yml` in core (cargo and github-actions), site and web: `cooldown:
    default-days: 7`. GitHub's Dependabot options reference: "The `cooldown` option is only
    available for _version_ updates, not _security_ updates."
  - `CONTRIBUTING.md`'s pins section is rewritten: the keys, the toolchains (an override holds per
    directory, so per worktree), which release qualifies, the one procedure for moving a pin, and
    the weekly refresh, which covers every `pins.env` key, cargo-geiger with its baseline, site's
    zola, the two actions with a single `v1` tag, and transitive crates with `cargo update` here
    and in `fuzz/` (quality SF1). The rule's pointers all lead to `ci.yml`'s header, and the
    comments say that Dependabot rewrites the tag comment when it moves the pin. `bootstrap.sh`
    (outside the repositories) sources `core/ci/pins.env`, installs every pinned tool,
    cargo-auditable, cargo-cyclonedx and cargo-semver-checks included, installs `RUST_STABLE` by
    name and sets it for `core/` when stable is another, and installs the dated nightly with miri
    and rust-src.
  - Residuals, as `CONTRIBUTING.md` lists them: the container images that pinned actions name by
    tag (scorecard-action's on ghcr.io, ClusterFuzzLite's on gcr.io); the toolchains that actions
    choose for themselves (CodeQL's extractor, ClusterFuzzLite's image); GitHub's runner images;
    and the line-based reading of `ci/pinned-actions.sh` and `ci/toolchains.sh`, whose headers
    list what they cannot see. `fuzz/` is a workspace of its own, so cargo-deny, cargo-vet and
    Dependabot do not read its lockfile; the weekly refresh updates it.
  - Tests that fail without the change: 15 of `ci/test-pinned-actions.sh`'s cases against the
    script before it; `ci/toolchains.sh` on the workflows before it (`value 1.99.0`, and the steps
    and jobs on it); and the gate's new copy checks against the workflows before it (`ci.yml`
    installed typos through `crate-ci/typos`, and its semgrep image had no digest).
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security) over three rounds; every finding fixed and confirmed clean on
    5753ddd. Author ac59cb154860b67dc; the merge agent wrote this line.
- The Rust toolchain pinned in CI: 1.99.0, and nightly-2026-10-14 for the jobs that need nightly
  (the entry above moves them to 1.99.1 and nightly-2026-10-18 and gives the check a script of its
  own), on the coordinator's ruling of 2026-10-25 that the owner's "CI tools - pin." covers the
  toolchain (TM-8, TM-29). Until now each `dtolnay/rust-toolchain` step installed the day's stable
  or nightly, and a release tag built with whatever stable was current. The 16 steps now name
  `toolchain: 1.99.0` (12) or `toolchain: nightly-2026-10-14` (4: `ci.yml`'s `udeps`,
  `nightly.yml`'s `fuzz`, `careful` and `miri`). That alone would pin nothing: the action makes its
  toolchain rustup's default, and in the checkout `rust-toolchain.toml`'s `channel = "stable"`
  outranks the default (`rustup show active-toolchain` there: "stable-x86_64-unknown-linux-gnu
  (overridden by '.../rust-toolchain.toml')"), so every cargo command would still have run the
  runner's stable. So `ci.yml`, `nightly.yml`, `mutants.yml` and `release.yml` set
  `RUSTUP_TOOLCHAIN: 1.99.0` for the workflow, and the four nightly jobs set
  `RUSTUP_TOOLCHAIN: nightly-2026-10-14` for the job; `RUSTUP_TOOLCHAIN` outranks the file
  ("nightly-2026-10-14-x86_64-unknown-linux-gnu (overridden by environment variable
  RUSTUP_TOOLCHAIN)"). The components the file names come, as before, from each step's `components:`
  (rustfmt, clippy, llvm-tools-preview; rust-src and miri for the nightly jobs). The
  `cargo +nightly` commands name `+nightly-2026-10-14` (udeps, the fuzz run, careful, and the
  comment on reproducing a crash). `clusterfuzzlite.yml` builds in its own image and installs no
  toolchain. `rust-toolchain.toml` stays on `channel = "stable"`, as ruled, so that the dev machine
  needs no separately named toolchain: its stable is 1.99.0 (b940084d7 2026-09-28) and
  nightly-2026-10-14 (rustc 1.101.0-nightly, 822182db4 2026-10-13) is installed. With that nightly,
  `cargo +nightly-2026-10-14 udeps --workspace --all-targets` passes ("All deps seem to have been
  used."), `cargo fuzz build` builds all 17 targets, and a 5-second `cargo fuzz run frame_decode`
  runs clean. Its channel manifest lists `rust-src` and `miri-preview` (`miri`) as available for
  x86_64 Linux, which the `careful` and `miri` jobs install; neither job ran locally, since the dev
  machine's copy of that nightly lacks both components and adding them downloads them. `gate.sh`
  names the two (`rust_stable`, `rust_nightly`) and stops unless `rustc --version` in the checkout
  is 1.99.0, printing `rustup update stable` for an older stable and, for a newer one, moving the
  pin or `rustup toolchain install 1.99.0 ...` with `rustup override set 1.99.0`, and unless
  `rustup toolchain list` has the dated nightly; `RUSTUP_AUTO_INSTALL=0` keeps the check from
  downloading. A new `toolchains` function reads each workflow: every `toolchain:`, every
  `RUSTUP_TOOLCHAIN` and every `+<toolchain>` after cargo, rustc or rustup must be one of the two,
  and each rust-toolchain step must install the `RUSTUP_TOOLCHAIN` its job runs with, the job's or
  else the workflow's. The gate's udeps step runs `cargo +nightly-2026-10-14 udeps`. `bootstrap.sh`
  (outside the repositories) installs the dated nightly with miri and rust-src, builds cargo-fuzz
  and cargo-udeps with it, and says when stable is not 1.99.0. `CONTRIBUTING.md` names both
  toolchains and adds them to the weekly hand check: a bump is one reviewed change to `gate.sh`'s
  two lines and every workflow, with `bootstrap.sh` and `CONTRIBUTING.md`. The Rust toolchain is no
  longer a residual in `ci.yml`'s header, `release.yml`, `CONTRIBUTING.md` or the entry below. Tests
  that fail without the change: on the entry below's workflows the new check stops the gate at
  `ci.yml` (`value stable`), and on `main`'s with `value nightly` and a line per job such as
  `job fmt - -`; on copies of the new ones, by hand, a step on `stable` or `nightly`, a workflow
  without `RUSTUP_TOOLCHAIN`, a nightly job without its own, a job whose `RUSTUP_TOOLCHAIN` differs
  from its step's, `cargo +nightly`, another version, a step with no `toolchain:`, a new workflow
  without the variable, and a gate that wants another stable or nightly each stop the gate and print
  what they found, while a commented-out `cargo +nightly` does not. The workflows parse as YAML.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security) over three rounds; every finding fixed and confirmed clean on
    5753ddd. Author ac59cb154860b67dc; the merge agent wrote this line.
- Every action in every workflow of core, site and web pinned by full commit SHA, GitHub's own
  included, and every tool CI installs pinned to an exact version, as the owner decided on
  2026-10-25 ("CI tools - pin."; the plan's decision "CI actions and tools pinned"), widening the
  rule that until now pinned only the jobs holding `id-token`, `attestations` or `contents` write
  (TM-8, TM-29). Each pin is followed by a comment naming the release tag on that commit, which
  Dependabot reads to move pin and comment together: each repository's `.github/dependabot.yml`
  already updates the `github-actions` ecosystem weekly and is unchanged. Each tag was read on
  2026-10-25 with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, an annotated one dereferenced
  with `git/tags/<sha>`, and is the action's newest release in the major the workflow used; after
  the edit, every one of the 81 `uses:` lines (72 in core, 5 in site, 4 in web) was resolved again
  the same way and names its tag's commit. Where an action was on a major tag, the commit pinned is
  the one that tag named that day, so the same code runs as before, except for codeql-action's v4,
  site's install-action (moved from `v2.87.30` to `v2.87.31`) and the refs that were branches (the
  entry two above moves several of these pins back to the newest release at least 7 days old):
  - `actions/checkout` `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`), in every job (it was
    already pinned in `codecov` and `scorecard`).
  - `actions/upload-artifact` `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (`v7.0.2`).
  - `actions/download-artifact` `9000827ccba6bdab643e8b6fd33ac0654aef8333` (`v8.0.2`),
    `actions/attest-build-provenance` `4d101475d8b20a2381f78447822ac1eab6504dd8` (`v4.2.2`),
    `codecov/codecov-action` `303a32d7a59b442fa8d48b6a1cc6825c09c847a5` (`v7.1.1`) and
    `ossf/scorecard-action` `fa7117db83c52d787ae5a89f350999701505d78e` (`v2.5.0`): already pinned,
    still the newest in their majors, unchanged.
  - `github/codeql-action` `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` (`v4.39.1`): `upload-sarif`
    unchanged; `init` and `analyze` in `codeql.yml` move from `v3` to `v4`, the plan's follow-up,
    since v3 is deprecated in December 2026 (codeql-action's changelog). Their `action.yml` at `v3`
    (`v3.39.1`, `4bfa242aa49c5f7c6770b98670d354a7dfac05f8`) and at `v4.39.1` differ only in
    `runs.using`, `node20` to `node24`, so `languages` and `queries` mean what they did.
  - `dtolnay/rust-toolchain` `683b588c487a69d01f6c6ddf40f036ff682cc2c8` (`v1`, its only tag, on
    master's head; already pinned in `release.yml`), in all 16 steps that install Rust. The
    `@stable` and `@nightly` refs were branches, each master's head plus a default for `toolchain`
    (`gh api repos/dtolnay/rust-toolchain/compare/<v1>...stable`), so every step now names its
    `toolchain:`.
  - `Swatinem/rust-cache` `d1527c8f67ef9af357290475d4af4b0fab8f12e0` (`v2.9.3`).
  - `taiki-e/install-action` `1e29709c0ec63babbe8f266397a465f29a825f91` (`v2.87.31`), in every
    step; site's `pages.yml` bumped from `v2.87.30` (`a4d3f3f761dcd95cce1b72cb61cb6d1963438177`).
    The `@nextest` and `@cargo-udeps` refs were branches that install the newest release; those
    steps now pass the tool and version.
  - `crate-ci/typos` `7f9d0819ca1c008ade73f4b41fa9d258d48f605b` (`v1.51.1`), was `@master`.
  - `google/clusterfuzzlite` `884713a6c30a92e5e8544c39945cd7cb630abcd1` (`v1`, its only tag; it
    publishes no releases), both actions.
  - `actions/configure-pages` `45bfe0192ca1faeb007ade9deae92b16b8254a0d` (`v6.0.0`),
    `actions/upload-pages-artifact` `fc324d3547104276b827a68afc52ff2a11cc49c9` (`v5.0.0`) and
    `actions/deploy-pages` `368f82528645a54fb793d4d04e342629a3f51346` (`v5.0.1`), in site's and
    web's `pages.yml`, in their own commits.

  The tools that floated are pinned to the dev machine's versions (`--version`, 2026-10-25), each
  in install-action's manifest at the pinned commit for every runner it runs on, with `fallback:
  none`: cargo-nextest 0.9.148 (`ci.yml`'s `test` and `coverage` jobs; the manifest's newest is
  0.9.149), cargo-llvm-cov 0.9.1 and cargo-udeps 0.1.61 (both the newest), and typos 1.51.1 (the
  newest), which the `crate-ci/typos` release commit names: its `action/entrypoint.sh` sets
  `VERSION=1.51.1` and downloads that release from GitHub, with no checksum (a residual).
  `gate.sh`'s `need_tool` now checks cargo-nextest, cargo-llvm-cov and cargo-udeps like the other
  seven, against `ci.yml`'s install lines, and reads the first X.Y.Z on the first line of
  `--version` instead of the last word, which for cargo-nextest is a date (`cargo-nextest 0.9.148
  (cd1d6d546 2026-10-07)`). A new check stops the gate unless `typos --version` is `typos-cli
  1.51.1` and `ci.yml` runs typos as exactly one step `uses: crate-ci/typos@<40 hex digits> #
  v1.51.1`. `bootstrap.sh` (outside the repositories) installs the four at those versions. The Rust
  toolchain itself is pinned by the entry above. The rule is stated once in full in `ci.yml`'s
  header (the `codecov` job's paragraph, which said "pinning every action is a pending decision",
  is gone), and `release.yml`,
  `scorecard.yml`, `codeql.yml` and site's and web's `pages.yml` point to it. New
  `ci/pinned-actions.sh` checks the rule's form in a workflow directory: each `uses:` names a full
  40-digit lowercase SHA with a `# v<version>` comment (`v1`, `v2.9` or `v7.0.1`); a local action,
  or a Docker image by `sha256:` digest, also passes; it fails closed on a missing or empty
  directory or an unreadable file. Whether the tag names that commit needs the network, so the
  reviewers of a change that moves a pin check it. `ci/test-pinned-actions.sh` has 30 cases, and
  `gate.sh` and a new `pinned-actions` job in `ci.yml` run both; site and web have no gate, so
  `core/ci/pinned-actions.sh <repo>/.github/workflows` checks them. `CONTRIBUTING.md` now lists the
  new tool pins and the hand checks of the weekly Dependabot review: the ten cargo tools, the two
  release tools, site's zola, the Codecov CLI, and the `dtolnay/rust-toolchain` and
  `google/clusterfuzzlite` commits, whose single `v1` tag gives Dependabot no newer release; and how
  a Dependabot bump of `crate-ci/typos` moves `gate.sh`'s typos version with it. Residuals: the
  container images that pinned actions name by tag (scorecard-action's
  on ghcr.io, ClusterFuzzLite's on gcr.io) and `ci.yml`'s `semgrep/semgrep:1.181.0`, a version tag,
  not a digest. Tests that fail without the change: `ci/pinned-actions.sh` on `main`'s workflows
  exits 1 and lists 61 unpinned `uses:` lines in core, 4 in site and 4 in web; `gate.sh`'s new
  `need_tool` lines fail against `main`'s `ci.yml` (`taiki-e/install-action@nextest`,
  `cargo-llvm-cov,nextest`, `taiki-e/install-action@cargo-udeps`), and its typos check against
  `crate-ci/typos@master`; and with the old version read, the `need_tool` for cargo-nextest would
  have read `2026-10-07)`. The workflows were parsed as YAML; where a step runs other code than
  before, its `with:` inputs were checked against the `action.yml` at the pinned commit
  (codeql-action's `init` and `analyze`, rust-toolchain, install-action and typos), and a script
  over the parsed files confirmed that every rust-toolchain step names a toolchain and every
  install-action step gives each tool a version and `fallback: none`; actionlint is not installed.
  They run on the first push after the merge (CI, CodeQL; Pages in site and web) and at the next
  scheduled runs.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security) over three rounds; every finding fixed and confirmed clean on
    5753ddd. Author ac59cb154860b67dc; the merge agent wrote this line.
- The index checks every stored record again when a folder opens (the owner's decision of
  2026-10-25, option A of the phase 1 store question; the plan's decision "Index check at open").
  `Index::open` gives each record that `Store::load` returns the checks a record from a peer gets
  before it is stored, through the same functions: step 1 against the folder (`Record::parse`, which
  the connection's `Record::from_bytes` calls; the suite and folder ID included) and the signature
  (`Record::verify`, which `judge` calls: Ed25519 `verify_strict` under the folder's verification
  key), at every tier, a sealed holder's included. The signatures are verified on
  `std::thread::available_parallelism` threads: the parsed records are split into one contiguous
  slice per thread under `std::thread::scope` with `Builder::spawn_scoped`, each thread borrowing
  its slice (nothing is cloned), the calling thread taking the first, and the verdicts joined in
  input order, so the result is the same on any number of threads; a slice whose thread cannot be
  spawned (`wasm32-unknown-unknown` has none) is verified on the calling thread, as everything is
  when parallelism is 1, and the same fallback takes a slice whose thread panicked, though
  verification has no panic path (`crates/index/src/verify.rs`). The open blocks its thread for the
  whole check. A record that fails is dropped: nothing of it is applied, counted in a cursor or
  digest, or served. Since a writer's records are held contiguously from `seq` 1, a record that
  passes but lies above a `seq` at which its writer has no stored record that passes is set aside:
  kept in memory, not held, and landed, without a second append, as soon as a record at that `seq`
  lands, from a peer or written here, so once every gap below it is filled (`Outcome::landed` names
  them; they count as newly accepted and are pushed to every connection where the folder is open,
  the one the filling record came in on included), each at one digest step; so the index stays what
  a reopen of the store gives, and this device, when its own record is the one missing, reuses only
  that `seq`. The other records that pass are replayed exactly as before (canonical order, one
  digest step each, seals opened again), so a store of genuine records opens to the index that
  accepting them builds. A dropped or missing genuine record comes back by normal index sync because
  the cursors and digests are rebuilt from the records held: one missing at the top of a writer's
  sequence leaves the cursor below it, so a responder serves it by case (a), (b) or (c), and a
  concurrent version missing at or below the cursor makes this device's digest differ from that of
  every peer that holds it, so the comparison resends the writer in full (case (c) and the marks).
  `Store::append` of a record whose hash the store holds keeps the envelope given in place of the
  one it had, so a good copy that arrives replaces one whose signature bytes changed at rest, and
  the next open is clean; `MemoryStore` already did. API: `Index::open` returns `Result<(Index<S>,
  OpenReport), OpenError>`; the new `OpenReport`, `#[non_exhaustive]`, has `dropped` (record hashes
  of the bodies as stored, ascending, each once; a failing copy beside a passing copy of the same
  hash is dropped without being listed) and `set_aside` (record hashes in canonical order) and
  `is_clean()` (nothing dropped or set aside); `Outcome` gains `landed`, its `fault`, `waits`,
  `own_ahead` and `rows()` describe the record passed in alone (each landed record's state shows
  through `Index::kept` and `Index::is_waiting`), and `own_ahead` is also set when this device's own
  records land above a record of its own, so that the informational issue of §4.5 is raised on that
  path; `OpenError::Unreadable` and `OpenError::Gap` are removed, since a record that fails step 1
  is now dropped and a gap sets records aside, which leaves `OpenError::Store`; the crate-private
  `Index::open_with_threads` takes the thread count, for tests. No new dependency and no unsafe
  code. Docs: `store.rs` ("The store is checked when the index opens", and the `append` contract),
  `lib.rs`, `index.rs`, the README's index row, and `rules.rs` in the protocol crate, whose module
  doc now says that `Cause` names every §5 row but the two about this device's own index store.
  - Spec changes in this commit: `threat-model.md` TM-9 (the index store is trusted to keep records,
    not for their authenticity; every record is verified at open, a failure dropped and reported,
    the records above a gap set aside and landed when it fills, cursors and digests rebuilt from the
    records held, so index sync fetches the rest again; the measured cost with its caveats; the
    keyed checksum as the fallback only; the key store stays trusted; the engine's Checking state
    and issue marked "when the engine lands"), §3.12 (the index store is out of scope only for what
    it keeps: it can lose or withhold records, not forge them, with the residuals: a record no peer
    holds stays missing and the records above it, of any writer, stay set aside and reported at
    every open; withholding this device's own records makes it reuse their sequence numbers, as
    after a restored backup, `protocol.md` §4.5; records only this device held are lost), TM-10 (the
    stored-record case involves no connection), TM-17 (a cursor falls only when the device's own
    store loses or corrupts records at rest) and TM-22 (the check at open is no peer's to trigger, a
    store failure's resume does not reopen the index, and a write holder that floods records
    lengthens every later open by one verification per record); `protocol.md` introduction (the
    stored-record case), §4.4 (the rebuild checks first and sets aside above a gap; step 4's note on
    the flood cost and the store-failure resume; "Rollback": a lost record leaves the ones above it
    set aside; a new paragraph "Opening a folder": dropped and set-aside records, landing, why sync
    refetches, same-hash replacement, the stated residuals, and for the engine when it lands:
    Checking in its own folder state, the open off any async executor, one issue with the counts and
    at most 16 hashes (a fixed engine constant), a store where nothing passes (an empty index, no
    record set aside and some dropped) treated as misconfigured and never scanned into an empty
    index, a fresh store after re-keying, and a phase 1 store that drops and reports undecodable
    bytes, `Store::load` needing a way to report them), §4.5 "Pushes" (landed records count as newly
    accepted and are pushed to every connection where the folder is open, the one the filling record
    came in on included) and "Durability before transmission" (own records that opening dropped or
    set aside move the counter when they come back) and §5 (the "nothing is silently skipped"
    paragraph names the two store rows that involve no connection, and a new row, "Stored record
    fails its check" when the folder opens, which covers a record above a gap too). The phase 1 open
    question is gone from TM-9, §3.12 and the crate docs, which record the decision.
  - Measured (scratch release build, not committed): 100 000 records of 100 writers, on an Intel
    Core i5-1145G7 laptop processor with 4 cores and 8 threads (`available_parallelism` 8), three
    runs each: open on 1 thread 5.6 to 6.1 s, of which the checks 4.8 to 5.6 s; on 8 threads 2.5 to
    3.3 s, of which the checks 1.83 to 1.86 s; open before this change, without the checks, 0.52 to
    0.79 s. The machine was shared with other builds and its clock moved between 1.3 and 2.5 GHz, so
    the figures are ranges; the checks gain about 2.7 times on 8 threads, which 4 physical cores
    bound. Tests do not depend on time.
  - Tests (`crates/index/src/tests/open.rs`, new): a store with one record whose signature and one
    whose body (in `sealed`, so it still parses) changed by one bit opens dropping exactly those,
    setting aside the record above the gap, and equals the index accepting the rest builds, at one
    digest step per record held; read and sealed holders report the same; a record of another folder
    (failing step 1) and this folder's record signed by another folder's key are dropped; a bad copy
    beside a good one drops nothing, and a bad one loaded twice is named once; a dropped record
    arriving later by `accept` is `Next`, lands the record set aside above it at one step and
    without a second append, and a body changed under a new hash is reported again at the next open;
    a good copy arriving later replaces the bad one in the store, so the next open is clean; a
    record that another write holder signs at the gap lands the three records above it, which a push
    had found to be a gap, at one step each, with the outcome's flags the filler's and each landed
    record applied and not waiting, and the index equals a reopen's; this device writing at its lost
    `seq` lands the record above it, setting `own_ahead` and the own-sequence-ahead row, and writes
    next at `seq` 4, not 3, and equals a reopen's; index sync through real requests and pages brings
    back what was dropped or set aside; a dropped concurrent version is found by the digest; a
    dropped record of this device lowers its next `seq` until it returns ahead of the counter and
    lands the one above; 1 thread and 0, 2, 3, 4, 7, 47, 48, 64 and 1 000 threads, and `open`
    itself, give the same index, report and next `seq` on 48 records with concurrent versions,
    waiting and opaque records and corruption; an empty store opens clean on any thread count.
    Property test (`properties.rs`): over random histories, a store with random records changed at
    rest in the signature or the body opens to exactly the index accepting the genuine ones builds,
    with exactly the changed ones dropped and the right ones set aside, on 1 thread and on 2 to 8
    alike, and clean when none changed; when the originals of the changed records then come back,
    every record set aside lands and the index, and a reopen of its store, equal the index accepting
    every record builds, the reopen naming only the bodies changed under new hashes. `behaviour.rs`:
    `opening_refuses_a_corrupt_store_and_tolerates_repeats` becomes
    `opening_sets_aside_a_gap_drops_a_foreign_record_and_tolerates_repeats` (its gap and
    another-folder cases now open and report instead of failing; its repeats case is unchanged), the
    errors test loses the two removed variants, and the memory-store test shows a copy under the
    same hash replacing the envelope kept. The test snapshot now includes the records set aside, and
    every other open in the tests goes through `kit::reopen`, which asserts a clean report, so the
    existing reopen, dedup and bounded-work tests hold as before. With the signature check bypassed,
    thirteen of the open and property tests fail; with set-aside records never landed, six fail;
    without `own_ahead` set for a landing of this device's own records, one fails.
  - Decisions for the plan: a record that fails step 1 at open is dropped like one whose signature
    fails, not an error; a writer's records above a gap are set aside and reported apart from the
    dropped ones, kept in memory and landed when a record at the gap lands, and a gap, whether a
    dropped record left it or the store lost a record, no longer fails the open, so one corrupt
    record cannot make a folder unopenable; the report is returned beside the index rather than kept
    in it, and `Outcome::landed` names the records a landing brought in, which count as newly
    accepted and are pushed to every connection where the folder is open, the one the filling record
    came in on included; the engine's issue names at most 16 record hashes; a record is named by the
    hash of its body as stored, and a failing copy beside a passing one is not named; a store keeps
    the envelope appended last under a hash; a record changed at rest under a new hash stays in the
    store (no store removes a record, TM-17) and is reported at every open until phase 1's store or
    `doctor` repairs it; a record of this device's own that opening dropped lowers its next `seq` to
    that one `seq`, a write there makes a concurrent version as after a restored backup, and the
    records set aside above it land with that write; a cursor can fall across a restart only through
    this device's own store at rest; a phase 1 store that keeps bytes drops and reports bytes that
    no longer decode, never failing the load or losing them silently; when nothing in a store passes
    the engine treats the folder as misconfigured, and re-keying starts a fresh store; verification
    spawns its threads for each open, with no pool and no minimum slice.
  - Reviewed 2026-10-25 by a913a68c8b3102a14 (correctness), a9f55faa34f1b4904 (quality) and
    aac254dea94bea21a (security); every finding fixed and confirmed clean (correctness confirmed
    the last round, 9f28260). Author ad8aff4742d87ddf7; the merge agent wrote this line.
- The browser client's domain is licketysync.app instead of licketysync.dev (owner's decision of
  2026-10-25: "Switch to licketysync.app for the browser client. Both licketysync.app and
  licketysync.com have been verified for GitHub Pages."). The invite link people click starts with
  the client's domain, and .app reads as an app where .dev reads as a developer or test site; both
  top-level domains are HSTS-preloaded. The documentation site stays on licketysync.com, a separate
  registrable domain (TM-18). A join link is now `https://licketysync.app/join#k=...`: `LINK_PREFIX`
  in `crates/keys/src/keystring.rs` with its doc comments and tests; `spec/keys.md` section 6.3,
  which now also says that a link beginning any other way is refused; and the client's host in
  `spec/threat-model.md`'s parties table, section 3.8 and TM-18, which now names licketysync.com as
  the documentation site's separate domain, says that a link that does not begin with
  `https://licketysync.app/join#` is refused, and counts the link parser in `keys` among what
  enforces it. A link starting `https://licketysync.dev/join#` is refused with `LinkError::Prefix`,
  like one on any foreign host: nothing has been released, so no such link needs honouring and no
  compatibility is kept. `crates/keys/tests/vectors/link.json` was regenerated with
  `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-keys vector_`; it is the only vector
  file that changed, and its three links differ from the old ones only in the host (key string,
  addresses and certificate hash byte for byte the same). The four `link_parse` fuzz seeds carry the
  new host: three still reach past the prefix, and `link-02`, the key string in the query, stays a
  near miss that the prefix check refuses. `ci/no-hostnames.sh` skipped licketysync.com and
  licketysync.dev wherever a string literal under `crates/` named them, so any URL on either, such
  as an update check, a relay or telemetry, would have passed CI unnoticed (TM-31). It now exempts
  only the join-link prefix: it removes the exact text `https://licketysync.app/join#` and checks
  the rest of the string, so a URL that begins with it passes, and the reviewers confirm that the
  binaries, which parse and write join links, never request it. The query form
  `https://licketysync.app/join?` is not exempt: the two tests that show a key string in the query
  refused (`link_rejections` in `keystring.rs` and `vector_link` in `test_vectors.rs`) build it as
  `LINK_PREFIX.replace('#', "?")`, and regenerating the vectors leaves `link.json` byte for byte as
  above. licketysync.com is no longer exempt (nothing under `crates/` names it outside comments),
  and any other host on either own domain goes through `spec/allowed-hosts.txt` like any other;
  TM-31 and the list's header say so in one sentence each, and the list stays empty. The check also
  fails closed now: its pipelines ended in `|| true`, so a failing `sed`, or a `grep -r` over a
  missing `crates/`, printed "no-hostnames: ok"; a wrapper now lets only grep's no-match status
  through, and any other failure fails the check. `ci/test-no-hostnames.sh` has 40 cases: the prefix
  passes; flagged are its query form, text after the prefix that names a host, a stray host beside
  it, `/join` with neither `#` nor `?`, another path (`/latest.json`), another scheme
  (`wss://licketysync.app/relay`), a port (`:8443`), the documentation domain, a subdomain, the
  client domain as the first labels of another host, a look-alike and licketysync.dev; an own-domain
  host on the list passes; and a missing `crates/` directory and a `sed` that fails (a stand-in on
  `PATH` that exits 2) fail closed. Five of them fail against the script on `main`. The web and site
  repositories' READMEs say licketysync.app, and that both sites are published with GitHub Pages at
  their own domains, in their own commits. Test that fails without the change:
  `keystring::tests::tm_18_links_on_other_domains_are_refused`, which pins `LINK_PREFIX` and checks
  that links on licketysync.dev, licketysync.com and licketysync.app.example are refused, as a link
  and as a key file; with the old prefix it fails on the pin, and the licketysync.dev link would
  parse. Decisions for the plan:
  - The browser client's domain is licketysync.app; licketysync.dev is no longer used.
  - The link format is
    `https://licketysync.app/join#k=<key_string>[&a=<multiaddr>]...[&c=<base64url(cert_hash)>]`.
  - Links on licketysync.dev are refused with no compatibility window, since nothing was released.
  - TM-18 now also requires the link parser to refuse a link that does not begin with
    `https://licketysync.app/join#`.
  - The CI host check exempts only the join-link prefix; any other host on the project's own domains
    needs its line in `spec/allowed-hosts.txt`.

  Reviewed 2026-10-25 by a9e5f6dcb73b9d83a (correctness), a9486e108d11818de (quality) and
  a0a836decf4c85d57 (security); every finding fixed and confirmed clean on c1cd489. Author
  abcfb023a8c1eeefd; the merge agent wrote this line.
- `scorecard.yml`'s actions pinned by commit, the coordinator's ruling on the review of this series
  (TM-8): its `scorecard` job holds `id-token: write` (and `security-events: write`), so the pinning
  rule `release.yml` and `ci.yml` state covers it, and every job in the repository that holds
  `id-token`, `attestations` or `contents` write now pins every action it uses by commit
  (`release.yml`, `ci.yml`, `scorecard.yml`, each stating the rule). The pins (each tag read with
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` on 2026-10-25, an annotated one dereferenced with
  `git/tags/<sha>`): `actions/checkout` `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`, as in
  `ci.yml`'s `codecov` job), `ossf/scorecard-action` `fa7117db83c52d787ae5a89f350999701505d78e`
  (`v2.5.0`, the latest release; an annotated tag) and `github/codeql-action/upload-sarif`
  `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` (`v4.39.1`, the newest v4 release, of 2026-10-21;
  `v4.39.1` and `v4` are annotated tags that both dereference to it). upload-sarif moves from v3 to
  v4: codeql-action's changelog says v3 will be deprecated in December 2026, and `upload-sarif`'s
  `action.yml` declares the same eight inputs with the same defaults at `v3` and at `v4.39.1`
  (`sarif_file` among them), only its runtime moving from Node 20 to Node 24. Scorecard's publishing
  rules approve a job's actions by name (its README, "Workflow Restrictions"), and Scorecard's own
  published workflow (`ossf/scorecard`, `scorecard-analysis.yml`) pins the same `checkout` and
  `scorecard-action` commits and `upload-sarif` v4 by commit, so the results should stay publishable
  (the job still has no `run:` step). The action runs the container image
  `docker://ghcr.io/ossf/scorecard-action:v2.5.0`, which its pinned commit names by tag; Scorecard
  approves actions by name, so the image cannot be pinned here (a residual). Not changed:
  `codeql.yml`, whose job holds `security-events: write` and `contents: read` and so is outside the
  rule, still runs `github/codeql-action` v3 (`init`, `analyze`) by tag; moving it to v4 before
  December 2026 is a follow-up. The workflow runs weekly and on demand, so it was not run here; its
  next run, or one started by hand after the merge, is the test.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security); every finding fixed and confirmed clean on f4acfd1. Author
    ae9a81200e90b5ed4; the merge agent wrote this line.
- `rand` and `rand_xorshift` confined beneath `proptest`: the reviewers' follow-up to block `rand`
  from first-party code before phase 1, which the owner approved on 2026-10-25 ("Yes to all").
  `suites.md` section 3 counts a random source as cryptography, and section 3.2 says no first-party
  crate names or uses `rand`; first-party randomness is `getrandom` (section 4.3). Nothing enforced
  that for `rand` without its default features: a first-party crate could depend on it and draw keys
  or nonces from a generator it seeds itself (TM-5, TM-12). With its default features `rand` brings
  `chacha20`, whose wrapper entry already fails; without them, in the scratch copy below, only
  `cargo vet --locked` failed, on the missing safe-to-deploy audits of `getrandom` 0.4.3 and `r-efi`
  6.0.0 (cargo-vet counts optional dependencies), by accident and only until phase 1 vets
  `getrandom`. `deny.toml` now allows `rand` and `rand_xorshift` only beneath `proptest`, their one
  dependent today (`cargo tree -i`), in the style of `chacha20`'s entry, and `deny-production.toml`
  bans both outright for the shipped graph, where nothing reaches them. When the change that adds
  `net` brings `rand` in beneath the `libp2p-*` crates and `quinn`, as section 3.1 expects, it adds
  those wrappers in both files; the comments say so. `rand_core` and `getrandom` stay open: section
  3.2 approves both for first-party use. Test that fails without the change: in a scratch copy of
  the tree just before it, with `rand = { version = "=0.10.3", default-features = false }` (the
  locked version) added to `licketysync-engine`, the old files pass both `cargo deny check` and
  `cargo deny --config deny-production.toml check bans` (exit 0, "bans ok"); with the new files both
  fail with exit 2, "error[banned]: crate 'rand = 0.10.3' is explicitly banned", `deny.toml` also
  warning that `licketysync-engine` is not a wrapper. The same holds for
  `rand_xorshift = { version = "=0.5.0", default-features = false }`. The real tree passes both
  commands with the new files ("bans ok", no warning about the new entries). Spec change in this
  commit (`spec/suites.md` section 3.1): its decision's list of what `deny.toml` holds today gains
  `rand` and `rand_xorshift`, confined beneath `proptest`, with `deny-production.toml` banning both
  outright until the change that adds `net` gives `rand` its wrappers. Section 3.1 already required
  an entry for each primitive on the graph, and the production counterpart for one that test tooling
  reaches.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security); every finding fixed and confirmed clean on f4acfd1. Author
    ae9a81200e90b5ed4; the merge agent wrote this line.
- Codecov upload moved to a job of its own that authenticates with GitHub's OIDC token, as the owner
  approved on 2026-10-23 ("Yes, set up Codecov if it's free.") and 2026-10-25 ("Codecov - I've
  signed in and installed the Codecov app on LicketySync organization." and "Yes to all"),
  superseding Dependabot pull request #7 (`codecov/codecov-action` 4 to 7), which Dependabot closes
  once this is on `main` (TM-8, TM-29). Until now the `coverage` job ran `codecov/codecov-action@v4`
  with no token and `fail_ci_if_error: false`, so every upload from `main` was refused ("Token
  required - not valid tokenless upload", run 39994401891 on 00bb282) and the job passed. Now
  `coverage`, its permissions unchanged (the workflow's `contents: read`), uploads `lcov.info` as an
  artifact, kept 7 days, after the 90% loop passes. A new `codecov` job (`needs: coverage`) runs
  only when `github.event_name == 'push' && github.ref == 'refs/heads/main' && github.repository ==
  'LicketySync/core'`, so pull requests, Dependabot's among them, and forks, a fork's own `main`
  included, never mint a token. It holds `id-token: write` and `contents: read` and nothing else,
  and pins every action by commit under the rule `ci.yml` now states with `release.yml`:
  `actions/checkout` `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`, the latest release, which
  `v7` also points to), `actions/download-artifact` `9000827ccba6bdab643e8b6fd33ac0654aef8333`
  (`v8.0.2`) and `codecov/codecov-action` `303a32d7a59b442fa8d48b6a1cc6825c09c847a5` (`v7.1.1`, the
  latest release; `v7` is an annotated tag, dereferenced with `gh api
  repos/codecov/codecov-action/git/tags/<sha>` on 2026-10-25). It checks out with
  `persist-credentials: false`, because the action needs the repository checked out (its README) to
  map the report's absolute paths onto the repository's files. The artifact came from a job that ran
  untrusted code, so it is downloaded to `${{ runner.temp }}/lcov`, outside the checkout (inside it,
  a planted `.git/config` could have run a command when the CLI calls `git`), and a shell step fails
  unless that directory holds exactly one regular file (not a symlink) named `lcov.info`, of at most
  64 MiB. The action runs with `files` set to that path, `disable_search: true` (that report only),
  `plugins: noop` (none of the CLI's coverage tools), `cleanup: true` (the CLI downloaded into a
  temporary directory, not the checkout), `disable_telem: true` (the CLI's Sentry error reporting
  never starts: `--disable-telem` skips `init_telem` in `codecov_cli/main.py` of v11.3.1), `version:
  v11.3.1`, `use_oidc: true` and `fail_ci_if_error: true`: the action's uploader script
  (`dist/codecov.sh` at that commit) only logs a failed GPG signature or SHA-256 check of the
  Codecov CLI it downloads, and runs that CLI anyway, unless the flag is true. v11.3.1 (2026-07-09)
  is the newest release of `codecov/codecov-cli` (`gh api
  repos/codecov/codecov-cli/releases/latest`), and the `SHA256SUM` that `cli.codecov.io` serves for
  `v11.3.1/linux` equals the one it serves for `latest/linux`, the GitHub release's digest of
  `codecovcli_linux` and the hash the uploader verified in run 39994401891
  (`ca1d64196d2d34771084afe76ea657d581bf628e31d993ff8e52ea09cc88a56d`). The GPG key the script
  checks against is still fetched at run time, from Keybase. What is left: the CLI still parses
  `lcov.info`'s content.
  The job is `continue-on-error: true`, so a Codecov failure or outage shows on the job and never
  turns CI red; and a new `codecov.yml` at the root makes Codecov's own commit statuses
  (`codecov/project`, `codecov/patch`) `informational: true`, since once uploads succeed the
  installed app would otherwise post them with its default thresholds and could mark a commit on
  `main` red. The threshold the project enforces stays the gate's and the coverage job's 90% per
  crate. Codecov's validator accepted the file ("Valid!"). The weekly Dependabot review now checks
  the Codecov CLI pin for new releases and reads the result of the last `codecov` job on `main`
  (`CONTRIBUTING.md`). The job contacts Codecov's hosts (`cli.codecov.io` for the CLI and its
  checksums, Codecov's API and the storage it hands the report to), and Keybase (a third party) for
  the GPG key; TM-31 and `spec/allowed-hosts.txt` govern the hosts the binaries contact, which do
  not change. There is no Codecov token secret anywhere. Uploads start with the first push to `main`
  after this change; that run's `codecov` job is the test. The check step was run on simulated
  artifacts (one `lcov.info`; an extra file, a symlink, a directory, a 70 MB file, another name, an
  empty or missing directory, each refused).
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security); every finding fixed and confirmed clean on f4acfd1. Author
    ae9a81200e90b5ed4; the merge agent wrote this line.
- The Release workflow (`.github/workflows/release.yml`) cut to least privilege, as the owner
  approved on 2026-10-25 ("Yes to all"), superseding Dependabot pull request #4
  (`actions/attest-build-provenance` 2 to 4), which Dependabot closes once this is on `main` (TM-8,
  TM-29). Until now the workflow granted `contents: write`, `id-token: write` and `attestations:
  write` to its one job, where third-party actions (`dtolnay/rust-toolchain@stable`,
  `taiki-e/install-action@v2`), the tools they install and every dependency's build script ran, and
  checkout left the token in `.git/config`: a compromised action or crate at release time could push
  to `main` or store genuine-looking attestations of anything. Now the workflow's token is
  `contents: read`. The `build` job holds only that and checks out with `persist-credentials:
  false`; each target's binary, named after the target (`licketysync-<target>`), and the CycloneDX
  SBOMs, under `sbom-<target>/`, go up as one artifact per target. A new `attest` job (`needs:
  build`), which checks out nothing and runs only GitHub's own actions and a shell check, alone
  holds `id-token: write` and `attestations: write` (with `contents: read`, as `actions/attest`'s
  example for files grants). It downloads the artifacts with `merge-multiple: true`, which puts
  their files straight into `dist/` whether one artifact matches or two, fails unless `dist/` holds
  exactly one regular file (not a symlink) `licketysync-<target>` per target it names and no other
  `licketysync-*` entry, and attests those binaries in one attestation. It runs only for a pushed
  `v*` tag: the workflow can now also be run by hand (`workflow_dispatch`) to build both targets
  from any branch or tag, and such a run never attests. No job has `contents: write`: nothing here
  pushes or creates a GitHub release, so the change that publishes releases adds it to a job of its
  own. The aarch64 leg now builds natively on `ubuntu-24.04-arm`: on `ubuntu-latest` nothing set an
  aarch64 linker, so cargo would have linked with the host's x86_64 `cc` and failed, and no tag
  could have been attested (the workflow has never run; there are no tags).
  Pinning rule, stated in `release.yml`'s header and in `ci.yml`: a job that holds `id-token`,
  `attestations` or `contents` write pins every action it uses by full commit SHA, GitHub's own
  included; elsewhere actions stay on tags for now, and pinning every action is a pending decision.
  The pins (each tag read with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` on 2026-10-25, an
  annotated one dereferenced with `git/tags/<sha>`): `actions/download-artifact`
  `9000827ccba6bdab643e8b6fd33ac0654aef8333` (`v8.0.2`, the latest release, which `v8` also points
  to), `actions/attest-build-provenance` `4d101475d8b20a2381f78447822ac1eab6504dd8` (`v4.2.2`, the
  latest release; `v4` is an annotated tag that dereferences to it), and in the build job
  `dtolnay/rust-toolchain` `683b588c487a69d01f6c6ddf40f036ff682cc2c8` (its `v1` tag, master's head
  on 2026-10-25; the `stable` branch used until now is that commit plus a default of `toolchain:
  stable`, which the step now passes) and `taiki-e/install-action`
  `1e29709c0ec63babbe8f266397a465f29a825f91` (`v2.87.31`, the latest release, which `v2` also points
  to). The tools it installs are pinned to cargo-auditable 0.7.7 and cargo-cyclonedx 0.5.9, each the
  newest release on crates.io and the `latest` in install-action's manifest at that commit, with
  aarch64 Linux builds, and whose SHA-256 for the x86_64 musl archive equals the `.sha256` asset of
  the upstream GitHub release; `fallback: none`, as in `ci.yml`, so a version missing from the
  manifest fails instead of going to cargo-binstall. Dependabot cannot see the two tool pins, so the
  weekly Dependabot review checks them and the rust-toolchain pin (`CONTRIBUTING.md`). The Rust
  toolchain itself still floats on stable, as `rust-toolchain.toml` says; pinning it to a version is
  a follow-up.
  Verifying a release, stated in `release.yml`'s header: `gh attestation verify <file> --repo
  LicketySync/core --signer-workflow LicketySync/core/.github/workflows/release.yml --source-ref
  refs/tags/vX.Y.Z --deny-self-hosted-runners`, or with cosign the exact `--certificate-identity
  https://github.com/LicketySync/core/.github/workflows/release.yml@refs/tags/vX.Y.Z` and
  `--certificate-oidc-issuer https://token.actions.githubusercontent.com`. Other jobs here mint OIDC
  tokens too (`ci.yml`'s `codecov` job, `scorecard.yml`), so any trust placed in this repository's
  OIDC identity, now or later, is scoped to a `job_workflow_ref` of `release.yml` at a `v*` tag.
  What the split does not change: an attestation says this workflow built these binaries from this
  tag on GitHub's runners, and a compromised build step still gets a genuine one for any bytes it
  hands on; the split takes away its power to attest anything of its choosing at any time and to
  write the repository's contents. The workflow was not run (the attest job needs a `v*` tag) and
  actionlint is not installed: it was checked by hand against each action's inputs at the pinned
  commit and parsed as YAML, and its two shell steps were run on simulated trees (both binaries,
  one, a symlink, an extra binary, a directory, none; the SBOM step with and without SBOMs).
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security); every finding fixed and confirmed clean on f4acfd1. Author
    ae9a81200e90b5ed4; the merge agent wrote this line.
- Dependabot pull requests #8 (`actions/checkout` 4 to 7, in the six workflows that use it) and #9
  (`actions/upload-artifact` 4 to 7, in `mutants.yml`, `nightly.yml` and `release.yml`) merged into
  `main` directly on 2026-10-25, as 36ed13c and 85dc471, after review by a0074be8100563602: tag-only
  diffs, every step's inputs unchanged, both actions now on Node 24, and all CI green on each pull
  request and on `main` after each merge (TM-8). Dependabot's commits do not touch this file, so
  this entry is their review record. The line below names the reviewers of this entry, not of the
  pull requests.
  - Reviewed 2026-10-25 by a83b13cf45293e98a (correctness), a5d7b60f381235d5a (quality) and
    a020d1ce8061c98b4 (security); every finding fixed and confirmed clean on f4acfd1. Author
    ae9a81200e90b5ed4; the merge agent wrote this line.
- `ctutils`, `cmov` and `constant_time_eq` confined beneath their wrappers in `deny.toml`, as the
  other primitives beneath the approved crates are (`suites.md` section 3.1, TM-5): `ctutils` to
  `universal-hash`, whose Poly1305 tag comparison is its one use here; `cmov` to `ctutils`; and
  `constant_time_eq` to `blake3`, whose constant-time `Hash` equality uses it
  (`blake3-1.8.7/src/lib.rs` lines 354 to 370). The changes that added `chacha20poly1305` and
  `blake3`, which brought them in, added no entries, so until now any first-party crate could depend
  on them directly and compare secrets with them instead of `subtle` (section 4.2). The other
  cryptography crates were checked against the lock file: every primitive beneath an approved crate
  already had its entry (`curve25519-dalek`, `fiat-crypto`, `ed25519`, `signature`, `sha2`,
  `chacha20`, `poly1305`, `universal-hash`, `cipher`, `aead`, `bitcoin_hashes`). `subtle` and
  `zeroize` are approved crates that first-party code may use, so they stay open. `rand`,
  `rand_core` and `getrandom` reach only the dev graph, through `proptest`. Trait, buffer and
  platform crates with no primitive of their own (`digest`, `crypto-common`, `block-buffer`,
  `inout`, `hybrid-array`, `cpufeatures`, `typenum`, the proc macro `curve25519-dalek-derive`) are
  not entries. Section 3.1's text needs no change: it already says that `deny.toml` restricts the
  primitives beneath the crates `keys` uses to listed wrappers, and that a change that adds another
  adds its entry; `deny.toml` lacked these three. They go in `deny.toml` alone: test tooling reaches
  none of them, so `deny-production.toml` needs no counterpart. Test that fails without the change:
  in a scratch copy of 48fdd51, each of the three made a direct dependency of `licketysync-engine`
  passes `cargo deny check bans` ("bans ok"); with this `deny.toml` each fails with exit 2,
  "error[banned]: crate '<name> = <version>' is explicitly banned" and an unmatched-wrapper warning
  naming `licketysync-engine`. The tree itself still passes both `cargo deny check` and
  `cargo deny --config deny-production.toml check bans`.
  Reviewed 2026-10-23 by a6f5b62e386e3052d (quality) and ae6e5cf67635866e1 (security), both clean.
  Author a9de371d3a0c03b1f; the merge agent wrote this line.
- CI's coverage job renamed from "coverage (cargo-llvm-cov, 90% on key/protocol/engine)" to
  "coverage (cargo-llvm-cov, 90% on keys/protocol/index/engine)", the crates its loop holds to 90%
  line coverage, as `gate.sh`'s does, since the index crate joined them (the review ruling of
  2026-10-22). Only the display name changes; no ruleset requires a status check by name.
  Reviewed 2026-10-23 by a4bc86829376620ff (correctness, clean), a6f5b62e386e3052d (quality; one
  should-fix, fixed, confirmed clean) and ae6e5cf67635866e1 (security, clean; confirmed, also for
  the correctness reviewer's items). Author a9de371d3a0c03b1f; the merge agent wrote this line.
- `ctutils` updated from 0.4.3 to 0.4.4 for RUSTSEC-2026-0385, "Non-constant-time mask generation
  and `u128` comparisons" (https://github.com/RustCrypto/utils/pull/1569, the 0.4.4 release; the
  fixes are its pull requests 1567 and 1568), published on 2026-10-23. It turned the Nightly
  workflow's cargo-audit job red in run 39931142612 on `main` (fd50a2a), and the next push to `main`
  would have failed the same way in CI and in `gate.sh`. `ctutils` is reached only as
  `licketysync-keys` → `chacha20poly1305` 0.11.0 → `poly1305` 0.9.1 → `universal-hash` 0.6.1 →
  `ctutils`. `Cargo.lock` moves `ctutils` to 0.4.4 with `cargo update -p ctutils --precise 0.4.4`
  and nothing else changes: `universal-hash` asks for `^0.4`, and 0.4.4 asks for the same `cmov`
  `^0.5.3` as 0.4.3 (still 0.5.4, which RUSTSEC-2026-0003 does not affect).
  `supply-chain/config.toml` moves the phase 0 exemption that covered 0.4.3 to 0.4.4, with the same
  criteria, safe-to-deploy, because no imported audit set covers 0.4.4 either (`cargo vet` unlocked
  left `imports.lock` unchanged); its note says that 0.4.4 was reviewed in this fix and what its
  diff from 0.4.3 holds, in the style of the bech32 exemption's note. 0.4.5, published three hours
  after 0.4.4, only hardens Thumb-1 (ARMv6-M) targets and adds a public `primitives` module; it is
  not taken here, and arrives with a later `cargo update` or with a direct dependency's bump
  (Dependabot's version updates cover only the crates our manifests name). On fd50a2a `cargo audit`
  and `cargo deny check advisories` both fail with this advisory; with the change both pass, as do
  `cargo deny check`, `cargo vet --locked` and `cargo machete`, and cargo-geiger's counts do not
  change (`ctutils` forbids unsafe code in both versions). Impact: the advisory names
  `Choice::to_u8_mask` to `to_u128_mask`, which 0.4.3 built from the raw byte without `to_u8`'s
  `black_box` barrier, so the compiler could branch on it, and the `u128` comparisons
  (`Choice::from_u128_lt` and `from_u128_le`, `CtLt` and `CtGt` for `u128`) on targets with 32-bit
  pointers (the fix's cfg, which includes wasm32 and 32-bit ARM). The one call into `ctutils` in our
  graph is `UniversalHash::verify` (`universal-hash-0.6.1/src/lib.rs` line 137), which `poly1305`
  inherits and `chacha20poly1305` calls to check the tag on every open
  (`chacha20poly1305-0.11.0/src/cipher.rs` line 90, reached from `xchacha_open` in
  `crates/keys/src/aead.rs`, which chunks, sealed metadata and the handshake's `FolderProof` open
  through). It compares the two 16-byte tags with `<[u8] as CtEq>::ct_eq`, which for `u8` is
  `cmov`'s word-wise `cmoveq` (`ctutils-0.4.3/src/traits/ct_eq.rs` lines 65 to 109), and turns the
  `Choice` into a `bool` through `to_u8`'s `black_box` (`ctutils-0.4.3/src/choice.rs` lines 387 to
  398 and 575 to 578). None of the affected functions is on that path: the masks feed only
  `Choice::select_i64` and `select_u8` to `select_u128` (`ctutils-0.4.3/src/choice.rs` lines 310 to
  362), which nothing here calls, and `hybrid-array`'s optional `ctutils` feature is off. So tag
  verification was not weakened, and sealing does not reach `ctutils`. Nothing has been released
  (phase 0), so nothing shipped was exposed. TM-8's daily cargo-audit feed caught the advisory as
  designed; TM-5, TM-10 and `suites.md` sections 2.3, 3.1 and 4.2 (the tag compared inside the
  approved crate, `ctutils` allowed only beneath it) are unchanged.
  Reviewed 2026-10-23 by a4bc86829376620ff (correctness, clean), a6f5b62e386e3052d (quality; one
  should-fix, fixed, confirmed clean) and ae6e5cf67635866e1 (security, clean; confirmed, also for
  the correctness reviewer's items). Author a9de371d3a0c03b1f; the merge agent wrote this line.
- Index crate built for shared folder keys (`licketysync-index`), to `spec/protocol.md` §4.4 and
  §4.5 over the rebuilt protocol crate, in place of the skeleton; the old crate's model (forks,
  equivocation, the cover forest, version vectors) is not carried over. `Index` holds one folder's
  signed records by record hash and by writer in canonical order (ascending `seq`, then record hash)
  and implements the protocol crate's `Held` (for `judge`) and `Cursors` (for the requests the
  connection builds); `accept` runs steps 2 to 5 through `judge` (duplicates and push gaps ignored
  unverified, reply gaps and out-of-scope writers sender violations, the folder key's signature
  before anything is stored), step 6 with the data key (a writer fault stored opaque and counted in
  the cursor and digest; a sealed holder stores records unopened and computes no heads), appends the
  record to the store, and only then step 7. Each writer's digest at every `seq` is cached: a record
  that sorts last in canonical order (at the cursor plus one, or at the cursor above the others
  there) takes one digest step, one that lands lower recomputes from its own `seq` up, a reopen
  replays the records in canonical order at one step each, and serving reads the cache. An applied
  record waits while a record it names is not held or itself waits (an opaque record never waits,
  and a record naming one does not wait for it); a record that stops waiting is activated through a
  work list, so the versions it names leave their paths' heads and it joins its own, and the heads
  equal the spec's definition for the set of records held in any arrival order. Heads are kept in
  display order (non-tombstones first, directories before files, then the greater `mtime_ns` and the
  smaller record hash, tombstones last in the same order), so the version at a path, deletion,
  conflicts and the first heads a write names cost a lookup; conflict copies (content differs by
  kind or by `plain_hashes`, compared in constant time) walk the heads. `draft` and `draft_rename`
  name a path's last known versions: its heads, then the versions of it a rename superseded that no
  record at the path has replaced since (kept per path beside the heads), in display order, at most
  `MAX_SUPERSEDES` (a rename the old path's, then the new path's); `write` signs with the write key
  and appends before it returns. `Reply` serves one request page by page by cases (a) to (d) from
  the index it is given, under that index's folder ID, reporting the writers case (c) marks
  (`Connection::send_page`'s `resent`), and resumes where it stopped. `Store` is `load` and one
  atomic `append` per record, persisting the records as received and nothing else; `MemoryStore` is
  phase 0's.
  - Spec changes in this commit (`spec/protocol.md`, `spec/threat-model.md`; the review rulings of
    2026-10-22): a write names the path's last known versions, its heads and the versions of it a
    rename superseded that no record at the path has replaced since, so a file renamed away and a
    new file then written at the old name never show a false conflict on a peer that has the new
    file before the rename, heads named before the renamed versions within the 16 (§4.4, "Versions
    and heads"; R2 SF2, R1 SF1, SEC N5); an opaque record never waits, whatever it names (§4.4); the
    display order puts tombstones last and orders them, as the others, by `mtime_ns` then record
    hash, their kind not compared (§4.4); the digest cache's cost: a record that sorts last takes
    one step, and a rebuild replays the records at one step each (§4.4 and step 5; SEC-B1); a
    **store failure** row in section 5 (this device's index store cannot take a verified record:
    nothing changes, the folder pauses until the store takes records again and then owes each
    connection a round) and the matching clause in §4.4 step 4 and TM-22 (SEC N3); §8 item 7 runs on
    a read holder and a write holder alike, says which heads remain after the 16-name cases (the
    write and the one left unnamed; the 4 left unnamed beside the rename, 5 in all), and gains the
    rename-then-new-file and the opaque-record-naming-a-missing-hash cases (R1 N3, N4); TM-9 and
    §3.12: the device's own index store, and any backup restored into it, is trusted like the key
    store, with what a corrupted or edited store would do (SEC-SF2, R1 SF3).
  - Decisions (for the plan): phase 0 keeps the index in memory behind `Store` (the plan's index
    decision of 2026-10-14/15); `Store` is the durability seam of phase 0 only: the index keeps
    every record and everything derived in memory whatever the store, and phase 1 moves those maps
    into `SQLite` on disk (the plan's best-in-class row: on disk, under 1 KB of index per file), the
    trait changing with it (R2 SF1); the store holds only the records: cursors, cached digests,
    opaque and waiting records, heads and renamed-away versions are rebuilt when the index opens, by
    replaying the records in canonical order through step 1 and step 6 again; `open` trusts the
    store and does not verify signatures again (each was verified before it was appended), and phase
    1 verifies at open (in a batch) or in `doctor`, as the plan's "Recovery is local" says, or keeps
    a keyed checksum per record (R1 SF3, SEC-SF2; the owner question below); this device's next
    `seq` is its cursor for its own device ID plus one, so appending a record commits the counter
    and a record under its ID from elsewhere moves it; each record is appended on its own,
    atomically, before anything changes in memory, so a store failure changes nothing (batching per
    page is phase 1's; R2 N4); on a store failure the engine pauses the folder, accepting none of
    its records, until an append succeeds, and then owes a round on each connection where it is open
    (SEC N3); a reply's pages take their folder ID from the index they are built from, so they can
    never carry one folder's records under another's ID (R2 SF3, SEC N4); the index holds the folder
    key at its tier (verification key, data key, write key); a record of another folder is refused
    before it is judged.
  - Phase 1 question for the owner (SEC-SF2): when the index is on disk, verify every stored record's
    signature when the index opens (measured about nine times slower to open, some 7 s per 100 000
    records) or keep a labelled keyed checksum per stored record from the keys crate.
  - Vectors (`crates/index/tests/vectors/*.json`, regenerated with `LICKETYSYNC_REGENERATE_VECTORS=1
    cargo test -p licketysync-index vector_`): `outcomes.json` (item 6's outcomes against a writer's
    records), `heads.json` (item 7 whole, each delivery and write with the heads after it, every
    step checked against a read holder given the same records) and `digests.json` (item 8's cached
    digests, serving cases (a) to (d), equal cursors, a listed request and a range that excludes the
    writer, each page's records asserted, and two indexes converging through range and listed
    requests). Each case's rows are the ones its outcomes reached, and every name in the files is
    spelled out, never a `Debug` form (R2 N11). Property tests: arrival order (with gaps and
    duplicates) never changes cursors, digests, waiting records, heads or renamed-away versions, nor
    does reopening, and all equal a naive computation from the set of records; histories without
    concurrent edits, drafted by the index itself, never show two heads at any step, a path renamed
    away and written again included (the narrowing of e304e07 removed); two indexes that exchange
    end with the same records and heads. Bounded work is counted in digest steps and waiter
    notifications: k versions at one `seq` in canonical order cost k steps on arrival and on reopen
    (SEC-B1); the dedup on open has a regression test (R1 SF2).
  - `gate.sh` and `ci.yml` hold the index crate to 90 % line coverage per crate, and `ci/mutants.sh`
    (with `ci/test-mutants.sh` and `mutants.yml`) runs cargo-mutants on it, since TM-17, TM-40 and
    TM-41 name it as their enforcer (R2 N14).
  - `ci/geiger-baseline.txt`: the index crate now builds on the protocol crate's unsafe counts.
  - Dependencies: none new; `licketysync-keys` and `licketysync-protocol` (normal), `proptest`,
    `serde_json`, `hex` and `prost` (dev), all already in the tree and vetted.
  - Reviewed (2026-10-22) on e304e07 by three fresh-context agents (Claude Opus 5.5): correctness
    adffa6f35bc9c6984, quality a291f17548a6bbd28 and security a81869b0f8884df7d (the
    security-reviewer pass); the accepted findings were applied in this commit (the one-step digest
    extension and linear reopen, the rename rule, `Reply` built from the index, one atomic `append`,
    the store-trust documents, and the tests, vectors, CI lists and spec edits they named);
    confirmed clean 2026-10-22 by a291f17548a6bbd28 and a81869b0f8884df7d (the latter also for
    adffa6f35bc9c6984's items); the merge agent wrote this line.
- Protocol crate rebuilt for shared folder keys (`licketysync-protocol`), to `spec/protocol.md` as
  rewritten for that model (and amended here, below), over the reworked keys crate (every key,
  hash, label, signature and cipher is the keys crate's; the protocol crate depends on no
  cryptography crate). Ported from the twice-reviewed old crate (`wip/protocol` 519bd9b) and
  adjusted: the frame decoder (length checked before any allocation, the body grown as it arrives),
  the strict proto3 reader (field numbers 1 to 2^29 - 1, no group wire types, each singular field
  once, `bool` 0 or 1, `uint32` below 2^32, repeated scalars packed, unpacked or mixed), the bounded
  parser of every message, the Close that keeps its reason when its detail breaks the grammar,
  `Unsupported` once per type, the pager and its byte accounting, the feature grammar and the shape
  of the connection state machine. New: `hello` (the 3.2 checks with the canonical device key,
  roles, the transcript hash), `proof` (one folder proof for every tier, over the keys crate's
  `seal_proof` and `open_proof`, the hint table built once per connection, the uniform REJECTED for
  every failure of 3.5), `record` (an index record's step 1 against the open folder, steps 2 to 5
  in the spec's order as `judge` over a small `Held` trait the index implements, step 6 with the
  path grammar, the kind and the chunk count, a directory with chunks and a non-empty file without
  chunks writer faults, NFC left to writers, the writer's `Draft::sign`, and the reference writer
  digests), `exchange` (typed cursors, the `Cursors` trait the index implements, range and listed
  scopes, the round split at `MAX_CURSORS_PER_REQUEST`, the serving cases (a) to (d), the page
  limit 64 to 4 096), `rules` (the section 5 table: 25 causes, their outcome and what each leaves
  behind), `limits` (every constant of sections 2 to 5, `MAX_SEND_QUEUE` and
  `MAX_REQUESTS_IN_FLIGHT` defined here once), and `connection`: per connection the handshake, the
  open folders, one `IndexRequest` per folder each way with fresh request IDs, built by the
  connection itself from the index's cursors (the next range read from above its start), the round
  on open and the next ranges, marks (gap or resend, 1 024 at most, overflow owes a round), the
  round owed by an empty push with its `INDEX_RESYNC_INTERVAL`, the gap-triggered listed request's
  interval, the peer's request held until `INDEX_REQUEST_MIN_INTERVAL` after serving the previous
  one began (its first page), every record of a page decoded once and past step 1, judged in or out
  of the request's scope, a reply page with `more` and no records malformed, pushes dropped when the
  send queue cannot take them with one never-dropped empty push owed, `REPLY_PAGE_TIMEOUT` counted
  from the request's departure from the send queue and restarted by pages, `CHUNK_OK` and stored
  pushes, chunk requests within the peer's `max_requests_in_flight` taken as at most
  `MAX_REQUESTS_IN_FLIGHT` (1 024) and one per (folder, hash), `CHUNK_BUSY` at dispatch at half of
  `MAX_SEND_QUEUE` counting the backlog, the backoff of 1 s doubling to 64 s and back on `CHUNK_OK`,
  chunk passes in ascending hash order waiting after a `CHUNK_NOT_FOUND` for a greater
  `chunks_stored` or a completed round (either remembered while the pass still asks, and judged when
  it ends) with one pending bit, the ciphertext hash of every chunk received and of every chunk sent
  (a blob corrupt in storage is never sent, TM-10), Status with `chunks_stored` and the device name
  once, `HELLO_TIMEOUT`, `PROOF_TIMEOUT`, `IDLE_TIMEOUT` and the delivery stall, and the close
  flush. Time, the transport's unsent bytes and randomness come from the caller (a `Tick` per call;
  the keys crate's `RandomFill`); one wake-up deadline per connection, which also hands over a held
  request when it may be served.
  - The engine's side of a connection: `receive`, `wake`, `prove` and `close`; `send_request(tick,
    folder, &cursors)` when `Event::RequestDue` says one is due; `Event::Serve` hands over a peer's
    request when it may be served, and `send_page(tick, &page, resent)` sends its pages, marking the
    writers resent in full (case (c)); `push(tick, &page)`; `judged(tick, folder, page, results)`
    takes the index's judgement of each record of an `Event::Records` page and itself marks gaps on
    a push, restarts the deadline for a push that stored a record and closes on a forged record or
    a sender violation; `chunk_position`, `request_chunk` and `pass_done`; `reply_chunk(tick,
    folder, hash, ChunkAnswer::Ok(blob) | ChunkAnswer::NotFound)`; `chunk_stored`; `send_status(tick,
    folders)`; and `want_room(tick, len)`, after which `Event::Room` comes once a frame of that
    length would be handed over. Every send that fails returns its `SendError` and changes nothing.
  - Decisions (for the plan): the connection keeps a small backlog of frames it may not hand to the
    transport yet, since three rules need the unsent bytes (a frame goes only while unsent plus the
    frame stay below `MAX_SEND_QUEUE`; a Close is never held back); the backlog holds only the
    connection's own small frames and this side's requests, each bounded by a constant, while what a
    peer can make this side send in volume (reply pages, `CHUNK_OK`) and Status are refused with
    `SendError::WouldBlock { len }` and stay with the engine until `Event::Room` (a Status is
    skipped instead; the next is due within `STATUS_INTERVAL`); `has_room` counts the larger of the
    tick's unsent bytes and what this side has handed over since, plus the backlog; while it waits
    on the transport, or the engine waits for room, the connection asks to be woken every
    `SEND_POLL_INTERVAL` (1 s), an implementation constant the spec does not fix, because the
    transport drains between calls without telling anyone; one timer per connection; an
    `IndexRequest` goes only when the connection says one is due, and the connection builds it;
    within a round the next range goes before a listed request for marks; a Hello with several
    faults is refused for the first found, the parse first, then the 3.2 order; every peer chunk
    request counts against this side's `max_requests_in_flight` until its reply, `CHUNK_BUSY`
    included, has left the backlog, so a peer that never reads cannot make replies pile up
    (security check of the WIP commit); a requester refuses to ask twice for a hash it has asked for
    on the connection (SEC-B1); the open-folder bound of 3.5 step 6 counts the proofs this side
    accepted, so a folder the peer rejected takes no slot (R1 N1); a tombstone's kind and size name
    what was deleted, so the two step-6 rules on a directory with chunks and a non-empty file
    without chunks do not apply to a tombstone; §3.5 step 5 (the folder's suite missing from the
    peer's Hello) cannot be reached while suite 1 is the only suite, since a Hello without it has no
    suite in common and is closed `NO_COMMON_SUITE`, so it has no vector; and the largest Hello this
    release sends is a frame of 2 583 bytes for suite 1 alone (2 587 with the length field), below
    the 2 664 that `protocol.md` section 2 states for any release of major 1.
  - Spec changes in this commit (`spec/protocol.md`; the review rulings of 2026-10-22):
    `MAX_REQUESTS_IN_FLIGHT` (1 024; a Hello advertising more is taken as that) in section 2's
    table, the Hello field of 4.2, 4.6 ("Who may ask") and section 5's limits sentence and constants
    table (SEC-B1); a reply page with `more = true` and no records is malformed, in 4.5 (the
    `IndexRecords` field, "Pages", "Replies and pushes") and section 5's malformed row, with the
    residual that a responder sending pages of records the requester already holds restarts the
    reply deadline with each, in 4.5 ("Reply deadline") (SEC-SF3); `CHUNK_BUSY` counts the frames a
    holder holds back for room, in 4.6 (SEC N8); `supersedes` holds at most 16 entries as encoded,
    a repeated entry counting once (producers sort and drop repeats, verifiers accept repeats within
    the 16), in 4.4's field and step 1 (R1 N4); and a Status the send queue cannot take is skipped
    rather than queued, in 4.5 (which SEC-SF2 implies for the wire).
  - Vectors (`crates/protocol/tests/vectors/*.json`, regenerated with
    `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-protocol vector_`, which also writes
    the fuzz seeds): items 1 to 5 and 10 whole (item 5 without §3.5 step 5, unreachable as above),
    the decoder vectors of items 6, 8, 9 and 11, item 6's outcomes of steps 2 to 5 through `judge`
    for a holder of a fixed record, and connection scenarios between two real connections for items
    5, 8, 9 and 11 (every frame both ways with its time, the rows, the end states): among them PUSH-2
    served by hand (page 1, the push of a record accepted meanwhile for a writer the reply is past,
    page 2), and the reply deadline with every chunk request answered `CHUNK_BUSY` (closed) and with
    `CHUNK_OK` replies arriving (kept open); item 8 also records pages of 4 096 records (accepted)
    and 4 097 (refused), a push with `more`, a reply page with `more` and no records, and a page
    with an unknown `request_id`. The folder-proof payloads equal the keys crate's `handshake.json`.
    Item 7 and the cached digests are the index crate's. Inputs over 4 KiB are recorded by length
    and prefix.
  - Fuzz targets: `frame_decode` (replacing the placeholder), `message_parse` (every bounded decoder
    behind a selector byte, with a canonical round-trip check), `hello_check`, `folder_proof`,
    `index_record` (steps 1 to 6), `index_records` (the page decoder and the keys crate's envelope
    decoder agree on every embedded record, both ways), `sealed_meta` and `handshake` (a fresh
    connection fed a peer's whole stream, and one with the folder open between two real
    connections), with seeds from the vectors.
  - `ci/geiger-baseline.txt`: the protocol crate now builds on the keys crate's unsafe counts.
  - Dependencies: none new; `prost` and `licketysync-keys` (normal), `proptest`, `serde_json` and
    `hex` (dev), all already in the tree and vetted; the fuzz crate adds `prost`.
  - Reviewed (2026-10-22) on e008cb5 by three fresh-context agents (Claude Opus 5.5): correctness
    a51271a428222e6f6, quality aa10ee3925cfd6e22 and security abf73e7d30fd47189 (the
    security-reviewer pass); the accepted findings were applied in this commit
    (the chunk-pass trigger of a round or Status that comes while a pass still asks, the requester's
    in-flight cap and one request per hash, the send-backlog bound and the room event, the typed
    sends and `judged`, the held request in the one wake-up, the chunk check before sending, the
    empty `more` page, and the tests, vectors and spec edits they named); confirmed clean
    2026-10-22 by aa10ee3925cfd6e22 and abf73e7d30fd47189 (the latter also for
    a51271a428222e6f6's items); the merge agent wrote this line.
- CI fixed forward after run 39869811485 on `main` (ab8b0f8), where two jobs
  failed. On Windows the keys crate's 12 vector tests failed with "<name>.json
  is not byte for byte": Git for Windows checks files out with
  `core.autocrlf=true`, which turned the committed vectors' LF into CRLF, and
  would also turn a fuzz seed's LF into CRLF on checkout (`link_parse/link-01`)
  and drop the CR of a seed's CRLF on commit (`words_parse/words-03`). The new
  `.gitattributes` unsets `text` for `crates/*/tests/vectors/**`, which covers
  the protocol crate's vectors when they land, and for `fuzz/seeds/**`, so git
  converts their line endings on no OS; `-text` rather than `text eol=lf`
  because a seed holds any bytes and a vector must be committed exactly as its
  test wrote it. `-text` does not change how git diffs these files: gitleaks'
  history scan reads the text ones as before and, as before, skips the seeds
  git takes for binary (a NUL byte; 15 today), so CI's gitleaks job now also
  runs `ci/gitleaks.sh tree` after the history scan, which reads them, and
  `ci/gitleaks.sh` says why. The tests are unchanged. Nothing else depends on
  the conversion: the only CR bytes in the repository are in seeds, there is no
  Windows script, and the registry test, which reads `spec/*.md`, passes on
  Windows with CRLF. The new `ci/test-vector-line-endings.sh` checks with
  `core.autocrlf=true` that every tracked vector and seed checks out, and every
  one in the working tree would commit, byte for byte, and that the patterns
  reach another crate, a nested directory and a new fuzz target and nothing
  else; on ab8b0f8 it fails 21 checks. `gate.sh` runs it, and so does CI's
  `ci-scripts` job (renamed to say so). gitleaks' history scan reported two
  `generic-api-key` findings in ab8b0f8, both public: the `lsr1` key string
  made from fixed seeds that `crates/keys/tests/vectors/link.json` names
  "key_string" (line 2), and the word after "sealed keys," in the keys crate's
  package description (`crates/keys/Cargo.toml` line 3). History mode reads
  that commit on every run, so the fix is configuration. `.gitleaks.toml` gains
  a second allowlist shaped like the hex one: `generic-api-key` only, a JSON
  file directly under a crate's `tests/vectors/`, and a value that is `lsr1`
  followed only by lowercase Bech32 characters: a read key string, the only
  tier a vector needs today, so a write or sealed key string is still reported
  even there, and the allowlist takes another tier only when a vector needs
  it. Its header, which said no rule matches key strings, now says where the
  rule reports one and what is still missed, the binary files the history
  scan cannot read included. The new `.gitleaksignore` holds one fingerprint,
  `ab8b0f8f52516ade778165b3df9043025846cca1:crates/keys/Cargo.toml:generic-api-key:3`,
  which names its commit and so skips that one finding in that one commit; the
  description now says "records signed with Ed25519", so the working tree,
  which `gate.sh` scans and whose findings carry no commit, has nothing to
  skip. gitleaks 8.30.1 reads that file from the root of what it scans, which
  both modes of `ci/gitleaks.sh` provide, and `--ignore-gitleaks-allow`
  disables inline `gitleaks:allow` comments only (its `cmd/root.go` and
  `detect/detect.go`). The protocol crate's vectors and the fuzz seeds on
  `wip/protocol-v2` (e008cb5) hold nothing the default rules report. gitleaks
  8.30.1 finds no leaks with `ci/gitleaks.sh history` over `main`, the
  Dependabot branches and this commit, nor with `ci/gitleaks.sh tree`; in a
  scratch copy it still reports values planted in a vectors file in other
  forms (mixed case, upper case, a write and a sealed key string, a link code,
  a key string with a stray character, a GitHub token), in a nested directory,
  in a non-JSON file and in Rust source, and the old description in the
  working tree. Reviewed (2026-10-22) on ac8bcc4 by two fresh-context agents
  (Claude Opus 5.5): correctness a9f6488ff90b881e8, clean, and security
  aadde0e48576c42ad, the security-reviewer pass, blocked by 1 wording
  should-fix. The accepted items (that wording, the tree scan in CI and the
  allowlist narrowed to read key strings) were applied in this commit;
  confirmed clean 2026-10-22 by aadde0e48576c42ad; the merge agent wrote this
  line.
- Keys crate reworked for shared folder keys, to `spec/keys.md` and `spec/suites.md` as rewritten in
  the entry below. Removed, with their tests, vectors, fuzz targets and seeds: the recovery phrase
  and the master secret, the identity seed and catalogue key, root seeds and folder nonces, key pair
  sets (Ed25519 + ML-DSA-65 + X-Wing from one seed), hybrid signatures and their hedged and
  deterministic forms, key IDs, X-Wing wrapping through HPKE, the epoch ladder, data keys per epoch
  and their confirmation values, the Folder record (genesis and every later form), grants and
  chains, `may_share`, expiry, Rotation, Wrap, Revocation, Suspension and Lift records, the
  key-record store with its quotas, refusal memory and held grants, the link's grant bundle (`g=`),
  the `test-vectors` feature, and `ci/no-test-vectors.sh` with its test, its `gate.sh` steps and its
  CI job (Ed25519 signing is deterministic, so vectors reproduce through the production signing path
  and no test-only signing mode is left to keep out of a shipped build). Kept and adjusted: the
  label registry (now the 25 labels of `keys.md` §10, with the registry test exact against both
  specs and a new test that `suites.md` §2.4 copies `keys.md` §10 row for row), XChaCha20-Poly1305
  helpers, Padmé and chunk encryption (associated data now the folder ID alone; only implemented
  compression codes decode, which in phase 0 is `0`), discovery hashes, the device's libp2p identity
  and DHT key, the link code and link proof, links and `.lskey` files (`k`, `a`, `c`), the strict
  protobuf scan (each singular field once, `uint32` range, no groups) and the BIP39 English word
  handling. New: `folder` (the write secret and its derivation tree, `WriteKey`, `ReadKey`,
  `SealedKey`, `FolderKey`, the folder verification key, the `FolderVerifier` that every tier
  carries, lowering to a lower tier, and the stored form `u8(tier) || payload` of `keys.md` §8.2; a
  read or sealed key is made only from a write key or a payload, never from loose halves), `sig`
  (Ed25519 over `label || 0x00 || body`, `verify_strict` only, and the check that every public key
  received from anywhere is the canonical encoding of a point not of small order, which
  `ed25519-dalek`'s ZIP-215 decoding does not make), `records` (the two-field `SignedRecord` of
  index records with its 4 000 000-byte cap and strict prefix, signing and verification under the
  folder key, the record hash and the writer digest; `SignedRecord::from_bytes` is the only way from
  bytes to a record, since the type has private fields and no Protocol Buffers decoder of its own,
  and the module documents which `protocol.md` §4.4 step-1 checks it makes and which stay the
  protocol crate's), `sealed_meta` (seal and open of index records' metadata under `rk` with
  `folder_id || device_id || be64(seq)`, 40 to 1 572 864 bytes on both sides), `handshake` (roles,
  the hint key and payload key derived from the access key, the hint, and
  `HandshakeKeys::seal_proof` and `open_proof`, which draw the proof's nonce inside the crate and
  seal and open the `FolderProof` payload under the proof key: one proof for every tier), `chunk`'s
  keys built only from a write or read key (`chunk_keys`), with `seal_chunk` returning the plaintext
  hash, `device` (the device key, the Hello form of its public key checked canonical, the device ID
  and the device proof), key strings with the `lsw`, `lsr` and `lss` prefixes (65 and 116
  characters, decoders capped at 116) decoded in the order of `keys.md` §6.1 as amended (the Bech32m
  string, a payload of under 2 bytes, the suite whatever the length, then the length under that
  suite, then the verification key), and the write key's 24 words with `keys.md` §6.2's refusal
  order (the count, then the first token that is no word or unique four-letter prefix, then the
  checksum), entry text over 4 096 bytes refused before it is split. The public surface is narrowed
  to what callers need: the AEAD module, `derive_key`, the signed-message prefix, the proof key and
  every key below a folder key but the record key are private to the crate; only the write secret,
  the device seed and the link secret can be made from bytes or randomness outside it; no secret
  type is `Clone`, every secret is built in place (the `blake3::Hash` temporaries are wiped too),
  and error values carry no length read from inside a ciphertext. Test vectors regenerated for all
  twelve items of `keys.md` §9 (folder, key strings, words, device, discovery, chunk, Padmé, index
  record, handshake on a fixed transcript hash in both roles through the production sealing path,
  the 14 `derive_key` labels, link, linking) and checked byte for byte against the committed files,
  with the items the review and the amended §9 add: key strings with a 1-byte payload and with suite
  2 at another length than suite 1's, and a chunk whose compression-0 payload is one byte over
  `MAX_CHUNK_PLAINTEXT` (given by its header, padded length, nonce and ciphertext hash rather than
  its 4 325 416 bytes); the RFC 8032, XChaCha draft (now in the AEAD module's own tests), BLAKE3 and
  BIP39 Trezor vectors stay, the Trezor set now all eight of its 256-bit entries. Property tests for
  key strings, words (random case, whitespace runs and four-letter prefixes), the stored form,
  links, link codes and signed records, each also feeding arbitrary input to its parser; tests of
  every length cap exactly at the cap. Fuzz targets: `chunk_open` (now under the vectors' folder),
  `key_string_parse`, `link_parse`, `link_code_parse`, and new `index_envelope_parse`,
  `words_parse`, `sealed_meta_open`, `device_proof_verify` and `stored_key_parse`, with seeds from
  the new vectors, each asserting that what it accepts round-trips; the old targets' seeds are gone.
  Dependencies removed: `ml-dsa`, `hpke` (and with it `x-wing`, `ml-kem`, `x25519-dalek`, `hkdf`,
  `hmac`, `kem`, `module-lattice`, `sha3`, `shake`, `turboshake`, `keccak`, `sponge-cursor`, and the
  never-built `pkcs8`, `der`, `spki`, `const-oid`, `base64ct`) and `rand_core` as a direct
  dependency. The reviewed Dependabot pull requests 1 and 2 are folded in: `bech32` moves from 0.11
  to 0.12 (the key-string vectors are byte-identical; its error-correction API is not used) and
  `base64` from 0.22 to 0.23 with default features off and `alloc` only, so its `simd-unsafe` code
  is not built. `deny.toml` loses the entries of the removed crates and their wrappers, and `blake3`
  and `chacha20poly1305` now have `licketysync-keys` as their only wrapper (the
  `licketysync-protocol` wrappers are gone); `ed25519-dalek`, `bip39` and the primitives beneath the
  remaining crates keep their confinement to `licketysync-keys`. `.semgrep/project.yml` no longer
  excludes `crates/protocol/src/hash.rs`, which does not exist. `supply-chain/`: exemptions for
  `bech32` 0.12.0 (replacing 0.11.1) and `base64` 0.23.1 (0.22.1 was covered by the Google import);
  `cargo vet prune` dropped the exemptions of the removed crates and replaced those of `chacha20`,
  `cpufeatures`, `getrandom`, `rand`, `rand_core` and `zeroize` with imported audits; stale notes
  updated. `ci/geiger-baseline.txt`: keys 94 4333 23 2 63 (was 95 4352 23 2 63). README's keys-crate
  row follows the new model. Coverage of the keys crate: 99.6 % of lines.
  Decisions for the plan:
  - The `test-vectors` feature and `ci/no-test-vectors.sh` are removed: Ed25519 signing is
    deterministic and every vector reproduces through the production path.
  - The crate's share of `keys.md` §8.2 in phase 0 is the stored form of one folder key; Argon2id
    and its RFC 9106 vectors arrive with the phase 1 key store, as both specs now say.
  - The handshake role is a type (`Role::A`, `Role::B`) rather than a byte everywhere the crate
    takes one, and a folder's hint key and payload key are derived once into `HandshakeKeys`, which
    a device caches per folder.
  - Join links are capped at 8 192 characters (was 262 144 with the grant bundle).
  - `SignedRecord::from_bytes` judges the envelope and the body's `record_type`; the rest of an
    index record's parse (its suite and folder, which need the open folder, and every other field)
    is the protocol crate's, whose schema the keys crate's vectors mirror in test code only.
    Protocol messages carry each embedded record as raw `bytes` and the protocol crate reads it
    only through `SignedRecord::from_bytes` (ruling SF6), keeping its own strict decoder for its
    messages; `verify_index_record` reports a forged record as `SignatureError`.
  - Word entry refuses a text over 4 096 bytes before splitting it (security N-4); `keys.md` §6.2
    does not state the cap yet.
  - `HandshakeKeys::seal_proof` returns its `(nonce, sealed)` inside a `Result`, since the AEAD's
    seal is fallible (a payload over about 256 GiB); every other seal in the crate has its own
    error variant for it.
  - A payload of the wrong length inside a key string or link code is `KeyStringError::Key` with
    `KeyError::Length`, and a data part ending in five padding bits or more is
    `KeyStringError::Padding`; there is no separate key-string length error.
  Reviewed (2026-10-22) on 5a9aef1 by three fresh-context agents (Claude Opus 5.5): correctness
  ac8209b50d5184499, blocked by 3 should-fixes, quality a5a901889bbd6cfa8, blocked by 6
  should-fixes, and security a61e36c37a15c499a, the security-reviewer pass, clean with 2
  should-fixes. Every accepted finding was applied in this commit (author ab1d7070b7eae97eb; first
  version by acfae6f32398cf668); confirmed clean 2026-10-22 on c7e1ac4 (before the rebase) by
  quality and by security, security also for correctness's items. One trivial test,
  `Suite::to_wire` for suite 2, is left as a follow-up. The merge agent wrote this record; it was
  not re-reviewed; rebased onto 28bf4da.

- Specification rewritten for shared folder keys (the owner's decision of 2026-10-18, both sets of
  the owner's answers of 2026-10-22, and the coordinator's rulings R-K1 to R-K6, S-1 to S-4 and the
  round-1 review fixes of that day; the owner's direction: "simplify the tracking, simplify the
  indexing, simplify the sharing whenever we can"). Each folder has three shared secret keys, as in
  Resilio Sync, and holding a key is the access; every update is signed with the folder's write key.
  `spec/keys.md` (1 552 lines in the drafts, now about 820): a 32-byte random write secret derives the
  folder's Ed25519 signing key, its data key and its folder ID (the labelled hash of the
  verification key); the read key is the verification key and the data key; the sealed key is the
  verification key and an access key derived from the data key; the access key parents a hint key
  and a payload key for the handshake, and the data key the chunk, chunk-nonce, chunk-hash and record
  keys; every public key must be canonically encoded and not of small order; key strings are Bech32m
  with one prefix per tier (`lsw` 65 characters, `lsr` and `lss` 116), each payload led by
  `be16(suite)`; the write key also has a 24-word BIP39 form with exact entry and refusal rules; there
  is no folder-wide record; chunk and sealed-metadata encryption lose their epochs, and the sealed
  part is capped at 1 572 864 bytes; one handshake proof, possession of the access key, serves every
  tier; making, unlinking (which keeps the files and the archive) and sharing an existing directory
  replace any re-key protocol; showing, exporting or sending a write key needs the operating
  system's own user authentication; device keys, the local key store (phase 1, with Argon2id),
  linked devices, the vectors, a 25-label registry and an old-to-new section map follow.
  `spec/protocol.md`: framing and the decoding rules are unchanged; Hello and the DeviceProof use
  34-byte canonical Ed25519 device keys and suite entries of 1 to 65 535; the folder proof carries
  only the tier the prover reports, shown and never relied on; the key-record messages and the
  Folder record are gone (0x8006 and 0x800B reserved, `FEATURE_REQUIRED` gone from `CloseReason`
  and `ProofStatus`); index records lose the key ID, epoch, `previous`, `resumes` and the version
  vector, cap `seq` at 2^62, and name in `supersedes` (at most 16) the versions they replace, from
  which every read and write holder computes a path's heads (two heads are a conflict; a record that
  names a version not yet held waits); duplicates and gaps on a push are ignored before any
  signature is verified; cursors carry cached digests; a round of range requests (16 384 writers
  each) covers any number of writers; pushes start when a folder opens and a dropped push owes the
  receiver a round; any peer may ask for any chunk it holds (the blob and a record naming it) and
  `CHUNK_NOT_FOUND` never closes; `CHUNK_BUSY` is exact, a queued chunk request holds only its hash,
  and a requester keeps one busy backoff timer per connection and no state per hash after
  `CHUNK_NOT_FOUND`: it asks for chunks in passes by ascending hash and starts a pass to a peer that
  lacked one only after Status's new `chunks_stored` counter grows or a round completes; heads have a
  full display order; writer-fault issues name the record, never a device; section 4.6 is now chunks; the outcome table, constants and vectors (now with one scenario
  shape for connection vectors) are rebuilt. `spec/threat-model.md` (version 2) states plainly that
  any write-key holder can change or delete anything (deletions from peers are not braked, and the
  archive limits how much is lost for good), can make peers track any number of writers and
  recompute and resend a writer's history, and cannot be removed except by the people who stay
  unlinking and sharing again by hand; read holders read but cannot write; sealed peers can neither;
  outsiders get nothing without a key. TM-16, TM-19, TM-34, TM-36 and TM-38 are retired with their
  numbers kept; TM-41 (concurrent versions kept, convergence) and TM-42 (removal is unlinking and
  sharing again) are new; TM-5, TM-9, TM-10, TM-11, TM-12, TM-14, TM-17, TM-18, TM-22, TM-30,
  TM-32, TM-33, TM-35, TM-37, TM-39 and TM-40 are rewritten, and TM-3, TM-6, TM-13 and TM-25
  updated in a phrase; the transport, local API, path resolver, supply-chain and fuzzing entries
  stand. `spec/suites.md` (version 2): Ed25519 alone for the two signatures left (index records and
  the DeviceProof), no key encapsulation (X-Wing, HPKE, ML-DSA-65 and age leave the approved list;
  `bip39` stays for the words), a folder's suite fixed by its keys, Padmé listed as the one padding
  scheme written here, `bech32` 0.12 without its error-correction API, `base64` 0.23 for the link's
  certificate hash, Argon2id from phase 1, and the label table copied from the new registry.
  `README.md` and `SECURITY.md` describe the new specs (TM-1 to TM-42, five retired), and README's
  index crate row drops version vectors, hash chains and equivocation withdrawal. The specs
  describe `main` as it will be once this commit and the keys-crate rework land together: `deny.toml`
  lists `licketysync-keys` as the only wrapper of `blake3` and `chacha20poly1305`, has no `hpke`,
  `ml-dsa`, `x-wing`, `ml-kem` or `x25519-dalek` entries, and the keys crate has no `test-vectors`
  feature. No code changes: the keys crate on main still implements the old model, so its
  label-registry test (`crates/keys/tests/registry.rs`) fails against these specs until the
  keys-crate rework lands, and the two must merge together as one series.
  Decisions for the plan:
  - Owner's answers of 2026-10-22, first set: Ed25519 alone; no re-key feature (unlink a folder
    keeping its files, share an existing directory as a new folder, give the new keys outside the
    client); the write key also as words; no cap on writers.
  - Owner's answers of 2026-10-22, second set: no brake on incoming mass deletions (the archive, 30
    days, keeps them); showing or exporting a write key, and sending one to a linked device, requires
    the operating system's own user authentication; per-file tracking keeps only the most recent
    revision (R-K6).
  - R-K1: every signature is Ed25519 alone (index records and the DeviceProof); no ML-DSA and no
    hybrid; post-quantum signatures, if added, come as a later suite.
  - R-K2: suite 1 has no key encapsulation; X-Wing through HPKE is removed with nothing in its
    place; linked devices pass folder keys as key strings over the authenticated device channel;
    XChaCha20-Poly1305, BLAKE3's labelled modes, Argon2id and the transport are unchanged.
  - R-K3, as specified: the write secret is 32 random bytes; `folder/signing-key` and
    `folder/data-key` derive the signing seed and the data key from it; the folder ID is
    `H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)`; the sealed key's secret is an
    access key derived from the data key (`data/access-key`), so every tier derives the folder ID
    and the access key; read key = verification key + data key, sealed key = verification key +
    access key, write key = write secret; Bech32m prefixes `lsw`, `lsr`, `lss`; the words are BIP39
    English over the write secret.
  - R-K4: no writer cap; an `IndexRequest` lists at most `MAX_CURSORS_PER_REQUEST` (16 384) cursors
    within a device-ID range (`after`, `through`), a round of range requests covers every writer, a
    responder keeps no state between requests, and every per-connection table is bounded by a
    constant; the residual (a write holder can make every peer store and compare any number of
    writers) is stated (threat model §3.6, TM-22).
  - R-K5: records of one device at one sequence number are concurrent versions in the canonical
    order (ascending `seq`, then record hash), stored and applied, with no fork, withdrawal,
    evidence or blame; three things make them, a write holder signing twice under its own ID, a
    write holder signing under another's, and a device restored from a backup.
  - R-K6: no version vectors and no per-device counters in records; each record names in
    `supersedes` the record hashes of the heads of its path that its writer held (at most
    `MAX_SUPERSEDES`, 16); heads are the versions no held record supersedes; two or more heads are a
    conflict, all kept; a record naming a version not yet held waits and makes no false conflict; a
    restored device's edit conflicts instead of overwriting; `seq` is capped at `MAX_SEQ` (2^62);
    history compaction (later) must keep enough of each replaced version to tell it apart (open
    item).
  - S-1: one folder proof for every tier, possession of the access key bound to the transcript and
    the role; the tier is reported for display only; the write proof, the read proof and
    `data/read-proof-key` are gone.
  - S-2: no Folder record for now (no revision, keep-the-greater rule, `required_features`,
    `FEATURE_REQUIRED` or pause on a missing feature); readers decode every format code their release
    implements and treat any other as a writer fault; features are negotiated in the Hello; a
    folder-level requirement is a later phase's item if ever needed.
  - S-3: any peer with the folder open may request any chunk hash; `CHUNK_NOT_FOUND` is an ordinary
    answer; the chunk-request permission rule and the 64-entry unknown-hash set are gone; requests are
    bounded only by `max_requests_in_flight`.
  - S-4: no "written by" display; device IDs are sync keys only.
  - PUSH-1: one "round owed" flag per folder per connection, set by an empty push and by a marks
    overflow; the owed round starts once the current reply completes and no sooner than
    `INDEX_RESYNC_INTERVAL` after the previous owed round began, and after any round under way has
    finished (decision: never abandoning a round, so that every round finishes however often the
    flag is set), going before a due listed request; one set during an owed round owes the next.
  - PUSH-2: pushes start as soon as the folder is open on the connection.
  - MARK: a range request clears only the marks in its range set before it was sent, and a listed
    request the marks it lists; a later mark stays for a listed request.
  - DUP: a record's hash is looked up before its signature is verified, and an exact duplicate is
    ignored unverified.
  - DIGEST: digests are cached per writer per `seq`, extended or recomputed from a low-landing
    record's `seq` up, and read, never recomputed, when serving; the O(C·n) cost a write holder can
    force is a stated residual (threat model §3.6, TM-22).
  - UNLINK: unlinking keeps the archive as ordinary files outside the hidden directory; before
    removing someone the app advises pausing the folder and restoring from the archive (`keys.md`
    §7.3, §7.4; TM-35, TM-42).
  - AK: the access key keys nothing itself: `handshake/hint-key` and `handshake/payload-key` derive
    from it, and the hint and proof key are keyed hashes under them with no label in the input.
  - WORDS: entry is whitespace-separated and case-insensitive, takes a word or a unique prefix of four
    letters or more, and refuses in this order: a count other than 24 (naming the count), the first
    token that is neither (naming its position), a bad checksum (naming no position); a later suite
    defines its own word form; the threat model notes that the words look like a wallet phrase.
  - POINTS: Hello's device key, and every verification key in a key string, must be canonical and
    not of small order (`PROTOCOL_ERROR` in the Hello), so one key has one ID.
  - NUMBERS: the drafts never shipped, so their numbers and labels carry no compatibility duty;
    `reserved` is a reading aid, and the never-reuse rule applies from the first release.
  - Decision: a rename is one record at the new path whose `supersedes` names the old path's heads
    (and the new path's, if any), so the old path keeps no head and needs no separate tombstone.
  - Decision: `supersedes` is a set: producers write it sorted and without repeats; verifiers do not
    check the order and count a repeat once.
  - Decision: a record also waits while a record it names waits, so a chain that arrives out of
    order waits as a whole; heads count only applied records that are not waiting, both as versions
    and as replacing one; an opaque record is held (a record naming it does not wait) but replaces
    nothing; a path with more than 16 heads stays a conflict until a later write names the rest.
  - Round 2 (R2 NIT1, NIT2): the display order of a path's heads is non-tombstones first, then
    (decision) directories before files, since a directory's children need it at the path, then the
    greater `mtime_ns`, then the smaller record hash; the first sits at the path, all tombstones
    mean deleted, and every other non-tombstone head whose content differs becomes a conflict copy;
    content differs when the kinds differ or two files' `plain_hashes` differ (two directories, or
    two files with equal `plain_hashes` whatever their times and modes, do not); so a file beats a
    tombstone with no copy, and a directory beats a file, which becomes a copy.
  - Round 2 (R1 N4): a rename whose old and new paths have more than 16 heads together names the old
    path's heads first, in display order, then the new path's, up to 16; the rest stay heads.
  - Decision, with round 2 (security N4): a record that names a version no peer holds waits for good
    (a stated write-holder residual); a waiting record writes a log line when it starts to wait and
    raises an informational issue naming the record once at least one peer has the folder open and
    a round with every peer that has it open has completed since it began to wait.
  - Round 2 (security N5, R1 N2): the one exception to "same records, same heads" is release skew: a
    `kind` an older release does not know is opaque there; so a `SealedMeta` kind, like a
    compression code, joins the baseline if added before 1.0 and needs a folder-level requirement if
    added after.
  - Round 2 (security N3): an unverified gap on a push may still set a mark, bounded by
    `MAX_MARKED_WRITERS` per folder per connection, whose overflow owes one round at most once per
    `INDEX_RESYNC_INTERVAL`; stated in the no-blame rule.
  - Round 2 (security N2): the tier a peer reports is shown marked "reported", like a device name.
  - Decision: the gap check also runs before verification: a gap on a push is ignored unverified, and
    a gap or an out-of-scope writer in a reply is a sender violation whatever the signature, so every
    signature a peer verifies either stores a record it lacked or closes the connection (TM-22).
  - Decision (with S-4): every writer-fault issue names the record (hash, and path where the seal
    opened), never the device a record claims.
  - Decision: a device whose next `seq` would pass `MAX_SEQ` draws a new device seed and so a new
    device ID; unreachable in practice, since records are held contiguously from 1.
  - Decision: a round's split rule is ascending device IDs, at most 16 384 per request, each
    request's `through` the last writer it lists and the last request's empty.
  - Decision: the owed empty push waits in order like a reply and is never dropped.
  - Decision, with round 2 (R2 SF1, security SF-A, R1 N1): `CHUNK_BUSY` exactly when the holder's
    unsent bytes are at least `MAX_SEND_QUEUE / 2` as it dispatches the request; a queued request
    holds only its hash and the chunk is read from storage only as it is sent; after `CHUNK_BUSY` the
    requester sends no chunk request on that connection for `CHUNK_BUSY_BACKOFF` (1 s, doubled up to
    64 s only by a busy answer to a request sent after the current backoff ended, back to 1 s after a
    `CHUNK_OK`), one timer per connection; after `CHUNK_NOT_FOUND` it keeps no state for the hash and
    asks other peers; TM-22 states that a key holder of any tier, under any number of device
    identities, can pin up to `MAX_SEND_QUEUE` per connection for as long as it keeps the connection
    alive (a trickling reader is never closed by `IDLE_TIMEOUT`), so the phase 1 connection limit is
    what bounds the total.
  - Round 2 ruling on the stall the reviser raised, with the final confirms: `FolderStatus` gains
    `chunks_stored` (field 6), the chunks the device has stored for the folder since the folder
    opened on the connection (0 at first, never falling), and a change in it alone sends at most one
    Status per second per folder per connection. A requester asks a peer for chunks in passes, in
    ascending `cipher_hash` order, keeping only its position; a `CHUNK_NOT_FOUND` does not pause the
    pass; after a pass that got any, the next pass to that peer for the folder starts only once the
    peer's Status shows a greater `chunks_stored` or a round with it completes, and no sooner than
    1 s after the latest `CHUNK_NOT_FOUND`; the trigger is evaluated at most once per
    `STATUS_INTERVAL`; per folder per connection the state is one position, one number and one time,
    nothing per hash.
  - Spec touch before the pair lands (KEYS-SF3): a key-string payload of at least 2 bytes is judged
    by its suite first (0 malformed, not implemented "this key needs a newer release"), then by its
    length under that suite; a payload under 2 bytes is malformed.
  - Spec touch (Q1): a directory record with chunks, and a file record that is not a tombstone with
    `size > 0` and no chunks, are writer faults (step 6).
  - Spec touch (Q2): NFC is the writer's duty only; readers check the rest of the path grammar and not
    normalisation, so Unicode-table differences between releases cannot split peers; residual: a
    write holder can write non-NFC names, which are then distinct paths.
  - Spec touch (Q3): a chunk-pass trigger that comes inside the `STATUS_INTERVAL` window is deferred by
    one pending bit per folder per connection and evaluated when the window ends, never dropped.
  - Spec touch (Q4, Q5): `protocol.md` §8 says which crate checks each vector item (heads and cached
    digests are the index crate's); every protocol constant, `MAX_SEND_QUEUE` included, is defined
    once in the protocol crate and imported by the engine and the runtime.
  - Round 2 (security N1): a device holds a chunk for the folder when it has the blob and holds a
    record naming its `cipher_hash`; threat-model §5 lists that `CHUNK_OK` against `CHUNK_NOT_FOUND`
    shows any peer with the folder open which chunks a device holds, and so, under selective sync or
    "free up space", which files it keeps locally.
  - Decision: the folder proof's suite check stays, folded into REJECTED; `ProofStatus` has
    `ACCEPTED` and `REJECTED` only; the payload is the tier alone (2 bytes, 18 sealed).
  - Decision: compression codes 0 to 3 stay named; phase 0 implements and writes 0 only; a writer
    uses another code only once every supported release of major 1 reads it: a decoder added before
    1.0 joins the baseline, and a code added after 1.0 needs a folder-level requirement first.
  - Decision, with round 2 (R2 NIT6, security SF-B): on a device with no operating-system
    authentication prompt (a headless box), the key store's passphrase stands in for it; the rule
    fails closed: the prompt or passphrase is asked at that moment, every time (an unlocked store, a
    running daemon or a process holding the API token does not count), and a device with neither
    refuses to show, export or link a write key until the person sets one; a read or sealed key is
    shown on explicit action alone, since neither can change anything.
  - Decision: Padmé is listed in `suites.md` as the one padding scheme written in this workspace, and
    TM-5 permits it by name.
  - Decision: the folder ID grants no access but lets its holder confirm and track the folder; logs
    redact it by default and error values may carry it.
  - Decision: `base64` 0.23 (default features off, `alloc` only) is approved for the link's `c`
    parameter only; `bech32` moves to 0.12 and its error-correction API is barred.
  - Decision: Argon2id and the key store are phase 1's; the RFC 9106 vector lands with them.
  - Decision: label vectors are for `derive_key` labels only; the other labels are covered by the
    vectors of what they compute; handshake vectors use a fixed transcript hash and cover both roles.
  - Decision: `keys.md` §2.2 (the Folder record) and `protocol.md` §4.6 (key records) are removed and
    the sections after them renumbered (discovery is `keys.md` §2.2, chunks `protocol.md` §4.6); both
    files say where each section went.
  - Kept from the drafts' rewrite: the handshake hint and proof key keyed by (now through) the access
    key, with the folder ID in their input, so relays and anyone who knows only a folder ID cannot
    open a proof and a key made from two folders' halves fails at the hint; one FolderProof per folder
    per connection, a repeated hint malformed, `MAX_PROOFS_PER_CONNECTION` 256, `sealed` 16 to
    1 024 bytes; marks bounded by `MAX_MARKED_WRITERS` (1 024); `REPLY_PAGE_TIMEOUT` restarts on a
    push that brings a stored record; pushes go to every connection where the folder is open except
    the one the record came by; reply pages may end anywhere; `MIN_MESSAGE_SIZE` stays 8 MiB; a
    folder's suite is fixed by its keys and a record under another suite is malformed; Hello's device
    key is `be16(suite) || ed25519_pk`, 34 bytes; a device holding records under its own ID at or
    above its next `seq` moves its counter past them; names have no key of their own; chunk
    associated data is the folder ID and sealed metadata's `folder_id || device_id || be64(seq)`; the
    local key store holds the device seed and one key per folder and nothing derived; linked devices
    pass key strings at most at the sender's tier, only over QUIC or TCP with TLS 1.3; only the
    write key has words; a device joining a re-shared directory adopts matching files and keeps a
    differing one as a conflict copy, and a directory belongs to at most one folder on a device.
  - Labels: added `folder/signing-key`, `folder/data-key`, `data/access-key`, `data/chunk-key`,
    `data/chunk-nonce-key`, `data/chunk-hash-key`, `data/record-key`, `handshake/hint-key`,
    `handshake/payload-key` and `hash/writer-digest`; `key/ed25519` now derives only the device key;
    removed every `identity/`, `epoch/` and `wrap/` label, `folder/root-seed`,
    `folder/chunk-hash-key`, `key/ml-dsa-65`, `key/x-wing`, `hash/id/identity`, `hash/id/key`, the
    keyed `handshake/folder-hint` and `handshake/proof-key`, and the `sig/` labels `folder`,
    `folder-proof`, `grant`, `grant-pop`, `rotation`, `wrap`, `revocation`, `suspension`, `lift` and
    `root-rotation`; the registry has 25 labels.
  - Plan passages this contradicts, for the plan scribe: "Writers cannot equivocate or roll back"
    (.140303: equivocation is not flagged, R-K5, and records name the versions they replace, not
    their predecessors; the rollback half stands); the index-sync decision (.173523) on forks, head
    hashes and fork pushes; "Capabilities" (.46197) and step 3 (.45435) on key IDs in the folder proof
    and on a folder's required features naming compressions (S-2); the protocol decision .164566
    (required features; Hello key IDs); the device-name decision .175973 (a folder proof "which
    anyone who knows the folder ID can open"); the crate list in "Security" (.99866: x25519-dalek,
    ml-kem, ml-dsa, age) and the unaudited post-quantum crates (.163702); hybrid key wrapping and
    X-Wing (.137539, .162513, .155116); hash-chained records against equivocation and authenticated
    key wrapping (.146253); records naming predecessors and equivocation flagging the key (.166311);
    the hardening table .147467 row .148967 (cell .149084, "Records name the hashes of their
    predecessors"; cell .149067, "Version vectors"); "AI and agent access" (.172120) on recovery
    words; "Linked devices" (.63931); version vectors in the Sync engine list (.48214 index, .49884
    conflicts, .122706 ordering), "Index growth" (.55484: tombstones as path hash plus version
    vector, vectors pruned when a device leaves), "Folder keys" (.63233: device IDs only in version
    vectors), the feature table cell .116412, the comparison table cells .130154 and .131727, the
    tests paragraph .98886 (property tests for version vectors) and the stable browser device ID
    (.182215: version vectors small); the "Key model simplified" decision and key table
    (.189713, .185935, .186396: the sealed key is the verification key and the access key, not the
    folder ID, and device IDs are sync keys, not vector entries); "Which devices use which key"
    (.106256: no device is shown as a record's author, S-4); the deletion brake (.121980, .126097)
    covers a device's own scans, and deletions from peers are not braked.
  Reviewed (2026-10-22) in rounds by fresh-context agents (Claude Opus 5.5), the security-reviewer
  pass among them; authors a5628fc094247fa8f (first draft) and acf6575edad08cf51 (revisions). Round
  1 on c5dcf1c: correctness a67a49385587fed85 blocked by 3 findings, clarity ae4109c83e24e3e8e
  blocked by 1 and security aff4a9adfaf5151c8 blocked by 6; the rulings R-K6 and S-1 to S-4, with
  the owner's answers, were applied. Round 2 on 4c83a57: correctness clean, clarity clean with 1
  should-fix, security blocked by 2, fixed in 0d68aaf and bfb5518. Final confirms: clarity clean on
  cd2ac95; security clean on bfb5518 and on the last touch, 5d78a87 (before the rebase). The merge
  agent wrote this record; it was not re-reviewed; rebased onto 28bf4da.

- The Nightly workflow fixed forward after runs 39576345810 (2026-10-21) and
  39755196041 (2026-10-22) on `main`, and cargo-mutants and OpenSSF Scorecard
  moved to weekly workflows, as the plan's checks table has them (the
  coordinator's ruling). OpenSSF Scorecard failed in 18 s each night:
  scorecard-action v2.4.0 pulls its image from gcr.io, which now refuses it
  ("requires billing to be enabled"); v2.5.0, Dependabot's pull request 5,
  pulls it from ghcr.io. It now runs from `scorecard.yml`, weekly and on
  demand, a workflow of its own because publishing the results holds the
  whole file to Scorecard's rules (no top-level env or defaults or write
  permission, id-token: write on its job only, only approved actions in that
  job), which its header now spells out; the job's permissions were already
  what publishing needs. cargo-mutants needs some 20 hours for the 1,371
  mutants of the keys and engine crates (about 50 s each), so the single
  nightly job was cancelled at GitHub's 6 h limit on 10-22, and on 10-21 it
  stopped after 2 h 44 min when its runner was shut down, not because of
  survivors. It now runs from `mutants.yml`, weekly and on demand, as 16
  jobs, each one shard (`--shard k/16`, dealt round-robin, about 86 mutants
  and 80 minutes today) through the new `ci/mutants.sh`, which stops the
  shard after 180 minutes (the job after 210), prints the counts and every
  surviving and timed-out mutant in the log and the job summary, and fails
  when the unmutated tree does not build or its tests fail, when the shard
  runs past its budget, or on any other cargo-mutants error; each shard
  uploads its `mutants.out`. cargo-fuzz passed in 17 s without fuzzing
  anything: install-action has no cargo-fuzz (its `cargo-fuzz` ref is a
  branch whose action installs nothing, with a warning), and `for t in
  $(cargo fuzz list)` ignored the "no such command" error. It would have
  failed even installed: `cargo fuzz run` in `fuzz/` picks stable through
  `rust-toolchain.toml`, which refuses the sanitizer flags. Now cargo-fuzz is
  built from crates.io with `--locked`, the new `ci/fuzz-targets.sh` lists the
  targets (it fails when the listing fails, and with no target it prints a
  notice and the fuzz jobs are skipped), and each target, eight today, runs
  as its own nightly job with `cargo +nightly fuzz run` for 30 minutes over
  its corpus and committed seeds, uploading the crashing input when it
  fails. This is the first nightly that fuzzes the seven keys decoders
  (`frame_decode` is still the placeholder), so a crash now turns the run
  red. The tools these workflows install are pinned like the supply-chain
  tools: cargo-mutants 27.1.0 and cargo-careful 0.4.10 through install-action
  with `fallback: none` (cargo-careful was `cargo install` of the newest),
  cargo-fuzz 0.13.2 through `cargo install --version`; `gate.sh` checks that
  each is installed at that version (cargo-careful has no `--version`, so for
  it the version `cargo install` recorded) and that its workflow installs it
  only as pinned, and `bootstrap.sh` (outside this repository) installs those
  versions. `ci/test-mutants.sh` and `ci/test-fuzz-targets.sh` test both
  scripts on stand-ins for the tools (exit codes, budget, listing failure,
  empty list, unsafe or non-ASCII names, the signal the budget sends);
  `gate.sh` runs them, a new `ci.yml` job runs them on every push, and the
  scheduled workflows run them before the real tools. The scheduled jobs check out
  without persisted credentials; mutants run 12 shards at a time (about 160
  minutes in all) and one run at a time, keeping `mutants.out` for 14 days
  and fuzz crash inputs for 30. `mutants.out` is ignored by git. Decisions
  for the plan: surviving mutants, and mutants whose tests run past 300 s, are
  reported, not failing, until the end of phase 0, while the keys crate is
  reworked to the shared-key model, and are revisited then (2026-10-22);
  mutation testing runs weekly (Saturdays) and on demand, in 16 round-robin
  shards, each held to a budget well inside the job limit, and gains shards
  when one nears it; Scorecard runs weekly (Saturdays) and on demand from a
  workflow of its own; nightly fuzzing runs one job per target;
  cargo-mutants, cargo-fuzz and cargo-careful are pinned like the
  supply-chain tools; before 1.0, a fuzz crash in a decoder is handled
  through a private security advisory. Reviewed (2026-10-22) on 1c3477d by
  two fresh-context agents (Claude Opus 5.5): correctness a1cb318c13cfcad3b,
  clean with 1 should-fix and nits, and security a64459b4eff497e1c, the
  security-reviewer pass, clean with nits. The accepted items were applied in
  this commit; confirmed clean 2026-10-22 by a1cb318c13cfcad3b for both
  reviewers; the merge agent wrote this line.
- CI's supply-chain tools pinned to exact versions, the ones `gate.sh` now
  requires: cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-machete 0.9.2 and
  cargo-vet 0.10.2. Run 39160240196 on `main` (877bb14) failed at `cargo vet
  --locked`: install-action's "latest" cargo-vet was 0.10.0, because 0.10.1
  and 0.10.2 are on crates.io without release binaries, and 0.10.0's formatter
  wants the double quotes inside one multi-line `notes` string in
  `supply-chain/imports.lock` (an imported Google audit of `quote`) escaped,
  which 0.10.2, the dev machine's, neither writes nor asks for; the two forms
  are the same TOML. cargo-vet stays at 0.10.2, so `supply-chain/` does not
  change: it is the newest release, it wrote the store, and it is the only
  release that knows the trusted-publishing form of wildcard audits and
  trusted entries, which imported audit sets may start to carry. CI builds it
  from crates.io with `cargo install cargo-vet --version 0.10.2 --locked`, as
  it does cargo-geiger, rather than through install-action's fallback. The
  other three, which CI happened to get at the dev machine's versions, are
  pinned in install-action (which checks each download's SHA-256) so that no
  new release changes what passes without a commit; nightly's cargo-audit
  too. Both install-action steps set `fallback: none`, so a pinned version
  missing from install-action's manifest fails the job instead of going to
  cargo-binstall, which can fetch an unverified binary and is handed the
  job's `github.token`. `gate.sh` now checks these four and semgrep before
  its first step. When an installed version differs it stops and prints the
  `cargo install` command; when `ci.yml` or `nightly.yml` installs one of the
  four any other way than its one pinned line (an install-action `tool:` item
  without `@version` or with another, an install-action step named after the
  tool, or another `cargo install` line; comments do not count), it stops and
  prints what the workflow has. `bootstrap.sh` (outside this repository)
  installs those versions, and `CONTRIBUTING.md` lists them. Dependabot
  cannot see the pins, so each weekly Dependabot review checks the four for
  new releases; a bump is one reviewed change to both workflows, `gate.sh`
  and `bootstrap.sh`. Decisions for the plan: CI supply-chain tools pinned to
  exact versions, bumped by hand at the weekly review; cargo-vet installed in
  CI from crates.io, not as a prebuilt binary. Reviewed (2026-10-22) on
  72e921b by two fresh-context agents (Claude Opus 5.5): correctness
  a6f7c6ef812de9c87, clean with 3 nits, and security a025f3b6e57384ba1, the
  security-reviewer pass, blocked by 2 should-fixes. Every accepted finding
  was applied in this commit; confirmed clean 2026-10-22 by a025f3b6e57384ba1
  for both reviewers; the merge agent wrote this line.
- CI fixed forward after run 39148844992 on `main` (b94dd0d), where four jobs
  failed, with the rulings on its three reviews. cargo-audit: `deny.toml`
  pointed cargo-deny's `db-path` at `~/.cargo/advisory-db`, which is
  cargo-audit's own clone; on a fresh runner cargo-deny ran first and left its
  checkout there, and cargo-audit then refused to clone into the non-empty
  directory. The line is gone, so cargo-deny keeps its default,
  `$CARGO_HOME/advisory-dbs`; nothing is ignored and both tools stay strict.
  `gate.sh` had the same fault on any fresh machine; the dev machine passed
  only because cargo-audit's clone was there first. Semgrep: `semgrep --test`
  read the header of `.semgrep/tests/project.rs`, which spelled the annotation
  form out, as two annotations, and it fails unless every rule the file names
  has a finding there, while `no-expect-on-remote-data` had only an `ok` case.
  The header no longer spells the form out, the rule has two `ruleid` cases and
  a second `ok` case, and its paths include `.semgrep/tests/**` as the blake3
  rules do. The scan step, reached for the first time, then flagged
  `std::env::args()` in the `cli` and `sim` binaries under the community rule
  `rust.lang.security.args.args`; both skip the program name and read only the
  arguments after it, so each line carries a `nosemgrep` comment for that one
  rule with the reason. CI's image is pinned to `semgrep/semgrep:1.181.0`, both
  commands run with `--metrics=off`, and the scan with `--timeout 60` (a
  review run saw the community unsafe-usage rule time out at the default 5 s on
  two keys test modules, which `--error` lets pass). `gate.sh` now runs both
  commands and requires semgrep 1.181.0 (`pipx install semgrep==1.181.0`;
  `bootstrap.sh` installs it). cargo-geiger: 0.14 exits 1 after any warning,
  and it warns about every file a dependency compiles in that it does not scan
  (38 for the keys crate: README files included as documentation, one C and
  one C++ source of `cc`). `ci/geiger.sh` runs it once per crate in its own
  target directory (`$CARGO_TARGET_DIR/geiger`, as it cleans what it scans)
  and accepts that exit only when the printed count matches and every warning
  names a file with a known non-Rust extension or a generated Rust file that
  `ci/geiger-baseline.txt` accepts by producing package and file name (serde's
  and serde_core's `private.rs`, read and free of unsafe code); any other
  unscanned file, a package with no metrics, another exit code or a build
  error fails. It holds every crate's five used unsafe counts (functions,
  expressions, impls, traits, methods) to the baseline, today keys 95 4352 23
  2 63 and every other crate 0: any difference, up or down, fails and prints
  the line to write, as do a crate without a line, a line for a crate that is
  gone, and a cargo-geiger other than 0.14.0, which CI now installs by version
  (missing-tool and version messages print the install command). This
  enforces the plan's checks table ("the count may not rise") more strictly,
  per the coordinator's rulings of 2026-10-18; TM-7 in `spec/threat-model.md`,
  which said no job compares the count, now says this. `gate.sh` runs it, so
  its comment that the report cannot fail is gone, and `ci/test-geiger.sh` (48
  cases on a stub `cargo`) tests it in `gate.sh` and CI. gitleaks:
  `gitleaks/gitleaks-action` needs a licence key for a repository an
  organization owns, free but issued on registration at gitleaks.io and kept as
  a secret, and from v2 on the action is no longer MIT-licensed. The job now
  runs the gitleaks 8.30.1 command-line tool (MIT), installed by
  `ci/gitleaks-install.sh` after checking the SHA-256 its release publishes
  (the script says how to move the pin, which Dependabot cannot see), over
  every commit of every fetched branch, with the checkout's token not kept.
  `ci/gitleaks.sh` ignores inline `gitleaks:allow` comments, redacts, and on a
  finding prints only rule, file, line and commit from a JSON report. Run for
  the first time, the default rules reported 86 `generic-api-key` hits, all
  lowercase hex in the keys crate's committed test vectors (`spec/keys.md`
  section 9); `.gitleaks.toml` drops a `generic-api-key` finding only when the
  file is a JSON file directly under a crate's `tests/vectors/` and the value
  is lowercase hex, and its header says what that still misses. `gate.sh` runs
  `ci/gitleaks.sh tree` over the working tree when gitleaks is installed, its
  one optional step. `CONTRIBUTING.md` says that the agent reviewing a
  Dependabot update writes changed geiger lines on the pull request's branch.
  Dependabot's gitleaks-action pull request no longer applies. Reviewed
  (2026-10-18) by three fresh-context agents (Claude Opus 5.5) on 3933fa9, one
  of them the security-reviewer pass; the author was a622ea95e66fe14db.
  Correctness aa5a81197d6b824bb blocked by 4 should-fixes, quality
  a5efcd22c48e90e11 by 5 and security a6e1f1c31221080e6 by 3; none found a
  blocker. Every finding was ruled on by the coordinator and every accepted one
  applied in 216bb6e (this commit before its rebase and review record). To save
  credits, the security reviewer alone confirmed 216bb6e on behalf of all three,
  and found it clean. Rebased onto 9e26fdb (the specification follow-up below);
  the only conflict was this changelog, and the TM-7 edit merged cleanly beside
  that change's other TM edits. The merge agent wrote this review record, which
  was not re-reviewed.

- Specification follow-up from the index crate's review: device admission per write key
  (ruling 33, which replaces ruling 31's mechanism, as amended by ruling 34 and the
  round-2 rulings), the direction "keys owns hashing" (ruling 13b as amended), and spec
  items from the protocol crate's reviews. `protocol.md` §4.4 step 6: a peer counts a
  device ID of a write key from a seq-1 record that has passed steps 3 to 5, so a read,
  sealed or not chain-valid key counts nothing and takes no writer slot, and it admits
  the `MAX_DEVICES_PER_KEY` (256) lowest counted IDs in unsigned byte-wise order; the
  invariant is that every admitted ID's seq-1 record is stored and served. The normative
  order is step 3 (forged), step 4 (write tier), step 5 (validity), then (1) excluded,
  (2) the folder bound, (3) count, admit and evict, then gap, duplicate and fork. A
  record under an ID above the 256 admitted ones is refused validity-only at any `seq`,
  before the gap and duplicate tests, blaming no one, with an Issues entry against the
  key once per key and device for a verified record; a peer may make that test earlier,
  after step 1, and before the signature it is a log line only, so a forged record under
  an excluded ID may be refused either way (both conform; the reference vectors verify
  first). A lower ID evicts the highest admitted writer: its chain is withdrawn as
  fork 1 would withdraw it (archive and deletion brake), but it is never served or
  forwarded, may be discarded once the archive has its paths and every connection open
  at the eviction has closed (the chunks it names are served until then; a sealed peer
  discards at the same point), raises an Issues entry naming the evicted device
  (exclusions and evictions coalesce per key), and is not a fork and causes no fork
  push. Exclusion only grows and each peer persists every key's admitted IDs (step 7),
  so peers that hold the same key records and have received the same seq-1 records admit
  the same IDs in any order. `have` and advertised cursors list admitted writers only
  (§4.5), so evictions cannot push `have` past its bound. A folder-bound refusal also
  refuses that writer's later records in the same reply (or push), never a gap, and the
  writers refused in one reply are bounded by `MAX_WRITERS_PER_FOLDER`, more distinct
  writers in a reply being a sender violation. The `MAX_WRITERS_PER_FOLDER` residual now
  names who reaches it (a `may_share` write key minting 63 keys, fewer when honest
  writers hold slots, the holders of 64 write keys acting together, or an honest folder
  that large), its effect (refused honest newcomers, divergence, a refused writer's
  chain re-sent up to once per `INDEX_RESYNC_INTERVAL` per connection) and its slots (an
  eviction frees one only for the evicting ID of the same key). Writer side (ruling 34,
  `keys.md` §4 and §4.2): a device with no admitted chain under a key writes no first
  record under it once it knows of 256 counted IDs; a device that joins through a
  `may_share` write key mints a child key of its own by default, while it sees the
  parent below its `MAX_KEY_RECORDS_PER_SIGNER` quota (the folder-quota cost is stated),
  and the browser client does so once per installation, never per session; a device
  whose own ID is excluded or evicted re-records its current paths under a key of its
  own and does not archive its own user's files (an engine rule); and the specs state
  plainly that an eviction withdraws the evicted device's past writes under the key on
  every peer (archive, 30 days), that devices starting under one key in a partition can
  evict one another, and that a device writing before it sees the lower IDs has those
  writes refused. Every claim that honest growth "never" loses a key's history is gone.
  Updated with it: the §4.4 definitions, step 3 (a pointer to the early test), the fork
  and gap bullets, step 7 and the guarantee sentence (two stated exceptions until
  phase 7); §3.1's push coalescing; §4.5's `Cursor` and `have` comments, the responder
  rule and forwarding (never an excluded or evicted writer's records); §5's no-blame
  rule, the Forged, Sender violation, Excluded device ID, Eviction and Validity-only
  rows and the per-connection limits; both constants rows; vector 6, whose
  device-admission cases (a) to (n), written as starting state → input → outcome, add a
  read key's seq-1 record, a forged low-ID record, a fork at seq 1, a restart, a forged
  excluded record, a folder-bound refusal followed by seq 2 and 3, and a chain split
  across pages; and vector 7 (`have` with 16 384 admitted and one evicted writer). From
  the protocol crate's reviews: §2 says a `bool` other than 0 or 1 and a `uint32` of
  2^32 or more are malformed (N5); a `ChunkReply`'s `data` is at most 4 325 416 bytes,
  longer malformed (N7); `missing_features` holds up to 33 entries, 32 features and a
  suite (N10); a chunk request follows only a record received from the holder or covered
  by its cursor, no longer one the requester sent (W2 SF1); a new `REPLY_PAGE_TIMEOUT`
  (10 min) closes with `TIMEOUT` a reply that brings no next page, counted from when the
  request left the send queue and restarted by pages of the peer's on-open key set,
  pages of replies to the requester's own requests and `CHUNK_OK` replies, not by
  `CHUNK_BUSY`, Status, pushes or `Unsupported` (W2 SF2, §4.5, §4.6, §5, constants); an
  unknown non-critical type is answered with `Unsupported` at most once per type per
  connection (W2 NIT3); §3.5 step 5 states what an outsider's self-made leaf grant still
  costs; vectors 1, 5, 7, 8 and 9 cover these. `threat-model.md`: §3.5, §3.6 (Can and
  Cannot), TM-13, TM-14, TM-16 (evictions reported; in phase 7 a cutoff can restore a
  forked chain but not yet an evicted one), TM-17, TM-20 (Unicode format characters in
  device names and Close details stay admitted and the UI isolates bidirectional text)
  and TM-22 (what an unauthenticated peer costs; a per-connection verification budget is
  a phase 1 engine item). `suites.md` §2.4: only `keys` calls BLAKE3, in its labels
  module, stated as the target with today's state beside it; `protocol` is to take the
  folder hint and the proof key from `keys` and build the transcript hash with its
  labelled hash; `index` uses `keys`'s record hash; every label is a `const` in `keys`'s
  registry; the change that lands the protocol crate removes the `licketysync-protocol`
  wrapper from `deny.toml`'s `blake3` and `chacha20poly1305` entries and the Semgrep
  exclusion of `crates/protocol/src/hash.rs`. `suites.md` §3.1 now says what `deny.toml`
  holds (`openssl`, `openssl-sys`, `md5`, `sha1`, `rust-crypto`, `pkcs8`, `der`, `spki`
  and, until `net`, `ring` banned outright; wrappers for the crates `keys` uses and
  those beneath them) and that `deny-production.toml` exists. Decisions for the plan
  (also in the notes' decisions-pending): ruling 33 as amended by ruling 34, a deviation
  from the plan's "Issued keys" (.63233, "any number of devices can use the same key"):
  any number may read, at most 256 may write under one key, and a device that joins
  through a `may_share` write key writes under a child key of its own by default;
  `REPLY_PAGE_TIMEOUT` (10 min) and its restart rule; the reply-or-push rule (a
  folder-bound refusal refuses its writer's later records in the same reply or push);
  decision .173523 becomes "a peer holds at most MAX_WRITERS_PER_FOLDER, 16 384 admitted
  writers, refusing more without blame, and admits for each write key the 256
  (MAX_DEVICES_PER_KEY) lowest device IDs it has counted, a lower one evicting the
  highest"; ruling 13b as amended, only `keys` calls BLAKE3, which refines .177123; the
  dependency direction keys ← index (keys ← protocol is already in the plan, .177123); a
  plan correction, key strings are 113 characters, not "about 100" (.63233); phase 7
  items: a Revocation cutoff that names a writer the lowest-256 rule excluded, restoring
  an evicted chain by a cutoff, and convergent admission with slot freeing for
  `MAX_WRITERS_PER_FOLDER`; engine items: a per-connection verification budget
  (phase 1), and re-recording an excluded or evicted device's paths under its own key.
  Reviewed (2026-10-18) by six fresh-context agents (Claude Opus 5.5) in two rounds of
  three, each with a security-reviewer pass, since this change touches keys and the
  protocol, and then by delta confirms from the second round's three; the author was
  a592da16a093b3de4. Round 1 on 74445c9 (ruling 31's over-limit evidence and the 13b
  wording): security a632b1c1d055a59ef blocked by 2, and the mechanism was replaced by
  ruling 33; reviewer 1 a4f73fc638a6173c4 and reviewer 2 a87b647d2e7036b0b stopped early,
  since the text was being replaced, and delivered their drafts (blocked by 1 and by 2),
  which the revision c3e2c06 took in. Round 2 on c3e2c06: reviewer 1 ad3dbf94dc9497dcd
  blocked by 4, reviewer 2 a95e0d4f59cec4e1d blocked by 2 and security abdbe86aa754f3651
  blocked by 3 blockers and 3 should-fixes, all ruled as ruling 34 and the round-2
  rulings. Round 3, the same three on 11c2d0b: reviewer 2 clean with two should-fixes,
  reviewer 1 blocked by 2 should-fixes and security by 4 (the reply deadline, discarding
  an evicted writer's records, the per-reply set of refused writers, default child
  minting), all ruled. Final confirms: reviewer 1 on 6edb02f clean with two nits, one of
  them (a page waiting behind key-record pushes on a slow link) left as a follow-up for
  the next specification change; security on 6edb02f blocked by 1 should-fix (a reply
  spanning an eviction at the folder bound, reviewer 1's other nit), fixed in ca7172f
  (this commit before its review record), which security confirmed clean. Every other
  finding was fixed as the coordinator ruled on it and confirmed by a reviewer on a
  later version. Main had not moved from b94dd0d, so nothing was rebased. The merge
  agent wrote this review record, which was not re-reviewed.

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
