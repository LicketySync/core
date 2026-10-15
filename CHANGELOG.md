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
  rest of `spec/` (threat model, suites, protocol, keys) is still to be written.
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
