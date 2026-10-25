# Changelog

All notable changes to Lickety-Sync are recorded here. Each entry says what
changed and names the agents that reviewed it; anything touching keys, protocol,
paths or the API also names the security-reviewer pass.

## Unreleased

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
  the one that tag named that day, so the same code runs as before, except for codeql-action's v4
  and the refs that were branches:
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
    (`gh api repos/dtolnay/rust-toolchain/compare/<v1>...stable`), so every step now names
    `toolchain: stable` or `toolchain: nightly`.
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
  toolchain is not pinned: stable is `rust-toolchain.toml`'s channel, which local builds and the
  gate follow too, and nightly (cargo-udeps; fuzzing, cargo-careful and Miri) is the day's, as
  `cargo +nightly` is on the dev machine; pinning either is a change to `rust-toolchain.toml`,
  `gate.sh` and `bootstrap.sh` with the workflows, and stays the plan's follow-up for the release
  toolchain. The rule is stated once in full in `ci.yml`'s header (the `codecov` job's paragraph,
  which said "pinning every action is a pending decision", is gone), and `release.yml`,
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
  a Dependabot bump of `crate-ci/typos` moves `gate.sh`'s typos version with it. Residuals: the Rust
  toolchain, as above; the container images that pinned actions name by tag (scorecard-action's
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
