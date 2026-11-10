# Vendored: libp2p-webtransport-websys 0.6.0

`libp2p-webtransport-websys-0.6.0/` is the crate as published on crates.io
(`libp2p-webtransport-websys-0.6.0.crate`, SHA-256
`c8ee91aeb40f3a284f764215c667fbcdfbdc246a1d55e2df29f26091eb78799b`; rust-libp2p
commit `7171dce2f90c05ba7892d4ba926abb1881db27c7`, as its `.cargo_vcs_info.json`
says), MIT-licensed. The published crate carries no licence file, so `LICENSE`
is rust-libp2p's own, from the repository root at that commit. The crate's
`Cargo.lock` is left out; nothing else is.

**What was changed:** one line of `Cargo.toml`, the `wasm-bindgen-futures`
requirement, from `=0.4.58` to `0.4.79`. `Cargo.toml.orig` and every source
file are as published.

**Why:** rust-libp2p's workspace pins `wasm-bindgen-futures = "=0.4.58"`, and so
`wasm-bindgen = "=0.2.108"` (2026-01-15), to avoid a gloo-timers 0.2.6 break
that futures-timer 3.0.4 no longer has. The pin would hold this test crate at
wasm-bindgen 0.2.108, and so the pinned wasm-bindgen-cli too, against the
stay-current rule. The test crate's tree has no gloo-timers. Upstream pull
requests #6446 and #6671 relax the pin; #6747 removes it.

**#6747** is the owner's pull request to rust-libp2p
(github.com/libp2p/rust-libp2p/pull/6747, opened 2026-11-06 from the owner's
fork, branch `deps/unpin-wasm-bindgen-futures`, as the review of #6671
suggested). It unpins `wasm-bindgen-futures`; read on 2026-11-09, it:

- replaces rust-libp2p's workspace `wasm-bindgen-futures = "=0.4.58"` with
  `0.4.80`, so that nothing holds `wasm-bindgen` at 0.2.108 any more, and
  bumps libp2p-webtransport-websys to 0.6.1, whose changelog says it needs
  wasm-bindgen-futures 0.4.80 or later (so wasm-bindgen 0.2.130 or later);
- requires futures-timer 3.0.4, which moves its wasm timer to gloo-timers 0.4
  (it requires `0.4.0`, and so does its master). gloo-timers 0.4.0, released
  2026-03-25, lacks the fix for the `panic = "unwind"` build (ranile/gloo#562,
  merged 2026-05-16, in no release). ranile/gloo#587 (open since 2026-11-08)
  prepares the release, gloo 0.13.0, and sets gloo-timers to 0.5.0, which
  futures-timer 3.0.4's requirement does not accept. So a gloo-timers release
  alone does not fix the emscripten build through futures-timer 3.0.4: it also
  needs a futures-timer release that takes gloo-timers 0.5, or a gloo-timers
  0.4.x patch;
- wraps the wakers and the `mpsc::Sender` that the JavaScript callbacks of
  libp2p-websocket-websys and libp2p-webrtc-websys capture in
  `AssertUnwindSafe`, because without it those crates do not compile for
  `wasm32-unknown-emscripten` with wasm-bindgen 0.2.109 or later (nothing
  changes with `panic = "abort"`);
- adds `wasm-tests/timer-tests`, which checks in a headless browser that a
  `futures_timer::Delay` fires and that a `Swarm` closes an idle connection.

It is open, and the owner asked there that it not be merged before gloo-timers
publishes the fix (requested in ranile/gloo#586). It changes nothing here until
a libp2p-webtransport-websys release carries it.

**Held to this copy:** `SHA256SUMS` lists every file here with its SHA-256,
and `ci/check-vendored.sh` (run by `gate.sh` and CI) fails on any edit, any
missing file and any extra one. cargo-vet vets the copy as the crates.io
release (`[policy.libp2p-webtransport-websys] audit-as-crates-io = true` in
`../supply-chain/config.toml`, with an exemption for 0.6.0), which keys on the
version and would not see an edit, hence the check.

**When it goes** (owner, 2026-11-04: "Yes, keep the patched version until
upstream releases the fix."): when a libp2p-webtransport-websys release without
the exact pin is published and has been out for at least 7 days. Then
`browser-tests/webtransport/Cargo.toml` takes that release, its
`[patch.crates-io]` entry, this directory and the vet policy are removed, and
the browser workspace's supply-chain/ vets the published crate. If that release
is #6747's 0.6.1 as it is written today, the test crate's own pins of
`wasm-bindgen`, `wasm-bindgen-futures` and `wasm-bindgen-test` (now 0.2.129,
0.4.79 and 0.3.79) and `WASM_BINDGEN_CLI` in `ci/pins.env` move up with it, to
the versions it needs (`ci/check-wasm-bindgen.sh` keeps `wasm-bindgen` and
`WASM_BINDGEN_CLI` alike).
