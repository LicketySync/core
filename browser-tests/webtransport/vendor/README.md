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
requests #6446 and #6671 relax the pin.

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
the browser workspace's supply-chain/ vets the published crate.
