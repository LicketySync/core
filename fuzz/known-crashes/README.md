# Known crashes, kept out of the nightly fuzz list

A fuzz target whose input crashes a dependency we cannot fix in this
repository yet. It is not a `[[bin]]` of `fuzz/Cargo.toml`, so `cargo fuzz list`,
`ci/fuzz-targets.sh` and the nightly fuzz jobs do not see it, and the nightly
stays green; it is kept so the crash reproduces and the target lands once the
dependency is fixed.

## `webtransport_proto/`: wtransport-proto 0.7.2's QPACK integer decoder

`Decoder::decode_integer` (`wtransport-proto-0.7.2/src/qpack.rs`, line 173)
shifts a 7-bit group by a count that grows 7 bits a continuation byte with no
bound, so `<< power` overflows once `power` reaches 64: "attempt to shift left
with overflow". It panics where overflow checks are on (debug and test builds,
fuzzing). In a release build (overflow checks off) the shift wraps; on the
recorded input decoding then fails; in general it yields a wrong value,
harmless because every decoded value is checked before use (discarded, looked
up in the static table, or checked as a length against the bytes left).
The input is the CONNECT request's HEADERS frame, from any client before
authentication (`wtransport-0.7.2/src/driver/mod.rs` line 601, inside the
worker task wtransport runs per connection). Found 2026-11-04 by a two-minute
run of `webtransport_proto.rs`; it is `threat-model.md` TM-23's residual (a),
and `crates/net/tests/webtransport.rs`'s
`a_panicking_session_request_is_contained` sends the same bytes to `net`'s
listener, which contains the panic (TM-23).

- `webtransport_proto.rs`: the target (a stream header, then frames; HEADERS
  through QPACK into a session request, SETTINGS into settings).
- `crash-fd695d341f880559d1a22c10bdf93a4348fd9c76`: the 18-byte input. It
  holds NUL bytes, so git treats it as binary and never converts its line
  endings.

To reproduce, from `fuzz/`: add `wtransport-proto = "0.7.2"` and
`idna_adapter = "~1.0"` to `[dependencies]` and a `[[bin]]` named
`webtransport_proto` with `path = "known-crashes/webtransport_proto/webtransport_proto.rs"`
(`test`, `doc` and `bench` false, as the others), then

    cargo +<RUST_NIGHTLY> fuzz run webtransport_proto known-crashes/webtransport_proto/crash-fd695d341f880559d1a22c10bdf93a4348fd9c76

The target moves to `fuzz_targets/` and into the nightly list with the fix:
upstream, or a vendored copy that stops with `IntegerOverflow` once the shift
reaches the integer's width (`threat-model.md` TM-23).
