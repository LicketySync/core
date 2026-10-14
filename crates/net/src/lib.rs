// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Networking on rust-libp2p: `QUIC` and TCP, mDNS and broadcast beacons, port mapping, hole punching, relays (private and public, with fair scheduling), the opt-in Mainline DHT, the HTTPS listener.
//!
//! Status: skeleton. The plan ("Lickety-Sync: Project Plan") is the specification
//! this crate implements; `spec/` in this repository carries the protocol and the
//! threat model as they are written down.

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-net";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-net");
    }
}
