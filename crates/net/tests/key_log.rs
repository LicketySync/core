// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `libp2p-tls` gives every rustls configuration it builds rustls's
//! `KeyLogFile`, which writes each TLS session's secrets to the file that
//! `SSLKEYLOGFILE` names. A node is not built while that variable is set
//! (TM-6). A test binary of its own, since it sets the process's
//! environment.

#![allow(
    unused_crate_dependencies,
    clippy::panic,
    reason = "integration tests link every dev-dependency; test code"
)]

use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, BuildError, KEY_LOG_VARIABLE};

#[test]
fn node_is_not_built_while_sslkeylogfile_is_set() {
    assert_eq!(KEY_LOG_VARIABLE, "SSLKEYLOGFILE");
    // A name, never opened: the build stops before any configuration exists.
    std::env::set_var(KEY_LOG_VARIABLE, "keys-must-not-be-logged");
    let identity = Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes([0xa0; 32]));
    match node::build(&identity, &Limits::default()) {
        Err(BuildError::KeyLogRequested) => {}
        other => panic!("built with {KEY_LOG_VARIABLE} set: {:?}", other.map(|_| ())),
    }
    assert!(!std::path::Path::new("keys-must-not-be-logged").exists());
}
