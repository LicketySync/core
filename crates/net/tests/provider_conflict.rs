// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A2(b), the refusal: a process-default rustls provider that another crate
//! installed first, without X25519MLKEM768 first, stops the transport from
//! being built (`suites.md` 2.6). A test binary of its own, since the
//! process default can be installed only once per process.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests link every dev-dependency; test code"
)]

use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, BuildError};
use licketysync_net::provider::{self, ProviderError};
use rustls::NamedGroup;

#[test]
fn default_provider_without_x25519mlkem768_first_is_refused() {
    // aws-lc-rs itself, with its classical groups ahead of the hybrid one.
    let mut classical_first = rustls::crypto::aws_lc_rs::default_provider();
    classical_first.kx_groups.rotate_left(1);
    assert_eq!(
        classical_first.kx_groups.first().map(|g| g.name()),
        Some(NamedGroup::X25519)
    );
    classical_first.install_default().unwrap();

    assert_eq!(
        provider::install_default_provider(),
        Err(ProviderError::NotPostQuantumFirst {
            first: Some(NamedGroup::X25519)
        })
    );
    let identity = Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes([0xa0; 32]));
    match node::build(&identity, &Limits::default()) {
        Err(BuildError::Provider(ProviderError::NotPostQuantumFirst { .. })) => {}
        other => panic!("built on the wrong provider: {:?}", other.map(|_| ())),
    }
}
