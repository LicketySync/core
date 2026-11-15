// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `libp2p-tls` gives every rustls configuration it builds rustls's
//! `KeyLogFile`, which writes each TLS session's secrets to the file that
//! `SSLKEYLOGFILE` names. A node is not built while that variable is set
//! (TM-6). The test starts its own binary again with the variable set in the
//! child's environment, since the workspace lint refuses a change to the
//! process's own.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests link every dev-dependency; test code"
)]

use std::path::Path;
use std::process::Command;

use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, BuildError, KEY_LOG_VARIABLE};

/// The variable's value in the child: a file never opened, since the build
/// stops before any configuration exists. Under the target directory, so that
/// a failing run leaves nothing in the source tree.
const NEVER_WRITTEN: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/keys-must-not-be-logged");

#[test]
fn node_is_not_built_while_sslkeylogfile_is_set() {
    assert_eq!(KEY_LOG_VARIABLE, "SSLKEYLOGFILE");
    if std::env::var_os(KEY_LOG_VARIABLE).is_some_and(|v| v == NEVER_WRITTEN) {
        // The child: the variable is set.
        let identity = Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes([0xa0; 32]));
        match node::build(&identity, &Limits::default()) {
            Err(BuildError::KeyLogRequested) => {}
            other => panic!("built with {KEY_LOG_VARIABLE} set: {:?}", other.map(|_| ())),
        }
        return;
    }
    // A file a failed run left behind would fail this one; none is expected.
    let _ = std::fs::remove_file(NEVER_WRITTEN);
    // Semgrep's community rule flags every std::env::current_exe(): whoever
    // runs a binary can change the path it gives. Here it only names this
    // test's own binary, to start again.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "node_is_not_built_while_sslkeylogfile_is_set"])
        .env(KEY_LOG_VARIABLE, NEVER_WRITTEN)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&child.stdout);
    // "1 passed": the child ran this test, not none.
    assert!(
        child.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "the child ({}) printed:\n{stdout}{}",
        child.status,
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(!Path::new(NEVER_WRITTEN).exists());
}
