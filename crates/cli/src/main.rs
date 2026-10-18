// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `licketysync` command line.
//!
//! Status: skeleton. Commands planned: status, doctor, issues, peers, folders,
//! keys, owner, devices, config, ignore, schedule, scrub, relay, decrypt.

// The command line is the one crate that talks to a terminal on purpose.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // Semgrep's community rule flags every std::env::args(): argv[0], the
    // program name, can be set to anything by the caller. It is skipped here
    // and decides nothing; only the arguments after it are read.
    // nosemgrep: rust.lang.security.args.args
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("licketysync {VERSION}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("licketysync: unknown command `{other}`; nothing is implemented yet");
            ExitCode::from(2)
        }
        None => {
            println!("licketysync {VERSION}: the service and its commands arrive with phase 1.");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_semver_shaped() {
        assert_eq!(super::VERSION.split('.').count(), 3);
    }
}
