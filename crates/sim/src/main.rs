// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `licketysync-sim` command. All logic is in the library's `cli` module,
//! where it is tested; this file only prints and exits.

// The simulator binary is a tool that reports to the terminal on purpose.
#![allow(clippy::print_stdout)]
// cargo hands the library's dependencies to the binary too; it uses only the library.
#![allow(unused_crate_dependencies)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // Semgrep's community rule flags every std::env::args(): argv[0], the
    // program name, can be set to anything by the caller. It is skipped here
    // and decides nothing; only the arguments after it are read.
    // nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = std::env::args().skip(1).collect();
    let report = licketysync_sim::cli::run(&args);
    print!("{}", report.text);
    ExitCode::from(report.code)
}
