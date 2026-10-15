// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `licketysync-sim` command: runs a named scenario over a range of seeds
//! and reports the first seed that does not converge. Arguments are parsed by
//! hand: there are three of them, and an argument-parsing crate is not among
//! the audited dependencies.

use core::fmt::Write as _;

use crate::scenarios;

/// What the command prints and how it exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// 0 when every seed converged, 1 when one did not, 2 for a usage error.
    pub code: u8,
    /// The text for standard output.
    pub text: String,
}

/// How to call the command.
pub const USAGE: &str = "usage: licketysync-sim list
       licketysync-sim <scenario> <first-seed> <count>
Runs <scenario> for <count> seeds starting at <first-seed> and stops at the
first seed that does not converge, printing it with the last events.
";

enum Command {
    List,
    Run {
        name: String,
        first: u64,
        count: u64,
    },
}

fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [cmd] if cmd == "list" => Ok(Command::List),
        [name, first, count] => {
            let first: u64 = first
                .parse()
                .map_err(|_| format!("first seed must be a number, not `{first}`"))?;
            let count: u64 = count
                .parse()
                .map_err(|_| format!("count must be a number, not `{count}`"))?;
            if count == 0 {
                return Err("count must be at least 1".to_owned());
            }
            Ok(Command::Run {
                name: name.clone(),
                first,
                count,
            })
        }
        _ => Err("expected `list` or `<scenario> <first-seed> <count>`".to_owned()),
    }
}

/// Runs the command line.
#[must_use]
pub fn run(args: &[String]) -> Report {
    let command = match parse(args) {
        Ok(c) => c,
        Err(why) => {
            return Report {
                code: 2,
                text: format!("licketysync-sim: {why}\n{USAGE}"),
            };
        }
    };
    match command {
        Command::List => {
            let mut text = String::new();
            for s in scenarios::all() {
                let _ = writeln!(text, "{:<14} {}", s.name, s.about);
            }
            Report { code: 0, text }
        }
        Command::Run { name, first, count } => run_range(&name, first, count),
    }
}

fn run_range(name: &str, first: u64, count: u64) -> Report {
    let Some(scenario) = scenarios::find(name) else {
        let names: Vec<&str> = scenarios::all().iter().map(|s| s.name).collect();
        return Report {
            code: 2,
            text: format!(
                "licketysync-sim: no scenario `{name}`; try one of: {}\n",
                names.join(", ")
            ),
        };
    };
    // The range saturates at the largest seed rather than wrapping, so the
    // count reported is the number of seeds actually run.
    let last = first.saturating_add(count - 1);
    let mut first_hash = None;
    let mut ran: u64 = 0;
    for seed in first..=last {
        let outcome = scenario.run(seed);
        first_hash.get_or_insert(outcome.trace_hash);
        ran = ran.saturating_add(1);
        if !outcome.converged {
            return Report {
                code: 1,
                text: format!("FAIL {name} seed {seed}\n{outcome}"),
            };
        }
    }
    Report {
        code: 0,
        text: format!(
            "ok {name}: {ran} seed(s) from {first} converged (seed {first} trace {:016x})\n",
            first_hash.unwrap_or(0)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn usage_errors_exit_2_and_print_usage() {
        for bad in [
            vec![],
            args(&["clean"]),
            args(&["clean", "0"]),
            args(&["clean", "x", "1"]),
            args(&["clean", "0", "y"]),
            args(&["clean", "0", "0"]),
            args(&["a", "b", "c", "d"]),
        ] {
            let r = run(&bad);
            assert_eq!(r.code, 2, "{bad:?}");
            assert!(r.text.contains("usage:"), "{}", r.text);
        }
    }

    #[test]
    fn unknown_scenario_lists_the_known_ones() {
        let r = run(&args(&["nope", "0", "1"]));
        assert_eq!(r.code, 2);
        assert!(r.text.contains("no scenario `nope`"));
        assert!(r.text.contains("clean"));
        assert!(r.text.contains("chaos"));
    }

    #[test]
    fn list_names_every_scenario() {
        let r = run(&args(&["list"]));
        assert_eq!(r.code, 0);
        for s in scenarios::all() {
            assert!(r.text.contains(s.name), "{}", r.text);
            assert!(r.text.contains(s.about), "{}", r.text);
        }
    }

    #[test]
    fn a_converging_scenario_exits_0_with_a_fingerprint() {
        let r = run(&args(&["clean", "3", "2"]));
        assert_eq!(r.code, 0, "{}", r.text);
        assert!(r
            .text
            .starts_with("ok clean: 2 seed(s) from 3 converged (seed 3 trace "));
        let again = run(&args(&["clean", "3", "2"]));
        assert_eq!(r, again, "the same seeds print the same fingerprint");
    }

    #[test]
    fn a_broken_scenario_exits_1_and_names_the_seed() {
        let r = run(&args(&["broken", "7", "5"]));
        assert_eq!(r.code, 1);
        assert!(
            r.text
                .starts_with("FAIL broken seed 7\nseed 7: NOT converged"),
            "{}",
            r.text
        );
        assert!(r.text.contains("last "), "{}", r.text);
    }

    #[test]
    fn the_seed_range_saturates_instead_of_wrapping_and_reports_the_seeds_run() {
        let r = run(&args(&["clean", &u64::MAX.to_string(), "3"]));
        assert_eq!(r.code, 0, "{}", r.text);
        let expected = format!(
            "ok clean: 1 seed(s) from {} converged (seed {} trace ",
            u64::MAX,
            u64::MAX
        );
        assert!(r.text.starts_with(&expected), "{}", r.text);
        assert!(
            !r.text.contains("trace 0000000000000000"),
            "the one seed that ran left a fingerprint: {}",
            r.text
        );
        let r = run(&args(&["clean", &(u64::MAX - 1).to_string(), "5"]));
        assert!(r.text.starts_with("ok clean: 2 seed(s) from"), "{}", r.text);
    }
}
