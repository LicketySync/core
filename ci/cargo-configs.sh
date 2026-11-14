# shellcheck shell=bash
# Sourced by ci/geiger.sh and ci/rustc-wrapper.sh, never run.
# cargo_configs <directory>: set the array `configs` to the cargo
# configuration files that cargo, run in that directory (an absolute path),
# reads: .cargo/config and .cargo/config.toml there and in each directory above
# it, then in CARGO_HOME (else ~/.cargo). Only the files that exist.
cargo_configs() {
  local d=$1 f home=${CARGO_HOME:-${HOME:-}/.cargo}
  configs=()
  while :; do
    for f in "$d/.cargo/config" "$d/.cargo/config.toml"; do
      [ ! -f "$f" ] || configs+=("$f")
    done
    [ -n "$d" ] || break
    d=${d%/*}
  done
  for f in "$home/config" "$home/config.toml"; do
    [ ! -f "$f" ] || configs+=("$f")
  done
}
