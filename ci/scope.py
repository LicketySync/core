# The files the word rule scans (unsafe_code-only-in-ffi-crates in
# .semgrep/project.yml), for ci/semgrep-scan.sh and ci/check-dep-info.sh: one
# definition, so that the two checks cannot drift apart (threat-model.md
# TM-7). Paths are as git lists them, relative to the repository's root with
# forward slashes; names count in any case, as macOS and Windows read them.
import os

# The project rules' cases, which the scan leaves out.
CASES = (".semgrep/tests/project.rs", ".semgrep/tests/manifests.toml")
# Trees the rules scan only in part, which no workspace crate may read: the
# vendored wasm-bindgen crate of browser-tests, whose bindings.rs the extern
# rule leaves out.
EXEMPT = ("browser-tests/webtransport/vendor/",)


def in_scope(path):
    """Every file under crates/ and fuzz/seeds/, every .rs file, every
    Cargo.toml and the root's clippy.toml, but the cases."""
    name = os.path.basename(path).lower()
    return path not in CASES and (
        path.startswith(("crates/", "fuzz/seeds/"))
        or name.endswith(".rs")
        or name == "cargo.toml"
        or path.lower() in ("clippy.toml", ".clippy.toml")
    )


def trusted(path):
    """A file a workspace crate may read (ci/check-dep-info.sh): in scope and
    outside the exempt trees."""
    return in_scope(path) and not path.lower().startswith(EXEMPT)
