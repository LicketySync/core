#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Fail when a tracked path is one Windows cannot hold.

Git for Windows refuses to check out such a path, and with it the whole checkout, so every job on
Windows fails before it starts. A path is refused when one of its components (each name between
slashes) is not UTF-8; holds `<`, `>`, `:`, `"`, `\\`, `|`, `?`, `*` or a control character
(U+0001 to U+001F); ends with a dot or a space; or is a device name: `CON`, `PRN`, `AUX`, `NUL`,
`COM0` to `COM9`, `LPT0` to `LPT9` (with the superscript digits too), `CONIN$` or `CONOUT$`, in
any case, with any extension and with spaces before it (`nul .txt`). These are the Windows rules of
`crates/fs/src/name.rs`. It fails closed: a repository git cannot list is a failure.
Usage: python3 -I ci/windows-paths.py [repository] (defaults to this one). Run by gate.sh and CI;
tested by ci/test-windows-paths.sh.
"""
import os
import subprocess
import sys

RESERVED = set('<>:"\\|?*')
DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
NUMBERED = {"COM", "LPT"}
DIGITS = set("0123456789¹²³")


def ascii_upper(text):
    """Upper case for ASCII letters only, as Windows compares device names."""
    return "".join(c.upper() if c.isascii() else c for c in text)


def problem(component):
    """Why Windows cannot hold the name `component`, or None."""
    try:
        name = component.decode("utf-8")
    except UnicodeDecodeError:
        return "is not UTF-8"
    for c in name:
        if c in RESERVED:
            return f"holds {c!r}, which Windows reserves"
        if c < "\x20":
            return f"holds the control character {c!r}"
    if name.endswith((".", " ")):
        return "ends with a dot or a space"
    stem = ascii_upper(name.split(".", 1)[0].rstrip(" "))
    if stem in DEVICES or (len(stem) == 4 and stem[:3] in NUMBERED and stem[3] in DIGITS):
        return "is a device name"
    return None


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=False)
    if listed.returncode != 0:
        sys.stderr.write(listed.stderr.decode("utf-8", "replace"))
        print(f"windows-paths: git could not list the files of {root}", file=sys.stderr)
        return 2
    found = []
    for path in listed.stdout.split(b"\0"):
        for component in path.split(b"/") if path else []:
            why = problem(component)
            if why:
                shown = path.decode("utf-8", "backslashreplace")
                name = component.decode("utf-8", "backslashreplace")
                found.append(f"{shown!r}: {name!r} {why}")
                break
    if found:
        print("\n".join(found), flush=True)
        print("Windows cannot hold the paths above, and Git for Windows refuses to check them out;"
              " rename them.", file=sys.stderr)
        return 1
    print("windows-paths: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
