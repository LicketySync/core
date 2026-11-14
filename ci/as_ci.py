#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Start a command of a test suite as a CI step starts one, and end it when the suite ends.

Usage: python3 -I ci/as_ci.py <the suite's PID> <command...>, started by the suite itself
(ci/test-download.sh and ci/test-mutants.sh, which test it).

The command starts with no signal ignored or blocked and no descriptor open but stdin, stdout and
stderr, whatever the suite inherited (Python's own ignored SIGPIPE and SIGXFSZ included). A caller
that ignores SIGINT (a background job of a script does, and passes it on) would leave a SIGINT to a
command that cannot trap it, and a descriptor inherited from a plain flock holds its lock while any
process that has it is alive.

The kernel sends the command SIGTERM when its parent, which must be the suite, ends, however it
ends, SIGKILL included (Linux's parent-death signal, which exec keeps). Python and bash end at it,
and timeout(1), GNU's and uutils' alike, passes it on to its command's process group. The parent is
checked once the signal is set, so that a suite that ended first is seen too.

When it does not run the command, its status is 125 (the signal not set, or the suite not its
parent), 126 (the command could not be run) or 127 (not found), as timeout(1)'s.
"""
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: python3 -I ci/as_ci.py <the suite's PID> <command...>\n")
        sys.exit(2)
    suite, command = int(sys.argv[1]), sys.argv[2:]
    for s in signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP}:
        if signal.getsignal(s) == signal.SIG_IGN:
            signal.signal(s, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, ())
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        sys.stderr.write("as_ci: PR_SET_PDEATHSIG: %s\n" % os.strerror(ctypes.get_errno()))
        sys.exit(125)
    if os.getppid() != suite:
        sys.stderr.write("as_ci: its parent is not the suite, PID %d\n" % suite)
        sys.exit(125)
    try:
        os.execvp(command[0], command)
    except FileNotFoundError as e:
        sys.stderr.write("as_ci: %s\n" % e)
        sys.exit(127)
    except OSError as e:
        sys.stderr.write("as_ci: %s\n" % e)
        sys.exit(126)


main()
