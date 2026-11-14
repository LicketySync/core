#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Run a test suite's run of itself so that it neither outlives the suite nor leaves anything behind.

Usage: python3 -I ci/reaper.py <the suite's PID> <seconds> <command...>, started by the suite itself
(ci/test-download.sh and ci/test-mutants.sh, which test it).

It runs the command with SIGINT ignored, as a background job of a script has it, and no signal
blocked. Any other signal the suite's caller ignored stays ignored (a gate run under nohup ignores
SIGHUP): starting a command with none ignored is ci/as_ci.py's job. Python's own ignored SIGPIPE
and SIGXFSZ, and the two signals this one handles, are back at their defaults. It waits until the
command and every process it leaves behind have ended: they become this one's children (a child
subreaper). Its status is the command's (128 + the signal, for one a signal ended).

It has the kernel send it SIGTERM when its parent, which must be the suite, ends, however it ends,
SIGKILL included (Linux's parent-death signal), and refuses (status 125) when its parent is not the
suite, checked once the signal is set, so that a suite that ended first is seen too. At SIGTERM, or
at SIGALRM once the seconds have passed, it stops (SIGSTOP) and kills (SIGKILL) every process under
it, pass after pass until one finds none (at most 50), so that none forks out of reach, then ends
(status 143 or 142); at SIGALRM it first writes a line for each, its PID and command line, to its
standard error, which the suite shows when the run fails. Every process under it, not its command's
process group alone: timeout(1) moves its command to a group of its own. A SIGKILL of this process
itself leaves the run to the suite's own cleanup: both suites' processes carry a variable that
their cleanup scans for.
"""
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
libc = ctypes.CDLL(None, use_errno=True)


def refuse(why):
    sys.stderr.write("reaper: %s\n" % why)
    sys.exit(125)


def under_me():
    """Every process under this one (its children, theirs and so on, by the parent /proc gives each),
    leaving out those that have ended."""
    children = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name) as stat:
                fields = stat.read().rpartition(")")[2].split()
        except OSError:
            continue
        if len(fields) > 1 and fields[0] not in ("Z", "X"):
            children.setdefault(int(fields[1]), []).append(int(name))
    found, todo = [], [os.getpid()]
    while todo:
        for pid in children.get(todo.pop(), ()):
            found.append(pid)
            todo.append(pid)
    return found


def command_line(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as cmdline:
            return cmdline.read().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        return ""


def end(status, report=None):
    """Stop and kill every process under this one, then end with the status given. With report
    (the time limit, in seconds), first write a line for each process to standard error."""
    told = set()
    for _ in range(50):
        found = under_me()
        if not found:
            break
        for pid in found:
            if report is not None and pid not in told:
                told.add(pid)
                line = "reaper: still running %d s after it started, now killed: %d %s\n"
                try:
                    sys.stderr.write(line % (report, pid, command_line(pid)))
                except OSError:
                    pass
        for sig in signal.SIGSTOP, signal.SIGKILL:
            for pid in found:
                try:
                    os.kill(pid, sig)
                except OSError:
                    pass
    try:
        sys.stderr.flush()
    except OSError:
        pass
    os._exit(status)


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("usage: python3 -I ci/reaper.py <the suite's PID> <seconds> <command...>\n")
        sys.exit(2)
    suite, seconds, command = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:]
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    ending = {signal.SIGTERM, signal.SIGALRM}
    # They wait, blocked, until the command's PID is known.
    signal.pthread_sigmask(signal.SIG_SETMASK, ending)
    signal.signal(signal.SIGTERM, lambda signum, _: end(128 + signum))
    signal.signal(signal.SIGALRM, lambda signum, _: end(128 + signum, seconds))
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        refuse("PR_SET_CHILD_SUBREAPER: " + os.strerror(ctypes.get_errno()))
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        refuse("PR_SET_PDEATHSIG: " + os.strerror(ctypes.get_errno()))
    if os.getppid() != suite:
        refuse("its parent is not the suite, PID %d" % suite)
    signal.alarm(seconds)
    pid = os.fork()
    if pid == 0:
        for s in ending | {signal.SIGPIPE, signal.SIGXFSZ}:
            signal.signal(s, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, ())
        try:
            os.execvp(command[0], command)
        except OSError as e:
            sys.stderr.write("reaper: %s\n" % e)
        os._exit(127)
    signal.pthread_sigmask(signal.SIG_SETMASK, ())
    status = 0
    while True:
        try:
            child, code = os.wait()
        except ChildProcessError:
            break
        if child == pid:
            status = os.WEXITSTATUS(code) if os.WIFEXITED(code) else 128 + os.WTERMSIG(code)
    sys.exit(status)


main()
