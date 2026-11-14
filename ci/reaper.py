#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Run a test suite's run of itself so that it neither outlives the suite nor leaves anything behind.

Usage: python3 -I ci/reaper.py <the suite's PID> <seconds> <command...>, started by the suite itself
(ci/test-download.sh and ci/test-mutants.sh, which test it).

It runs the command with SIGINT ignored, as a background job of a script has it, and no signal
blocked (Python's own ignored SIGPIPE and SIGXFSZ back to their defaults), and waits until the
command and every process it leaves behind have ended: they become this one's children (a child
subreaper). Its status is the command's (128 + the signal, for one a signal ended); past the
seconds, SIGALRM ends it (status 142).

It has the kernel send it SIGTERM when its parent, which must be the suite, ends, however it ends,
SIGKILL included (Linux's parent-death signal), and refuses (status 125) when its parent is not the
suite, checked once the signal is set, so that a suite that ended first is seen too. At SIGTERM it
stops (SIGSTOP) and kills (SIGKILL) every process under it, pass after pass until one finds none
(at most 50), so that none forks out of reach, then ends (status 143). Every process under it, not
its command's process group alone: timeout(1) moves its command to a group of its own.
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


def end(*_):
    for _ in range(50):
        found = under_me()
        if not found:
            break
        for sig in signal.SIGSTOP, signal.SIGKILL:
            for pid in found:
                try:
                    os.kill(pid, sig)
                except OSError:
                    pass
    os._exit(128 + signal.SIGTERM)


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("usage: python3 -I ci/reaper.py <the suite's PID> <seconds> <command...>\n")
        sys.exit(2)
    suite, seconds, command = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:]
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    for s in signal.SIGPIPE, signal.SIGXFSZ, signal.SIGALRM:
        signal.signal(s, signal.SIG_DFL)
    # SIGTERM waits, blocked, until the command's PID is known.
    signal.pthread_sigmask(signal.SIG_SETMASK, {signal.SIGTERM})
    signal.signal(signal.SIGTERM, end)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        refuse("PR_SET_CHILD_SUBREAPER: " + os.strerror(ctypes.get_errno()))
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        refuse("PR_SET_PDEATHSIG: " + os.strerror(ctypes.get_errno()))
    if os.getppid() != suite:
        refuse("its parent is not the suite, PID %d" % suite)
    signal.alarm(seconds)
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
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
