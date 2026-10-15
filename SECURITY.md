# Security policy

Lickety-Sync is a serverless, end-to-end encrypted file synchronisation tool.
Security outranks features and schedule; a confirmed vulnerability stops other
work until it is fixed.

## Reporting

Report privately through GitHub's "Report a vulnerability" button on this
repository (Security advisories), or by email to security@licketysync.com once
the domain is live. Please include steps to reproduce and the version or commit.

We acknowledge reports within 72 hours and aim to ship a fix within 90 days,
sooner for anything that exposes content or keys. We will credit you in the
advisory unless you ask us not to.

## Scope

In scope: the service, command line, apps, browser client, protocol, key model,
the website build and release pipeline. Out of scope: the operating systems and
networks the program runs on, and denial of service that needs a volume of
traffic any home connection would already fail under.

## What we promise about keys

Keys are never sent to any server because there is none. The threat model in
`spec/threat-model.md` (to be written in phase 0; until then the plan's Security
section serves) lists the adversaries we design against and the ones we
explicitly do not.
