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

Keys are never sent to any server because there is none. Holding a folder's
key is the access, as in Resilio Sync: whoever holds a folder's write key can
change or delete anything in it, and removing someone means sharing the folder
again under new keys; the threat model states this as the design, not as a
vulnerability. The threat model in `spec/threat-model.md` lists the adversaries
we design against, the ones we explicitly do not, what stays visible to whom,
and the numbered requirements (TM-1 to TM-42, of which TM-16, TM-19, TM-34,
TM-36 and TM-38 are retired) the code is reviewed against; `spec/suites.md`
lists every algorithm, parameter and crate that may perform cryptography. A
report that shows one of those requirements unmet is a vulnerability.
