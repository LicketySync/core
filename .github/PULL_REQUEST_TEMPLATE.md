## What and why

<!-- One paragraph. Link the plan section or issue. -->

## Reviewer checklist (fresh context, not the author)

- [ ] Correct at the edges: empty, huge, concurrent, offline, clock skew
- [ ] Idiomatic Rust: typed errors; no `unwrap`/`expect` outside tests; no panic reachable from untrusted input
- [ ] Dead code gone, including branches no caller reaches and features that lost their last user
- [ ] Tests exercise behaviour, cover failure paths, are deterministic, and fail if the change is reverted
- [ ] Security: checked against `spec/threat-model.md`; every peer byte treated as untrusted
- [ ] Docs and CHANGELOG updated
- [ ] Touches keys, protocol, paths or API? Second reviewer and security-reviewer pass recorded below

## Plain-language summary for the owner

<!-- What this change does, what it risks, how to try it by hand. -->
