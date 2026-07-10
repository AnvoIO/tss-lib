# Maintenance and security governance

## Current model

This project currently has one human maintainer. The repository does not claim a second human approval when none occurred. Instead, security-sensitive changes use reproducible tests, CI gates, recorded fresh-context tool review, and periodic external audit where practical.

If another qualified maintainer becomes available, cryptographic and protocol changes should require their approval.

## Change classes

High-risk changes include protocol rounds, transcript/SSID construction, proof systems, curve or modular arithmetic, randomness, key serialization, committee membership/indexing, wire parsing, and secret cleanup. Dependency and CI changes are security-sensitive maintenance changes.

## Solo-maintainer merge process

For a high-risk change:

1. State the security invariant and threat model in the PR.
2. Add an adversarial regression that fails before the fix.
3. Run the full required checks from the PR template.
4. Obtain a fresh-context review of the final diff. Codex, Claude, or another review tool may be used when no human reviewer is available.
5. Record the tool/model, date, commit SHA, scope, findings, and disposition in the PR. Preserve disagreements rather than averaging them away.
6. Re-run review if the reviewed diff changes materially.
7. Merge only the reviewed commit after required CI checks pass.

Tool output must not be represented as human approval or an independent professional cryptographic audit. A review that cannot be turned into a test, invariant, or documented rationale remains an open risk.

## Repository settings to configure on GitHub

Create a ruleset for `master` with:

- deletion and force pushes blocked;
- required status checks for Go fmt, all Build & Test matrix jobs, Signing race regression, and Vet and vulnerability scan;
- branches required to be up to date before merge;
- signed commits required where contributor tooling supports them;
- administrator bypass limited to emergency response and recorded in the incident notes.

Because the project has one human maintainer, do not configure a fictitious required approval. Enable an approval requirement when a second qualified maintainer joins.

Also enable:

- GitHub Private Vulnerability Reporting;
- Dependabot alerts and security updates;
- secret scanning and push protection when available;
- tag protection for release tags.

These hosted settings cannot be enforced by files in the repository and must be verified periodically.

## Releases

Security-sensitive releases require a changelog entry, migration notes for breaking behavior, a signed annotated tag, checksums for artifacts, and a link to the reviewed commit. Never move or reuse a release tag.

## Incident response

For a credible vulnerability: preserve evidence, determine affected commits and downstream projects, prepare the fix privately when necessary, add a regression, coordinate embargo and release timing, publish an advisory, and document lessons and follow-up controls after disclosure.
