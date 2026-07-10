# Security and maintenance review — 2026-07-10

## Scope and threat model

This review covered the current ECDSA and EdDSA keygen, signing, and resharing implementations; proof and commitment deserialization; wire parsing; party/committee identity; randomness helpers; dependency state; CI; release process; and repository governance.

The deployment model supplied by the maintainer uses known, authenticated parties and is not currently exposed to adversarial participants. The review nevertheless treats authenticated peer messages as structurally untrusted. This reduces the likelihood of intentional exploitation but does not remove risks from compromised peers, routing mistakes, stale sessions, or malformed state.

The review included the existing audit report, recent security regression tests, current pull-request history, targeted source inspection, full tests, race tests, fuzz smoke tests, `go vet`, and `govulncheck`.

## Findings and disposition

| ID | Finding | Impact in stated model | Disposition |
| --- | --- | --- | --- |
| R1 | Commitment length prefixes were converted with `Int64` and used for slicing without rejecting negative or non-representable values. | Authenticated-peer process crash. | Fixed and fuzzed. |
| R2 | Protocol stores trusted `PartyID.Index`; resharing reused one index across old/new committees. | Message-slot corruption, panic, or incorrect resharing when committee positions differ. | Fixed by key-derived source membership and committee-local indexes. |
| R3 | Party keys could collide or become zero modulo the curve order. | Failed inversions, ambiguous interpolation identities, or abort. | Rejected during parameter construction. |
| R4 | ECDSA resharing SSID comparison skipped an old party using the local new-committee index. | Incomplete transcript consistency check. | Fixed; only the explicit anchor is skipped. |
| R5 | Top-level wire messages and proof integer fields had no explicit decoding ceiling. | Memory/CPU exhaustion by malformed authenticated input or direct API use. | Added 4 MiB wire cap and per-proof element bounds. |
| R6 | EdDSA's numeric message API could lose leading zero bytes; an invalid optional length could panic. | Signing a different byte string than intended or local crash. | Added `NewLocalPartyWithBytes`; legacy conversion now returns a `Start` error. |
| R7 | Session nonces were optional, with zero or message-derived fallbacks. | Cross-session transcript/proof replay when runs are repeated or overlap. | Staged: v3.1 hardens the nonce API and deprecates fallback behavior; the follow-on v4 branch rejects missing or non-positive nonces before prepare/secret work. |
| R8 | Temporary secrets were cleared on successful completion but not on every abort. | Longer secret lifetime in memory after errors. | Fatal `Start`/`Update` errors terminalize the party and invoke cleanup under the party mutex; resharing copies output before success cleanup. |
| R9 | Several exported proof/share verification paths lacked complete nil guards. | Direct-API panic. | Fixed and covered by package tests. |
| R10 | Random-byte acquisition accepted successful short reads. | Partially uninitialized/deterministic output with a nonstandard reader. | Switched to `io.ReadFull`. |
| R11 | Validation and wire-parse errors could format themselves by reading mutable round state without the party mutex. | Data race in error-only scheduling metadata; possible undefined behavior under concurrent delivery. | Validation is serialized with round advancement; `WrapError` uses a separately synchronized immutable round-context snapshot, so pre-parse errors never dereference live round state. |
| R12 | An error could wipe temporary state and then allow an already-queued update to continue on that wiped party. | Session corruption, secondary failures, and inconsistent abort behavior. | Added explicit created/running/finished/aborted lifecycle states; fatal errors terminalize before cleanup and queued updates return the same terminal error. |
| M1 | Go 1.23 was unsupported; CI downloaded ARM Go with unchecked `curl | tar`; workflows targeted `main` while the repository uses `master`. | Missing security patches and ineffective/supply-chain-weak CI. | Go 1.25 minimum, 1.25/1.26 matrix, official pinned setup actions, correct branch. |
| M2 | Dependencies and protobuf/crypto modules were stale; no automated reachable-vulnerability gate existed. | Delayed security updates. | Direct dependencies updated, `govulncheck` pinned as a Go tool, CI and Dependabot added. |
| G1 | Security reporting, merge controls, and solo-maintainer review expectations were undocumented. | Inconsistent disclosure and review; tool review could be mistaken for human approval. | Added `SECURITY.md`, `GOVERNANCE.md`, and a PR security/review template. |

## Verification performed

The remediated tree passed:

```text
go test ./...
go test ./ecdsa/keygen ./ecdsa/resharing ./ecdsa/signing \
  ./eddsa/keygen ./eddsa/resharing ./eddsa/signing ./tss
go vet ./...
GOTOOLCHAIN=go1.25.11 go tool govulncheck ./...
make test_signing_race
make test_unit_race
make test_lifecycle_race
go test ./crypto/commitments -run=^$ -fuzz=FuzzParseSecrets -fuzztime=2s
go test ./tss -run=^$ -fuzz=FuzzParseWireMessage -fuzztime=2s
go mod verify
git diff --check
```

`govulncheck` reported no reachable vulnerabilities with patched Go 1.25.11. It reported two advisories in imported packages and one in required modules as unreachable; these should remain monitored by CI and Dependabot.

## Race-test adequacy

The race detector instruments executed code; it does not create adversarial
interleavings or prove that unexecuted paths are race-free. The earlier full-suite
job missed R11 because no test delivered malformed wire bytes through
`UpdateFromBytes` while another goroutine advanced the same party's round. It
missed R12 because no test deliberately held a fatal update inside the mutex while
a second update waited behind it.

The remediation combines complementary gates: a full `go test -race ./...` run,
deterministic channel-controlled terminalization coverage, and repeated live EdDSA
sessions that inject non-member messages and malformed wire bytes during honest
round advancement while querying status/error helpers. CI runs the targeted cases
ten times after the full race suite. Parser fuzzing remains separate because fuzzing
byte inputs does not by itself explore concurrent schedules.

## Compatibility and staged breaking behavior

- v3.1 retains the legacy session fallback for existing integrations, but callers should set a positive `Parameters.SessionNonce` unique to each run and agreed by every party.
- EdDSA integrations should migrate to `NewLocalPartyWithBytes`.
- Invalid contexts, oversized messages, and oversized proofs that were previously accepted are rejected.
- The minimum supported Go release is 1.25.

The follow-on v4 branch makes the nonce requirement mandatory and changes the Go module/import path to `/v4`; that branch requires coordinated downstream migration.

## Residual risks and manual actions

1. No second human cryptographer reviewed this change set. Codex/Claude review records are useful supporting evidence, not an independent professional audit.
2. GG18/GG20-family protocols have complex malicious-security and identifiable-abort assumptions. This review is source-level assurance, not a new formal proof.
3. The legacy EdDSA numeric constructor remains for compatibility and is inherently ambiguous without an explicit byte length; downstream code should prohibit it.
4. GitHub-hosted rulesets, private vulnerability reporting, secret scanning, push protection, and tag protection must be enabled manually as listed in `GOVERNANCE.md`.
5. Applications still own peer authentication, reliable broadcast, replay storage, timeouts, crash recovery, and secure key-share storage.
6. The 4 MiB global ceiling is defense in depth, not a substitute for smaller message-type and transport limits. Revisit it if protocol sizes or party counts grow.
7. Old foundational EdDSA/logging dependencies remain because replacing them is a larger compatibility project. Continue isolating them and plan a separately reviewed migration.

## Recommended release process

Release v3.1 only after a fresh-context review of the final commit and all required CI checks. Prepare v4 as a separate coordinated migration, review its final diff independently, sign each release tag, publish checksums and migration notes, and verify GitHub repository settings before announcing either release.
