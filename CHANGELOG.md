# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v3.1.1] - Unreleased (release candidate)

v3.1.1 is a security-hardening release candidate planned for publication
concurrently with v4.0.1. It is a wire- and transcript-compatible continuation
of the v3.1 line: existing valid v3 integrations interoperate unchanged. The
breaking Fiat-Shamir, wire, and proof-format hardening carried by v4.0.1 is
deliberately excluded here.

### Release status

- Security review covered both commits in `117f3c3..bbea7d8`, followed by remediation and regression coverage for every concrete issue found.
- The pre-remediation candidate tip `bbea7d8` must not be tagged. The final release commit and `v3.1.1` tag must include the review remediations and be maintainer-signed.
- The remediated candidate passes the supported Go 1.25.12 unit and race suites, the Go 1.26 compatibility suite, `go vet`, `go build`, `go mod verify`, targeted fuzzing, dual-committee resharing tests, and `govulncheck` with no reachable or imported vulnerabilities.
- The only remaining qualification is the documented ModProof security boundary below; deployments that require proof of stronger factor properties need an independently reviewed protocol extension before release.

See the [release-candidate security review](security/2026-08-11-release-candidate-review.md)
for scope, evidence, signature verification, findings, and command-level results.

### Fixed (security)

- Reject nil or invalid curves, coordinates, scalars, cross-curve operands, the identity element, and non-prime-order results throughout checked EC operations and EC-point proof verification.
- Harden `paillier.Proof.Verify` against a prime-modulus Fermat bypass.
- Make `GetRandomPositiveInt` return strictly positive values, and add group-membership and canonical-input validation helpers.
- Make `ECPoint.Add` nil-safe and route degenerate signing scalar multiplications, including the round-5 signature share, through checked, identity-rejecting variants.
- Reject intra-session message replacement in `StoreMessage`.
- Harden VSS create/verify/reconstruct against nil curves and shares, invalid or negative indexes, zero-residue share IDs, threshold overflow, identity commitments, and malformed inputs that previously panicked; reject short keygen decommitments.
- Enforce group-membership and honest-sampling response-scalar bounds in the DLN and FacProof verifiers.
- Validate MtA public inputs before transcript hashing, require Bob-WC points to use the expected curve, reject nil private inputs, and bound response scalars and decrypted shares.
- Make `BaseParty.ValidateMessage` reject nil message content without dereferencing it in the error path.
- Deep-copy `LocalSecrets` on every `BuildLocalSaveDataSubset` return path, including missing-signer fallback, so re-sharing (round 5) and HD signing cannot alter the caller's saved share through a shared pointer.
- Bound the declared length in `ECPoint.GobDecode` before allocating, so a malformed length prefix cannot reserve a large buffer ahead of the read that would reject it anyway.
- Bound the exported crypto primitives against out-of-protocol inputs: a rejection floor in `paillier.GenerateKeyPair`, a width mask on `paillier.GenerateXs` candidates, and an empty-blinding-group guard in `paillier.Encrypt`. In-protocol moduli are already pinned to 2048 bits, so these change no value the protocol produces.
- Answer "no such value" instead of looping in `GetRandomPrimeInt`, `GetRandomPositiveRelativelyPrimeInt`, and `GetRandomQuadraticNonResidue` (adding a try bound plus perfect-square and parity guards to the last), fail `modproof.NewProof` rather than inherit that wait, and let the concurrent safe-prime generator be cancelled while handing over a result.
- Bound de-commitment part counts before `DeCommit` hashes them, in keygen round 3 and resharing round 4 on both curves.
- Return a marker from `PartyID.String()` and guard `BuildLocalSaveDataSubset` and the `ReSharingParameters` old-committee readers against a nil embedded pointer, so a `PartyID` or `ReSharingParameters` shape produced by `encoding/json` or a shallow copy cannot fault.
- In MtA, check the counterparty's `(NTilde, h1, h2)` ring and the values computed in it on the proving side, and attribute a ring-decided failure to the counterparty that supplied the ring rather than to the honest prover that built the proof.

### Maintenance

- Raise the minimum supported Go patch release to 1.25.12; the former 1.25.0 floor has reachable standard-library advisories under `govulncheck`.

### Security scope: ModProof

`ProofMod` attests the implemented Blum-integer shape statement. It does not
prove that the hidden factors are safe primes, that they are balanced, or that
their induced group order has no small factors. This limitation is explicit and
unchanged by the release review; a deployment whose malicious-peer model
requires those stronger properties should not treat the current proof as
providing them.

### Verification

- Full tests pass with Go 1.25.12 and Go 1.26.0; the full Go 1.25.12 suite also passes under the race detector.
- `go vet ./...`, `go build ./...`, and `go mod verify` pass.
- `govulncheck` reports no reachable or imported vulnerabilities on Go 1.25.12.
- Targeted wire/secrets fuzzing and dual-committee resharing tests pass.

### Compatibility

- Wire- and transcript-compatible with the v3 line (v3.0.x, v3.1.0). No protobuf or Fiat-Shamir transcript changes. Applications requiring the breaking proof-format hardening should plan a coordinated migration to v4.0.1.

### Divergence from upstream: overlapping-committee resharing

This fork deliberately supports re-sharing where a party belongs to **both** the
old and the new committee — an in-place refresh that retains existing members
while rotating the shares. This is a supported, maintained capability, kept
because there are legitimate operational reasons to retain existing parties across
a re-share rather than stand up an entirely disjoint new committee. We ported the
`bnb-chain/tss-lib#128` dual-committee fix (a dual member stores its self-dealt
VSS share locally instead of on the wire; membership gates on committee-exclusive
party keys rather than indices; slots resolve in committee-correct index space)
and guard it with a dedicated regression suite and an automated fail-open check.
We deliberately do **not** adopt upstream changes that assume disjoint committees,
because they would break this path.

## [v3.1.0] - 2026-07-10

v3.1.0 security and maintenance hardening. Existing valid v3 integrations retain their session fallback behavior; explicit fresh session nonces are strongly recommended and become mandatory in v4.

### Fixed (security)

- Rejected negative, nil, non-representable, trailing, and oversized commitment length prefixes before slicing, closing an authenticated-peer panic in proof decoding.
- Derived every keygen/signing/resharing message slot from committee membership by party key instead of trusting `PartyID.Index`; resharing now uses separate old/new committee-local indexes.
- Corrected the ECDSA resharing round-2 SSID loop so a new-committee index cannot skip an unrelated old-committee participant.
- Added a 4 MiB wire-message ceiling and per-element proof decoding bounds before `big.Int` allocation.
- Made session nonce values immutable across the API boundary and added explicit positive-value validation for callers preparing for v4.
- Added byte-preserving EdDSA signing via `NewLocalPartyWithBytes` and made invalid legacy lengths return errors rather than panic.
- Zero temporary secret material after protocol aborts as well as successful completion; a fatal error now terminalizes the party under its mutex before cleanup, so queued updates cannot resume on wiped state. Resharing copies persisted output before success cleanup.
- Serialized message validation with round advancement, made wire-parse error formatting independent of mutable round state, and made party status/error helpers concurrency-safe.
- Kept validation failures non-terminal so malformed or non-member messages cannot wipe an otherwise live session; valid transport messages racing `Start` or successful completion retain v3 delivery behavior.
- Added nil-safe MtA proof and VSS share verification guards.

### Maintenance and governance

- Raised the minimum Go version from 1.23 to 1.25 and test both supported Go release lines (1.25 and 1.26).
- Updated direct cryptographic/runtime dependencies and pinned `govulncheck` as a Go tool dependency.
- Removed unverified `curl | tar` Go installation from ARM CI; official setup actions are pinned to release commit SHAs with read-only permissions.
- Added CI vet/vulnerability gates, Dependabot configuration, a private-reporting policy, PR security checklist, and an explicit solo-maintainer tool-review process.
- Added deterministic queued-update terminalization coverage and repeated malformed-wire/live-round stress tests under the race detector.

### Compatibility

- Existing callers continue to run without setting `SessionNonce`, but that compatibility fallback is deprecated; set a new positive nonce for every run before migrating to v4.
- EdDSA callers should migrate from the numeric message constructor to `NewLocalPartyWithBytes`.
- Parameter construction now requires peer contexts sorted by distinct, non-zero-mod-order party keys, and the local `PartyID.Index` must match its sorted committee position.
- Wire format is unchanged, but oversized messages/proof integers previously accepted are now rejected.

## [v3.0.2] - 2026-07-03

July 2026 security update. A non-breaking patch: no wire-format changes and no
breaking API changes (the only API addition is the `ScalarMultChecked` /
`ScalarBaseMultChecked` helpers), interoperable with honest v3.0.0/v3.0.1 peers.
It closes a resharing-continuity
authentication bug and a resharing modulus-size gap, ports an upstream
dual-committee correctness fix to EdDSA, corrects abort attribution in several
paths, and adds a batch of defense-in-depth guards — all identified by a
multi-agent audit of resharing continuity and protocol-logic invariants. A
follow-up pass closed a reachable zero-scalar verifier DoS, added non-panicking
scalar-multiplication variants, hardened two one-time secret-modulus inversions
against timing leaks, and extended test coverage. See
[Appendix C](./security/2026-02-24-tss-lib-full-audit.md#appendix-c-july-2026-resharing-continuity-and-protocol-logic-update)
of the audit report for full detail.

### Fixed (security)

- **`SRC-2026-1155` (resharing continuity bypass):** the new committee's round-1
  handler looped over every old-committee `DGRound1Message` but always unmarshalled
  slot `0` instead of the loop's current message, so the "every old party must
  advertise the same aggregate public key" check degenerated to comparing slot 0
  against itself and never fired. A malicious old slot-0 party could advertise a
  forged aggregate key (and a matching VSS constant) and make honest new parties
  complete resharing for an attacker-chosen key. The handler now reads the current
  message so each old party's advertised key is checked; a mismatch aborts round 1.
  Present on both ECDSA and EdDSA. (`{ecdsa,eddsa}/resharing/round_1_old_step_1.go`)
- **Paillier/NTilde modulus size floor in ECDSA resharing:** the new committee's
  round-4 validation checked the mod/DLN proofs but — unlike keygen — never enforced
  the 2048-bit floor on peer-supplied Paillier `N` and `NTilde`. Neither proof bounds
  modulus size, so a malicious new-committee member could seat a small modulus as the
  reshared group's long-term auxiliary material; that `NTilde` is later the Pedersen
  parameter for the signing MtA range proofs, so a weak factorization breaks their
  statistical hiding. The round-4 loop now applies the same `BitLen() == 2048` checks
  as keygen. ECDSA-only (EdDSA resharing uses no Paillier material).
  (`ecdsa/resharing/round_4_new_step_2.go`)
- **Zero-scalar verifier DoS (`K13`):** several proof `Verify` paths multiplied a
  peer-supplied scalar that was range-checked only to `[0, q)` — so a value of `0`
  was accepted and `ScalarBaseMult(0)`/`P^0` (the point at infinity) panicked the
  honest verifier via the panicking `ScalarMult`/`ScalarBaseMult`. A single malicious
  peer could crash a verifier. The affected paths (schnorr `ZKProof`/`ZKVProof.Verify`
  on `T`/`U`, mta `ProofBobWC.Verify` on `S1`, vss `Share.Verify` on `Share`) now use
  the checked variants and reject instead. The keygen/resharing `BigXj` reconstruction
  loops were migrated too, so a peer with `KeyInt ≡ 0 (mod q)` yields a clean attributed
  abort rather than a panic.

### Fixed (correctness)

- **EdDSA dual-committee resharing (upstream `bnb-chain/tss-lib#128`):** ported the
  two guards ECDSA already carried for a party sitting in both the old and new
  committees. Round 1/round 3 no longer call `allOldOK()` unconditionally (gated
  behind `!IsNewCommittee()`), and a dual party's self-dealt round-3 share is now
  stored locally instead of emitted on the wire and clobbered. Without this a reshare
  including a dual-committee member aborts. (`eddsa/resharing/round_{1,3}_*.go`)
- **Resharing round-4/5 abort attribution:** the round-4 `Vc[0]!=pub` assertion
  attributed the abort to the honest reporting party itself; round-4 `newBigXj`
  reconstruction and round-5 `facProof` verification returned `WrapError` over a
  `nil` cause, surfacing real failures as the uninformative "Error is nil". Now
  attribute the old committee and return descriptive non-nil errors. (ECDSA + EdDSA)
- **Resharing round-2 SSID attribution:** the new committee's round-2 SSID check
  read old-committee slot 0 as an unvalidated anchor and blamed the *other* party on
  a mismatch, so a malicious old slot-0 party could forge an ssid and force an abort
  that frames the honest first-mismatching party (usable to grind honest nodes off
  the committee where the culprit list drives penalties). Now attribute both parties
  in the disagreeing pair. ECDSA-only. (`ecdsa/resharing/round_2_new_step_1.go`)
- **Signing abort attribution:** the ECDSA phase-5 `U != T` consistency failure
  (round 9) attributed the abort to the honest party running the check — now the
  other signers; and the EdDSA round-3 de-commitment failure branches passed *no*
  culprit (unlike their sibling branches), leaving a griefer un-attributable — now
  the sender. (`ecdsa/signing/round_9.go`, `eddsa/signing/round_3.go`)

### Hardened (defense-in-depth, non-exploitable)

- `crypto/schnorr` `ZKProof.ValidateBasic` now also requires `Alpha.ValidateBasic()`
  (on-curve), matching `ZKVProof`, so `Verify` cannot dereference off-curve coordinates.
- `crypto/dlnproof` `Verify` nil-checks each `Alpha[i]`/`T[i]` before the modular
  reduction instead of after, returning `false` rather than panicking on a nil element.
- `tss.ParseWireMessage` rejects a nil `from` party with an error instead of panicking
  on the exported boundary.
- `common.RejectionSample` reduces into a fresh `big.Int` instead of mutating the
  caller's `eHash` in place, removing an aliasing footgun.
- Removed a dead `kgRound2Message1s[i] = r2msg1` self-write in EdDSA keygen round 2
  (inert, but the same wrong-index class the audit was hunting; the ECDSA sibling
  lacks it).
- Added non-panicking `crypto.ECPoint.ScalarMultChecked` / `ScalarBaseMultChecked`
  that return an error instead of panicking when the result is the point at infinity;
  the panicking variants are retained as thin wrappers for call sites that have
  established the scalar is nonzero (`crypto/ecpoint.go`).
- **Constant-time (timing side-channel):** the constant-time layer already routes every
  secret-*exponent* modular exponentiation (incl. Paillier `Decrypt`) through
  `filippo.io/bigmod`. The two remaining variable-time-on-secret operations — inverting
  `N` modulo the even secret totient `φ` in `paillier.Proof` and `modproof.NewProof` —
  are now **blinded** (`g⁻¹ = r·(g·r)⁻¹`, decorrelating the extended-GCD timing from `φ`),
  and modproof's fourth-root exponent no longer reduces modulo the secret `φ` (the
  reduction was unnecessary — every `Yᵢ` there is a unit, so the transcript is identical).
  Both are one-time keygen/proof operations. (`common/int.go`, `crypto/paillier`,
  `crypto/modproof`)

### Known limitations

- **Modulus factor properties:** `ProofMod.Verify(Session, N)` receives only the
  public modulus, so the proof attests Blum-integer shape but does not prove that
  the factors are safe primes, balanced, or have non-smooth `(p-1)/2` and
  `(q-1)/2` halves. A maliciously generated 2048-bit Blum modulus can therefore
  satisfy the proof without those stronger properties. Establishing them requires
  an independently reviewed factor-property/range proof and is outside this
  release's protocol. Applies to keygen as well as resharing.

### Verification

- New regression/adversarial tests: resharing slot-0 continuity (ECDSA + EdDSA),
  small-Paillier-`N` and small-`NTilde` rejection, EdDSA dual-committee self-share
  continuity, round-2 SSID slot-0 misattribution, EdDSA signing de-commitment
  culprit attribution, and unit tests for each defense-in-depth guard.
- Follow-up tests: ECDSA dual-committee self-share continuity (porting the EdDSA
  case), `ScalarMultChecked`/`ScalarBaseMultChecked` point-at-infinity rejection,
  schnorr `T=0`/`U=0` and vss `Share=0` verifier rejection (no panic), and a
  differential check of the blinded even-modulus inverse against `math/big`.
- `go build ./...` and `go vet ./...` clean; the touched protocol and crypto suites
  pass. Every non-trivial fix was verified fail-open (neutralize the guard → the test
  goes red).

## [v3.0.1] - 2026-06-19

June 2026 security update. A non-breaking security patch: no API or wire-format
changes, interoperable with honest v3.0.0 peers. It closes two input-validation
gaps cross-referenced from upstream advisories and adds six defense-in-depth /
canonicality hardenings identified by a multi-agent audit of adversarial input
validation at protocol message boundaries. See
[Appendix B](./security/2026-02-24-tss-lib-full-audit.md#appendix-b-june-2026-boundary-validation-update-and-remediation)
of the audit report for full detail.

### Fixed (security)

- **J2 / `SRC-2026-644` (remote DoS):** EdDSA signing round 3 checked the
  `NewECPoint(Rj)` error *after* calling `EightInvEight()` on the result. A
  malicious party sending off-curve coordinates could panic an honest signer via a
  nil-pointer dereference. The error is now checked before use.
  (`eddsa/signing/round_3.go`)
- **J1 / `SRC-2026-573`:** `crypto.NewECPoint` accepted non-canonical coordinates
  ≥ P that `btcec/v2`'s `IsOnCurve` silently reduces mod P. `isOnCurve` now rejects
  coordinates outside `[0, P)`. (`crypto/ecpoint.go`)

### Hardened (defense-in-depth, non-exploitable)

- **J3:** `eddsa/keygen` round 3 now checks the `UnFlattenECPoints` error before
  iterating the returned points (matches the ECDSA sibling).
- **J4:** `ProofBobWCFromBytes` enforces exactly 12 byte-parts before indexing
  `bzs[10]`/`bzs[11]` instead of trusting the caller. (`crypto/mta/proofs.go`)
- **J5:** `ecdsa/signing` round 9 decommitment guard uses `||` instead of `&&`,
  matching rounds 5 and 7 and removing a latent index-out-of-bounds.
- **J6:** Resharing accumulates the new key share with `modQ.Add`, keeping the saved
  `Xi` canonical in `[0, q)` (matches keygen). (ECDSA + EdDSA resharing round 4)
- **J7:** Added nil-guards to the exported proof `Verify()` parameters in schnorr,
  modproof, dlnproof, and mta.
- **J8:** Reject non-canonical peer-supplied scalars — Schnorr `T`/`U` and VSS
  `Share` in `[0, q)`, and the EdDSA signature share `S` in `[0, L)` (also closing a
  silent 32-byte truncation of oversize `S`).

### Verification

- New regression tests for J1, J2, J4, J8 (and the existing EdDSA adversarial tests
  updated for the new S range check).
- Full test suite passes on the default build and compiles with
  `-tags insecure_noproofs`; the protocol packages pass under the race detector.
- Every fix was independently re-verified (present, correct, and proven not to reject
  any legitimate protocol value) before release.

## [v3.0.0] - 2026-02

Initial Stratovera release of the fork. Module re-path to
`github.com/AnvoIO/tss-lib/v3`, v3.0 security audit and hardening (constant-time
arithmetic, session-bound Fiat-Shamir challenges, VSS correctness, secure-by-default
proof gating). See the [v3.0 breaking changes](./README.md#v30-security-hardening-and-session-context)
and the [February 2026 audit report](./security/2026-02-24-tss-lib-full-audit.md).

[v3.0.2]: https://github.com/AnvoIO/tss-lib/compare/v3.0.1...v3.0.2
[v3.0.1]: https://github.com/AnvoIO/tss-lib/compare/v3.0.0...v3.0.1
[v3.0.0]: https://github.com/AnvoIO/tss-lib/releases/tag/v3.0.0
