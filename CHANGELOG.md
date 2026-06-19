# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[v3.0.1]: https://github.com/AnvoIO/tss-lib/compare/v3.0.0...v3.0.1
[v3.0.0]: https://github.com/AnvoIO/tss-lib/releases/tag/v3.0.0
