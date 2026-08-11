# v4.0.1 / v3.1.1 release-candidate security review

Date: 2026-08-11

## Decision

The implementation defects found in this review have remediations and regression
tests in the two release-candidate changesets that contain this report. The
original candidate tips listed in scope are pre-remediation and must not be
released. The release commits carrying these changes must be maintainer-signed;
signed annotated tags are a separate release handoff step.

One protocol boundary remains explicit. `ProofMod.Verify(Session, N)` proves the
Blum-integer shape covered by that protocol; it does not prove safe-primality,
factor balance, or non-smooth hidden-factor order. The release no longer claims
those properties, and an executable scope test demonstrates that non-safe Blum
factors can satisfy the proof. If the deployment requires a malicious participant
to prove those stronger factor properties, neither candidate is approved for
that threat model without a separately reviewed proof/setup extension.

Subject to that stated protocol scope, the concrete implementation findings are
resolved by the changes reviewed here.

## Exact scope

The user-directed baseline is every commit ahead of the named base, not only the
last release-note tranche.

| Line | Base | Candidate tip | Range | Size |
| --- | --- | --- | --- | --- |
| v4.0.1 | local `master` = `6c1f2c3` | `599c5e8` | `master..599c5e8` | 39 commits; 170 files; +6217/-2017 |
| v3.1.1 | `117f3c3` | `bbea7d8` | `117f3c3..bbea7d8` | 2 commits; 5 files; +152/-2 |

The earlier statement that v4 was ten commits ahead of `master` described
`50ee15d..599c5e8`, not the local repository topology. The review therefore used
the 39-commit range above.

Generated protobuf Go was reviewed as generated code plus source `.proto`
definitions and round-trip/build behavior; routine generator internals were not
manually line-audited.

## Threat model

- Protocol peers are authenticated and known, but every wire field is hostile.
- A participant may be malicious, send malformed group elements/proofs, replay or
  replace messages, attempt CPU/memory amplification, or try to corrupt durable
  key-share state.
- Public library APIs may receive malformed values from an integration and must
  return an error/`false` rather than crash on validation paths.
- Local build, dependency, CI, commit-signature, and release controls are part of
  the attack surface.

## Method

- Enumerated and read every commit and the full source diff in both ranges.
- Mapped wire parsing, message routing/storage, party lifecycle, secret state,
  VSS, EC operations, Paillier, DLN/Fac/Mod/Schnorr proofs, MtA, keygen, signing,
  resharing, protobuf, CI, dependencies, and release controls.
- Compared related fixes across ECDSA/EdDSA and v3/v4, and checked later local
  upstream-review commits for corrections/follow-ups.
- Exercised malformed points/scalars/shares, missing signer mappings, duplicate
  messages, proof bounds, lifecycle concurrency, full tests/race tests, fuzz
  targets, `go vet`, builds, module verification, and `govulncheck`.

## Findings and disposition

### RC-01: missing-signer fallback reintroduced secret aliasing

Affected: both candidates; ECDSA and EdDSA.

`BuildLocalSaveDataSubset` deep-copied `Xi` and `ShareID` on its successful path,
but returned `sourceData` by value when a requested signer was absent. The two
`*big.Int` secrets therefore still aliased the caller. Mutating/zeroing the
returned fallback changed the caller's durable share; this was reproduced in all
four branch/package combinations.

Disposition: fixed. The fallback retains the historical data shape but replaces
`LocalSecrets` with a deep copy. Regression tests mutate both returned fields and
assert that the source survives.

### RC-02: ModProof claims exceeded the verifier statement

Affected: the v4 NTilde feature and shared ModProof documentation.

The v4 comments and changelog claimed that the NTilde proof established a product
of safe primes and closed smooth-subgroup injection. The verifier receives only
`N`; it receives neither factor nor a safe-primality statement. A 2048-bit product
of two Blum primes whose `(p-1)/2` halves were composite was accepted by
`NewProof`/`Verify`.

Disposition: the false security claim is fixed across code comments, protobuf
source/generated comments, changelog, and `SECURITY.md`. A regression test pins
the actual scope. No new cryptographic protocol was invented in a release-fix
patch. The stronger malicious-setup property remains an explicit design
limitation and is a release blocker if an integration requires it.

### RC-03: the declared minimum Go release had reachable standard-library advisories

Affected: both candidates.

Under the declared `go 1.25.0` minimum, `govulncheck` reported seven reachable
standard-library vulnerabilities. Scanning with patched Go 1.25.11 was clean for
reachable vulnerabilities during initial review; Go 1.25.12 is available and is
now the declared/tested minimum.

Disposition: fixed in `go.mod` and README on both lines by requiring Go 1.25.12
or later. The final verification scan is run with that exact toolchain.

### RC-04: VSS exported APIs contained malformed-input panics

Affected: both candidates.

- `Shares.ReConstruct` read `shares[0].Threshold` before checking whether
  `shares[0]` was nil.
- `CheckIndexes` dereferenced a nil curve/order or nil index.
- `Create` could overflow `threshold+1` and could panic while committing a zero
  or order-multiple secret.
- `Share.Verify` accepted a positive ID with zero residue modulo the curve order,
  leading to a zero-scalar multiplication panic.

Disposition: fixed with early curve/order, nil, positivity, residue, scalar, and
threshold validation. Positive Ed25519 party IDs larger than the order remain
compatible and are reduced modulo the order. Tests cover nil-first-share, nil and
negative indexes, zero-residue IDs, zero/order secrets, and maximum-int threshold.

### RC-05: checked EC helpers were not fully checked

Affected: both candidates.

`ValidateBasic`, `IsOnCurve`, `IsInPrimeOrderSubgroup`, `ScalarMultChecked`,
`ScalarBaseMultChecked`, `Add`, and `Equals` retained nil-curve/coordinate/scalar,
invalid-point, identity, or curve-mismatch paths that could panic or return an
incorrect subgroup/equality result for directly constructed points.

Disposition: fixed. Checked APIs reject malformed inputs without panicking;
addition and equality enforce curve consistency. Tests cover nil curves,
coordinates and scalars, negative scalars, identity/subgroup behavior, and
cross-curve operands.

### RC-06: MtA with-check verifier dereferenced points before validation

Affected: both candidates.

`ProofBobWC.Verify` hashed `X.X/Y` and `U.X/Y` before subgroup/basic validation,
and did not require `U` to be on the verifier's curve. Directly constructed
malformed points could therefore crash verification or cross a curve boundary.
The matching prover and `AliceEnd` entry points also lacked basic nil checks.

Disposition: fixed. Both points and curve assignments are checked before the
transcript hash, the prover validates optional `X`, and Alice rejects incomplete
Paillier private keys before decryption. Tests exercise nil coordinates,
cross-curve `U`, and nil private keys. V3 transcript construction is unchanged.

### RC-07: malformed ParsedMessage error handling could itself panic

Affected: both candidates.

`BaseParty.ValidateMessage` formatted a message with nil content using `String`;
`MessageImpl.String` dereferences the same content/wire fields being validated.

Disposition: fixed. Nil message/content and invalid-sender paths avoid formatting
untrusted message internals; existing detailed errors remain for structurally
complete messages. A direct-construction regression test verifies non-panicking
rejection.

## Commit-signature verification

All 41 commits in scope have valid cryptographic signatures.

- 37/39 v4 commits and 2/2 v3 commits are good SSH signatures for
  `robert@stratovera.io`, fingerprint
  `SHA256:7XpN7+LCQYDJq73B4FtetW/7MgzEaIf+PXYTNjqD3zw`.
- The ten commits in `50ee15d..599c5e8` and both v3 commits are all directly
  signed by that maintainer SSH key.
- v4 merge commits `b6c59e6` and `fa8daf9` are good GitHub web-flow signatures,
  RSA fingerprint `968479A1AFF927E37D1A566BB5690EEEBB952194`, verified in an
  isolated keyring using `https://github.com/web-flow.gpg`. They are platform
  signatures, not signatures from the maintainer SSH key.

## Commit inventory

Every entry below was included in source/history review:

```text
9a04fdc security: harden protocol boundaries and maintenance for v3.1
e3690d6 fix: serialize abort cleanup and preserve live sessions
6820a3e fix: serialize validation with round advancement
49b219f docs: require adversarial concurrency review
396b155 fix: harden concurrent party lifecycle
e46478e security!: require session nonces and migrate module to v4
123cf3a security!: freeze party identity snapshots
96dc819 docs: clarify v4 release line
6d63aa8 docs: clarify v3 maintenance line
4d061dc docs: finalize v4 release notes
3ff0130 docs: finalize v3 review policy
769e5bd merge: align v4 with approved v3 tip
b6c59e6 Merge pull request #9 from AnvoIO/release/v3.1.0
8d02f93 docs: finalize v3.1.0 changelog
fa8daf9 Merge pull request #11 from AnvoIO/release/v3.1.0-finalize
0751d50 merge: incorporate finalized v3.1.0 release
558fdd0 docs: clarify concurrent v3.1.0 and v4.0.0 releases
f35a90e security: reject identity and non-prime-order EC points in proof verifiers
efd5c51 security: harden paillier.Proof.Verify against prime-modulus Fermat bypass
fa496af harden: GetRandomPositiveInt returns strictly positive values
091ee0a common: add group-membership and canonical-input validation helpers
2cc041d security: nil-safe ECPoint.Add and route degenerate signing scalar-mults through checked variants
59b87b5 security: route the round-5 signature-share scalar-mult through the checked variant
8ed320c security: reject intra-session message replacement in StoreMessage
91d12ac security: harden VSS create/verify/reconstruct and reject short keygen decommitments
98ed9b3 security: enforce group-membership and response-scalar bounds in DLN and FacProof verifiers
1fa2f62 security: validate MtA public inputs and bound response scalars and decrypted shares
d962f5f build: retract v4.0.0 (superseded by v4.0.1)
50ee15d test: make dual-committee resharing regression net bulletproof and loud
4154f7f build: regenerate all protobufs on protoc-gen-go v1.36.11
edc8282 security: prove NTilde structure during ECDSA keygen
4b16713 security: bind resharing peer NTilde to a ModProof
f3687c1 security: add per-proof-type Fiat-Shamir domain separation
f695991 security: sample modproof Y_i uniformly over Z_N (expand-then-reject)
a15c759 security: bind the message being signed into the signing SSID
0ccf351 docs: add v4.0.1 and v3.1.1 changelog entries
c804aac security: bind the eddsa signing message length-sensitively in the SSID
8cdc2c6 security: deep-copy LocalSecrets in BuildLocalSaveDataSubset
599c5e8 docs: note the save-data fix and the overlapping-committee divergence

v3 maintenance range:
9ff3d9f security: deep-copy LocalSecrets in BuildLocalSaveDataSubset
bbea7d8 docs: add the v3.1.1 changelog entry
```

## Compatibility of the remediation

- No protobuf field number or serialized descriptor changed; only source and
  generated comments were synchronized for the ModProof scope correction.
- V3 Fiat-Shamir transcript inputs and wire format remain unchanged.
- V4 retains its intended breaking domain-separated transcripts and new NTilde
  proof fields.
- Valid VSS party IDs remain compatible, including positive Ed25519 IDs greater
  than the group order; invalid zero residues are now rejected.
- The minimum toolchain moves from Go 1.25.0 to Go 1.25.12.

## Verification results

All commands below completed successfully on both remediated worktrees unless a
line names one branch explicitly.

| Gate | Result |
| --- | --- |
| Go 1.25.12 full unit suite | PASS, `go test -timeout 60m ./...` |
| Go 1.25.12 full race suite | PASS, `go test -timeout 60m -race ./...` |
| Go 1.26.0 cross-version full suite | PASS, `go test -timeout 60m ./...` |
| Static/build | PASS, `go vet ./...` and `go build ./...` |
| Module integrity | PASS, `go mod verify` (`all modules verified`) |
| Vulnerabilities | PASS for reachable/imported code, Go 1.25.12 `govulncheck ./...` |
| Focused regressions | PASS: EC, VSS, ModProof, MtA, ECDSA/EdDSA keygen, and `tss` |
| Resharing fail-open | v4 PASS: normal dual-committee tests pass and both defanged packages fail; v3 dual-committee tests pass |
| Parser fuzz smoke tests | PASS: `FuzzParseWireMessage` and `FuzzParseSecrets`, 15 seconds each on each branch |
| Touched-file formatting/diff | PASS: touched Go files formatted; `git diff --check` clean |

The patched scan reports zero symbol/package vulnerabilities. It also reports
`GO-2026-5932` against the required `golang.org/x/crypto` module because its
`openpgp` package is unmaintained; this repository neither imports nor reaches
that package, so the result is module-only and not an imported-package finding.

`protoc` was not installed in the review environment. The two changed protobuf
source comments were mirrored into their generated Go comments manually; field
definitions and raw serialized descriptors are unchanged. Earlier clean-tip
build and round-trip gates passed before remediation as well.

## Review limitations

- This is a source/history/dynamic-tooling review, not a mathematical proof of
  GG18/GG20 security or a hardware side-channel evaluation.
- Fuzzing was bounded smoke testing, not an exhaustive campaign.
- The hashes listed in scope are pre-remediation candidate tips. Required CI
  must pass the exact pushed, signed release-branch tips before either is tagged.

## Release handoff

1. Confirm each pushed release-branch tip has the maintainer signature and do not
   reuse either pre-fix candidate hash as a release tag.
2. Require the recorded local gates and protected-branch CI to pass on the exact
   signed commit hashes.
3. Create signed annotated release tags and publish checksums/SBOM or provenance
   according to `GOVERNANCE.md`.
