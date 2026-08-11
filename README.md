# tss-lib

[![Build & Test][1]][2] [![Go fmt][3]][4] [![MIT licensed][5]][6]

[1]: https://github.com/AnvoIO/tss-lib/actions/workflows/test.yml/badge.svg
[2]: https://github.com/AnvoIO/tss-lib/actions/workflows/test.yml
[3]: https://github.com/AnvoIO/tss-lib/actions/workflows/gofmt.yml/badge.svg
[4]: https://github.com/AnvoIO/tss-lib/actions/workflows/gofmt.yml
[5]: https://img.shields.io/badge/license-MIT-blue.svg
[6]: LICENSE

A Go implementation of multi-party {t,n}-threshold ECDSA and EdDSA signature schemes based on Gennaro and Goldfeder CCS 2018 [1]. Provides distributed key generation, signing, and dynamic group re-sharing with no trusted dealer.

Based on [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) with security hardening, constant-time arithmetic, session-bound Fiat-Shamir challenges, VSS correctness fixes, and adversarial input-validation hardening at protocol message boundaries.

## Release line

This source tree is the breaking v4 release line. v4.0.1 is currently a release
candidate planned for publication alongside v3.1.1:

- Go module: `github.com/AnvoIO/tss-lib/v4`
- Release branch: `release/v4.0.1`
- Candidate status: security review and remediation complete; final signed release tag pending
- Adoption target: `v4.0.1` (`v4.0.0` was not rolled out and is retracted)

The v3 API is not bundled into the v4 source tree. It remains available and
maintained independently through the `v3.1.0` tag and the v3.1.1 candidate on
the `release/v3.1.1` branch using module path
`github.com/AnvoIO/tss-lib/v3`. Releasing v4 does not delete or invalidate
tagged v3 source or existing v3 module downloads.

Choose the major version through the Go import path. Do not mix v3 and v4
participants in one keygen, signing, or resharing session. v4.0.1 adds mandatory
NTilde ModProof fields to keygen and resharing and changes every proof transcript;
its mandatory session nonce and stricter API contracts also form a coordinated
migration boundary.

### v3.1.1 compared with v4.0.1

| Area | v3.1.1 | v4.0.1 |
| --- | --- | --- |
| Release intent | Wire-compatible v3 security maintenance | Breaking v4 security hardening |
| Go module | `github.com/AnvoIO/tss-lib/v3` | `github.com/AnvoIO/tss-lib/v4` |
| Session nonce | Optional legacy fallback; fresh positive nonce strongly recommended | Fresh positive coordinated nonce required before `Party.Start()` |
| Party identities | Reference-backed; callers must treat contexts and IDs as immutable | Constructor snapshots and identity accessors are defensive deep copies; `SetIDs` removed |
| Public `Party` API | Low-level validation/storage/round hooks remain exposed but are not concurrent application entry points | Public interface narrowed to serialized lifecycle/update and concurrency-safe status/error operations |
| Proof transcripts | Unchanged from the v3 line | Per-proof-type domain separation, uniform ModProof sampling, and message-bound signing SSID |
| Keygen/resharing wire | Unchanged from the v3 line | New mandatory NTilde ModProof field |
| Session deployment | Use only v3 participants | Use only v4 participants; migrate every party together |

Existing releases remain available from their tags; the v3.1.1 and v4.0.1
candidates are maintained on separate release branches until their signed
annotated release tags are cut.

## Features

- **ECDSA threshold signatures** -- {t,n}-threshold signing on secp256k1 and other curves
- **EdDSA threshold signatures** -- Edwards-curve variant following the same approach
- **Distributed key generation** -- no trusted dealer, each party holds one secret share
- **Dynamic re-sharing** -- change the group of participants while preserving the key
- **Constant-time arithmetic** -- centralized via `filippo.io/bigmod` to prevent timing side channels
- **Session-bound proofs** -- all Fiat-Shamir challenges bound to protocol SSID, preventing cross-session replay
- **Paillier, DLN, range, and factor proofs** -- with optional build-tag disable for testing (`-tags insecure_noproofs`)

## Requirements

- Go 1.25.12 or later (use a currently supported, patched Go toolchain)
- Protocol Buffers compiler (for regenerating wire format, not required to build)

## Building

```bash
go build ./...
```

### Running tests

```bash
# Unit tests
make test_unit

# Unit tests with race detector
make test_unit_race

# Repeated adversarial lifecycle/wire concurrency regressions
make test_lifecycle_race
```

## Usage

Create a `LocalParty` from the `keygen`, `signing`, or `resharing` package and wire it to your network transport.

### Setup

```go
// Pre-compute safe primes and Paillier secret (can take time)
preParams, err := keygen.GeneratePreParams(1 * time.Minute)
if err != nil {
    // handle error
}

// Create PartyIDs for each peer
parties := tss.SortPartyIDs(getParticipantPartyIDs())
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(parties)

// Select curve: tss.S256() for ECDSA, tss.Edwards() for EdDSA
params, err := tss.NewParameters(tss.S256(), ctx, thisParty, len(parties), threshold)
if err != nil {
    // handle error
}

// Required: use a fresh positive nonce agreed by every participant.
// Never reuse it across protocol runs.
params.SetSessionNonce(sessionNonce)
```

`Party.Start()` rejects a missing, zero, or negative nonce before protocol preparation begins. Set a fresh coordinated nonce before every keygen, signing, or resharing run.

### Key generation

```go
party := keygen.NewLocalParty(params, outCh, endCh, preParams)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Signing

```go
party := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

For EdDSA, pass the exact message bytes so leading zeros are preserved:

```go
party := eddsasigning.NewLocalPartyWithBytes(messageBytes, params, ourKeyData, outCh, endCh)
```

### Re-sharing

```go
party := resharing.NewLocalParty(params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Messaging

```go
// Receiving updates from the wire
UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (ok bool, err *tss.Error)

// Sending messages to the wire
WireBytes() ([]byte, *tss.MessageRouting, error)
```

Concurrent transports may call `Start`, `Update`, and `UpdateFromBytes` on the
same party; updates are serialized, valid messages that arrive just before
`Start` are queued, and valid messages already queued after successful completion
are ignored. A fatal protocol error terminalizes the party and clears temporary
secrets before any queued update can run. `Running`, `WaitingFor`, `String`,
and `WrapError` are safe status/error helpers during concurrent delivery.

The public `Party` interface exposes only serialized update/lifecycle operations
and concurrency-safe status/error helpers. Concrete protocol types retain
`ValidateMessage`, `StoreMessage`, and `FirstRound` solely as implementation
hooks; application code should not type-assert and call them directly.
`NewPeerContext` and parameter constructors take deep identity snapshots, and
`PeerContext.IDs()` / `Parameters.PartyID()` return deep copies. Compare party
keys (or use `SortedPartyIDs.IndexOf`), never `*PartyID` pointer addresses.

`PeerContext.IDs()` allocates a deep copy on each call; applications targeting
very large committees should take one snapshot outside hot loops and reuse it
within that operation. The copy preserves sorted order and committee-local index
correspondence.

## How to use this securely

The transport layer is your responsibility. You must provide:

- **Broadcast and point-to-point channels** with end-to-end encryption (TLS with AEAD recommended)
- **Session IDs** unique to each protocol run, agreed upon out-of-band before rounds begin; pass the positive value with `SetSessionNonce`
- **Reliable broadcast** so all parties receive identical messages (hash-and-compare)
- **Timeouts and error handling** -- use `Party.WaitingFor()` and `*tss.Error` culprit info

Inbound transports should reject messages above 4 MiB before buffering; `ParseWireMessage` enforces the same ceiling as defense in depth.

## Releases

### v4.0.0: mandatory sessions and immutable identities (breaking)

Released concurrently with v3.1.0, v4.0.0 requires a fresh positive session nonce before every
`Party.Start()`, removes the legacy session fallback, changes the module path to
`/v4`, freezes committee and local identity snapshots, and narrows the public
`Party` interface to serialized application entry points. See the
[`CHANGELOG`](./CHANGELOG.md) for migration details.

### v3.1.0: wire-compatible security and maintenance release (separate v3 line)

The v3.1 release remains at module path
`github.com/AnvoIO/tss-lib/v3`. It preserves the v3 protobuf/wire format and
legacy nonce fallback while adding protocol-boundary hardening, terminal party
lifecycle handling, race regressions, dependency maintenance, and governance
controls. A fresh positive nonce is strongly recommended. v3 source remains
available from its own tag and maintenance branch; it is not copied into this
v4 tree.

### v3.0.2: July 2026 resharing-continuity and protocol-logic update (non-breaking)

Security patch. No breaking API or wire-format changes — interoperable with honest
v3.0.0/v3.0.1 peers (the only API change is the additive `ScalarMultChecked` /
`ScalarBaseMultChecked` helpers). Closes a resharing-continuity authentication
bypass (`SRC-2026-1155`) and a resharing Paillier/`NTilde` modulus-size gap, ports
the upstream dual-committee resharing fix (`bnb-chain/tss-lib#128`) to EdDSA,
corrects abort attribution in several resharing/signing paths, and adds a batch of
defense-in-depth guards. A follow-up pass closed a reachable zero-scalar verifier
DoS (`K13`), hardened two one-time secret-modulus inversions against timing leaks,
and added ECDSA dual-committee test coverage. Found by a security audit of
resharing continuity and protocol-logic invariants. See the [`CHANGELOG`](./CHANGELOG.md) and
[Appendix C of the audit report](./security/2026-02-24-tss-lib-full-audit.md#appendix-c-july-2026-resharing-continuity-and-protocol-logic-update).

### v3.0.1: June 2026 boundary-validation security update (non-breaking)

Security patch. No API or wire-format changes — interoperable with honest v3.0.0
peers. Closes two input-validation gaps cross-referenced from upstream advisories
(`SRC-2026-573`, `SRC-2026-644`), including a remote denial-of-service against EdDSA
signers, plus six defense-in-depth / canonicality hardenings found by a security
boundary-validation audit. See the [`CHANGELOG`](./CHANGELOG.md) and
[Appendix B of the audit report](./security/2026-02-24-tss-lib-full-audit.md#appendix-b-june-2026-boundary-validation-update-and-remediation).

## Breaking changes

### v4.0: mandatory sessions, immutable identities, and module migration

- Every protocol run requires a fresh positive `Parameters.SetSessionNonce` value agreed by all parties. `Party.Start()` fails before preparation when the nonce is absent or invalid.
- Legacy zero/message-derived session fallbacks have been removed.
- The Go module and internal import path changed from `github.com/AnvoIO/tss-lib/v3` to `github.com/AnvoIO/tss-lib/v4`; integrations must update their imports.
- Peer contexts and parameter identities are deep snapshots; `SetIDs` was removed and identity accessors return copies.
- The public `Party` interface no longer exposes low-level validation/storage/round hooks; deliver through `Update` or `UpdateFromBytes`.
- No protobuf wire fields changed from v3.1, but every participant must coordinate the required nonce and migrate together.

### v2.0: Paillier preparams

`PaillierSK.P` and `PaillierSK.Q` fields were added. Key vaults from v1.x must be regenerated via re-sharing.

### v3.0: Security hardening and session context

- Module path changed from `github.com/bnb-chain/tss-lib/v2` to `github.com/AnvoIO/tss-lib/v3`
- `tss.NewParameters()` and `tss.NewReSharingParameters()` now return `error`
- `PrepareForSigning()` (ECDSA/EdDSA) now returns `error`
- `SetNoProofMod()` / `SetNoProofFac()` blocked unless built with `-tags insecure_noproofs`
- DLN proof, MTA range proof, and Alice init functions now require `Session []byte` as first parameter
- Proof hashes include additional inputs (`NTilde`, `h1`, `h2`) and use tagged hashing -- wire-incompatible with v2
- `vss.Shares.ReConstruct()` correctly requires `threshold + 1` shares (was silently wrong with `threshold`)

All parties in a session **must** run the same version.

## Project structure

```
tss-lib/
  tss/              Core types: Party, Parameters, PartyID, message routing
  common/           Shared utilities, constant-time ModInt (bigmod), hash functions
  crypto/            Elliptic curve helpers, Paillier, commitments, proofs
    dlnproof/       Dlog-based non-interactive proofs
    facproof/       Factor proofs
    modproof/       Modular proofs
    mta/            Multiplicative-to-additive conversion proofs
    vss/            Verifiable secret sharing
  ecdsa/
    keygen/         ECDSA distributed key generation
    signing/        ECDSA threshold signing
    resharing/      ECDSA dynamic group re-sharing
  eddsa/
    keygen/         EdDSA distributed key generation
    signing/        EdDSA threshold signing
    resharing/      EdDSA dynamic group re-sharing
  test/             Test helpers and configuration
```

## Security audits

**Stratovera LLC (July 2026)** -- Resharing-continuity and protocol-logic audit. A review of the resharing continuity invariants and the protocol-logic bug class (wrong indices, no-op consistency checks, unaborted proof failures, mis-attributed aborts) across ECDSA/EdDSA keygen, signing, and resharing, with adversarial verification of every candidate. Fixed a resharing-continuity authentication bypass (`SRC-2026-1155`) and a resharing Paillier/`NTilde` modulus-size gap, ported the upstream dual-committee resharing fix (`bnb-chain/tss-lib#128`) to EdDSA, corrected abort attribution in several paths, and added defense-in-depth guards. Released in v3.0.2. Documented in [Appendix C](./security/2026-02-24-tss-lib-full-audit.md#appendix-c-july-2026-resharing-continuity-and-protocol-logic-update) of the report below.

**Stratovera LLC (June 2026)** -- Follow-up boundary-validation audit, cross-referencing upstream advisories (`SRC-2026-573`, `SRC-2026-644`) against this fork and reviewing adversarial input validation at every protocol message boundary. Fixed a remote denial-of-service (nil-pointer dereference on an off-curve point in EdDSA signing) and non-canonical EC point acceptance, plus six defense-in-depth / canonicality hardenings (`J1`–`J8`); no further exploitable vulnerability was found. Released in v3.0.1. Documented in [Appendix B](./security/2026-02-24-tss-lib-full-audit.md#appendix-b-june-2026-boundary-validation-update-and-remediation) of the report below.

**Stratovera LLC (February 2026)** -- Full-scope audit of the ECDSA/EdDSA threshold signature implementation, covering keygen, signing, resharing, and all supporting cryptographic primitives. Identified 13 findings (2 critical, 3 high, 5 medium, 3 low). All findings have been addressed. The full report is available at [`security/2026-02-24-tss-lib-full-audit.md`](./security/2026-02-24-tss-lib-full-audit.md).

**Kudelski Security (October 2019)** -- Review of the original bnb-chain/tss-lib. The report is available in the [upstream v1.0.0 release](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf).

## References

[1] R. Gennaro and S. Goldfeder, "Fast Multiparty Threshold ECDSA with Fast Trustless Setup," CCS 2018. https://eprint.iacr.org/2019/114.pdf

## License

[MIT](./LICENSE)

Copyright (c) 2026 Stratovera LLC and its contributors.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
