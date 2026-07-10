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

This source tree is the wire-compatible v3 maintenance line:

- Go module: `github.com/AnvoIO/tss-lib/v3`
- Release branch: `release/v3.1.0`
- Current release: `v3.1.0`

The breaking v4 API is released independently from its own branch and tag using
module path `github.com/AnvoIO/tss-lib/v4`. It is not bundled into this source
tree. Releasing v4 does not delete, replace, or invalidate tagged v3 source;
future compatible v3 security fixes can continue from the v3 maintenance branch.

Choose the major version through the Go import path. Do not mix v3 and v4
participants in one keygen, signing, or resharing session. v3.1 preserves the v3
protobuf/wire format and legacy nonce fallback; applications should nevertheless
set a fresh positive session nonce for every run before migrating to v4.

## Features

- **ECDSA threshold signatures** -- {t,n}-threshold signing on secp256k1 and other curves
- **EdDSA threshold signatures** -- Edwards-curve variant following the same approach
- **Distributed key generation** -- no trusted dealer, each party holds one secret share
- **Dynamic re-sharing** -- change the group of participants while preserving the key
- **Constant-time arithmetic** -- centralized via `filippo.io/bigmod` to prevent timing side channels
- **Session-bound proofs** -- all Fiat-Shamir challenges bound to protocol SSID, preventing cross-session replay
- **Paillier, DLN, range, and factor proofs** -- with optional build-tag disable for testing (`-tags insecure_noproofs`)

## Requirements

- Go 1.25+
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

// Strongly recommended in v3 and required in v4: use a fresh positive nonce
// agreed by every participant. Never reuse it across protocol runs.
params.SetSessionNonce(sessionNonce)
```

For v3 compatibility, an unset nonce retains the legacy fallback. This is deprecated: set a fresh coordinated nonce before every keygen, signing, or resharing run so the integration is ready for v4.

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
`ValidateMessage` and `StoreMessage` are low-level hooks and must not be called
directly from concurrent application code. Treat party IDs and peer contexts as
immutable after constructing parameters.

## How to use this securely

The transport layer is your responsibility. You must provide:

- **Broadcast and point-to-point channels** with end-to-end encryption (TLS with AEAD recommended)
- **Session IDs** unique to each protocol run, agreed upon out-of-band before rounds begin; pass the positive value with `SetSessionNonce`
- **Reliable broadcast** so all parties receive identical messages (hash-and-compare)
- **Timeouts and error handling** -- use `Party.WaitingFor()` and `*tss.Error` culprit info

Inbound transports should reject messages above 4 MiB before buffering; `ParseWireMessage` enforces the same ceiling as defense in depth.

## Releases

### v3.1.0: wire-compatible security and maintenance release

This release preserves the v3 protobuf/wire format and existing session fallback
while adding protocol-boundary validation, committee-local sender binding,
terminal party lifecycle handling, malformed-wire and queued-abort race
regressions, dependency maintenance, and repository governance controls.
`Parameters.SetSessionNonce` remains optional for v3 compatibility but a fresh
positive value agreed by every participant is strongly recommended. See the
[`CHANGELOG`](./CHANGELOG.md) and
[`security review`](./security/2026-07-10-security-maintenance-review.md).

### v3.0.2: July 2026 resharing-continuity and protocol-logic update (non-breaking)

Security patch. No breaking API or wire-format changes — interoperable with honest
v3.0.0/v3.0.1 peers (the only API change is the additive `ScalarMultChecked` /
`ScalarBaseMultChecked` helpers). Closes a resharing-continuity authentication
bypass (`SRC-2026-1155`) and a resharing Paillier/`NTilde` modulus-size gap, ports
the upstream dual-committee resharing fix (`bnb-chain/tss-lib#128`) to EdDSA,
corrects abort attribution in several resharing/signing paths, and adds a batch of
defense-in-depth guards. A follow-up pass closed a reachable zero-scalar verifier
DoS (`K13`), hardened two one-time secret-modulus inversions against timing leaks,
and added ECDSA dual-committee test coverage. Found by a multi-agent audit of
resharing continuity and protocol-logic invariants. See the [`CHANGELOG`](./CHANGELOG.md) and
[Appendix C of the audit report](./security/2026-02-24-tss-lib-full-audit.md#appendix-c-july-2026-resharing-continuity-and-protocol-logic-update).

### v3.0.1: June 2026 boundary-validation security update (non-breaking)

Security patch. No API or wire-format changes — interoperable with honest v3.0.0
peers. Closes two input-validation gaps cross-referenced from upstream advisories
(`SRC-2026-573`, `SRC-2026-644`), including a remote denial-of-service against EdDSA
signers, plus six defense-in-depth / canonicality hardenings found by a multi-agent
boundary-validation audit. See the [`CHANGELOG`](./CHANGELOG.md) and
[Appendix B of the audit report](./security/2026-02-24-tss-lib-full-audit.md#appendix-b-june-2026-boundary-validation-update-and-remediation).

## Breaking changes

### v4.0: separate breaking release

- Every protocol run requires a fresh positive `Parameters.SetSessionNonce` value agreed by all parties.
- The Go module and internal import path changes from `/v3` to `/v4`.
- Legacy zero/message-derived session fallbacks are removed.
- Peer contexts and parameter identities become defensive snapshots.
- The public `Party` interface no longer exposes low-level validation/storage/round hooks.
- v4 is maintained in a separate source branch; the v3 tag and maintenance branch remain available.
- All participants in a protocol session must migrate together.

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

**Stratovera LLC (July 2026)** -- Resharing-continuity and protocol-logic audit. A multi-agent review of the resharing continuity invariants and the protocol-logic bug class (wrong indices, no-op consistency checks, unaborted proof failures, mis-attributed aborts) across ECDSA/EdDSA keygen, signing, and resharing, with adversarial verification of every candidate. Fixed a resharing-continuity authentication bypass (`SRC-2026-1155`) and a resharing Paillier/`NTilde` modulus-size gap, ported the upstream dual-committee resharing fix (`bnb-chain/tss-lib#128`) to EdDSA, corrected abort attribution in several paths, and added defense-in-depth guards. Released in v3.0.2. Documented in [Appendix C](./security/2026-02-24-tss-lib-full-audit.md#appendix-c-july-2026-resharing-continuity-and-protocol-logic-update) of the report below.

**Stratovera LLC (June 2026)** -- Follow-up boundary-validation audit, cross-referencing upstream advisories (`SRC-2026-573`, `SRC-2026-644`) against this fork and running a multi-agent review of adversarial input validation at every protocol message boundary. Fixed a remote denial-of-service (nil-pointer dereference on an off-curve point in EdDSA signing) and non-canonical EC point acceptance, plus six defense-in-depth / canonicality hardenings (`J1`–`J8`); no further exploitable vulnerability was found. Released in v3.0.1. Documented in [Appendix B](./security/2026-02-24-tss-lib-full-audit.md#appendix-b-june-2026-boundary-validation-update-and-remediation) of the report below.

**Stratovera LLC (February 2026)** -- Full-scope audit of the ECDSA/EdDSA threshold signature implementation, covering keygen, signing, resharing, and all supporting cryptographic primitives. Identified 13 findings (2 critical, 3 high, 5 medium, 3 low). All findings have been addressed. The full report is available at [`security/2026-02-24-tss-lib-full-audit.md`](./security/2026-02-24-tss-lib-full-audit.md).

**Kudelski Security (October 2019)** -- Review of the original bnb-chain/tss-lib. The report is available in the [upstream v1.0.0 release](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf).

## References

[1] R. Gennaro and S. Goldfeder, "Fast Multiparty Threshold ECDSA with Fast Trustless Setup," CCS 2018. https://eprint.iacr.org/2019/114.pdf

## License

[MIT](./LICENSE)

Copyright (c) 2026 Stratovera LLC and its contributors.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
