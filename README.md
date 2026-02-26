# tss-lib

[![MIT licensed][1]][2]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE

A Go implementation of multi-party {t,n}-threshold ECDSA and EdDSA signature schemes based on Gennaro and Goldfeder CCS 2018 [1]. Provides distributed key generation, signing, and dynamic group re-sharing with no trusted dealer.

Based on [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) with security hardening, constant-time arithmetic, and session-bound Fiat-Shamir challenges.

## Features

- **ECDSA threshold signatures** -- {t,n}-threshold signing on secp256k1 and other curves
- **EdDSA threshold signatures** -- Edwards-curve variant following the same approach
- **Distributed key generation** -- no trusted dealer, each party holds one secret share
- **Dynamic re-sharing** -- change the group of participants while preserving the key
- **Paillier, DLN, range, and factor proofs** -- with optional build-tag disable for testing (`-tags insecure_noproofs`)

## Requirements

- Go 1.20+
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
```

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

## How to use this securely

The transport layer is your responsibility. You must provide:

- **Broadcast and point-to-point channels** with end-to-end encryption (TLS with AEAD recommended)
- **Session IDs** unique to each protocol run, agreed upon out-of-band before rounds begin
- **Reliable broadcast** so all parties receive identical messages (hash-and-compare)
- **Timeouts and error handling** -- use `Party.WaitingFor()` and `*tss.Error` culprit info

## Breaking changes

### v2.0: Paillier preparams

`PaillierSK.P` and `PaillierSK.Q` fields were added. Key vaults from v1.x must be regenerated via re-sharing.

### v3.0: Security hardening

- Module path changed from `github.com/bnb-chain/tss-lib/v2` to `github.com/AnvoIO/tss-lib/v3`
- `tss.NewParameters()` and `tss.NewReSharingParameters()` now return `error`
- `PrepareForSigning()` (ECDSA/EdDSA) now returns `error`
- `SetNoProofMod()` / `SetNoProofFac()` blocked unless built with `-tags insecure_noproofs`

## Project structure

```
tss-lib/
  tss/              Core types: Party, Parameters, PartyID, message routing
  common/           Shared utilities, hash functions
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

**Stratovera LLC (February 2026)** -- Full-scope audit of the ECDSA/EdDSA threshold signature implementation, covering keygen, signing, resharing, and all supporting cryptographic primitives. Identified 13 findings (2 critical, 3 high, 5 medium, 3 low). All findings have been addressed. The full report is available at [`security/2026-02-24-tss-lib-full-audit.md`](./security/2026-02-24-tss-lib-full-audit.md).

**Kudelski Security (October 2019)** -- Review of the original bnb-chain/tss-lib. The report is available in the [upstream v1.0.0 release](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf).

## References

[1] R. Gennaro and S. Goldfeder, "Fast Multiparty Threshold ECDSA with Fast Trustless Setup," CCS 2018. https://eprint.iacr.org/2019/114.pdf

## License

[MIT](./LICENSE)

Copyright (c) 2026 Stratovera LLC and its contributors.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
