// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// Every proof in this package is built under the COUNTERPARTY's ring and
// verified by that same counterparty, so a ring that makes a correctly-computed
// proof unacceptable would otherwise be reported against the honest prover. The
// prover-side checks move that rejection to the party responsible for the ring.
func TestCounterpartyRingUsableRejectsDegenerateRings(t *testing.T) {
	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTilde, h1, h2, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	assert.True(t, counterpartyRingUsable(NTilde, h1, h2), "a well-formed ring must pass")
	assert.False(t, counterpartyRingUsable(nil, h1, h2), "nil NTilde")
	assert.False(t, counterpartyRingUsable(NTilde, h1, h1), "h1 == h2")
	assert.False(t, counterpartyRingUsable(NTilde, big.NewInt(1), h2), "h1 == 1 is not a canonical generator")
	// A prime modulus has known order, so it is not a usable unknown-order ring.
	prime := common.GetRandomPrimeInt(rand.Reader, 2048)
	assert.False(t, counterpartyRingUsable(prime, h1, h2), "prime NTilde")
}

func TestRingSideValuesUsableRejectsDegenerateValues(t *testing.T) {
	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTilde, h1, _, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	assert.True(t, ringSideValuesUsable(NTilde, h1), "a canonical unit must pass")
	assert.False(t, ringSideValuesUsable(NTilde, nil), "nil value")
	assert.False(t, ringSideValuesUsable(NTilde, big.NewInt(0)), "v == 0 is outside (0, NTilde)")
	assert.False(t, ringSideValuesUsable(NTilde, big.NewInt(1)), "v == 1 binds nothing")
	assert.False(t, ringSideValuesUsable(NTilde, new(big.Int).Set(NTilde)), "v == NTilde is outside (0, NTilde)")
	// A value that shares a factor with NTilde is not a unit in the ring.
	nonUnit := new(big.Int).Lsh(big.NewInt(1), 3) // 8: shares the factor 2 with the even 2*NTilde below
	assert.False(t, ringSideValuesUsable(new(big.Int).Lsh(NTilde, 1), nonUnit), "gcd(v, modulus) != 1")
}

// A degenerate ring makes an honest prover decline with ErrCounterpartyRingUnusable
// rather than emit a proof the counterparty's own verifier will reject.
func TestProveRangeAliceRejectsUnusableCounterpartyRing(t *testing.T) {
	q := tss.EC().Params().N
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)
	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTilde, h1, _, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	// h1 == h2 is a ring the counterparty's own verifier rejects; the honest
	// prover must decline with an error routable to the counterparty.
	_, err = ProveRangeAlice(Session, tss.EC(), pk, c, NTilde, h1, h1, m, r, rand.Reader)
	assert.True(t, errors.Is(err, ErrCounterpartyRingUnusable), "expected ErrCounterpartyRingUnusable, got %v", err)
}
