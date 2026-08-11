// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package dlnproof_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/common"
	. "github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
)

var Session = []byte("session")

var (
	fixtureOnce  sync.Once
	fixtureH1    *big.Int
	fixtureH2    *big.Int
	fixtureN     *big.Int
	fixtureP     *big.Int
	fixtureQ     *big.Int
	fixtureAlpha *big.Int
	fixtureErr   error
)

// loadFixture lazily generates one set of safe-prime / h1 / h2 / alpha
// parameters and reuses them across subtests. Generating two 1024-bit safe
// primes via GetRandomSafePrimesConcurrent takes seconds; caching via sync.Once
// keeps the whole file's runtime modest.
func loadFixture(t *testing.T) {
	t.Helper()
	fixtureOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		sgps, err := common.GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU(), rand.Reader)
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureP, fixtureQ = sgps[0].Prime(), sgps[1].Prime()
		P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
		fixtureN = new(big.Int).Mul(P, Q)
		modN := common.ModInt(fixtureN)
		f1 := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, fixtureN)
		fixtureH1 = modN.Mul(f1, f1)
		fixtureAlpha = common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, fixtureN)
		fixtureH2 = modN.Exp(fixtureH1, fixtureAlpha)
	})
	assert.NoError(t, fixtureErr)
}

// TestVerify_NilElementsDoesNotPanic is a defense-in-depth regression test: a
// Proof whose Alpha/T arrays contain nil entries must be rejected by Verify
// rather than panicking on the nil dereference. Valid h1/h2/N are used so Verify
// reaches the per-iteration array scan where the nil handling lives.
func TestVerify_NilElementsDoesNotPanic(t *testing.T) {
	loadFixture(t)

	proof := &Proof{} // all Alpha[i]/T[i] are nil

	assert.NotPanics(t, func() {
		ok := proof.Verify(Session, fixtureH1, fixtureH2, fixtureN)
		assert.False(t, ok, "a proof with nil elements must not verify")
	})
}

func TestUnmarshalDLNProofRejectsOversizedElement(t *testing.T) {
	parts := make([][]byte, 2+(Iterations*2))
	for i := range parts {
		parts[i] = []byte{1}
	}
	parts[0] = big.NewInt(Iterations).Bytes()
	parts[Iterations+1] = big.NewInt(Iterations).Bytes()
	parts[1] = make([]byte, MaxProofElementBytes+1)

	proof, err := UnmarshalDLNProof(parts)
	assert.Nil(t, proof)
	assert.Error(t, err)
}

// TestDLNVerifyRejectsMalformedInputs asserts the group-membership invariants
// added to Verify: N must be a usable unknown-order modulus, and h1/h2/Alpha[i]
// must be canonical generators on their raw (unreduced) bytes.
func TestDLNVerifyRejectsMalformedInputs(test *testing.T) {
	loadFixture(test)
	h1, h2, N, p, q, alpha := fixtureH1, fixtureH2, fixtureN, fixtureP, fixtureQ, fixtureAlpha
	pf := NewDLNProof(Session, h1, h2, alpha, p, q, N, rand.Reader)
	assert.True(test, pf.Verify(Session, h1, h2, N), "sanity: honest proof must verify")

	test.Run("nil N", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h2, nil))
	})
	test.Run("prime N", func(tt *testing.T) {
		primeN := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, pf.Verify(Session, h1, h2, primeN))
	})
	test.Run("small N", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h2, big.NewInt(15)))
	})
	test.Run("h1 = 1", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, big.NewInt(1), h2, N))
	})
	test.Run("h1 = 0", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, big.NewInt(0), h2, N))
	})
	test.Run("h1 = N (non-canonical)", func(tt *testing.T) {
		// h1 mod N == 0 would have passed the earlier Mod-based check if the
		// reduction had landed in (1, N); the canonical-input requirement
		// rejects this on the raw value instead.
		assert.False(tt, pf.Verify(Session, new(big.Int).Set(N), h2, N))
	})
	test.Run("h1 + N (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(h1, N)
		assert.False(tt, pf.Verify(Session, nonCanonical, h2, N))
	})
	test.Run("h1 shares factor with N", func(tt *testing.T) {
		// p is a Germain prime; the safe prime 2p+1 divides N, so it is a
		// non-unit modulo N.
		nonUnit := new(big.Int).Lsh(p, 1)
		nonUnit.Add(nonUnit, big.NewInt(1))
		assert.False(tt, pf.Verify(Session, nonUnit, h2, N))
	})
	test.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h1, N))
	})
	_ = q
}
