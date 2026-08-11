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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(Session, tss.EC(), pk, c, NTildei, h1i, h2i, m, r, rand.Reader)
	assert.NoError(t, err)

	ok := proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}

func TestProveRangeAliceBypassed(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk0, pk0, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m0 := common.GetRandomPositiveInt(rand.Reader, q)
	c0, r0, err := sk0.EncryptAndReturnRandomness(rand.Reader, m0)
	assert.NoError(t, err)

	primes0 := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	Ntildei0, h1i0, h2i0, err := crypto.GenerateNTildei(rand.Reader, primes0)
	assert.NoError(t, err)
	proof0, err := ProveRangeAlice(Session, tss.EC(), pk0, c0, Ntildei0, h1i0, h2i0, m0, r0, rand.Reader)
	assert.NoError(t, err)

	ok0 := proof0.Verify(Session, tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.True(t, ok0, "proof must verify")

	// proof 2
	sk1, pk1, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m1 := common.GetRandomPositiveInt(rand.Reader, q)
	c1, r1, err := sk1.EncryptAndReturnRandomness(rand.Reader, m1)
	assert.NoError(t, err)

	primes1 := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	Ntildei1, h1i1, h2i1, err := crypto.GenerateNTildei(rand.Reader, primes1)
	assert.NoError(t, err)
	proof1, err := ProveRangeAlice(Session, tss.EC(), pk1, c1, Ntildei1, h1i1, h2i1, m1, r1, rand.Reader)
	assert.NoError(t, err)

	ok1 := proof1.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.True(t, ok1, "proof must verify")

	cross0 := proof0.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.False(t, cross0, "proof must not verify")

	cross1 := proof1.Verify(Session, tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.False(t, cross1, "proof must not verify")

	fmt.Println("Did verify proof 0 with data from 0?", ok0)
	fmt.Println("Did verify proof 1 with data from 1?", ok1)

	fmt.Println("Did verify proof 0 with data from 1?", cross0)
	fmt.Println("Did verify proof 1 with data from 0?", cross1)

	// new bypass
	bypassedproofNew := &RangeProofAlice{
		S:  big.NewInt(1),
		S1: big.NewInt(0),
		S2: big.NewInt(0),
		Z:  big.NewInt(1),
		U:  big.NewInt(1),
		W:  big.NewInt(1),
	}

	cBogus := big.NewInt(1)
	proofBogus, _ := ProveRangeAlice(Session, tss.EC(), pk1, cBogus, Ntildei1, h1i1, h2i1, m1, r1, rand.Reader)

	ok2 := proofBogus.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)
	bypassresult3 := bypassedproofNew.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)

	// c = 1 is not valid, even though we can find a range proof for it that passes!
	// this also means that the homo mul and add needs to be checked with this!
	fmt.Println("Did verify proof bogus with data from bogus?", ok2)
	fmt.Println("Did we bypass proof 3?", bypassresult3)
}

// TestVerifyRejectsCNotCoprime verifies that Verify rejects ciphertexts
// where gcd(c, N) != 1, which would cause a nil-pointer panic in c^(-e).
func TestVerifyRejectsCNotCoprime(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	// Create a valid proof with the real ciphertext
	proof, err := ProveRangeAlice(Session, tss.EC(), pk, c, NTildei, h1i, h2i, m, r, rand.Reader)
	assert.NoError(t, err)

	// Verify with c = 0 (gcd(0, N) = N != 1)
	ok := proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, big.NewInt(0))
	assert.False(t, ok, "verify must reject c = 0")

	// Verify with c = N (gcd(N, N) = N != 1)
	ok = proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, pk.N)
	assert.False(t, ok, "verify must reject c = N")

	// Verify with c = 2*N (gcd(2N, N) = N != 1)
	twoN := new(big.Int).Mul(big.NewInt(2), pk.N)
	ok = proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, twoN)
	assert.False(t, ok, "verify must reject c that is a multiple of N")

	// Verify with c = P (a factor of N, gcd(P, N) = P != 1) — adversarial
	// We can't extract P from the public key, but we can use N itself as c.
	// Also test with a known-bad value that shares a factor.
	ok = proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, new(big.Int).Set(pk.N))
	assert.False(t, ok, "verify must reject c = N (shares factor)")
}

// TestVerifyRejectsCNilPanic ensures no panic occurs with adversarial c values
// that would previously cause nil pointer dereference in big.Int.Exp.
func TestVerifyRejectsCNilPanic(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	proof, err := ProveRangeAlice(Session, tss.EC(), pk, c, NTildei, h1i, h2i, m, r, rand.Reader)
	assert.NoError(t, err)

	// These should NOT panic — the GCD check catches them before the Exp call
	assert.NotPanics(t, func() {
		proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, big.NewInt(0))
	}, "must not panic on c = 0")

	assert.NotPanics(t, func() {
		proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, pk.N)
	}, "must not panic on c = N")

	assert.NotPanics(t, func() {
		proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, pk.NSquare())
	}, "must not panic on c = N^2")
}

// mtaTestParty bundles a Paillier keypair and a valid NTilde/h1/h2 triple for
// building honest MtA transcripts to tamper with.
type mtaTestParty struct {
	sk             *paillier.PrivateKey
	pk             *paillier.PublicKey
	NTilde, h1, h2 *big.Int
}

func newMtaTestParty(t *testing.T) *mtaTestParty {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
	primes := [2]*big.Int{
		common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits),
		common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits),
	}
	NTilde, h1, h2, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)
	return &mtaTestParty{sk: sk, pk: pk, NTilde: NTilde, h1: h1, h2: h2}
}

// buildBobTranscript constructs cA = Enc(a), cB = cA^b * Enc(betaPrm) and the
// Bob witness (b, betaPrm, cRand) for a conforming run.
func buildBobTranscript(t *testing.T, p *mtaTestParty) (cA, cB, b, betaPrm, cRand *big.Int) {
	t.Helper()
	q := tss.EC().Params().N
	a := common.GetRandomPositiveInt(rand.Reader, q)
	b = common.GetRandomPositiveInt(rand.Reader, q)
	cA, _, err := p.pk.EncryptAndReturnRandomness(rand.Reader, a)
	assert.NoError(t, err)
	q5 := new(big.Int).Mul(q, q)
	q5 = new(big.Int).Mul(q5, q5)
	q5 = new(big.Int).Mul(q5, q)
	betaPrm = common.GetRandomPositiveInt(rand.Reader, q5)
	cBetaPrm, r, err := p.pk.EncryptAndReturnRandomness(rand.Reader, betaPrm)
	assert.NoError(t, err)
	cRand = r
	cB, err = p.pk.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = p.pk.HomoAdd(cB, cBetaPrm)
	assert.NoError(t, err)
	return cA, cB, b, betaPrm, cRand
}

// TestRangeProofAliceRejectsOversizedS2 pins the CPU-amplification DoS bound
// S2 < 2*q^3*NTilde added to RangeProofAlice.Verify. Uses real moduli so the
// rejection comes from the S2 bound, not the modulus/canonical-input checks.
func TestRangeProofAliceRejectsOversizedS2(t *testing.T) {
	q := tss.EC().Params().N
	p := newMtaTestParty(t)
	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := p.pk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(Session, tss.EC(), p.pk, c, p.NTilde, p.h1, p.h2, m, r, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, c), "sanity: honest proof must verify")

	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	upperS2 := new(big.Int).Mul(q3, p.NTilde)
	upperS2.Lsh(upperS2, 1)

	tampered := *proof
	tampered.S2 = upperS2 // exactly the boundary 2*q^3*NTilde, rejected by the >= check
	assert.False(t, tampered.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, c),
		"proof with oversized S2 must be rejected before exponentiation")
}

// TestProofBobRejectsOversizedS2T2 pins the same DoS bound S2,T2 < 2*q^3*NTilde
// added to ProofBobWC.Verify (reached here via the non-WC ProofBob.Verify path).
func TestProofBobRejectsOversizedS2T2(t *testing.T) {
	q := tss.EC().Params().N
	p := newMtaTestParty(t)
	cA, cB, b, betaPrm, cRand := buildBobTranscript(t, p)
	proof, err := ProveBob(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB), "sanity: honest proof must verify")

	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	upperS2T2 := new(big.Int).Mul(q3, p.NTilde)
	upperS2T2.Lsh(upperS2T2, 1)

	t.Run("oversized S2", func(tt *testing.T) {
		bad := *proof
		bad.S2 = upperS2T2
		assert.False(tt, bad.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB))
	})
	t.Run("oversized T2", func(tt *testing.T) {
		bad := *proof
		bad.T2 = upperS2T2
		assert.False(tt, bad.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB))
	})
}

// TestRangeProofAliceVerifyRejectsMalformedInputs covers the public-input
// validation (usable moduli, canonical generators, canonical ciphertext) and
// the gcd(S, N) unit check added to RangeProofAlice.Verify.
func TestRangeProofAliceVerifyRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N
	p := newMtaTestParty(t)
	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := p.sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(Session, tss.EC(), p.pk, c, p.NTilde, p.h1, p.h2, m, r, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, c), "sanity: honest proof must verify")

	t.Run("prime pk.N", func(tt *testing.T) {
		primePk := &paillier.PublicKey{N: common.GetRandomPrimeInt(rand.Reader, 2048)}
		assert.False(tt, proof.Verify(Session, tss.EC(), primePk, p.NTilde, p.h1, p.h2, c))
	})
	t.Run("prime NTilde", func(tt *testing.T) {
		primeNTilde := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, primeNTilde, p.h1, p.h2, c))
	})
	t.Run("small NTilde", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, big.NewInt(101), p.h1, p.h2, c))
	})
	t.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h1, c))
	})
	t.Run("h1 == 1", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, big.NewInt(1), p.h2, c))
	})
	t.Run("c == 0", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, big.NewInt(0)))
	})
	t.Run("c >= N^2 (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(p.pk.NSquare(), c)
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, nonCanonical))
	})
	t.Run("S shares factor with pk.N", func(tt *testing.T) {
		bad := *proof
		// sk.P is a prime factor of pk.N, so gcd(sk.P, pk.N) = sk.P > 1 while
		// sk.P < pk.N keeps IsInInterval(S, pk.N) satisfied.
		bad.S = new(big.Int).Set(p.sk.P)
		assert.False(tt, bad.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, c))
	})
}

// TestProofBobWCVerifyRejectsMalformedInputs covers the same public-input
// validation on the with-check verifier.
func TestProofBobWCVerifyRejectsMalformedInputs(t *testing.T) {
	p := newMtaTestParty(t)
	cA, cB, b, betaPrm, cRand := buildBobTranscript(t, p)
	B := crypto.ScalarBaseMult(tss.EC(), b)
	proof, err := ProveBobWC(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, cA, cB, B), "sanity: honest WC proof must verify")

	c1, c2, X := cA, cB, B

	t.Run("prime pk.N", func(tt *testing.T) {
		primePk := &paillier.PublicKey{N: common.GetRandomPrimeInt(rand.Reader, 2048)}
		assert.False(tt, proof.Verify(Session, tss.EC(), primePk, p.NTilde, p.h1, p.h2, c1, c2, X))
	})
	t.Run("prime NTilde", func(tt *testing.T) {
		primeNTilde := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, primeNTilde, p.h1, p.h2, c1, c2, X))
	})
	t.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h1, c1, c2, X))
	})
	t.Run("c1 == 0", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, big.NewInt(0), c2, X))
	})
	t.Run("c2 >= N^2 (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(p.pk.NSquare(), c2)
		assert.False(tt, proof.Verify(Session, tss.EC(), p.pk, p.NTilde, p.h1, p.h2, c1, nonCanonical, X))
	})
}
