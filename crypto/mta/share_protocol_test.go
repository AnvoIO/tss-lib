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
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	"github.com/AnvoIO/tss-lib/v4/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var Session = []byte("session")

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(rand.Reader, q)
	b := common.GetRandomPositiveInt(rand.Reader, q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(Session, tss.EC(), pk, a, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(Session, tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEnd(Session, tss.EC(), pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

// mtaBoundsInputs returns the two multiplicands: a belongs to the decrypting
// party, b to the counterparty constructing the ciphertext. Both are < q.
func mtaBoundsInputs(t *testing.T) (a, b *big.Int) {
	t.Helper()
	q := tss.EC().Params().N
	a = big.NewInt(0xC0FFEE)
	b, ok := new(big.Int).SetString("d1ce0ff1ce0fbadc0ffee0ddf00d1235", 16)
	assert.True(t, ok)
	assert.Equal(t, -1, a.Cmp(q))
	assert.Equal(t, -1, b.Cmp(q))
	return a, b
}

// buildCiphertextWithMask assembles cB = Enc(a*b - mask mod N) with the local
// witness set to -mask. Nothing negative is transmitted: the witness stays with
// the constructing party and cB is an ordinary ciphertext.
func buildCiphertextWithMask(t *testing.T, pk *paillier.PublicKey, a, b, mask *big.Int) (cA, cB, cRand, betaPrm *big.Int) {
	t.Helper()
	cA, _, err := pk.EncryptAndReturnRandomness(rand.Reader, a)
	assert.NoError(t, err)
	betaPrm = new(big.Int).Neg(mask)
	// Encrypt takes nonnegative plaintexts, so the positive representative is
	// encrypted; homomorphically the effect is the same.
	encPlain := new(big.Int).Mod(betaPrm, pk.N)
	cBetaPrm, r, err := pk.EncryptAndReturnRandomness(rand.Reader, encPlain)
	assert.NoError(t, err)
	cRand = r
	cB, err = pk.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = pk.HomoAdd(cB, cBetaPrm)
	assert.NoError(t, err)
	return cA, cB, cRand, betaPrm
}

// maskAboveProduct puts the mask strictly above a*b, so the decrypted plaintext
// leaves the range a conforming run produces.
func maskAboveProduct(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Add(a, big.NewInt(1)), b)
}

// maskBelowProduct puts the mask strictly below a*b, so the plaintext stays in
// range and the additive share is arithmetically correct.
func maskBelowProduct(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Sub(a, big.NewInt(1)), b)
}

// TestAliceEndWCRejectsOutOfRangePlaintext pins the [0, q^6) output bound in
// AliceEndWC: a mask above the product yields a decrypted plaintext far outside
// the conforming range, which must be rejected after decryption even though the
// proof itself verifies.
func TestAliceEndWCRejectsOutOfRangePlaintext(t *testing.T) {
	p := newMtaTestParty(t)
	ec := tss.EC()
	a, b := mtaBoundsInputs(t)
	B := crypto.ScalarBaseMult(ec, b)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p.pk, a, b, maskAboveProduct(a, b))
	pf, err := ProveBobWC(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)
	// Precondition: the range proof is not what stops this, so the output bound
	// is doing real work rather than shadowing an earlier check.
	assert.True(t, pf.Verify(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, B),
		"precondition: ProofBobWC.Verify accepts this transcript")

	alpha, err := AliceEndWC(Session, ec, p.pk, pf, B, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.Error(t, err, "an out-of-range plaintext must be rejected after decryption")
	assert.Nil(t, alpha, "no share may be returned for a rejected instance")
}

// TestAliceEndRejectsOutOfRangePlaintext covers the second call site (non-WC),
// reached independently of the with-check variant.
func TestAliceEndRejectsOutOfRangePlaintext(t *testing.T) {
	p := newMtaTestParty(t)
	ec := tss.EC()
	a, b := mtaBoundsInputs(t)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p.pk, a, b, maskAboveProduct(a, b))
	pf, err := ProveBob(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, pf.Verify(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB),
		"precondition: ProofBob.Verify accepts this transcript")

	alpha, err := AliceEnd(Session, ec, p.pk, pf, p.h1, p.h2, cA, cB, p.NTilde, p.sk)
	assert.Error(t, err, "the second call site must apply the same bound")
	assert.Nil(t, alpha)
}

// TestAliceEndWCAcceptsInRangePlaintext documents the scope of the bound: it
// rejects values outside the range and nothing else. A mask below the product
// leaves the plaintext in range and the MtA output correct, and must pass.
func TestAliceEndWCAcceptsInRangePlaintext(t *testing.T) {
	p := newMtaTestParty(t)
	ec := tss.EC()
	q := ec.Params().N
	a, b := mtaBoundsInputs(t)
	B := crypto.ScalarBaseMult(ec, b)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p.pk, a, b, maskBelowProduct(a, b))
	pf, err := ProveBobWC(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(Session, ec, p.pk, pf, B, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.NoError(t, err, "an in-range plaintext must not be rejected")

	// alpha + beta == a*b (mod q): the MtA output is correct here.
	beta := common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	lhs := common.ModInt(q).Add(alpha, beta)
	rhs := new(big.Int).Mod(new(big.Int).Mul(a, b), q)
	assert.Equal(t, 0, lhs.Cmp(rhs), "in-range: the additive share is arithmetically correct")
}

// TestAlphaPrmRangeBoundary pins the window. A conforming run produces
// alphaPrm = a*b + betaPrm < q^2 + q^5 < q^6, and the modulus is at least
// 2^2047, so the cut has wide margin on both sides.
func TestAlphaPrmRangeBoundary(t *testing.T) {
	q := tss.EC().Params().N
	q4 := new(big.Int).Exp(q, big.NewInt(4), nil)
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	q6 := new(big.Int).Exp(q, big.NewInt(6), nil)

	conformingCeiling := new(big.Int).Add(q4, q5) // strict upper bound in a conforming run

	for _, tc := range []struct {
		name  string
		v     *big.Int
		valid bool
	}{
		{"negative", big.NewInt(-1), false},
		{"zero", big.NewInt(0), true},
		{"small value", big.NewInt(1 << 20), true},
		{"conforming ceiling a*b+betaPrm", conformingCeiling, true},
		{"q^6 - 1", new(big.Int).Sub(q6, big.NewInt(1)), true},
		{"q^6 exactly", q6, false},
		{"value near the modulus", new(big.Int).Exp(big.NewInt(2), big.NewInt(2040), nil), false},
	} {
		assert.Equal(t, tc.valid, alphaPrmInRange(tc.v, q), tc.name)
	}
	assert.Equal(t, -1, conformingCeiling.Cmp(q6), "the conforming ceiling sits strictly below the cut")
}

func TestShareProtocolWC(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(rand.Reader, q)
	b := common.GetRandomPositiveInt(rand.Reader, q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(Session, tss.EC(), pk, a, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(Session, tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(Session, tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
