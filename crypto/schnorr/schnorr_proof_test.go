// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	. "github.com/AnvoIO/tss-lib/v4/crypto/schnorr"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

var Session = []byte("session")

// TestZKProofValidateBasic_RejectsOffCurveAlpha is a defense-in-depth regression
// test: ZKProof.ValidateBasic must reject an Alpha that is nil or off-curve (as
// ZKVProof already does), so that Verify does not later dereference bad coords.
func TestZKProofValidateBasic_RejectsOffCurveAlpha(t *testing.T) {
	// valid proof passes
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	good, _ := NewZKProof(Session, u, uG, rand.Reader)
	assert.True(t, good.ValidateBasic(), "a well-formed proof must validate")

	// (1,1) is not on secp256k1; ValidateBasic must reject it
	offCurve := crypto.NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(1))
	bad := &ZKProof{Alpha: offCurve, T: big.NewInt(1)}
	assert.False(t, bad.ValidateBasic(), "off-curve Alpha must be rejected")

	// nil Alpha must also be rejected
	nilAlpha := &ZKProof{Alpha: nil, T: big.NewInt(1)}
	assert.False(t, nilAlpha.ValidateBasic(), "nil Alpha must be rejected")
}

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	proof, _ := NewZKProof(Session, u, uG, rand.Reader)

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(Session, u, X, rand.Reader)
	res := proof.Verify(Session, X)

	assert.True(t, res, "verify result must be true")
}

// TestSchnorrProofVerifyRejectsNonCanonicalT is a regression test for the
// June 2026 hardening (J8): a proof scalar T outside [0, q) must be rejected,
// even though it is congruent mod q to the canonical value.
func TestSchnorrProofVerifyRejectsNonCanonicalT(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(Session, u, X, rand.Reader)
	// Canonical proof verifies.
	assert.True(t, proof.Verify(Session, X))

	// T + q is congruent mod q but non-canonical; must be rejected.
	proof.T = new(big.Int).Add(proof.T, q)
	assert.False(t, proof.Verify(Session, X), "non-canonical T (T+q) must be rejected")

	// nil X must be rejected, not panic.
	assert.False(t, proof.Verify(Session, nil), "nil X must be rejected")
}

// TestSchnorrProofVerifyRejectsZeroScalar checks that a peer-supplied zero proof
// scalar (which is in the canonical range [0, q) yet drives ScalarBaseMult/ScalarMult
// to the point at infinity) is rejected rather than panicking an honest verifier.
func TestSchnorrProofVerifyRejectsZeroScalar(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	// ZKProof with T = 0.
	proof, _ := NewZKProof(Session, u, X, rand.Reader)
	proof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(Session, X), "T=0 must be rejected, not panic")
	})

	// ZKVProof with T = 0 and with U = 0.
	R := crypto.ScalarBaseMult(tss.EC(), common.GetRandomPositiveInt(rand.Reader, q))
	s, l := common.GetRandomPositiveInt(rand.Reader, q), common.GetRandomPositiveInt(rand.Reader, q)
	V, _ := R.ScalarMult(s).Add(crypto.ScalarBaseMult(tss.EC(), l))
	vproof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	origT := vproof.T
	vproof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, vproof.Verify(Session, V, R), "T=0 must be rejected, not panic")
	})
	vproof.T, vproof.U = origT, big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, vproof.Verify(Session, V, R), "U=0 must be rejected, not panic")
	})
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	u2 := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, _ := NewZKProof(Session, u2, X2, rand.Reader)
	res := proof.Verify(Session, X)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrVProofVerifyBadPartialV(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	V := Rs

	proof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerifyBadS(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	s2 := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(Session, V, R, s2, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.False(t, res, "verify result must be false")
}

// TestSchnorrProofCTMul verifies that the constant-time multiplication path
// (modQ.Mul) produces the same proof that verifies correctly. This exercises
// the code change from raw big.Int.Mul to modular CT mul.
func TestSchnorrProofCTMul(t *testing.T) {
	q := tss.EC().Params().N

	// Run multiple iterations to increase confidence in correctness
	for i := 0; i < 10; i++ {
		x := common.GetRandomPositiveInt(rand.Reader, q)
		X := crypto.ScalarBaseMult(tss.EC(), x)

		proof, err := NewZKProof(Session, x, X, rand.Reader)
		assert.NoError(t, err)
		assert.NotNil(t, proof)

		// Must verify with the correct public point
		res := proof.Verify(Session, X)
		assert.True(t, res, "proof must verify (iter %d)", i)

		// Must NOT verify with a different public point
		x2 := common.GetRandomPositiveInt(rand.Reader, q)
		X2 := crypto.ScalarBaseMult(tss.EC(), x2)
		res2 := proof.Verify(Session, X2)
		assert.False(t, res2, "proof must not verify with wrong X (iter %d)", i)

		// Must NOT verify with a different session
		res3 := proof.Verify([]byte("wrong-session"), X)
		assert.False(t, res3, "proof must not verify with wrong session (iter %d)", i)
	}
}

// TestSchnorrVProofCTMul verifies that the CT multiplication path in ZKVProof
// produces correct proofs.
func TestSchnorrVProofCTMul(t *testing.T) {
	q := tss.EC().Params().N

	for i := 0; i < 10; i++ {
		k := common.GetRandomPositiveInt(rand.Reader, q)
		s := common.GetRandomPositiveInt(rand.Reader, q)
		l := common.GetRandomPositiveInt(rand.Reader, q)
		R := crypto.ScalarBaseMult(tss.EC(), k)
		Rs := R.ScalarMult(s)
		lG := crypto.ScalarBaseMult(tss.EC(), l)
		V, err := Rs.Add(lG)
		assert.NoError(t, err)

		proof, err := NewZKVProof(Session, V, R, s, l, rand.Reader)
		assert.NoError(t, err)

		// Must verify
		res := proof.Verify(Session, V, R)
		assert.True(t, res, "proof must verify (iter %d)", i)

		// Wrong secret s2 must not verify
		s2 := common.GetRandomPositiveInt(rand.Reader, q)
		proofBad, _ := NewZKVProof(Session, V, R, s2, l, rand.Reader)
		res2 := proofBad.Verify(Session, V, R)
		assert.False(t, res2, "proof with wrong s must not verify (iter %d)", i)

		// Wrong secret l2 must not verify
		l2 := common.GetRandomPositiveInt(rand.Reader, q)
		proofBad2, _ := NewZKVProof(Session, V, R, s, l2, rand.Reader)
		res3 := proofBad2.Verify(Session, V, R)
		assert.False(t, res3, "proof with wrong l must not verify (iter %d)", i)

		// Wrong session must not verify
		res4 := proof.Verify([]byte("wrong-session"), V, R)
		assert.False(t, res4, "proof must not verify with wrong session (iter %d)", i)
	}
}
