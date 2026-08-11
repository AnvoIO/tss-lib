// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	. "github.com/AnvoIO/tss-lib/v4/crypto/vss"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs))
	}
}

// TestVerifyRejectsNonCanonicalShare is a regression test for the June 2026
// hardening (J8): a share scalar outside [0, q) must be rejected even though it
// is congruent mod q to the valid share (g^(s+q) == g^s would otherwise pass).
func TestVerifyRejectsNonCanonicalShare(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N

	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, q))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	// Canonical share verifies.
	assert.True(t, shares[0].Verify(tss.EC(), threshold, vs))

	// share + q is congruent mod q but non-canonical; must be rejected.
	inflated := &Share{Threshold: threshold, ID: shares[0].ID, Share: new(big.Int).Add(shares[0].Share, q)}
	assert.False(t, inflated.Verify(tss.EC(), threshold, vs), "non-canonical share (s+q) must be rejected")

	// A zero share is in the canonical range [0, q) yet makes ScalarBaseMult the
	// point at infinity; it must be rejected, not panic the verifier.
	zeroShare := &Share{Threshold: threshold, ID: shares[0].ID, Share: big.NewInt(0)}
	assert.NotPanics(t, func() {
		assert.False(t, zeroShare.Verify(tss.EC(), threshold, vs), "zero share must be rejected")
	})
}

// TestCreateRejectsMalformedInputs is a regression test for the VSS Create
// hardening (upstream 76fa474): nil ec / nil rand, and the num < threshold+1
// bound (a degree-`threshold` polynomial needs at least threshold+1 distinct
// shares; the old `num < threshold` admitted num == threshold).
func TestCreateRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := []*big.Int{
		common.GetRandomPositiveInt(rand.Reader, q),
		common.GetRandomPositiveInt(rand.Reader, q),
		common.GetRandomPositiveInt(rand.Reader, q),
	}

	t.Run("nil ec", func(tt *testing.T) {
		_, _, err := Create(nil, 1, secret, ids, rand.Reader)
		assert.Error(tt, err)
	})
	t.Run("nil rand", func(tt *testing.T) {
		_, _, err := Create(tss.EC(), 1, secret, ids, nil)
		assert.Error(tt, err)
	})
	t.Run("num == threshold (boundary)", func(tt *testing.T) {
		// 3 shares for a degree-3 polynomial: too few to reconstruct
		// (need >= threshold+1). Old `num < threshold` admitted this.
		_, _, err := Create(tss.EC(), 3, secret, ids, rand.Reader)
		assert.Error(tt, err)
		assert.Equal(tt, ErrNumSharesBelowThreshold, err)
	})
	t.Run("num == threshold+1 (minimum honest)", func(tt *testing.T) {
		_, _, err := Create(tss.EC(), 2, secret, ids, rand.Reader)
		assert.NoError(tt, err)
	})
}

// TestVerifyRejectsCurveMismatch is a regression test for the VSS Verify
// hardening (upstream 76fa474): the old code called vs[j].SetCurve(ec), which
// silently re-attached ec to whatever curve the caller had assigned. Verify now
// gates on tss.SameCurve(vs[j].Curve(), ec) and rejects a mismatched-curve
// commitment up-front instead of mutating the caller's ECPoint.
func TestVerifyRejectsCurveMismatch(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, q))
	}
	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	// Reassign vs[0] to a copy whose stored curve is Edwards rather than
	// secp256k1; coords are unchanged. The old SetCurve behavior would have
	// silently re-attached secp256k1 and proceeded; the SameCurve gate rejects.
	mismatched := crypto.NewECPointNoCurveCheck(tss.Edwards(), vs[0].X(), vs[0].Y())
	tampered := make(Vs, len(vs))
	copy(tampered, vs)
	tampered[0] = mismatched
	assert.False(t, shares[0].Verify(tss.EC(), threshold, tampered))
}

// TestReConstructRejectsMalformedInputs is a regression test for the VSS
// ReConstruct hardening (upstream 76fa474): nil ec, empty shares (a non-nil but
// empty slice previously panicked on shares[0]), nil share elements, mixed
// thresholds, and the k-vs-k+q mod-q ID collision. In our fork the collision is
// caught by common.ModInverseChecked (returns an error, no panic) rather than
// upstream's explicit sub.Sign() == 0 guard, so the collision subtest asserts
// on our "not invertible" error text.
func TestReConstructRejectsMalformedInputs(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, q))
	}
	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	t.Run("nil ec", func(tt *testing.T) {
		_, err := shares[:threshold+1].ReConstruct(nil)
		assert.Error(tt, err)
	})
	t.Run("empty shares", func(tt *testing.T) {
		_, err := Shares{}.ReConstruct(tss.EC())
		assert.Error(tt, err)
		assert.Equal(tt, ErrNumSharesBelowThreshold, err)
	})
	t.Run("nil share element", func(tt *testing.T) {
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = nil
		_, err := bad.ReConstruct(tss.EC())
		assert.Error(tt, err)
	})
	t.Run("mixed threshold", func(tt *testing.T) {
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = &Share{Threshold: threshold + 99, ID: shares[1].ID, Share: shares[1].Share}
		_, err := bad.ReConstruct(tss.EC())
		assert.Error(tt, err)
	})
	t.Run("mod-q ID collision (k vs k+q)", func(tt *testing.T) {
		// Forge a share whose raw ID = honest_id + q. The Lagrange code computes
		// (k+q) - k = q ≡ 0 mod q, so ModInverseChecked returns an error instead
		// of ModInverse(0) → nil → panic on the next Mul.
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = &Share{
			Threshold: shares[1].Threshold,
			ID:        new(big.Int).Add(shares[0].ID, q),
			Share:     shares[1].Share,
		}
		assert.NotPanics(tt, func() {
			_, err := bad.ReConstruct(tss.EC())
			assert.Error(tt, err)
			assert.Contains(tt, err.Error(), "not invertible")
		})
	})
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold+1].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)
	assert.Zero(t, secret.Cmp(secret3))

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	assert.Zero(t, secret.Cmp(secret4))
}

func TestReconstructDuplicateIDs(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	// Create a set with duplicate share IDs
	dupShares := Shares{shares[0], shares[1], shares[2], shares[0]} // shares[0] duplicated
	dupShares[0] = &Share{Threshold: threshold, ID: shares[0].ID, Share: shares[0].Share}
	_, err = dupShares.ReConstruct(tss.EC())
	assert.Error(t, err, "ReConstruct should fail with duplicate share IDs")
}
