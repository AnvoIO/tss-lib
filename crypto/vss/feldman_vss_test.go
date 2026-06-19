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

	"github.com/AnvoIO/tss-lib/v3/common"
	. "github.com/AnvoIO/tss-lib/v3/crypto/vss"
	"github.com/AnvoIO/tss-lib/v3/tss"
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
