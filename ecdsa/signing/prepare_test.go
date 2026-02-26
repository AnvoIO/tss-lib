// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestPrepareForSigning_LenMismatch(t *testing.T) {
	ec := tss.S256()
	G := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	ks := []*big.Int{big.NewInt(1), big.NewInt(2)}
	bigXs := []*crypto.ECPoint{G} // length mismatch

	_, _, err := PrepareForSigning(ec, 0, 2, big.NewInt(42), ks, bigXs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "len(ks) != len(bigXs)")
}

func TestPrepareForSigning_LenNotPax(t *testing.T) {
	ec := tss.S256()
	G := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	ks := []*big.Int{big.NewInt(1), big.NewInt(2)}
	bigXs := []*crypto.ECPoint{G, G}

	_, _, err := PrepareForSigning(ec, 0, 3, big.NewInt(42), ks, bigXs) // pax=3 but len=2
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "len(ks) != pax")
}

func TestPrepareForSigning_IndexOutOfRange(t *testing.T) {
	ec := tss.S256()
	G := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	ks := []*big.Int{big.NewInt(1), big.NewInt(2)}
	bigXs := []*crypto.ECPoint{G, G}

	_, _, err := PrepareForSigning(ec, 2, 2, big.NewInt(42), ks, bigXs) // i=2 >= len(ks)=2
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "len(ks) <= i")
}

func TestPrepareForSigning_DuplicateIndices(t *testing.T) {
	ec := tss.S256()
	G := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	ks := []*big.Int{big.NewInt(5), big.NewInt(5)} // duplicate
	bigXs := []*crypto.ECPoint{G, G}

	_, _, err := PrepareForSigning(ec, 0, 2, big.NewInt(42), ks, bigXs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "index of two parties are equal")
}
