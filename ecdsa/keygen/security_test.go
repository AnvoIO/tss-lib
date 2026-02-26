// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/crypto/vss"
)

func TestClear_Keygen_ZerosSecretMaterial(t *testing.T) {
	td := &localTempData{}

	// Populate ui with known non-zero value
	td.ui = big.NewInt(999)

	// Populate shares with non-zero values
	td.shares = vss.Shares{
		{Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(111)},
		{Threshold: 1, ID: big.NewInt(2), Share: big.NewInt(222)},
		{Threshold: 1, ID: big.NewInt(3), Share: big.NewInt(333)},
	}

	td.Clear()

	assert.Equal(t, int64(0), td.ui.Int64(), "ui should be zeroed after Clear()")
	for i, s := range td.shares {
		assert.Equal(t, int64(0), s.Share.Int64(), "share[%d] should be zeroed after Clear()", i)
	}
}
