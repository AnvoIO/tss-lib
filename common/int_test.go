// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModInverseCheckedValid(t *testing.T) {
	mod := ModInt(big.NewInt(17))
	result, err := mod.ModInverseChecked(big.NewInt(3))
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// 3 * 6 = 18 ≡ 1 (mod 17)
	assert.Equal(t, big.NewInt(6), result)
}

func TestModInverseCheckedZero(t *testing.T) {
	mod := ModInt(big.NewInt(17))
	result, err := mod.ModInverseChecked(big.NewInt(0))
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestModInverseCheckedNonInvertible(t *testing.T) {
	mod := ModInt(big.NewInt(6))
	// gcd(3, 6) = 3 ≠ 1, so 3 is not invertible mod 6
	result, err := mod.ModInverseChecked(big.NewInt(3))
	assert.Error(t, err)
	assert.Nil(t, result)
}
