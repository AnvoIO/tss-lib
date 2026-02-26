// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/common"
)

type failReader struct{}

func (f failReader) Read([]byte) (int, error) { return 0, errors.New("mock random failure") }

var _ io.Reader = failReader{}

const (
	randomIntBitLen = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rand.Reader, rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(rand.Reader, randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}

func TestGetRandomPositiveIntNilLessThan(t *testing.T) {
	result := common.GetRandomPositiveInt(rand.Reader, nil)
	assert.Nil(t, result, "nil lessThan should return nil")
}

func TestGetRandomPositiveIntZeroLessThan(t *testing.T) {
	result := common.GetRandomPositiveInt(rand.Reader, big.NewInt(0))
	assert.Nil(t, result, "zero lessThan should return nil")
}

func TestGetRandomQuadraticNonResidueNilInput(t *testing.T) {
	// With nil input, GetRandomPositiveInt returns nil, and so should GetRandomQuadraticNonResidue
	result := common.GetRandomQuadraticNonResidue(rand.Reader, nil)
	assert.Nil(t, result, "nil input should return nil")
}

func TestMustGetRandomInt_PanicsOnReaderFailure(t *testing.T) {
	assert.Panics(t, func() {
		common.MustGetRandomInt(failReader{}, 256)
	})
}

func TestMustGetRandomInt_PanicsOnZeroBits(t *testing.T) {
	assert.Panics(t, func() {
		common.MustGetRandomInt(rand.Reader, 0)
	})
}

func TestMustGetRandomInt_PanicsOnNegativeBits(t *testing.T) {
	assert.Panics(t, func() {
		common.MustGetRandomInt(rand.Reader, -1)
	})
}

func TestMustGetRandomInt_PanicsOnExcessiveBits(t *testing.T) {
	assert.Panics(t, func() {
		common.MustGetRandomInt(rand.Reader, 5001)
	})
}

func TestGetRandomBytes_InvalidLength(t *testing.T) {
	_, err := common.GetRandomBytes(rand.Reader, 0)
	assert.Error(t, err)

	_, err = common.GetRandomBytes(rand.Reader, -1)
	assert.Error(t, err)
}

func TestGetRandomBytes_ReaderFailure(t *testing.T) {
	_, err := common.GetRandomBytes(failReader{}, 32)
	assert.Error(t, err)
}

func TestIsNumberInMultiplicativeGroup_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		n, v *big.Int
		want bool
	}{
		{"nil n", nil, big.NewInt(2), false},
		{"nil v", big.NewInt(10), nil, false},
		{"both nil", nil, nil, false},
		{"v >= n", big.NewInt(5), big.NewInt(5), false},
		{"v > n", big.NewInt(5), big.NewInt(10), false},
		{"v == 0", big.NewInt(10), big.NewInt(0), false},
		{"n == 0", big.NewInt(0), big.NewInt(1), false},
		{"n negative", big.NewInt(-5), big.NewInt(2), false},
		{"GCD != 1 (v=4, n=8)", big.NewInt(8), big.NewInt(4), false},
		{"valid (v=3, n=10)", big.NewInt(10), big.NewInt(3), true},
		{"v == 1", big.NewInt(10), big.NewInt(1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, common.IsNumberInMultiplicativeGroup(tt.n, tt.v))
		})
	}
}
