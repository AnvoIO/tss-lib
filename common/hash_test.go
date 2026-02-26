// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/common"
)

func TestSHA512_256iValid(t *testing.T) {
	result := common.SHA512_256i(big.NewInt(42), big.NewInt(100))
	assert.NotNil(t, result)
	assert.True(t, result.Sign() > 0)
}

func TestSHA512_256iEmpty(t *testing.T) {
	result := common.SHA512_256i()
	assert.Nil(t, result, "SHA512_256i with no inputs should return nil")
}

func TestSHA512_256i_TAGGEDValid(t *testing.T) {
	tag := []byte("test-tag")
	result := common.SHA512_256i_TAGGED(tag, big.NewInt(1), big.NewInt(2))
	assert.NotNil(t, result)
	assert.True(t, result.Sign() > 0)
}

func TestSHA512_256i_TAGGEDEmpty(t *testing.T) {
	tag := []byte("test-tag")
	result := common.SHA512_256i_TAGGED(tag)
	assert.Nil(t, result, "SHA512_256i_TAGGED with no int inputs should return nil")
}
