// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadToLengthBytesInPlacePadsAndZerosOriginal(t *testing.T) {
	src := []byte{0xAA, 0xBB}
	out := PadToLengthBytesInPlace(src, 4)

	assert.Equal(t, []byte{0x00, 0x00, 0xAA, 0xBB}, out)
	assert.Equal(t, []byte{0x00, 0x00}, src)
}

func TestPadToLengthBytesInPlaceNoOp(t *testing.T) {
	src := []byte{0x11, 0x22, 0x33}
	out := PadToLengthBytesInPlace(src, 3)

	assert.Equal(t, []byte{0x11, 0x22, 0x33}, out)
	assert.Equal(t, []byte{0x11, 0x22, 0x33}, src)
}

func TestPadToLengthBytesInPlaceNilSource(t *testing.T) {
	var src []byte
	out := PadToLengthBytesInPlace(src, 3)

	assert.Equal(t, []byte{0x00, 0x00, 0x00}, out)
	assert.Nil(t, src)
}

func TestNonEmptyMultiBytesBounded(t *testing.T) {
	assert.True(t, NonEmptyMultiBytesBounded([][]byte{{1}, {2, 3}}, 2, 2))
	assert.False(t, NonEmptyMultiBytesBounded([][]byte{{1}, {2, 3}}, 1, 2))
	assert.False(t, NonEmptyMultiBytesBounded([][]byte{{1}}, 2, 2))
	assert.False(t, NonEmptyMultiBytesBounded([][]byte{{}}, 2, 1))
	assert.False(t, NonEmptyMultiBytesBounded([][]byte{{1}}, 0, 1))
}
