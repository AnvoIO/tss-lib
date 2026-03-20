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

	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestBuildLocalSaveDataSubsetMissingSignerDoesNotPanic(t *testing.T) {
	source := NewLocalPartySaveData(1)
	source.Ks[0] = big.NewInt(999) // does not match generated party id key

	ids := tss.GenerateTestPartyIDs(1)

	assert.NotPanics(t, func() {
		got := BuildLocalSaveDataSubset(source, ids)
		assert.Equal(t, source.Ks, got.Ks)
		assert.Equal(t, len(source.Ks), len(got.Ks))
	})
}
