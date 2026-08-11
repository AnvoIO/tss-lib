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

	"github.com/AnvoIO/tss-lib/v4/tss"
)

// TestBuildLocalSaveDataSubsetDeepCopiesLocalSecrets pins the load-bearing deep
// copy: the subset's secret Xi/ShareID must be distinct objects from the
// caller's, because resharing round 5 zeroes round.input.Xi on the old-committee
// path. A struct assignment would share the pointers and silently destroy the
// caller's share — a regression the rest of the suite cannot see, since it never
// inspects the caller's copy after a run.
func TestBuildLocalSaveDataSubsetDeepCopiesLocalSecrets(t *testing.T) {
	keys, pids, err := LoadKeygenTestFixtures(1)
	assert.NoError(t, err, "should load keygen fixtures")

	source := keys[0]
	source.Xi = big.NewInt(0xC0FFEE)
	source.ShareID = big.NewInt(0xBEEF)
	xiBefore := new(big.Int).Set(source.Xi)
	shareIDBefore := new(big.Int).Set(source.ShareID)

	subset := BuildLocalSaveDataSubset(source, pids)
	if assert.NotNil(t, subset.Xi) && assert.NotNil(t, subset.ShareID) {
		// resharing round 5, old-committee path
		subset.Xi.SetInt64(0)
		subset.ShareID.SetInt64(0)
	}
	assert.Zero(t, xiBefore.Cmp(source.Xi),
		"caller's Xi must survive the subset being zeroed (deep copy)")
	assert.Zero(t, shareIDBefore.Cmp(source.ShareID),
		"caller's ShareID must survive the subset being zeroed (deep copy)")
}

func TestBuildLocalSaveDataSubsetMissingSignerDoesNotPanic(t *testing.T) {
	source := NewLocalPartySaveData(1)
	source.Ks[0] = big.NewInt(999) // does not match generated party id key
	source.Xi = big.NewInt(0xC0FFEE)
	source.ShareID = big.NewInt(0xBEEF)

	ids := tss.GenerateTestPartyIDs(1)

	assert.NotPanics(t, func() {
		got := BuildLocalSaveDataSubset(source, ids)
		assert.Equal(t, source.Ks, got.Ks)
		assert.Equal(t, len(source.Ks), len(got.Ks))
		got.Xi.SetInt64(0)
		got.ShareID.SetInt64(0)
		assert.Equal(t, int64(0xC0FFEE), source.Xi.Int64(),
			"missing-signer fallback must not alias Xi")
		assert.Equal(t, int64(0xBEEF), source.ShareID.Int64(),
			"missing-signer fallback must not alias ShareID")
	})
}
