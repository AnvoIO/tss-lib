// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewParametersValid(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	params, err := NewParameters(EC(), ctx, ids[0], 3, 1)
	assert.NoError(t, err)
	assert.NotNil(t, params)
}

func TestNewParametersInvalidThreshold(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)

	// threshold = 0
	_, err := NewParameters(EC(), ctx, ids[0], 3, 0)
	assert.Error(t, err)

	// threshold >= partyCount
	_, err = NewParameters(EC(), ctx, ids[0], 3, 3)
	assert.Error(t, err)

	// threshold > partyCount
	_, err = NewParameters(EC(), ctx, ids[0], 3, 5)
	assert.Error(t, err)
}

func TestNewParametersInvalidPartyCount(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)

	// partyCount < 2
	_, err := NewParameters(EC(), ctx, ids[0], 1, 1)
	assert.Error(t, err)
}

func TestNewParametersNilInputs(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)

	// nil curve
	_, err := NewParameters(nil, ctx, ids[0], 3, 1)
	assert.Error(t, err)

	// nil context
	_, err = NewParameters(EC(), nil, ids[0], 3, 1)
	assert.Error(t, err)

	// nil partyID
	_, err = NewParameters(EC(), ctx, nil, 3, 1)
	assert.Error(t, err)
}

func TestNewReSharingParametersValid(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(4)
	oldCtx := NewPeerContext(oldIDs)
	newCtx := NewPeerContext(newIDs)
	params, err := NewReSharingParameters(EC(), oldCtx, newCtx, oldIDs[0], 3, 1, 4, 2)
	assert.NoError(t, err)
	assert.NotNil(t, params)
}

func TestNewReSharingParametersInvalid(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(4)
	oldCtx := NewPeerContext(oldIDs)
	newCtx := NewPeerContext(newIDs)

	// newThreshold >= newPartyCount
	_, err := NewReSharingParameters(EC(), oldCtx, newCtx, oldIDs[0], 3, 1, 4, 4)
	assert.Error(t, err)

	// newThreshold = 0
	_, err = NewReSharingParameters(EC(), oldCtx, newCtx, oldIDs[0], 3, 1, 4, 0)
	assert.Error(t, err)

	// newPartyCount = 0
	_, err = NewReSharingParameters(EC(), oldCtx, newCtx, oldIDs[0], 3, 1, 0, 1)
	assert.Error(t, err)

	// nil new context
	_, err = NewReSharingParameters(EC(), oldCtx, nil, oldIDs[0], 3, 1, 4, 2)
	assert.Error(t, err)
}

func TestNewParameters_ThresholdBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		partyCount int
		threshold  int
		wantErr    bool
	}{
		{"threshold=1, partyCount=2 (minimum valid)", 2, 1, false},
		{"threshold=4, partyCount=5 (n-1)", 5, 4, false},
		{"threshold=0 (too low)", 5, 0, true},
		{"threshold=partyCount (equal)", 5, 5, true},
		{"threshold>partyCount", 5, 6, true},
		{"partyCount=1 (too low)", 1, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := GenerateTestPartyIDs(tt.partyCount)
			ctx := NewPeerContext(ids)
			params, err := NewParameters(EC(), ctx, ids[0], tt.partyCount, tt.threshold)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, params)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, params)
			}
		})
	}
}

func TestSetConcurrencyClampsToMinimum(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	params, err := NewParameters(EC(), ctx, ids[0], 3, 1)
	assert.NoError(t, err)
	assert.NotNil(t, params)

	params.SetConcurrency(0)
	assert.Equal(t, 1, params.Concurrency())

	params.SetConcurrency(-5)
	assert.Equal(t, 1, params.Concurrency())

	params.SetConcurrency(4)
	assert.Equal(t, 4, params.Concurrency())
}

func TestSessionNonceMustBePositiveAndIsCopied(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	params, err := NewParameters(EC(), NewPeerContext(ids), ids[0], 3, 1)
	assert.NoError(t, err)

	assert.Error(t, params.ValidateSessionNonce())
	params.SetSessionNonce(big.NewInt(0))
	assert.Error(t, params.ValidateSessionNonce())
	params.SetSessionNonce(big.NewInt(-1))
	assert.Error(t, params.ValidateSessionNonce())

	nonce := big.NewInt(7)
	params.SetSessionNonce(nonce)
	assert.NoError(t, params.ValidateSessionNonce())
	nonce.SetInt64(99)
	assert.Equal(t, int64(7), params.SessionNonce().Int64())

	returned := params.SessionNonce()
	returned.SetInt64(42)
	assert.Equal(t, int64(7), params.SessionNonce().Int64())
}

func TestNewParametersRejectsInvalidPeerContexts(t *testing.T) {
	ids := GenerateTestPartyIDs(3)

	_, err := NewParameters(EC(), NewPeerContext(ids[:2]), ids[0], 3, 1)
	assert.ErrorContains(t, err, "expected 3")

	duplicate := SortedPartyIDs{
		NewPartyID("p1", "p1", big.NewInt(1)),
		NewPartyID("p2", "p2", big.NewInt(1)),
		NewPartyID("p3", "p3", big.NewInt(3)),
	}
	for i := range duplicate {
		duplicate[i].Index = i
	}
	_, err = NewParameters(EC(), NewPeerContext(duplicate), duplicate[0], 3, 1)
	assert.ErrorContains(t, err, "duplicate party keys")

	notMember := NewPartyID("outsider", "outsider", big.NewInt(999))
	_, err = NewParameters(EC(), NewPeerContext(ids), notMember, 3, 1)
	assert.ErrorContains(t, err, "not a member")

	wrongIndex := &PartyID{
		MessageWrapper_PartyID: ids[0].MessageWrapper_PartyID,
		Index:                  999,
	}
	_, err = NewParameters(EC(), NewPeerContext(ids), wrongIndex, 3, 1)
	assert.ErrorContains(t, err, "does not match committee position")
}

func TestNewParametersRejectsPartyKeysInvalidModuloCurveOrder(t *testing.T) {
	q := EC().Params().N
	zeroModuloQ := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("p1", "p1", big.NewInt(1)),
		NewPartyID("p2", "p2", new(big.Int).Set(q)),
	})
	_, err := NewParameters(EC(), NewPeerContext(zeroModuloQ), zeroModuloQ[0], 2, 1)
	assert.ErrorContains(t, err, "zero modulo the curve order")

	collidingModuloQ := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("p1", "p1", big.NewInt(1)),
		NewPartyID("p2", "p2", new(big.Int).Add(q, big.NewInt(1))),
	})
	_, err = NewParameters(EC(), NewPeerContext(collidingModuloQ), collidingModuloQ[0], 2, 1)
	assert.ErrorContains(t, err, "collide modulo the curve order")
}

func TestReSharingParametersUseCommitteeLocalIndexes(t *testing.T) {
	oldIDs := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("old-1", "old-1", big.NewInt(1)),
		NewPartyID("both", "both", big.NewInt(2)),
		NewPartyID("old-3", "old-3", big.NewInt(3)),
	})
	newIDs := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("both", "both", big.NewInt(2)),
		NewPartyID("new-4", "new-4", big.NewInt(4)),
		NewPartyID("new-5", "new-5", big.NewInt(5)),
		NewPartyID("new-6", "new-6", big.NewInt(6)),
	})

	params, err := NewReSharingParameters(
		EC(),
		NewPeerContext(oldIDs),
		NewPeerContext(newIDs),
		oldIDs[1],
		len(oldIDs), 1,
		len(newIDs), 2,
	)
	assert.NoError(t, err)

	oldIndex, ok := params.OldPartyIndex()
	assert.True(t, ok)
	assert.Equal(t, 1, oldIndex)
	newIndex, ok := params.NewPartyIndex()
	assert.True(t, ok)
	assert.Equal(t, 0, newIndex)
}
