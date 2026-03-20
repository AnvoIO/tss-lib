// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
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
