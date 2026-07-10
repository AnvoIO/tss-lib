// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParameterIdentitySnapshotsAreRaceSafe(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	expectedID := ids[0].Id
	expectedIndex := ids[0].Index
	expectedKey := append([]byte(nil), ids[0].Key...)

	ctx := NewPeerContext(ids)
	params, err := NewParameters(EC(), ctx, ids[0], len(ids), 1)
	require.NoError(t, err)

	// Constructor inputs are not retained by reference.
	ids[0].Id = "mutated-input"
	ids[0].Index = 999
	ids[0].Key[0] ^= 0xff

	ctxID := ctx.IDs()[0]
	require.Equal(t, expectedID, ctxID.Id)
	require.Equal(t, expectedIndex, ctxID.Index)
	require.Equal(t, expectedKey, ctxID.Key)

	paramID := params.PartyID()
	require.Equal(t, expectedID, paramID.Id)
	require.Equal(t, expectedIndex, paramID.Index)
	require.Equal(t, expectedKey, paramID.Key)

	// Accessors return independent deep copies.
	ctxID.Id = "mutated-output"
	ctxID.Index = 888
	ctxID.Key[0] ^= 0xff
	paramID.Id = "mutated-output"
	paramID.Index = 777
	paramID.Key[0] ^= 0xff

	require.Equal(t, expectedID, ctx.IDs()[0].Id)
	require.Equal(t, expectedIndex, ctx.IDs()[0].Index)
	require.Equal(t, expectedKey, ctx.IDs()[0].Key)
	require.Equal(t, expectedID, params.PartyID().Id)
	require.Equal(t, expectedIndex, params.PartyID().Index)
	require.Equal(t, expectedKey, params.PartyID().Key)

	// Concurrent callers may mutate their own snapshots without sharing state.
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				committee := params.Parties().IDs()
				committee[0].Id = "private"
				committee[0].Index = int(value)
				committee[0].Key[0] ^= value

				local := params.PartyID()
				local.Id = "private"
				local.Index = int(value)
				local.Key[0] ^= value
			}
		}(byte(i + 1))
	}
	wg.Wait()

	require.Equal(t, expectedID, params.PartyID().Id)
	require.Equal(t, expectedIndex, params.PartyID().Index)
	require.Equal(t, expectedKey, params.PartyID().Key)
}

func TestReSharingParametersFreezeNewCommittee(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(4)
	expectedID := newIDs[0].Id
	expectedIndex := newIDs[0].Index
	expectedKey := append([]byte(nil), newIDs[0].Key...)

	params, err := NewReSharingParameters(
		EC(),
		NewPeerContext(oldIDs),
		NewPeerContext(newIDs),
		oldIDs[0],
		len(oldIDs), 1,
		len(newIDs), 2,
	)
	require.NoError(t, err)

	newIDs[0].Id = "mutated-input"
	newIDs[0].Index = 999
	newIDs[0].Key[0] ^= 0xff

	snapshot := params.NewParties().IDs()
	require.Equal(t, expectedID, snapshot[0].Id)
	require.Equal(t, expectedIndex, snapshot[0].Index)
	require.Equal(t, expectedKey, snapshot[0].Key)

	snapshot[0].Id = "mutated-output"
	snapshot[0].Index = 888
	snapshot[0].Key[0] ^= 0xff

	require.Equal(t, expectedID, params.NewParties().IDs()[0].Id)
	require.Equal(t, expectedIndex, params.NewParties().IDs()[0].Index)
	require.Equal(t, expectedKey, params.NewParties().IDs()[0].Key)
}
