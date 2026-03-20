// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestNewLocalPartyInvalidOptionalPreParamsDoesNotPanic(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(3)
	ctx := tss.NewPeerContext(ids)
	params, err := tss.NewParameters(tss.S256(), ctx, ids[0], len(ids), 1)
	assert.NoError(t, err)

	out := make(chan tss.Message, 1)
	end := make(chan *LocalPartySaveData, 1)

	assert.NotPanics(t, func() {
		_ = NewLocalParty(params, out, end, LocalPreParams{})
	})
}

func TestNewLocalPartyTooManyOptionalPreParamsDoesNotPanic(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(3)
	ctx := tss.NewPeerContext(ids)
	params, err := tss.NewParameters(tss.S256(), ctx, ids[0], len(ids), 1)
	assert.NoError(t, err)

	out := make(chan tss.Message, 1)
	end := make(chan *LocalPartySaveData, 1)

	assert.NotPanics(t, func() {
		_ = NewLocalParty(params, out, end, LocalPreParams{}, LocalPreParams{})
	})
}
