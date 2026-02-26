// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

//go:build !insecure_noproofs

package tss

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetNoProofBlockedInSecureBuild(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	params, err := NewParameters(EC(), ctx, ids[0], 3, 1)
	assert.NoError(t, err)
	assert.NotNil(t, params)

	params.SetNoProofMod()
	params.SetNoProofFac()

	assert.False(t, params.NoProofMod(), "NoProofMod must remain disabled in secure builds")
	assert.False(t, params.NoProofFac(), "NoProofFac must remain disabled in secure builds")
}
