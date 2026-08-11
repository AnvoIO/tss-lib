// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/ecdsa/keygen"
	resharing "github.com/AnvoIO/tss-lib/v3/ecdsa/resharing"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// TestStoreMessageRejectsCrossCommitteeReplacement is a regression test for the
// resharing-specific gap in the intra-session message-replacement guard.
//
// Resharing spans two independent, overlapping committee index spaces. A naive
// self-echo exemption of the form `fromPIdx == p.PartyID().Index` compares a
// single index against both spaces, so a new-committee party whose new index
// equals an old-committee peer's old index would mis-classify that peer as "self"
// (isDup=false) and silently accept a replacement of the peer's already-stored
// commitment. The guard instead detects self-echoes by sender IDENTITY (key).
//
// This test constructs exactly that index collision (new-index 0 vs old-index 0,
// distinct keys). Under an index-based exemption the conflicting second message
// would be accepted; under the identity-based exemption it is rejected.
func TestStoreMessageRejectsCrossCommitteeReplacement(t *testing.T) {
	a := assert.New(t)
	ec := tss.S256()

	// Two disjoint committees, both index-0-based, so a new-committee party and
	// an old-committee party can share the numeric index 0 with distinct keys.
	oldPIDs := tss.GenerateTestPartyIDs(testThreshold + 1)
	newPIDs := tss.GenerateTestPartyIDs(testThreshold + 1)
	oldCtx := tss.NewPeerContext(oldPIDs)
	newCtx := tss.NewPeerContext(newPIDs)

	// `p` is a NEW-committee-only party at new-index 0.
	self := newPIDs[0]
	params, perr := tss.NewReSharingParameters(ec, oldCtx, newCtx, self,
		len(oldPIDs), testThreshold, len(newPIDs), testThreshold)
	a.NoError(perr)
	p := resharing.NewLocalParty(params, keygen.NewLocalPartySaveData(len(newPIDs)), nil, nil).(*resharing.LocalParty)

	// The colliding peer is the OLD-committee party at old-index 0.
	oldPeer := oldPIDs[0]
	a.True(params.IsNewCommittee())
	a.False(params.IsOldCommittee())
	a.Equal(p.PartyID().Index, oldPeer.Index, "precondition: indices collide across committees")
	a.NotEqual(0, p.PartyID().KeyInt().Cmp(oldPeer.KeyInt()), "precondition: identities differ")

	pub := crypto.ScalarBaseMult(ec, big.NewInt(7))
	ssid := []byte("test-ssid")
	mkMsg := func(commitment int64) tss.ParsedMessage {
		// DGRound1Message is an old-committee-sourced broadcast; `from` is the old
		// peer whose old-index collides with this party's new-index.
		return resharing.NewDGRound1Message(newPIDs, oldPeer, pub, big.NewInt(commitment), ssid)
	}

	// 1. First DGRound1Message from the old peer is accepted.
	ok, err := p.StoreMessage(mkMsg(0xC0FFEE))
	a.True(ok)
	a.Nil(err)

	// 2. A DIFFERENT-content DGRound1Message from the SAME old peer is rejected.
	//    Under the index-based self exemption this was silently accepted because
	//    the old peer's index collided with this party's own index.
	ok, err = p.StoreMessage(mkMsg(0xBADBEEF))
	a.False(ok)
	a.NotNil(err)

	// 3. An identical re-send is still tolerated (idempotent at-least-once
	//    delivery must not be mistaken for adversarial replacement).
	dup := mkMsg(0xC0FFEE)
	ok, err = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(err)
	ok, err = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(err)
}
