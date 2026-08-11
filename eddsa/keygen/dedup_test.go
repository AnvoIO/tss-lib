// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// TestStoreMessageRejectsIntraSessionReplacement is a regression test for the
// intra-session message-replacement guard added to every StoreMessage driver.
//
// The security property: once a peer's slot for a round is filled, a SECOND
// message with DIFFERENT content from that peer must be rejected; an idempotent
// identical re-send (at-least-once transport) must still be accepted. keygen is a
// single-committee protocol, so the party's own self-echo is exempted by
// committee index, which NewParameters pins to the sender's key-derived position.
func TestStoreMessageRejectsIntraSessionReplacement(t *testing.T) {
	a := assert.New(t)

	pIDs := tss.GenerateTestPartyIDs(3)
	ctx := tss.NewPeerContext(pIDs)
	self, peer := pIDs[0], pIDs[1]

	params, err := tss.NewParameters(tss.Edwards(), ctx, self, len(pIDs), 1)
	a.NoError(err)

	p := keygen.NewLocalParty(params, nil, nil).(*keygen.LocalParty)
	a.NotEqual(self.Index, peer.Index, "precondition: peer is not self")

	mkMsg := func(commitment int64) tss.ParsedMessage {
		return keygen.NewKGRound1Message(peer, big.NewInt(commitment))
	}

	// 1. First round-1 message from the peer is accepted into its empty slot.
	ok, serr := p.StoreMessage(mkMsg(0xC0FFEE))
	a.True(ok)
	a.Nil(serr)

	// 2. A DIFFERENT-content round-1 message from the SAME peer is rejected
	//    (intra-session replacement) instead of silently overwriting.
	ok, serr = p.StoreMessage(mkMsg(0xBADBEEF))
	a.False(ok)
	a.NotNil(serr)

	// 3. An identical re-send is still tolerated (idempotent delivery must not be
	//    mistaken for adversarial replacement).
	dup := mkMsg(0xC0FFEE)
	ok, serr = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(serr)
	ok, serr = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(serr)

	// 4. The party's own self-echo is exempt: each round pre-populates its own
	//    outgoing slot, so re-storing self content (even differing) is accepted.
	ok, serr = p.StoreMessage(keygen.NewKGRound1Message(self, big.NewInt(0x1111)))
	a.True(ok)
	a.Nil(serr)
	ok, serr = p.StoreMessage(keygen.NewKGRound1Message(self, big.NewInt(0x2222)))
	a.True(ok)
	a.Nil(serr)
}
