// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

type (
	PeerContext struct {
		partyIDs SortedPartyIDs
	}
)

// NewPeerContext takes a deep snapshot of the committee identities.
func NewPeerContext(parties SortedPartyIDs) *PeerContext {
	return &PeerContext{partyIDs: clonePartyIDs(parties)}
}

// IDs returns a deep copy. Mutating the result cannot alter this context.
func (p2pCtx *PeerContext) IDs() SortedPartyIDs {
	if p2pCtx == nil {
		return nil
	}
	return clonePartyIDs(p2pCtx.partyIDs)
}
