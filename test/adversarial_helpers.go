// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package test

import (
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// MessageTamperFunc modifies wire bytes from adversary before delivery.
// Return nil to drop the message entirely.
type MessageTamperFunc func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte

// MaliciousUpdater returns an updater function that tampers messages from adversaryIdx
// before delivering them to the receiving party. Messages from other parties are
// delivered normally via SharedPartyUpdater semantics.
func MaliciousUpdater(adversaryIdx int, tamperFn MessageTamperFunc) func(tss.Party, tss.Message, chan<- *tss.Error) {
	return func(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
		// do not send a message from this party back to itself
		if party.PartyID() == msg.GetFrom() {
			return
		}
		bz, _, err := msg.WireBytes()
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		// tamper messages from the adversary
		if msg.GetFrom().Index == adversaryIdx {
			bz = tamperFn(bz, msg.GetFrom(), msg.IsBroadcast())
			if bz == nil {
				return // drop
			}
		}
		pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		if _, err := party.Update(pMsg); err != nil {
			errCh <- err
		}
	}
}

// FlipBytesAt flips a byte at the given offset in a copy of the data.
func FlipBytesAt(data []byte, offset int) []byte {
	if offset >= len(data) || offset < 0 {
		return data
	}
	out := make([]byte, len(data))
	copy(out, data)
	out[offset] ^= 0xFF
	return out
}
