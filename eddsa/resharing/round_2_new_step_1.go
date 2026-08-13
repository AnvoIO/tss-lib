// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/subtle"
	"errors"

	"github.com/AnvoIO/tss-lib/v4/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		return nil
	}
	round.allNewOK()

	Pi := round.PartyID()
	i, ok := round.ReSharingParams().NewPartyIndex()
	if !ok {
		return round.WrapError(errors.New("local party is not in the new committee"), Pi)
	}

	// Session binding: every old-committee round-1 message must declare a nonce
	// hash equal to THIS new party's own. The ssid unanimity check below only
	// compares the old committee's declarations to EACH OTHER, so a full transcript
	// captured from another session is unanimous with itself and would pass it;
	// this check, against a value only a same-session party holds (the new
	// committee cannot recompute the old committee's ssid), is what rejects it.
	nonce := round.Params().SessionNonce()
	if nonce == nil || nonce.Sign() <= 0 {
		return round.WrapError(errors.New("round 2: this party has no session nonce, so it cannot verify the old committee is in the same session; call Parameters.SetSessionNonce"), Pi)
	}
	wantNonceHash := sessionNonceHash(nonce)
	for j, Pj := range round.OldParties().IDs() {
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		if subtle.ConstantTimeCompare(r1msg.UnmarshalSessionNonceHash(), wantNonceHash) != 1 {
			return round.WrapError(errors.New("round 2: an old committee member's session nonce hash does not match this party's; the two committees are not in the same session"), Pj)
		}
	}

	// Check consistency of the SSID across the old committee, and adopt it: the new
	// committee cannot derive the old committee's ssid itself, so it takes the
	// unanimous declared value and uses it to check the round-1 VSS commitments on
	// decommit in round 4 (EdDSA resharing has no ZK proof context to anchor them).
	// Slot 0 is only the reference value, not a privileged/validated anchor: on a
	// mismatch the liar could be the slot-0 party (whose value is never itself
	// checked) just as easily as Pj, so attribute both parties in the disagreeing
	// pair rather than blaming Pj alone (the same fixed-slot anti-pattern as
	// SRC-2026-1155 in round 1).
	anchor := round.OldParties().IDs()[0]
	r1msg0 := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
	SSID := r1msg0.UnmarshalSSID()
	for j, Pj := range round.OldParties().IDs() {
		if j == 0 {
			continue
		}
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		SSIDj := r1msg.UnmarshalSSID()
		if subtle.ConstantTimeCompare(SSID, SSIDj) != 1 {
			return round.WrapError(errors.New("ssid mismatch"), anchor, Pj)
		}
	}
	round.temp.ssid = SSID

	// 1. "broadcast" "ACK" members of the OLD committee
	r2msg := NewDGRound2Message(round.OldParties().IDs(), Pi)
	round.temp.dgRound2Messages[i] = r2msg
	round.out <- r2msg

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// only the old committee receive in this round
	if !round.ReSharingParams().IsOldCommittee() {
		return true, nil
	}

	ret := true
	// accept messages from new -> old committee
	for j, msg := range round.temp.dgRound2Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.newOK[j] = true
	}

	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
