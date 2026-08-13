// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

const (
	TaskName = "eddsa-resharing"
)

type (
	base struct {
		*tss.ReSharingParameters
		temp        *localTempData
		input, save *keygen.LocalPartySaveData
		out         chan<- tss.Message
		end         chan<- *keygen.LocalPartySaveData
		oldOK,      // old committee "ok" tracker
		newOK []bool // `ok` tracks parties which have been verified by Update(); this one is for the new committee
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.ReSharingParameters.Parameters
}

func (round *base) ReSharingParams() *tss.ReSharingParameters {
	return round.ReSharingParameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range append(round.oldOK, round.newOK...) {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	oldPs := round.OldParties().IDs()
	newPs := round.NewParties().IDs()
	idsMap := make(map[string]*tss.PartyID)
	ids := make([]*tss.PartyID, 0, len(round.oldOK))
	for j, ok := range round.oldOK {
		if ok {
			continue
		}
		idsMap[oldPs[j].KeyInt().String()] = oldPs[j]
	}
	for j, ok := range round.newOK {
		if ok {
			continue
		}
		idsMap[newPs[j].KeyInt().String()] = newPs[j]
	}
	// consolidate into the list
	for _, id := range idsMap {
		ids = append(ids, id)
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `oldOK` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.oldOK {
		round.oldOK[j] = false
	}
	for j := range round.newOK {
		round.newOK[j] = false
	}
}

// sets all pairings in `oldOK` to true
func (round *base) allOldOK() {
	for j := range round.oldOK {
		round.oldOK[j] = true
	}
}

// sets all pairings in `newOK` to true
func (round *base) allNewOK() {
	for j := range round.newOK {
		round.newOK[j] = true
	}
}

// getSSID derives this reshare's session identifier from local params. It is
// computed by the OLD committee in round 1 (it reads the old share's public
// material, which only the old committee holds) and declared to the new committee
// on the wire; the new committee never recomputes it, it checks unanimity and the
// companion session_nonce_hash instead.
//
// EdDSA resharing carries NO zero-knowledge proofs, so unlike ECDSA resharing
// there is no ssid-bound proof context to anchor the transcript. The ssid is
// therefore bound directly into the round-1 VSS hash commitment (see
// round_1_old_step_1.go) and checked on decommit in round 4; this function fixes
// what that ssid contains.
func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                         // OLD committee
	// The NEW committee is the defining input of a reshare (it decides who
	// receives the key) and both thresholds fix the polynomial degrees. Bind them
	// so two reshares of the same key by the same old committee to different new
	// committees (or thresholds) under one nonce cannot collide on the ssid, which
	// is the only session anchor this proof-free protocol has.
	ssidList = append(ssidList, round.NewParties().IDs().Keys()...) // NEW committee
	BigXjList, err := crypto.FlattenECPoints(round.input.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...) // BigXj (per-party public shares)
	if round.input.EDDSAPub != nil {
		ssidList = append(ssidList, round.input.EDDSAPub.X(), round.input.EDDSAPub.Y()) // aggregate group key y
	}
	ssidList = append(ssidList, big.NewInt(int64(round.Threshold())))    // old reconstruction threshold
	ssidList = append(ssidList, big.NewInt(int64(round.NewThreshold()))) // new reconstruction threshold
	ssidList = append(ssidList, big.NewInt(int64(round.number)))         // round number
	ssidList = append(ssidList, round.temp.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}

// sessionNonceHash is what the old committee declares in round 1 and each new
// committee party checks in round 2. It is a hash rather than the nonce itself so
// the wire does not hand a passive observer the identifier of a session it is not
// in; every party that IS in the session already holds the nonce and recomputes
// this.
//
// SCOPE: this makes a transcript non-portable between sessions for a peer that
// cannot forge messages. It does NOT authenticate the sender — nothing here signs
// or MACs a message — so an adversary who can rewrite arbitrary bytes on the wire
// can substitute the expected hash. Transport authentication remains the host's
// job, exactly as it is for the rest of the protocol.
func sessionNonceHash(nonce *big.Int) []byte {
	if nonce == nil {
		return nil
	}
	return common.SHA512_256i(nonce).Bytes()
}
