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
	"github.com/AnvoIO/tss-lib/v4/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	Pi := round.PartyID()
	i, ok := round.ReSharingParams().NewPartyIndex()
	if round.IsNewCommittee() && !ok {
		return round.WrapError(errors.New("local party is not in the new committee"), Pi)
	}

	if round.IsNewCommittee() {
		// 21.
		// for this P: SAVE data
		ContextI := common.AppendBigIntToBytesSliceFramed(round.temp.ssid, big.NewInt(int64(i)))
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = new(big.Int).Set(round.temp.newXi)
		round.save.Ks = round.temp.newKs

		// misc: build list of paillier public keys to save
		for j, msg := range round.temp.dgRound2Message1s {
			if j == i {
				continue
			}
			r2msg1 := msg.Content().(*DGRound2Message1)
			round.save.PaillierPKs[j] = r2msg1.UnmarshalPaillierPK()
		}
		for j, msg := range round.temp.dgRound4Message1s {
			if j == i {
				continue
			}
			r4msg1 := msg.Content().(*DGRound4Message1)
			proof, err := r4msg1.UnmarshalFacProof()
			if err != nil && round.Parameters.NoProofFac() {
				common.Logger.Warningf("facProof verify failed for party %s", msg.GetFrom(), err)
			} else {
				if err != nil {
					common.Logger.Warningf("facProof verify failed for party %s", msg.GetFrom(), err)
					return round.WrapError(err, round.NewParties().IDs()[j])
				}
				if ok := proof.Verify(ContextI, round.EC(), round.save.PaillierPKs[j].N, round.save.NTildei,
					round.save.H1i, round.save.H2i); !ok {
					// err is nil in this branch (UnmarshalFacProof succeeded); build a
					// real cause so the failure is not surfaced as "Error is nil".
					common.Logger.Warningf("facProof verification failed for party %s", msg.GetFrom())
					return round.WrapError(errors.New("facProof verification failed"), round.NewParties().IDs()[j])
				}
			}

		}
	} else if round.IsOldCommittee() {
		round.input.Xi.SetInt64(0)
	}

	round.temp.Clear()
	round.end <- round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
