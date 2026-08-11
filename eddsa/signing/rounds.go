// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

const (
	TaskName = "eddsa-signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *common.SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *common.SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
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
	finalization struct {
		*round3
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

// getSSID derives the session identifier from the local params. The message
// being signed is part of the pre-image so that two runs of the same committee
// over different messages can never share an SSID, including when the caller
// reuses one session nonce. Everything else in the list is fixed by the key
// material, so without the message the nonce would be the single source of
// separation. temp.message holds the raw signed bytes (see round_3); it is bound
// as a big.Int, matching how the ecdsa signer binds temp.m.
func (round *base) getSSID() ([]byte, error) {
	if round.temp.message == nil {
		return nil, round.WrapError(errors.New("message to sign is not set"), round.PartyID())
	}
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                         // parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                              // BigXj
	ssidList = append(ssidList, big.NewInt(int64(round.number)))           // round number
	ssidList = append(ssidList, round.temp.ssidNonce)                      // caller-supplied session nonce
	ssidList = append(ssidList, new(big.Int).SetBytes(round.temp.message)) // message being signed
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}
