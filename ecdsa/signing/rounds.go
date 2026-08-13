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
	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

const (
	TaskName = "signing"
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
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5
	}
	round7 struct {
		*round6
	}
	round8 struct {
		*round7
	}
	round9 struct {
		*round8
	}
	finalization struct {
		*round9
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
	_ tss.Round = (*round6)(nil)
	_ tss.Round = (*round7)(nil)
	_ tss.Round = (*round8)(nil)
	_ tss.Round = (*round9)(nil)
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
// being signed is part of the pre-image: signing is the only protocol here with
// a per-execution value of its own, so binding it means two runs of the same
// committee over different messages can never share an SSID — including when the
// caller reuses one session nonce (the shape a long-lived Parameters object
// makes easiest to reach). Everything else in the list is fixed by the key
// material, so without the message the nonce would be the single source of
// separation.
func (round *base) getSSID() ([]byte, error) {
	if round.temp.m == nil {
		return nil, round.WrapError(errors.New("message to sign is not set"), round.PartyID())
	}
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().B, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                                                // parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, round.key.NTildej...)            // NTilde
	ssidList = append(ssidList, round.key.H1j...)                // h1
	ssidList = append(ssidList, round.key.H2j...)                // h2
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)            // caller-supplied session nonce
	// Bind a length-sensitive digest of the EXACT bytes this session signs — the
	// same encoding finalize records as data.M (temp.m, fixed to fullBytesLen
	// when set). SHA512_256i hashes magnitudes only, so binding the bare scalar
	// temp.m cannot separate two runs that differ solely in fullBytesLen while
	// binding different byte strings. This mirrors the eddsa signer, which binds
	// SHA512_256 of its exact message bytes for the same reason.
	ssidList = append(ssidList, new(big.Int).SetBytes(common.SHA512_256(encodedMessage(round.temp.m, round.temp.fullBytesLen)))) // message being signed
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}

// encodedMessage returns the exact message bytes this signer commits to: the
// minimal big-endian encoding of m, or a fixed-width FillBytes encoding when
// fullBytesLen is set. getSSID binds a digest of these bytes and finalize records
// them as data.M, so the two share one definition of "the message" and cannot
// disagree about it.
func encodedMessage(m *big.Int, fullBytesLen int) []byte {
	if fullBytesLen == 0 {
		return m.Bytes()
	}
	mBytes := make([]byte, fullBytesLen)
	m.FillBytes(mBytes)
	return mBytes
}
