// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"fmt"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	cmt "github.com/AnvoIO/tss-lib/v4/crypto/commitments"
	"github.com/AnvoIO/tss-lib/v4/crypto/vss"
	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.ReSharingParameters

		temp        localTempData
		input, save keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *keygen.LocalPartySaveData
	}

	localMessageStore struct {
		dgRound1Messages,
		dgRound2Message1s,
		dgRound2Message2s,
		dgRound3Message1s,
		dgRound3Message2s,
		dgRound4Message1s,
		dgRound4Message2s []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after rounds)
		NewVs     vss.Vs
		NewShares vss.Shares
		VD        cmt.HashDeCommitment

		// temporary storage of data that is persisted by the new party in round 5 if all "ACK" messages are received
		newXi     *big.Int
		newKs     []*big.Int
		newBigXjs []*crypto.ECPoint // Xj to save in round 5

		ssid      []byte
		ssidNonce *big.Int
	}
)

// Exported, used in `tss` client
// The `key` is read from and/or written to depending on whether this party is part of the old or the new committee.
// You may optionally generate and set the LocalPreParams if you would like to use pre-generated safe primes and Paillier secret.
// (This is similar to providing the `optionalPreParams` to `keygen.LocalParty`).
func NewLocalParty(
	params *tss.ReSharingParameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *keygen.LocalPartySaveData,
) tss.Party {
	oldPartyCount := len(params.OldParties().IDs())
	subset := key
	if params.IsOldCommittee() {
		subset = keygen.BuildLocalSaveDataSubset(key, params.OldParties().IDs())
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		input:     subset,
		save:      keygen.NewLocalPartySaveData(params.NewPartyCount()),
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.dgRound1Messages = make([]tss.ParsedMessage, oldPartyCount)           // from t+1 of Old Committee
	p.temp.dgRound2Message1s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound2Message2s = make([]tss.ParsedMessage, params.NewPartyCount()) // "
	p.temp.dgRound3Message1s = make([]tss.ParsedMessage, oldPartyCount)          // from t+1 of Old Committee
	p.temp.dgRound3Message2s = make([]tss.ParsedMessage, oldPartyCount)          // "
	p.temp.dgRound4Message1s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound4Message2s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	// save data init
	if key.LocalPreParams.ValidateWithProof() {
		p.save.LocalPreParams = key.LocalPreParams
	}
	return p
}

func (td *localTempData) Clear() {
	for _, share := range td.NewShares {
		if share != nil && share.Share != nil {
			share.Share.SetInt64(0)
		}
	}
	for _, value := range td.VD {
		if value != nil {
			value.SetInt64(0)
		}
	}
	if td.newXi != nil {
		td.newXi.SetInt64(0)
	}
	if td.ssidNonce != nil {
		td.ssidNonce.SetInt64(0)
	}
}

func (p *LocalParty) ClearSensitiveData() {
	p.temp.Clear()
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.input, &p.save, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	if _, ok := p.senderIndex(msg); !ok {
		return false, p.WrapError(fmt.Errorf("message sender is not a member of the source committee"), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) senderIndex(msg tss.ParsedMessage) (int, bool) {
	switch msg.Content().(type) {
	case *DGRound2Message1, *DGRound2Message2, *DGRound4Message1, *DGRound4Message2:
		return p.params.NewParties().IDs().IndexOf(msg.GetFrom())
	default:
		return p.params.OldParties().IDs().IndexOf(msg.GetFrom())
	}
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx, ok := p.senderIndex(msg)
	if !ok {
		return false, p.WrapError(fmt.Errorf("message sender is not a member of the source committee"), msg.GetFrom())
	}

	// switch/case is necessary to store any messages beyond current round.
	// Each branch rejects intra-session message replacement: once a slot is
	// filled, a second message with different content is rejected. Idempotent
	// identical re-sends (at-least-once transports) are tolerated via
	// tss.IsSameMessage.
	//
	// senderIndex already resolves each slot in its committee-correct index
	// space (old-committee-sourced slots dgRound1/dgRound3* by the sender's OLD
	// index, new-sourced slots dgRound2*/dgRound4* by the sender's NEW index).
	// Because those two index spaces overlap, p.PartyID().Index is NOT a safe
	// self-echo discriminator: a cross-committee peer whose index in one
	// committee equals this party's index in the other would be mis-read as
	// "self" and skip the guard, re-opening intra-session replacement. Detect
	// our own echoes by sender IDENTITY (key) instead, which is committee-agnostic.
	isDup := msg.GetFrom().KeyInt().Cmp(p.PartyID().KeyInt()) != 0
	dupErr := func() (bool, *tss.Error) {
		return false, p.WrapError(
			fmt.Errorf("duplicate %T from party %d", msg.Content(), fromPIdx),
			msg.GetFrom())
	}
	switch msg.Content().(type) {
	case *DGRound1Message:
		if isDup && p.temp.dgRound1Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound1Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound1Messages[fromPIdx] = msg
	case *DGRound2Message1:
		if isDup && p.temp.dgRound2Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound2Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound2Message1s[fromPIdx] = msg
	case *DGRound2Message2:
		if isDup && p.temp.dgRound2Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound2Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound2Message2s[fromPIdx] = msg
	case *DGRound3Message1:
		if isDup && p.temp.dgRound3Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message1s[fromPIdx] = msg
	case *DGRound3Message2:
		if isDup && p.temp.dgRound3Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message2s[fromPIdx] = msg
	case *DGRound4Message1:
		if isDup && p.temp.dgRound4Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound4Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound4Message1s[fromPIdx] = msg
	case *DGRound4Message2:
		if isDup && p.temp.dgRound4Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound4Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound4Message2s[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
