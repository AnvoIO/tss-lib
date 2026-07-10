// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	cmt "github.com/AnvoIO/tss-lib/v4/crypto/commitments"
	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data *common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *common.SignatureData
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages,
		signRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		wi,
		ri *big.Int
		message  []byte
		initErr  error
		pointRi  *crypto.ECPoint
		deCommit cmt.HashDeCommitment

		// round 2
		cjs []*big.Int
		si  *[32]byte

		// round 3
		r *big.Int

		ssid      []byte
		ssidNonce *big.Int
	}
)

// NewLocalParty is retained for compatibility. New code should use
// NewLocalPartyWithBytes so leading zero bytes are represented unambiguously.
func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
	fullBytesLen ...int,
) tss.Party {
	message, err := legacyMessageBytes(msg, fullBytesLen...)
	return newLocalParty(message, err, params, key, out, end)
}

// NewLocalPartyWithBytes constructs an EdDSA signer over the exact message
// bytes supplied by the caller, including leading zero bytes.
func NewLocalPartyWithBytes(
	message []byte,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Party {
	return newLocalParty(append([]byte{}, message...), nil, params, key, out, end)
}

func legacyMessageBytes(msg *big.Int, fullBytesLen ...int) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("message must not be nil")
	}
	if msg.Sign() < 0 {
		return nil, errors.New("message must not be negative")
	}
	if len(fullBytesLen) > 1 {
		return nil, errors.New("at most one full message byte length may be supplied")
	}
	minimal := msg.Bytes()
	if len(fullBytesLen) == 0 {
		return append([]byte{}, minimal...), nil
	}
	if fullBytesLen[0] < 0 || fullBytesLen[0] < len(minimal) {
		return nil, fmt.Errorf("full message byte length %d is smaller than the encoded message length %d", fullBytesLen[0], len(minimal))
	}
	message := make([]byte, fullBytesLen[0])
	msg.FillBytes(message)
	return message, nil
}

func newLocalParty(
	message []byte,
	initErr error,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      &common.SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.message = message
	p.temp.initErr = initErr
	p.temp.cjs = make([]*big.Int, partyCount)
	return p
}

// Clear zeros sensitive data in temp storage to reduce the window of exposure.
// Internally-generated secrets are zeroed in-place; externally-provided values
// (like m) are nil'd out to avoid mutating the caller's data.
func (td *localTempData) Clear() {
	if td.wi != nil {
		td.wi.SetInt64(0)
	}
	if td.ri != nil {
		td.ri.SetInt64(0)
	}
	if td.si != nil {
		for i := range td.si {
			td.si[i] = 0
		}
	}
	if td.r != nil {
		td.r.SetInt64(0)
	}
	for i := range td.message {
		td.message[i] = 0
	}
	td.message = nil
	for _, c := range td.cjs {
		if c != nil {
			c.SetInt64(0)
		}
	}
}

func (p *LocalParty) ClearSensitiveData() {
	p.temp.Clear()
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		if p.temp.initErr != nil {
			return round.WrapError(p.temp.initErr)
		}
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
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
	if _, ok := p.params.Parties().IDs().IndexOf(msg.GetFrom()); !ok {
		return false, p.WrapError(fmt.Errorf("message sender is not a committee member"), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx, _ := p.params.Parties().IDs().IndexOf(msg.GetFrom())

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message:
		p.temp.signRound1Messages[fromPIdx] = msg

	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg

	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg

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
