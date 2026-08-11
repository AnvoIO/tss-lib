// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/AnvoIO/tss-lib/v3/common"
)

type Party interface {
	// Start starts this party exactly once. Transport delivery may race Start;
	// valid early messages are queued for the first round.
	Start() *Error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via a reliable broadcast
	// UpdateFromBytes is safe to call concurrently for a party.
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	// Update is safe to call concurrently for a party.
	Update(msg ParsedMessage) (ok bool, err *Error)
	// Running, WaitingFor, WrapError, and String are safe to call concurrently
	// with Start and Update.
	Running() bool
	WaitingFor() []*PartyID
	// ValidateMessage and StoreMessage are low-level protocol hooks. Callers
	// must not invoke them concurrently; use Update or UpdateFromBytes.
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	FirstRound() Round
	WrapError(err error, culprits ...*PartyID) *Error
	// Treat the returned identity as immutable for the lifetime of the party.
	PartyID() *PartyID
	String() string

	// Private lifecycle methods
	setRound(Round) *Error
	round() Round
	advance()
	lock()
	unlock()
	lifecycle() partyLifecycle
	setLifecycle(partyLifecycle)
	terminalError() *Error
	setTerminalError(*Error)
	setErrorContext(string)
}

type partyLifecycle uint8

const (
	partyCreated partyLifecycle = iota
	partyRunning
	partyFinished
	partyAborted
)

func (state partyLifecycle) String() string {
	switch state {
	case partyCreated:
		return "created"
	case partyRunning:
		return "running"
	case partyFinished:
		return "finished"
	case partyAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

type partyErrorContext struct {
	task   string
	round  int
	victim *PartyID
}

type BaseParty struct {
	mtx         sync.Mutex
	rnd         Round
	FirstRound  Round
	state       partyLifecycle
	terminalErr *Error
	contextMtx  sync.RWMutex
	errorCtx    *partyErrorContext
}

func (p *BaseParty) Running() bool {
	p.lock()
	defer p.unlock()
	return p.state == partyRunning
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.lock()
	defer p.unlock()
	if p.state != partyRunning || p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	p.contextMtx.RLock()
	ctx := p.errorCtx
	if ctx == nil {
		p.contextMtx.RUnlock()
		return NewError(err, "", -1, nil, culprits...)
	}
	task, round, victim := ctx.task, ctx.round, ctx.victim
	p.contextMtx.RUnlock()
	return NewError(err, task, round, victim, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil {
		return false, p.WrapError(errors.New("received nil msg"))
	}
	if msg.Content() == nil {
		// Do not format msg here: MessageImpl.String dereferences its content and
		// wire metadata, which are precisely the fields this boundary is
		// validating and may be nil on a directly constructed ParsedMessage.
		return false, p.WrapError(errors.New("received msg with nil content"))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(errors.New("received msg with an invalid sender"))
	}
	if !msg.ValidateBasic() {
		if msg.WireMsg() == nil {
			return false, p.WrapError(errors.New("message failed ValidateBasic"), msg.GetFrom())
		}
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	p.lock()
	defer p.unlock()
	if p.state == partyRunning && p.rnd != nil {
		return fmt.Sprintf("round: %d", p.rnd.RoundNumber())
	}
	if p.state == partyAborted {
		return partyAborted.String()
	}
	return "No more rounds"
}

// -----
// Private lifecycle methods

func (p *BaseParty) setRound(round Round) *Error {
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) lock() {
	p.mtx.Lock()
}

func (p *BaseParty) unlock() {
	p.mtx.Unlock()
}

func (p *BaseParty) lifecycle() partyLifecycle {
	return p.state
}

func (p *BaseParty) setLifecycle(state partyLifecycle) {
	p.state = state
}

func (p *BaseParty) terminalError() *Error {
	return p.terminalErr
}

func (p *BaseParty) setTerminalError(err *Error) {
	p.terminalErr = err
}

func (p *BaseParty) setErrorContext(task string) {
	if p.rnd == nil {
		return
	}
	ctx := &partyErrorContext{
		task:   task,
		round:  p.rnd.RoundNumber(),
		victim: p.rnd.Params().PartyID(),
	}
	p.contextMtx.Lock()
	p.errorCtx = ctx
	p.contextMtx.Unlock()
}

// ----- //

type sensitiveDataClearer interface {
	ClearSensitiveData()
}

func abortPartyLocked(p Party, err *Error) *Error {
	if err == nil {
		return nil
	}
	p.setTerminalError(err)
	p.setLifecycle(partyAborted)
	if clearer, ok := p.(sensitiveDataClearer); ok {
		clearer.ClearSensitiveData()
	}
	return err
}

func BaseStart(p Party, task string, prepare ...func(Round) *Error) (err *Error) {
	p.lock()
	defer p.unlock()
	if p.lifecycle() != partyCreated {
		if p.lifecycle() == partyAborted && p.terminalError() != nil {
			return p.terminalError()
		}
		return p.WrapError(fmt.Errorf("could not start: party is %s; use a new party instance", p.lifecycle()))
	}
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		err = p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
		return abortPartyLocked(p, err)
	}
	round := p.FirstRound()
	if round == nil {
		err = p.WrapError(errors.New("could not start: FirstRound returned nil"))
		return abortPartyLocked(p, err)
	}
	if err := p.setRound(round); err != nil {
		return abortPartyLocked(p, err)
	}
	p.setLifecycle(partyRunning)
	if 1 < len(prepare) {
		err = p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
		return abortPartyLocked(p, err)
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return abortPartyLocked(p, err)
		}
	}
	common.Logger.Infof("party %s: %s round %d starting", p.round().Params().PartyID(), task, 1)
	p.setErrorContext(task)
	if err := p.round().Start(); err != nil {
		return abortPartyLocked(p, err)
	}
	common.Logger.Debugf("party %s: %s round %d finished", p.round().Params().PartyID(), task, 1)
	return nil
}

// IsSameMessage reports whether two ParsedMessage values carry identical
// content. Per-protocol StoreMessage implementations use it to distinguish
// legitimate at-least-once redelivery (same content, idempotent) from
// adversarial intra-session replacement (different content, which must be
// rejected). Two messages are considered the same when they share a type and
// their wire-encoded bytes match exactly.
func IsSameMessage(a, b ParsedMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a == b {
		return true
	}
	if a.Type() != b.Type() {
		return false
	}
	aBz, _, errA := a.WireBytes()
	bBz, _, errB := b.WireBytes()
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(aBz, bBz)
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	p.lock()
	if p.lifecycle() == partyAborted {
		err := p.terminalError()
		p.unlock()
		return false, err
	}
	// Validation can format errors with the current round, so it must be
	// serialized with round advancement. Rejected messages do not mutate party
	// state and therefore must not trigger sensitive-data cleanup.
	if _, err := p.ValidateMessage(msg); err != nil {
		p.unlock()
		return false, err
	}
	// Concurrent transports can still have already-queued messages when this
	// party finishes. Validate them, then ignore valid ones instead of turning
	// normal delivery skew into an error reported by the session coordinator.
	if p.lifecycle() == partyFinished {
		p.unlock()
		return false, nil
	}
	// Preserve the v3 behavior that allows transport delivery to race Start:
	// queue a valid message now and let the first live round consume it.
	if p.lifecycle() == partyCreated {
		ok, err := p.StoreMessage(msg)
		if err != nil {
			err = abortPartyLocked(p, err)
		}
		p.unlock()
		return ok, err
	}
	if p.lifecycle() != partyRunning || p.round() == nil {
		err := p.WrapError(fmt.Errorf("could not update: party is %s", p.lifecycle()))
		p.unlock()
		return false, err
	}
	// Need this unlock hook because the round-advance path recurses below.
	r := func(ok bool, err *Error) (bool, *Error) {
		if err != nil {
			err = abortPartyLocked(p, err)
		}
		p.unlock()
		return ok, err
	}
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	if ok, err := p.StoreMessage(msg); err != nil {
		return r(false, err)
	} else if !ok {
		p.unlock()
		return false, nil
	}
	common.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
	if _, err := p.round().Update(); err != nil {
		return r(false, err)
	}
	if p.round().CanProceed() {
		p.advance()
		if p.round() == nil {
			p.setLifecycle(partyFinished)
			common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			p.unlock()
			return true, nil
		}
		p.setErrorContext(task)
		if err := p.round().Start(); err != nil {
			return r(false, err)
		}
		rndNum := p.round().RoundNumber()
		common.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
		p.unlock()
		return BaseUpdate(p, msg, task)
	}
	return r(true, nil)
}
