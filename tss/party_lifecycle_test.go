// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type lifecycleTestParty struct {
	*BaseParty
	id           *PartyID
	storeEntered chan struct{}
	releaseStore chan struct{}
	storeCalls   atomic.Int32
	clearCalls   atomic.Int32
}

func (p *lifecycleTestParty) Start() *Error {
	return BaseStart(p, "lifecycle-test")
}

func (p *lifecycleTestParty) UpdateFromBytes([]byte, *PartyID, bool) (bool, *Error) {
	return false, nil
}

func (p *lifecycleTestParty) Update(msg ParsedMessage) (bool, *Error) {
	return BaseUpdate(p, msg, "lifecycle-test")
}

func (p *lifecycleTestParty) ValidateMessage(ParsedMessage) (bool, *Error) {
	return true, nil
}

func (p *lifecycleTestParty) StoreMessage(ParsedMessage) (bool, *Error) {
	if p.storeCalls.Add(1) != 1 {
		return true, nil
	}
	close(p.storeEntered)
	<-p.releaseStore
	return false, p.WrapError(errors.New("fatal store failure"))
}

func (p *lifecycleTestParty) FirstRound() Round {
	return nil
}

func (p *lifecycleTestParty) PartyID() *PartyID {
	return p.id
}

func (p *lifecycleTestParty) ClearSensitiveData() {
	p.clearCalls.Add(1)
}

type lifecycleTestRound struct {
	params *Parameters
}

func (r *lifecycleTestRound) Params() *Parameters          { return r.params }
func (r *lifecycleTestRound) Start() *Error                { return nil }
func (r *lifecycleTestRound) Update() (bool, *Error)       { return false, nil }
func (r *lifecycleTestRound) RoundNumber() int             { return 1 }
func (r *lifecycleTestRound) CanAccept(ParsedMessage) bool { return true }
func (r *lifecycleTestRound) CanProceed() bool             { return false }
func (r *lifecycleTestRound) NextRound() Round             { return nil }
func (r *lifecycleTestRound) WaitingFor() []*PartyID       { return nil }
func (r *lifecycleTestRound) WrapError(err error, culprits ...*PartyID) *Error {
	return NewError(err, "lifecycle-test", 1, r.params.PartyID(), culprits...)
}

type lifecycleTestMessage struct {
	from *PartyID
}

func (m *lifecycleTestMessage) Type() string                  { return "lifecycle-test" }
func (m *lifecycleTestMessage) GetTo() []*PartyID             { return nil }
func (m *lifecycleTestMessage) GetFrom() *PartyID             { return m.from }
func (m *lifecycleTestMessage) IsBroadcast() bool             { return true }
func (m *lifecycleTestMessage) IsToOldCommittee() bool        { return false }
func (m *lifecycleTestMessage) IsToOldAndNewCommittees() bool { return false }
func (m *lifecycleTestMessage) WireBytes() ([]byte, *MessageRouting, error) {
	return nil, nil, nil
}
func (m *lifecycleTestMessage) WireMsg() *MessageWrapper { return nil }
func (m *lifecycleTestMessage) String() string           { return "lifecycle-test" }
func (m *lifecycleTestMessage) Content() MessageContent  { return nil }
func (m *lifecycleTestMessage) ValidateBasic() bool      { return true }

func TestFatalUpdateTerminalizesBeforeQueuedUpdateRuns(t *testing.T) {
	ids := GenerateTestPartyIDs(2)
	params, err := NewParameters(Edwards(), NewPeerContext(ids), ids[0], len(ids), 1)
	require.NoError(t, err)

	party := &lifecycleTestParty{
		BaseParty:    &BaseParty{},
		id:           ids[0],
		storeEntered: make(chan struct{}),
		releaseStore: make(chan struct{}),
	}
	party.rnd = &lifecycleTestRound{params: params}
	party.state = partyRunning
	party.setErrorContext("lifecycle-test")
	msg := &lifecycleTestMessage{from: ids[1]}

	type result struct {
		ok  bool
		err *Error
	}
	first := make(chan result, 1)
	second := make(chan result, 1)
	go func() {
		ok, updateErr := party.Update(msg)
		first <- result{ok: ok, err: updateErr}
	}()
	<-party.storeEntered
	go func() {
		ok, updateErr := party.Update(msg)
		second <- result{ok: ok, err: updateErr}
	}()

	stopReaders := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = party.Running()
					_ = party.String()
					_ = party.WaitingFor()
					_ = party.WrapError(errors.New("status probe"))
				}
			}
		}()
	}

	close(party.releaseStore)
	firstResult := <-first
	secondResult := <-second
	close(stopReaders)
	readers.Wait()

	require.False(t, firstResult.ok)
	require.False(t, secondResult.ok)
	require.ErrorContains(t, firstResult.err, "fatal store failure")
	require.Same(t, firstResult.err, secondResult.err)
	require.Equal(t, int32(1), party.storeCalls.Load(), "queued update must not touch wiped state")
	require.Equal(t, int32(1), party.clearCalls.Load(), "sensitive state must be cleared exactly once")
	require.False(t, party.Running())
	require.Equal(t, "aborted", party.String())
	require.Empty(t, party.WaitingFor())
}
