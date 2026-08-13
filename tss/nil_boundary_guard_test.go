// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"math/big"
	"strings"
	"testing"
)

func guardPID(name string, key int64, idx int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id: name, Moniker: name, Key: big.NewInt(key).Bytes(),
		},
		Index: idx,
	}
}

func wantGuardPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic mentioning %q", want)
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected an error panic value, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()
	fn()
}

// NewMessageWrapper dereferences routing.From and every routing.To element. The
// old `routing.To != nil` check guarded only the container; the elements and
// From were read unchecked. A nil there is a caller's malformed routing and must
// fail attributably, since the constructor has no error channel.
func TestNewMessageWrapperGuardsFromAndToElements(t *testing.T) {
	from := guardPID("from", 1, 0)
	good := guardPID("to", 2, 1)

	wantGuardPanic(t, "routing.From", func() {
		NewMessageWrapper(MessageRouting{From: nil, To: []*PartyID{good}}, nil)
	})
	wantGuardPanic(t, "routing.From", func() {
		NewMessageWrapper(MessageRouting{From: new(PartyID), To: []*PartyID{good}}, nil)
	})
	wantGuardPanic(t, "routing.To[1]", func() {
		NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{good, nil}}, nil)
	})
	wantGuardPanic(t, "routing.To[0]", func() {
		NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{new(PartyID)}}, nil)
	})
}

// Negative control: the guards must accept well-formed routing. Marshalling a nil
// content is not what this exercises, so only a guard-attributable panic is a
// failure here.
func TestNewMessageWrapperAcceptsWellFormedRouting(t *testing.T) {
	from, to := guardPID("from", 1, 0), guardPID("to", 2, 1)
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && strings.Contains(err.Error(), "NewMessageWrapper:") {
				t.Fatalf("guards rejected well-formed routing: %v", err)
			}
		}
	}()
	_ = NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{to}}, nil)
}

// Keys() reads pid.KeyInt(), promoted through the embedded *MessageWrapper_PartyID,
// so a nil embedded pointer faults there. SortedPartyIDs is an exported slice
// type built directly by callers, so this is reachable without SortPartyIDs
// having screened anything.
func TestSortedPartyIDsKeysGuardsNilEmbedded(t *testing.T) {
	wantGuardPanic(t, "SortedPartyIDs.Keys:", func() {
		SortedPartyIDs{new(PartyID)}.Keys()
	})
}

func TestSortedPartyIDsKeysStillReturnsKeysForWellFormed(t *testing.T) {
	got := SortedPartyIDs{guardPID("a", 7, 0), guardPID("b", 9, 1)}.Keys()
	if len(got) != 2 || got[0].Int64() != 7 || got[1].Int64() != 9 {
		t.Fatalf("got %v, want [7 9]", got)
	}
}
