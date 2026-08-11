// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// sameMsgStub is a minimal ParsedMessage used to exercise IsSameMessage in
// isolation: it lets the test control the reported type, the wire-encoded
// bytes, and whether WireBytes surfaces an error.
type sameMsgStub struct {
	typ     string
	bz      []byte
	wireErr error
}

func (m *sameMsgStub) Type() string                  { return m.typ }
func (m *sameMsgStub) GetTo() []*PartyID             { return nil }
func (m *sameMsgStub) GetFrom() *PartyID             { return nil }
func (m *sameMsgStub) IsBroadcast() bool             { return true }
func (m *sameMsgStub) IsToOldCommittee() bool        { return false }
func (m *sameMsgStub) IsToOldAndNewCommittees() bool { return false }
func (m *sameMsgStub) WireBytes() ([]byte, *MessageRouting, error) {
	if m.wireErr != nil {
		return nil, nil, m.wireErr
	}
	return m.bz, nil, nil
}
func (m *sameMsgStub) WireMsg() *MessageWrapper { return nil }
func (m *sameMsgStub) String() string           { return m.typ }
func (m *sameMsgStub) Content() MessageContent  { return nil }
func (m *sameMsgStub) ValidateBasic() bool      { return true }

// TestIsSameMessage pins the discriminator that every StoreMessage driver relies
// on to separate idempotent at-least-once redelivery (accepted) from adversarial
// intra-session replacement (rejected).
func TestIsSameMessage(t *testing.T) {
	a := assert.New(t)

	base := &sameMsgStub{typ: "round1", bz: []byte{0x01, 0x02, 0x03}}
	sameContent := &sameMsgStub{typ: "round1", bz: []byte{0x01, 0x02, 0x03}}
	diffContent := &sameMsgStub{typ: "round1", bz: []byte{0x01, 0x02, 0x04}}
	diffType := &sameMsgStub{typ: "round2", bz: []byte{0x01, 0x02, 0x03}}

	// Same pointer is trivially the same message.
	a.True(IsSameMessage(base, base))
	// Distinct instances with identical type + wire bytes: an idempotent re-send.
	a.True(IsSameMessage(base, sameContent))
	// Same type but different wire bytes: intra-session replacement.
	a.False(IsSameMessage(base, diffContent))
	// Different type: not the same message.
	a.False(IsSameMessage(base, diffType))

	// nil handling: two nils match; a nil vs non-nil does not.
	a.True(IsSameMessage(nil, nil))
	a.False(IsSameMessage(base, nil))
	a.False(IsSameMessage(nil, base))

	// A wire-encoding failure fails closed (treated as "not the same" so the
	// caller rejects rather than silently overwrites).
	broken := &sameMsgStub{typ: "round1", wireErr: errors.New("marshal failed")}
	a.False(IsSameMessage(base, broken))
	a.False(IsSameMessage(broken, base))
}
