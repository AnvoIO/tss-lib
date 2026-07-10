// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseWireMessage_NilFromReturnsError is a defense-in-depth regression test:
// ParseWireMessage dereferences the caller-supplied `from` party; a nil `from`
// must return an error rather than panic on the exported boundary.
func TestParseWireMessage_NilFromReturnsError(t *testing.T) {
	assert.NotPanics(t, func() {
		msg, err := ParseWireMessage([]byte{0x00}, nil, true)
		assert.Nil(t, msg)
		assert.Error(t, err, "nil from party must be rejected, not panic")
	})
}

func TestParseWireMessage_RejectsOversizedInput(t *testing.T) {
	from := NewPartyID("p1", "p1", big.NewInt(1))

	assert.NotPanics(t, func() {
		msg, err := ParseWireMessage(make([]byte, MaxWireMessageSize+1), from, true)
		assert.Nil(t, msg)
		assert.ErrorContains(t, err, "message is too large")
	})
}

func FuzzParseWireMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x0a, 0x00})
	from := NewPartyID("p1", "p1", big.NewInt(1))
	from.Index = 0

	f.Fuzz(func(t *testing.T, wireBytes []byte) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("ParseWireMessage panicked for %x: %v", wireBytes, recovered)
			}
		}()
		_, _ = ParseWireMessage(wireBytes, from, true)
	})
}
