// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateBasic_KGRound1Message(t *testing.T) {
	tests := []struct {
		name string
		msg  *KGRound1Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil Commitment", &KGRound1Message{Commitment: nil}, false},
		{"empty Commitment", &KGRound1Message{Commitment: []byte{}}, false},
		{"valid", &KGRound1Message{Commitment: []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_KGRound2Message1(t *testing.T) {
	tests := []struct {
		name string
		msg  *KGRound2Message1
		want bool
	}{
		{"nil message", nil, false},
		{"nil Share", &KGRound2Message1{Share: nil}, false},
		{"empty Share", &KGRound2Message1{Share: []byte{}}, false},
		{"valid", &KGRound2Message1{Share: []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_KGRound2Message2(t *testing.T) {
	tests := []struct {
		name string
		msg  *KGRound2Message2
		want bool
	}{
		{"nil message", nil, false},
		{"nil DeCommitment", &KGRound2Message2{DeCommitment: nil}, false},
		{"empty DeCommitment", &KGRound2Message2{DeCommitment: [][]byte{}}, false},
		{"DeCommitment with empty entry", &KGRound2Message2{DeCommitment: [][]byte{{}}}, false},
		{"valid DeCommitment", &KGRound2Message2{DeCommitment: [][]byte{{0x01}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}
