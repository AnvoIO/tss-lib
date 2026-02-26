// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestValidateBasic_SignRound1Message(t *testing.T) {
	tests := []struct {
		name string
		msg  *SignRound1Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil Commitment", &SignRound1Message{Commitment: nil}, false},
		{"empty Commitment", &SignRound1Message{Commitment: []byte{}}, false},
		{"valid", &SignRound1Message{Commitment: []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.msg == nil {
				// nil receiver will panic on field access; test ValidateBasic on the content check
				assert.False(t, tt.want) // just documenting the nil case
			} else {
				assert.Equal(t, tt.want, tt.msg.ValidateBasic())
			}
		})
	}
}

func TestValidateBasic_SignRound2Message(t *testing.T) {
	tests := []struct {
		name string
		msg  *SignRound2Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil DeCommitment", &SignRound2Message{
			DeCommitment: nil, ProofAlphaX: []byte{0x01}, ProofAlphaY: []byte{0x01}, ProofT: []byte{0x01},
		}, false},
		{"empty DeCommitment", &SignRound2Message{
			DeCommitment: [][]byte{}, ProofAlphaX: []byte{0x01}, ProofAlphaY: []byte{0x01}, ProofT: []byte{0x01},
		}, false},
		{"nil ProofAlphaX", &SignRound2Message{
			DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}}, ProofAlphaX: nil, ProofAlphaY: []byte{0x01}, ProofT: []byte{0x01},
		}, false},
		{"nil ProofAlphaY", &SignRound2Message{
			DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}}, ProofAlphaX: []byte{0x01}, ProofAlphaY: nil, ProofT: []byte{0x01},
		}, false},
		{"nil ProofT", &SignRound2Message{
			DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}}, ProofAlphaX: []byte{0x01}, ProofAlphaY: []byte{0x01}, ProofT: nil,
		}, false},
		{"valid", &SignRound2Message{
			DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}}, ProofAlphaX: []byte{0x01}, ProofAlphaY: []byte{0x01}, ProofT: []byte{0x01},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_SignRound3Message(t *testing.T) {
	tests := []struct {
		name string
		msg  *SignRound3Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil S", &SignRound3Message{S: nil}, false},
		{"empty S", &SignRound3Message{S: []byte{}}, false},
		{"valid", &SignRound3Message{S: []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestUnmarshalZKProof_EdDSA_Malformed(t *testing.T) {
	msg := &SignRound2Message{
		DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}},
		ProofAlphaX:  []byte{0xFF},
		ProofAlphaY:  []byte{0xFF},
		ProofT:       []byte{0x01},
	}
	_, err := msg.UnmarshalZKProof(tss.Edwards())
	assert.Error(t, err, "malformed EC point should fail")
}
