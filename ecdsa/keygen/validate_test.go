// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
)

func TestValidateBasic_KGRound2Message1(t *testing.T) {
	tests := []struct {
		name string
		msg  *KGRound2Message1
		want bool
	}{
		{"nil message", nil, false},
		{"nil Share", &KGRound2Message1{Share: nil}, false},
		{"empty Share", &KGRound2Message1{Share: []byte{}}, false},
		{"valid Share", &KGRound2Message1{Share: []byte{0x01}}, true},
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

func TestValidateBasic_KGRound3Message(t *testing.T) {
	validProof := make([][]byte, 13) // paillier.ProofIters = 13
	for i := range validProof {
		validProof[i] = []byte{0x01}
	}

	tests := []struct {
		name string
		msg  *KGRound3Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil PaillierProof", &KGRound3Message{PaillierProof: nil}, false},
		{"empty PaillierProof", &KGRound3Message{PaillierProof: [][]byte{}}, false},
		{"wrong length PaillierProof", &KGRound3Message{PaillierProof: [][]byte{{0x01}}}, false},
		{"valid PaillierProof", &KGRound3Message{PaillierProof: validProof}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestUnmarshalDLNProof_Errors(t *testing.T) {
	tests := []struct {
		name string
		msg  *KGRound1Message
	}{
		{"nil DLN proof 1", &KGRound1Message{
			Commitment: []byte{0x01},
			PaillierN:  []byte{0x01},
			NTilde:     []byte{0x01},
			H1:         []byte{0x01},
			H2:         []byte{0x01},
			Dlnproof_1: nil,
			Dlnproof_2: makeDLNProofBytes(),
		}},
		{"empty DLN proof 1", &KGRound1Message{
			Commitment: []byte{0x01},
			PaillierN:  []byte{0x01},
			NTilde:     []byte{0x01},
			H1:         []byte{0x01},
			H2:         []byte{0x01},
			Dlnproof_1: [][]byte{},
			Dlnproof_2: makeDLNProofBytes(),
		}},
		{"nil DLN proof 2", &KGRound1Message{
			Commitment: []byte{0x01},
			PaillierN:  []byte{0x01},
			NTilde:     []byte{0x01},
			H1:         []byte{0x01},
			H2:         []byte{0x01},
			Dlnproof_1: makeDLNProofBytes(),
			Dlnproof_2: nil,
		}},
		{"empty DLN proof 2", &KGRound1Message{
			Commitment: []byte{0x01},
			PaillierN:  []byte{0x01},
			NTilde:     []byte{0x01},
			H1:         []byte{0x01},
			H2:         []byte{0x01},
			Dlnproof_1: makeDLNProofBytes(),
			Dlnproof_2: [][]byte{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, tt.msg.ValidateBasic())
		})
	}
}

func TestUnmarshalDLNProof1_NilInput(t *testing.T) {
	msg := &KGRound1Message{Dlnproof_1: nil}
	_, err := msg.UnmarshalDLNProof1()
	assert.Error(t, err)
}

func TestUnmarshalDLNProof1_EmptyInput(t *testing.T) {
	msg := &KGRound1Message{Dlnproof_1: [][]byte{}}
	_, err := msg.UnmarshalDLNProof1()
	assert.Error(t, err)
}

func TestUnmarshalDLNProof2_NilInput(t *testing.T) {
	msg := &KGRound1Message{Dlnproof_2: nil}
	_, err := msg.UnmarshalDLNProof2()
	assert.Error(t, err)
}

func TestUnmarshalDLNProof2_EmptyInput(t *testing.T) {
	msg := &KGRound1Message{Dlnproof_2: [][]byte{}}
	_, err := msg.UnmarshalDLNProof2()
	assert.Error(t, err)
}

func TestUnmarshalFacProof_EmptyInput(t *testing.T) {
	msg := &KGRound2Message1{FacProof: [][]byte{}}
	_, err := msg.UnmarshalFacProof()
	assert.Error(t, err)
}

func TestUnmarshalModProof_EmptyInput(t *testing.T) {
	msg := &KGRound2Message2{ModProof: [][]byte{}}
	_, err := msg.UnmarshalModProof()
	assert.Error(t, err)
}

// makeDLNProofBytes creates a valid-length DLN proof byte slice for testing.
func makeDLNProofBytes() [][]byte {
	n := 2 + (dlnproof.Iterations * 2)
	bzs := make([][]byte, n)
	for i := range bzs {
		bzs[i] = []byte{0x01}
	}
	return bzs
}
