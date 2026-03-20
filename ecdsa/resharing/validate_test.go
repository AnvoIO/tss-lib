// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"testing"

	"github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
	. "github.com/AnvoIO/tss-lib/v3/ecdsa/resharing"
	"github.com/stretchr/testify/assert"
)

func makeDLNProofBytes() [][]byte {
	n := 2 + (dlnproof.Iterations * 2)
	bzs := make([][]byte, n)
	for i := range bzs {
		bzs[i] = []byte{0x01}
	}
	return bzs
}

func TestValidateBasic_DGRound1Message(t *testing.T) {
	tests := []struct {
		name string
		msg  *DGRound1Message
		want bool
	}{
		{"nil message", nil, false},
		{"nil VCommitment", &DGRound1Message{
			EcdsaPubX: []byte{0x01}, EcdsaPubY: []byte{0x01}, VCommitment: nil,
		}, false},
		{"nil EcdsaPubX", &DGRound1Message{
			EcdsaPubX: nil, EcdsaPubY: []byte{0x01}, VCommitment: []byte{0x01},
		}, false},
		{"nil EcdsaPubY", &DGRound1Message{
			EcdsaPubX: []byte{0x01}, EcdsaPubY: nil, VCommitment: []byte{0x01},
		}, false},
		{"valid", &DGRound1Message{
			EcdsaPubX: []byte{0x01}, EcdsaPubY: []byte{0x01}, VCommitment: []byte{0x01},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_DGRound2Message1(t *testing.T) {
	valid := &DGRound2Message1{
		PaillierN:  []byte{0x01},
		NTilde:     []byte{0x01},
		H1:         []byte{0x01},
		H2:         []byte{0x01},
		Dlnproof_1: makeDLNProofBytes(),
		Dlnproof_2: makeDLNProofBytes(),
	}
	assert.True(t, valid.ValidateBasic())

	tests := []struct {
		name   string
		mutate func(*DGRound2Message1)
	}{
		{"nil PaillierN", func(m *DGRound2Message1) { m.PaillierN = nil }},
		{"nil NTilde", func(m *DGRound2Message1) { m.NTilde = nil }},
		{"nil H1", func(m *DGRound2Message1) { m.H1 = nil }},
		{"nil H2", func(m *DGRound2Message1) { m.H2 = nil }},
		{"nil Dlnproof_1", func(m *DGRound2Message1) { m.Dlnproof_1 = nil }},
		{"empty Dlnproof_1", func(m *DGRound2Message1) { m.Dlnproof_1 = [][]byte{} }},
		{"nil Dlnproof_2", func(m *DGRound2Message1) { m.Dlnproof_2 = nil }},
		{"empty Dlnproof_2", func(m *DGRound2Message1) { m.Dlnproof_2 = [][]byte{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &DGRound2Message1{
				PaillierN:  []byte{0x01},
				NTilde:     []byte{0x01},
				H1:         []byte{0x01},
				H2:         []byte{0x01},
				Dlnproof_1: makeDLNProofBytes(),
				Dlnproof_2: makeDLNProofBytes(),
			}
			tt.mutate(m)
			assert.False(t, m.ValidateBasic())
		})
	}
}

func TestValidateBasic_DGRound3Message1(t *testing.T) {
	tests := []struct {
		name string
		msg  *DGRound3Message1
		want bool
	}{
		{"nil message", nil, false},
		{"nil Share", &DGRound3Message1{Share: nil}, false},
		{"empty Share", &DGRound3Message1{Share: []byte{}}, false},
		{"valid", &DGRound3Message1{Share: []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_DGRound3Message2(t *testing.T) {
	tests := []struct {
		name string
		msg  *DGRound3Message2
		want bool
	}{
		{"nil message", nil, false},
		{"nil VDecommitment", &DGRound3Message2{VDecommitment: nil}, false},
		{"empty VDecommitment", &DGRound3Message2{VDecommitment: [][]byte{}}, false},
		{"VDecommitment with empty entry", &DGRound3Message2{VDecommitment: [][]byte{{}}}, false},
		{"valid", &DGRound3Message2{VDecommitment: [][]byte{{0x01}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.msg.ValidateBasic())
		})
	}
}

func TestValidateBasic_VacuousMessages(t *testing.T) {
	// DGRound2Message2, DGRound4Message1, DGRound4Message2 always return true
	assert.True(t, (&DGRound2Message2{}).ValidateBasic())
	assert.True(t, (&DGRound4Message1{}).ValidateBasic())
	assert.True(t, (&DGRound4Message2{}).ValidateBasic())
}
