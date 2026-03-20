// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/crypto/mta"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestUnmarshalRangeProofAlice_WrongPartCount(t *testing.T) {
	tests := []struct {
		name string
		bzs  [][]byte
	}{
		{"nil", nil},
		{"empty", [][]byte{}},
		{"too few parts", make([][]byte, mta.RangeProofAliceBytesParts-1)},
		{"too many parts", make([][]byte, mta.RangeProofAliceBytesParts+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mta.RangeProofAliceFromBytes(tt.bzs)
			assert.Error(t, err)
		})
	}
}

func TestUnmarshalProofBob_WrongPartCount(t *testing.T) {
	tests := []struct {
		name string
		bzs  [][]byte
	}{
		{"nil", nil},
		{"empty", [][]byte{}},
		{"too few parts", make([][]byte, mta.ProofBobBytesParts-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mta.ProofBobFromBytes(tt.bzs)
			assert.Error(t, err)
		})
	}
}

func TestUnmarshalProofBobWC_WrongPartCount(t *testing.T) {
	tests := []struct {
		name string
		bzs  [][]byte
	}{
		{"nil", nil},
		{"empty", [][]byte{}},
		{"too few parts", make([][]byte, mta.ProofBobWCBytesParts-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mta.ProofBobWCFromBytes(tss.S256(), tt.bzs)
			assert.Error(t, err)
		})
	}
}

func TestUnmarshalZKProof_Round4_Malformed(t *testing.T) {
	msg := &SignRound4Message{
		DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}},
		ProofAlphaX:  []byte{0xFF},
		ProofAlphaY:  []byte{0xFF},
		ProofT:       []byte{0x01},
	}
	_, err := msg.UnmarshalZKProof(tss.S256())
	assert.Error(t, err, "malformed EC point should fail")
}

func TestUnmarshalZKProof_Round6_Malformed(t *testing.T) {
	msg := &SignRound6Message{
		DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}},
		ProofAlphaX:  []byte{0xFF},
		ProofAlphaY:  []byte{0xFF},
		ProofT:       []byte{0x01},
		VProofAlphaX: []byte{0xFF},
		VProofAlphaY: []byte{0xFF},
		VProofT:      []byte{0x01},
		VProofU:      []byte{0x01},
	}
	_, err := msg.UnmarshalZKProof(tss.S256())
	assert.Error(t, err, "malformed EC point should fail")
}

func TestUnmarshalZKVProof_Round6_Malformed(t *testing.T) {
	msg := &SignRound6Message{
		DeCommitment: [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}},
		ProofAlphaX:  []byte{0xFF},
		ProofAlphaY:  []byte{0xFF},
		ProofT:       []byte{0x01},
		VProofAlphaX: []byte{0xFF},
		VProofAlphaY: []byte{0xFF},
		VProofT:      []byte{0x01},
		VProofU:      []byte{0x01},
	}
	_, err := msg.UnmarshalZKVProof(tss.S256())
	assert.Error(t, err, "malformed EC point should fail")
}
