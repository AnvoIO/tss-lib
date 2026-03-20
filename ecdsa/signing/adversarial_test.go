// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func tamperSignAnyField(wireBytes []byte, targetMsgType string, tamperFn func([]byte) []byte) []byte {
	var anyMsg anypb.Any
	if err := proto.Unmarshal(wireBytes, &anyMsg); err != nil {
		return wireBytes
	}
	if !strings.Contains(anyMsg.TypeUrl, targetMsgType) {
		return wireBytes
	}
	anyMsg.Value = tamperFn(anyMsg.Value)
	out, err := proto.Marshal(&anyMsg)
	if err != nil {
		return wireBytes
	}
	return out
}

// runAdversarialSigning runs a full signing protocol with a malicious updater.
// It expects the protocol to fail and returns the error.
func runAdversarialSigning(t *testing.T, updater func(tss.Party, tss.Message, chan<- *tss.Error)) *tss.Error {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err, "should load keygen fixtures")

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		require.NoError(t, pErr)
		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
	for {
		select {
		case err := <-errCh:
			return err

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return nil
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				return nil
			}
		}
	}
}

func TestAdversarial_Sign_InvalidMTARangeProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound1Message1", func(value []byte) []byte {
			var msg SignRound1Message1
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the RangeProofAlice
			if len(msg.RangeProofAlice) > 0 && len(msg.RangeProofAlice[0]) > 0 {
				msg.RangeProofAlice[0] = test.FlipBytesAt(msg.RangeProofAlice[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted MTA range proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Sign_CorruptedProofBob(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound2Message", func(value []byte) []byte {
			var msg SignRound2Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the ProofBob
			if len(msg.ProofBob) > 0 && len(msg.ProofBob[0]) > 0 {
				msg.ProofBob[0] = test.FlipBytesAt(msg.ProofBob[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted ProofBob")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Sign_InvalidGammaDecommitment(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound4Message", func(value []byte) []byte {
			var msg SignRound4Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the DeCommitment
			if len(msg.DeCommitment) > 0 && len(msg.DeCommitment[0]) > 0 {
				msg.DeCommitment[0] = test.FlipBytesAt(msg.DeCommitment[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted gamma decommitment")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Sign_InvalidSchnorrProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound4Message", func(value []byte) []byte {
			var msg SignRound4Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the Schnorr proof T value
			if len(msg.ProofT) > 0 {
				msg.ProofT = test.FlipBytesAt(msg.ProofT, 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted Schnorr proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Sign_InvalidZKVProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound6Message", func(value []byte) []byte {
			var msg SignRound6Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the VProof T value
			if len(msg.VProofT) > 0 {
				msg.VProofT = test.FlipBytesAt(msg.VProofT, 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted ZKV proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Sign_CorruptedSi(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperSignAnyField(wireBytes, "SignRound9Message", func(value []byte) []byte {
			var msg SignRound9Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt Si
			if len(msg.S) > 0 {
				msg.S = test.FlipBytesAt(msg.S, 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialSigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted Si")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "signature verification failed")
}

func TestAdversarial_Sign_ValidateBasic_AllMessages(t *testing.T) {
	setUp("debug")

	tests := []struct {
		name    string
		content tss.MessageContent
	}{
		{"SignRound1Message1 nil C", &SignRound1Message1{C: nil, RangeProofAlice: make([][]byte, 11)}},
		{"SignRound1Message2 nil Commitment", &SignRound1Message2{Commitment: nil}},
		{"SignRound2Message nil C1", &SignRound2Message{C1: nil, C2: []byte{1}, ProofBob: make([][]byte, 10), ProofBobWc: make([][]byte, 12)}},
		{"SignRound3Message nil Theta", &SignRound3Message{Theta: nil}},
		{"SignRound4Message nil DeCommitment", &SignRound4Message{DeCommitment: nil, ProofAlphaX: []byte{1}, ProofAlphaY: []byte{1}, ProofT: []byte{1}}},
		{"SignRound5Message nil Commitment", &SignRound5Message{Commitment: nil}},
		{"SignRound6Message nil DeCommitment", &SignRound6Message{DeCommitment: nil, ProofAlphaX: []byte{1}, ProofAlphaY: []byte{1}, ProofT: []byte{1}, VProofAlphaX: []byte{1}, VProofAlphaY: []byte{1}, VProofT: []byte{1}, VProofU: []byte{1}}},
		{"SignRound7Message nil Commitment", &SignRound7Message{Commitment: nil}},
		{"SignRound8Message nil DeCommitment", &SignRound8Message{DeCommitment: nil}},
		{"SignRound9Message nil S", &SignRound9Message{S: nil}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok := tc.content.ValidateBasic()
			assert.False(t, ok, "ValidateBasic should fail for %s", tc.name)
		})
	}
}
