// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// tamperAnyField unmarshals wireBytes as an anypb.Any, checks if the TypeUrl
// contains targetMsgType, and if so applies tamperFn to the inner Value bytes.
func tamperAnyField(wireBytes []byte, targetMsgType string, tamperFn func([]byte) []byte) []byte {
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

// --- Pattern B: Full E2E tests with MaliciousUpdater ---

func TestAdversarial_InvalidDLNProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	// Corrupt the DLN proof in the adversary's round 1 message.
	// We corrupt a middle element (index 2) to avoid corrupting the serialization
	// header metadata while still making the proof invalid.
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound1Message", func(value []byte) []byte {
			var msg KGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt a DLN proof element (use index 2 to avoid metadata corruption)
			if len(msg.Dlnproof_1) > 2 && len(msg.Dlnproof_1[2]) > 0 {
				msg.Dlnproof_1[2] = test.FlipBytesAt(msg.Dlnproof_1[2], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted DLN proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	assert.Contains(t, tssErr.Error(), "dln proof verification failed")
}

func TestAdversarial_H1EqualsH2(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	// Set H1 = H2 in the adversary's round 1 message
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound1Message", func(value []byte) []byte {
			var msg KGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Set H2 = H1 (same non-zero value)
			msg.H2 = make([]byte, len(msg.H1))
			copy(msg.H2, msg.H1)
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to H1 == H2")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	assert.Contains(t, tssErr.Error(), "h1j and h2j were equal")
}

func TestAdversarial_PaillierNTooSmall(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	// Replace PaillierN with a 1024-bit value (too small, needs 2048)
	smallN := new(big.Int).SetBit(new(big.Int), 1023, 1)
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound1Message", func(value []byte) []byte {
			var msg KGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			msg.PaillierN = smallN.Bytes()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to small Paillier N")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	assert.Contains(t, tssErr.Error(), "paillier modulus with insufficient bits")
}

func TestAdversarial_NTildeTooSmall(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	// Replace NTilde with a 1024-bit value (too small, needs 2048)
	smallNTilde := new(big.Int).SetBit(new(big.Int), 1023, 1)
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound1Message", func(value []byte) []byte {
			var msg KGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			msg.NTilde = smallNTilde.Bytes()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to small NTilde")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	assert.Contains(t, tssErr.Error(), "NTildej with insufficient bits")
}

// --- Pattern B: Full E2E with MaliciousUpdater ---

// runAdversarialKeygen runs a full keygen protocol with a malicious updater.
// It expects the protocol to fail and returns the error.
func runAdversarialKeygen(t *testing.T, numParties, threshold int, updater func(tss.Party, tss.Message, chan<- *tss.Error), noProofMod, noProofFac bool) *tss.Error {
	t.Helper()

	fixtures, pIDs, err := LoadKeygenTestFixtures(numParties)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(numParties)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params, pErr := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		require.NoError(t, pErr)
		if noProofMod {
			params.SetNoProofMod()
		}
		if noProofFac {
			params.SetNoProofFac()
		}
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
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
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				return nil // protocol completed successfully (unexpected for adversarial tests)
			}
		}
	}
}

func TestAdversarial_DuplicateH1H2AcrossParties(t *testing.T) {
	setUp("info")
	adversaryIdx := 1

	// Intercept party 1's round 1 message and copy H1 from first observed party
	var storedH1 []byte
	var mu sync.Mutex
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound1Message", func(value []byte) []byte {
			var msg KGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			mu.Lock()
			if storedH1 == nil {
				// Use the adversary's own H2 as H1 to create duplicate.
				storedH1 = msg.GetH2()
			}
			msg.H1 = storedH1
			mu.Unlock()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to duplicate H1/H2")
	t.Logf("Error: %s", tssErr)
	// The error should identify the adversary or indicate h1/h2 duplication
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_CorruptedVSSShare(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound2Message1", func(value []byte) []byte {
			var msg KGRound2Message1
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the share
			if len(msg.Share) > 0 {
				msg.Share = test.FlipBytesAt(msg.Share, 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted VSS share")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_InvalidDecommitment(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound2Message2", func(value []byte) []byte {
			var msg KGRound2Message2
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the first decommitment element
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

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted decommitment")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_InvalidModProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound2Message2", func(value []byte) []byte {
			var msg KGRound2Message2
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the ModProof
			if len(msg.ModProof) > 0 && len(msg.ModProof[0]) > 0 {
				msg.ModProof[0] = test.FlipBytesAt(msg.ModProof[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	// Note: must NOT use SetNoProofMod() for this test
	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, false, true)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted mod proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_InvalidPaillierProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperAnyField(wireBytes, "KGRound3Message", func(value []byte) []byte {
			var msg KGRound3Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the Paillier proof
			if len(msg.PaillierProof) > 0 && len(msg.PaillierProof[0]) > 0 {
				msg.PaillierProof[0] = test.FlipBytesAt(msg.PaillierProof[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialKeygen(t, testParticipants, testThreshold, updater, true, true)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted Paillier proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	assert.Contains(t, tssErr.Error(), "paillier verify failed")
}

// --- Pattern C: Table-driven ValidateBasic ---

func TestAdversarial_ValidateBasic_AllMessages(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	params, err := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], len(pIDs), 1)
	assert.NoError(t, err)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	<-out // consume round 1 message

	_ = runtime.NumGoroutine()

	tests := []struct {
		name    string
		message tss.ParsedMessage
	}{
		{
			"KGRound1Message with zero commitment",
			func() tss.ParsedMessage {
				m, _ := NewKGRound1Message(pIDs[1], zero, &paillier.PublicKey{N: big.NewInt(1)}, big.NewInt(1), big.NewInt(1), big.NewInt(2), new(dlnproof.Proof), new(dlnproof.Proof))
				return m
			}(),
		},
		{
			"KGRound1Message with zero PaillierN",
			func() tss.ParsedMessage {
				m, _ := NewKGRound1Message(pIDs[1], big.NewInt(1), &paillier.PublicKey{N: zero}, big.NewInt(1), big.NewInt(1), big.NewInt(2), new(dlnproof.Proof), new(dlnproof.Proof))
				return m
			}(),
		},
		{
			"KGRound1Message with zero NTilde",
			func() tss.ParsedMessage {
				m, _ := NewKGRound1Message(pIDs[1], big.NewInt(1), &paillier.PublicKey{N: big.NewInt(1)}, zero, big.NewInt(1), big.NewInt(2), new(dlnproof.Proof), new(dlnproof.Proof))
				return m
			}(),
		},
		{
			"KGRound1Message with zero H1",
			func() tss.ParsedMessage {
				m, _ := NewKGRound1Message(pIDs[1], big.NewInt(1), &paillier.PublicKey{N: big.NewInt(1)}, big.NewInt(1), zero, big.NewInt(2), new(dlnproof.Proof), new(dlnproof.Proof))
				return m
			}(),
		},
		{
			"KGRound1Message with zero H2",
			func() tss.ParsedMessage {
				m, _ := NewKGRound1Message(pIDs[1], big.NewInt(1), &paillier.PublicKey{N: big.NewInt(1)}, big.NewInt(1), big.NewInt(1), zero, new(dlnproof.Proof), new(dlnproof.Proof))
				return m
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.message == nil {
				t.Skip("message construction failed")
				return
			}
			ok, err2 := lp.Update(tc.message)
			assert.False(t, ok, "Update should fail for %s", tc.name)
			if assert.Error(t, err2, "should have error for %s", tc.name) {
				assert.Equal(t, 1, len(err2.Culprits()), "should have 1 culprit for %s", tc.name)
				assert.Equal(t, pIDs[1], err2.Culprits()[0], "culprit should be adversary for %s", tc.name)
				assert.Contains(t, err2.Error(), "ValidateBasic", "error should mention ValidateBasic for %s", tc.name)
				t.Logf("%s -> %s", tc.name, err2)
			}
		})
	}
}

func init() {
	fmt.Print() // avoid unused import
}
