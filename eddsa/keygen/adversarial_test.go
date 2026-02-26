// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func tamperEdDSAKeygenAnyField(wireBytes []byte, targetMsgType string, tamperFn func([]byte) []byte) []byte {
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

func runAdversarialEdDSAKeygen(t *testing.T, updater func(tss.Party, tss.Message, chan<- *tss.Error)) *tss.Error {
	t.Helper()

	threshold := testThreshold
	pIDs := tss.GenerateTestPartyIDs(testParticipants)

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	for i := 0; i < len(pIDs); i++ {
		params, pErr := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], len(pIDs), threshold)
		require.NoError(t, pErr)
		P := NewLocalParty(params, outCh, endCh).(*LocalParty)
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
				return nil
			}
		}
	}
}

func TestAdversarial_EdDSA_Keygen_CorruptedVSSShare(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperEdDSAKeygenAnyField(wireBytes, "KGRound2Message1", func(value []byte) []byte {
			var msg KGRound2Message1
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
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

	tssErr := runAdversarialEdDSAKeygen(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted VSS share")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_EdDSA_Keygen_InvalidDecommitment(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperEdDSAKeygenAnyField(wireBytes, "KGRound2Message2", func(value []byte) []byte {
			var msg KGRound2Message2
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
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

	tssErr := runAdversarialEdDSAKeygen(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted decommitment")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_EdDSA_Keygen_InvalidSchnorrProof(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperEdDSAKeygenAnyField(wireBytes, "KGRound2Message2", func(value []byte) []byte {
			var msg KGRound2Message2
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

	tssErr := runAdversarialEdDSAKeygen(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted Schnorr proof")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
	_ = common.Logger
}
