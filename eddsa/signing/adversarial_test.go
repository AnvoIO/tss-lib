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
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/crypto/commitments"
	"github.com/AnvoIO/tss-lib/v3/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func tamperEdDSASignAnyField(wireBytes []byte, targetMsgType string, tamperFn func([]byte) []byte) []byte {
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

func runAdversarialEdDSASigning(t *testing.T, updater func(tss.Party, tss.Message, chan<- *tss.Error)) *tss.Error {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err, "should load keygen fixtures")

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	msg := big.NewInt(200)
	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		require.NoError(t, pErr)
		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
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

func TestAdversarial_EdDSA_Sign_InvalidDecommitment(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperEdDSASignAnyField(wireBytes, "SignRound2Message", func(value []byte) []byte {
			var msg SignRound2Message
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

	tssErr := runAdversarialEdDSASigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted decommitment")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0 || strings.Contains(tssErr.Error(), "de-commitment"), "should identify failure")
}

// TestAdversarial_EdDSA_Sign_OffCurveRj is a regression test for SRC-2026-644:
// round 3 must reject an off-curve Rj returned by NewECPoint *before* calling
// EightInvEight() on it, otherwise an honest signer panics on a nil receiver
// (remote DoS). Unlike the InvalidDecommitment test — which corrupts the
// decommitment so DeCommit() fails early — this sends a *consistent*
// commitment/decommitment pair over an off-curve point, so DeCommit() succeeds
// and NewECPoint(Rj) is the gate that must reject it.
func TestAdversarial_EdDSA_Sign_OffCurveRj(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	// (1, 1) is not on the Edwards curve; assert that as a precondition so the
	// test fails loudly if the curve check ever changes.
	offX, offY := big.NewInt(1), big.NewInt(1)
	if _, err := crypto.NewECPoint(tss.Edwards(), offX, offY); err == nil {
		t.Fatal("precondition failed: (1,1) must be off the Edwards curve")
	}

	// Forge a single consistent commit/decommit pair over the off-curve point.
	// Its C is injected into the adversary's round-1 message and its D into the
	// round-2 message, so the honest party's DeCommit() opens successfully.
	forged := commitments.NewHashCommitmentWithRandomness(big.NewInt(0xC0FFEE), offX, offY)

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		wireBytes = tamperEdDSASignAnyField(wireBytes, "SignRound1Message", func(value []byte) []byte {
			var msg SignRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			msg.Commitment = forged.C.Bytes()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
		wireBytes = tamperEdDSASignAnyField(wireBytes, "SignRound2Message", func(value []byte) []byte {
			var msg SignRound2Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			msg.DeCommitment = common.BigIntsToBytes(forged.D)
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
		return wireBytes
	})

	tssErr := runAdversarialEdDSASigning(t, updater)
	require.NotNil(t, tssErr, "protocol must reject off-curve Rj with an error, not panic")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "NewECPoint(Rj)", "off-curve Rj should be rejected at NewECPoint")
}

func TestAdversarial_EdDSA_Sign_CorruptedSi(t *testing.T) {
	setUp("info")
	adversaryIdx := 0

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperEdDSASignAnyField(wireBytes, "SignRound3Message", func(value []byte) []byte {
			var msg SignRound3Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
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

	tssErr := runAdversarialEdDSASigning(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted Si")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "signature verification failed")
}
