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

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	"github.com/AnvoIO/tss-lib/v4/crypto/commitments"
	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/test"
	"github.com/AnvoIO/tss-lib/v4/tss"
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
	return runAdversarialEdDSASigningBuilt(t, func([]keygen.LocalPartySaveData, tss.SortedPartyIDs, *big.Int) func(tss.Party, tss.Message, chan<- *tss.Error) {
		return updater
	})
}

// runAdversarialEdDSASigningBuilt is runAdversarialEdDSASigning but builds the
// malicious updater AFTER the (randomly chosen) fixture set is loaded, so a test
// can derive session-dependent values — notably this session's ssid — from the
// exact keys, parties and message the honest signers will use. Needed now that the
// round-1 commitment binds the ssid: a forged commitment must carry the real ssid
// to be accepted far enough to exercise a later check (e.g. NewECPoint).
func runAdversarialEdDSASigningBuilt(
	t *testing.T,
	build func(keys []keygen.LocalPartySaveData, signPIDs tss.SortedPartyIDs, msg *big.Int) func(tss.Party, tss.Message, chan<- *tss.Error),
) *tss.Error {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err, "should load keygen fixtures")

	msg := big.NewInt(200)
	updater := build(keys, signPIDs, msg)

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
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
	assert.Contains(t, tssErr.Error(), "de-commitment", "should abort on the de-commitment check")
	// The de-commitment C/D belong unambiguously to the malicious signer, so the
	// failure must name it. Pre-fix these branches passed no culprit, leaving an
	// honest coordinator unable to identify the griefer (un-attributable abort).
	require.True(t, len(tssErr.Culprits()) > 0, "de-commitment failure must attribute the offending signer")
	foundAdversary := false
	for _, c := range tssErr.Culprits() {
		if c.Index == adversaryIdx {
			foundAdversary = true
		}
	}
	assert.True(t, foundAdversary, "the malicious signer (index 0) must be named as the culprit")
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

	// The round-1 commitment now binds the ssid, so a consistent forged commitment
	// must carry the real ssid to be accepted past the decommit check and actually
	// reach NewECPoint(Rj). The adversary is a real signer and knows the ssid; build
	// the updater once the (random) fixture set is loaded so we can reproduce it.
	tssErr := runAdversarialEdDSASigningBuilt(t, func(keys []keygen.LocalPartySaveData, signPIDs tss.SortedPartyIDs, message *big.Int) func(tss.Party, tss.Message, chan<- *tss.Error) {
		ssid := eddsaSigningSSIDForTest(t, keys, signPIDs, adversaryIdx, message)

		// Forge a single consistent commit/decommit pair over [ssid, off-curve point].
		// Its C is injected into the adversary's round-1 message and its D into the
		// round-2 message, so the honest party's DeCommit() opens successfully, the
		// ssid check passes, and the off-curve point reaches NewECPoint(Rj).
		forged := commitments.NewHashCommitmentWithRandomness(big.NewInt(0xC0FFEE), new(big.Int).SetBytes(ssid), offX, offY)

		return test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
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
	})
	require.NotNil(t, tssErr, "protocol must reject off-curve Rj with an error, not panic")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "NewECPoint(Rj)", "off-curve Rj should be rejected at NewECPoint")
}

// eddsaSigningSSIDForTest reproduces the ssid a signer derives in round 1, using
// the production getSSID over party idx's own key/params, so a test can forge a
// session-bound commitment. It must match what the honest signers compute, so it
// mirrors the harness exactly: same curve, parties, message and session nonce.
func eddsaSigningSSIDForTest(t *testing.T, keys []keygen.LocalPartySaveData, signPIDs tss.SortedPartyIDs, idx int, message *big.Int) []byte {
	t.Helper()
	p2pCtx := tss.NewPeerContext(signPIDs)
	params, err := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[idx], len(signPIDs), testThreshold)
	require.NoError(t, err)
	params.SetSessionNonce(big.NewInt(1))
	oc := make(chan tss.Message, len(signPIDs))
	ec := make(chan *common.SignatureData, len(signPIDs))
	P := NewLocalParty(message, params, keys[idx], oc, ec).(*LocalParty)
	r1 := P.FirstRound().(*round1)
	r1.temp.ssidNonce = params.SessionNonce()
	ssid, err := r1.getSSID()
	require.NoError(t, err)
	return ssid
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
	// A corrupted S_i is caught by one of two gates: the [0, L) range check on
	// the share (when the corruption pushes S out of range, with culprit
	// attribution) or the final aggregate signature verification.
	errStr := tssErr.Error()
	assert.True(t,
		strings.Contains(errStr, "signature share S out of range") ||
			strings.Contains(errStr, "signature verification failed"),
		"corrupted Si should be rejected by the S range check or final verification, got: %s", errStr)
}
