// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing_test

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
	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	. "github.com/AnvoIO/tss-lib/v4/ecdsa/resharing"
	"github.com/AnvoIO/tss-lib/v4/test"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

func tamperResharingAnyField(wireBytes []byte, targetMsgType string, tamperFn func([]byte) []byte) []byte {
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

// runAdversarialResharing runs a full resharing protocol with a malicious updater.
// adversaryIdx is an index in the OLD committee.
func runAdversarialResharing(t *testing.T, updater func(tss.Party, tss.Message, chan<- *tss.Error)) *tss.Error {
	t.Helper()

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 1, 1
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	require.NoError(t, err, "should load keygen fixtures")

	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)

	errCh := make(chan *tss.Error, len(oldPIDs)+newPCount)
	outCh := make(chan tss.Message, len(oldPIDs)+newPCount)
	endCh := make(chan *keygen.LocalPartySaveData, len(oldPIDs)+newPCount)

	for j, pID := range oldPIDs {
		params, pErr := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
		P := NewLocalParty(params, oldKeys[j], outCh, endCh).(*LocalParty)
		oldCommittee = append(oldCommittee, P)
	}
	for j, pID := range newPIDs {
		params, pErr := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
		params.SetNoProofMod()
		params.SetNoProofFac()
		save := keygen.NewLocalPartySaveData(newPCount)
		if j < len(fixtures) && len(newPIDs) <= len(fixtures) {
			save.LocalPreParams = fixtures[j].LocalPreParams
		}
		P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var reSharingEnded int32
	for {
		select {
		case err := <-errCh:
			return err

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(newCommittee[destP.Index], msg, errCh)
				}
			}

		case <-endCh:
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				return nil
			}
		}
	}
}

func TestAdversarial_Resharing_CorruptedVSSShare(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // first old committee member

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound3Message1", func(value []byte) []byte {
			var msg DGRound3Message1
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

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted VSS share in resharing")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Resharing_InvalidDecommitment(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // first old committee member

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound3Message2", func(value []byte) []byte {
			var msg DGRound3Message2
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			if len(msg.VDecommitment) > 0 && len(msg.VDecommitment[0]) > 0 {
				msg.VDecommitment[0] = test.FlipBytesAt(msg.VDecommitment[0], 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to corrupted decommitment in resharing")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

func TestAdversarial_Resharing_V0MismatchPublicKey(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // first old committee member

	// Corrupt the V commitment to make the accumulated V_0 not equal ECDSAPub.
	// We do this by corrupting the DGRound1Message's VCommitment which will cause
	// the decommit to fail or the V_0 accumulation to mismatch.
	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound1Message", func(value []byte) []byte {
			var msg DGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Corrupt the V commitment
			if len(msg.VCommitment) > 0 {
				msg.VCommitment = test.FlipBytesAt(msg.VCommitment, 0)
			}
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to V_0 != y mismatch")
	t.Logf("Error: %s", tssErr)
	assert.True(t, len(tssErr.Culprits()) > 0, "should have culprits")
}

// TestAdversarial_Resharing_SmallPaillierModulusRejected pins the round-4 modulus
// size guard added to close the resharing bit-length gap: unlike keygen
// (ecdsa/keygen/round_2.go), the new committee's round-4 validation did not enforce
// the 2048-bit floor on peer-supplied Paillier/NTilde material. The security
// rationale is that a malicious new-committee member could seat a small (though
// still validly-structured) modulus as the reshared group's long-term auxiliary
// key — later used as the Pedersen parameter for the signing MtA range proofs,
// whose hiding then breaks and leaks honest signers' witnesses.
//
// Fidelity note: the mod-proof and DLN proofs independently reject *malformed*
// material, so this wire-tamper cannot fully fail-open (a true exploit needs a
// small-but-valid Blum modulus with a valid mod-proof bound to the session ssid,
// which a wire-tamper cannot forge). What this test guarantees is that the
// dedicated size guard is present and fires with a specific "insufficient bits"
// error attributing the sender: remove the guard and this asserted behavior is
// lost (the failure degrades to the generic proof-verification error).
func TestAdversarial_Resharing_SmallPaillierModulusRejected(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // new-committee member sending DGRound2Message1

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound2Message1", func(value []byte) []byte {
			var msg DGRound2Message1
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Non-empty (so ValidateBasic passes) but far below 2048 bits.
			msg.PaillierN = new(big.Int).SetInt64(0x10001).Bytes()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "resharing must reject a sub-2048-bit Paillier modulus")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "insufficient bits", "size guard must reject on the Paillier modulus floor")
	assert.True(t, len(tssErr.Culprits()) > 0, "should attribute the culprit")
}

// TestAdversarial_Resharing_SmallNTildeRejected is the NTilde counterpart: the
// ZK-commitment auxiliary NTilde must also meet the 2048-bit floor in resharing
// round 4, matching keygen. NTilde is the security-critical field — no mod-proof
// covers it and the DLN proof bounds the h1/h2 relation, not the modulus size, so
// this guard is NTilde's only size defense in every configuration. Same fidelity
// note as above: assert the guard's specific rejection, which vanishes if removed.
func TestAdversarial_Resharing_SmallNTildeRejected(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // new-committee member sending DGRound2Message1

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound2Message1", func(value []byte) []byte {
			var msg DGRound2Message1
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			msg.NTilde = new(big.Int).SetInt64(0x10001).Bytes()
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "resharing must reject a sub-2048-bit NTilde")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "insufficient bits", "size guard must reject on the NTilde floor")
	assert.True(t, len(tssErr.Culprits()) > 0, "should attribute the culprit")
}

// TestAdversarial_Resharing_SsidSlotZeroMisattribution covers a malicious OLD-
// committee party seated at index 0 — the slot the new committee's round-2 SSID
// consistency check uses as its (unvalidated) reference. Pre-fix, a mismatch
// between the forged slot-0 ssid and the first honest old party attributed the
// abort solely to that honest party (Pj), letting the slot-0 adversary force an
// abort that frames an honest node. The fix names both parties in the
// disagreeing pair, so the actual adversary (old index 0) now appears in the
// culprit set. Remove the `anchor` culprit and this assertion fails (the slot-0
// adversary escapes attribution).
func TestAdversarial_Resharing_SsidSlotZeroMisattribution(t *testing.T) {
	setUp("info")
	adversaryIdx := 0 // OLD-committee member sending DGRound1Message

	updater := test.MaliciousUpdater(adversaryIdx, func(wireBytes []byte, from *tss.PartyID, isBroadcast bool) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound1Message", func(value []byte) []byte {
			var msg DGRound1Message
			if err := proto.Unmarshal(value, &msg); err != nil {
				return value
			}
			// Honest old parties all advertise the same deterministic ssid, so a
			// forged prefix diverges from every other slot and trips the check.
			msg.Ssid = append([]byte("forged-ssid"), msg.GetSsid()...)
			out, err := proto.Marshal(&msg)
			if err != nil {
				return value
			}
			return out
		})
	})

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "resharing must reject an inconsistent old-committee SSID")
	t.Logf("Error: %s", tssErr)
	assert.Contains(t, tssErr.Error(), "ssid mismatch", "should abort on the SSID consistency check")
	foundAdversary := false
	for _, c := range tssErr.Culprits() {
		if c.Index == adversaryIdx {
			foundAdversary = true
		}
	}
	assert.True(t, foundAdversary, "slot-0 adversary must be attributed, not just the honest mismatching party")
}

func TestAdversarial_Resharing_MultipleCorruptedSharesReportsMultipleCulprits(t *testing.T) {
	setUp("info")
	adversaries := map[int]struct{}{
		0: {},
		1: {},
	}

	tamperFn := func(wireBytes []byte) []byte {
		return tamperResharingAnyField(wireBytes, "DGRound3Message1", func(value []byte) []byte {
			var msg DGRound3Message1
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
	}

	updater := func(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
		if party.PartyID().KeyInt().Cmp(msg.GetFrom().KeyInt()) == 0 {
			return
		}
		bz, _, err := msg.WireBytes()
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		if _, ok := adversaries[msg.GetFrom().Index]; ok {
			bz = tamperFn(bz)
			if bz == nil {
				return
			}
		}
		pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		if _, err := party.Update(pMsg); err != nil {
			errCh <- err
		}
	}

	tssErr := runAdversarialResharing(t, updater)
	require.NotNil(t, tssErr, "protocol should fail due to multiple corrupted VSS shares in resharing")
	t.Logf("Error: %s", tssErr)

	culpritIndices := make(map[int]struct{}, len(tssErr.Culprits()))
	for _, culprit := range tssErr.Culprits() {
		culpritIndices[culprit.Index] = struct{}{}
	}
	assert.GreaterOrEqual(t, len(culpritIndices), 2, "should report multiple culprits")
	_, hasFirst := culpritIndices[0]
	_, hasSecond := culpritIndices[1]
	assert.True(t, hasFirst, "culprit list should include adversary 0")
	assert.True(t, hasSecond, "culprit list should include adversary 1")
}
