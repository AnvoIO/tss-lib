// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/AnvoIO/tss-lib/v3/ecdsa/keygen"
	. "github.com/AnvoIO/tss-lib/v3/ecdsa/resharing"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// TestResharing_DualCommitteeMember_SelfShareContinuity is the ECDSA counterpart
// of the EdDSA dual-committee regression test. It exercises the in-production
// bnb-chain/tss-lib#128 fix: a party that sits in BOTH the old and new committees
// must store the VSS share it deals to itself locally, rather than emitting it on
// the wire — where a real transport drops the self-addressed message and the
// party's own round-3 slot ends up holding the last new member's share, failing
// its round-4 VSS verification.
//
// Faithfulness requirements (why the standard E2E harness cannot catch this):
//   - ONE instance per party: the dual member is a single LocalParty, so the share
//     it deals to itself is genuinely self-addressed.
//   - The router drops self-addressed messages, modeling a real transport
//     (SharedPartyUpdater also skips from==self).
//   - Index alignment: the dual member occupies index 0 in both committees, so the
//     old-indexed (round 3) and new-indexed (round 4) array accesses agree.
//
// ECDSA-specific wrinkle vs. the EdDSA test: round 2 sets up Paillier material, so
// the new-committee members run with SetNoProofMod/SetNoProofFac and carry fixture
// pre-params (mirroring the ecdsa/resharing adversarial harness) to keep the test
// fast. Each new-committee member needs a DISTINCT pre-param so the round-4 h1/h2
// uniqueness check passes. Because the fixture keys are consecutive integers, the
// fresh members' keys collide with the other old members and every old party
// becomes dual — so the old committee owns fixtures 0..len(old)-1 and the fresh
// members draw from the fixtures beyond that range.
//
// Against the unfixed round-3 code the dual member's round-4 VSS verification fails
// on its own clobbered slot and resharing aborts; with the fix it completes.
func TestResharing_DualCommitteeMember_SelfShareContinuity(t *testing.T) {
	setUp("info")
	threshold, newThreshold := testThreshold, testThreshold

	// Old committee from fixtures (threshold+1 parties); index 0 has the smallest key.
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	require.NoError(t, err, "should load keygen fixtures")

	// Distinct pre-params for the fresh new-committee members (avoids slow
	// safe-prime generation and keeps every new member's h1/h2 unique).
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	require.NoError(t, err, "should load pre-param fixtures")

	// The dual member is old party 0 (smallest key → old-committee index 0).
	dualPID := oldPIDs[0]
	dualKey := dualPID.KeyInt()

	// New committee: the dual member plus fresh members whose keys are all strictly
	// greater, so the dual member also sorts to index 0 in the new committee.
	newPCount := testParticipants
	newRaw := tss.UnSortedPartyIDs{dualPID}
	for k := 1; k < newPCount; k++ {
		key := new(big.Int).Add(dualKey, big.NewInt(int64(k)))
		newRaw = append(newRaw, tss.NewPartyID(fmt.Sprintf("new-%d", k), fmt.Sprintf("NP[%d]", k), key))
	}
	newPIDs := tss.SortPartyIDs(newRaw)
	require.Equal(t, 0, newPIDs[0].Index, "sorted new committee should be 0-indexed")
	require.Equal(t, 0, dualPID.KeyInt().Cmp(newPIDs[0].KeyInt()),
		"dual member must occupy index 0 in the new committee (index alignment)")
	require.Less(t, 0, newPCount-1, "dual member must not be the last new index, or the bug cannot trigger")

	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	errCh := make(chan *tss.Error, len(oldPIDs)+newPCount)
	outCh := make(chan tss.Message, (len(oldPIDs)+newPCount)*8)
	endCh := make(chan *keygen.LocalPartySaveData, len(oldPIDs)+newPCount)

	// Exactly one LocalParty per unique party (keyed by KeyInt). New-committee
	// members run with proof-gating off; the dual member is in the new committee too.
	partyByKey := make(map[string]*LocalParty)
	var instances []*LocalParty
	newInstance := func(pID *tss.PartyID, save keygen.LocalPartySaveData) *LocalParty {
		params, pErr := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, len(oldPIDs), threshold, newPCount, newThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
		params.SetNoProofMod()
		params.SetNoProofFac()
		P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
		partyByKey[pID.KeyInt().String()] = P
		instances = append(instances, P)
		return P
	}
	for j, pID := range oldPIDs {
		newInstance(pID, oldKeys[j]) // dual member (old idx 0) created here, once, with its own pre-params
	}
	// The fixture keys are consecutive integers, so the fresh members' keys
	// (dualKey+1, +2, …) coincide with the other old members: every old party ends
	// up in the new committee too (an even stronger, all-dual scenario). The old
	// committee therefore occupies fixtures 0..len(oldPIDs)-1, so the genuinely
	// fresh members must draw pre-params from beyond that range to keep every
	// new-committee member's h1/h2 unique (the round-4 uniqueness check).
	fixIdx := len(oldPIDs)
	for _, pID := range newPIDs {
		if _, exists := partyByKey[pID.KeyInt().String()]; exists {
			continue // this key is already an (old, now dual) committee member
		}
		save := keygen.NewLocalPartySaveData(newPCount)
		require.Less(t, fixIdx, len(fixtures), "not enough fixture pre-params for the new committee")
		save.LocalPreParams = fixtures[fixIdx].LocalPreParams
		fixIdx++
		newInstance(pID, save)
	}

	for _, P := range instances {
		go func(P *LocalParty) {
			if startErr := P.Start(); startErr != nil {
				errCh <- startErr
			}
		}(P)
	}

	// Router: deliver each message to the single instance of every intended
	// recipient, EXCEPT the sender itself (a real transport does not echo
	// self-addressed messages — the crux of the #128 scenario).
	route := func(msg tss.Message) {
		from := msg.GetFrom()
		for _, dest := range msg.GetTo() {
			if dest.KeyInt().Cmp(from.KeyInt()) == 0 {
				continue // drop self-addressed message
			}
			if inst, ok := partyByKey[dest.KeyInt().String()]; ok {
				go test.SharedPartyUpdater(inst, msg, errCh)
			}
		}
	}

	var ended int32
	timeout := time.After(120 * time.Second)
	for {
		select {
		case rErr := <-errCh:
			t.Fatalf("resharing with a dual-committee member must not error: %s", rErr)
		case msg := <-outCh:
			if msg.GetTo() == nil {
				t.Fatal("unexpected nil destination during resharing")
			}
			route(msg)
		case <-endCh:
			if atomic.AddInt32(&ended, 1) == int32(len(instances)) {
				t.Logf("resharing completed for all %d parties (incl. the dual-committee member)", len(instances))
				return
			}
		case <-timeout:
			t.Fatalf("timed out: only %d/%d parties finished — the dual member likely self-aborted at round 4 (unfixed #128)", atomic.LoadInt32(&ended), len(instances))
		}
	}
}
