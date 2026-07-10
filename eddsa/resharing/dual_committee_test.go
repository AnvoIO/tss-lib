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

	"github.com/AnvoIO/tss-lib/v4/eddsa/keygen"
	. "github.com/AnvoIO/tss-lib/v4/eddsa/resharing"
	"github.com/AnvoIO/tss-lib/v4/test"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// TestResharing_DualCommitteeMember_SelfShareContinuity is a regression test for
// the EdDSA port of bnb-chain/tss-lib#128: a party that sits in BOTH the old and
// new committees must store the VSS share it deals to itself locally, rather than
// emitting it on the wire and clobbering its own round-3 slot with the last new
// member's share.
//
// Faithfulness requirements (why the existing E2E harness cannot catch this):
//   - ONE instance per party: the dual member is a single LocalParty, not two, so
//     the share it deals to itself is genuinely self-addressed.
//   - Self-addressed messages are dropped by the router, modeling a real transport
//     (a node does not loop network messages back to itself). This is what turns
//     the buggy "emit self-share on the wire" into a lost share.
//   - Index alignment: the dual member occupies index 0 in both committees, so the
//     old-indexed (round 3) and new-indexed (round 4) array accesses agree.
//
// Against the unfixed round-3 code the dual member's round-4 VSS verification fails
// on its own corrupted slot and resharing aborts; with the fix it completes.
func TestResharing_DualCommitteeMember_SelfShareContinuity(t *testing.T) {
	setUp("info")
	threshold, newThreshold := testThreshold, testThreshold

	// Old committee from fixtures (threshold+1 parties); index 0 has the smallest key.
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	require.NoError(t, err, "should load keygen fixtures")

	// The dual member is old party 0 (smallest key → old-committee index 0).
	dualPID := oldPIDs[0]
	dualKey := dualPID.KeyInt()

	// New committee: the dual member plus fresh members whose keys are all strictly
	// greater than the dual member's, so it also sorts to index 0 in the new committee.
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

	// Build exactly one LocalParty per unique party (keyed by KeyInt). Old members
	// (including the dual member) carry their old key data; new-only members start blank.
	partyByKey := make(map[string]*LocalParty)
	var instances []*LocalParty
	newInstance := func(pID *tss.PartyID, save keygen.LocalPartySaveData) *LocalParty {
		params, pErr := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, pID, len(oldPIDs), threshold, newPCount, newThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
		P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
		partyByKey[pID.KeyInt().String()] = P
		instances = append(instances, P)
		return P
	}
	for j, pID := range oldPIDs {
		newInstance(pID, oldKeys[j]) // dual member is created here, once
	}
	for _, pID := range newPIDs {
		if _, exists := partyByKey[pID.KeyInt().String()]; exists {
			continue // dual member already created as an old member
		}
		newInstance(pID, keygen.NewLocalPartySaveData(newPCount))
	}

	for _, P := range instances {
		go func(P *LocalParty) {
			if startErr := P.Start(); startErr != nil {
				errCh <- startErr
			}
		}(P)
	}

	// Router: deliver each message to the single instance of every intended recipient,
	// EXCEPT the sender itself (a real transport does not echo self-addressed messages).
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
	timeout := time.After(60 * time.Second)
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
