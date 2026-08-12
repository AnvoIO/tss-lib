// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/AnvoIO/tss-lib/v4/crypto"
	"github.com/AnvoIO/tss-lib/v4/crypto/vss"
	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	. "github.com/AnvoIO/tss-lib/v4/ecdsa/resharing"
	"github.com/AnvoIO/tss-lib/v4/test"
	"github.com/AnvoIO/tss-lib/v4/tss"
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
//     old-indexed (round 3) and new-indexed (round 4) array accesses agree. The
//     MISALIGNED case is covered separately by TestResharing_DualCommitteeMember_MisalignedIndex.
//
// ECDSA-specific wrinkle vs. the EdDSA test: round 2 sets up Paillier material, so
// the new-committee members request the test-only SetNoProofMod/SetNoProofFac
// gates and carry fixture pre-params (mirroring the ecdsa/resharing adversarial
// harness). Secure builds intentionally leave the proofs enabled, while the
// fixtures still avoid slow safe-prime generation. Each new-committee member needs
// a DISTINCT pre-param so the round-4 h1/h2 uniqueness check passes. Because the
// fixture keys are consecutive integers, the
// fresh members' keys collide with the other old members and every old party
// becomes dual — so the old committee owns fixtures 0..len(old)-1 and the fresh
// members draw from the fixtures beyond that range.
//
// Against the unfixed round-3 code the dual member's round-4 VSS verification fails
// on its own clobbered slot and resharing aborts; with the fix it completes AND the
// reshared shares reconstruct the ORIGINAL key (see assertReshareCorrect — completion
// alone is not proof of correctness).
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
	// members request test-only proof gating; secure builds keep proofs enabled.
	// The dual member is in the new committee too.
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

	newKeys := driveReshareToDone(t, instances, partyByKey, outCh, endCh, errCh, newPCount)

	// Completion is necessary but NOT sufficient: prove the reshared shares are a
	// valid sharing of the SAME key, exercising the dual member's self-dealt share
	// (new-index 0 in this aligned scenario).
	assertReshareCorrect(t, oldKeys[0].ECDSAPub, newKeys, newThreshold, 0)
}

// TestResharing_DualCommitteeMember_MisalignedIndex covers the case the aligned
// test deliberately excludes: a dual member whose OLD-committee index differs from
// its NEW-committee index. Production overlap does not guarantee alignment. The
// #128 self-share store writes the round-3 slot by the sender's OLD index while
// round-4 verification is new-indexed, so a latent conflation of the two index
// spaces would corrupt the dual member's slot HERE but pass the aligned test. The
// dual member is old-index 0 but new-index `belowCount` (two fresh members are
// seeded with keys just below the dual's, pushing it up the sorted new committee).
func TestResharing_DualCommitteeMember_MisalignedIndex(t *testing.T) {
	setUp("info")
	threshold, newThreshold := testThreshold, testThreshold

	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	require.NoError(t, err, "should load keygen fixtures")
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	require.NoError(t, err, "should load pre-param fixtures")

	dualPID := oldPIDs[0] // old-index 0 (smallest old key)
	dualKey := dualPID.KeyInt()

	const belowCount = 2 // fresh new members with keys < dualKey → dual lands at new-index belowCount
	newPCount := testParticipants

	// Only the dual member overlaps. Seed `belowCount` fresh members just under the
	// dual's key and the rest well above every old key (so no other old member is
	// accidentally pulled into the new committee).
	newRaw := tss.UnSortedPartyIDs{dualPID}
	for k := 1; k <= belowCount; k++ {
		key := new(big.Int).Sub(dualKey, big.NewInt(int64(k)))
		newRaw = append(newRaw, tss.NewPartyID(fmt.Sprintf("below-%d", k), fmt.Sprintf("BP[%d]", k), key))
	}
	aboveBase := new(big.Int).Add(dualKey, big.NewInt(1_000_000))
	for k := 1; k <= newPCount-1-belowCount; k++ {
		key := new(big.Int).Add(aboveBase, big.NewInt(int64(k)))
		newRaw = append(newRaw, tss.NewPartyID(fmt.Sprintf("above-%d", k), fmt.Sprintf("AP[%d]", k), key))
	}
	newPIDs := tss.SortPartyIDs(newRaw)

	dualNewIdx := -1
	for i, p := range newPIDs {
		if p.KeyInt().Cmp(dualKey) == 0 {
			dualNewIdx = i
		}
	}
	require.Equal(t, belowCount, dualNewIdx, "dual member must sit at new-index == belowCount")
	require.NotEqual(t, 0, dualNewIdx, "scenario is only meaningful when old-index (0) != new-index")

	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	errCh := make(chan *tss.Error, len(oldPIDs)+newPCount)
	outCh := make(chan tss.Message, (len(oldPIDs)+newPCount)*8)
	endCh := make(chan *keygen.LocalPartySaveData, len(oldPIDs)+newPCount)

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
	// Old members: the dual (old idx 0) carries its old key data (incl. its
	// pre-params, fixtures[0]).
	for j, pID := range oldPIDs {
		newInstance(pID, oldKeys[j])
	}
	// Fresh new members draw DISTINCT pre-params from fixtures beyond the dual's,
	// so every new-committee member's round-4 h1/h2 is unique.
	fixIdx := 1
	for _, pID := range newPIDs {
		if _, exists := partyByKey[pID.KeyInt().String()]; exists {
			continue // the dual member, already created
		}
		save := keygen.NewLocalPartySaveData(newPCount)
		require.Less(t, fixIdx, len(fixtures), "not enough fixture pre-params for the new committee")
		save.LocalPreParams = fixtures[fixIdx].LocalPreParams
		fixIdx++
		newInstance(pID, save)
	}

	newKeys := driveReshareToDone(t, instances, partyByKey, outCh, endCh, errCh, newPCount)

	// Reconstruct through the dual member's self-dealt share at its NEW index.
	assertReshareCorrect(t, oldKeys[0].ECDSAPub, newKeys, newThreshold, dualNewIdx)
}

// driveReshareToDone starts every instance, routes messages between the single
// instance of each party while DROPPING self-addressed messages (a real transport
// does not loop a node's own messages back — the crux of the #128 scenario), and
// returns the new-committee save data indexed by new-committee index.
//
// It is loud: any party error fails immediately with the underlying cause, and a
// stall fails with the finished/expected count and the #128 hypothesis rather than
// hanging silently.
func driveReshareToDone(
	t *testing.T,
	instances []*LocalParty,
	partyByKey map[string]*LocalParty,
	outCh chan tss.Message,
	endCh chan *keygen.LocalPartySaveData,
	errCh chan *tss.Error,
	newPCount int,
) []keygen.LocalPartySaveData {
	t.Helper()
	for _, P := range instances {
		go func(P *LocalParty) {
			if startErr := P.Start(); startErr != nil {
				errCh <- startErr
			}
		}(P)
	}
	route := func(msg tss.Message) {
		from := msg.GetFrom()
		for _, dest := range msg.GetTo() {
			if dest.KeyInt().Cmp(from.KeyInt()) == 0 {
				continue // drop self-addressed message (real transport does not echo)
			}
			if inst, ok := partyByKey[dest.KeyInt().String()]; ok {
				go test.SharedPartyUpdater(inst, msg, errCh)
			}
		}
	}
	newKeys := make([]keygen.LocalPartySaveData, newPCount)
	var ended int32
	// Idle-progress watchdog: a healthy run has continuous message flow, so a
	// prolonged silence means a party is stuck waiting for a message that will
	// never arrive — the #128 failure mode (a dual member lost its self-dealt
	// share). Resetting on every message/completion surfaces a stall in seconds
	// instead of relying only on the process-wide deadline. Secure macOS ARM64 CI
	// can spend more than 30 seconds in proof computation without emitting a wire
	// message, so leave enough headroom for healthy compute-bound rounds while a
	// regressed self-share still stalls indefinitely.
	const idleTimeout = 2 * time.Minute
	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()
	bumpIdle := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(idleTimeout)
	}
	for {
		select {
		case rErr := <-errCh:
			t.Fatalf("resharing with a dual-committee member must not error: %s", rErr)
		case msg := <-outCh:
			bumpIdle()
			if msg.GetTo() == nil {
				t.Fatal("unexpected nil destination during resharing")
			}
			route(msg)
		case save := <-endCh:
			bumpIdle()
			if save.Xi != nil { // a new-committee share; old-only members deliver Xi==nil
				idx, oErr := save.OriginalIndex()
				require.NoError(t, oErr, "new save data must resolve its committee index")
				newKeys[idx] = *save
			}
			if atomic.AddInt32(&ended, 1) == int32(len(instances)) {
				t.Logf("resharing completed for all %d parties (incl. the dual-committee member)", len(instances))
				return newKeys
			}
		case <-idle.C:
			t.Fatalf("resharing STALLED (no progress for %s): only %d/%d parties finished — a dual member likely lost its self-dealt share (regressed #128 fix)", idleTimeout, atomic.LoadInt32(&ended), len(instances))
		}
	}
}

// assertReshareCorrect fails the test unless the reshared keys pass the
// correctness oracle (checkReshareCorrect).
func assertReshareCorrect(t *testing.T, oldPub *crypto.ECPoint, newKeys []keygen.LocalPartySaveData, newThreshold, mustIncludeNewIdx int) {
	t.Helper()
	require.NoError(t, checkReshareCorrect(oldPub, newKeys, newThreshold, mustIncludeNewIdx))
}

// checkReshareCorrect is the correctness oracle. Reaching endCh proves only that
// the protocol did not abort; it does NOT prove the reshared shares are right — a
// silently corrupted self-dealt share would still "finish". This returns an error
// (nil on success) for the first violation of the real resharing invariant: the
// new-committee keys are a valid (newThreshold)-of-n sharing of the SAME group
// public key as before. Specifically:
//   - every new party carries a share and the UNCHANGED group public key;
//   - each published BigXj equals Xi·G (per-share commitment self-consistency);
//   - any newThreshold+1 shares INCLUDING the dual member (mustIncludeNewIdx)
//     Lagrange-reconstruct the original private key behind oldPub.
//
// It returns an error rather than failing a *testing.T so the negative control
// TestDualCommitteeOracle_DetectsCorruptedShare can assert the oracle actually
// REJECTS a corrupted share — proving these checks have teeth.
func checkReshareCorrect(oldPub *crypto.ECPoint, newKeys []keygen.LocalPartySaveData, newThreshold, mustIncludeNewIdx int) error {
	ec := tss.S256()
	for j := range newKeys {
		key := newKeys[j]
		if key.Xi == nil {
			return fmt.Errorf("new party %d produced no share", j)
		}
		if !key.ECDSAPub.Equals(oldPub) {
			return fmt.Errorf("new party %d: group public key changed under resharing", j)
		}
		if !key.BigXj[j].Equals(crypto.ScalarBaseMult(ec, key.Xi)) {
			return fmt.Errorf("new party %d: BigXj != Xi·G (share/commitment mismatch)", j)
		}
	}
	idxs := reconstructSubset(len(newKeys), newThreshold+1, mustIncludeNewIdx)
	shares := make(vss.Shares, 0, len(idxs))
	for _, j := range idxs {
		shares = append(shares, &vss.Share{Threshold: newThreshold, ID: newKeys[j].ShareID, Share: newKeys[j].Xi})
	}
	secret, err := shares.ReConstruct(ec)
	if err != nil {
		return fmt.Errorf("reconstruction from newThreshold+1 new shares failed: %w", err)
	}
	if !crypto.ScalarBaseMult(ec, secret).Equals(oldPub) {
		return fmt.Errorf("newThreshold+1 new shares (incl. dual member at new-index %d) do not reconstruct the original key", mustIncludeNewIdx)
	}
	return nil
}

// TestDualCommitteeOracle_DetectsCorruptedShare is the fail-open negative control
// for the oracle itself: it feeds checkReshareCorrect an honest sharing and then a
// deliberately corrupted dual-member share, asserting the honest set passes and
// that BOTH the per-share commitment gate and the reconstruction gate reject the
// corruption. Without it, a future edit could silently weaken the oracle into a
// no-op that the dual-committee tests would never notice.
func TestDualCommitteeOracle_DetectsCorruptedShare(t *testing.T) {
	ec := tss.S256()
	const n, threshold, dualIdx = testParticipants, testThreshold, 2

	secret, err := rand.Int(rand.Reader, ec.Params().N)
	require.NoError(t, err)
	pub := crypto.ScalarBaseMult(ec, secret)

	ids := make([]*big.Int, n)
	for i := range ids {
		ids[i] = big.NewInt(int64(i + 1))
	}
	_, shares, err := vss.Create(ec, threshold, secret, ids, rand.Reader)
	require.NoError(t, err)

	build := func() []keygen.LocalPartySaveData {
		nk := make([]keygen.LocalPartySaveData, n)
		for j := 0; j < n; j++ {
			sd := keygen.NewLocalPartySaveData(n)
			sd.Xi = shares[j].Share
			sd.ShareID = shares[j].ID
			sd.ECDSAPub = pub
			sd.Ks = ids
			for k := 0; k < n; k++ {
				sd.BigXj[k] = crypto.ScalarBaseMult(ec, shares[k].Share)
			}
			nk[j] = sd
		}
		return nk
	}

	// The honest sharing passes.
	require.NoError(t, checkReshareCorrect(pub, build(), threshold, dualIdx),
		"honest sharing must pass the oracle")

	// Xi-only corruption of the dual member: caught by the per-share commitment gate.
	c1 := build()
	c1[dualIdx].Xi = new(big.Int).Add(c1[dualIdx].Xi, big.NewInt(1))
	require.Error(t, checkReshareCorrect(pub, c1, threshold, dualIdx),
		"oracle must reject a dual share inconsistent with its commitment")

	// Consistent corruption (Xi and its BigXj moved together) stays on-commitment
	// but off-polynomial: only the reconstruction gate can catch it.
	c2 := build()
	badXi := new(big.Int).Add(c2[dualIdx].Xi, big.NewInt(1))
	c2[dualIdx].Xi = badXi
	c2[dualIdx].BigXj[dualIdx] = crypto.ScalarBaseMult(ec, badXi)
	require.Error(t, checkReshareCorrect(pub, c2, threshold, dualIdx),
		"reconstruction gate must reject an on-commitment but off-polynomial dual share")
}

// reconstructSubset returns k distinct new-committee indices in [0,n) that always
// include mustInclude, so the dual member's self-dealt share is on the
// reconstruction path.
func reconstructSubset(n, k, mustInclude int) []int {
	idxs := []int{mustInclude}
	for j := 0; j < n && len(idxs) < k; j++ {
		if j != mustInclude {
			idxs = append(idxs, j)
		}
	}
	return idxs
}
