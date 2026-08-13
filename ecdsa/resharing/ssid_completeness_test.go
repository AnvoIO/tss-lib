// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

// Internal (package resharing) test so it can read the unexported
// round1.temp.ssid produced by the real production path.
package resharing

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/AnvoIO/tss-lib/v4/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

func buildNewCommittee(base int64, n int) tss.SortedPartyIDs {
	raw := make(tss.UnSortedPartyIDs, 0, n)
	for k := 0; k < n; k++ {
		raw = append(raw, tss.NewPartyID(
			fmt.Sprintf("new-%d-%d", base, k), fmt.Sprintf("N[%d]", k), big.NewInt(base+int64(k))))
	}
	return tss.SortPartyIDs(raw)
}

// The resharing SSID must bind the NEW committee and both thresholds: the new
// committee is the defining input of a reshare (it decides who receives the key)
// and the thresholds fix the polynomial degrees. Two reshares of the SAME key by
// the SAME old committee to DIFFERENT new committees (or thresholds) under the
// SAME nonce must not share an SSID — otherwise every ssid||index proof context
// (mod/fac/dln) is byte-identical across the two runs and transfers between them.
// This was reproduced as a byte-identical SSID before the fix.
func TestReshareSSIDBindsNewCommitteeAndThresholds(t *testing.T) {
	oldThreshold := keygen.TestThreshold
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(oldThreshold + 1)
	if err != nil {
		t.Fatalf("load keygen fixtures (run keygen tests first if this fails): %v", err)
	}
	oldCtx := tss.NewPeerContext(oldPIDs)
	actingOld := oldPIDs[0]

	var actingKey keygen.LocalPartySaveData
	found := false
	for _, k := range oldKeys {
		if k.ShareID.Cmp(actingOld.KeyInt()) == 0 {
			actingKey, found = k, true
		}
	}
	if !found {
		t.Fatal("no fixture save-data for the acting old party")
	}

	reshareSSID := func(newPIDs tss.SortedPartyIDs, newThreshold int, nonce *big.Int) []byte {
		newCtx := tss.NewPeerContext(newPIDs)
		params, perr := tss.NewReSharingParameters(
			tss.S256(), oldCtx, newCtx, actingOld,
			len(oldPIDs), oldThreshold, len(newPIDs), newThreshold)
		if perr != nil {
			t.Fatalf("NewReSharingParameters: %v", perr)
		}
		params.SetSessionNonce(nonce)

		out := make(chan tss.Message, len(newPIDs)+1)
		end := make(chan *keygen.LocalPartySaveData, 1)
		P := NewLocalParty(params, actingKey, out, end).(*LocalParty)
		r1 := P.FirstRound()
		if sErr := r1.Start(); sErr != nil {
			t.Fatalf("round1.Start: %v", sErr)
		}
		if len(P.temp.ssid) == 0 {
			t.Fatal("round1 produced an empty ssid")
		}
		return append([]byte(nil), P.temp.ssid...)
	}

	nonce := big.NewInt(1)
	committee1 := buildNewCommittee(1001, keygen.TestParticipants)
	committee2 := buildNewCommittee(5001, keygen.TestParticipants)

	ssidA := reshareSSID(committee1, oldThreshold, nonce)
	ssidB := reshareSSID(committee2, oldThreshold, nonce)             // DIFFERENT new committee
	ssidD := reshareSSID(committee1, keygen.TestParticipants-1, nonce) // DIFFERENT new threshold

	if bytes.Equal(ssidA, ssidB) {
		t.Fatalf("two reshares to different new committees must not share an SSID:\n A=%x\n B=%x", ssidA, ssidB)
	}
	if bytes.Equal(ssidA, ssidD) {
		t.Fatalf("two reshares with different new thresholds must not share an SSID:\n A=%x\n D=%x", ssidA, ssidD)
	}
	// Control: the same configuration must still reproduce the SSID.
	if !bytes.Equal(ssidA, reshareSSID(committee1, oldThreshold, nonce)) {
		t.Fatal("the same configuration under the same nonce must reproduce the SSID")
	}
}
