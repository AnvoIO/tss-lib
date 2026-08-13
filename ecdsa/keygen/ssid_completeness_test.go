// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/AnvoIO/tss-lib/v4/tss"
)

// The keygen SSID must bind the reconstruction threshold: it is a
// session-distinguishing public parameter (it fixes the VSS polynomial degree),
// so two keygens of the same committee under the same nonce that differ only in
// the threshold must not share an SSID. Otherwise every ssid||index proof context
// collides across the two runs.
func TestKeygenSSIDBindsThreshold(t *testing.T) {
	pids := tss.GenerateTestPartyIDs(3)
	ctx := tss.NewPeerContext(pids)
	nonce := big.NewInt(1)

	ssidFor := func(threshold int) []byte {
		params, err := tss.NewParameters(tss.S256(), ctx, pids[0], len(pids), threshold)
		if err != nil {
			t.Fatalf("NewParameters(threshold=%d): %v", threshold, err)
		}
		temp := &localTempData{ssidNonce: nonce}
		r := newRound1(params, &LocalPartySaveData{}, temp,
			make(chan tss.Message, 1), make(chan *LocalPartySaveData, 1)).(*round1)
		ssid, err := r.getSSID()
		if err != nil {
			t.Fatalf("getSSID(threshold=%d): %v", threshold, err)
		}
		return ssid
	}

	if bytes.Equal(ssidFor(1), ssidFor(2)) {
		t.Fatal("two keygens differing only in threshold must not share an SSID")
	}
	if !bytes.Equal(ssidFor(1), ssidFor(1)) {
		t.Fatal("getSSID must be deterministic for a fixed configuration")
	}
}
