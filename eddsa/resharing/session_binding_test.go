// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"bytes"
	"math/big"
	"testing"
)

// The new committee cannot recompute the old committee's ssid (its pre-image is
// the OLD save data), so sessionNonceHash is the one value it can check the old
// committee's round-1 declaration against. It must therefore be a deterministic
// function of the nonce alone, and distinct nonces must not collide.
func TestSessionNonceHashSeparatesSessions(t *testing.T) {
	h1 := sessionNonceHash(big.NewInt(1))
	h2 := sessionNonceHash(big.NewInt(2))
	if len(h1) == 0 || len(h2) == 0 {
		t.Fatal("a valid nonce must yield a non-empty hash")
	}
	if bytes.Equal(h1, h2) {
		t.Fatal("two different session nonces must not produce the same hash")
	}
	if !bytes.Equal(h1, sessionNonceHash(big.NewInt(1))) {
		t.Fatal("the hash must be deterministic")
	}
	if sessionNonceHash(nil) != nil {
		t.Fatal("a nil nonce yields no hash rather than a hash of nothing")
	}
}
