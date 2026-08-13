// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"strings"
	"testing"
)

// ProofBob.Bytes and ProofBobWC.Bytes serialise into a fixed-size array with no
// error channel, so a nil field cannot be reported: it faults inside
// (*big.Int).Bytes(), or for the WC form inside the embedded proof or pf.U. Each
// type's own ValidateBasic defines "well-formed" and is therefore the guard; a
// violation is an attributable panic, never a proof that only looks serialisable.

func fullProofBob() *ProofBob {
	one := big.NewInt(1)
	return &ProofBob{Z: one, ZPrm: one, T: one, V: one, W: one, S: one, S1: one, S2: one, T1: one, T2: one}
}

func wantErrPanicContaining(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic mentioning %q", want)
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected the panic value to be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()
	fn()
}

// A ProofBob with only Z set faults inside T.Bytes() without a guard; with one it
// names the violated contract instead.
func TestProofBobBytesRejectsNilField(t *testing.T) {
	wantErrPanicContaining(t, "ProofBob.Bytes:", func() {
		(&ProofBob{Z: big.NewInt(1)}).Bytes()
	})
}

// ProofBobWC.Bytes reads two parts unique to the WC form via the embedded pointer
// and pf.U; delegating to ProofBob.Bytes establishes neither. The type's own
// ValidateBasic does.
func TestProofBobWCBytesRejectsMalformedReceiver(t *testing.T) {
	cases := map[string]*ProofBobWC{
		"nil receiver":       nil,
		"nil embedded proof": {ProofBob: nil, U: nil},
		"nil U":              {ProofBob: fullProofBob(), U: nil},
	}
	for name, pf := range cases {
		pf := pf
		t.Run(name, func(t *testing.T) {
			wantErrPanicContaining(t, "ProofBobWC.Bytes:", func() { pf.Bytes() })
		})
	}
}

// Negative control: a well-formed proof must still serialise, or the assertions
// above would hold just as well against a Bytes() that panicked unconditionally.
func TestProofBobBytesStillSerialisesWellFormed(t *testing.T) {
	if got := fullProofBob().Bytes(); len(got) != ProofBobBytesParts {
		t.Fatalf("got %d parts, want %d", len(got), ProofBobBytesParts)
	}
}
