// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package dlnproof_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
)

// TestVerify_NilElementsDoesNotPanic is a defense-in-depth regression test: a
// Proof whose Alpha/T arrays contain nil entries must be rejected by Verify
// rather than panicking on the nil dereference. Wire deserialization already
// rejects short/nil proofs (SetBytes never yields nil), so this guards a
// directly-constructed Proof reaching Verify.
func TestVerify_NilElementsDoesNotPanic(t *testing.T) {
	Session := []byte("session")
	// h1, h2 in (1, N) so Verify reaches the per-iteration array scan.
	N := new(big.Int).Lsh(big.NewInt(1), 2048)
	h1, h2 := big.NewInt(2), big.NewInt(3)

	proof := &Proof{} // all Alpha[i]/T[i] are nil

	assert.NotPanics(t, func() {
		ok := proof.Verify(Session, h1, h2, N)
		assert.False(t, ok, "a proof with nil elements must not verify")
	})
}
