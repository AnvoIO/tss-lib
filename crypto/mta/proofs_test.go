// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package mta

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v3/tss"
)

// TestProofBobWCFromBytesRejectsShortInput is a regression test for the June
// 2026 hardening (J4): a 10-part input (valid for ProofBob) must be rejected by
// ProofBobWCFromBytes with an error rather than panicking on the bzs[10]/bzs[11]
// index access. ProofBobFromBytes accepts 10-or-12 parts, so ProofBobWCFromBytes
// must enforce the 12-part length itself.
func TestProofBobWCFromBytesRejectsShortInput(t *testing.T) {
	bzs := make([][]byte, ProofBobBytesParts) // 10 parts
	for i := range bzs {
		bzs[i] = []byte{0x01}
	}

	assert.NotPanics(t, func() {
		proof, err := ProofBobWCFromBytes(tss.EC(), bzs)
		assert.Error(t, err, "10-part input must be rejected for ProofBobWC")
		assert.Nil(t, proof)
	})
}
