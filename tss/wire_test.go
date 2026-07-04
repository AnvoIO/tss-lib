// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseWireMessage_NilFromReturnsError is a defense-in-depth regression test:
// ParseWireMessage dereferences the caller-supplied `from` party; a nil `from`
// must return an error rather than panic on the exported boundary.
func TestParseWireMessage_NilFromReturnsError(t *testing.T) {
	assert.NotPanics(t, func() {
		msg, err := ParseWireMessage([]byte{0x00}, nil, true)
		assert.Nil(t, msg)
		assert.Error(t, err, "nil from party must be rejected, not panic")
	})
}
