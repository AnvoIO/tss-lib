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

func TestBasePartyValidateMessageRejectsNilContentWithoutPanic(t *testing.T) {
	p := &BaseParty{}
	msg := NewMessage(MessageRouting{}, nil, nil)

	assert.NotPanics(t, func() {
		ok, err := p.ValidateMessage(msg)
		assert.False(t, ok)
		assert.Error(t, err)
	})
}
