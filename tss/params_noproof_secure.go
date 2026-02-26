// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

//go:build !insecure_noproofs

package tss

import "github.com/AnvoIO/tss-lib/v3/common"

// SetNoProofMod is blocked in secure builds.
func (params *Parameters) SetNoProofMod() {
	common.Logger.Error("SetNoProofMod blocked: build with -tags insecure_noproofs only for trusted test environments")
}

// SetNoProofFac is blocked in secure builds.
func (params *Parameters) SetNoProofFac() {
	common.Logger.Error("SetNoProofFac blocked: build with -tags insecure_noproofs only for trusted test environments")
}
