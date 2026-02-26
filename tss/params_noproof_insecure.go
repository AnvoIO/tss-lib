// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

//go:build insecure_noproofs

package tss

import "github.com/AnvoIO/tss-lib/v3/common"

// SetNoProofMod disables modulus proof verification.
// This must only be used in trusted test/backward-compatibility environments.
func (params *Parameters) SetNoProofMod() {
	common.Logger.Warn("SetNoProofMod: SECURITY DEGRADED (insecure_noproofs build tag enabled)")
	params.noProofMod = true
}

// SetNoProofFac disables factorization proof verification.
// This must only be used in trusted test/backward-compatibility environments.
func (params *Parameters) SetNoProofFac() {
	common.Logger.Warn("SetNoProofFac: SECURITY DEGRADED (insecure_noproofs build tag enabled)")
	params.noProofFac = true
}
