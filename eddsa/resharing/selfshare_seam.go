//go:build !defang_selfshare_128

// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing

// selfShareStoredLocally gates the bnb-chain/tss-lib#128 fix in round 3: a party
// that sits in BOTH the old and new committees stores the VSS share it deals to
// itself LOCALLY, instead of emitting it on the wire where a real transport drops
// the self-addressed message and the share is lost.
//
// It is a compile-time constant, so it has zero effect on production builds (the
// gate is always true and the branch is identical to the un-gated fix). The
// companion selfshare_seam_defang.go, selected by the `defang_selfshare_128` build
// tag, provides the false variant that reverts the fix — used only by the Makefile
// `test_reshare_failopen` target to PROVE the dual-committee regression tests go
// red against a regressed fix (automated fail-open verification, not a manual memory).
const selfShareStoredLocally = true
