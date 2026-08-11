//go:build defang_selfshare_128

// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package resharing

// selfShareStoredLocally is false ONLY under the defang_selfshare_128 test tag,
// reverting the bnb-chain/tss-lib#128 fix so a dual-committee member emits its
// self-dealt share on the wire (where the test transport drops it). This lets the
// `test_reshare_failopen` Makefile target confirm the dual-committee tests detect
// the regression. This tag is never set in production builds.
const selfShareStoredLocally = false
