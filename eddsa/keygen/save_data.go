// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"math/big"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

type (
	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj []*crypto.ECPoint // Xj

		// used for test assertions (may be discarded)
		EDDSAPub *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	return
}

// copyLocalSecrets returns a LocalSecrets whose *big.Int fields are fresh, so the
// result shares no mutable state with s. A nil field stays nil rather than
// becoming a zero-valued big.Int, so callers can still distinguish "absent" from
// "zero".
func copyLocalSecrets(s LocalSecrets) LocalSecrets {
	out := LocalSecrets{}
	if s.Xi != nil {
		out.Xi = new(big.Int).Set(s.Xi)
	}
	if s.ShareID != nil {
		out.ShareID = new(big.Int).Set(s.ShareID)
	}
	return out
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
//
// LocalSecrets is DEEP-COPIED, not assigned. Its fields (Xi, ShareID) are
// *big.Int, so a plain struct assignment would leave the returned value sharing
// the caller's numbers, and anything this library writes through them would reach
// the caller's own save data. Resharing round 5 does exactly that on the
// old-committee path (round.input.Xi.SetInt64(0)), silently corrupting the
// caller's share through the alias.
//
// LocalSecrets is the ONLY thing copied; it is the only secret material. Everything
// else in the returned value is shared with the caller: EDDSAPub is the caller's
// pointer, and while Ks/BigXj are freshly allocated slices, the elements they hold
// are the caller's pointers. If this library ever writes through any of it, extend
// the copy first.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		if kj == nil {
			continue
		}
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalSecrets = copyLocalSecrets(sourceData.LocalSecrets)
	newData.EDDSAPub = sourceData.EDDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			// Do not panic in constructor paths. Preserve the historical fallback
			// shape so callers can fail gracefully later, but retain the deep-copy
			// guarantee for mutable local secrets on every return path.
			common.Logger.Errorf("BuildLocalSaveDataSubset: unable to find signer in local save data for id=%x", id.Key)
			fallback := sourceData
			fallback.LocalSecrets = copyLocalSecrets(sourceData.LocalSecrets)
			return fallback
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
	}
	return newData
}
