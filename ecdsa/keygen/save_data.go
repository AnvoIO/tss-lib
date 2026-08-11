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
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

type (
	LocalPreParams struct {
		PaillierSK *paillier.PrivateKey // ski
		NTildei,
		H1i, H2i,
		Alpha, Beta,
		P, Q *big.Int
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // Xj
		PaillierPKs []*paillier.PublicKey // pkj

		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.NTildej = make([]*big.Int, partyCount)
	saveData.H1j, saveData.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
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
// old-committee path (round.input.Xi.SetInt64(0)), and HD signing reassigns
// round.key.Xi — both would silently corrupt the caller's share through the alias.
//
// LocalSecrets is the ONLY thing copied; it is the only secret material. Everything
// else in the returned value is shared with the caller: LocalPreParams is assigned
// as a struct (PaillierSK, NTildei, H1i, H2i, Alpha, Beta, P, Q), ECDSAPub is the
// caller's pointer, and while Ks/NTildej/H1j/H2j/BigXj/PaillierPKs are freshly
// allocated slices, the elements they hold are the caller's pointers. If this
// library ever writes through any of it, extend the copy first.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		if kj == nil {
			continue
		}
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalPreParams = sourceData.LocalPreParams
	newData.LocalSecrets = copyLocalSecrets(sourceData.LocalSecrets)
	newData.ECDSAPub = sourceData.ECDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			// Do not panic in constructor paths; return original data so callers can fail gracefully later.
			common.Logger.Errorf("BuildLocalSaveDataSubset: unable to find signer in local save data for id=%x", id.Key)
			return sourceData
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.NTildej[j] = sourceData.NTildej[savedIdx]
		newData.H1j[j] = sourceData.H1j[savedIdx]
		newData.H2j[j] = sourceData.H2j[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
	}
	return newData
}
