// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
)

// PrepareForSigning(), GG18Spec (11) Fig. 14
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint, err error) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(bigXs) {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs))
	}
	if len(ks) != pax {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax)
	}
	if len(ks) <= i {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i)
	}

	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			return nil, nil, fmt.Errorf("index of two parties are equal")
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		inv, err := modQ.ModInverseChecked(new(big.Int).Sub(ksj, ksi))
		if err != nil {
			return nil, nil, fmt.Errorf("PrepareForSigning: ModInverse failed: %v", err)
		}
		coef := modQ.Mul(ks[j], inv)
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				return nil, nil, fmt.Errorf("index of two parties are equal")
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			inv, err := modQ.ModInverseChecked(new(big.Int).Sub(ksc, ksj))
			if err != nil {
				return nil, nil, fmt.Errorf("PrepareForSigning: ModInverse failed: %v", err)
			}
			iota := modQ.Mul(ksc, inv)
			// SECURITY (SRC-2026-641): a degenerate (identity) Lagrange result
			// would make our fork's ScalarMult panic; route through the checked
			// variant and surface the error rather than crashing (or, upstream,
			// nil-dereferencing on the next chained op / downstream X()).
			bigWj, err = bigWj.ScalarMultChecked(iota)
			if err != nil {
				return nil, nil, fmt.Errorf("PrepareForSigning: scalar mult produced a degenerate point at index %d: %w", j, err)
			}
		}
		bigWs[j] = bigWj
	}
	return
}
