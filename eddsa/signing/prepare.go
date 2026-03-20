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

	"github.com/AnvoIO/tss-lib/v3/common"
)

// PrepareForSigning(), Fig. 7
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) (wi *big.Int, err error) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != pax {
		return nil, fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax)
	}
	if len(ks) <= i {
		return nil, fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i)
	}

	// 1-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			return nil, fmt.Errorf("index of two parties are equal")
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		inv, err := modQ.ModInverseChecked(new(big.Int).Sub(ksj, ksi))
		if err != nil {
			return nil, fmt.Errorf("PrepareForSigning: ModInverse failed: %v", err)
		}
		coef := modQ.Mul(ks[j], inv)
		wi = modQ.Mul(wi, coef)
	}

	return
}
