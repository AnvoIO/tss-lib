// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	"fmt"
	"math/big"
	"sync"

	"filippo.io/bigmod"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// bigmodCache caches *bigmod.Modulus values keyed by the modulus bytes (as string).
// This avoids reconstructing the Modulus on every call; protocol structs reuse
// the same *big.Int pointers so the cache stays small.
var bigmodCache sync.Map // map[string]*bigmod.Modulus

// getBigmodModulus returns a cached *bigmod.Modulus for the given big.Int modulus.
// Returns nil if the modulus is <= 1 (bigmod requires modulus > 1).
func getBigmodModulus(mod *big.Int) *bigmod.Modulus {
	key := string(mod.Bytes())
	if v, ok := bigmodCache.Load(key); ok {
		return v.(*bigmod.Modulus)
	}
	m, err := bigmod.NewModulus(mod.Bytes())
	if err != nil {
		return nil
	}
	v, _ := bigmodCache.LoadOrStore(key, m)
	return v.(*bigmod.Modulus)
}

func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

// Exp computes x^y mod mi using constant-time arithmetic for odd moduli.
// For even moduli, it falls back to math/big (non-constant-time).
func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	mod := mi.i()

	// Edge case: exponent is zero → return 1 (mod m).
	if y.Sign() == 0 {
		return new(big.Int).Mod(one, mod)
	}

	// Negative exponent: compute ModInverse(x) first, then Exp with |y|.
	if y.Sign() < 0 {
		inv := mi.ModInverse(x)
		if inv == nil {
			return nil
		}
		absY := new(big.Int).Abs(y)
		return mi.Exp(inv, absY)
	}

	// Even modulus: bigmod requires odd modulus, fall back to math/big.
	if mod.Bit(0) == 0 {
		return new(big.Int).Exp(x, y, mod)
	}

	m := getBigmodModulus(mod)
	if m == nil {
		// Modulus <= 1; fall back.
		return new(big.Int).Exp(x, y, mod)
	}

	// Use SetOverflowingBytes to handle base >= modulus without manual reduction.
	// If the base has more bits than the modulus bit-length, reduce first.
	base := new(big.Int).Mod(x, mod)
	if base.Sign() < 0 {
		base.Add(base, mod)
	}

	// Pad base bytes to modulus size to avoid "overflows the modulus size" error.
	modSize := m.Size()
	baseBytes := base.Bytes()
	if len(baseBytes) < modSize {
		padded := make([]byte, modSize)
		copy(padded[modSize-len(baseBytes):], baseBytes)
		baseBytes = padded
	}

	natBase, err := bigmod.NewNat().SetBytes(baseBytes, m)
	if err != nil {
		// Shouldn't happen after Mod, but fall back just in case.
		return new(big.Int).Exp(x, y, mod)
	}

	expBytes := y.Bytes()
	result := bigmod.NewNat().Exp(natBase, expBytes, m)

	return new(big.Int).SetBytes(result.Bytes(m))
}

// ModInverse computes the modular inverse of g mod mi.
// For odd prime moduli, uses constant-time Fermat's little theorem: g^(m-2) mod m.
// For odd composite moduli, tries Fermat first and verifies; falls back to math/big if wrong.
// For even moduli, falls back to math/big (non-constant-time).
func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	mod := mi.i()

	// Even modulus: fall back to math/big.
	if mod.Bit(0) == 0 {
		return new(big.Int).ModInverse(g, mod)
	}

	// For odd moduli, use Fermat: g^(m-2) mod m (CT via Exp).
	// This is correct when m is prime. For composite odd m, we verify.
	exp := new(big.Int).Sub(mod, two) // m - 2
	inv := mi.Exp(g, exp)
	if inv == nil {
		return new(big.Int).ModInverse(g, mod)
	}

	// Verify: g * inv mod m == 1.
	check := new(big.Int).Mul(g, inv)
	check.Mod(check, mod)
	if check.Cmp(one) == 0 {
		return inv
	}

	// Fermat failed (composite modulus without known phi), fall back.
	return new(big.Int).ModInverse(g, mod)
}

// ModInverseChecked wraps ModInverse with a nil check. Returns an error if g is not invertible mod mi.
func (mi *modInt) ModInverseChecked(g *big.Int) (*big.Int, error) {
	result := mi.ModInverse(g)
	if result == nil {
		return nil, fmt.Errorf("ModInverse: element %v is not invertible mod %v", g, mi.i())
	}
	return result, nil
}

// ModInverseWithTotient computes the modular inverse of g mod mi using the known
// Euler totient: g^(totient-1) mod mi. This is constant-time for odd moduli and
// correct for any modulus when the totient is known.
// Used specifically for Paillier decryption where PhiN is available.
func (mi *modInt) ModInverseWithTotient(g, totient *big.Int) *big.Int {
	exp := new(big.Int).Sub(totient, one) // totient - 1
	return mi.Exp(g, exp)
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}

func AppendBigIntToBytesSlice(commonBytes []byte, appended *big.Int) []byte {
	resultBytes := make([]byte, len(commonBytes), len(commonBytes)+len(appended.Bytes()))
	copy(resultBytes, commonBytes)
	resultBytes = append(resultBytes, appended.Bytes()...)
	return resultBytes
}
