// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	cryptorand "crypto/rand"
	"encoding/binary"
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

	// Even modulus: bigmod (constant-time) requires an odd modulus, so the
	// constant-time Exp/Fermat path is unavailable. The even secret moduli that
	// reach here are Paillier totients (φ = (p-1)(q-1)); inverting mod them with a
	// raw math/big.ModInverse would leak φ's structure through the variable-time
	// extended-GCD. Use a blinded inverse instead, which randomizes the GCD trace.
	if mod.Bit(0) == 0 {
		return modInverseEvenBlinded(g, mod)
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

// modInverseEvenBlinded computes g^{-1} mod m for an EVEN modulus m using
// multiplicative blinding, so the underlying variable-time extended-GCD runs on a
// randomized value and its timing no longer correlates with the secret modulus.
//
// bigmod (the constant-time backend) only supports odd moduli, so an even secret
// modulus — a Paillier totient φ = (p-1)(q-1) — cannot take the constant-time
// path. Rather than call math/big.ModInverse(g, m) directly (whose Euclidean
// quotient sequence, hence running time, depends on the secret m), we pick a
// fresh random blinder r and use the exact identity
//
//	g^{-1} = r · (g·r mod m)^{-1}   (mod m),
//
// since (g·r)^{-1} = r^{-1}·g^{-1}. The inversion now operates on the blinded
// value g·r, decorrelating the GCD trace from m. This is a timing-randomization
// countermeasure, not a strictly constant-time algorithm; it is used only on
// one-time keygen/proof operations, never a per-signature hot path.
//
// Correctness never depends on the blinding: the candidate is verified
// (g·inv ≡ 1 mod m) before return, a blinding miss retries with a fresh r, and
// the last resort is the plain inverse. Returns nil if g is not invertible mod m.
func modInverseEvenBlinded(g, m *big.Int) *big.Int {
	if m.Sign() <= 0 {
		return nil
	}
	gg := new(big.Int).Mod(g, m) // reduce into [0, m)
	for attempt := 0; attempt < 8; attempt++ {
		r, err := cryptorand.Int(cryptorand.Reader, m)
		if err != nil {
			break
		}
		// Force r odd (hence coprime to the 2-part of an even m) and non-zero; the
		// post-verification rejects the negligible odd-but-non-coprime case.
		r.Or(r, one)
		b := new(big.Int).Mul(gg, r)
		b.Mod(b, m)
		bInv := new(big.Int).ModInverse(b, m)
		if bInv == nil {
			continue
		}
		cand := new(big.Int).Mul(r, bInv)
		cand.Mod(cand, m)
		chk := new(big.Int).Mul(gg, cand)
		chk.Mod(chk, m)
		if chk.Cmp(one) == 0 {
			return cand
		}
	}
	// Guaranteed-correct fallback (variable-time). Reached only if g is genuinely
	// non-invertible mod m, or after repeated blinding misses (astronomically
	// unlikely for a safe-prime totient).
	return new(big.Int).ModInverse(gg, m)
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}

// IsInIntervalPositive reports whether b is in the open interval (0, bound).
// Stricter than IsInInterval, which accepts b == 0; use this for prover-supplied
// values that the honest sampler always draws from a positive range (e.g.
// GetRandomPositiveInt outputs).
func IsInIntervalPositive(b *big.Int, bound *big.Int) bool {
	return b != nil && b.Sign() > 0 && b.Cmp(bound) < 0
}

// Deprecated: not injective, so unsafe for building Fiat-Shamir Session contexts.
// It concatenates commonBytes||appended.Bytes() with no delimiter; commonBytes (an
// ssid) is a variable-length big.Int hash with leading zeros stripped and
// appended.Bytes() is empty for a zero index, so distinct (commonBytes, appended)
// pairs can produce identical output and therefore share a proof challenge. Use
// AppendBigIntToBytesSliceFramed instead. Retained only for API compatibility.
func AppendBigIntToBytesSlice(commonBytes []byte, appended *big.Int) []byte {
	resultBytes := make([]byte, len(commonBytes), len(commonBytes)+len(appended.Bytes()))
	copy(resultBytes, commonBytes)
	resultBytes = append(resultBytes, appended.Bytes()...)
	return resultBytes
}

// AppendBigIntToBytesSliceFramed encodes (commonBytes, appended) unambiguously for
// use as a per-party Fiat-Shamir Session context (ssid || index). A fixed-width
// 4-byte big-endian length prefix on commonBytes makes its boundary explicit, so
// reading back the length then that many bytes recovers commonBytes exactly and
// the remainder is appended.Bytes(); the encoding is therefore injective in
// (commonBytes, appended) for non-negative appended. Unlike the deprecated
// AppendBigIntToBytesSlice, this cannot collide two different (ssid, index) pairs
// onto one challenge, and it always allocates a fresh slice (never aliasing the
// caller's ssid backing array the way a bare append(round.temp.ssid, …) can).
func AppendBigIntToBytesSliceFramed(commonBytes []byte, appended *big.Int) []byte {
	appendedBytes := appended.Bytes()
	resultBytes := make([]byte, 4, 4+len(commonBytes)+len(appendedBytes))
	binary.BigEndian.PutUint32(resultBytes, uint32(len(commonBytes)))
	resultBytes = append(resultBytes, commonBytes...)
	resultBytes = append(resultBytes, appendedBytes...)
	return resultBytes
}
