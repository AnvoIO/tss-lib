// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModInverseCheckedValid(t *testing.T) {
	mod := ModInt(big.NewInt(17))
	result, err := mod.ModInverseChecked(big.NewInt(3))
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// 3 * 6 = 18 ≡ 1 (mod 17)
	assert.Equal(t, big.NewInt(6), result)
}

func TestModInverseCheckedZero(t *testing.T) {
	mod := ModInt(big.NewInt(17))
	result, err := mod.ModInverseChecked(big.NewInt(0))
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestModInverseCheckedNonInvertible(t *testing.T) {
	mod := ModInt(big.NewInt(6))
	// gcd(3, 6) = 3 ≠ 1, so 3 is not invertible mod 6
	result, err := mod.ModInverseChecked(big.NewInt(3))
	assert.Error(t, err)
	assert.Nil(t, result)
}

// --- Constant-Time Exp Tests ---

func TestExpCTMatchesBigInt(t *testing.T) {
	// Oracle test: for random inputs, verify CT Exp matches big.Int Exp.
	bitSizes := []int{256, 1024, 2048}
	for _, bits := range bitSizes {
		t.Run(
			"bits="+big.NewInt(int64(bits)).String(),
			func(t *testing.T) {
				// Generate a random odd modulus.
				mod, err := rand.Prime(rand.Reader, bits)
				require.NoError(t, err)

				base, err := rand.Int(rand.Reader, mod)
				require.NoError(t, err)
				if base.Sign() == 0 {
					base.SetInt64(1)
				}

				exp, err := rand.Int(rand.Reader, mod)
				require.NoError(t, err)

				expected := new(big.Int).Exp(base, exp, mod)
				got := ModInt(mod).Exp(base, exp)
				assert.Equal(t, 0, expected.Cmp(got), "CT Exp should match big.Int Exp at %d bits", bits)
			},
		)
	}
}

// TestModInverseEvenModulusBlinded verifies that the blinded even-modulus inverse
// path returns exactly the same result as math/big.ModInverse across a range of
// even moduli — small values, random even moduli, and safe-prime-shaped totients
// φ = (p-1)(q-1) — and that non-invertible inputs return nil. Correctness must not
// depend on the internal blinding randomness.
func TestModInverseEvenModulusBlinded(t *testing.T) {
	t.Run("small even moduli, exhaustive", func(t *testing.T) {
		for _, m := range []int64{2, 4, 6, 8, 10, 12, 100, 1000} {
			mod := big.NewInt(m)
			mi := ModInt(mod)
			for g := int64(0); g < m; g++ {
				gg := big.NewInt(g)
				got := mi.ModInverse(gg)
				want := new(big.Int).ModInverse(gg, mod)
				if want == nil {
					assert.Nil(t, got, "g=%d mod %d should be non-invertible", g, m)
					continue
				}
				require.NotNil(t, got, "g=%d mod %d should be invertible", g, m)
				assert.Equal(t, 0, want.Cmp(got), "inverse of %d mod %d mismatch", g, m)
				// Sanity: g*inv ≡ 1 (mod m).
				chk := new(big.Int).Mul(gg, got)
				chk.Mod(chk, mod)
				assert.Equal(t, 0, chk.Cmp(big.NewInt(1)), "g*inv != 1 for g=%d mod %d", g, m)
			}
		}
	})

	t.Run("random even moduli", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			mod, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 512))
			require.NoError(t, err)
			mod.SetBit(mod, 0, 0) // force even
			if mod.Sign() == 0 {
				continue
			}
			g, err := rand.Int(rand.Reader, mod)
			require.NoError(t, err)
			got := ModInt(mod).ModInverse(g)
			want := new(big.Int).ModInverse(g, mod)
			if want == nil {
				assert.Nil(t, got)
				continue
			}
			require.NotNil(t, got)
			assert.Equal(t, 0, want.Cmp(got), "random even-modulus inverse mismatch")
		}
	})

	t.Run("safe-prime totient shape phi=(p-1)(q-1)", func(t *testing.T) {
		// Small safe primes p=2p'+1: 7 (p'=3), 11 (p'=5), 23 (p'=11), 47 (p'=23).
		safePrimes := []int64{7, 11, 23, 47, 59, 83}
		for _, p := range safePrimes {
			for _, q := range safePrimes {
				if p == q {
					continue
				}
				N := big.NewInt(p * q)
				phi := big.NewInt((p - 1) * (q - 1)) // even
				got := ModInt(phi).ModInverse(N)
				want := new(big.Int).ModInverse(N, phi)
				// These contrived small primes can share a factor (e.g. p|q-1), so
				// N is not always invertible; the blinded path must agree with
				// math/big either way (both nil, or the same inverse).
				if want == nil {
					assert.Nil(t, got, "p=%d q=%d: expected non-invertible", p, q)
					continue
				}
				require.NotNil(t, got)
				assert.Equal(t, 0, want.Cmp(got), "N^{-1} mod phi mismatch for p=%d q=%d", p, q)
			}
		}
	})
}

func TestExpEdgeCases(t *testing.T) {
	mod := big.NewInt(17) // prime
	mi := ModInt(mod)

	t.Run("exp=0 returns 1", func(t *testing.T) {
		result := mi.Exp(big.NewInt(7), big.NewInt(0))
		assert.Equal(t, big.NewInt(1), result)
	})

	t.Run("exp=1 returns base mod m", func(t *testing.T) {
		result := mi.Exp(big.NewInt(20), big.NewInt(1))
		// 20 mod 17 = 3
		assert.Equal(t, big.NewInt(3), result)
	})

	t.Run("base=0", func(t *testing.T) {
		result := mi.Exp(big.NewInt(0), big.NewInt(5))
		assert.Equal(t, 0, big.NewInt(0).Cmp(result))
	})

	t.Run("base=1", func(t *testing.T) {
		result := mi.Exp(big.NewInt(1), big.NewInt(100))
		assert.Equal(t, big.NewInt(1), result)
	})

	t.Run("base > mod", func(t *testing.T) {
		// 20^3 mod 17 = 3^3 mod 17 = 27 mod 17 = 10
		result := mi.Exp(big.NewInt(20), big.NewInt(3))
		expected := new(big.Int).Exp(big.NewInt(20), big.NewInt(3), mod)
		assert.Equal(t, expected, result)
	})
}

func TestExpNegativeExponent(t *testing.T) {
	mod := big.NewInt(17)
	mi := ModInt(mod)
	base := big.NewInt(3)
	negExp := big.NewInt(-5)

	result := mi.Exp(base, negExp)

	// Should equal Exp(ModInverse(3, 17), 5, 17)
	inv := new(big.Int).ModInverse(base, mod)
	require.NotNil(t, inv)
	expected := new(big.Int).Exp(inv, big.NewInt(5), mod)
	assert.Equal(t, expected, result)
}

func TestExpEvenModulusFallback(t *testing.T) {
	// Even modulus should fall back to math/big without panicking.
	mod := big.NewInt(100) // even
	mi := ModInt(mod)
	result := mi.Exp(big.NewInt(3), big.NewInt(7))
	expected := new(big.Int).Exp(big.NewInt(3), big.NewInt(7), mod)
	assert.Equal(t, expected, result)
}

// --- Constant-Time ModInverse Tests ---

func TestModInverseCTPrime(t *testing.T) {
	// On a prime modulus, Fermat path should be used and match big.Int.
	mod, err := rand.Prime(rand.Reader, 256)
	require.NoError(t, err)

	base, err := rand.Int(rand.Reader, mod)
	require.NoError(t, err)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}

	result := ModInt(mod).ModInverse(base)
	require.NotNil(t, result)

	// Verify: base * result mod m == 1
	check := new(big.Int).Mul(base, result)
	check.Mod(check, mod)
	assert.Equal(t, big.NewInt(1), check)
}

func TestModInverseWithTotient(t *testing.T) {
	// Generate P, Q, N = P*Q, phi = (P-1)(Q-1)
	P, err := rand.Prime(rand.Reader, 512)
	require.NoError(t, err)
	Q, err := rand.Prime(rand.Reader, 512)
	require.NoError(t, err)
	N := new(big.Int).Mul(P, Q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(P, big.NewInt(1)),
		new(big.Int).Sub(Q, big.NewInt(1)),
	)

	// Pick a random element coprime to N
	a, err := rand.Int(rand.Reader, N)
	require.NoError(t, err)
	if a.Sign() == 0 {
		a.SetInt64(1)
	}

	inv := ModInt(N).ModInverseWithTotient(a, phi)
	require.NotNil(t, inv)

	// Verify: a * inv mod N == 1
	check := new(big.Int).Mul(a, inv)
	check.Mod(check, N)
	assert.Equal(t, big.NewInt(1), check)
}

func TestModInverseCompositeOdd(t *testing.T) {
	// Composite odd modulus: N = P * Q (both prime, so N is odd)
	P, err := rand.Prime(rand.Reader, 128)
	require.NoError(t, err)
	Q, err := rand.Prime(rand.Reader, 128)
	require.NoError(t, err)
	N := new(big.Int).Mul(P, Q)

	// Pick a base coprime to N
	for i := 0; i < 10; i++ {
		a, err := rand.Int(rand.Reader, N)
		require.NoError(t, err)
		if a.Sign() == 0 {
			continue
		}
		gcd := new(big.Int).GCD(nil, nil, a, N)
		if gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}

		inv := ModInt(N).ModInverse(a)
		require.NotNil(t, inv, "ModInverse should not return nil for invertible element")

		check := new(big.Int).Mul(a, inv)
		check.Mod(check, N)
		assert.Equal(t, big.NewInt(1), check, "a * inv mod N should be 1")
		return
	}
	t.Skip("could not find coprime element in 10 tries")
}

func TestExpCTLargeModulus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large modulus test in short mode")
	}
	// 4096-bit test
	mod, err := rand.Prime(rand.Reader, 4096)
	require.NoError(t, err)
	base, err := rand.Int(rand.Reader, mod)
	require.NoError(t, err)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}
	exp, err := rand.Int(rand.Reader, mod)
	require.NoError(t, err)

	expected := new(big.Int).Exp(base, exp, mod)
	got := ModInt(mod).Exp(base, exp)
	assert.Equal(t, 0, expected.Cmp(got), "CT Exp should match big.Int Exp at 4096 bits")
}

// --- Benchmarks ---

func BenchmarkExpCT(b *testing.B) {
	mod, _ := rand.Prime(rand.Reader, 2048)
	base, _ := rand.Int(rand.Reader, mod)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}
	exp, _ := rand.Int(rand.Reader, mod)
	mi := ModInt(mod)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mi.Exp(base, exp)
	}
}

func BenchmarkExpBigInt(b *testing.B) {
	mod, _ := rand.Prime(rand.Reader, 2048)
	base, _ := rand.Int(rand.Reader, mod)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}
	exp, _ := rand.Int(rand.Reader, mod)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(big.Int).Exp(base, exp, mod)
	}
}

func BenchmarkModInverseCT(b *testing.B) {
	mod, _ := rand.Prime(rand.Reader, 2048)
	base, _ := rand.Int(rand.Reader, mod)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}
	mi := ModInt(mod)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mi.ModInverse(base)
	}
}

func BenchmarkModInverseBigInt(b *testing.B) {
	mod, _ := rand.Prime(rand.Reader, 2048)
	base, _ := rand.Int(rand.Reader, mod)
	if base.Sign() == 0 {
		base.SetInt64(1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(big.Int).ModInverse(base, mod)
	}
}
