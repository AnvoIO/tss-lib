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
