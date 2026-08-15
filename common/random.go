// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package common

import (
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
	// maxQuadraticNonResidueTries bounds GetRandomQuadraticNonResidue so a
	// caller-supplied io.Reader that has stopped producing entropy cannot park a
	// party there forever (modproof.NewProof samples with the party mutex held).
	// For an admissible n a try succeeds with probability > phi(n)/2n, minimised
	// over bounded n by the odd primorial (> 1/16 for every reachable n given the
	// mustGetRandomIntMaxBits cap), so 1024 tries all miss with probability well
	// below 2^-95; for the products of two large primes this library samples over
	// it is ~1/2 per try.
	maxQuadraticNonResidueTries = 1024
)

// MustGetRandomInt panics if it is unable to gather entropy from `io.Reader` or when `bits` is <= 0
func MustGetRandomInt(rand io.Reader, bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := cryptorand.Int(rand, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

// GetRandomPositiveInt returns a uniformly random integer in the OPEN interval
// (0, lessThan). The lower bound is strict: 0 is never returned. This matches
// the name's "Positive" claim and the assumption made by every Verify-side
// IsInInterval/positive check on values produced by this sampler.
//
// Returns nil if lessThan is nil or <= 1 (no value exists in (0, 1)).
func GetRandomPositiveInt(rand io.Reader, lessThan *big.Int) *big.Int {
	if lessThan == nil || lessThan.Cmp(one) <= 0 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, lessThan.BitLen())
		if try.Sign() > 0 && try.Cmp(lessThan) < 0 {
			break
		}
	}
	return try
}

// GetRandomPrimeInt returns a random prime of exactly `bits` bits, or nil when
// no such prime exists (bits < 2: crypto/rand.Prime's own documented contract,
// and the only 1-bit values 0 and 1 are not prime — the fallback loop below
// cannot do better, since MustGetRandomInt(rand, 1) draws only 0).
func GetRandomPrimeInt(rand io.Reader, bits int) *big.Int {
	if bits < 2 {
		return nil
	}
	try, err := cryptorand.Prime(rand, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(rand, bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// GetRandomPositiveRelativelyPrimeInt returns a uniformly random element of
// (Z/nZ)*, the group of elements of Z/nZ that have a multiplicative inverse, or
// nil if n is nil or <= 1 (no such element exists; for n == 1 the old n <= 0
// guard left a loop whose acceptance probability was exactly zero, since
// MustGetRandomInt(rand, 1) draws only 0).
func GetRandomPositiveRelativelyPrimeInt(rand io.Reader, n *big.Int) *big.Int {
	if n == nil || n.Cmp(one) <= 0 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//	Return a random generator of RQn with high probability.
//	THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
//
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(rand io.Reader, n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(rand, n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

// GetRandomQuadraticNonResidue returns a w in (0, n) with Jacobi(w, n) = -1.
//
// It returns nil when n is outside the domain where such a w exists — n nil,
// n <= 1, n even, or n a perfect square — and nil in the vanishingly unlikely
// event that maxQuadraticNonResidueTries draws all miss. For a perfect square
// every prime-power exponent is even, so the Jacobi symbol is the constant +1
// on units and never the -1 the loop waits for; for n <= 1 or even n big.Jacobi
// panics. The preconditions used to live in this comment only ("of odd n")
// while the loop just kept sampling. See maxQuadraticNonResidueTries for the
// try-bound derivation.
func GetRandomQuadraticNonResidue(rand io.Reader, n *big.Int) *big.Int {
	if n == nil || n.Cmp(one) <= 0 || n.Bit(0) == 0 {
		return nil
	}
	if sqrt := new(big.Int).Sqrt(n); new(big.Int).Mul(sqrt, sqrt).Cmp(n) == 0 {
		return nil
	}
	for i := 0; i < maxQuadraticNonResidueTries; i++ {
		w := GetRandomPositiveInt(rand, n)
		if w == nil {
			return nil
		}
		if big.Jacobi(w, n) == -1 {
			return w
		}
	}
	return nil
}

// GetRandomBytes returns random bytes of length.
func GetRandomBytes(rand io.Reader, length int) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length <= 0 {
		return nil, errors.New("invalid length")
	}

	buf := make([]byte, length)
	_, err := io.ReadFull(rand, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
