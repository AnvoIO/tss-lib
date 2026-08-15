// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

// The Paillier Crypto-system is an additive crypto-system. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plain texts.
// Additionally, Paillier Crypto-system supports further computations:
//
// * Encrypted integers can be added together
// * Encrypted integers can be multiplied by an unencrypted integer
// * Encrypted integers and unencrypted integers can be added together
//
// Implementation adheres to GG18Spec (6)

package paillier

import (
	"context"
	"errors"
	"fmt"
	"io"
	gmath "math"
	"math/big"
	"runtime"
	"strconv"

	"github.com/otiai10/primes"

	"github.com/AnvoIO/tss-lib/v3/common"
	crypto2 "github.com/AnvoIO/tss-lib/v3/crypto"
)

const (
	ProofIters         = 13
	verifyPrimesUntil  = 1000 // Verify uses primes <1000
	pQBitLenDifference = 3    // >1020-bit P-Q
	// minModulusBitLen is the smallest modulus GenerateKeyPair can produce at
	// all. Below it the |P-Q| retry (BitLen(P-Q) >= h - pQBitLenDifference, with
	// h = modulusBitLen/2) is not merely slow but unsatisfiable: the safe-prime
	// generator sets the top two bits of the (h-1)-bit Germain prime, so every
	// safe prime it can return lies in a window of width 2^(h-2), and for the
	// three smallest widths it accepts (h=6/7/8) that window holds a single
	// candidate — both draws coincide, |P-Q| = 0, and no round breaks. h=9 is the
	// first width with a wide-enough spread, so 18 is the exact floor and it
	// refuses no size that could have terminated; 2048 was never in question.
	minModulusBitLen = 18
	// verifyMinModulusBitLen is the minimum Paillier modulus bit length accepted
	// by Proof.Verify; matches the paillierBitsLen enforced by the keygen /
	// resharing wire-format checks.
	verifyMinModulusBitLen = 2048
	// verifyPrimalityRounds is the number of Miller-Rabin rounds for the
	// composite check in Proof.Verify (<=4^-30 false-positive rate).
	verifyPrimalityRounds = 30
)

type (
	PublicKey struct {
		N *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN, // lcm(p-1, q-1)
		PhiN *big.Int // (p-1) * (q-1)
		P, Q *big.Int
	}

	// Proof uses the new GenerateXs method in GG18Spec (6)
	Proof [ProofIters]*big.Int
)

var (
	ErrMessageTooLong   = fmt.Errorf("the message is too large or < 0")
	ErrMessageMalFormed = fmt.Errorf("the message is mal-formed")
	ErrModulusMalFormed = fmt.Errorf("the public key modulus is mal-formed")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

func init() {
	// init primes cache
	_ = primes.Globally.Until(verifyPrimesUntil)
}

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPair(ctx context.Context, rand io.Reader, modulusBitLen int, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	if modulusBitLen < minModulusBitLen {
		return nil, nil, fmt.Errorf("GenerateKeyPair: modulusBitLen must be at least %d, got %d", minModulusBitLen, modulusBitLen)
	}
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			return nil, nil, errors.New("GenerateKeyPair: expected 0 or 1 item in `optionalConcurrency`")
		}
		concurrency = optionalConcurrency[0]
		if concurrency < 1 {
			return nil, nil, errors.New("GenerateKeyPair: `optionalConcurrency` must be >= 1")
		}
	} else {
		concurrency = runtime.NumCPU()
	}

	// KS-BTL-F-03: use two safe primes for P, Q
	var P, Q, N *big.Int
	{
		tmp := new(big.Int)
		for {
			sgps, err := common.GetRandomSafePrimesConcurrent(ctx, modulusBitLen/2, 2, concurrency, rand)
			if err != nil {
				return nil, nil, err
			}
			P, Q = sgps[0].SafePrime(), sgps[1].SafePrime()
			// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
			if tmp.Sub(P, Q).BitLen() >= (modulusBitLen/2)-pQBitLenDifference {
				break
			}
		}
		N = tmp.Mul(P, Q)
	}

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN, P: P, Q: Q}
	return
}

// ----- //

func (publicKey *PublicKey) EncryptAndReturnRandomness(rand io.Reader, m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageTooLong
	}
	x = common.GetRandomPositiveRelativelyPrimeInt(rand, publicKey.N)
	if x == nil {
		// (Z/NZ)* is empty, so there is no randomness to blind with. Only
		// reachable for N <= 1, which the m < N test above cannot catch on its
		// own: for N = 1 the one admissible m is 0.
		return nil, nil, ErrModulusMalFormed
	}
	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := common.ModInt(N2).Exp(publicKey.Gamma(), m)
	// 2. x^N mod N2
	xN := common.ModInt(N2).Exp(x, publicKey.N)
	// 3. (1) * (2) mod N2
	c = common.ModInt(N2).Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) Encrypt(rand io.Reader, m *big.Int) (c *big.Int, err error) {
	c, _, err = publicKey.EncryptAndReturnRandomness(rand, m)
	return
}

func (publicKey *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	return common.ModInt(N2).Exp(c1, m), nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	if c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { // c2 < 0 || c2 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// c1 * c2 mod N2
	return common.ModInt(N2).Mul(c1, c2), nil
}

func (publicKey *PublicKey) NSquare() *big.Int {
	return new(big.Int).Mul(publicKey.N, publicKey.N)
}

// AsInts returns the PublicKey serialised to a slice of *big.Int for hashing
func (publicKey *PublicKey) AsInts() []*big.Int {
	return []*big.Int{publicKey.N, publicKey.Gamma()}
}

// Gamma returns N+1
func (publicKey *PublicKey) Gamma() *big.Int {
	return new(big.Int).Add(publicKey.N, one)
}

// ----- //

func (privateKey *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	N2 := privateKey.NSquare()
	if c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // c < 0 || c >= N2 ?
		return nil, ErrMessageTooLong
	}
	cg := new(big.Int).GCD(nil, nil, c, N2)
	if cg.Cmp(one) == 1 {
		return nil, ErrMessageMalFormed
	}
	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(common.ModInt(N2).Exp(c, privateKey.LambdaN), privateKey.N)
	// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
	Lg := L(common.ModInt(N2).Exp(privateKey.Gamma(), privateKey.LambdaN), privateKey.N)
	// 3. (1) * modInv(2) mod N — CT inverse using known totient (Paillier decryption hot path)
	inv := common.ModInt(privateKey.N).ModInverseWithTotient(Lg, privateKey.PhiN)
	if inv == nil {
		return nil, fmt.Errorf("L(g^lambda) is not invertible mod N")
	}
	m = common.ModInt(privateKey.N).Mul(Lc, inv)
	return
}

// ----- //

// Proof is an implementation of Gennaro, R., Micciancio, D., Rabin, T.:
// An efficient non-interactive statistical zero-knowledge proof system for quasi-safe prime products.
// In: In Proc. of the 5th ACM Conference on Computer and Communications Security (CCS-98. Citeseer (1998)

func (privateKey *PrivateKey) Proof(k *big.Int, ecdsaPub *crypto2.ECPoint) (Proof, error) {
	var pi Proof
	iters := ProofIters
	xs := GenerateXs(iters, k, privateKey.N, ecdsaPub)
	for i := 0; i < iters; i++ {
		// PhiN is even, so this inverse takes the blinded even-modulus path
		// (common/int.go modInverseEvenBlinded) rather than constant-time bigmod,
		// which requires an odd modulus. One-time keygen/proof operation.
		M := common.ModInt(privateKey.PhiN).ModInverse(privateKey.N)
		if M == nil {
			return pi, fmt.Errorf("N is not invertible mod PhiN")
		}
		pi[i] = common.ModInt(privateKey.N).Exp(xs[i], M)
	}
	return pi, nil
}

func (pf Proof) Verify(pkN, k *big.Int, ecdsaPub *crypto2.ECPoint) (bool, error) {
	// Input validation, up-front so malformed inputs cannot reach GenerateXs
	// (which dereferences k / ecdsaPub and would loop without a sane pkN).
	if pkN == nil || k == nil || ecdsaPub == nil || !ecdsaPub.ValidateBasic() {
		return false, nil
	}
	if pkN.Sign() != 1 || pkN.Bit(0) == 0 || pkN.BitLen() < verifyMinModulusBitLen {
		return false, nil
	}
	// Reject prime pkN. By Fermat's little theorem x^p == x (mod p) for every
	// x in Z_p*, so a prover with a prime modulus can set pf[i] = xi (the
	// verifier-derived challenge) and pass every iteration without proving any
	// factorization. The trial-division goroutine below only catches factors
	// < verifyPrimesUntil; this closes the gap for larger primes.
	if pkN.ProbablyPrime(verifyPrimalityRounds) {
		return false, nil
	}
	iters := ProofIters
	// Every pf[i] must be a canonical unit in Z_{pkN}*; a zero or non-unit pf[i]
	// has degenerate iteration cases and can leak gcd(pf[i], pkN) via the modexp.
	for i := 0; i < iters; i++ {
		if pf[i] == nil || pf[i].Sign() != 1 || pf[i].Cmp(pkN) != -1 {
			return false, nil
		}
		if new(big.Int).GCD(nil, nil, pf[i], pkN).Cmp(one) != 0 {
			return false, nil
		}
	}
	pch, xch := make(chan bool, 1), make(chan []*big.Int, 1) // buffered to allow early exit
	prms := primes.Until(verifyPrimesUntil).List()           // uses cache primed in init()
	go func(ch chan<- bool) {
		for _, prm := range prms {
			// If prm divides N then Return 0
			if new(big.Int).Mod(pkN, big.NewInt(prm)).Cmp(zero) == 0 {
				ch <- false // is divisible
				return
			}
		}
		ch <- true
	}(pch)
	go func(ch chan<- []*big.Int) {
		ch <- GenerateXs(iters, k, pkN, ecdsaPub)
	}(xch)
	for j := 0; j < 2; j++ {
		select {
		case ok := <-pch:
			if !ok {
				return false, nil
			}
		case xs := <-xch:
			if len(xs) != iters {
				return false, fmt.Errorf("paillier proof verify: expected %d xs but got %d", iters, len(xs))
			}
			for i, xi := range xs {
				xiModN := new(big.Int).Mod(xi, pkN)
				yiExpN := new(big.Int).Exp(pf[i], pkN, pkN)
				if xiModN.Cmp(yiExpN) != 0 {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// ----- utils

func L(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, one)
	return new(big.Int).Div(t, N)
}

// GenerateXs generates the challenges used in Paillier key Proof
func GenerateXs(m int, k, N *big.Int, ecdsaPub *crypto2.ECPoint) []*big.Int {
	var i, n int
	ret := make([]*big.Int, m)
	sX, sY := ecdsaPub.X(), ecdsaPub.Y()
	kb, sXb, sYb, Nb := k.Bytes(), sX.Bytes(), sY.Bytes(), N.Bytes()
	bits := N.BitLen()
	blocks := int(gmath.Ceil(float64(bits) / 256))
	// Cut each candidate down to N's width before testing it against N, the way
	// modproof.sampleYModN does. A candidate is `blocks` concatenated 256-bit
	// hash blocks, so without the mask it is up to 256*blocks bits wide while
	// only candidates below N are accepted: the acceptance rate bottoms out at
	// 2^-255 for bits ≡ 1 (mod 256), a live resample the caller Verify parks on.
	// The mask changes no challenge this library has produced — keygen/resharing
	// pin peer moduli to exactly 2048 bits, and for bits ≡ 0 (mod 256) the
	// concatenation is already exactly `bits` wide so the mask clears nothing.
	mask := new(big.Int).Lsh(one, uint(bits))
	mask.Sub(mask, one)
	chs := make([]chan []byte, blocks)
	for k := range chs {
		chs[k] = make(chan []byte)
	}
	for i < m {
		xi := make([]byte, 0, blocks*32)
		ib := []byte(strconv.Itoa(i))
		nb := []byte(strconv.Itoa(n))
		for j := 0; j < blocks; j++ {
			go func(j int) {
				jBz := []byte(strconv.Itoa(j))
				hash := common.SHA512_256(ib, jBz, nb, kb, sXb, sYb, Nb)
				chs[j] <- hash
			}(j)
		}
		for _, ch := range chs { // must be in order
			rx := <-ch
			if rx == nil { // this should never happen. see: https://golang.org/pkg/hash/#Hash
				panic(errors.New("GenerateXs hash write error!"))
			}
			xi = append(xi, rx...) // xi1||···||xib
		}
		ret[i] = new(big.Int).SetBytes(xi)
		ret[i].And(ret[i], mask)
		if common.IsNumberInMultiplicativeGroup(N, ret[i]) {
			i++
		} else {
			n++
		}
	}
	return ret
}
