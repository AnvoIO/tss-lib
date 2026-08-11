// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019-2023 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
)

const (
	// Iterations controls the soundness of the mod proof: 80 iterations → 2^{-80} soundness error.
	Iterations           = 80
	ProofModBytesParts   = Iterations*2 + 3
	MaxProofElementBytes = 512
	// fsDomainTag is the per-proof-type Fiat-Shamir domain separator prepended
	// to the caller-supplied Session (see crypto/facproof.fsSession for the
	// rationale). Frozen once shipped — changing it invalidates every modproof
	// transcript.
	fsDomainTag = "AnvoIO.tss-lib.v4.modproof"
)

var one = big.NewInt(1)

func fsSession(Session []byte) []byte {
	return append([]byte(fsDomainTag+"|"), Session...)
}

// sampleYModN deterministically derives Y_i ∈ [0, N) by seeding from the
// Fiat-Shamir transcript, expanding via SHA512_256 counter mode to the bit
// length of N, masking down to exactly N.BitLen() bits, and then rejecting
// candidates ≥ N. The rejection probability per attempt is at most 1/2 because
// N ∈ (2^{bitlen-1}, 2^bitlen], so the loop is bounded (1–2 iterations in
// practice).
//
// This replaces the earlier RejectionSample(N, hash) derivation, which for a
// 2048-bit N was effectively a no-op modular reduction: the 256-bit
// SHA512_256i_TAGGED output already satisfies hash < N, so Y_i landed in a
// 256-bit subset of [0, N) rather than the Z_N support the Paillier-Blum
// proof's formal soundness analysis assumes. The collapsed support is not a
// known attack against the 80-iteration repetition, but a textbook-vs-
// implementation mismatch a reviewer should not have to defend. Wire-incompat
// with v3 by design — consumed by the /v4 module bump.
func sampleYModN(Session []byte, N *big.Int, transcript []*big.Int) *big.Int {
	seedBig := common.SHA512_256i_TAGGED(fsSession(Session), transcript...)
	// Pad the seed to a fixed 32-byte width so the counter mixing below is
	// canonical regardless of leading-zero bytes in seedBig.Bytes().
	seed := seedBig.Bytes()
	if len(seed) < 32 {
		pad := make([]byte, 32-len(seed))
		seed = append(pad, seed...)
	}
	bitLen := N.BitLen()
	blocks := (bitLen + 255) / 256
	mask := new(big.Int).Lsh(one, uint(bitLen))
	mask.Sub(mask, one)
	counterBz := make([]byte, 4)
	for counter := uint32(0); counter < 1<<31; counter++ {
		binary.BigEndian.PutUint32(counterBz, counter)
		combined := make([]byte, 0, blocks*32)
		for j := 0; j < blocks; j++ {
			block := common.SHA512_256(seed, counterBz, []byte{byte(j)})
			combined = append(combined, block...)
		}
		candidate := new(big.Int).SetBytes(combined)
		candidate.And(candidate, mask)
		if candidate.Cmp(N) < 0 {
			return candidate
		}
	}
	// 1<<31 attempts at rejection rate ≤ 1/2 has failure probability
	// 2^-(2^31), far below any cryptographic concern; reaching this point
	// indicates a bug in N's bit-length / mask derivation.
	panic("modproof.sampleYModN: exhausted counter (mask/N invariant violated)")
}

type (
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)

// isQuadraticResidue checks Euler criterion
func isQuadraticResidue(X, N *big.Int) bool {
	return big.Jacobi(X, N) == 1
}

func NewProof(Session []byte, N, P, Q *big.Int, rand io.Reader) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuadraticNonResidue(rand, N)

	// Fig 16.2: Y_i ~ Z_N derived via expand-then-reject sampling so the support
	// set matches the paper's `Y <- Z_N` assumption rather than landing in a
	// 256-bit subset (see sampleYModN docstring).
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{W, N}, Y[:i]...))
	}

	// Fig 16.3
	modN := common.ModInt(N)
	// Phi is even, so this inverse takes the blinded even-modulus path
	// (common/int.go modInverseEvenBlinded) rather than constant-time bigmod,
	// which requires an odd modulus. Keygen-time operation, not the signing hot path.
	invN := common.ModInt(Phi).ModInverse(N)
	if invN == nil {
		return nil, fmt.Errorf("N is not invertible mod Phi")
	}
	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}

	// for fourth-root
	expo := new(big.Int).Add(Phi, big.NewInt(4))
	expo = new(big.Int).Rsh(expo, 3)
	// Square without reducing mod the secret Phi. The reduction was a
	// variable-time division by Phi and leaked its structure; it is unnecessary
	// here because expo is only ever an exponent base-Yi mod N, and every Yi that
	// reaches the fourth-root branch below is a unit mod N (it passed the QR test
	// mod both P and Q), so Yi^Phi ≡ 1 and Yi^(expo mod Phi) ≡ Yi^expo (mod N).
	// The unreduced exponent is ~twice as long (keygen-time cost only) and the
	// resulting Xi — hence the proof transcript — is byte-for-byte identical.
	expo = new(big.Int).Mul(expo, expo)

	for i := range Y {
		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}
			if isQuadraticResidue(Yi, P) && isQuadraticResidue(Yi, Q) {
				Xi := modN.Exp(Yi, expo)
				Zi := modN.Exp(Y[i], invN)
				X[i], Z[i] = Xi, Zi
				A.SetBit(A, i, uint(a))
				B.SetBit(B, i, uint(b))
				break
			}
		}
	}

	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytesBounded(bzs, MaxProofElementBytes, ProofModBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || N == nil {
		return false
	}
	// N must be at least 2048 bits and odd (not prime)
	if N.BitLen() < 2048 {
		return false
	}
	if N.Bit(0) == 0 {
		return false
	}
	if isQuadraticResidue(pf.W, N) {
		return false
	}
	if pf.W.Sign() != 1 || pf.W.Cmp(N) != -1 {
		return false
	}
	gcd := new(big.Int).GCD(nil, nil, pf.W, N)
	if gcd.Cmp(one) != 0 {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i].Sign() != 1 || pf.Z[i].Cmp(N) != -1 {
			return false
		}
	}
	for i := range pf.X {
		if pf.X[i].Sign() != 1 || pf.X[i].Cmp(N) != -1 {
			return false
		}
	}
	if pf.A.BitLen() != Iterations+1 {
		return false
	}
	if pf.B.BitLen() != Iterations+1 {
		return false
	}

	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{pf.W, N}, Y[:i]...))
	}

	// Fig 16. Verification
	{
		if N.Bit(0) == 0 || N.ProbablyPrime(30) {
			return false
		}
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)

		go func(i int) {
			a := pf.A.Bit(i)
			b := pf.B.Bit(i)
			if a != 0 && a != 1 {
				chs <- false
				return
			}
			if b != 0 && b != 1 {
				chs <- false
				return
			}
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			return false
		}
	}

	return true
}

func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		if pf.X[i] != nil {
			bzs[1+i] = pf.X[i].Bytes()
		}
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		if pf.Z[i] != nil {
			bzs[Iterations+3+i] = pf.Z[i].Bytes()
		}
	}
	return bzs
}
