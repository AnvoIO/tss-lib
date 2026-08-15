// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
)

const (
	RangeProofAliceBytesParts = 6
	MaxProofElementBytes      = 1024
	// verifyMinModulusBitLen matches the keygen wire-format check for the
	// Paillier N and NTilde moduli (paillierBitsLen = 2048). Also used by
	// ProofBobWC.Verify in proofs.go.
	verifyMinModulusBitLen = 2048
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type (
	RangeProofAlice struct {
		Z, U, W, S, S1, S2 *big.Int
	}
)

// counterpartyRingUsable applies, to the ring a prover is about to commit into,
// the shape conditions RangeProofAlice.Verify and ProofBobWC.Verify both apply
// to it. The ring is the counterparty's keygen output, so this runs BEFORE a
// secret is committed into it rather than after the counterparty has rejected
// the result. (Keygen's DLN proof establishes <h1> == <h2> but not their order,
// so an order-3 ring passes every keygen gate; this does not fix that, it moves
// the resulting rejection to the party responsible for the ring.)
func counterpartyRingUsable(NTilde, h1, h2 *big.Int) bool {
	if NTilde == nil || h1 == nil || h2 == nil {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen) {
		return false
	}
	return common.IsCanonicalGenerator(NTilde, h1) &&
		common.IsCanonicalGenerator(NTilde, h2) &&
		h1.Cmp(h2) != 0
}

// ringSideValuesUsable applies, to values this party has just computed IN the
// counterparty's ring, the conditions a verifier applies to them. ONLY ring-side
// values (Pedersen commitments h1^a*h2^b mod NTilde) belong here: a rejection
// caused by the local party's own Paillier key or randomness is already its own
// fault, so admitting a value that is NOT ring-decided would name an innocent
// counterparty. The v == 1 check is applied uniformly — stricter than the
// verifier, which names it for RangeProofAlice's Z alone — which against
// large-order generators costs a conforming counterparty a proof with
// probability about 2^-2046.
func ringSideValuesUsable(NTilde *big.Int, values ...*big.Int) bool {
	for _, v := range values {
		if v == nil || !common.IsInIntervalPositive(v, NTilde) {
			return false
		}
		if v.Cmp(one) == 0 {
			return false
		}
		if new(big.Int).GCD(nil, nil, v, NTilde).Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// ProveRangeAlice implements Alice's range proof used in the MtA and MtAwc protocols from GG18Spec (9) Fig. 9.
func ProveRangeAlice(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, c, NTilde, h1, h2, m, r *big.Int, rand io.Reader) (*RangeProofAlice, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil || m == nil || r == nil {
		return nil, errors.New("ProveRangeAlice constructor received nil value(s)")
	}
	// (NTilde, h1, h2) is the counterparty's ring, and so is the verifier that
	// will judge the result — check it before committing a secret into it so a
	// ring-decided failure is attributed to the counterparty (via
	// ErrCounterpartyRingUnusable), not to this honest prover.
	if !counterpartyRingUsable(NTilde, h1, h2) {
		return nil, ErrCounterpartyRingUnusable
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// 1.
	alpha := common.GetRandomPositiveInt(rand, q3)
	// 2.
	beta := common.GetRandomPositiveRelativelyPrimeInt(rand, pk.N)

	// 3.
	gamma := common.GetRandomPositiveInt(rand, q3NTilde)

	// 4.
	rho := common.GetRandomPositiveInt(rand, qNTilde)

	// 5.
	modNTilde := common.ModInt(NTilde)
	z := modNTilde.Exp(h1, m)
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho))

	// 6.
	modNSquared := common.ModInt(pk.NSquare())
	u := modNSquared.Exp(pk.Gamma(), alpha)
	u = modNSquared.Mul(u, modNSquared.Exp(beta, pk.N))

	// 7.
	w := modNTilde.Exp(h1, alpha)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, gamma))

	// 8-9. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), NTilde, h1, h2, c, z, u, w)...)
		e = common.RejectionSample(q, eHash)
	}

	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// s1 = e * m + alpha
	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	// s2 = e * rho + gamma
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	pf := &RangeProofAlice{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
	// Do not hand out a proof whose ring-side values the counterparty's own
	// verifier rejects. Z is the one Verify names explicitly (pf.Z.Cmp(one) == 0)
	// and Z is a function of the counterparty's generators, so without this the
	// counterparty both causes the rejection and reports it against this prover.
	if !ringSideValuesUsable(NTilde, pf.Z, pf.W) {
		return nil, ErrCounterpartyRingUnusable
	}
	return pf, nil
}

func RangeProofAliceFromBytes(bzs [][]byte) (*RangeProofAlice, error) {
	if !common.NonEmptyMultiBytesBounded(bzs, MaxProofElementBytes, RangeProofAliceBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct RangeProofAlice", RangeProofAliceBytesParts)
	}
	return &RangeProofAlice{
		Z:  new(big.Int).SetBytes(bzs[0]),
		U:  new(big.Int).SetBytes(bzs[1]),
		W:  new(big.Int).SetBytes(bzs[2]),
		S:  new(big.Int).SetBytes(bzs[3]),
		S1: new(big.Int).SetBytes(bzs[4]),
		S2: new(big.Int).SetBytes(bzs[5]),
	}, nil
}

func (pf *RangeProofAlice) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || pk.N == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil {
		return false
	}
	// pk.N and NTilde must both be plausible unknown-order moduli before any
	// modular arithmetic runs (prevents prime / undersized / even / nil moduli
	// from making downstream operations panic or trivially pass).
	if !common.IsUsableUnknownOrderModulus(pk.N, verifyMinModulusBitLen) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen) {
		return false
	}
	// h1, h2 are public NTilde generators agreed in keygen; require canonical
	// non-trivial unit membership and distinctness.
	if !common.IsCanonicalGenerator(NTilde, h1) || !common.IsCanonicalGenerator(NTilde, h2) || h1.Cmp(h2) == 0 {
		return false
	}
	// c is the Paillier ciphertext from the peer. Require canonical encoding
	// (in (0, N^2)) and gcd(c, N) == 1 — the latter prevents c^(-e) mod N^2 from
	// returning nil when the modular inverse doesn't exist (also covers c == 0);
	// the former rejects non-canonical c + k*N^2 that could bypass downstream
	// invariants. Replaces the previous standalone gcd(c, N) check.
	if !common.IsCanonicalPaillierCiphertext(c, pk.N) {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	upperS2 := new(big.Int).Mul(q3, NTilde)
	upperS2.Lsh(upperS2, 1)

	if !common.IsInInterval(pf.Z, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.U, pk.NSquare()) {
		return false
	}
	if !common.IsInInterval(pf.W, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.S, pk.N) {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.Z, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.U, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.W, NTilde).Cmp(one) != 0 {
		return false
	}
	// Mirror of ProofBob/WC.Verify's gcd(S, N) check. Honest S = r^e * beta
	// mod N is a unit (beta is sampled coprime to N, r in Z_N*); reject the
	// non-unit case directly rather than relying on downstream equality checks.
	if new(big.Int).GCD(nil, nil, pf.S, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.S1.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(q) == -1 {
		return false
	}
	// Upper bound derived from honest sampling: S2 = e*rho + gamma with
	// rho < q*NTilde, gamma < q^3*NTilde, e < q, so S2 < 2*q^3*NTilde. Rejects
	// attacker-controlled oversized exponents before any modexp (CPU-amplification DoS).
	if pf.S2.Cmp(upperS2) >= 0 {
		return false
	}
	if pf.S.Cmp(one) == 0 {
		return false
	}
	if pf.Z.Cmp(one) == 0 {
		return false
	}
	if pf.S1.Cmp(pf.S2) == 0 {
		return false
	}

	// 3.
	if pf.S1.Cmp(q3) == 1 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), NTilde, h1, h2, c, pf.Z, pf.U, pf.W)...)
		e = common.RejectionSample(q, eHash)
	}

	var products *big.Int // for the following conditionals
	minusE := new(big.Int).Sub(zero, e)

	{ // 4. gamma^s_1 * s^N * c^-e
		modNSquared := common.ModInt(pk.NSquare())

		cExpMinusE := modNSquared.Exp(c, minusE)
		sExpN := modNSquared.Exp(pf.S, pk.N)
		gammaExpS1 := modNSquared.Exp(pk.Gamma(), pf.S1)
		// u != (4)
		products = modNSquared.Mul(gammaExpS1, sExpN)
		products = modNSquared.Mul(products, cExpMinusE)
		if pf.U.Cmp(products) != 0 {
			return false
		}
	}

	{ // 5. h_1^s_1 * h_2^s_2 * z^-e
		modNTilde := common.ModInt(NTilde)

		h1ExpS1 := modNTilde.Exp(h1, pf.S1)
		h2ExpS2 := modNTilde.Exp(h2, pf.S2)
		zExpMinusE := modNTilde.Exp(pf.Z, minusE)
		// w != (5)
		products = modNTilde.Mul(h1ExpS1, h2ExpS2)
		products = modNTilde.Mul(products, zExpMinusE)
		if pf.W.Cmp(products) != 0 {
			return false
		}
	}
	return true
}

func (pf *RangeProofAlice) ValidateBasic() bool {
	return pf.Z != nil &&
		pf.U != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil
}

func (pf *RangeProofAlice) Bytes() [RangeProofAliceBytesParts][]byte {
	return [...][]byte{
		pf.Z.Bytes(),
		pf.U.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
	}
}
