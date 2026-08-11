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
	"io"
	"math/big"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/crypto/paillier"
)

// alphaPrmInRange reports whether a decrypted MtA plaintext lies within the
// range a protocol-conforming counterparty can produce, [0, q^6).
//
// The range proofs verified beforehand bound the magnitude of the prover's
// responses, which is not the same as bounding the value that comes back out of
// the decryption, so the output is checked directly. A conforming run yields
// alphaPrm = a*b + betaPrm < q^2 + q^5 < q^6 (~1536 bits), while the Paillier
// modulus is at least 2^2047, so the cut has wide margin on both sides.
func alphaPrmInRange(alphaPrm, q *big.Int) bool {
	if alphaPrm == nil || alphaPrm.Sign() < 0 {
		return false
	}
	q6 := new(big.Int).Exp(q, big.NewInt(6), nil)
	return alphaPrm.Cmp(q6) < 0
}

func AliceInit(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	a, NTildeB, h1B, h2B *big.Int,
	rand io.Reader,
) (cA *big.Int, pf *RangeProofAlice, err error) {
	cA, rA, err := pkA.EncryptAndReturnRandomness(rand, a)
	if err != nil {
		return nil, nil, err
	}
	pf, err = ProveRangeAlice(Session, ec, pkA, cA, NTildeB, h1B, h2B, a, rA, rand)
	return cA, pf, err
}

func BobMid(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	rand io.Reader,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	if !pf.Verify(Session, ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)  // q^2
	q5 = new(big.Int).Mul(q5, q5) // q^4
	q5 = new(big.Int).Mul(q5, q)  // q^5
	betaPrm = common.GetRandomPositiveInt(rand, q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(rand, betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, rand)
	return
}

func BobMidWC(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *crypto.ECPoint,
	rand io.Reader,
) (beta, cB, betaPrm *big.Int, piB *ProofBobWC, err error) {
	if !pf.Verify(Session, ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)  // q^2
	q5 = new(big.Int).Mul(q5, q5) // q^4
	q5 = new(big.Int).Mul(q5, q)  // q^5
	betaPrm = common.GetRandomPositiveInt(rand, q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(rand, betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBobWC(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B, rand)
	return
}

func AliceEnd(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if sk == nil || sk.N == nil || sk.LambdaN == nil || sk.PhiN == nil {
		return nil, errors.New("AliceEnd: invalid Paillier private key")
	}
	if !pf.Verify(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB) {
		return nil, errors.New("ProofBob.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	// The verified proof bounds the prover's responses, not the decrypted
	// output. Reject a plaintext outside [0, q^6) — the range a protocol-
	// conforming counterparty can produce — before it is reduced mod q, which
	// would otherwise silently absorb an out-of-range value.
	if !alphaPrmInRange(alphaPrm, q) {
		return nil, errors.New("AliceEnd: decrypted share outside the expected range")
	}
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndWC(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *crypto.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if sk == nil || sk.N == nil || sk.LambdaN == nil || sk.PhiN == nil {
		return nil, errors.New("AliceEndWC: invalid Paillier private key")
	}
	if !pf.Verify(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, B) {
		return nil, errors.New("ProofBobWC.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	// The verified proof bounds the prover's responses, not the decrypted
	// output. Reject a plaintext outside [0, q^6) — the range a protocol-
	// conforming counterparty can produce — before it is reduced mod q, which
	// would otherwise silently absorb an out-of-range value.
	if !alphaPrmInRange(alphaPrm, q) {
		return nil, errors.New("AliceEndWC: decrypted share outside the expected range")
	}
	return new(big.Int).Mod(alphaPrm, q), nil
}
