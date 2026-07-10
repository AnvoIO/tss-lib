// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"errors"
	"io"
	"math/big"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
)

type (
	ZKProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}

	ZKVProof struct {
		Alpha *crypto.ECPoint
		T, U  *big.Int
	}
)

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func NewZKProof(Session []byte, x *big.Int, X *crypto.ECPoint, rand io.Reader) (*ZKProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(rand, q)
	alpha := crypto.ScalarBaseMult(ec, a)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t := common.ModInt(q).Mul(c, x)
	t = common.ModInt(q).Add(a, t)

	return &ZKProof{Alpha: alpha, T: t}, nil
}

// NewZKProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(Session []byte, X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil {
		return false
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	// reject non-canonical proof scalar (T must be in [0, q))
	if pf.T.Sign() < 0 || pf.T.Cmp(q) >= 0 {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	// pf.T is peer-supplied and only range-checked to [0, q), so T == 0 is
	// possible; ScalarBaseMult(0) is the point at infinity and would panic. Use
	// the checked variant and reject instead. c is a hash challenge (≈never 0),
	// checked too for uniformity.
	tG, err := crypto.ScalarBaseMultChecked(ec, pf.T)
	if err != nil {
		return false
	}
	Xc, err := X.ScalarMultChecked(c)
	if err != nil {
		return false
	}
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	return aXc.X().Cmp(tG.X()) == 0 && aXc.Y().Cmp(tG.Y()) == 0
}

func (pf *ZKProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17)
func NewZKVProof(Session []byte, V, R *crypto.ECPoint, s, l *big.Int, rand io.Reader) (*ZKVProof, error) {
	if V == nil || R == nil || s == nil || l == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return nil, errors.New("ZKVProof constructor received nil value(s)")
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(rand, q), common.GetRandomPositiveInt(rand, q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(ec, b)
	alpha, _ := aR.Add(bG) // already on the curve.

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	modQ := common.ModInt(q)
	t := modQ.Add(a, modQ.Mul(c, s))
	u := modQ.Add(b, modQ.Mul(c, l))

	return &ZKVProof{Alpha: alpha, T: t, U: u}, nil
}

func (pf *ZKVProof) Verify(Session []byte, V, R *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || V == nil || R == nil {
		return false
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	// reject non-canonical proof scalars (T, U must be in [0, q))
	if pf.T.Sign() < 0 || pf.T.Cmp(q) >= 0 || pf.U.Sign() < 0 || pf.U.Cmp(q) >= 0 {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	// pf.T, pf.U are peer-supplied and only range-checked to [0, q), so a value of
	// 0 is possible; R^0 and G^0 are the point at infinity and would panic. Use the
	// checked variants and reject instead. c is a hash challenge, checked too.
	tR, err := R.ScalarMultChecked(pf.T)
	if err != nil {
		return false
	}
	uG, err := crypto.ScalarBaseMultChecked(ec, pf.U)
	if err != nil {
		return false
	}
	tRuG, err := tR.Add(uG)
	if err != nil {
		return false
	}
	Vc, err := V.ScalarMultChecked(c)
	if err != nil {
		return false
	}
	aVc, err := pf.Alpha.Add(Vc)
	if err != nil {
		return false
	}
	return tRuG.X().Cmp(aVc.X()) == 0 && tRuG.Y().Cmp(aVc.Y()) == 0
}

func (pf *ZKVProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.T != nil && pf.U != nil && pf.Alpha.ValidateBasic()
}
