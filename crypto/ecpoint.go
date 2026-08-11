// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/AnvoIO/tss-lib/v4/tss"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

var (
	eight    = big.NewInt(8)
	eightInv = new(big.Int).ModInverse(eight, edwards.Edwards().Params().N)
)

func init() {
	if eightInv == nil {
		panic("crypto/ecpoint: failed to compute ModInverse(8, edwards.N)")
	}
}

// Creates a new ECPoint and checks that the given coordinates are on the elliptic curve.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

// Creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	// SECURITY (SRC-2026-641): guard against a nil receiver/operand or a nil
	// coordinate before dereferencing via X()/Y(). A degenerate point reaching
	// Add then surfaces as an error the caller can attribute to the responsible
	// peer rather than crashing the process. Every Add call site already checks
	// the returned error.
	if p == nil || p1 == nil || !p.ValidateBasic() || !p1.ValidateBasic() {
		return nil, errors.New("ECPoint.Add: invalid operand")
	}
	if !tss.SameCurve(p.curve, p1.curve) {
		return nil, errors.New("ECPoint.Add: curve mismatch")
	}
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

// ScalarMult multiplies the point by k. It panics if the result is the point at
// infinity (which is not a representable ECPoint on a short-Weierstrass curve).
// Retained for callers that have already established k cannot reduce to 0 mod the
// group order; prefer ScalarMultChecked at sites that may receive a zero,
// order-multiple, or otherwise attacker-influenced scalar.
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	newP, err := p.ScalarMultChecked(k)
	if err != nil {
		panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
	}
	return newP
}

// ScalarMultChecked multiplies the point by k and returns an error, rather than
// panicking, when the result is the point at infinity. curve.ScalarMult yields
// the identity for k ≡ 0 mod N (a zero or order-multiple scalar); on a
// short-Weierstrass curve such as secp256k1 the identity encodes as (0,0), which
// is off-curve and so is rejected by NewECPoint. Callers that may pass such a
// scalar should use this variant and handle the error instead of crashing.
func (p *ECPoint) ScalarMultChecked(k *big.Int) (*ECPoint, error) {
	if p == nil || !p.ValidateBasic() {
		return nil, errors.New("ScalarMultChecked: invalid point")
	}
	if k == nil || k.Sign() < 0 {
		return nil, errors.New("ScalarMultChecked: scalar must be non-negative")
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	newP, err := NewECPoint(p.curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("ScalarMultChecked: result is not a valid curve point (point at infinity?): %w", err)
	}
	return newP, nil
}

func (p *ECPoint) ToECDSAPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

func (p *ECPoint) IsOnCurve() bool {
	return p != nil && isOnCurve(p.curve, p.coords[0], p.coords[1])
}

func (p *ECPoint) Curve() elliptic.Curve {
	return p.curve
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil ||
		p.coords[0] == nil || p.coords[1] == nil ||
		p2.coords[0] == nil || p2.coords[1] == nil ||
		!tss.SameCurve(p.curve, p2.curve) {
		return false
	}
	return p.coords[0].Cmp(p2.coords[0]) == 0 && p.coords[1].Cmp(p2.coords[1]) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.curve != nil && p.curve.Params() != nil &&
		p.curve.Params().N != nil && p.curve.Params().P != nil &&
		p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve() && !p.IsIdentity()
}

// IsIdentity reports whether p is the identity element of its curve. It covers
// both curve families used here:
//
//   - Edwards (Ed25519): the affine identity is (0, 1) and IS on-curve, so it
//     passes IsOnCurve unaided. Left unchecked, a party could submit (0, 1) as a
//     Schnorr commitment or VSS share and have a degenerate proof accepted.
//   - Weierstrass (secp256k1): the identity is the point-at-infinity, encoded as
//     (0, 0), which is off-curve and already rejected by isOnCurve; the (0, 0)
//     branch here is defense-in-depth against alternate infinity encodings.
//
// Returns false for nil points (no coordinate to inspect).
func (p *ECPoint) IsIdentity() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil {
		return false
	}
	if p.coords[0].Sign() != 0 {
		return false
	}
	return p.coords[1].Sign() == 0 || p.coords[1].Cmp(big.NewInt(1)) == 0
}

// IsInPrimeOrderSubgroup reports whether p lies in the prime-order subgroup of
// its curve, i.e. [curve.N]·p == identity. For prime-order curves (cofactor 1 —
// secp256k1 / NIST) every on-curve point satisfies this by Lagrange; for
// composite-cofactor curves (Ed25519, cofactor 8) it is load-bearing, since
// on-curve membership alone admits the 8 small-order points an adversary can
// inject as a Schnorr commitment, VSS share, etc.
//
// Adapted from upstream: our ScalarMult panics on the point-at-infinity, so we
// use ScalarMultChecked. On short-Weierstrass curves [N]·p reduces to the
// off-curve point-at-infinity, which surfaces here as an error — itself the
// prime-order witness. On Edwards curves the identity (0, 1) is on-curve, so a
// subgroup point comes back as a non-error identity.
//
// Returns false for nil points or points whose [N]·p is not the identity.
func (p *ECPoint) IsInPrimeOrderSubgroup() bool {
	if !p.ValidateBasic() {
		return false
	}
	n := p.curve.Params().N
	np, err := p.ScalarMultChecked(n)
	if err != nil {
		return true
	}
	return np.IsIdentity()
}

// ValidateInSubgroup is the stricter sibling of ValidateBasic for untrusted EC
// points. It runs the basic on-curve / non-identity / non-nil checks and, on
// composite-cofactor curves, additionally requires prime-order subgroup
// membership. On prime-order curves the subgroup check is structurally implied
// by IsOnCurve and is skipped to save a ScalarMult. Callers consuming
// attacker-controlled points (Schnorr Alpha/X/V/R, VSS vs[j], MtA ProofBobWC
// pf.U, etc.) should prefer this over ValidateBasic.
func (p *ECPoint) ValidateInSubgroup() bool {
	if !p.ValidateBasic() {
		return false
	}
	if !tss.HasCompositeCofactor(p.curve) {
		return true
	}
	return p.IsInPrimeOrderSubgroup()
}

func (p *ECPoint) EightInvEight() *ECPoint {
	return p.ScalarMult(eight).ScalarMult(eightInv)
}

// ScalarBaseMult multiplies the curve base point by k. Like ScalarMult it panics
// when the result is the point at infinity; prefer ScalarBaseMultChecked at sites
// that may receive a zero, order-multiple, or attacker-influenced scalar.
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	p, err := ScalarBaseMultChecked(curve, k)
	if err != nil {
		panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
	}
	return p
}

// ScalarBaseMultChecked multiplies the curve base point by k and returns an error,
// rather than panicking, when the result is the point at infinity (k ≡ 0 mod N).
func ScalarBaseMultChecked(curve elliptic.Curve, k *big.Int) (*ECPoint, error) {
	if curve == nil || curve.Params() == nil || curve.Params().N == nil || curve.Params().P == nil {
		return nil, errors.New("ScalarBaseMultChecked: invalid curve")
	}
	if k == nil || k.Sign() < 0 {
		return nil, errors.New("ScalarBaseMultChecked: scalar must be non-negative")
	}
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, err := NewECPoint(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("ScalarBaseMultChecked: result is not a valid curve point (point at infinity?): %w", err)
	}
	return p, nil
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if c == nil || c.Params() == nil || c.Params().P == nil || x == nil || y == nil {
		return false
	}
	// Reject coordinates outside [0, P) to prevent non-canonical point
	// representations from bypassing the curve equation check via modular
	// reduction (SRC-2026-573). btcec/v2's IsOnCurve silently accepts
	// coordinates >= P that fit in 32 bytes, reducing them mod P internally.
	P := c.Params().P
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
		return false
	}
	return c.IsOnCurve(x, y)
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

// ----- //
// Gob helpers for if you choose to encode messages with Gob.

func (p *ECPoint) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	x, err := p.coords[0].GobEncode()
	if err != nil {
		return nil, err
	}
	y, err := p.coords[1].GobEncode()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(len(x)))
	if err != nil {
		return nil, err
	}
	buf.Write(x)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(y)))
	if err != nil {
		return nil, err
	}
	buf.Write(y)

	return buf.Bytes(), nil
}

func (p *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	x := make([]byte, length)
	n, err := reader.Read(x)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	y := make([]byte, length)
	n, err = reader.Read(y)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}

	X := new(big.Int)
	if err := X.GobDecode(x); err != nil {
		return err
	}
	Y := new(big.Int)
	if err := Y.GobDecode(y); err != nil {
		return err
	}
	p.curve = tss.EC()
	p.coords = [2]*big.Int{X, Y}
	if !p.IsOnCurve() {
		return errors.New("ECPoint.UnmarshalJSON: the point is not on the elliptic curve")
	}
	return nil
}

// ----- //

// crypto.ECPoint is not inherently json marshal-able
func (p *ECPoint) MarshalJSON() ([]byte, error) {
	ecName, ok := tss.GetCurveName(p.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", p.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: p.coords,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		p.curve = ec
	} else {
		// forward compatible, use global ec as default value
		p.curve = tss.EC()
	}

	if !p.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", p.curve)
	}

	return nil
}
