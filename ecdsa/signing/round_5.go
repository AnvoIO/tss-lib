// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/crypto"
	"github.com/AnvoIO/tss-lib/v3/crypto/commitments"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	R := round.temp.pointGamma
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		r1msg2 := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)
		SCj, SDj := r1msg2.UnmarshalCommitment(), r4msg.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
		ok, bigGammaJ := cmtDeCmt.DeCommit()
		if !ok || len(bigGammaJ) != 2 {
			return round.WrapError(errors.New("commitment verify failed"), Pj)
		}
		bigGammaJPoint, err := crypto.NewECPoint(round.Params().EC(), bigGammaJ[0], bigGammaJ[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigGammaJ)"), Pj)
		}
		proof, err := r4msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal bigGamma proof"), Pj)
		}
		ok = proof.Verify(ContextJ, bigGammaJPoint)
		if !ok {
			return round.WrapError(errors.New("failed to prove bigGamma"), Pj)
		}
		R, err = R.Add(bigGammaJPoint)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "R.Add(bigGammaJ)"), Pj)
		}
	}

	R = R.ScalarMult(round.temp.thetaInverse)
	N := round.Params().EC().Params().N
	modN := common.ModInt(N)
	rx := R.X()
	ry := R.Y()
	si := modN.Add(modN.Mul(round.temp.m, round.temp.k), modN.Mul(rx, round.temp.sigma))

	// Clear secrets in place; do not assign package-level shared zero pointers.
	if round.temp.w != nil {
		round.temp.w.SetInt64(0)
	}
	if round.temp.k != nil {
		round.temp.k.SetInt64(0)
	}

	li := common.GetRandomPositiveInt(round.Rand(), N) // li
	if li == nil {
		return round.WrapError(errors.New("failed to generate random li"))
	}
	roI := common.GetRandomPositiveInt(round.Rand(), N) // pi
	if roI == nil {
		return round.WrapError(errors.New("failed to generate random roi"))
	}
	rToSi := R.ScalarMult(si)
	liPoint := crypto.ScalarBaseMult(round.Params().EC(), li)
	bigAi := crypto.ScalarBaseMult(round.Params().EC(), roI)
	bigVi, err := rToSi.Add(liPoint)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "rToSi.Add(li)"))
	}

	cmt := commitments.NewHashCommitment(round.Rand(), bigVi.X(), bigVi.Y(), bigAi.X(), bigAi.Y())
	r5msg := NewSignRound5Message(round.PartyID(), cmt.C)
	round.temp.signRound5Messages[round.PartyID().Index] = r5msg
	round.out <- r5msg

	round.temp.li = li
	round.temp.bigAi = bigAi
	round.temp.bigVi = bigVi
	round.temp.roi = roI
	round.temp.DPower = cmt.D
	round.temp.si = si
	round.temp.rx = rx
	round.temp.ry = ry
	round.temp.bigR = R

	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound5Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round}
}
