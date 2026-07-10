// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/AnvoIO/tss-lib/v4/common"
)

// TestRejectionSample_DoesNotMutateInput is a defense-in-depth regression test:
// RejectionSample must not reduce eHash in place, or a caller that reuses the
// same *big.Int across calls (or afterwards) silently gets a corrupted value.
func TestRejectionSample_DoesNotMutateInput(t *testing.T) {
	q := big.NewInt(97)
	eHash := new(big.Int).SetInt64(1000)
	before := new(big.Int).Set(eHash)

	got := common.RejectionSample(q, eHash)

	if eHash.Cmp(before) != 0 {
		t.Fatalf("RejectionSample mutated its input: got %v, was %v", eHash, before)
	}
	if got.Cmp(big.NewInt(1000%97)) != 0 {
		t.Fatalf("RejectionSample returned %v, want %v", got, 1000%97)
	}
}

func TestRejectionSample(t *testing.T) {
	curveQ := common.GetRandomPrimeInt(rand.Reader, 256)
	randomQ := common.MustGetRandomInt(rand.Reader, 64)
	hash := common.SHA512_256iOne(big.NewInt(123))
	rs1 := common.RejectionSample(curveQ, hash)
	rs2 := common.RejectionSample(randomQ, hash)
	rs3 := common.RejectionSample(common.MustGetRandomInt(rand.Reader, 64), hash)
	type args struct {
		q     *big.Int
		eHash *big.Int
	}
	tests := []struct {
		name       string
		args       args
		want       *big.Int
		wantBitLen int
		notEqual   bool
	}{{
		name:       "happy path with curve order",
		args:       args{curveQ, hash},
		want:       rs1,
		wantBitLen: 256,
	}, {
		name:       "happy path with random 64-bit int",
		args:       args{randomQ, hash},
		want:       rs2,
		wantBitLen: 64,
	}, {
		name:       "inequality with different input",
		args:       args{randomQ, hash},
		want:       rs3,
		wantBitLen: 64,
		notEqual:   true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.RejectionSample(tt.args.q, tt.args.eHash)
			if !tt.notEqual && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RejectionSample() = %v, want %v", got, tt.want)
			}
			if tt.wantBitLen < got.BitLen() { // leading zeros not counted
				t.Errorf("RejectionSample() = bitlen %d, want %d", got.BitLen(), tt.wantBitLen)
			}
		})
	}
}
