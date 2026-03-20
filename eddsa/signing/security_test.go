// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// runEdDSASigningE2E runs a full EdDSA signing protocol and returns the parties and signature data.
func runEdDSASigningE2E(t *testing.T, msg *big.Int, keys []keygen.LocalPartySaveData, signPIDs tss.SortedPartyIDs) ([]*LocalParty, *common.SignatureData) {
	t.Helper()

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		require.NoError(t, pErr)
		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
	var result *common.SignatureData
signing:
	for {
		select {
		case err := <-errCh:
			require.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sigData := <-endCh:
			atomic.AddInt32(&ended, 1)
			if result == nil {
				result = sigData
			}
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
	return parties, result
}

func TestE2E_EdDSA_SignZeroMessage(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	_, sigData := runEdDSASigningE2E(t, big.NewInt(0), keys, signPIDs)
	require.NotNil(t, sigData)
	assert.NotEmpty(t, sigData.Signature)
}

func TestE2E_EdDSA_SignMaxMessage(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	N := tss.Edwards().Params().N
	maxMsg := new(big.Int).Sub(N, big.NewInt(1))
	_, sigData := runEdDSASigningE2E(t, maxMsg, keys, signPIDs)
	require.NotNil(t, sigData)
	assert.NotEmpty(t, sigData.Signature)
}

func TestE2E_EdDSA_ReSignSameKey(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	_, sigData1 := runEdDSASigningE2E(t, big.NewInt(42), keys, signPIDs)
	require.NotNil(t, sigData1)

	_, sigData2 := runEdDSASigningE2E(t, big.NewInt(43), keys, signPIDs)
	require.NotNil(t, sigData2)

	assert.NotEqual(t, sigData1.Signature, sigData2.Signature, "different messages should produce different signatures")
}

func TestClear_EdDSA_ZerosSecretMaterial(t *testing.T) {
	td := &localTempData{}

	// Populate fields with known non-zero values
	td.wi = big.NewInt(123)
	td.m = big.NewInt(456)
	td.ri = big.NewInt(789)
	td.r = big.NewInt(101)
	td.si = &[32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	td.cjs = []*big.Int{big.NewInt(201), big.NewInt(202)}

	td.Clear()

	// Internally-generated secrets should be zeroed
	assert.Equal(t, int64(0), td.wi.Int64(), "wi should be zeroed")
	assert.Equal(t, int64(0), td.ri.Int64(), "ri should be zeroed")
	assert.Equal(t, int64(0), td.r.Int64(), "r should be zeroed")
	// m should be nil'd (externally provided)
	assert.Nil(t, td.m, "m should be nil after Clear()")
	// si byte array should be zeroed
	for i, b := range td.si {
		assert.Equal(t, byte(0), b, "si[%d] should be zeroed", i)
	}
	// cjs should be zeroed
	for _, c := range td.cjs {
		assert.Equal(t, int64(0), c.Int64(), "cj should be zeroed")
	}
}

func TestSignature_EdDSA_ValidWithEdwards(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	msgVal := big.NewInt(200)
	parties, sigData := runEdDSASigningE2E(t, msgVal, keys, signPIDs)
	require.NotNil(t, sigData)

	pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
	pk := edwards.PublicKey{
		Curve: tss.Edwards(),
		X:     pkX,
		Y:     pkY,
	}

	newSig, err := edwards.ParseSignature(parties[0].data.Signature)
	require.NoError(t, err)

	ok := edwards.Verify(&pk, msgVal.Bytes(), newSig.R, newSig.S)
	assert.True(t, ok, "EdDSA signature must verify")
}
