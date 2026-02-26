// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AnvoIO/tss-lib/v3/common"
	"github.com/AnvoIO/tss-lib/v3/ecdsa/keygen"
	"github.com/AnvoIO/tss-lib/v3/test"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

// runSigningE2E runs a full ECDSA signing protocol and returns the signature data.
func runSigningE2E(t *testing.T, msg *big.Int) *common.SignatureData {
	t.Helper()
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err, "should load keygen fixtures")

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
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
	return result
}

func TestE2E_SignZeroMessage(t *testing.T) {
	setUp("info")
	sigData := runSigningE2E(t, big.NewInt(0))
	require.NotNil(t, sigData)
	assert.NotEmpty(t, sigData.R)
	assert.NotEmpty(t, sigData.S)
}

func TestE2E_SignMaxMessage(t *testing.T) {
	setUp("info")
	N := tss.S256().Params().N
	maxMsg := new(big.Int).Sub(N, big.NewInt(1))
	sigData := runSigningE2E(t, maxMsg)
	require.NotNil(t, sigData)
	assert.NotEmpty(t, sigData.R)
	assert.NotEmpty(t, sigData.S)
}

func TestE2E_ReSignSameKey(t *testing.T) {
	setUp("info")
	fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())

	sigData1 := runSigningE2E(t, big.NewInt(42))
	require.NotNil(t, sigData1)

	sigData2 := runSigningE2E(t, big.NewInt(43))
	require.NotNil(t, sigData2)

	// Both should be valid but different
	assert.NotEqual(t, sigData1.Signature, sigData2.Signature, "different messages should produce different signatures")
}

func TestClear_ZerosSecretMaterial(t *testing.T) {
	td := &localTempData{}

	// Populate fields with known non-zero values
	td.w = big.NewInt(123)
	td.m = big.NewInt(456)
	td.k = big.NewInt(789)
	td.theta = big.NewInt(101)
	td.thetaInverse = big.NewInt(102)
	td.sigma = big.NewInt(103)
	td.gamma = big.NewInt(104)
	td.si = big.NewInt(105)
	td.li = big.NewInt(106)
	td.roi = big.NewInt(107)
	td.betas = []*big.Int{big.NewInt(201), big.NewInt(202)}
	td.cis = []*big.Int{big.NewInt(301), big.NewInt(302)}

	td.Clear()

	// Internally-generated secrets should be zeroed
	for _, field := range []*big.Int{td.w, td.k, td.theta, td.thetaInverse, td.sigma, td.gamma, td.si, td.li, td.roi} {
		assert.Equal(t, int64(0), field.Int64(), "secret field should be zeroed")
	}
	// m should be nil'd (externally provided)
	assert.Nil(t, td.m, "m should be nil after Clear()")
	// betas and cis should be zeroed
	for _, b := range td.betas {
		assert.Equal(t, int64(0), b.Int64(), "beta should be zeroed")
	}
	for _, c := range td.cis {
		assert.Equal(t, int64(0), c.Int64(), "ci should be zeroed")
	}
}

func TestSignature_ValidWithStdLib(t *testing.T) {
	setUp("info")
	msgVal := big.NewInt(42)
	sigData := runSigningE2E(t, msgVal)
	require.NotNil(t, sigData)

	keys, _, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	r := new(big.Int).SetBytes(sigData.R)
	s := new(big.Int).SetBytes(sigData.S)

	pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     pkX,
		Y:     pkY,
	}
	ok := ecdsa.Verify(&pk, msgVal.Bytes(), r, s)
	assert.True(t, ok, "signature must verify with crypto/ecdsa")
}

func TestSignature_SMalleabilityProtection(t *testing.T) {
	setUp("info")
	sigData := runSigningE2E(t, big.NewInt(42))
	require.NotNil(t, sigData)

	s := new(big.Int).SetBytes(sigData.S)
	N := tss.S256().Params().N
	halfN := new(big.Int).Rsh(N, 1)

	assert.True(t, s.Cmp(halfN) <= 0, "S should be <= N/2 for anti-malleability (S=%s, N/2=%s)", s.String(), halfN.String())
}
