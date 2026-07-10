// Copyright © 2026 Stratovera LLC and its contributors.
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"sync"
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

type invalidUpdateResult struct {
	ok  bool
	err *tss.Error
}

// runEdDSASigningE2E runs a full EdDSA signing protocol and returns the parties and signature data.
func runEdDSASigningE2E(t *testing.T, msg *big.Int, keys []keygen.LocalPartySaveData, signPIDs tss.SortedPartyIDs, injectInvalidSender ...bool) ([]*LocalParty, *common.SignatureData) {
	t.Helper()

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	injectInvalid := len(injectInvalidSender) > 0 && injectInvalidSender[0]
	invalidResults := make(chan invalidUpdateResult, 256)
	var invalidWG sync.WaitGroup
	var invalidMessage tss.ParsedMessage
	if injectInvalid {
		outsider := tss.NewPartyID("outsider", "outsider", big.NewInt(999999999))
		outsider.Index = 0
		_, isMember := signPIDs.IndexOf(outsider)
		require.False(t, isMember)
		invalidMessage = NewSignRound1Message(outsider, big.NewInt(1))
	}

	injectFor := func(party *LocalParty) {
		if !injectInvalid {
			return
		}
		invalidWG.Add(1)
		go func() {
			defer invalidWG.Done()
			ok, updateErr := party.Update(invalidMessage)
			invalidResults <- invalidUpdateResult{ok: ok, err: updateErr}
		}()
	}

	updater := test.SharedPartyUpdater
	for i := 0; i < len(signPIDs); i++ {
		params, pErr := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		require.NoError(t, pErr)
		params.SetSessionNonce(big.NewInt(1))
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
					injectFor(P)
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				target := parties[dest[0].Index]
				injectFor(target)
				go updater(target, msg, errCh)
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
	if injectInvalid {
		invalidWG.Wait()
		close(invalidResults)
		for invalidResult := range invalidResults {
			require.False(t, invalidResult.ok)
			require.ErrorContains(t, invalidResult.err, "message sender is not a committee member")
		}
	}
	return parties, result
}

func TestUpdateRejectsOutsiderWithoutClearingSensitiveData(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	params, err := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[0], len(signPIDs), testThreshold)
	require.NoError(t, err)
	params.SetSessionNonce(big.NewInt(1))

	outCh := make(chan tss.Message, 1)
	endCh := make(chan *common.SignatureData, 1)
	party := NewLocalPartyWithBytes([]byte("live-session-secret"), params, keys[0], outCh, endCh).(*LocalParty)
	require.Nil(t, party.Start())
	require.NotNil(t, party.temp.wi)
	require.NotNil(t, party.temp.ri)

	wiBefore := new(big.Int).Set(party.temp.wi)
	riBefore := new(big.Int).Set(party.temp.ri)
	messageBefore := append([]byte{}, party.temp.message...)

	outsider := tss.NewPartyID("outsider", "outsider", big.NewInt(999999999))
	outsider.Index = 0
	_, isMember := signPIDs.IndexOf(outsider)
	require.False(t, isMember)
	invalidMessage := NewSignRound1Message(outsider, big.NewInt(1))

	type updateResult struct {
		ok  bool
		err *tss.Error
	}
	const updateCount = 32
	results := make(chan updateResult, updateCount)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < updateCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, updateErr := party.Update(invalidMessage)
			results <- updateResult{ok: ok, err: updateErr}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for result := range results {
		require.False(t, result.ok)
		require.ErrorContains(t, result.err, "message sender is not a committee member")
	}
	require.Equal(t, wiBefore, party.temp.wi)
	require.Equal(t, riBefore, party.temp.ri)
	require.Equal(t, messageBefore, party.temp.message)
}

func TestE2EConcurrentInvalidSenderValidation(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	require.NoError(t, err)

	_, sigData := runEdDSASigningE2E(t, big.NewInt(200), keys, signPIDs, true)
	require.NotNil(t, sigData)
	assert.NotEmpty(t, sigData.Signature)
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
	message := []byte{4, 5, 6}
	td.message = message
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
	assert.Nil(t, td.message, "message should be nil after Clear()")
	for i, b := range message {
		assert.Equal(t, byte(0), b, "message[%d] should be zeroed", i)
	}
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
