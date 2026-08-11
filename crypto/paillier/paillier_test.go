// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package paillier_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/AnvoIO/tss-lib/v4/common"
	"github.com/AnvoIO/tss-lib/v4/crypto"
	. "github.com/AnvoIO/tss-lib/v4/crypto/paillier"
	"github.com/AnvoIO/tss-lib/v4/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey *PrivateKey
	publicKey  *PublicKey
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestGenerateKeyPair(t *testing.T) {
	setUp(t)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestGenerateKeyPairOptionalConcurrencyValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	sk, pk, err := GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength, 1, 2)
	assert.Error(t, err)
	assert.Nil(t, sk)
	assert.Nil(t, pk)

	sk, pk, err = GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength, 0)
	assert.Error(t, err)
	assert.Nil(t, sk)
	assert.Nil(t, pk)
}

func TestEncrypt(t *testing.T) {
	setUp(t)
	cipher, err := publicKey.Encrypt(rand.Reader, big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(rand.Reader, exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}

func TestHomoMul(t *testing.T) {
	setUp(t)
	three, err := privateKey.Encrypt(rand.Reader, big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	setUp(t)
	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	one, _ := publicKey.Encrypt(rand.Reader, num1)
	two, _ := publicKey.Encrypt(rand.Reader, num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestProofVerify(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof, err := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestProofVerifyFail(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof, err := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	last := proof[len(proof)-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify result must be true")
}

// TestProofVerifyRejectsPrimePkN demonstrates the Fermat trivial-pass: for prime
// pkN, every xi in Z_{pkN}* satisfies xi^pkN == xi (mod pkN), so a proof with
// pf[i] = xs[i] passes the iteration check without proving any factorization.
// Verify must reject the modulus before that point.
func TestProofVerifyRejectsPrimePkN(t *testing.T) {
	ki := common.MustGetRandomInt(rand.Reader, 256)
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	pub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)

	primePkN := common.GetRandomPrimeInt(rand.Reader, 2048)
	xs := GenerateXs(ProofIters, ki, primePkN, pub)
	var forged Proof
	for i := range forged {
		forged[i] = new(big.Int).Mod(xs[i], primePkN)
	}

	res, err := forged.Verify(primePkN, ki, pub)
	assert.NoError(t, err)
	assert.False(t, res, "Verify must reject a prime pkN even when iteration equality would otherwise hold")
}

func TestProofVerifyRejectsMalformedInputs(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	pub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)
	good, gerr := privateKey.Proof(ki, pub)
	assert.NoError(t, gerr)

	t.Run("nil pkN", func(t *testing.T) {
		res, err := good.Verify(nil, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("nil k", func(t *testing.T) {
		res, err := good.Verify(publicKey.N, nil, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("nil ecdsaPub", func(t *testing.T) {
		res, err := good.Verify(publicKey.N, ki, nil)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pkN too small", func(t *testing.T) {
		small := big.NewInt(15) // 3*5, composite but tiny
		res, err := good.Verify(small, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pkN even", func(t *testing.T) {
		even := new(big.Int).Lsh(publicKey.N, 1) // shift to make even, keep bit length
		res, err := good.Verify(even, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] nil", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = nil
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] zero", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = big.NewInt(0)
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] out of range", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = new(big.Int).Add(publicKey.N, big.NewInt(1)) // > N
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] non-unit", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		// privateKey.P is a prime factor of publicKey.N, so gcd(P, N) = P > 1
		bad[0] = new(big.Int).Set(privateKey.P)
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := common.MustGetRandomInt(rand.Reader, 256)
	sX := common.MustGetRandomInt(rand.Reader, 256)
	sY := common.MustGetRandomInt(rand.Reader, 256)
	N := common.GetRandomPrimeInt(rand.Reader, 2048)

	xs := GenerateXs(13, k, N, crypto.NewECPointNoCurveCheck(tss.EC(), sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}
