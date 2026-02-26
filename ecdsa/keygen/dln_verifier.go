// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"

	"github.com/AnvoIO/tss-lib/v3/crypto/dlnproof"
)

type DlnProofVerifier struct {
	semaphore chan interface{}
}

type message interface {
	UnmarshalDLNProof1() (*dlnproof.Proof, error)
	UnmarshalDLNProof2() (*dlnproof.Proof, error)
}

func NewDlnProofVerifier(concurrency int) *DlnProofVerifier {
	if concurrency < 1 {
		concurrency = 1
	}

	semaphore := make(chan interface{}, concurrency)

	return &DlnProofVerifier{
		semaphore: semaphore,
	}
}

func (dpv *DlnProofVerifier) VerifyDLNProof1(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof1()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (dpv *DlnProofVerifier) VerifyDLNProof2(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof2()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}
