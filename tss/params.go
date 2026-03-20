// Copyright © 2026 Stratovera LLC and its contributors.
// Copyright © 2019 Binance
//
// This file is part of the tss-lib project. The full copyright notice,
// including terms governing use, modification, and redistribution, is
// contained in the file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"time"
)

type (
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// sessionNonce provides per-session SSID uniqueness for GG20 session binding.
		// For signing, defaults to the message hash if not set.
		// For keygen/resharing, the caller SHOULD set this to a value agreed upon by
		// all parties (e.g., a coordinator-assigned session ID) to prevent cross-session
		// proof replay. If not set, falls back to 0 (no session binding).
		sessionNonce *big.Int
		// for keygen
		noProofMod bool
		noProofFac bool
		// random sources
		partialKeyRand, rand io.Reader
	}

	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) (*Parameters, error) {
	if ec == nil {
		return nil, fmt.Errorf("NewParameters: ec curve must not be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("NewParameters: peer context must not be nil")
	}
	if partyID == nil {
		return nil, fmt.Errorf("NewParameters: partyID must not be nil")
	}
	if partyCount < 2 {
		return nil, fmt.Errorf("NewParameters: partyCount must be >= 2, got %d", partyCount)
	}
	if threshold < 1 {
		return nil, fmt.Errorf("NewParameters: threshold must be >= 1, got %d", threshold)
	}
	if threshold >= partyCount {
		return nil, fmt.Errorf("NewParameters: threshold must be < partyCount, got threshold=%d partyCount=%d", threshold, partyCount)
	}
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
		partialKeyRand:      rand.Reader,
		rand:                rand.Reader,
	}, nil
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) Concurrency() int {
	return params.concurrency
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// The concurrency level must be >= 1.
func (params *Parameters) SetConcurrency(concurrency int) {
	if concurrency < 1 {
		concurrency = 1
	}
	params.concurrency = concurrency
}

func (params *Parameters) SetSafePrimeGenTimeout(timeout time.Duration) {
	params.safePrimeGenTimeout = timeout
}

func (params *Parameters) NoProofMod() bool {
	return params.noProofMod
}

func (params *Parameters) NoProofFac() bool {
	return params.noProofFac
}

func (params *Parameters) PartialKeyRand() io.Reader {
	return params.partialKeyRand
}

func (params *Parameters) Rand() io.Reader {
	return params.rand
}

func (params *Parameters) SetPartialKeyRand(rand io.Reader) {
	params.partialKeyRand = rand
}

func (params *Parameters) SetRand(rand io.Reader) {
	params.rand = rand
}

// SessionNonce returns the per-session nonce for SSID uniqueness.
// Returns nil if not set.
func (params *Parameters) SessionNonce() *big.Int {
	return params.sessionNonce
}

// SetSessionNonce sets a per-session nonce that all parties must agree on.
// This value is mixed into the SSID to provide GG20 session binding, preventing
// cross-session proof replay attacks. All parties in the same session MUST use
// the same nonce value. The caller is responsible for coordinating this.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	params.sessionNonce = nonce
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) (*ReSharingParameters, error) {
	params, err := NewParameters(ec, ctx, partyID, partyCount, threshold)
	if err != nil {
		return nil, err
	}
	if newCtx == nil {
		return nil, fmt.Errorf("NewReSharingParameters: new peer context must not be nil")
	}
	if newPartyCount < 1 {
		return nil, fmt.Errorf("NewReSharingParameters: newPartyCount must be >= 1, got %d", newPartyCount)
	}
	if newThreshold < 1 {
		return nil, fmt.Errorf("NewReSharingParameters: newThreshold must be >= 1, got %d", newThreshold)
	}
	if newThreshold >= newPartyCount {
		return nil, fmt.Errorf("NewReSharingParameters: newThreshold must be < newPartyCount, got newThreshold=%d newPartyCount=%d", newThreshold, newPartyCount)
	}
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}, nil
}

func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	return rgParams.partyCount
}

func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}
