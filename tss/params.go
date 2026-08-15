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
		// sessionNonce provides per-session SSID uniqueness and must be a fresh
		// positive value agreed by all parties before Start.
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
	return newParameters(ec, ctx, partyID, partyCount, threshold, true)
}

func newParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int, requirePartyMembership bool) (*Parameters, error) {
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
	contextCount := partyCount
	if !requirePartyMembership {
		contextCount = len(ctx.IDs())
	}
	if err := validatePeerContext(ctx, contextCount); err != nil {
		return nil, err
	}
	if err := validatePartyKeysForCurve(ec, ctx); err != nil {
		return nil, err
	}
	if requirePartyMembership {
		partyIndex, ok := ctx.IDs().IndexOf(partyID)
		if !ok {
			return nil, fmt.Errorf("NewParameters: partyID is not a member of the peer context")
		}
		if partyID.Index != partyIndex {
			return nil, fmt.Errorf("NewParameters: partyID index %d does not match committee position %d", partyID.Index, partyIndex)
		}
	}
	return &Parameters{
		ec:                  ec,
		parties:             NewPeerContext(ctx.IDs()),
		partyID:             clonePartyID(partyID),
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
		partialKeyRand:      rand.Reader,
		rand:                rand.Reader,
	}, nil
}

func validatePeerContext(ctx *PeerContext, partyCount int) error {
	ids := ctx.IDs()
	if len(ids) != partyCount {
		return fmt.Errorf("NewParameters: peer context has %d parties, expected %d", len(ids), partyCount)
	}
	for i, party := range ids {
		if party == nil || !party.ValidateBasic() {
			return fmt.Errorf("NewParameters: peer context contains an invalid party at position %d", i)
		}
		if i == 0 {
			continue
		}
		cmp := ids[i-1].KeyInt().Cmp(party.KeyInt())
		if cmp == 0 {
			return fmt.Errorf("NewParameters: peer context contains duplicate party keys at positions %d and %d", i-1, i)
		}
		if cmp > 0 {
			return fmt.Errorf("NewParameters: peer context is not sorted by party key")
		}
	}
	return nil
}

func validatePartyKeysForCurve(ec elliptic.Curve, ctx *PeerContext) error {
	q := ec.Params().N
	seen := make(map[string]int, len(ctx.IDs()))
	for i, party := range ctx.IDs() {
		reduced := new(big.Int).Mod(party.KeyInt(), q)
		if reduced.Sign() == 0 {
			return fmt.Errorf("NewParameters: party key at position %d is zero modulo the curve order", i)
		}
		encoded := string(reduced.Bytes())
		if previous, ok := seen[encoded]; ok {
			return fmt.Errorf("NewParameters: party keys at positions %d and %d collide modulo the curve order", previous, i)
		}
		seen[encoded] = i
	}
	return nil
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

// PartyID returns a deep copy of the local identity.
func (params *Parameters) PartyID() *PartyID {
	return clonePartyID(params.partyID)
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

// SessionNonce returns a copy of the required per-session nonce used for SSID
// uniqueness. Party.Start rejects nil, zero, and negative nonces.
func (params *Parameters) SessionNonce() *big.Int {
	if params.sessionNonce == nil {
		return nil
	}
	return new(big.Int).Set(params.sessionNonce)
}

// SetSessionNonce sets a required per-session nonce that all parties must agree on.
// This value is mixed into the SSID to provide GG20 session binding, preventing
// cross-session proof replay attacks. All parties in the same session MUST use
// the same fresh positive nonce value. The caller is responsible for coordinating
// it and MUST NOT reuse it across protocol runs.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	if nonce == nil {
		params.sessionNonce = nil
		return
	}
	params.sessionNonce = new(big.Int).Set(nonce)
}

func (params *Parameters) ValidateSessionNonce() error {
	if params == nil || params.sessionNonce == nil || params.sessionNonce.Sign() <= 0 {
		return fmt.Errorf("a positive session nonce agreed by all parties is required")
	}
	return nil
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) (*ReSharingParameters, error) {
	params, err := newParameters(ec, ctx, partyID, partyCount, threshold, false)
	if err != nil {
		return nil, err
	}
	if len(ctx.IDs()) < threshold+1 {
		return nil, fmt.Errorf("NewReSharingParameters: old peer context has %d active parties, need at least %d", len(ctx.IDs()), threshold+1)
	}
	if newCtx == nil {
		return nil, fmt.Errorf("NewReSharingParameters: new peer context must not be nil")
	}
	frozenNewCtx := NewPeerContext(newCtx.IDs())
	if newPartyCount < 1 {
		return nil, fmt.Errorf("NewReSharingParameters: newPartyCount must be >= 1, got %d", newPartyCount)
	}
	if newThreshold < 1 {
		return nil, fmt.Errorf("NewReSharingParameters: newThreshold must be >= 1, got %d", newThreshold)
	}
	if newThreshold >= newPartyCount {
		return nil, fmt.Errorf("NewReSharingParameters: newThreshold must be < newPartyCount, got newThreshold=%d newPartyCount=%d", newThreshold, newPartyCount)
	}
	if err := validatePeerContext(frozenNewCtx, newPartyCount); err != nil {
		return nil, fmt.Errorf("NewReSharingParameters: invalid new peer context: %w", err)
	}
	if err := validatePartyKeysForCurve(ec, frozenNewCtx); err != nil {
		return nil, fmt.Errorf("NewReSharingParameters: invalid new peer context: %w", err)
	}
	_, isOld := params.Parties().IDs().IndexOf(params.PartyID())
	_, isNew := frozenNewCtx.IDs().IndexOf(params.PartyID())
	if !isOld && !isNew {
		return nil, fmt.Errorf("NewReSharingParameters: partyID is not a member of either committee")
	}
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    frozenNewCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}, nil
}

// OldParties and OldPartyCount read through the EMBEDDED *Parameters (Parties()
// and the promoted partyCount), which is nil for a ReSharingParameters the
// caller did not build with NewReSharingParameters — ReSharingParameters{} and
// json.Unmarshal("{}") both leave it nil. An absent *Parameters describes no old
// committee, so each answers as the package already does for an undescribed one:
// no roster, and a count of zero. (The New readers need no such guard — their
// backing fields are ReSharingParameters' own.)
func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	if rgParams.Parameters == nil {
		return nil
	}
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	if rgParams.Parameters == nil {
		return 0
	}
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

func (rgParams *ReSharingParameters) OldPartyIndex() (int, bool) {
	return rgParams.OldParties().IDs().IndexOf(rgParams.PartyID())
}

func (rgParams *ReSharingParameters) NewPartyIndex() (int, bool) {
	return rgParams.NewParties().IDs().IndexOf(rgParams.PartyID())
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	_, ok := rgParams.OldPartyIndex()
	return ok
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	_, ok := rgParams.NewPartyIndex()
	return ok
}
