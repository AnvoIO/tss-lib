// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/AnvoIO/tss-lib/v4/common"
)

type (
	// PartyID represents a participant in the TSS protocol rounds.
	// Note: The `id` and `moniker` are provided for convenience to allow you to track participants easier.
	// The `id` is intended to be a unique string representation of `key` and `moniker` can be anything (even left blank).
	PartyID struct {
		*MessageWrapper_PartyID
		Index int `json:"index"`
	}

	UnSortedPartyIDs []*PartyID
	SortedPartyIDs   []*PartyID
)

func (pid *PartyID) ValidateBasic() bool {
	return pid != nil &&
		pid.MessageWrapper_PartyID != nil &&
		len(pid.Key) > 0 &&
		0 <= pid.Index
}

// --- ProtoBuf Extensions

func (mpid *MessageWrapper_PartyID) KeyInt() *big.Int {
	return new(big.Int).SetBytes(mpid.Key)
}

// ----- //

// NewPartyID constructs a new PartyID
// Exported, used in `tss` client. `key` should remain consistent between runs for each party.
func NewPartyID(id, moniker string, key *big.Int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id:      id,
			Moniker: moniker,
			Key:     key.Bytes(),
		},
		Index: -1, // not known until sorted
	}
}

// String must never fault: pid.Moniker is a PROMOTED field, so reading it
// dereferences the embedded *MessageWrapper_PartyID, which encoding/json and a
// shallow copy leave nil. A diagnostic that panics while something is being
// diagnosed removes the diagnosis (a direct call faults, since fmt recovers a
// panicking String). Answer with a marker instead — there is no return channel
// here and nothing downstream branches on the text.
func (pid PartyID) String() string {
	if pid.MessageWrapper_PartyID == nil {
		return fmt.Sprintf("{%d,<no PartyID content>}", pid.Index)
	}
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

func clonePartyID(pid *PartyID) *PartyID {
	if pid == nil {
		return nil
	}
	cloned := &PartyID{Index: pid.Index}
	if pid.MessageWrapper_PartyID != nil {
		cloned.MessageWrapper_PartyID = &MessageWrapper_PartyID{
			Id:      pid.Id,
			Moniker: pid.Moniker,
			Key:     append([]byte(nil), pid.Key...),
		}
	}
	return cloned
}

func clonePartyIDs(ids SortedPartyIDs) SortedPartyIDs {
	cloned := make(SortedPartyIDs, len(ids))
	for i, id := range ids {
		cloned[i] = clonePartyID(id)
	}
	return cloned
}

// ----- //

// SortPartyIDs sorts a list of []*PartyID by their keys in ascending order
// Exported, used in `tss` client
func SortPartyIDs(ids UnSortedPartyIDs, startAt ...int) SortedPartyIDs {
	sorted := make(SortedPartyIDs, 0, len(ids))
	for _, id := range ids {
		sorted = append(sorted, id)
	}
	sort.Sort(sorted)
	// assign party indexes
	for i, id := range sorted {
		frm := 0
		if len(startAt) > 0 {
			frm = startAt[0]
		}
		id.Index = i + frm
	}
	return sorted
}

// GenerateTestPartyIDs generates a list of mock PartyIDs for tests
func GenerateTestPartyIDs(count int, startAt ...int) SortedPartyIDs {
	ids := make(UnSortedPartyIDs, 0, count)
	key := common.MustGetRandomInt(rand.Reader, 256)
	frm := 0
	i := 0 // default `i`
	if len(startAt) > 0 {
		frm = startAt[0]
		i = startAt[0]
	}
	for ; i < count+frm; i++ {
		ids = append(ids, &PartyID{
			MessageWrapper_PartyID: &MessageWrapper_PartyID{
				Id:      fmt.Sprintf("%d", i+1),
				Moniker: fmt.Sprintf("P[%d]", i+1),
				Key:     new(big.Int).Sub(key, big.NewInt(int64(count)-int64(i))).Bytes(),
			},
			Index: i,
			// this key makes tests more deterministic
		})
	}
	return SortPartyIDs(ids, startAt...)
}

func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
		// KeyInt is promoted through the embedded *MessageWrapper_PartyID, so it
		// is that pointer the read dereferences. There is no safe substitute for
		// a missing key: the slice is positional and 0 is the one value that must
		// never appear (a party keyed 0 mod q would be dealt the Shamir secret
		// itself), so an attributable panic is the only honest outcome.
		if pid == nil || pid.MessageWrapper_PartyID == nil {
			panic(fmt.Errorf("SortedPartyIDs.Keys: entry %d is a nil PartyID or has a nil embedded PartyID", i))
		}
		ids[i] = pid.KeyInt()
	}
	return ids
}

func (spids SortedPartyIDs) ToUnSorted() UnSortedPartyIDs {
	return UnSortedPartyIDs(spids)
}

func (spids SortedPartyIDs) FindByKey(key *big.Int) *PartyID {
	for _, pid := range spids {
		if pid.KeyInt().Cmp(key) == 0 {
			return pid
		}
	}
	return nil
}

// IndexOf returns the committee-local position for a party key. Protocol code
// must use this value instead of trusting PartyID.Index received from a peer.
func (spids SortedPartyIDs) IndexOf(party *PartyID) (int, bool) {
	if party == nil || party.MessageWrapper_PartyID == nil || len(party.Key) == 0 {
		return -1, false
	}
	for i, candidate := range spids {
		if candidate != nil && candidate.MessageWrapper_PartyID != nil && candidate.KeyInt().Cmp(party.KeyInt()) == 0 {
			return i, true
		}
	}
	return -1, false
}

func (spids SortedPartyIDs) Exclude(exclude *PartyID) SortedPartyIDs {
	newSpIDs := make(SortedPartyIDs, 0, len(spids))
	for _, pid := range spids {
		if pid.KeyInt().Cmp(exclude.KeyInt()) == 0 {
			continue // exclude
		}
		newSpIDs = append(newSpIDs, pid)
	}
	return newSpIDs
}

// Sortable

func (spids SortedPartyIDs) Len() int {
	return len(spids)
}

func (spids SortedPartyIDs) Less(a, b int) bool {
	return spids[a].KeyInt().Cmp(spids[b].KeyInt()) < 0
}

func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
