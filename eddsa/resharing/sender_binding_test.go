package resharing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/AnvoIO/tss-lib/v3/eddsa/keygen"
	"github.com/AnvoIO/tss-lib/v3/tss"
)

func TestStoreMessageBindsNewCommitteeSenderByKey(t *testing.T) {
	oldIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		tss.NewPartyID("old-1", "old-1", big.NewInt(1)),
		tss.NewPartyID("old-2", "old-2", big.NewInt(2)),
		tss.NewPartyID("old-3", "old-3", big.NewInt(3)),
	})
	newIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		tss.NewPartyID("new-4", "new-4", big.NewInt(4)),
		tss.NewPartyID("new-5", "new-5", big.NewInt(5)),
		tss.NewPartyID("new-6", "new-6", big.NewInt(6)),
	})
	params, err := tss.NewReSharingParameters(
		tss.Edwards(), tss.NewPeerContext(oldIDs), tss.NewPeerContext(newIDs),
		newIDs[0], len(oldIDs), 1, len(newIDs), 1,
	)
	require.NoError(t, err)
	party := NewLocalParty(
		params, keygen.NewLocalPartySaveData(len(newIDs)),
		make(chan tss.Message, 1), make(chan *keygen.LocalPartySaveData, 1),
	).(*LocalParty)

	claimedWrongIndex := &tss.PartyID{
		MessageWrapper_PartyID: newIDs[2].MessageWrapper_PartyID,
		Index:                  999,
	}
	msg := NewDGRound2Message(nil, claimedWrongIndex)
	ok, storeErr := party.StoreMessage(msg)
	require.True(t, ok)
	require.Nil(t, storeErr)
	require.Same(t, msg, party.temp.dgRound2Messages[2])

	outsider := tss.NewPartyID("outsider", "outsider", big.NewInt(99))
	outsider.Index = 0
	ok, validationErr := party.ValidateMessage(NewDGRound2Message(nil, outsider))
	require.False(t, ok)
	require.NotNil(t, validationErr)
}
