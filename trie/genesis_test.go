package trie

import (
	"testing"

	// "github.com/ChainSafe/gossamer/dot/types"
	sub "github.com/octopus-network/trie-go/substrate"
	"github.com/octopus-network/trie-go/util"
	"github.com/stretchr/testify/assert"
)

func Test_Trie_GenesisBlock(t *testing.T) {
	t.Parallel()

	withHash := func(header sub.Header) sub.Header {
		header.Hash()
		return header
	}

	testCases := map[string]struct {
		trie          Trie
		genesisHeader sub.Header
		errSentinel   error
		errMessage    string
	}{
		"empty trie": {
			genesisHeader: withHash(sub.Header{
				ParentHash:     util.Hash{0},
				StateRoot:      EmptyHash,
				ExtrinsicsRoot: EmptyHash,
				Digest:         sub.NewDigest(),
			}),
		},
		"non empty trie": {
			trie: Trie{
				root: &sub.Node{
					PartialKey:   []byte{1, 2, 3},
					StorageValue: []byte{4, 5, 6},
				},
			},
			genesisHeader: withHash(sub.Header{
				ParentHash: util.Hash{0},
				StateRoot: util.Hash{
					0x25, 0xc1, 0x86, 0xd4, 0x5b, 0xc9, 0x1d, 0x9f,
					0xf5, 0xfd, 0x29, 0xd3, 0x29, 0x8a, 0xa3, 0x63,
					0x83, 0xf3, 0x2d, 0x14, 0xa8, 0xbd, 0xde, 0xc9,
					0x7b, 0x57, 0x92, 0x78, 0x67, 0xfc, 0x8a, 0xfa},
				ExtrinsicsRoot: EmptyHash,
				Digest:         sub.NewDigest(),
			}),
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			trie := testCase.trie

			genesisHeader, err := trie.GenesisBlock()

			assert.ErrorIs(t, err, testCase.errSentinel)
			if testCase.errSentinel != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
			assert.Equal(t, testCase.genesisHeader, genesisHeader)
		})
	}
}
