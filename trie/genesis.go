package trie

import (
	"fmt"

	// "github.com/ChainSafe/gossamer/dot/types"
	sub "github.com/octopus-network/trie-go/substrate"
	"github.com/octopus-network/trie-go/util"
)

// GenesisBlock creates a genesis block from the trie.
func (t *Trie) GenesisBlock() (genesisHeader sub.Header, err error) {
	rootHash, err := t.Hash()
	if err != nil {
		return genesisHeader, fmt.Errorf("root hashing trie: %w", err)
	}

	parentHash := util.Hash{0}
	extrinsicRoot := EmptyHash
	const blockNumber = 0
	digest := sub.NewDigest()
	genesisHeader = *sub.NewHeader(parentHash, rootHash, extrinsicRoot, blockNumber, digest)
	return genesisHeader, nil
}
