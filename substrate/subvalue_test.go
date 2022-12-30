

package substrate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Node_StorageValueEqual(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		node     Node
		subValue []byte
		equal    bool
	}{
		"nil node subvalue and nil subvalue": {
			equal: true,
		},
		"empty node subvalue and empty subvalue": {
			node:     Node{StorageValue: []byte{}},
			subValue: []byte{},
			equal:    true,
		},
		"nil node subvalue and empty subvalue": {
			subValue: []byte{},
		},
		"empty node subvalue and nil subvalue": {
			node: Node{StorageValue: []byte{}},
		},
		"equal non empty values": {
			node:     Node{StorageValue: []byte{1, 2}},
			subValue: []byte{1, 2},
			equal:    true,
		},
		"not equal non empty values": {
			node:     Node{StorageValue: []byte{1, 2}},
			subValue: []byte{1, 3},
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			node := testCase.node

			equal := node.StorageValueEqual(testCase.subValue)

			assert.Equal(t, testCase.equal, equal)
		})
	}
}
