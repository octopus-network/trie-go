package substrate

import "fmt"

// Kind is the type of the node.
type Kind byte

const (
	// Leaf kind for leaf nodes.
	Leaf Kind = iota
	// Branch kind for branches (with or without value).
	Branch
)

func (k Kind) String() string {
	switch k {
	case Leaf:
		return "leaf"
	case Branch:
		return "branch"
	default:
		panic(fmt.Sprintf("invalid node type: %d", k))
	}
}
