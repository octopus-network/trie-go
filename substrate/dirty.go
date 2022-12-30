package substrate

// SetDirty sets the dirty status to true for the node.
func (n *Node) SetDirty() {
	n.Dirty = true
	// A node is marked dirty if its partial key or storage value is modified.
	// This means its Merkle value field is no longer valid.
	n.NodeValue = nil
}

// SetClean sets the dirty status to false for the node.
func (n *Node) SetClean() {
	n.Dirty = false
}
