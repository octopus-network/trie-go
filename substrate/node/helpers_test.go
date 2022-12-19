
package node

func padRightChildren(slice []*Node) (paddedSlice []*Node) {
	paddedSlice = make([]*Node, ChildrenCapacity)
	copy(paddedSlice, slice)
	return paddedSlice
}
