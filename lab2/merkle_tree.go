package main

import (
	"crypto/sha256"
	"fmt"
)

// MerkleTree represent a Merkle tree
type MerkleTree struct {
	RootNode *MerkleNode
	Leaf     [][]byte
}

// MerkleNode represent a Merkle tree node
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleTree creates a new Merkle tree from a sequence of data
// implement
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return nil
	}
	mk_tree := MerkleTree{}
	mk_tree.Leaf = data
	//构建默克尔树叶节点
	leaf := mk_tree.buildMerkleTreeLeaf(data)
	//构建默克尔树中间节点
	root, _ := mk_tree.buildMerkleTreeNode(leaf)
	mk_tree.RootNode = root
	return &mk_tree
}

// NewMerkleNode creates a new Merkle tree node
// implement
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}
	if left == nil && right == nil {
		datahash := sha256.Sum256(data)
		node.Data = datahash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		datahash := sha256.Sum256(prevHashes)
		node.Data = datahash[:]
	}
	node.Left = left
	node.Right = right
	return &node

}

// 构建默克尔树叶节点
func (m *MerkleTree) buildMerkleTreeLeaf(date [][]byte) []*MerkleNode {
	var leaf []*MerkleNode
	for _, item := range date {
		node := NewMerkleNode(nil, nil, item)
		leaf = append(leaf, node)
	}
	return leaf
}

// 构建默克尔树中间节点
func (m *MerkleTree) buildMerkleTreeNode(nodes []*MerkleNode) (*MerkleNode, error) {
	length := len(nodes)
	if length == 0 {
		return nil, nil
	}
	if length == 1 {
		return nodes[0], nil
	}
	var nodeSlice []*MerkleNode
	for i := 0; i < (length+1)/2; i++ {
		leftNode := nodes[i*2]
		var rightNode = new(MerkleNode)
		if i*2+1 < len(nodes) {
			rightNode = nodes[i*2+1]
		} else {
			rightNode.Data = leftNode.Data
		}
		node := NewMerkleNode(leftNode, rightNode, nil)
		nodeSlice = append(nodeSlice, node)
	}
	//递归构建默克尔树
	if len(nodeSlice) > 1 {
		return m.buildMerkleTreeNode(nodeSlice)
	}
	return nodeSlice[0], nil
}

func (t *MerkleTree) SPVproof(index int) ([][]byte, error) {
	node := t.RootNode
	path := findPath(node, index)
	return path, nil
}
func findPath(root *MerkleNode, index int) [][]byte {
	if root.Left == nil && root.Right == nil {
		return nil
	}
	leftCount := countLeaves(root.Left)

	if index < leftCount {
		path := findPath(root.Left, index)
		return append([][]byte{root.Right.Data}, path...)
	} else {
		path := findPath(root.Right, index-leftCount)
		return append([][]byte{root.Left.Data}, path...)
	}

}
func countLeaves(node *MerkleNode) int {
	if node == nil {
		return 0
	}
	if node.Left == nil && node.Right == nil {
		return 1 // var path [][]byte
	}
	return countLeaves(node.Left) + countLeaves(node.Right)
}
func (t *MerkleTree) VerifyProof(index int, path [][]byte) (bool, error) {
	data := t.Leaf[index]
	var dataHash = sha256.Sum256(data)
	data = dataHash[:]
	for i := len(path) - 1; i >= 0; i-- {
		item := path[i]
		fmt.Println("item", item)
		if index%2 == 0 {
			data = append(data, item...)
		} else {
			data = append(item, data...)
		}
		var dataHash = sha256.Sum256(data)
		data = dataHash[:]
		index = index / 2
	}
	if string(data) != string(t.RootNode.Data) {
		return false, nil
	}

	return true, nil
}
