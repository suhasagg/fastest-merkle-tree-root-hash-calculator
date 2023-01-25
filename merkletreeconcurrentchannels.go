package main

import (
    "crypto/sha256"
    "fmt"
    "sync"
)

// LeafNode represents a leaf node in the Merkle tree
type LeafNode struct {
    Data  []byte
    Hash  []byte
    Level int
}

// Node represents a node in the Merkle tree
type Node struct {
    Left  *Node
    Right *Node
    Hash  []byte
    Level int
}

// NewLeafNode creates a new leaf node
func NewLeafNode(data []byte) *LeafNode {
    hash := sha256.Sum256(data)
    return &LeafNode{
        Data:  data,
        Hash:  hash[:],
        Level: 0,
    }
}

// NewNode creates a new node
func NewNode(left, right *Node) *Node {
    var data []byte
    if left != nil {
        data = append(data, left.Hash...)
    }
    if right != nil {
        data = append(data, right.Hash...)
    }
    hash := sha256.Sum256(data)
    return &Node{
        Left:  left,
        Right: right,
        Hash:  hash[:],
        Level: left.Level + 1,
    }
}

// BuildMerkleTree creates a Merkle tree from a list of leaf nodes
func BuildMerkleTree(leafNodes []*LeafNode) *Node {
    // Create a channel to receive leaf node hashes
    leafNodeHashes := make(chan *LeafNode)

    // Create a wait group to wait for all goroutines to finish
    var wg sync.WaitGroup

    // Start a goroutine for each leaf node
    for _, leafNode := range leafNodes {
        wg.Add(1)
        go func(leafNode *LeafNode) {
            defer wg.Done()
            leafNodeHashes <- leafNode
        }(leafNode)
    }

    // Create a channel to receive tree nodes
    nodes := make(chan *Node)

    // Start a goroutine to build the tree
    go func() {
        defer close(nodes)

        // Wait for all leaf node hashes to be received
        wg.Wait()
        close(leafNodeHashes)

        // Create a list of tree nodes
        var treeNodes []*Node
        for leafNode := range leafNodeHashes {
            treeNodes = append(treeNodes, &Node{
                Left:  nil,
                Right: nil,
                Hash:  leafNode.Hash,
                Level: leafNode.Level,
            })
        }

        // Build the tree
        for len(treeNodes) > 1 {
            var newTreeNodes []*Node
            for i := 0; i < len(treeNodes); i += 2 {
                var left, right *Node
                if i < len(treeNodes) {
                    left = treeNodes[i]
                }
                if i+1 < len(treeNodes) {
                    right = treeNodes[i+1]
                }
                newTree

}
