// MIT License
//
// Copyright (c) 2022 Suhas Aggarwal
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package merkletree

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"math"
	"runtime"
	"sync"

	fastsha256 "github.com/minio/sha256-simd"
	zeeboBLAKE3 "github.com/zeebo/blake3"
	"golang.org/x/sync/errgroup"
)

const (

	// ModeTreeBuild is the tree building configuration mode.
	ModeTreeBuildCalculateRootHash = iota

	// ModeRootHash Divide and Conquer - root hash calculation mode - divide and conquer
	ModeRootHashCalculateDivideandConquer

	// Generate Proof - Merkle treego get
	GenerateLeafIndexProof

	// Default hash result length using SHA256.
	defaultHashLen = 32
)

// ModeType is the type in the Merkle Tree configuration indicating what operations are performed.
type ModeType int

// LeafIndex is the interface of input data blocks to generate the Merkle Tree.
type LeafIndex interface {
	Serialize() ([]byte, error)
}

// HashFuncAlgorithm is the signature of the hash functions used for Merkle Tree generation.
// Supported -
// SHA 256
// SHA 256 AVX 512
// BLAKE 3
type HashFuncAlgorithm func([]byte) ([]byte, error)

// Config is the configuration of Merkle Tree.
type Config struct {
	// Customizable hash function used for tree generation.
	HashFunc HashFuncAlgorithm
	// If true, the root hash calculatior runs in parallel, otherwise runs without parallelization.
	// This increase the performance for the calculation of large number of leaves, e.g. over 10,000 blocks. (Common validator bootstrap parameter)
	RunInParallel bool
	// Number of goroutines run in parallel.
	// If RunInParallel is true and NumRoutine is set to 0, use number of CPU as the number of goroutines.
	NumRoutines int
	// If true, generate a dummy node with random hash value.
	// Otherwise, then the odd node situation is handled by duplicating the previous node.
	NoDuplicates bool
	// Mode of the Merkle Tree generation.
	Mode ModeType

	leafIndex LeafIndex
}

// MerkleTree implements the Merkle Tree structure
type MerkleTree struct {
	// Config is the Merkle Tree configuration
	*Config
	// Root is the Merkle root hash
	Root []byte
	// Leaves are Merkle Tree leaves, i.e. the hashes of the data blocks for tree generation
	Leaves [][]byte
	// Proofs are proofs to the leaf index generated during the tree building process (contains siblings needed for proof i.e generate root hash)
	Proofs *Proof
	// Depth is the Merkle Tree depth
	Depth uint32
	// tree is the Merkle Tree structure, only available when config mode is ModeTreeBuild or ModeProofGenAndTreeBuild
	tree [][][]byte
	// leafMap is the map of the leaf hash to the index in the Tree slice,
	// only available when config mode is ModeTreeBuild or ModeProofGenAndTreeBuild
	leafMap sync.Map
}

// Proof implements the Merkle Tree proof.
type Proof struct {
	Path     uint32   // path variable indicating whether the neighbor is on the left or right
	Siblings [][]byte // sibling nodes to the Merkle Tree path of the data block
}

// New generates a new Merkle Tree with specified configuration.
func New(config *Config, blocks [][]byte) (m *MerkleTree, err error) {
	//if len(blocks) <= 1 {
	//	return nil, errors.New("the number of data blocks must be greater than 1")
	//}
	if config == nil {
		config = new(Config)
	}
	if config.HashFunc == nil {
		config.HashFunc = defaultHashFunc
	}
	// if the configuration mode is not set, then set it to ModeProofGen by default
	if config.Mode == 0 {
		config.Mode = ModeTreeBuildCalculateRootHash
	}
	if config.RunInParallel && config.NumRoutines == 0 {
		config.NumRoutines = runtime.NumCPU()
	}
	m = &MerkleTree{
		Config: config,
	}

	m.Leaves = blocks

	if m.Mode == ModeTreeBuildCalculateRootHash {
		if m.RunInParallel {
			err = m.RootHashCalculatorProcessDepthConcurrently(config.NumRoutines)
			//m.Leaves, err = leafGenParal(blocks, m.HashFunc, m.NumRoutines)
			if err != nil {
				return

			}

		} else {
			err = m.RootHashCalculatorNonConcurrent()
			if err != nil {
				return

			}
		}
	}

	if m.Mode == ModeRootHashCalculateDivideandConquer {
		RootCalculatorDivideandConquer(m.Leaves)

	}

	if m.Mode == GenerateLeafIndexProof {
		_, err = m.GenerateLeafIndexProof(config.leafIndex)
		if err != nil {
			return

		}

	}

	return
}

// calTreeDepth calculates the tree depth,
// the tree depth is then used to declare the capacity of the proof slices.
func calTreeDepth(blockLen int) uint32 {
	log2BlockLen := math.Log2(float64(blockLen))
	// check if log2BlockLen is an integer
	if log2BlockLen != math.Trunc(log2BlockLen) {
		return uint32(log2BlockLen) + 1
	}
	return uint32(log2BlockLen)
}

// if the length of the buffer calculating the Merkle Tree is odd, then append a node to the buffer
// if AllowDuplicates is true, append a node by duplicating the previous node
// otherwise, append a node by random
func (m *MerkleTree) fixOdd(buf [][]byte, prevLen int) ([][]byte, int, error) {
	if prevLen&1 == 1 {
		var appendNode []byte
		if m.NoDuplicates {
			var err error
			appendNode, err = getDummyHash()
			if err != nil {
				return nil, 0, err
			}
		} else {
			appendNode = buf[prevLen-1]
		}
		if len(buf) <= prevLen+1 {
			buf = append(buf, appendNode)
		} else {
			buf[prevLen] = appendNode
		}
		prevLen++
	}
	return buf, prevLen, nil
}

// generate a dummy hash to make odd-length buffer even
func getDummyHash() ([]byte, error) {
	dummyBytes := make([]byte, defaultHashLen)
	_, err := rand.Read(dummyBytes)
	if err != nil {
		return nil, err
	}
	return dummyBytes, nil
}

// defaultHashFunc is used when no user hash function is specified.
// It implements SHA256 hash function.
func defaultHashFunc(data []byte) ([]byte, error) {
	sha256Func := sha256.New()
	sha256Func.Write(data)
	return sha256Func.Sum(nil), nil
}

func defaultHashFuncBlake3(data []byte) ([]byte, error) {
	hasher := zeeboBLAKE3.New()
	hasher.Write([]byte(data))
	return hasher.Sum(nil), nil

}

// defaultHashFunc is used when no user hash function is specified.
// It implements SHA256 hash function.
// Accelerate SHA256 computations in pure Go using AVX512, SHA Extensions for x86 and ARM64 for ARM. On AVX512 it provides an up to 8x improvement (over 3 GB/s per core). SHA Extensions give a performance boost of close to 4x over native.
func defaultHashFuncSHA256AVX512(data []byte) ([]byte, error) {
	server := fastsha256.NewAvx512Server()
	shaWriter := fastsha256.NewAvx512(server)
	shaWriter.Write(data)
	return shaWriter.Sum(nil), nil
}

func (m *MerkleTree) RootHashCalculatorNonConcurrent() (err error) {
	numLeaves := len(m.Leaves)
	m.tree = make([][][]byte, calTreeDepth(numLeaves))
	m.tree[0] = make([][]byte, numLeaves)
	copy(m.tree[0], m.Leaves)
	m.Depth = calTreeDepth(numLeaves)
	m.tree = make([][][]byte, m.Depth)
	m.tree[0] = make([][]byte, numLeaves)
	copy(m.tree[0], m.Leaves)
	var prevLen int
	m.tree[0], prevLen, err = m.fixOdd(m.tree[0], numLeaves)
	if err != nil {
		return
	}
	for i := uint32(0); i < m.Depth-1; i++ {
		m.tree[i+1] = make([][]byte, prevLen>>1)
		for j := 0; j < prevLen; j += 2 {
			m.tree[i+1][j>>1], err = m.HashFunc(append(m.tree[i][j], m.tree[i][j+1]...))
			if err != nil {
				return
			}
		}
		m.tree[i+1], prevLen, err = m.fixOdd(m.tree[i+1], len(m.tree[i+1]))
		if err != nil {
			return err
		}
	}
	m.Root, err = m.HashFunc(append(m.tree[m.Depth-1][0], m.tree[m.Depth-1][1]...))
	if err != nil {
		return err
	}
	return
}

// Merkle Root hash calculator - Algorithm 1
func (m *MerkleTree) RootHashCalculatorProcessDepthConcurrently(goroutines int) (err error) {
	numRoutines := goroutines
	numLeaves := len(m.Leaves)
	m.Depth = calTreeDepth(numLeaves)
	m.tree = make([][][]byte, m.Depth)
	m.tree[0] = make([][]byte, numLeaves)
	copy(m.tree[0], m.Leaves)
	var prevLen int
	m.tree[0], prevLen, err = m.fixOdd(m.tree[0], numLeaves)
	if err != nil {
		return
	}
	for i := uint32(0); i < m.Depth-1; i++ {
		m.tree[i+1] = make([][]byte, prevLen>>1)
		g := new(errgroup.Group)
		for j := 0; j < numRoutines && j < prevLen; j++ {
			idx := j << 1
			g.Go(func() error {
				for k := idx; k < prevLen; k += numRoutines << 1 {
					newHash, err := m.HashFunc(append(m.tree[i][k], m.tree[i][k+1]...))
					if err != nil {
						return err
					}
					m.tree[i+1][k>>1] = newHash
				}
				return nil
			})
		}
		if err = g.Wait(); err != nil {
			return
		}
		m.tree[i+1], prevLen, err = m.fixOdd(m.tree[i+1], len(m.tree[i+1]))
		if err != nil {
			return
		}
	}
	m.Root, err = m.HashFunc(append(m.tree[m.Depth-1][0], m.tree[m.Depth-1][1]...))
	if err != nil {
		return err
	}
	return nil
}

func ConcatHash(left, right []byte) []byte {
	merged := make([]byte, 0, len(left)+len(right))
	var err error
	merged, err = defaultHashFunc(append(left, right...))
	if err != nil {
		log.Print(err)
	}

	return merged
}

// Merkle Root hash calculator Divide and Conquer - Algorithm 2
func RootCalculatorDivideandConquer(data [][]byte) []byte {

	if len(data) <= 1 {
		return data[0]
	}
	done := make(chan bool)
	mid := len(data) / 2
	var left []byte
	go func() {
		left = RootCalculatorDivideandConquer(data[:mid])
		done <- true
	}()
	right := RootCalculatorDivideandConquer(data[mid:])
	<-done
	return ConcatHash(left, right)

}

// VerifyLeafIndex verifies the data block with the Merkle Tree proof
func (m *MerkleTree) Verify(dataBlock LeafIndex, proof *Proof) (bool, error) {
	return VerifyLeafIndex(dataBlock, proof, m.Root, m.HashFunc)
}

// VerifyLeafIndex verifies the leaf index with the Merkle Tree proof and Merkle root hash
func VerifyLeafIndex(dataBlock LeafIndex, proof *Proof, root []byte, hashFunc HashFuncAlgorithm) (bool, error) {
	if proof == nil {
		return false, errors.New("proof is nil")
	}
	if hashFunc == nil {
		hashFunc = defaultHashFunc
	}
	var (
		data, err = dataBlock.Serialize()
		hash      []byte
	)
	if err != nil {
		return false, err
	}
	hash, err = hashFunc(data)
	if err != nil {
		return false, err
	}
	path := proof.Path
	for _, n := range proof.Siblings {
		if path&1 == 1 {
			hash, err = hashFunc(append(hash, n...))
		} else {
			hash, err = hashFunc(append(n, hash...))
		}
		if err != nil {
			return false, err
		}
		path >>= 1
	}
	return bytes.Equal(hash, root), nil
}

// GenerateLeafIndexProof generates the Merkle proof for a Leaf Index with the Merkle Tree structure generated earlier
// In ModeProofGen, proofs for all the leaf index are already generated, so that leaf index can be verified for tamper
func (m *MerkleTree) GenerateLeafIndexProof(dataBlock LeafIndex) (*Proof, error) {
	blockByte, err := dataBlock.Serialize()
	if err != nil {
		return nil, err
	}
	blockHash, err := m.HashFunc(blockByte)
	if err != nil {
		return nil, err
	}
	val, ok := m.leafMap.Load(string(blockHash))
	if !ok {
		return nil, errors.New("data block is not a member of the Merkle Tree")
	}
	var (
		idx      = val.(int)
		path     uint32
		siblings = make([][]byte, m.Depth)
	)
	for i := uint32(0); i < m.Depth; i++ {
		if idx&1 == 1 {
			siblings[i] = m.tree[i][idx-1]
		} else {
			path += 1 << i
			siblings[i] = m.tree[i][idx+1]
		}
		idx >>= 1
	}
	return &Proof{
		Path:     path,
		Siblings: siblings,
	}, nil
}
