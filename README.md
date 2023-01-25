# Go Merkle Tree

![MerkleTree-min](https://user-images.githubusercontent.com/3880512/187171515-36ae370c-c30c-4231-858d-dc71b275ce6a.png)


Parallel construction of a Merkle tree in Go (Golang) can be achieved by using goroutines and channels. A goroutine is a lightweight thread of execution, and channels are used for communication between goroutines.

One approach to building a parallel Merkle tree in Go would be to use goroutines to compute the hashes for each leaf node of the tree in parallel. The leaf nodes can be passed to the goroutines through channels, and the resulting hashes can be collected in another channel. Once all of the leaf hashes have been computed, the goroutines can be used to compute the hashes for the next level of the tree in the same manner.

Another approach could be to have one goroutine per leaf node, where each goroutine computes the hashes for its corresponding leaf node and then sends it to the channel.

Another approach is to have a pool of goroutines, where the main goroutine assigns a leaf node to a goroutine from the pool and waits for the goroutine to compute the hash and return it.


Feature set 

1)Merkle Tree build - Normal / Concurrent Mode

2)Fastest Merkle Tree Root Hash Calculator - Two concurrency based Algorithms

3)Experiment with Fast Hashing Algorithms - sha256 vs blake3 benchmark

4)Experiment with number of go routines and benchmark reports

5)Merkle leaf index  tree proof generation Algorithm  / Sibling storage to generate root hash 

6)Merkle tree proof verification Algorithm


# Configuration

```
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
```

To define a new Hash function:

```go
func NewHashFunc(data []byte) ([]byte, error) {
    sha256Func := sha256.New()
    sha256Func.Write(data)
    return sha256Func.Sum(nil), nil
}
```

*Important Notice*: please make sure the hash function used by paralleled algorithms is concurrent-safe.



### Build tree and calculate root hash

```
 
Modes - 

// ModeTreeBuild is the tree building configuration mode.
ModeTreeBuildCalculateRootHash = iota

// ModeRootHash Divide and Conquer - root hash calculation mode - divide and conquer
ModeRootHashCalculateDivideandConquer
```


### Generate data blocks using input transaction file 

```go
//Specify n - for number of transactions

func genTestDataBlocks(num int) [][]byte {
	i := 0
	filePath := "/home/swordfish/Downloads/input.txt"
	readFile, err := os.Open(filePath)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileLines [][]byte

	for fileScanner.Scan() {
		i++
		fileLines = append(fileLines, []byte(fileScanner.Text()))
		if i == num {
			break
		}
	}

	return fileLines
}

```

### Build tree - Calculate Root Hash

```go
func main() {
    blocks := genTestDataBlocks(1024)
    // the first argument is config, if it is nil, then default config is adopted
    tree, err := mt.New(nil, blocks)
    rootHash := tree.Root  
}
```

### Build tree - Non Concurrent

```go
blocks := genTestDataBlocks(1024)


// create a Merkle Tree config and set mode to tree building
config := &mt.Config{
    Mode: ModeTreeBuildCalculateRootHash,
}
tree, err := mt.New(config, blocks)
```

### Parallel run

```go
blocks := genTestDataBlocks(1024))

// create a Merkle Tree config and set parallel run parameters
config := &mt.Config{
    RunInParallel: true,
    NumRoutines: 4,
    Mode: ModeTreeBuildCalculateRootHash,
}
tree, err := mt.New(config, blocks)
```

### Parallel run - Divide and Conquer 

```go
blocks := genTestDataBlocks(1024))

// create a Merkle Tree config and set parallel run parameters
config := &mt.Config{
    RunInParallel: true,
    NumRoutines: 4,
    Mode: ModeRootHashCalculateDivideandConquer,
}
tree, err := mt.New(config, blocks)
```

### Choose Alternate hashing algorithm - BLAKE3 

```go
config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   16,
		HashFunc:      defaultHashFuncBlake3,
	}
```



Benchmark Report 
```
goos: linux
goarch: amd64
pkg: github.com/suhasagg/fastestmerkletreeroothashcalculator
cpu: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
BenchmarkMerkleTreeNew                                                85          13225754 ns/op
BenchmarkMerkleTreeBuild                                              87          12964021 ns/op
BenchmarkMerkleTreeBuildParallel                                      86          13066228 ns/op
BenchmarkMerkleTreeBuildParalle8                                      87          13166350 ns/op
BenchmarkMerkleTreeBuildParalle16                                     85          13395900 ns/op
BenchmarkMerkleTreeBuildParallel32                                    84          13652891 ns/op
BenchmarkMerkleTreeRootHashDivideAndConquer                           24          48058342 ns/op
BenchmarkMerkleTreeRootHashDivideAndConquer8                          24          47822800 ns/op
BenchmarkMerkleTreeRootHashDivideAndConquer16                         24          47753576 ns/op
BenchmarkMerkleTreeRootHashDivideAndConquer32                         24          47775141 ns/op
BenchmarkMerkleTreeHashFuncBlake3PNew                                118           9728318 ns/op
BenchmarkMerkleTreeHashFuncBlake3PBuild                              117           9744272 ns/op
BenchmarkMerkleTreeBuildHashFuncBlake3Parallel                       116           9941032 ns/op
BenchmarkMerkleTreeBuildHashFuncBlake3Parallel8                      115          10046266 ns/op
BenchmarkMerkleTreeBuildHashFuncBlake3Parallel16                     114          10102191 ns/op
BenchmarkMerkleTreeBuildHashFuncBlake3Parallel32                     111          10278611 ns/op
BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer             24          47866590 ns/op
BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer8            24          47804965 ns/op
BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer16           24          47684666 ns/op
BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer32           24          47866174 ns/op


(```100 ns/op``` means each function execution takes 100 nanoseconds (10^9 ns = 1s))
```


