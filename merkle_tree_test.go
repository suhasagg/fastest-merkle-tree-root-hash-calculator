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
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

const benchSize = 16384

type mockLeafIndex struct {
	data []byte
}

func (t *mockLeafIndex) Serialize() ([]byte, error) {
	return t.data, nil
}

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

func TestMerkleTreeNew_buildTree(t *testing.T) {
	type args struct {
		blocks [][]byte
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_build_tree_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_128",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_512",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_1024",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_hash_func_error",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					HashFunc: func([]byte) ([]byte, error) {
						return nil, fmt.Errorf("hash func error")
					},
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.args.config, tt.args.blocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			m1, err := New(nil, tt.args.blocks)
			if err != nil {
				t.Errorf("test setup error %v", err)
				return
			}
			if !bytes.Equal(m.Root, m1.Root) && !tt.wantErr {
				fmt.Println("m", m.Root)
				fmt.Println("m1", m1.Root)
				t.Errorf("tree generated is wrong")
				return
			}
		})
	}
}

func TestMerkleTreeNew_treeBuildParallel(t *testing.T) {
	type args struct {
		blocks [][]byte
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_build_tree_parallel_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_8",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_8",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_8",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_8",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_16",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_16",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_16",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_32",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_32",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_32",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_32",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.args.config, tt.args.blocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			m1, err := New(nil, tt.args.blocks)
			if err != nil {
				t.Errorf("test setup error %v", err)
				return
			}
			if !bytes.Equal(m.Root, m1.Root) && !tt.wantErr {
				fmt.Println("m", m.Root)
				fmt.Println("m1", m1.Root)
				t.Errorf("tree generated is wrong")
				return
			}
		})
	}
}

func verifySetup(size int) (*MerkleTree, [][]byte, error) {
	blocks := genTestDataBlocks(size)
	m, err := New(nil, blocks)
	if err != nil {
		return nil, nil, err
	}
	return m, blocks, nil
}

func verifySetupParallel(size int) (*MerkleTree, [][]byte, error) {
	blocks := genTestDataBlocks(size)
	m, err := New(&Config{
		RunInParallel: true,
		NumRoutines:   4,
	}, blocks)
	if err != nil {
		return nil, nil, err
	}
	return m, blocks, nil
}

func testHashFunc(data []byte) ([]byte, error) {
	sha256Func := sha256.New()
	sha256Func.Write(data)
	return sha256Func.Sum(nil), nil
}

func BenchmarkMerkleTreeNew(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(nil, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuild(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode: ModeTreeBuildCalculateRootHash,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildParallel(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   4,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildParalle8(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   8,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildParalle16(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   16,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildParallel32(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   32,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashDivideAndConquer(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   8,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashDivideAndConquer8(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   8,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashDivideAndConquer16(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   16,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashDivideAndConquer32(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   32,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func TestMerkleTreeNew_buildHashFuncBlake3PTree(t *testing.T) {
	type args struct {
		blocks [][]byte
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_build_tree_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					Mode:     ModeTreeBuildCalculateRootHash,
					HashFunc: defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_128",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					Mode:     ModeTreeBuildCalculateRootHash,
					HashFunc: defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_512",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					Mode:     ModeTreeBuildCalculateRootHash,
					HashFunc: defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_1024",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					Mode:     ModeTreeBuildCalculateRootHash,
					HashFunc: defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_hash_func_error",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					HashFunc: func([]byte) ([]byte, error) {
						return nil, fmt.Errorf("hash func error")
					},
					Mode: ModeTreeBuildCalculateRootHash,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.args.config, tt.args.blocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			config := &Config{
				HashFunc: defaultHashFuncBlake3,
			}
			m1, err := New(config, tt.args.blocks)
			if err != nil {
				t.Errorf("test setup error %v", err)
				return
			}
			if !bytes.Equal(m.Root, m1.Root) && !tt.wantErr {
				fmt.Println("m", m.Root)
				fmt.Println("m1", m1.Root)
				t.Errorf("tree generated is wrong")
				return
			}
		})
	}
}

func TestMerkleTreeNew_treeBuildHashFuncBlake3PParallel(t *testing.T) {
	type args struct {
		blocks [][]byte
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_build_tree_parallel_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   4,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_8",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_8",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_8",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_8",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   8,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_16",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_16",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_16",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_16",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   16,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_16_32",
			args: args{
				blocks: genTestDataBlocks(16),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_128_32",
			args: args{
				blocks: genTestDataBlocks(128),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_512_32",
			args: args{
				blocks: genTestDataBlocks(512),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
		{
			name: "test_build_tree_parallel_1024_32",
			args: args{
				blocks: genTestDataBlocks(1024),
				config: &Config{
					RunInParallel: true,
					NumRoutines:   32,
					Mode:          ModeTreeBuildCalculateRootHash,
					HashFunc:      defaultHashFuncBlake3,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.args.config, tt.args.blocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			config := &Config{
				HashFunc: defaultHashFuncBlake3,
			}
			m1, err := New(config, tt.args.blocks)
			if err != nil {
				t.Errorf("test setup error %v", err)
				return
			}
			if !bytes.Equal(m.Root, m1.Root) && !tt.wantErr {
				fmt.Println("m", m.Root)
				fmt.Println("m1", m1.Root)
				t.Errorf("tree generated is wrong")
				return
			}
		})
	}
}

func BenchmarkMerkleTreeHashFuncBlake3PNew(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	config := &Config{
		HashFunc: defaultHashFuncBlake3,
	}
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeHashFuncBlake3PBuild(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:     ModeTreeBuildCalculateRootHash,
		HashFunc: defaultHashFuncBlake3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildHashFuncBlake3Parallel(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   4,
		HashFunc:      defaultHashFuncBlake3,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildHashFuncBlake3Parallel8(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   8,
		HashFunc:      defaultHashFuncBlake3,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildHashFuncBlake3Parallel16(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   16,
		HashFunc:      defaultHashFuncBlake3,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeBuildHashFuncBlake3Parallel32(b *testing.B) {
	config := &Config{
		Mode:          ModeTreeBuildCalculateRootHash,
		RunInParallel: true,
		NumRoutines:   32,
		HashFunc:      defaultHashFuncBlake3,
	}
	testCases := genTestDataBlocks(benchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   8,
		HashFunc:      defaultHashFuncBlake3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer8(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   8,
		HashFunc:      defaultHashFuncBlake3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer16(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   16,
		HashFunc:      defaultHashFuncBlake3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeRootHashHashFuncBlake3DivideAndConquer32(b *testing.B) {
	testCases := genTestDataBlocks(benchSize)
	config := &Config{
		Mode:          ModeRootHashCalculateDivideandConquer,
		RunInParallel: true,
		NumRoutines:   32,
		HashFunc:      defaultHashFuncBlake3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}
