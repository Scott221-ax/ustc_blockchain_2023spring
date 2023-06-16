package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/big"
)

var (
	maxNonce int64 = math.MaxInt64
)

const targetBits = 8

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

func IntToBytes(n int64) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, n)
	return bytesBuffer.Bytes()
}

// Run performs a proof-of-work
// implement
func (pow *ProofOfWork) Run() (int64, []byte) {
	nonce := int64(0)
	var hashInt big.Int
	var hash [32]byte

	for nonce < maxNonce {
		data := getCurBlkHeader(pow, nonce)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	return nonce, hash[:]
}

func getCurBlkHeader(pow *ProofOfWork, nonce int64) []byte {
	data := bytes.Join(
		[][]byte{
			IntToBytes(pow.block.Header.Version),   //版本号
			pow.block.Header.PrevBlockHash[:],      //前一个区块的哈希值
			pow.block.Header.MerkleRoot[:],         //默克尔树根,当前区块数据对应哈希值
			IntToBytes(pow.block.Header.Timestamp), //时间戳
			IntToBytes(targetBits),                 //难度值
			IntToBytes(nonce),                      //随机数
		},
		[]byte{},
	)
	return data
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := getCurBlkHeader(pow, pow.block.Header.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1 //比较哈希值与目标值
}
