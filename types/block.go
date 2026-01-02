package types

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Hash represents a 32-byte hash
type Hash [32]byte

// EmptyHash is the zero hash
var EmptyHash = Hash{}

// Block represents a block in the SWIFT blockchain
type Block struct {
	// Header fields
	Height     uint64    // Block height (0-indexed)
	Round      uint32    // Round number within this height
	ParentHash Hash      // Hash of the parent block
	TxRoot     Hash      // Merkle root of transactions
	StateRoot  Hash      // State root after applying transactions
	Timestamp  int64     // Unix timestamp in nanoseconds
	Proposer   PublicKey // Public key of the proposer

	// Signature
	Signature Signature // BLS signature from proposer

	// Body
	Transactions []Transaction // List of transactions (not hashed)
}

// Transaction represents a transaction in a block
type Transaction struct {
	From      PublicKey // Sender public key
	To        PublicKey // Recipient public key
	Amount    uint64    // Amount to transfer
	Nonce     uint64    // Sender's nonce
	Data      []byte    // Optional data
	Signature Signature // Sender's signature
}

// NewBlock creates a new block
func NewBlock(height uint64, round uint32, parent Hash, proposer PublicKey) *Block {
	return &Block{
		Height:       height,
		Round:        round,
		ParentHash:   parent,
		Timestamp:    time.Now().UnixNano(),
		Proposer:     proposer,
		Transactions: make([]Transaction, 0),
	}
}

// Hash computes the hash of the block header (excluding signature)
func (b *Block) Hash() Hash {
	h := sha256.New()

	// Height
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, b.Height)
	h.Write(buf)

	// Round
	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, b.Round)
	h.Write(buf)

	// ParentHash
	h.Write(b.ParentHash[:])

	// TxRoot
	h.Write(b.TxRoot[:])

	// StateRoot
	h.Write(b.StateRoot[:])

	// Timestamp
	buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(b.Timestamp))
	h.Write(buf)

	// Proposer
	h.Write(b.Proposer[:])

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// HashWithSignature computes the full hash including signature
func (b *Block) HashWithSignature() Hash {
	h := sha256.New()
	blockHash := b.Hash()
	h.Write(blockHash[:])
	h.Write(b.Signature[:])

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// IsGenesis returns true if this is the genesis block
func (b *Block) IsGenesis() bool {
	return b.Height == 0 && b.ParentHash == EmptyHash
}

// Size returns the approximate size of the block in bytes
func (b *Block) Size() int {
	size := 8 + 4 + 32 + 32 + 32 + 8 + 48 + 96 // Header fields
	for _, tx := range b.Transactions {
		size += tx.Size()
	}
	return size
}

// Size returns the approximate size of a transaction in bytes
func (tx *Transaction) Size() int {
	return 48 + 48 + 8 + 8 + len(tx.Data) + 96
}

// Hash computes the hash of a transaction
func (tx *Transaction) Hash() Hash {
	h := sha256.New()
	h.Write(tx.From[:])
	h.Write(tx.To[:])

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, tx.Amount)
	h.Write(buf)

	binary.BigEndian.PutUint64(buf, tx.Nonce)
	h.Write(buf)

	h.Write(tx.Data)

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// GenesisBlock creates the genesis block for a chain
func GenesisBlock(validators []Validator) *Block {
	block := &Block{
		Height:       0,
		Round:        0,
		ParentHash:   EmptyHash,
		TxRoot:       EmptyHash,
		StateRoot:    EmptyHash,
		Timestamp:    time.Now().UnixNano(),
		Transactions: make([]Transaction, 0),
	}

	// Genesis block has no proposer signature
	return block
}
