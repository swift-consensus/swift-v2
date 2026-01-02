package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/swift-consensus/swift-v2/types"
)

// Hash256 computes SHA-256 hash of data
func Hash256(data []byte) types.Hash {
	return sha256.Sum256(data)
}

// HashConcat computes hash of concatenated byte slices
func HashConcat(parts ...[]byte) types.Hash {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// HashUint64 computes hash of a uint64
func HashUint64(n uint64) types.Hash {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return Hash256(buf)
}

// CombineHashes combines multiple hashes into one
func CombineHashes(hashes ...types.Hash) types.Hash {
	h := sha256.New()
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// MerkleRoot computes the Merkle root of a list of hashes
func MerkleRoot(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.EmptyHash
	}

	if len(hashes) == 1 {
		return hashes[0]
	}

	// Make a copy to avoid modifying the input
	current := make([]types.Hash, len(hashes))
	copy(current, hashes)

	// Pad to even length if necessary
	if len(current)%2 == 1 {
		current = append(current, current[len(current)-1])
	}

	for len(current) > 1 {
		next := make([]types.Hash, len(current)/2)
		for i := 0; i < len(next); i++ {
			next[i] = CombineHashes(current[i*2], current[i*2+1])
		}
		current = next

		// Pad if necessary
		if len(current) > 1 && len(current)%2 == 1 {
			current = append(current, current[len(current)-1])
		}
	}

	return current[0]
}

// TransactionsMerkleRoot computes Merkle root of transactions
func TransactionsMerkleRoot(txs []types.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.EmptyHash
	}

	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash()
	}

	return MerkleRoot(hashes)
}

// HashToHex converts a hash to hex string
func HashToHex(hash types.Hash) string {
	return hex.EncodeToString(hash[:])
}

// HexToHash converts a hex string to hash
func HexToHash(s string) (types.Hash, error) {
	var hash types.Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return hash, err
	}
	if len(b) != 32 {
		return hash, ErrInvalidPublicKey
	}
	copy(hash[:], b)
	return hash, nil
}

// VerifyMerkleProof verifies a Merkle proof
type MerkleProof struct {
	Index    int          // Index of the element
	Siblings []types.Hash // Sibling hashes along the path
}

// Verify verifies a Merkle proof
func (p *MerkleProof) Verify(leaf types.Hash, root types.Hash) bool {
	current := leaf
	idx := p.Index

	for _, sibling := range p.Siblings {
		if idx%2 == 0 {
			current = CombineHashes(current, sibling)
		} else {
			current = CombineHashes(sibling, current)
		}
		idx /= 2
	}

	return current == root
}

// GenerateMerkleProof generates a Merkle proof for an element
func GenerateMerkleProof(hashes []types.Hash, index int) *MerkleProof {
	if len(hashes) == 0 || index < 0 || index >= len(hashes) {
		return nil
	}

	proof := &MerkleProof{
		Index:    index,
		Siblings: make([]types.Hash, 0),
	}

	// Make a copy
	current := make([]types.Hash, len(hashes))
	copy(current, hashes)

	// Pad to even length if necessary
	if len(current)%2 == 1 {
		current = append(current, current[len(current)-1])
	}

	idx := index
	for len(current) > 1 {
		// Find sibling
		var siblingIdx int
		if idx%2 == 0 {
			siblingIdx = idx + 1
		} else {
			siblingIdx = idx - 1
		}
		proof.Siblings = append(proof.Siblings, current[siblingIdx])

		// Move up the tree
		next := make([]types.Hash, len(current)/2)
		for i := 0; i < len(next); i++ {
			next[i] = CombineHashes(current[i*2], current[i*2+1])
		}
		current = next
		idx /= 2

		// Pad if necessary
		if len(current) > 1 && len(current)%2 == 1 {
			current = append(current, current[len(current)-1])
		}
	}

	return proof
}
