package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// Vote represents a validator's vote for a block
type Vote struct {
	BlockHash Hash      // Hash of the block being voted for
	Height    uint64    // Block height
	Round     uint32    // Round number
	Voter     PublicKey // Voter's public key
	Signature Signature // BLS signature on BlockHash
}

// NewVote creates a new vote
func NewVote(blockHash Hash, height uint64, round uint32, voter PublicKey) *Vote {
	return &Vote{
		BlockHash: blockHash,
		Height:    height,
		Round:     round,
		Voter:     voter,
	}
}

// Hash computes the hash of the vote (for verification)
func (v *Vote) Hash() Hash {
	h := sha256.New()

	h.Write(v.BlockHash[:])

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v.Height)
	h.Write(buf)

	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v.Round)
	h.Write(buf)

	h.Write(v.Voter[:])

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// SigningMessage returns the message to be signed
// SECURITY: Must include Height and Round to prevent vote replay attacks
// across different rounds with the same block hash
func (v *Vote) SigningMessage() []byte {
	// Build message: BlockHash || Height || Round
	msg := make([]byte, 0, 32+8+4) // Hash is 32 bytes
	msg = append(msg, v.BlockHash[:]...)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v.Height)
	msg = append(msg, buf...)

	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v.Round)
	msg = append(msg, buf...)

	return msg
}

// FinalizeMsg announces a finalized block with aggregated signature
type FinalizeMsg struct {
	Block         Block     // The finalized block
	AggSignature  Signature // Aggregated BLS signature from voters
	VoterBitfield []byte    // Bitmap indicating which validators signed
}

// NewFinalizeMsg creates a new finalization message
func NewFinalizeMsg(block Block, aggSig Signature, bitfield []byte) *FinalizeMsg {
	return &FinalizeMsg{
		Block:         block,
		AggSignature:  aggSig,
		VoterBitfield: bitfield,
	}
}

// GetVoters returns the indices of validators who voted
func (f *FinalizeMsg) GetVoters(numValidators int) []int {
	voters := make([]int, 0)
	for i := 0; i < numValidators; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		if byteIdx < len(f.VoterBitfield) && f.VoterBitfield[byteIdx]&(1<<bitIdx) != 0 {
			voters = append(voters, i)
		}
	}
	return voters
}

// SetVoter sets a bit in the bitfield for a voter
func SetVoterBit(bitfield []byte, index int) {
	byteIdx := index / 8
	bitIdx := index % 8
	if byteIdx < len(bitfield) {
		bitfield[byteIdx] |= 1 << bitIdx
	}
}

// GetVoterBit returns true if the bit at index is set
func GetVoterBit(bitfield []byte, index int) bool {
	byteIdx := index / 8
	bitIdx := index % 8
	if byteIdx >= len(bitfield) {
		return false
	}
	return bitfield[byteIdx]&(1<<bitIdx) != 0
}

// NewBitfield creates a new bitfield for n validators
func NewBitfield(n int) []byte {
	return make([]byte, (n+7)/8)
}

// VoteSet tracks votes for a specific height/round
type VoteSet struct {
	Height uint64
	Round  uint32
	Votes  map[string]*Vote // Voter public key hex -> vote
}

// NewVoteSet creates a new vote set
func NewVoteSet(height uint64, round uint32) *VoteSet {
	return &VoteSet{
		Height: height,
		Round:  round,
		Votes:  make(map[string]*Vote),
	}
}

// Add adds a vote to the set, returns true if it's new
func (vs *VoteSet) Add(vote *Vote) bool {
	key := string(vote.Voter[:])
	if _, exists := vs.Votes[key]; exists {
		return false
	}
	vs.Votes[key] = vote
	return true
}

// Get retrieves a vote by voter
func (vs *VoteSet) Get(voter PublicKey) *Vote {
	return vs.Votes[string(voter[:])]
}

// Size returns the number of votes
func (vs *VoteSet) Size() int {
	return len(vs.Votes)
}

// GetAll returns all votes
func (vs *VoteSet) GetAll() []*Vote {
	votes := make([]*Vote, 0, len(vs.Votes))
	for _, v := range vs.Votes {
		votes = append(votes, v)
	}
	return votes
}
