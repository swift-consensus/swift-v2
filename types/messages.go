package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// MessageType identifies the type of consensus message
type MessageType uint8

const (
	MessageTypePropose MessageType = iota
	MessageTypeVote
	MessageTypeFinalize
	MessageTypeViewChange
	MessageTypeViewChangeCert
	MessageTypeHeartbeat
)

// ProposeMsg is sent by the leader to propose a block
type ProposeMsg struct {
	Block          Block            // The proposed block
	ViewChangeCert *ViewChangeCert  // Optional: included after view change
}

// ViewChangeMsg is sent when a validator wants to change view
type ViewChangeMsg struct {
	Height        uint64    // Current height
	NewRound      uint32    // Round we're moving to
	LastFinalized Hash      // Last finalized block hash
	HighestVoted  *Block    // Highest block voted for (if any)
	Voter         PublicKey // Voter's public key
	Signature     Signature // BLS signature
}

// Hash computes the hash of a view change message
func (vc *ViewChangeMsg) Hash() Hash {
	h := sha256.New()

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, vc.Height)
	h.Write(buf)

	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, vc.NewRound)
	h.Write(buf)

	h.Write(vc.LastFinalized[:])

	if vc.HighestVoted != nil {
		blockHash := vc.HighestVoted.Hash()
		h.Write(blockHash[:])
	}

	h.Write(vc.Voter[:])

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// SigningMessage returns the message to be signed
func (vc *ViewChangeMsg) SigningMessage() []byte {
	hash := vc.Hash()
	return hash[:]
}

// ViewChangeCert is a certificate proving valid view change
type ViewChangeCert struct {
	Height       uint64           // Height of the view change
	Round        uint32           // New round number
	Messages     []*ViewChangeMsg // Collected view change messages
	AggSignature Signature        // Aggregated signature
	Bitfield     []byte           // Who signed
}

// NewViewChangeCert creates a new view change certificate
func NewViewChangeCert(height uint64, round uint32) *ViewChangeCert {
	return &ViewChangeCert{
		Height:   height,
		Round:    round,
		Messages: make([]*ViewChangeMsg, 0),
	}
}

// Add adds a view change message to the certificate
func (vcc *ViewChangeCert) Add(msg *ViewChangeMsg) {
	vcc.Messages = append(vcc.Messages, msg)
}

// HighestVotedBlock returns the highest voted block from all messages
func (vcc *ViewChangeCert) HighestVotedBlock() *Block {
	var highest *Block
	var highestRound uint32

	for _, msg := range vcc.Messages {
		if msg.HighestVoted != nil {
			if highest == nil || msg.HighestVoted.Round > highestRound {
				highest = msg.HighestVoted
				highestRound = msg.HighestVoted.Round
			}
		}
	}

	return highest
}

// HeartbeatMsg is sent periodically to indicate liveness
type HeartbeatMsg struct {
	Height    uint64    // Current height
	Round     uint32    // Current round
	Validator PublicKey // Sender's public key
	Timestamp int64     // Unix timestamp
	Signature Signature // BLS signature
}

// Hash computes the hash of a heartbeat message
func (hb *HeartbeatMsg) Hash() Hash {
	h := sha256.New()

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, hb.Height)
	h.Write(buf)

	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, hb.Round)
	h.Write(buf)

	h.Write(hb.Validator[:])

	buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(hb.Timestamp))
	h.Write(buf)

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// SigningMessage returns the message to be signed
func (hb *HeartbeatMsg) SigningMessage() []byte {
	hash := hb.Hash()
	return hash[:]
}

// EquivocationProof proves a validator signed conflicting blocks
type EquivocationProof struct {
	Vote1 Vote // First vote
	Vote2 Vote // Second vote (conflicting)
}

// IsValid checks if the equivocation proof is valid
func (ep *EquivocationProof) IsValid() bool {
	// Same voter
	if ep.Vote1.Voter != ep.Vote2.Voter {
		return false
	}

	// Same height and round
	if ep.Vote1.Height != ep.Vote2.Height || ep.Vote1.Round != ep.Vote2.Round {
		return false
	}

	// Different blocks
	if ep.Vote1.BlockHash == ep.Vote2.BlockHash {
		return false
	}

	return true
}

// ConsensusState represents the current state of consensus
type ConsensusState struct {
	Height         uint64 // Current height
	Round          uint32 // Current round
	Step           Step   // Current step in the round
	LockedBlock    *Block // Block we're locked on (if any)
	LockedRound    uint32 // Round we locked
	ValidBlock     *Block // Valid block we've seen
	ValidRound     uint32 // Round of valid block
	LastFinalized  Hash   // Hash of last finalized block
	ProposedBlock  *Block // Current proposed block
	CommitRound    uint32 // Round at which we committed
}

// Step represents the current step in a consensus round
type Step uint8

const (
	StepPropose Step = iota
	StepVote
	StepFinalize
	StepCommit
)

// String returns a string representation of the step
func (s Step) String() string {
	switch s {
	case StepPropose:
		return "Propose"
	case StepVote:
		return "Vote"
	case StepFinalize:
		return "Finalize"
	case StepCommit:
		return "Commit"
	default:
		return "Unknown"
	}
}
