// Package consensus implements the SWIFT v2 consensus protocol.
package consensus

import (
	"sync"
	"time"

	"github.com/swift-consensus/swift-v2/types"
)

// State represents the current consensus state
type State struct {
	mu sync.RWMutex

	// Current position
	Height uint64
	Round  uint32
	Step   types.Step

	// Block state
	LastFinalized     types.Hash
	LastFinalizedTime time.Time
	ProposedBlock     *types.Block
	LockedBlock       *types.Block
	LockedRound       uint32
	ValidBlock        *types.Block
	ValidRound        uint32

	// Vote tracking
	Votes *types.VoteSet

	// Timing
	RoundStartTime time.Time
	StepStartTime  time.Time
}

// NewState creates a new consensus state
func NewState() *State {
	return &State{
		Height:        0,
		Round:         0,
		Step:          types.StepPropose,
		LastFinalized: types.EmptyHash,
		Votes:         types.NewVoteSet(0, 0),
	}
}

// NewRound advances to a new round
func (s *State) NewRound(round uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Round = round
	s.Step = types.StepPropose
	s.ProposedBlock = nil
	s.Votes = types.NewVoteSet(s.Height, round)
	s.RoundStartTime = time.Now()
	s.StepStartTime = time.Now()
}

// NewHeight advances to a new height
func (s *State) NewHeight(height uint64, lastFinalizedHash types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Height = height
	s.Round = 0
	s.Step = types.StepPropose
	s.LastFinalized = lastFinalizedHash
	s.LastFinalizedTime = time.Now()
	s.ProposedBlock = nil
	s.LockedBlock = nil
	s.LockedRound = 0
	s.ValidBlock = nil
	s.ValidRound = 0
	s.Votes = types.NewVoteSet(height, 0)
	s.RoundStartTime = time.Now()
	s.StepStartTime = time.Now()
}

// SetStep sets the current step
func (s *State) SetStep(step types.Step) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Step = step
	s.StepStartTime = time.Now()
}

// SetProposedBlock sets the proposed block
func (s *State) SetProposedBlock(block *types.Block) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ProposedBlock = block
}

// SetLockedBlock sets the locked block
func (s *State) SetLockedBlock(block *types.Block, round uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LockedBlock = block
	s.LockedRound = round
}

// SetValidBlock sets the valid block
func (s *State) SetValidBlock(block *types.Block, round uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ValidBlock = block
	s.ValidRound = round
}

// GetHeight returns the current height
func (s *State) GetHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Height
}

// SetHeight sets the current height (used for state restoration)
func (s *State) SetHeight(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Height = height
	s.Votes = types.NewVoteSet(height, s.Round)
}

// GetRound returns the current round
func (s *State) GetRound() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Round
}

// SetRound sets the current round (used for state restoration)
func (s *State) SetRound(round uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Round = round
	s.Votes = types.NewVoteSet(s.Height, round)
}

// GetStep returns the current step
func (s *State) GetStep() types.Step {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Step
}

// GetProposedBlock returns the proposed block
func (s *State) GetProposedBlock() *types.Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ProposedBlock
}

// GetLastFinalized returns the last finalized hash
func (s *State) GetLastFinalized() types.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastFinalized
}

// SetLastFinalized sets the last finalized hash (used for state restoration)
func (s *State) SetLastFinalized(hash types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastFinalized = hash
}

// AddVote adds a vote to the current vote set
func (s *State) AddVote(vote *types.Vote) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if vote.Height != s.Height || vote.Round != s.Round {
		return false
	}

	return s.Votes.Add(vote)
}

// GetVotes returns all votes for current round
func (s *State) GetVotes() []*types.Vote {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Votes.GetAll()
}

// GetVoteCount returns the number of votes
func (s *State) GetVoteCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Votes.Size()
}

// RoundDuration returns how long the current round has been running
func (s *State) RoundDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.RoundStartTime)
}

// StepDuration returns how long the current step has been running
func (s *State) StepDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.StepStartTime)
}

// Snapshot returns a snapshot of the current state
type StateSnapshot struct {
	Height           uint64
	Round            uint32
	Step             types.Step
	LastFinalized    types.Hash
	ProposedBlock    *types.Block
	LockedBlock      *types.Block
	LockedRound      uint32
	ValidBlock       *types.Block
	ValidRound       uint32
	VoteCount        int
	RoundDuration    time.Duration
}

// Snapshot returns a snapshot of the current state
func (s *State) Snapshot() StateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return StateSnapshot{
		Height:        s.Height,
		Round:         s.Round,
		Step:          s.Step,
		LastFinalized: s.LastFinalized,
		ProposedBlock: s.ProposedBlock,
		LockedBlock:   s.LockedBlock,
		LockedRound:   s.LockedRound,
		ValidBlock:    s.ValidBlock,
		ValidRound:    s.ValidRound,
		VoteCount:     s.Votes.Size(),
		RoundDuration: time.Since(s.RoundStartTime),
	}
}
