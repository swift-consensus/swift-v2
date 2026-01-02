package consensus

import (
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// VoteHandler handles vote processing
type VoteHandler struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	quorum     *QuorumCalculator
	state      *State

	// Vote storage per height/round
	votes map[uint64]map[uint32]*types.VoteSet

	// Callbacks
	onQuorumReached func(height uint64, round uint32, votes []*types.Vote)
}

// NewVoteHandler creates a new vote handler
func NewVoteHandler(validators *types.ValidatorSet, quorum *QuorumCalculator, state *State) *VoteHandler {
	return &VoteHandler{
		validators: validators,
		quorum:     quorum,
		state:      state,
		votes:      make(map[uint64]map[uint32]*types.VoteSet),
	}
}

// SetQuorumCallback sets the callback for when quorum is reached
func (vh *VoteHandler) SetQuorumCallback(cb func(uint64, uint32, []*types.Vote)) {
	vh.onQuorumReached = cb
}

// CreateVote creates a vote for a block
func (vh *VoteHandler) CreateVote(block *types.Block, sk types.SecretKey, pk types.PublicKey) *types.Vote {
	vote := types.NewVote(block.Hash(), block.Height, block.Round, pk)
	vote.Signature = crypto.SignVote(sk, vote)
	return vote
}

// ProcessVote processes an incoming vote
// SECURITY FIX #20: Callback invoked AFTER releasing mutex to prevent deadlock
func (vh *VoteHandler) ProcessVote(vote *types.Vote) (bool, error) {
	// Capture callback data under lock
	var callbackData struct {
		shouldCall bool
		height     uint64
		round      uint32
		votes      []*types.Vote
	}

	func() {
		vh.mu.Lock()
		defer vh.mu.Unlock()

		// Validate vote
		if !vh.validateVote(vote) {
			return
		}

		// Get or create vote set
		if vh.votes[vote.Height] == nil {
			vh.votes[vote.Height] = make(map[uint32]*types.VoteSet)
		}
		if vh.votes[vote.Height][vote.Round] == nil {
			vh.votes[vote.Height][vote.Round] = types.NewVoteSet(vote.Height, vote.Round)
		}

		voteSet := vh.votes[vote.Height][vote.Round]

		// Add vote
		if !voteSet.Add(vote) {
			return // Duplicate
		}

		// Also add to state if current
		if vote.Height == vh.state.GetHeight() && vote.Round == vh.state.GetRound() {
			vh.state.AddVote(vote)
		}

		// Check for quorum
		allVotes := voteSet.GetAll()
		weight := vh.quorum.CalculateVoteWeight(allVotes)

		if vh.quorum.HasQuorum(weight) {
			if vh.onQuorumReached != nil {
				// Capture data for callback - will invoke AFTER releasing lock
				callbackData.shouldCall = true
				callbackData.height = vote.Height
				callbackData.round = vote.Round
				// Copy votes to prevent data races
				callbackData.votes = make([]*types.Vote, len(allVotes))
				copy(callbackData.votes, allVotes)
			}
		}
	}()

	// Invoke callback OUTSIDE the lock to prevent deadlock
	// SECURITY: If callback calls VoteHandler methods, they can safely acquire the lock
	if callbackData.shouldCall {
		vh.onQuorumReached(callbackData.height, callbackData.round, callbackData.votes)
		return true, nil
	}

	return false, nil
}

// validateVote validates a vote
func (vh *VoteHandler) validateVote(vote *types.Vote) bool {
	// Check voter exists
	v := vh.validators.Get(vote.Voter)
	if v == nil {
		return false
	}

	// Verify signature
	if !crypto.VerifyVote(vote) {
		return false
	}

	return true
}

// GetVotes returns all votes for a height/round
func (vh *VoteHandler) GetVotes(height uint64, round uint32) []*types.Vote {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	if vh.votes[height] == nil || vh.votes[height][round] == nil {
		return nil
	}

	return vh.votes[height][round].GetAll()
}

// GetVote returns a specific vote
func (vh *VoteHandler) GetVote(height uint64, round uint32, voter types.PublicKey) *types.Vote {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	if vh.votes[height] == nil || vh.votes[height][round] == nil {
		return nil
	}

	return vh.votes[height][round].Get(voter)
}

// VoteCount returns the number of votes for a height/round
func (vh *VoteHandler) VoteCount(height uint64, round uint32) int {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	if vh.votes[height] == nil || vh.votes[height][round] == nil {
		return 0
	}

	return vh.votes[height][round].Size()
}

// CurrentVoteWeight returns the current voting weight for the current round
func (vh *VoteHandler) CurrentVoteWeight() float64 {
	height := vh.state.GetHeight()
	round := vh.state.GetRound()
	votes := vh.GetVotes(height, round)
	return vh.quorum.CalculateVoteWeight(votes)
}

// HasQuorum checks if current round has quorum
func (vh *VoteHandler) HasQuorum() bool {
	weight := vh.CurrentVoteWeight()
	return vh.quorum.HasQuorum(weight)
}

// Cleanup removes old vote data
func (vh *VoteHandler) Cleanup(currentHeight uint64, keepHeights uint64) {
	vh.mu.Lock()
	defer vh.mu.Unlock()

	cutoff := int64(currentHeight) - int64(keepHeights)
	if cutoff < 0 {
		cutoff = 0
	}

	for height := range vh.votes {
		if height < uint64(cutoff) {
			delete(vh.votes, height)
		}
	}
}

// VoteStats provides vote statistics
type VoteStats struct {
	Height       uint64
	Round        uint32
	VoteCount    int
	TotalWeight  float64
	QuorumWeight float64
	Progress     float64
	HasQuorum    bool
}

// GetVoteStats returns statistics for current round
func (vh *VoteHandler) GetVoteStats() VoteStats {
	height := vh.state.GetHeight()
	round := vh.state.GetRound()
	votes := vh.GetVotes(height, round)
	weight := vh.quorum.CalculateVoteWeight(votes)
	quorumWeight := vh.quorum.GetQuorum()

	var progress float64
	if quorumWeight > 0 {
		progress = weight / quorumWeight * 100
	}

	return VoteStats{
		Height:       height,
		Round:        round,
		VoteCount:    len(votes),
		TotalWeight:  weight,
		QuorumWeight: quorumWeight,
		Progress:     progress,
		// Use HasQuorum for consistent epsilon-safe comparison
		HasQuorum: vh.quorum.HasQuorum(weight),
	}
}
