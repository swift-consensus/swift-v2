package consensus

import (
	"log"
	"os"
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// SECURITY FIX #17: Panic mode for consensus safety violations
// When a safety violation is detected (double finalization), the node
// should halt to prevent compounding damage during a fork

// SafetyViolation represents a detected consensus safety violation
type SafetyViolation struct {
	Height        uint64
	ExistingBlock types.Hash
	ConflictBlock types.Hash
	Message       string
}

// Finalizer handles block finalization
type Finalizer struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	state      *State
	quorum     *QuorumCalculator

	// Finalized blocks
	finalized map[uint64]*types.FinalizeMsg // height -> finalize message

	// Callbacks
	onFinalized func(msg *types.FinalizeMsg)

	// SECURITY FIX #17: Panic mode handling
	// inPanicMode indicates a consensus safety violation was detected
	inPanicMode bool
	// safetyViolation stores details about the detected violation
	safetyViolation *SafetyViolation
	// onSafetyViolation is called when a safety violation is detected
	// If nil, the node will halt with os.Exit(1)
	onSafetyViolation func(*SafetyViolation)
	// autoHalt controls whether to automatically halt on safety violation
	autoHalt bool
}

// NewFinalizer creates a new finalizer
func NewFinalizer(validators *types.ValidatorSet, state *State, quorum *QuorumCalculator) *Finalizer {
	return &Finalizer{
		validators: validators,
		state:      state,
		quorum:     quorum,
		finalized:  make(map[uint64]*types.FinalizeMsg),
		autoHalt:   true, // SECURITY FIX #17: Default to halting on safety violation
	}
}

// SetFinalizedCallback sets the callback for when a block is finalized
func (f *Finalizer) SetFinalizedCallback(cb func(*types.FinalizeMsg)) {
	f.onFinalized = cb
}

// SetSafetyViolationCallback sets the callback for when a safety violation is detected
// If set, this callback is called instead of halting the node
func (f *Finalizer) SetSafetyViolationCallback(cb func(*SafetyViolation)) {
	f.onSafetyViolation = cb
}

// SetAutoHalt controls whether to automatically halt on safety violation
// WARNING: Setting this to false is dangerous and only for testing
func (f *Finalizer) SetAutoHalt(halt bool) {
	f.autoHalt = halt
}

// IsInPanicMode returns true if a safety violation was detected
func (f *Finalizer) IsInPanicMode() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.inPanicMode
}

// GetSafetyViolation returns the detected safety violation, if any
func (f *Finalizer) GetSafetyViolation() *SafetyViolation {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.safetyViolation
}

// TryFinalize attempts to finalize a block with the given votes
func (f *Finalizer) TryFinalize(block *types.Block, votes []*types.Vote) *types.FinalizeMsg {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if already finalized at this height
	if _, exists := f.finalized[block.Height]; exists {
		return nil
	}

	// Check quorum
	weight := f.quorum.CalculateVoteWeight(votes)
	if !f.quorum.HasQuorum(weight) {
		return nil
	}

	// Aggregate votes
	msg := crypto.AggregateVotes(block, votes, f.validators)
	if msg == nil {
		return nil
	}

	// Record finalization
	f.finalized[block.Height] = msg

	// Callback
	if f.onFinalized != nil {
		f.onFinalized(msg)
	}

	return msg
}

// ProcessFinalizeMsg processes an incoming finalization message
func (f *Finalizer) ProcessFinalizeMsg(msg *types.FinalizeMsg) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Validate
	if !f.validateFinalizeMsg(msg) {
		return false
	}

	// Check if already finalized at this height
	if existing, exists := f.finalized[msg.Block.Height]; exists {
		// If same block, that's fine
		if existing.Block.Hash() == msg.Block.Hash() {
			return true
		}
		// SECURITY FIX #17: Trigger panic mode on consensus safety violation
		// Different block at same height is a CRITICAL consensus failure
		// This indicates either:
		// 1. Network partition with Byzantine validators
		// 2. Bug in consensus protocol
		// 3. Attack in progress
		existingHash := existing.Block.Hash()
		newHash := msg.Block.Hash()

		violation := &SafetyViolation{
			Height:        msg.Block.Height,
			ExistingBlock: existingHash,
			ConflictBlock: newHash,
			Message: "Double finalization detected: two different blocks finalized at the same height",
		}

		// Enter panic mode
		f.inPanicMode = true
		f.safetyViolation = violation

		log.Printf("[CRITICAL] CONSENSUS SAFETY VIOLATION: Double finalization detected at height %d! "+
			"Existing block: %x, New block: %x. "+
			"NODE ENTERING PANIC MODE - HALTING TO PREVENT FURTHER DAMAGE.",
			msg.Block.Height,
			existingHash[:8],
			newHash[:8])

		// Call violation callback if set
		if f.onSafetyViolation != nil {
			f.onSafetyViolation(violation)
		}

		// SECURITY FIX #17: Auto-halt to prevent compounding damage
		if f.autoHalt {
			log.Printf("[CRITICAL] CONSENSUS HALTED: Safety violation requires manual investigation. "+
				"Existing finalized block: %x, Conflicting block: %x at height %d. "+
				"DO NOT RESTART WITHOUT INVESTIGATION.",
				existingHash[:8], newHash[:8], msg.Block.Height)
			os.Exit(1)
		}

		return false
	}

	// Record
	f.finalized[msg.Block.Height] = msg

	// Callback
	if f.onFinalized != nil {
		f.onFinalized(msg)
	}

	return true
}

// validateFinalizeMsg validates a finalization message
func (f *Finalizer) validateFinalizeMsg(msg *types.FinalizeMsg) bool {
	// Check voter weight
	voterIndices := msg.GetVoters(f.validators.Size())
	voters := make([]types.PublicKey, 0, len(voterIndices))

	for _, idx := range voterIndices {
		v := f.validators.GetByIndex(idx)
		if v == nil {
			return false
		}
		voters = append(voters, v.PublicKey)
	}

	weight := f.quorum.CalculateVoterWeight(voters)
	if !f.quorum.HasQuorum(weight) {
		return false
	}

	// Verify aggregate signature
	if !crypto.VerifyFinalizeMsg(msg, f.validators) {
		return false
	}

	return true
}

// IsFinalized checks if a height is finalized
func (f *Finalizer) IsFinalized(height uint64) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, exists := f.finalized[height]
	return exists
}

// GetFinalized returns the finalization message for a height
func (f *Finalizer) GetFinalized(height uint64) *types.FinalizeMsg {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.finalized[height]
}

// GetFinalizedBlock returns the finalized block at a height
func (f *Finalizer) GetFinalizedBlock(height uint64) *types.Block {
	msg := f.GetFinalized(height)
	if msg == nil {
		return nil
	}
	return &msg.Block
}

// LastFinalizedHeight returns the last finalized height
func (f *Finalizer) LastFinalizedHeight() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var max uint64
	for height := range f.finalized {
		if height > max {
			max = height
		}
	}
	return max
}

// GetVoters returns the public keys of voters who finalized a block
func (f *Finalizer) GetVoters(height uint64) []types.PublicKey {
	f.mu.RLock()
	defer f.mu.RUnlock()

	msg := f.finalized[height]
	if msg == nil {
		return nil
	}

	voterIndices := msg.GetVoters(f.validators.Size())
	voters := make([]types.PublicKey, 0, len(voterIndices))

	for _, idx := range voterIndices {
		v := f.validators.GetByIndex(idx)
		if v != nil {
			voters = append(voters, v.PublicKey)
		}
	}

	return voters
}

// Cleanup removes old finalization data
func (f *Finalizer) Cleanup(currentHeight uint64, keepHeights uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := int64(currentHeight) - int64(keepHeights)
	if cutoff < 0 {
		cutoff = 0
	}

	for height := range f.finalized {
		if height < uint64(cutoff) {
			delete(f.finalized, height)
		}
	}
}

// FinalizationStats provides finalization statistics
type FinalizationStats struct {
	TotalFinalized   int
	LastHeight       uint64
	AvgVoterCount    float64
	AvgVoterWeight   float64
}

// GetStats returns finalization statistics
func (f *Finalizer) GetStats() FinalizationStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := FinalizationStats{
		TotalFinalized: len(f.finalized),
	}

	if len(f.finalized) == 0 {
		return stats
	}

	totalVoters := 0
	totalWeight := 0.0

	for height, msg := range f.finalized {
		if height > stats.LastHeight {
			stats.LastHeight = height
		}

		voterIndices := msg.GetVoters(f.validators.Size())
		totalVoters += len(voterIndices)

		for _, idx := range voterIndices {
			v := f.validators.GetByIndex(idx)
			if v != nil {
				totalWeight += v.VotingWeight()
			}
		}
	}

	stats.AvgVoterCount = float64(totalVoters) / float64(len(f.finalized))
	stats.AvgVoterWeight = totalWeight / float64(len(f.finalized))

	return stats
}
