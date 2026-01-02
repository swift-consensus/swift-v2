package consensus

import (
	"math"
	"sync"

	"github.com/swift-consensus/swift-v2/types"
)

// QuorumCalculator calculates quorum thresholds
type QuorumCalculator struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	config     types.Config

	// Cached values
	cachedTotal  float64
	cachedOnline float64
	cacheValid   bool
}

// NewQuorumCalculator creates a new quorum calculator
func NewQuorumCalculator(validators *types.ValidatorSet, config types.Config) *QuorumCalculator {
	return &QuorumCalculator{
		validators: validators,
		config:     config,
	}
}

// InvalidateCache invalidates the cached quorum values
func (qc *QuorumCalculator) InvalidateCache() {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	qc.cacheValid = false
}

// updateCache updates the cached values
func (qc *QuorumCalculator) updateCache() {
	qc.cachedTotal = qc.validators.TotalVotingWeight()
	qc.cachedOnline = qc.validators.OnlineVotingWeight()
	qc.cacheValid = true
}

// GetQuorum returns the quorum threshold
// quorum = max(adaptive_quorum, safety_floor)
func (qc *QuorumCalculator) GetQuorum() float64 {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	adaptiveQuorum := qc.config.AdaptiveQuorum * qc.cachedOnline
	safetyFloor := qc.config.SafetyFloor * qc.cachedTotal

	return math.Max(adaptiveQuorum, safetyFloor)
}

// GetAdaptiveQuorum returns only the adaptive quorum component
func (qc *QuorumCalculator) GetAdaptiveQuorum() float64 {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	return qc.config.AdaptiveQuorum * qc.cachedOnline
}

// GetSafetyFloor returns only the safety floor component
func (qc *QuorumCalculator) GetSafetyFloor() float64 {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	return qc.config.SafetyFloor * qc.cachedTotal
}

// TotalWeight returns total voting weight
func (qc *QuorumCalculator) TotalWeight() float64 {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	return qc.cachedTotal
}

// OnlineWeight returns online voting weight
func (qc *QuorumCalculator) OnlineWeight() float64 {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	return qc.cachedOnline
}

// QuorumSafetyEpsilon is added to quorum calculations to prevent
// floating point precision from allowing sub-quorum weights to pass.
// This covers:
//   - Representation error in 0.67 (~4.4e-17)
//   - Accumulated FP errors in weight sums (~1e-14 for 1000 validators)
// The value of 1e-9 provides a >100,000x safety margin while being
// negligible in practice (67% vs 67.0000001%).
const QuorumSafetyEpsilon = 1e-9

// HasQuorum checks if the given weight meets quorum
// SECURITY FIX: Uses strict comparison with safety margin to prevent
// floating point precision issues from allowing sub-quorum weights
// to incorrectly meet quorum. This is critical for BFT safety.
//
// The issue: 0.67 is not exactly representable in binary floating point,
// so quorum = 0.67 * onlineWeight may be slightly LESS than true 67%.
// Combined with accumulated positive errors in weight sums, sub-quorum
// weight could incorrectly pass the >= check.
func (qc *QuorumCalculator) HasQuorum(weight float64) bool {
	quorum := qc.GetQuorum()

	// Add safety epsilon to quorum to ensure we never accept sub-quorum
	// weight due to floating point representation errors.
	// For BFT: safety (reject invalid) > liveness (accept valid)
	return weight >= quorum+QuorumSafetyEpsilon
}

// CalculateVoteWeight calculates the total weight of votes
func (qc *QuorumCalculator) CalculateVoteWeight(votes []*types.Vote) float64 {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	total := 0.0
	for _, vote := range votes {
		v := qc.validators.Get(vote.Voter)
		if v != nil {
			total += v.VotingWeight()
		}
	}
	return total
}

// CalculateVoterWeight calculates weight from voter public keys
func (qc *QuorumCalculator) CalculateVoterWeight(voters []types.PublicKey) float64 {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	total := 0.0
	for _, pk := range voters {
		v := qc.validators.Get(pk)
		if v != nil {
			total += v.VotingWeight()
		}
	}
	return total
}

// QuorumInfo provides detailed quorum information
type QuorumInfo struct {
	AdaptiveQuorum float64
	SafetyFloor    float64
	Quorum         float64
	TotalWeight    float64
	OnlineWeight   float64
	OnlineRatio    float64
	UsingFloor     bool
}

// GetQuorumInfo returns detailed quorum information
func (qc *QuorumCalculator) GetQuorumInfo() QuorumInfo {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.cacheValid {
		qc.updateCache()
	}

	adaptiveQuorum := qc.config.AdaptiveQuorum * qc.cachedOnline
	safetyFloor := qc.config.SafetyFloor * qc.cachedTotal

	var onlineRatio float64
	if qc.cachedTotal > 0 {
		onlineRatio = qc.cachedOnline / qc.cachedTotal
	}

	return QuorumInfo{
		AdaptiveQuorum: adaptiveQuorum,
		SafetyFloor:    safetyFloor,
		Quorum:         math.Max(adaptiveQuorum, safetyFloor),
		TotalWeight:    qc.cachedTotal,
		OnlineWeight:   qc.cachedOnline,
		OnlineRatio:    onlineRatio,
		UsingFloor:     safetyFloor > adaptiveQuorum,
	}
}

// CanFinalize checks if a set of votes can finalize a block
func (qc *QuorumCalculator) CanFinalize(votes []*types.Vote) bool {
	weight := qc.CalculateVoteWeight(votes)
	return qc.HasQuorum(weight)
}

// WeightNeeded returns how much more weight is needed for quorum
// Uses the same safety epsilon as HasQuorum for consistency
func (qc *QuorumCalculator) WeightNeeded(currentWeight float64) float64 {
	quorum := qc.GetQuorum()
	safeQuorum := quorum + QuorumSafetyEpsilon
	if currentWeight >= safeQuorum {
		return 0
	}
	return safeQuorum - currentWeight
}

// ProgressToQuorum returns progress as a percentage
func (qc *QuorumCalculator) ProgressToQuorum(currentWeight float64) float64 {
	quorum := qc.GetQuorum()
	if quorum == 0 {
		return 100.0
	}
	progress := currentWeight / quorum * 100
	return math.Min(100.0, progress)
}
