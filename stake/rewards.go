package stake

import (
	"log"
	"math"
	"sync"

	"github.com/swift-consensus/swift-v2/types"
)

// safeAddBalance adds two uint64 values with overflow protection
// SECURITY FIX #21: Prevents balance overflow from wrapping to 0
func safeAddBalance(balance, amount uint64) uint64 {
	result := balance + amount
	if result < balance {
		// Overflow - cap at max value and log warning
		log.Printf("[REWARDS] WARNING: Balance overflow detected. Capping at max uint64.")
		return math.MaxUint64
	}
	return result
}

// RewardEvent records a reward distribution
type RewardEvent struct {
	Round       uint64
	TotalReward uint64
	Proposer    types.PublicKey
	ProposerBonus uint64
	Distributions map[string]uint64 // pubkey -> amount
}

// RewardDistributor handles reward distribution
type RewardDistributor struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	config     types.Config

	// Reward history
	history []RewardEvent

	// Accumulated rewards per validator
	accumulated map[string]uint64 // pubkey -> accumulated rewards
}

// NewRewardDistributor creates a new reward distributor
func NewRewardDistributor(validators *types.ValidatorSet, config types.Config) *RewardDistributor {
	return &RewardDistributor{
		validators:  validators,
		config:      config,
		history:     make([]RewardEvent, 0),
		accumulated: make(map[string]uint64),
	}
}

// DistributeBlockReward distributes the block reward
func (rd *RewardDistributor) DistributeBlockReward(
	round uint64,
	reward uint64,
	proposer types.PublicKey,
	voters []types.PublicKey,
) *RewardEvent {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	event := &RewardEvent{
		Round:         round,
		TotalReward:   reward,
		Proposer:      proposer,
		Distributions: make(map[string]uint64),
	}

	// Calculate proposer bonus
	proposerBonus := reward * rd.config.ProposerBonus / 100
	event.ProposerBonus = proposerBonus

	// Remaining goes to voters
	voterReward := reward - proposerBonus

	// Calculate total voting weight of voters
	totalWeight := 0.0
	voterWeights := make(map[string]float64)
	for _, pk := range voters {
		v := rd.validators.Get(pk)
		if v != nil {
			weight := v.VotingWeight()
			voterWeights[string(pk[:])] = weight
			totalWeight += weight
		}
	}

	if totalWeight == 0 {
		// No voters, all goes to proposer
		proposerBonus = reward
		event.ProposerBonus = proposerBonus
		voterReward = 0
	}

	// Distribute to proposer
	// SECURITY FIX #21: Use overflow-safe addition for balance
	proposerKey := string(proposer[:])
	p := rd.validators.Get(proposer)
	if p != nil {
		p.Balance = safeAddBalance(p.Balance, proposerBonus)
		rd.accumulated[proposerKey] = safeAddBalance(rd.accumulated[proposerKey], proposerBonus)
		event.Distributions[proposerKey] = proposerBonus
	}

	// Distribute to voters proportionally
	if voterReward > 0 && totalWeight > 0 {
		distributed := uint64(0)
		votersList := voters // Make a copy for iteration

		for i, pk := range votersList {
			key := string(pk[:])
			weight := voterWeights[key]

			var share uint64
			if i == len(votersList)-1 {
				// Last voter gets remainder to avoid rounding errors
				share = voterReward - distributed
			} else {
				share = uint64(float64(voterReward) * weight / totalWeight)
			}

			v := rd.validators.Get(pk)
			if v != nil {
				// SECURITY FIX #21: Use overflow-safe addition for balance
				v.Balance = safeAddBalance(v.Balance, share)
				rd.accumulated[key] = safeAddBalance(rd.accumulated[key], share)
				event.Distributions[key] += share
				distributed += share
			}
		}
	}

	// Record event
	rd.history = append(rd.history, *event)

	return event
}

// GetAccumulatedRewards returns accumulated rewards for a validator
func (rd *RewardDistributor) GetAccumulatedRewards(pubKey types.PublicKey) uint64 {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	return rd.accumulated[string(pubKey[:])]
}

// GetBalance returns the current balance of a validator
func (rd *RewardDistributor) GetBalance(pubKey types.PublicKey) uint64 {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	v := rd.validators.Get(pubKey)
	if v == nil {
		return 0
	}
	return v.Balance
}

// Withdraw withdraws rewards from a validator's balance
func (rd *RewardDistributor) Withdraw(pubKey types.PublicKey, amount uint64) (uint64, error) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	v := rd.validators.Get(pubKey)
	if v == nil {
		return 0, ErrValidatorNotFound
	}

	if amount > v.Balance {
		amount = v.Balance
	}

	v.Balance -= amount
	return amount, nil
}

// WithdrawAll withdraws all rewards from a validator's balance
func (rd *RewardDistributor) WithdrawAll(pubKey types.PublicKey) (uint64, error) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	v := rd.validators.Get(pubKey)
	if v == nil {
		return 0, ErrValidatorNotFound
	}

	amount := v.Balance
	v.Balance = 0
	return amount, nil
}

// GetHistory returns reward history
func (rd *RewardDistributor) GetHistory(limit int) []RewardEvent {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	if limit <= 0 || limit > len(rd.history) {
		limit = len(rd.history)
	}

	// Return most recent
	start := len(rd.history) - limit
	return rd.history[start:]
}

// GetValidatorHistory returns reward history for a specific validator
func (rd *RewardDistributor) GetValidatorHistory(pubKey types.PublicKey, limit int) []RewardEvent {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	key := string(pubKey[:])
	result := make([]RewardEvent, 0)

	for i := len(rd.history) - 1; i >= 0 && len(result) < limit; i-- {
		event := rd.history[i]
		if _, ok := event.Distributions[key]; ok {
			result = append(result, event)
		}
	}

	// Reverse to get chronological order
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// Stats returns reward statistics
type RewardStats struct {
	TotalDistributed  uint64
	TotalProposerBonus uint64
	TotalVoterRewards uint64
	RoundsProcessed   int
	AvgRewardPerRound uint64
}

// GetStats returns current reward statistics
func (rd *RewardDistributor) GetStats() RewardStats {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	stats := RewardStats{
		RoundsProcessed: len(rd.history),
	}

	for _, event := range rd.history {
		stats.TotalDistributed += event.TotalReward
		stats.TotalProposerBonus += event.ProposerBonus
		stats.TotalVoterRewards += event.TotalReward - event.ProposerBonus
	}

	if stats.RoundsProcessed > 0 {
		stats.AvgRewardPerRound = stats.TotalDistributed / uint64(stats.RoundsProcessed)
	}

	return stats
}

// CalculateAPY estimates the annual percentage yield for a validator
func (rd *RewardDistributor) CalculateAPY(pubKey types.PublicKey, rewardPerRound uint64, roundsPerYear uint64) float64 {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	v := rd.validators.Get(pubKey)
	if v == nil || v.Stake == 0 {
		return 0
	}

	// Estimate annual rewards based on voting weight share
	totalWeight := rd.validators.TotalVotingWeight()
	if totalWeight == 0 {
		return 0
	}

	weight := v.VotingWeight()
	share := weight / totalWeight

	// Annual rewards (excluding proposer bonus which is variable)
	voterPoolPerRound := rewardPerRound * (100 - rd.config.ProposerBonus) / 100
	annualRewards := float64(voterPoolPerRound) * share * float64(roundsPerYear)

	// APY = annual rewards / stake
	return annualRewards / float64(v.Stake) * 100
}

// SimulateRewards simulates reward distribution for testing
func SimulateRewards(
	validators *types.ValidatorSet,
	rewardPerRound uint64,
	rounds int,
	participationRate float64,
) map[types.PublicKey]uint64 {
	result := make(map[types.PublicKey]uint64)

	totalWeight := validators.TotalVotingWeight()
	if totalWeight == 0 {
		return result
	}

	for _, v := range validators.Validators {
		weight := v.VotingWeight()
		share := weight / totalWeight

		// Expected rewards based on participation
		expectedVoterReward := float64(rewardPerRound) * 0.95 * share * participationRate

		// Add proposer bonus expectation
		expectedProposerBonus := float64(rewardPerRound) * 0.05 * share

		totalExpected := (expectedVoterReward + expectedProposerBonus) * float64(rounds)

		result[v.PublicKey] = uint64(totalExpected)
	}

	return result
}
