package consensus

import (
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// LeaderSelector handles leader selection
type LeaderSelector struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	config     types.Config

	// Track recent leaders for cooldown
	recentLeaders map[string]uint32 // pubkey -> round they last led
}

// NewLeaderSelector creates a new leader selector
func NewLeaderSelector(validators *types.ValidatorSet, config types.Config) *LeaderSelector {
	return &LeaderSelector{
		validators:    validators,
		config:        config,
		recentLeaders: make(map[string]uint32),
	}
}

// SelectLeader selects the leader for a given height and round
func (ls *LeaderSelector) SelectLeader(height uint64, round uint32, lastHash types.Hash) *types.Validator {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Generate deterministic seed
	seed := crypto.VRFHash(lastHash, height, round)

	// Build list of eligible validators
	eligible := make([]*types.Validator, 0)
	weights := make([]float64, 0)

	for _, v := range ls.validators.Validators {
		if !ls.isEligible(v, round) {
			continue
		}

		eligible = append(eligible, v)
		weights = append(weights, v.LeaderWeight())
	}

	// Fallback if no one is eligible
	if len(eligible) == 0 {
		return ls.fallbackLeader()
	}

	// Weighted selection
	idx := crypto.WeightedSelect(weights, seed)
	if idx < 0 {
		return ls.fallbackLeader()
	}

	return eligible[idx]
}

// isEligible checks if a validator is eligible to be leader
func (ls *LeaderSelector) isEligible(v *types.Validator, currentRound uint32) bool {
	// Must be online
	if !v.Online {
		return false
	}

	// Must meet minimum trust
	if v.EffectiveTrust() < ls.config.MinLeaderTrust {
		return false
	}

	// Check cooldown
	key := string(v.PublicKey[:])
	if lastLed, ok := ls.recentLeaders[key]; ok {
		if currentRound-lastLed <= ls.config.LeaderCooldown {
			return false
		}
	}

	return true
}

// fallbackLeader returns any online validator as fallback
func (ls *LeaderSelector) fallbackLeader() *types.Validator {
	for _, v := range ls.validators.Validators {
		if v.Online {
			return v
		}
	}
	// Last resort: return first validator
	if len(ls.validators.Validators) > 0 {
		return ls.validators.Validators[0]
	}
	return nil
}

// RecordLeader records that a validator was leader
// SECURITY FIX: Also cleans up old entries to prevent memory leak
func (ls *LeaderSelector) RecordLeader(pubKey types.PublicKey, round uint32) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Add the new leader record
	ls.recentLeaders[string(pubKey[:])] = round

	// Cleanup old entries that are past cooldown period
	// This prevents unbounded memory growth
	cooldown := ls.config.LeaderCooldown
	for key, lastRound := range ls.recentLeaders {
		// Entry is stale if current round is past the cooldown window
		// Use signed arithmetic to handle round rollover correctly
		if int64(round)-int64(lastRound) > int64(cooldown)+1 {
			delete(ls.recentLeaders, key)
		}
	}
}

// ClearCooldowns clears all cooldown records
func (ls *LeaderSelector) ClearCooldowns() {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	ls.recentLeaders = make(map[string]uint32)
}

// IsLeader checks if a validator is the leader for given height/round
func (ls *LeaderSelector) IsLeader(pubKey types.PublicKey, height uint64, round uint32, lastHash types.Hash) bool {
	leader := ls.SelectLeader(height, round, lastHash)
	if leader == nil {
		return false
	}
	return leader.PublicKey == pubKey
}

// GetLeaderWeight returns the weight used for leader selection
func (ls *LeaderSelector) GetLeaderWeight(pubKey types.PublicKey) float64 {
	v := ls.validators.Get(pubKey)
	if v == nil {
		return 0
	}
	return v.LeaderWeight()
}

// GetEligibleLeaders returns all validators eligible to be leader
func (ls *LeaderSelector) GetEligibleLeaders(currentRound uint32) []*types.Validator {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	eligible := make([]*types.Validator, 0)
	for _, v := range ls.validators.Validators {
		if ls.isEligible(v, currentRound) {
			eligible = append(eligible, v)
		}
	}
	return eligible
}

// LeaderProbability calculates the probability of a validator being selected as leader
func (ls *LeaderSelector) LeaderProbability(pubKey types.PublicKey, currentRound uint32) float64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	v := ls.validators.Get(pubKey)
	if v == nil || !ls.isEligible(v, currentRound) {
		return 0
	}

	// Calculate total weight of eligible validators
	totalWeight := 0.0
	for _, val := range ls.validators.Validators {
		if ls.isEligible(val, currentRound) {
			totalWeight += val.LeaderWeight()
		}
	}

	if totalWeight == 0 {
		return 0
	}

	return v.LeaderWeight() / totalWeight
}

// NextLeaders returns the expected leaders for the next n rounds
func (ls *LeaderSelector) NextLeaders(height uint64, startRound uint32, n int, lastHash types.Hash) []*types.Validator {
	leaders := make([]*types.Validator, n)

	for i := 0; i < n; i++ {
		round := startRound + uint32(i)
		leaders[i] = ls.SelectLeader(height, round, lastHash)
	}

	return leaders
}
