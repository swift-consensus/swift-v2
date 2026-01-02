// Package trust manages validator trust scores in SWIFT v2 consensus.
package trust

import (
	"math"
	"sync"

	"github.com/swift-consensus/swift-v2/types"
)

// Manager manages trust scores for all validators
type Manager struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	config     types.Config

	// Online tracking
	voteHistory map[string][]uint64 // pubkey -> rounds they voted in

	// Byzantine tracking
	byzantineHistory map[string]int // pubkey -> offense count
}

// NewManager creates a new trust manager
func NewManager(validators *types.ValidatorSet, config types.Config) *Manager {
	return &Manager{
		validators:       validators,
		config:           config,
		voteHistory:      make(map[string][]uint64),
		byzantineHistory: make(map[string]int),
	}
}

// RewardVote rewards a validator for voting correctly
func (m *Manager) RewardVote(pubKey types.PublicKey, round uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return
	}

	// Record vote
	key := string(pubKey[:])
	m.voteHistory[key] = append(m.voteHistory[key], round)

	// Trim old history
	m.trimVoteHistory(key, round)

	// Increase trust (bounded by ceiling)
	newTrust := v.Trust.BaseTrust + m.config.TrustReward
	ceiling := v.TrustCeiling()
	v.Trust.BaseTrust = math.Min(newTrust, ceiling)

	// Increment rounds active
	v.Trust.RoundsActive++
	v.Trust.LastVoteRound = round
	v.Online = true
}

// PenaltyMiss penalizes a validator for missing a vote while online
func (m *Manager) PenaltyMiss(pubKey types.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return
	}

	// Only penalize if considered online
	if !v.Online {
		return
	}

	// Decrease trust
	newTrust := v.Trust.BaseTrust - m.config.TrustPenaltyMiss
	v.Trust.BaseTrust = math.Max(types.TrustMin, newTrust)
}

// PenaltyByzantine penalizes validators for Byzantine behavior
func (m *Manager) PenaltyByzantine(pubKeys []types.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Calculate correlation penalty
	correlationMult := CorrelationPenalty(len(pubKeys))

	for _, pubKey := range pubKeys {
		v := m.validators.Get(pubKey)
		if v == nil {
			continue
		}

		key := string(pubKey[:])

		// Increment offense count
		m.byzantineHistory[key]++
		v.Trust.OffenseCount = m.byzantineHistory[key]

		// Calculate penalty with escalation
		penalty := ByzantinePenalty(
			m.config.TrustPenaltyByzantine,
			correlationMult,
			v.Trust.OffenseCount,
		)

		// Apply penalty
		v.Trust.BaseTrust = math.Max(types.TrustMin, v.Trust.BaseTrust-penalty)
	}
}

// ApplyDecay applies trust decay to all validators
func (m *Manager) ApplyDecay() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, v := range m.validators.Validators {
		v.Trust.BaseTrust *= m.config.TrustDecay
	}
}

// UpdateOnlineStatus updates online status based on recent votes
func (m *Manager) UpdateOnlineStatus(currentRound uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	windowSize := m.config.OnlineWindow

	for _, v := range m.validators.Validators {
		key := string(v.PublicKey[:])
		votes := m.voteHistory[key]

		// Check if voted in window
		online := false
		for _, round := range votes {
			if currentRound-round <= windowSize {
				online = true
				break
			}
		}

		v.Online = online
	}
}

// trimVoteHistory trims old votes from history
func (m *Manager) trimVoteHistory(key string, currentRound uint64) {
	votes := m.voteHistory[key]
	windowSize := m.config.OnlineWindow * 2 // Keep 2x window for safety

	// Find cutoff point
	cutoff := int64(currentRound) - int64(windowSize)
	if cutoff < 0 {
		cutoff = 0
	}

	// Filter old votes
	newVotes := make([]uint64, 0)
	for _, round := range votes {
		if int64(round) >= cutoff {
			newVotes = append(newVotes, round)
		}
	}

	m.voteHistory[key] = newVotes
}

// GetTrust returns the effective trust of a validator
func (m *Manager) GetTrust(pubKey types.PublicKey) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return 0
	}

	return v.EffectiveTrust()
}

// GetVotingWeight returns the voting weight of a validator
func (m *Manager) GetVotingWeight(pubKey types.PublicKey) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return 0
	}

	return v.VotingWeight()
}

// TotalVotingWeight returns the total voting weight
func (m *Manager) TotalVotingWeight() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.validators.TotalVotingWeight()
}

// OnlineVotingWeight returns the voting weight of online validators
func (m *Manager) OnlineVotingWeight() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.validators.OnlineVotingWeight()
}

// IsOnline returns whether a validator is considered online
func (m *Manager) IsOnline(pubKey types.PublicKey) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return false
	}

	return v.Online
}

// GetOffenseCount returns the number of Byzantine offenses
func (m *Manager) GetOffenseCount(pubKey types.PublicKey) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.byzantineHistory[string(pubKey[:])]
}

// ProcessRoundEnd processes end of round trust updates
func (m *Manager) ProcessRoundEnd(voters []types.PublicKey, currentRound uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create set of voters for fast lookup
	voterSet := make(map[string]bool)
	for _, pk := range voters {
		voterSet[string(pk[:])] = true
	}

	// Update each validator
	for _, v := range m.validators.Validators {
		key := string(v.PublicKey[:])

		if voterSet[key] {
			// Voted correctly
			m.voteHistory[key] = append(m.voteHistory[key], currentRound)
			m.trimVoteHistory(key, currentRound)

			newTrust := v.Trust.BaseTrust + m.config.TrustReward
			ceiling := v.TrustCeiling()
			v.Trust.BaseTrust = math.Min(newTrust, ceiling)

			v.Trust.RoundsActive++
			v.Trust.LastVoteRound = currentRound
			v.Online = true
		} else if v.Online {
			// Online but didn't vote
			newTrust := v.Trust.BaseTrust - m.config.TrustPenaltyMiss
			v.Trust.BaseTrust = math.Max(types.TrustMin, newTrust)
		}

		// Apply decay
		v.Trust.BaseTrust *= m.config.TrustDecay
	}
}

// Stats returns trust statistics
type Stats struct {
	TotalValidators   int
	OnlineValidators  int
	TotalTrust        float64
	OnlineTrust       float64
	TotalVotingWeight float64
	OnlineVotingWeight float64
	AvgTrust          float64
	MinTrust          float64
	MaxTrust          float64
}

// PruneValidator removes all history data for a validator
// STABILITY FIX: Prevents memory leaks when validators leave the set
// Call this when a validator is removed (e.g., after unbonding completes)
func (m *Manager) PruneValidator(pubKey types.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(pubKey[:])
	delete(m.voteHistory, key)
	delete(m.byzantineHistory, key)
}

// GetStats returns current trust statistics
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{
		TotalValidators: len(m.validators.Validators),
		MinTrust:        1.0,
		MaxTrust:        0.0,
	}

	for _, v := range m.validators.Validators {
		trust := v.EffectiveTrust()
		weight := v.VotingWeight()

		stats.TotalTrust += trust
		stats.TotalVotingWeight += weight

		if v.Online {
			stats.OnlineValidators++
			stats.OnlineTrust += trust
			stats.OnlineVotingWeight += weight
		}

		if trust < stats.MinTrust {
			stats.MinTrust = trust
		}
		if trust > stats.MaxTrust {
			stats.MaxTrust = trust
		}
	}

	if stats.TotalValidators > 0 {
		stats.AvgTrust = stats.TotalTrust / float64(stats.TotalValidators)
	}

	return stats
}
