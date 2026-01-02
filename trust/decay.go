package trust

import (
	"math"

	"github.com/swift-consensus/swift-v2/types"
)

// DecayConfig configures trust decay behavior
type DecayConfig struct {
	// BaseDecay is the multiplicative decay per round (e.g., 0.9999)
	BaseDecay float64

	// InactivityMultiplier increases decay for inactive validators
	InactivityMultiplier float64

	// InactivityThreshold is rounds of inactivity before multiplier applies
	InactivityThreshold uint64
}

// DefaultDecayConfig returns the default decay configuration
func DefaultDecayConfig() DecayConfig {
	return DecayConfig{
		BaseDecay:            types.TrustDecay,
		InactivityMultiplier: 2.0,
		InactivityThreshold:  10,
	}
}

// ApplyDecay applies decay to a trust value
func ApplyDecay(trust float64, decayRate float64) float64 {
	return trust * decayRate
}

// ApplyDecayN applies decay n times (optimized)
func ApplyDecayN(trust float64, decayRate float64, n uint64) float64 {
	if n == 0 {
		return trust
	}
	// trust * decay^n
	return trust * math.Pow(decayRate, float64(n))
}

// CalculateDecayToTarget calculates rounds needed to decay to target trust
func CalculateDecayToTarget(currentTrust, targetTrust, decayRate float64) uint64 {
	if currentTrust <= targetTrust {
		return 0
	}
	if decayRate >= 1.0 {
		return math.MaxUint64
	}

	// trust * decay^n = target
	// n = log(target/trust) / log(decay)
	ratio := targetTrust / currentTrust
	n := math.Log(ratio) / math.Log(decayRate)

	return uint64(math.Ceil(n))
}

// TrustAfterRounds calculates trust after n rounds with decay
func TrustAfterRounds(initialTrust, decayRate float64, rounds uint64) float64 {
	return ApplyDecayN(initialTrust, decayRate, rounds)
}

// HalfLife calculates the half-life in rounds
func HalfLife(decayRate float64) uint64 {
	if decayRate >= 1.0 {
		return math.MaxUint64
	}
	// decay^n = 0.5
	// n = log(0.5) / log(decay)
	n := math.Log(0.5) / math.Log(decayRate)
	return uint64(math.Ceil(n))
}

// DecayManager manages decay with advanced features
type DecayManager struct {
	config DecayConfig
}

// NewDecayManager creates a new decay manager
func NewDecayManager(config DecayConfig) *DecayManager {
	return &DecayManager{config: config}
}

// CalculateDecay calculates the decay rate for a validator
func (dm *DecayManager) CalculateDecay(v *types.Validator, currentRound uint64) float64 {
	decay := dm.config.BaseDecay

	// Check for inactivity
	if currentRound > v.Trust.LastVoteRound+dm.config.InactivityThreshold {
		// Apply increased decay for inactive validators
		inactiveRounds := currentRound - v.Trust.LastVoteRound - dm.config.InactivityThreshold
		multiplier := 1.0 + (dm.config.InactivityMultiplier-1.0)*math.Min(1.0, float64(inactiveRounds)/100.0)
		decay = math.Pow(decay, multiplier)
	}

	return decay
}

// ApplyDecayToValidator applies appropriate decay to a validator
func (dm *DecayManager) ApplyDecayToValidator(v *types.Validator, currentRound uint64) {
	decay := dm.CalculateDecay(v, currentRound)
	v.Trust.BaseTrust = ApplyDecay(v.Trust.BaseTrust, decay)
}

// EffectiveDecay calculates effective decay including trust recovery
// Returns net trust change per round assuming consistent voting
func EffectiveDecay(decayRate, reward float64) float64 {
	// If voting every round: trust_new = trust_old * decay + reward
	// At equilibrium: trust = trust * decay + reward
	// trust * (1 - decay) = reward
	// trust = reward / (1 - decay)

	// The equilibrium trust level
	if decayRate >= 1.0 {
		return math.MaxFloat64
	}
	return reward / (1.0 - decayRate)
}

// EquilibriumTrust calculates the equilibrium trust for consistent voters
func EquilibriumTrust(decayRate, reward float64) float64 {
	return EffectiveDecay(decayRate, reward)
}

// TimeToEquilibrium estimates rounds to reach 95% of equilibrium
func TimeToEquilibrium(initialTrust, decayRate, reward float64) uint64 {
	equilibrium := EquilibriumTrust(decayRate, reward)
	target := 0.95 * equilibrium

	if initialTrust >= target {
		return 0
	}

	// Approximate by simulation
	trust := initialTrust
	rounds := uint64(0)
	for trust < target && rounds < 100000 {
		trust = trust*decayRate + reward
		rounds++
	}

	return rounds
}
