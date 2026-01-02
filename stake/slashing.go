package stake

import (
	"math"
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// SlashReason identifies why a validator was slashed
type SlashReason int

const (
	SlashReasonEquivocation SlashReason = iota
	SlashReasonInvalidProposal
	SlashReasonDowntime
	SlashReasonByzantine
)

// SlashEvent records a slashing event
type SlashEvent struct {
	Validator   types.PublicKey
	Reason      SlashReason
	Amount      uint64
	Severity    float64
	Round       uint64
	Description string
}

// Slasher handles slashing logic
type Slasher struct {
	mu         sync.RWMutex
	stakeManager *Manager
	validators   *types.ValidatorSet
	config       types.Config

	// Slashing history
	history map[string][]SlashEvent // pubkey -> events
}

// NewSlasher creates a new slasher
func NewSlasher(stakeManager *Manager, validators *types.ValidatorSet, config types.Config) *Slasher {
	return &Slasher{
		stakeManager: stakeManager,
		validators:   validators,
		config:       config,
		history:      make(map[string][]SlashEvent),
	}
}

// Slash slashes a validator based on severity
func (s *Slasher) Slash(pubKey types.PublicKey, severity float64, reason SlashReason, round uint64, description string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	v := s.validators.Get(pubKey)
	if v == nil {
		return 0
	}

	// Calculate slash amount
	// slashAmount = stake * severity * slashRate
	slashAmount := uint64(float64(v.Stake) * severity * s.config.SlashRate)

	// Ensure we don't slash more than available
	if slashAmount > v.Stake {
		slashAmount = v.Stake
	}

	// Apply slash
	v.Stake -= slashAmount
	// Ignore overflow error - slashing should proceed even if pool is full
	_ = s.stakeManager.AddToSlashedPool(slashAmount)

	// Record event
	event := SlashEvent{
		Validator:   pubKey,
		Reason:      reason,
		Amount:      slashAmount,
		Severity:    severity,
		Round:       round,
		Description: description,
	}

	key := string(pubKey[:])
	s.history[key] = append(s.history[key], event)

	// Check if should be removed
	if v.Stake < s.config.MinStake {
		s.validators.Remove(pubKey)
	}

	return slashAmount
}

// SlashForEquivocation handles equivocation slashing
// SECURITY: Uses VerifyEquivocationProof which verifies signatures
// to prevent attackers from forging proofs to slash honest validators
func (s *Slasher) SlashForEquivocation(proof *types.EquivocationProof, round uint64) uint64 {
	if !crypto.VerifyEquivocationProof(proof) {
		return 0
	}

	validator := proof.Vote1.Voter

	// Equivocation is a serious offense - high severity
	severity := 1.0

	return s.Slash(
		validator,
		severity,
		SlashReasonEquivocation,
		round,
		"signed conflicting blocks",
	)
}

// SlashForByzantine handles Byzantine behavior slashing with correlation
func (s *Slasher) SlashForByzantine(validators []types.PublicKey, round uint64) map[types.PublicKey]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[types.PublicKey]uint64)

	// Calculate correlation multiplier
	correlationMult := 1.0 + float64(len(validators))*types.CorrelationFactor

	for _, pubKey := range validators {
		v := s.validators.Get(pubKey)
		if v == nil {
			continue
		}

		key := string(pubKey[:])

		// Get offense count for escalation
		offenseCount := len(s.history[key]) + 1
		escalation := float64(offenseCount)

		// Calculate severity
		severity := types.TrustPenaltyByzantine * correlationMult * escalation

		// Cap severity at 1.0
		severity = math.Min(1.0, severity)

		// Calculate slash amount
		slashAmount := uint64(float64(v.Stake) * severity * s.config.SlashRate)
		if slashAmount > v.Stake {
			slashAmount = v.Stake
		}

		// Apply slash
		v.Stake -= slashAmount
		// Ignore overflow error - slashing should proceed even if pool is full
		_ = s.stakeManager.AddToSlashedPool(slashAmount)

		// Record event
		event := SlashEvent{
			Validator:   pubKey,
			Reason:      SlashReasonByzantine,
			Amount:      slashAmount,
			Severity:    severity,
			Round:       round,
			Description: "coordinated Byzantine behavior",
		}
		s.history[key] = append(s.history[key], event)

		result[pubKey] = slashAmount

		// Check if should be removed
		if v.Stake < s.config.MinStake {
			s.validators.Remove(pubKey)
		}
	}

	return result
}

// SlashForDowntime handles downtime slashing
func (s *Slasher) SlashForDowntime(pubKey types.PublicKey, missedRounds uint64, round uint64) uint64 {
	// Downtime has lower severity
	// Severity increases with more missed rounds
	severity := math.Min(0.1, float64(missedRounds)*0.001)

	return s.Slash(
		pubKey,
		severity,
		SlashReasonDowntime,
		round,
		"excessive downtime",
	)
}

// GetSlashHistory returns the slash history for a validator
func (s *Slasher) GetSlashHistory(pubKey types.PublicKey) []SlashEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.history[string(pubKey[:])]
}

// TotalSlashed returns the total amount slashed from a validator
func (s *Slasher) TotalSlashed(pubKey types.PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total uint64
	for _, event := range s.history[string(pubKey[:])] {
		total += event.Amount
	}
	return total
}

// SlashCount returns the number of times a validator was slashed
func (s *Slasher) SlashCount(pubKey types.PublicKey) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.history[string(pubKey[:])])
}

// SlashingSeverity calculates the cumulative slashing severity for a validator
func (s *Slasher) SlashingSeverity(pubKey types.PublicKey) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total float64
	for _, event := range s.history[string(pubKey[:])] {
		total += event.Severity
	}
	return total
}

// PruneValidator removes all history data for a validator
// STABILITY FIX: Prevents memory leaks when validators leave the set
// Call this when a validator is removed (e.g., after unbonding completes)
func (s *Slasher) PruneValidator(pubKey types.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.history, string(pubKey[:]))
}

// ReasonString returns a human-readable string for a slash reason
func (r SlashReason) String() string {
	switch r {
	case SlashReasonEquivocation:
		return "equivocation"
	case SlashReasonInvalidProposal:
		return "invalid proposal"
	case SlashReasonDowntime:
		return "downtime"
	case SlashReasonByzantine:
		return "byzantine behavior"
	default:
		return "unknown"
	}
}
