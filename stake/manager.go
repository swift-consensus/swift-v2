// Package stake manages validator stakes in SWIFT v2 consensus.
package stake

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/swift-consensus/swift-v2/types"
)

var (
	// ErrInsufficientStake is returned when stake is below minimum
	ErrInsufficientStake = errors.New("insufficient stake")

	// ErrValidatorNotFound is returned when validator doesn't exist
	ErrValidatorNotFound = errors.New("validator not found")

	// ErrUnbondingInProgress is returned when unbonding is already in progress
	ErrUnbondingInProgress = errors.New("unbonding already in progress")

	// ErrNoUnbonding is returned when there's no unbonding to complete
	ErrNoUnbonding = errors.New("no unbonding in progress")

	// ErrUnbondingNotComplete is returned when unbonding period hasn't passed
	ErrUnbondingNotComplete = errors.New("unbonding period not complete")

	// ErrOverflow is returned when an arithmetic operation would overflow
	ErrOverflow = errors.New("arithmetic overflow")
)

// safeAddUint64 adds two uint64 values with overflow check
// Returns (result, true) on success, (0, false) on overflow
func safeAddUint64(a, b uint64) (uint64, bool) {
	result := a + b
	if result < a { // Overflow occurred
		return 0, false
	}
	return result, true
}

// UnbondingRecord tracks a pending unbonding
type UnbondingRecord struct {
	Validator    types.PublicKey
	Amount       uint64
	StartTime    time.Time
	CompleteTime time.Time
}

// Manager manages stakes for all validators
type Manager struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	config     types.Config

	// Unbonding tracking
	unbonding map[string]*UnbondingRecord // pubkey -> unbonding

	// Slashed pool
	slashedPool uint64

	// Total staked
	totalStaked uint64

	// Callback for when a validator is removed (for cleanup)
	// STABILITY FIX: Used to wire PruneValidator calls for memory cleanup
	onValidatorRemoved func(pubKey types.PublicKey)
}

// NewManager creates a new stake manager
// Returns error if total stake would overflow
func NewManager(validators *types.ValidatorSet, config types.Config) (*Manager, error) {
	m := &Manager{
		validators:  validators,
		config:      config,
		unbonding:   make(map[string]*UnbondingRecord),
		slashedPool: 0,
	}

	// Calculate initial total with overflow checking
	for _, v := range validators.Validators {
		newTotal, ok := safeAddUint64(m.totalStaked, v.Stake)
		if !ok {
			return nil, ErrOverflow
		}
		m.totalStaked = newTotal
	}

	return m, nil
}

// SetOnValidatorRemoved sets the callback for when a validator is removed
// STABILITY FIX: Wire this to trust.Manager.PruneValidator and Slasher.PruneValidator
func (m *Manager) SetOnValidatorRemoved(cb func(types.PublicKey)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onValidatorRemoved = cb
}

// AddStake adds stake to a validator
// SECURITY FIX: Uses overflow-checked arithmetic
func (m *Manager) AddStake(pubKey types.PublicKey, amount uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return ErrValidatorNotFound
	}

	// Check for validator stake overflow
	newStake, ok := safeAddUint64(v.Stake, amount)
	if !ok {
		return ErrOverflow
	}

	// Check for total stake overflow
	newTotal, ok := safeAddUint64(m.totalStaked, amount)
	if !ok {
		return ErrOverflow
	}

	v.Stake = newStake
	m.totalStaked = newTotal

	return nil
}

// Join adds a new validator with initial stake
// SECURITY FIX: Uses overflow-checked arithmetic
func (m *Manager) Join(pubKey types.PublicKey, stake uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stake < m.config.MinStake {
		return ErrInsufficientStake
	}

	// Check if already exists - use internal helper to avoid deadlock
	v := m.validators.Get(pubKey)
	if v != nil {
		// Add to existing stake with overflow check
		newStake, ok := safeAddUint64(v.Stake, stake)
		if !ok {
			return ErrOverflow
		}
		newTotal, ok := safeAddUint64(m.totalStaked, stake)
		if !ok {
			return ErrOverflow
		}
		v.Stake = newStake
		m.totalStaked = newTotal
		return nil
	}

	// Check for total stake overflow before adding new validator
	newTotal, ok := safeAddUint64(m.totalStaked, stake)
	if !ok {
		return ErrOverflow
	}

	// Create new validator
	v = types.NewValidator(pubKey, stake)
	m.validators.Add(v)
	m.totalStaked = newTotal

	return nil
}

// StartUnbonding starts the unbonding process for a validator
func (m *Manager) StartUnbonding(pubKey types.PublicKey, amount uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return ErrValidatorNotFound
	}

	key := string(pubKey[:])
	if _, exists := m.unbonding[key]; exists {
		return ErrUnbondingInProgress
	}

	if v.Stake < amount {
		amount = v.Stake
	}

	// Ensure minimum stake remains
	if v.Stake-amount < m.config.MinStake {
		// Unbond everything, will be removed after unbonding completes
		amount = v.Stake
	}

	now := time.Now()
	m.unbonding[key] = &UnbondingRecord{
		Validator:    pubKey,
		Amount:       amount,
		StartTime:    now,
		CompleteTime: now.Add(types.UnbondingPeriod),
	}

	return nil
}

// CompleteUnbonding completes the unbonding process
func (m *Manager) CompleteUnbonding(pubKey types.PublicKey) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(pubKey[:])
	record, exists := m.unbonding[key]
	if !exists {
		return 0, ErrNoUnbonding
	}

	if time.Now().Before(record.CompleteTime) {
		return 0, ErrUnbondingNotComplete
	}

	v := m.validators.Get(pubKey)
	if v == nil {
		delete(m.unbonding, key)
		return 0, ErrValidatorNotFound
	}

	amount := record.Amount
	if amount > v.Stake {
		amount = v.Stake
	}

	v.Stake -= amount
	m.totalStaked -= amount

	// Remove from unbonding
	delete(m.unbonding, key)

	// Remove validator if no stake left
	if v.Stake == 0 {
		m.validators.Remove(pubKey)

		// STABILITY FIX: Call cleanup callback to prune validator history
		// This prevents memory leaks from voteHistory, byzantineHistory, slashHistory
		if m.onValidatorRemoved != nil {
			m.onValidatorRemoved(pubKey)
		}
	}

	return amount, nil
}

// CancelUnbonding cancels an in-progress unbonding
func (m *Manager) CancelUnbonding(pubKey types.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(pubKey[:])
	if _, exists := m.unbonding[key]; !exists {
		return ErrNoUnbonding
	}

	delete(m.unbonding, key)
	return nil
}

// GetStake returns the stake of a validator
func (m *Manager) GetStake(pubKey types.PublicKey) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return 0
	}

	return v.Stake
}

// TotalStake returns the total staked amount
func (m *Manager) TotalStake() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.totalStaked
}

// VotingWeight returns the voting weight of a validator
func (m *Manager) VotingWeight(pubKey types.PublicKey) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.validators.Get(pubKey)
	if v == nil {
		return 0
	}

	return v.VotingWeight()
}

// CalculateVotingWeight calculates voting weight from stake and trust
// STABILITY FIX: Guards against minStake == 0 to prevent division by zero
func CalculateVotingWeight(stake uint64, effectiveTrust float64, minStake uint64) float64 {
	// Guard against zero minStake to prevent division by zero
	if minStake == 0 {
		minStake = 1
	}

	if stake < minStake {
		return 0
	}

	// Log scale for stake
	stakeWeight := math.Log2(float64(stake)/float64(minStake) + 1)

	// Multiply by trust
	return stakeWeight * effectiveTrust
}

// GetUnbonding returns unbonding info for a validator
func (m *Manager) GetUnbonding(pubKey types.PublicKey) *UnbondingRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.unbonding[string(pubKey[:])]
}

// IsUnbonding returns whether a validator is unbonding
func (m *Manager) IsUnbonding(pubKey types.PublicKey) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.unbonding[string(pubKey[:])]
	return exists
}

// SlashedPool returns the amount in the slashed pool
func (m *Manager) SlashedPool() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.slashedPool
}

// AddToSlashedPool adds to the slashed pool
// SECURITY FIX: Uses overflow-checked arithmetic
func (m *Manager) AddToSlashedPool(amount uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	newPool, ok := safeAddUint64(m.slashedPool, amount)
	if !ok {
		return ErrOverflow
	}
	m.slashedPool = newPool
	return nil
}

// WithdrawFromSlashedPool withdraws from the slashed pool
func (m *Manager) WithdrawFromSlashedPool(amount uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if amount > m.slashedPool {
		amount = m.slashedPool
	}

	m.slashedPool -= amount
	return amount
}

// Stats returns stake statistics
type Stats struct {
	TotalValidators int
	TotalStaked     uint64
	AvgStake        uint64
	MinStake        uint64
	MaxStake        uint64
	SlashedPool     uint64
	UnbondingCount  int
	UnbondingAmount uint64
}

// GetStats returns current stake statistics
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{
		TotalValidators: len(m.validators.Validators),
		TotalStaked:     m.totalStaked,
		SlashedPool:     m.slashedPool,
		UnbondingCount:  len(m.unbonding),
		MinStake:        ^uint64(0),
		MaxStake:        0,
	}

	for _, v := range m.validators.Validators {
		if v.Stake < stats.MinStake {
			stats.MinStake = v.Stake
		}
		if v.Stake > stats.MaxStake {
			stats.MaxStake = v.Stake
		}
	}

	for _, record := range m.unbonding {
		stats.UnbondingAmount += record.Amount
	}

	if stats.TotalValidators > 0 {
		stats.AvgStake = stats.TotalStaked / uint64(stats.TotalValidators)
	}

	if stats.MinStake == ^uint64(0) {
		stats.MinStake = 0
	}

	return stats
}
