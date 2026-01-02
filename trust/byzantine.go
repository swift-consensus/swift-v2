package trust

import (
	"math"
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// MaxByzantinePenalty is the maximum penalty that can be applied
// This prevents overflow causing NaN/Inf in voting weight calculations
const MaxByzantinePenalty = 1.0

// MaxOffenseMultiplier caps the offense count escalation
// After 10 offenses, penalty is maxed out
const MaxOffenseMultiplier = 10

// CorrelationPenalty calculates the correlation penalty multiplier
// When multiple validators are Byzantine together, penalty is amplified
// Capped to prevent overflow
func CorrelationPenalty(numByzantine int) float64 {
	penalty := 1.0 + float64(numByzantine)*types.CorrelationFactor
	// Cap to prevent extreme values (max 3x amplification)
	if penalty > 3.0 {
		return 3.0
	}
	return penalty
}

// ByzantinePenalty calculates the total penalty for Byzantine behavior
// SECURITY FIX: Caps result to prevent overflow causing NaN in voting weight
func ByzantinePenalty(basePenalty, correlationMult float64, offenseCount int) float64 {
	// Cap offense count to prevent runaway escalation
	effectiveOffenses := offenseCount
	if effectiveOffenses > MaxOffenseMultiplier {
		effectiveOffenses = MaxOffenseMultiplier
	}

	// Penalty = base × correlation × offense_count
	penalty := basePenalty * correlationMult * float64(effectiveOffenses)

	// Cap to maximum penalty to prevent NaN/Inf
	if penalty > MaxByzantinePenalty || math.IsNaN(penalty) || math.IsInf(penalty, 0) {
		return MaxByzantinePenalty
	}

	return penalty
}

// ByzantineDetector detects and tracks Byzantine behavior
type ByzantineDetector struct {
	mu sync.RWMutex

	// Track votes per height/round to detect equivocation
	votes map[uint64]map[uint32]map[string][]*types.Vote // height -> round -> voter -> votes

	// Track detected Byzantine validators
	detected map[string][]ByzantineEvent

	// Validators
	validators *types.ValidatorSet
}

// ByzantineEvent represents a detected Byzantine behavior
type ByzantineEvent struct {
	Type      ByzantineType
	Round     uint64
	Validator types.PublicKey
	Evidence  interface{}
}

// ByzantineType identifies the type of Byzantine behavior
type ByzantineType int

const (
	ByzantineTypeEquivocation ByzantineType = iota
	ByzantineTypeInvalidVote
	ByzantineTypeInvalidProposal
	ByzantineTypeDoublePropose
)

// NewByzantineDetector creates a new Byzantine detector
func NewByzantineDetector(validators *types.ValidatorSet) *ByzantineDetector {
	return &ByzantineDetector{
		votes:      make(map[uint64]map[uint32]map[string][]*types.Vote),
		detected:   make(map[string][]ByzantineEvent),
		validators: validators,
	}
}

// RecordVote records a vote and checks for equivocation
func (bd *ByzantineDetector) RecordVote(vote *types.Vote) *types.EquivocationProof {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	// Initialize nested maps
	if bd.votes[vote.Height] == nil {
		bd.votes[vote.Height] = make(map[uint32]map[string][]*types.Vote)
	}
	if bd.votes[vote.Height][vote.Round] == nil {
		bd.votes[vote.Height][vote.Round] = make(map[string][]*types.Vote)
	}

	voterKey := string(vote.Voter[:])
	existingVotes := bd.votes[vote.Height][vote.Round][voterKey]

	// Check for equivocation
	for _, existing := range existingVotes {
		if existing.BlockHash != vote.BlockHash {
			// Equivocation detected!
			proof := &types.EquivocationProof{
				Vote1: *existing,
				Vote2: *vote,
			}

			// Record Byzantine event
			event := ByzantineEvent{
				Type:      ByzantineTypeEquivocation,
				Round:     vote.Height,
				Validator: vote.Voter,
				Evidence:  proof,
			}
			bd.detected[voterKey] = append(bd.detected[voterKey], event)

			return proof
		}
	}

	// Record the vote
	bd.votes[vote.Height][vote.Round][voterKey] = append(existingVotes, vote)

	return nil
}

// RecordByzantine records a Byzantine event
func (bd *ByzantineDetector) RecordByzantine(event ByzantineEvent) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	key := string(event.Validator[:])
	bd.detected[key] = append(bd.detected[key], event)
}

// GetEvents returns all Byzantine events for a validator
func (bd *ByzantineDetector) GetEvents(validator types.PublicKey) []ByzantineEvent {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	return bd.detected[string(validator[:])]
}

// IsByzantine returns true if a validator has been detected as Byzantine
func (bd *ByzantineDetector) IsByzantine(validator types.PublicKey) bool {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	return len(bd.detected[string(validator[:])]) > 0
}

// ByzantineCount returns the number of Byzantine events for a validator
func (bd *ByzantineDetector) ByzantineCount(validator types.PublicKey) int {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	return len(bd.detected[string(validator[:])])
}

// Cleanup removes old data to prevent memory leaks
func (bd *ByzantineDetector) Cleanup(currentHeight uint64, keepRounds uint64) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	// Remove old vote records
	cutoff := int64(currentHeight) - int64(keepRounds)
	if cutoff < 0 {
		cutoff = 0
	}

	for height := range bd.votes {
		if height < uint64(cutoff) {
			delete(bd.votes, height)
		}
	}
}

// ByzantineHandler handles Byzantine validators
type ByzantineHandler struct {
	detector     *ByzantineDetector
	trustManager *Manager
	validators   *types.ValidatorSet
	config       types.Config

	mu sync.Mutex

	// Callbacks
	onSlash func(validator types.PublicKey, severity float64)
	onRemove func(validator types.PublicKey)
}

// NewByzantineHandler creates a new Byzantine handler
func NewByzantineHandler(
	detector *ByzantineDetector,
	trustManager *Manager,
	validators *types.ValidatorSet,
	config types.Config,
) *ByzantineHandler {
	return &ByzantineHandler{
		detector:     detector,
		trustManager: trustManager,
		validators:   validators,
		config:       config,
	}
}

// SetSlashCallback sets the callback for slashing
func (bh *ByzantineHandler) SetSlashCallback(cb func(types.PublicKey, float64)) {
	bh.onSlash = cb
}

// SetRemoveCallback sets the callback for removing validators
func (bh *ByzantineHandler) SetRemoveCallback(cb func(types.PublicKey)) {
	bh.onRemove = cb
}

// HandleEquivocation handles an equivocation proof
// SECURITY: Uses VerifyEquivocationProof which verifies signatures
// to prevent attackers from forging proofs to slash honest validators
func (bh *ByzantineHandler) HandleEquivocation(proof *types.EquivocationProof) {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	if !crypto.VerifyEquivocationProof(proof) {
		return
	}

	validator := proof.Vote1.Voter

	// Apply trust penalty
	bh.trustManager.PenaltyByzantine([]types.PublicKey{validator})

	// Get offense count for severity
	offenseCount := bh.detector.ByzantineCount(validator)
	severity := bh.config.TrustPenaltyByzantine * float64(offenseCount)

	// Call slash callback
	if bh.onSlash != nil {
		bh.onSlash(validator, severity)
	}

	// Check if should remove
	v := bh.validators.Get(validator)
	if v != nil && v.Trust.BaseTrust <= 0 {
		if bh.onRemove != nil {
			bh.onRemove(validator)
		}
	}
}

// HandleByzantineGroup handles a group of Byzantine validators
func (bh *ByzantineHandler) HandleByzantineGroup(validators []types.PublicKey) {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	// Apply correlation penalty
	bh.trustManager.PenaltyByzantine(validators)

	// Calculate severity for each
	correlationMult := CorrelationPenalty(len(validators))

	for _, validator := range validators {
		offenseCount := bh.detector.ByzantineCount(validator)
		severity := ByzantinePenalty(
			bh.config.TrustPenaltyByzantine,
			correlationMult,
			offenseCount,
		)

		// Call slash callback
		if bh.onSlash != nil {
			bh.onSlash(validator, severity)
		}

		// Check if should remove
		v := bh.validators.Get(validator)
		if v != nil && v.Trust.BaseTrust <= 0 {
			if bh.onRemove != nil {
				bh.onRemove(validator)
			}
		}
	}
}

// AnalyzeRound analyzes a round for Byzantine behavior patterns
func (bh *ByzantineHandler) AnalyzeRound(height uint64, round uint32, finalizedBlock types.Hash) []types.PublicKey {
	bh.mu.Lock()
	defer bh.mu.Unlock()

	byzantineValidators := make([]types.PublicKey, 0)

	// Get all votes for this round
	votes := bh.detector.votes[height][round]
	if votes == nil {
		return byzantineValidators
	}

	// Check for validators who voted for blocks other than finalized
	for voterKey, voterVotes := range votes {
		for _, vote := range voterVotes {
			if vote.BlockHash != finalizedBlock {
				var pk types.PublicKey
				copy(pk[:], voterKey)
				byzantineValidators = append(byzantineValidators, pk)
				break
			}
		}
	}

	return byzantineValidators
}

// RiskScore calculates a Byzantine risk score for a validator
func (bh *ByzantineHandler) RiskScore(validator types.PublicKey) float64 {
	v := bh.validators.Get(validator)
	if v == nil {
		return 1.0 // Max risk for unknown
	}

	score := 0.0

	// Factor 1: Low trust
	if v.EffectiveTrust() < 0.5 {
		score += 0.3 * (1.0 - v.EffectiveTrust()/0.5)
	}

	// Factor 2: New validator
	if v.Trust.RoundsActive < 100 {
		score += 0.2 * (1.0 - float64(v.Trust.RoundsActive)/100.0)
	}

	// Factor 3: Previous offenses
	offenseCount := bh.detector.ByzantineCount(validator)
	if offenseCount > 0 {
		score += 0.5 * math.Min(1.0, float64(offenseCount)/3.0)
	}

	return math.Min(1.0, score)
}
