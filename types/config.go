// Package types defines core data structures and configuration for SWIFT v2 consensus.
package types

import "time"

// Timing configuration
const (
	// BlockTime is the target time between blocks
	BlockTime = 500 * time.Millisecond

	// ViewChangeTimeout is the time to wait before triggering view change
	ViewChangeTimeout = 1000 * time.Millisecond

	// FinalizeTimeout is the time to wait for finalization
	FinalizeTimeout = 2 * BlockTime
)

// Stake configuration
const (
	// MinStake is the minimum stake required to become a validator
	MinStake uint64 = 1000

	// SlashRate is the percentage of stake slashed per 1.0 severity
	SlashRate = 0.05

	// UnbondingPeriod is the time stake is locked after exit request
	UnbondingPeriod = 14 * 24 * time.Hour

	// ProposerBonus is the percentage bonus for block proposer
	ProposerBonus = 5

	// DefaultBlockReward is the default reward per finalized block
	DefaultBlockReward uint64 = 1000
)

// Trust configuration
const (
	// TrustReward is trust gained per correct vote
	TrustReward = 0.01

	// TrustPenaltyMiss is trust lost for missing a vote while online
	TrustPenaltyMiss = 0.02

	// TrustPenaltyByzantine is base trust lost for Byzantine behavior
	TrustPenaltyByzantine = 0.10

	// TrustDecay is multiplicative decay per round
	TrustDecay = 0.9999

	// InitialTrust is the starting trust for new validators
	InitialTrust = 0.10

	// TrustMin is the minimum trust score
	TrustMin = 0.0

	// TrustMax is the maximum trust score
	TrustMax = 1.0

	// CorrelationFactor is the multiplier per additional Byzantine validator
	CorrelationFactor = 0.10
)

// Trust ceiling configuration (by rounds active)
const (
	// CeilingRound100 is max trust for validators active < 100 rounds
	CeilingRound100 = 0.20

	// CeilingRound250 is max trust for validators active < 250 rounds
	CeilingRound250 = 0.40

	// CeilingRound500 is max trust for validators active < 500 rounds
	CeilingRound500 = 0.60

	// CeilingRound1000 is max trust for validators active < 1000 rounds
	CeilingRound1000 = 0.80

	// CeilingMax is max trust for validators active >= 1000 rounds
	CeilingMax = 1.00

	// VouchBonus is the ceiling bonus per voucher
	VouchBonus = 0.10

	// MaxVouchBonus is the maximum vouching bonus
	MaxVouchBonus = 0.30

	// VoucherMinTrust is minimum trust required to vouch for others
	VoucherMinTrust = 0.70
)

// Leader selection configuration
const (
	// LeaderCooldown is rounds before a leader can lead again
	LeaderCooldown = 5

	// LeaderTrustCap is max trust considered for leader selection
	LeaderTrustCap = 0.60

	// MinLeaderTrust is minimum trust to be eligible for leadership
	MinLeaderTrust = 0.30
)

// Quorum configuration
const (
	// AdaptiveQuorum is the quorum percentage of online validators
	AdaptiveQuorum = 0.67

	// SafetyFloor is the minimum quorum percentage of total validators
	SafetyFloor = 0.51

	// OnlineWindow is rounds to look back for online determination
	OnlineWindow = 10
)

// Network configuration
const (
	// MaxValidators is the maximum number of validators
	MaxValidators = 1000

	// MinValidators is the minimum number of validators
	MinValidators = 4

	// MaxBlockSize is maximum block size in bytes
	MaxBlockSize = 1024 * 1024 // 1 MB

	// MaxTransactionsPerBlock is maximum transactions per block
	MaxTransactionsPerBlock = 5000
)

// Config holds runtime configuration for a SWIFT node
type Config struct {
	// Timing
	BlockTime         time.Duration
	ViewChangeTimeout time.Duration

	// Stake
	MinStake      uint64
	SlashRate     float64
	ProposerBonus uint64
	BlockReward   uint64 // Reward per finalized block

	// Trust
	TrustReward           float64
	TrustPenaltyMiss      float64
	TrustPenaltyByzantine float64
	TrustDecay            float64
	InitialTrust          float64

	// Leader
	LeaderCooldown uint32
	LeaderTrustCap float64
	MinLeaderTrust float64

	// Quorum
	AdaptiveQuorum float64
	SafetyFloor    float64
	OnlineWindow   uint64
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		BlockTime:             BlockTime,
		ViewChangeTimeout:     ViewChangeTimeout,
		MinStake:              MinStake,
		SlashRate:             SlashRate,
		ProposerBonus:         ProposerBonus,
		BlockReward:           DefaultBlockReward,
		TrustReward:           TrustReward,
		TrustPenaltyMiss:      TrustPenaltyMiss,
		TrustPenaltyByzantine: TrustPenaltyByzantine,
		TrustDecay:            TrustDecay,
		InitialTrust:          InitialTrust,
		LeaderCooldown:        LeaderCooldown,
		LeaderTrustCap:        LeaderTrustCap,
		MinLeaderTrust:        MinLeaderTrust,
		AdaptiveQuorum:        AdaptiveQuorum,
		SafetyFloor:           SafetyFloor,
		OnlineWindow:          OnlineWindow,
	}
}
