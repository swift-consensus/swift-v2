package trust

import (
	"math"

	"github.com/swift-consensus/swift-v2/types"
)

// CalculateCeiling computes the trust ceiling for a validator
func CalculateCeiling(roundsActive uint64, numVouchers int) float64 {
	// Base ceiling from tenure
	var base float64
	switch {
	case roundsActive < 100:
		base = types.CeilingRound100
	case roundsActive < 250:
		base = types.CeilingRound250
	case roundsActive < 500:
		base = types.CeilingRound500
	case roundsActive < 1000:
		base = types.CeilingRound1000
	default:
		base = types.CeilingMax
	}

	// Vouching bonus (capped)
	vouchBonus := math.Min(types.MaxVouchBonus, float64(numVouchers)*types.VouchBonus)

	return math.Min(types.TrustMax, base+vouchBonus)
}

// InterpolateCeiling computes a smooth ceiling using interpolation
// This provides a smoother progression than discrete steps
func InterpolateCeiling(roundsActive uint64, numVouchers int) float64 {
	var base float64

	switch {
	case roundsActive < 100:
		// Interpolate from 0.1 to 0.2
		progress := float64(roundsActive) / 100.0
		base = 0.1 + 0.1*progress
	case roundsActive < 250:
		// Interpolate from 0.2 to 0.4
		progress := float64(roundsActive-100) / 150.0
		base = 0.2 + 0.2*progress
	case roundsActive < 500:
		// Interpolate from 0.4 to 0.6
		progress := float64(roundsActive-250) / 250.0
		base = 0.4 + 0.2*progress
	case roundsActive < 1000:
		// Interpolate from 0.6 to 0.8
		progress := float64(roundsActive-500) / 500.0
		base = 0.6 + 0.2*progress
	default:
		// Interpolate from 0.8 to 1.0 (asymptotic)
		excess := float64(roundsActive - 1000)
		// Asymptotic approach to 1.0
		base = 0.8 + 0.2*(1-math.Exp(-excess/1000.0))
	}

	// Vouching bonus
	vouchBonus := math.Min(types.MaxVouchBonus, float64(numVouchers)*types.VouchBonus)

	return math.Min(types.TrustMax, base+vouchBonus)
}

// CeilingManager manages trust ceilings with more advanced features
type CeilingManager struct {
	useInterpolation bool
}

// NewCeilingManager creates a new ceiling manager
func NewCeilingManager(useInterpolation bool) *CeilingManager {
	return &CeilingManager{
		useInterpolation: useInterpolation,
	}
}

// GetCeiling returns the trust ceiling for a validator
func (cm *CeilingManager) GetCeiling(v *types.Validator) float64 {
	if cm.useInterpolation {
		return InterpolateCeiling(v.Trust.RoundsActive, len(v.Trust.Vouchers))
	}
	return CalculateCeiling(v.Trust.RoundsActive, len(v.Trust.Vouchers))
}

// TimeToFullTrust estimates rounds needed to reach max ceiling
func TimeToFullTrust(currentRounds uint64) uint64 {
	if currentRounds >= 1000 {
		return 0
	}
	return 1000 - currentRounds
}

// CeilingProgression describes the ceiling at each milestone
type CeilingProgression struct {
	Rounds  uint64
	Ceiling float64
}

// GetCeilingProgression returns the ceiling progression milestones
func GetCeilingProgression() []CeilingProgression {
	return []CeilingProgression{
		{0, types.CeilingRound100},     // Initial
		{100, types.CeilingRound250},   // After 100 rounds
		{250, types.CeilingRound500},   // After 250 rounds
		{500, types.CeilingRound1000},  // After 500 rounds
		{1000, types.CeilingMax},       // After 1000 rounds
	}
}
