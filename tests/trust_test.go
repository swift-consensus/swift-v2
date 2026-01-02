package tests

import (
	"testing"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

func TestTrustCeiling(t *testing.T) {
	testCases := []struct {
		roundsActive    uint64
		numVouchers     int
		expectedCeiling float64
	}{
		{0, 0, 0.20},      // New validator
		{50, 0, 0.20},     // Still in first tier
		{100, 0, 0.40},    // Second tier
		{250, 0, 0.60},    // Third tier
		{500, 0, 0.80},    // Fourth tier
		{1000, 0, 1.00},   // Max tier
		{0, 1, 0.30},      // New with 1 voucher
		{0, 3, 0.50},      // New with 3 vouchers (max bonus)
		{1000, 3, 1.00},   // Max tier with vouchers (capped at 1.0)
	}

	for i, tc := range testCases {
		ceiling := trust.CalculateCeiling(tc.roundsActive, tc.numVouchers)
		if abs(ceiling-tc.expectedCeiling) > 0.0001 {
			t.Errorf("Case %d: expected %.4f, got %.4f", i, tc.expectedCeiling, ceiling)
		}
	}
}

func TestTrustReward(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.10
	v.Trust.RoundsActive = 1000 // Max ceiling
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Reward vote
	initialTrust := v.Trust.BaseTrust
	mgr.RewardVote(kp.PublicKey, 1)

	// Trust should increase
	if v.Trust.BaseTrust <= initialTrust {
		t.Errorf("Trust should have increased from %.4f", initialTrust)
	}

	// Should increase by reward amount
	expectedTrust := initialTrust + config.TrustReward
	if v.Trust.BaseTrust != expectedTrust {
		t.Errorf("Expected trust %.4f, got %.4f", expectedTrust, v.Trust.BaseTrust)
	}
}

func TestTrustPenalty(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.50
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Penalty for missing vote
	initialTrust := v.Trust.BaseTrust
	mgr.PenaltyMiss(kp.PublicKey)

	// Trust should decrease
	if v.Trust.BaseTrust >= initialTrust {
		t.Errorf("Trust should have decreased from %.4f", initialTrust)
	}

	// Should decrease by penalty amount
	expectedTrust := initialTrust - config.TrustPenaltyMiss
	if v.Trust.BaseTrust != expectedTrust {
		t.Errorf("Expected trust %.4f, got %.4f", expectedTrust, v.Trust.BaseTrust)
	}
}

func TestByzantineCorrelationPenalty(t *testing.T) {
	// SECURITY FIX: Correlation penalty is now capped at 3.0 to prevent overflow
	// causing NaN/Inf in voting weight calculations
	testCases := []struct {
		numByzantine int
		expectedMult float64
	}{
		{1, 1.1},
		{5, 1.5},
		{10, 2.0},
		{40, 3.0}, // Capped at 3.0 (was 5.0 before security fix)
	}

	for _, tc := range testCases {
		mult := trust.CorrelationPenalty(tc.numByzantine)
		if mult != tc.expectedMult {
			t.Errorf("For %d Byzantine validators: expected mult %.2f, got %.2f",
				tc.numByzantine, tc.expectedMult, mult)
		}
	}
}

func TestByzantinePenalty(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(5)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		validators.Add(v)
	}

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// All 5 validators are Byzantine
	pubKeys := make([]types.PublicKey, 5)
	for i, kp := range keyPairs {
		pubKeys[i] = kp.PublicKey
	}

	// Apply Byzantine penalty
	mgr.PenaltyByzantine(pubKeys)

	// Check penalties were applied with correlation
	// Correlation multiplier = 1 + 5 * 0.1 = 1.5
	expectedPenalty := config.TrustPenaltyByzantine * 1.5 // First offense

	for _, kp := range keyPairs {
		v := validators.Get(kp.PublicKey)
		expectedTrust := 1.0 - expectedPenalty
		if v.Trust.BaseTrust != expectedTrust {
			t.Errorf("Expected trust %.4f, got %.4f", expectedTrust, v.Trust.BaseTrust)
		}
	}
}

func TestTrustDecay(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply decay
	initialTrust := v.Trust.BaseTrust
	mgr.ApplyDecay()

	// Trust should decrease
	if v.Trust.BaseTrust >= initialTrust {
		t.Errorf("Trust should have decreased from %.6f", initialTrust)
	}

	// Should be approximately multiplied by decay rate
	expectedTrust := initialTrust * config.TrustDecay
	tolerance := 0.0001
	if abs(v.Trust.BaseTrust-expectedTrust) > tolerance {
		t.Errorf("Expected trust %.6f, got %.6f", expectedTrust, v.Trust.BaseTrust)
	}
}

func TestDecayHalfLife(t *testing.T) {
	decayRate := types.TrustDecay // 0.9999

	halfLife := trust.HalfLife(decayRate)

	// Half-life should be around 6931 rounds for 0.9999 decay
	// ln(0.5) / ln(0.9999) ≈ 6931
	if halfLife < 6000 || halfLife > 7500 {
		t.Errorf("Unexpected half-life: %d (expected ~6931)", halfLife)
	}
}

func TestEquilibriumTrust(t *testing.T) {
	decayRate := types.TrustDecay
	reward := types.TrustReward

	equilibrium := trust.EquilibriumTrust(decayRate, reward)

	// At equilibrium: trust = trust * decay + reward
	// trust * (1 - decay) = reward
	// trust = reward / (1 - decay)
	expected := reward / (1 - decayRate)

	tolerance := 0.01
	if abs(equilibrium-expected) > tolerance {
		t.Errorf("Expected equilibrium %.4f, got %.4f", expected, equilibrium)
	}

	// With 0.01 reward and 0.9999 decay:
	// equilibrium = 0.01 / 0.0001 = 100
	// But trust is capped at 1.0, so effective equilibrium is 1.0
	// This means consistent voters will reach max trust
}

func TestVouching(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(3)

	// Validator 0: high trust (can vouch)
	v0 := types.NewValidator(keyPairs[0].PublicKey, 10000)
	v0.Trust.BaseTrust = 0.80
	v0.Trust.RoundsActive = 1000
	validators.Add(v0)

	// Validator 1: low trust (cannot vouch)
	v1 := types.NewValidator(keyPairs[1].PublicKey, 10000)
	v1.Trust.BaseTrust = 0.30
	validators.Add(v1)

	// Validator 2: new validator
	v2 := types.NewValidator(keyPairs[2].PublicKey, 10000)
	v2.Trust.BaseTrust = 0.10
	v2.Trust.RoundsActive = 0
	validators.Add(v2)

	vm := trust.NewVouchingManager(validators)

	// v0 vouches for v2
	err := vm.Vouch(keyPairs[0].PublicKey, keyPairs[2].PublicKey, 0)
	if err != nil {
		t.Errorf("Vouch failed: %v", err)
	}

	// v2's ceiling should have increased
	ceiling := v2.TrustCeiling()
	expectedCeiling := types.CeilingRound100 + types.VouchBonus // 0.20 + 0.10 = 0.30
	if abs(ceiling-expectedCeiling) > 0.0001 {
		t.Errorf("Expected ceiling %.4f, got %.4f", expectedCeiling, ceiling)
	}

	// v1 cannot vouch (trust too low)
	err = vm.Vouch(keyPairs[1].PublicKey, keyPairs[2].PublicKey, 0)
	if err != trust.ErrInvalidVoucher {
		t.Errorf("Expected ErrInvalidVoucher, got %v", err)
	}

	// Self-vouch should fail
	err = vm.Vouch(keyPairs[0].PublicKey, keyPairs[0].PublicKey, 0)
	if err != trust.ErrSelfVouch {
		t.Errorf("Expected ErrSelfVouch, got %v", err)
	}
}

func TestByzantineDetector(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	detector := trust.NewByzantineDetector(validators)

	// Create two conflicting votes (equivocation)
	vote1 := &types.Vote{
		BlockHash: types.Hash{1},
		Height:    1,
		Round:     0,
		Voter:     kp.PublicKey,
	}

	vote2 := &types.Vote{
		BlockHash: types.Hash{2}, // Different block
		Height:    1,
		Round:     0,
		Voter:     kp.PublicKey,
	}

	// Record first vote
	proof := detector.RecordVote(vote1)
	if proof != nil {
		t.Error("First vote should not produce equivocation proof")
	}

	// Record conflicting vote
	proof = detector.RecordVote(vote2)
	if proof == nil {
		t.Error("Conflicting vote should produce equivocation proof")
	}

	// Verify proof
	if !proof.IsValid() {
		t.Error("Equivocation proof should be valid")
	}

	// Check that validator is marked as Byzantine
	if !detector.IsByzantine(kp.PublicKey) {
		t.Error("Validator should be marked as Byzantine")
	}
}
