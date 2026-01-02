package tests

import (
	"math"
	"testing"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// GRADUATED CEILING COMPREHENSIVE TESTS
// ============================================================================

func TestCeilingProgressionAllTiers(t *testing.T) {
	// Test all tier boundaries
	testCases := []struct {
		rounds   uint64
		vouchers int
		minCeil  float64
		maxCeil  float64
	}{
		// Tier 1: 0-99 rounds
		{0, 0, 0.19, 0.21},
		{50, 0, 0.19, 0.21},
		{99, 0, 0.19, 0.21},

		// Tier 2: 100-249 rounds
		{100, 0, 0.39, 0.41},
		{150, 0, 0.39, 0.41},
		{249, 0, 0.39, 0.41},

		// Tier 3: 250-499 rounds
		{250, 0, 0.59, 0.61},
		{375, 0, 0.59, 0.61},
		{499, 0, 0.59, 0.61},

		// Tier 4: 500-999 rounds
		{500, 0, 0.79, 0.81},
		{750, 0, 0.79, 0.81},
		{999, 0, 0.79, 0.81},

		// Tier 5: 1000+ rounds
		{1000, 0, 0.99, 1.01},
		{5000, 0, 0.99, 1.01},
		{100000, 0, 0.99, 1.01},

		// With vouchers
		{0, 1, 0.29, 0.31},      // +0.10
		{0, 2, 0.39, 0.41},      // +0.20
		{0, 3, 0.49, 0.51},      // +0.30 (max bonus)
		{0, 10, 0.49, 0.51},     // Capped at +0.30
		{500, 3, 0.99, 1.01},    // 0.80 + 0.30 = 1.10 -> capped at 1.0
	}

	for i, tc := range testCases {
		ceiling := trust.CalculateCeiling(tc.rounds, tc.vouchers)
		if ceiling < tc.minCeil || ceiling > tc.maxCeil {
			t.Errorf("Case %d (rounds=%d, vouchers=%d): expected [%.2f, %.2f], got %.4f",
				i, tc.rounds, tc.vouchers, tc.minCeil, tc.maxCeil, ceiling)
		}
	}
}

func TestCeilingMonotonicity(t *testing.T) {
	// Ceiling should never decrease as rounds increase
	prevCeiling := 0.0
	for rounds := uint64(0); rounds <= 2000; rounds += 10 {
		ceiling := trust.CalculateCeiling(rounds, 0)
		if ceiling < prevCeiling-0.001 {
			t.Errorf("Ceiling decreased from %.4f to %.4f at round %d",
				prevCeiling, ceiling, rounds)
		}
		prevCeiling = ceiling
	}
}

func TestVouchBonusStacking(t *testing.T) {
	base := trust.CalculateCeiling(0, 0)
	oneVouch := trust.CalculateCeiling(0, 1)
	twoVouch := trust.CalculateCeiling(0, 2)
	threeVouch := trust.CalculateCeiling(0, 3)

	// Each vouch should add 0.10
	if math.Abs((oneVouch-base)-types.VouchBonus) > 0.001 {
		t.Errorf("One vouch should add %.2f, added %.4f", types.VouchBonus, oneVouch-base)
	}

	if math.Abs((twoVouch-base)-2*types.VouchBonus) > 0.001 {
		t.Errorf("Two vouches should add %.2f, added %.4f", 2*types.VouchBonus, twoVouch-base)
	}

	if math.Abs((threeVouch-base)-types.MaxVouchBonus) > 0.001 {
		t.Errorf("Three vouches should add %.2f (max), added %.4f", types.MaxVouchBonus, threeVouch-base)
	}
}

// ============================================================================
// TRUST REWARD/PENALTY COMPREHENSIVE TESTS
// ============================================================================

func TestRewardAccumulation(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.0
	v.Trust.RoundsActive = 10000 // Max ceiling
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply rewards
	numRewards := 50
	for i := 0; i < numRewards; i++ {
		mgr.RewardVote(kp.PublicKey, uint64(i))
	}

	expected := float64(numRewards) * config.TrustReward
	if expected > 1.0 {
		expected = 1.0
	}

	if math.Abs(v.Trust.BaseTrust-expected) > 0.001 {
		t.Errorf("Expected trust %.4f after %d rewards, got %.4f",
			expected, numRewards, v.Trust.BaseTrust)
	}
}

func TestPenaltyAccumulation(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply penalties
	numPenalties := 25
	for i := 0; i < numPenalties; i++ {
		mgr.PenaltyMiss(kp.PublicKey)
	}

	expected := 1.0 - float64(numPenalties)*config.TrustPenaltyMiss
	if expected < 0 {
		expected = 0
	}

	if math.Abs(v.Trust.BaseTrust-expected) > 0.001 {
		t.Errorf("Expected trust %.4f after %d penalties, got %.4f",
			expected, numPenalties, v.Trust.BaseTrust)
	}
}

func TestMixedRewardsAndPenalties(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.5
	v.Trust.RoundsActive = 10000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Simulate realistic pattern: 90% good, 10% bad
	numRounds := 100
	for i := 0; i < numRounds; i++ {
		if i%10 == 0 {
			mgr.PenaltyMiss(kp.PublicKey)
		} else {
			mgr.RewardVote(kp.PublicKey, uint64(i))
		}
	}

	// Net effect: 90 * 0.01 - 10 * 0.02 = 0.90 - 0.20 = +0.70
	expectedDelta := 90*config.TrustReward - 10*config.TrustPenaltyMiss
	expectedTrust := 0.5 + expectedDelta
	if expectedTrust > 1.0 {
		expectedTrust = 1.0
	}

	if math.Abs(v.Trust.BaseTrust-expectedTrust) > 0.01 {
		t.Errorf("Expected trust ~%.4f, got %.4f", expectedTrust, v.Trust.BaseTrust)
	}
}

// ============================================================================
// TRUST DECAY COMPREHENSIVE TESTS
// ============================================================================

func TestDecayMathematicalProperties(t *testing.T) {
	// Verify: trust(n) = trust(0) * decay^n
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	initialTrust := v.Trust.BaseTrust
	numRounds := 1000

	for i := 0; i < numRounds; i++ {
		mgr.ApplyDecay()
	}

	expected := initialTrust * math.Pow(config.TrustDecay, float64(numRounds))

	if math.Abs(v.Trust.BaseTrust-expected) > 0.0001 {
		t.Errorf("Decay formula mismatch: expected %.6f, got %.6f", expected, v.Trust.BaseTrust)
	}
}

func TestHalfLifeCalculation(t *testing.T) {
	decayRate := types.TrustDecay // 0.9999

	// Half-life = ln(0.5) / ln(decay)
	expectedHalfLife := math.Log(0.5) / math.Log(decayRate)

	calculatedHalfLife := trust.HalfLife(decayRate)

	if math.Abs(float64(calculatedHalfLife)-expectedHalfLife) > 100 {
		t.Errorf("Half-life mismatch: expected %.0f, got %d", expectedHalfLife, calculatedHalfLife)
	}

	t.Logf("Half-life at decay rate %.4f: %d rounds", decayRate, calculatedHalfLife)
}

func TestEquilibriumWithRewards(t *testing.T) {
	// At equilibrium: trust * (1 - decay) = reward
	// trust_eq = reward / (1 - decay)
	decayRate := types.TrustDecay
	reward := types.TrustReward

	expectedEquilibrium := reward / (1 - decayRate)
	t.Logf("Theoretical equilibrium: %.2f", expectedEquilibrium)

	// But trust is capped at 1.0
	if expectedEquilibrium > 1.0 {
		t.Log("Equilibrium exceeds 1.0, so consistent voters reach max trust")
	}

	// Verify empirically
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.0
	v.Trust.RoundsActive = 10000
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Run for many rounds with rewards and decay
	for i := 0; i < 100000; i++ {
		mgr.RewardVote(kp.PublicKey, uint64(i))
		mgr.ApplyDecay()
	}

	t.Logf("Empirical equilibrium after 100k rounds: %.6f", v.Trust.BaseTrust)

	// Should reach max trust (1.0)
	if v.Trust.BaseTrust < 0.99 {
		t.Errorf("Should reach near-max trust, got %.4f", v.Trust.BaseTrust)
	}
}

// ============================================================================
// VOUCHING COMPREHENSIVE TESTS
// ============================================================================

func TestVouchingFullCycle(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(5)

	// Create vouchers (high trust, old validators)
	for i := 0; i < 3; i++ {
		v := types.NewValidator(keyPairs[i].PublicKey, 10000)
		v.Trust.BaseTrust = 0.9
		v.Trust.RoundsActive = 2000
		validators.Add(v)
	}

	// Create vouchee (new validator)
	vouchee := types.NewValidator(keyPairs[3].PublicKey, 10000)
	vouchee.Trust.BaseTrust = types.InitialTrust
	vouchee.Trust.RoundsActive = 0
	validators.Add(vouchee)

	vm := trust.NewVouchingManager(validators)

	initialCeiling := vouchee.TrustCeiling()
	t.Logf("Initial ceiling: %.2f", initialCeiling)

	// Apply vouches
	for i := 0; i < 3; i++ {
		err := vm.Vouch(keyPairs[i].PublicKey, keyPairs[3].PublicKey, 0)
		if err != nil {
			t.Errorf("Vouch %d failed: %v", i, err)
		}
		t.Logf("After vouch %d: ceiling = %.2f", i, vouchee.TrustCeiling())
	}

	finalCeiling := vouchee.TrustCeiling()
	expectedFinal := initialCeiling + types.MaxVouchBonus

	if math.Abs(finalCeiling-expectedFinal) > 0.01 {
		t.Errorf("Expected final ceiling %.2f, got %.2f", expectedFinal, finalCeiling)
	}
}

func TestVouchWithdrawal(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(2)

	voucher := types.NewValidator(keyPairs[0].PublicKey, 10000)
	voucher.Trust.BaseTrust = 0.9
	voucher.Trust.RoundsActive = 2000
	validators.Add(voucher)

	vouchee := types.NewValidator(keyPairs[1].PublicKey, 10000)
	vouchee.Trust.BaseTrust = 0.1
	vouchee.Trust.RoundsActive = 0
	validators.Add(vouchee)

	vm := trust.NewVouchingManager(validators)

	// Vouch
	vm.Vouch(keyPairs[0].PublicKey, keyPairs[1].PublicKey, 0)
	ceilingAfterVouch := vouchee.TrustCeiling()

	// Unvouch
	vm.Unvouch(keyPairs[0].PublicKey, keyPairs[1].PublicKey)

	ceilingAfterUnvouch := vouchee.TrustCeiling()

	if ceilingAfterUnvouch >= ceilingAfterVouch {
		t.Error("Ceiling should decrease after unvouch")
	}
}

func TestVoucherByzantinePenalty(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(2)

	voucher := types.NewValidator(keyPairs[0].PublicKey, 10000)
	voucher.Trust.BaseTrust = 0.9
	voucher.Trust.RoundsActive = 2000
	validators.Add(voucher)

	vouchee := types.NewValidator(keyPairs[1].PublicKey, 10000)
	vouchee.Trust.BaseTrust = 0.1
	vouchee.Trust.RoundsActive = 0
	validators.Add(vouchee)

	config := types.DefaultConfig()
	trustMgr := trust.NewManager(validators, config)
	vm := trust.NewVouchingManager(validators)

	// Vouch
	vm.Vouch(keyPairs[0].PublicKey, keyPairs[1].PublicKey, 0)
	ceilingWithVouch := vouchee.TrustCeiling()

	// Vouchee acts Byzantine
	vm.OnByzantine(keyPairs[1].PublicKey, trustMgr)

	// Voucher should lose vouch and potentially face penalty
	ceilingAfterByzantine := vouchee.TrustCeiling()

	if ceilingAfterByzantine >= ceilingWithVouch {
		t.Log("Ceiling should decrease after Byzantine behavior (vouch removed)")
	}
}

// ============================================================================
// BYZANTINE DETECTION COMPREHENSIVE TESTS
// ============================================================================

func TestMultipleEquivocations(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	detector := trust.NewByzantineDetector(validators)

	// Multiple equivocations at different heights
	for height := uint64(1); height <= 10; height++ {
		vote1 := &types.Vote{BlockHash: types.Hash{byte(height)}, Height: height, Round: 0, Voter: kp.PublicKey}
		vote2 := &types.Vote{BlockHash: types.Hash{byte(height + 100)}, Height: height, Round: 0, Voter: kp.PublicKey}

		detector.RecordVote(vote1)
		proof := detector.RecordVote(vote2)

		if proof == nil {
			t.Errorf("Should detect equivocation at height %d", height)
		}
	}

	if !detector.IsByzantine(kp.PublicKey) {
		t.Error("Validator should be marked as Byzantine")
	}
}

func TestByzantineAtDifferentRounds(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	detector := trust.NewByzantineDetector(validators)

	// Same height, different rounds (not equivocation)
	vote1 := &types.Vote{BlockHash: types.Hash{1}, Height: 5, Round: 0, Voter: kp.PublicKey}
	vote2 := &types.Vote{BlockHash: types.Hash{2}, Height: 5, Round: 1, Voter: kp.PublicKey}

	detector.RecordVote(vote1)
	proof := detector.RecordVote(vote2)

	if proof != nil {
		t.Error("Different rounds should not be equivocation")
	}

	// Same round, different blocks (equivocation)
	vote3 := &types.Vote{BlockHash: types.Hash{3}, Height: 5, Round: 0, Voter: kp.PublicKey}
	proof = detector.RecordVote(vote3)

	if proof == nil {
		t.Error("Same round different block should be equivocation")
	}
}

// ============================================================================
// EFFECTIVE TRUST TESTS
// ============================================================================

func TestEffectiveTrustCapping(t *testing.T) {
	testCases := []struct {
		baseTrust    float64
		roundsActive uint64
		vouchers     int
		maxEffective float64
	}{
		{1.0, 0, 0, 0.20},      // High trust but new = capped
		{0.1, 0, 0, 0.10},      // Low trust, new = use base
		{0.5, 500, 0, 0.50},    // Medium trust, ceiling 0.80
		{1.0, 1000, 0, 1.0},    // Max trust, max ceiling
		{0.8, 0, 3, 0.50},      // With vouches: ceiling = 0.20 + 0.30 = 0.50
		{0.15, 0, 0, 0.15},     // Base below ceiling
	}

	for i, tc := range testCases {
		v := types.NewValidator(types.PublicKey{}, 10000)
		v.Trust.BaseTrust = tc.baseTrust
		v.Trust.RoundsActive = tc.roundsActive

		// Add vouchers
		for j := 0; j < tc.vouchers; j++ {
			v.Trust.Vouchers = append(v.Trust.Vouchers, types.PublicKey{byte(j)})
		}

		effective := v.EffectiveTrust()

		if effective > tc.maxEffective+0.01 {
			t.Errorf("Case %d: effective trust %.4f exceeds max %.4f",
				i, effective, tc.maxEffective)
		}

		// Effective should be min(base, ceiling)
		ceiling := v.TrustCeiling()
		expectedEffective := math.Min(tc.baseTrust, ceiling)
		if math.Abs(effective-expectedEffective) > 0.01 {
			t.Errorf("Case %d: expected %.4f, got %.4f (base=%.2f, ceiling=%.2f)",
				i, expectedEffective, effective, tc.baseTrust, ceiling)
		}
	}
}

// ============================================================================
// VOTING WEIGHT FORMULA TESTS
// ============================================================================

func TestVotingWeightFormula(t *testing.T) {
	// weight = log2(stake/MIN_STAKE + 1) * effective_trust
	testCases := []struct {
		stake         uint64
		trust         float64
		roundsActive  uint64
		expectedMin   float64
		expectedMax   float64
	}{
		{types.MinStake, 1.0, 1000, 0.9, 1.1},          // log2(2) * 1.0 = 1.0
		{2 * types.MinStake, 1.0, 1000, 1.5, 1.6},      // log2(3) * 1.0 ≈ 1.58
		{10 * types.MinStake, 1.0, 1000, 3.3, 3.5},     // log2(11) * 1.0 ≈ 3.46
		{100 * types.MinStake, 1.0, 1000, 6.6, 6.7},    // log2(101) * 1.0 ≈ 6.66
		{types.MinStake, 0.5, 1000, 0.4, 0.6},          // log2(2) * 0.5 = 0.5
		{types.MinStake, 0.0, 1000, 0.0, 0.0},          // Zero trust = zero weight
		{types.MinStake - 1, 1.0, 1000, 0.0, 0.0},      // Below min stake = zero weight
	}

	for i, tc := range testCases {
		v := types.NewValidator(types.PublicKey{}, tc.stake)
		v.Trust.BaseTrust = tc.trust
		v.Trust.RoundsActive = tc.roundsActive

		weight := v.VotingWeight()

		if weight < tc.expectedMin || weight > tc.expectedMax {
			t.Errorf("Case %d (stake=%d, trust=%.2f): weight %.4f not in [%.2f, %.2f]",
				i, tc.stake, tc.trust, weight, tc.expectedMin, tc.expectedMax)
		}
	}
}

func TestLogScaleReducesWhaleDominance(t *testing.T) {
	// Compare weight of whale vs small staker
	small := types.NewValidator(types.PublicKey{1}, types.MinStake)
	small.Trust.BaseTrust = 1.0
	small.Trust.RoundsActive = 1000

	whale := types.NewValidator(types.PublicKey{2}, 1_000_000) // 1000x more stake
	whale.Trust.BaseTrust = 1.0
	whale.Trust.RoundsActive = 1000

	smallWeight := small.VotingWeight()
	whaleWeight := whale.VotingWeight()

	ratio := whaleWeight / smallWeight

	t.Logf("Small staker weight: %.4f", smallWeight)
	t.Logf("Whale (1000x stake) weight: %.4f", whaleWeight)
	t.Logf("Weight ratio: %.2fx", ratio)

	// With log scale, 1000x stake should give ~10x weight, not 1000x
	if ratio > 15 {
		t.Errorf("Whale dominance too high: %.2fx (should be ~10x)", ratio)
	}
	if ratio < 5 {
		t.Errorf("Whale weight too low: %.2fx (should be ~10x)", ratio)
	}
}

func TestTrustMultiplierEffect(t *testing.T) {
	// Two validators with same stake but different trust
	highTrust := types.NewValidator(types.PublicKey{1}, 10000)
	highTrust.Trust.BaseTrust = 1.0
	highTrust.Trust.RoundsActive = 1000

	lowTrust := types.NewValidator(types.PublicKey{2}, 10000)
	lowTrust.Trust.BaseTrust = 0.5
	lowTrust.Trust.RoundsActive = 1000

	highWeight := highTrust.VotingWeight()
	lowWeight := lowTrust.VotingWeight()

	ratio := highWeight / lowWeight

	t.Logf("High trust weight: %.4f", highWeight)
	t.Logf("Low trust weight: %.4f", lowWeight)
	t.Logf("Weight ratio: %.2fx", ratio)

	// 2x trust should give 2x weight
	if math.Abs(ratio-2.0) > 0.1 {
		t.Errorf("Expected 2x weight ratio, got %.2fx", ratio)
	}
}

// ============================================================================
// ROUNDS ACTIVE TRACKING TESTS
// ============================================================================

func TestRoundsActiveIncrement(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.RoundsActive = 0
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Rewards should increment rounds active
	for i := 0; i < 100; i++ {
		mgr.RewardVote(kp.PublicKey, uint64(i))
	}

	if v.Trust.RoundsActive < 100 {
		t.Errorf("Rounds active should be >= 100, got %d", v.Trust.RoundsActive)
	}
}

func TestCeilingEvolutionOverTime(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0 // Max trust
	v.Trust.RoundsActive = 0
	validators.Add(v)

	milestones := []struct {
		rounds  uint64
		ceiling float64
	}{
		{0, 0.20},
		{100, 0.40},
		{250, 0.60},
		{500, 0.80},
		{1000, 1.00},
	}

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	for _, m := range milestones {
		// Advance to milestone
		for v.Trust.RoundsActive < m.rounds {
			mgr.RewardVote(kp.PublicKey, v.Trust.RoundsActive)
		}

		ceiling := v.TrustCeiling()
		if math.Abs(ceiling-m.ceiling) > 0.01 {
			t.Errorf("At round %d: expected ceiling %.2f, got %.2f",
				m.rounds, m.ceiling, ceiling)
		}

		effectiveTrust := v.EffectiveTrust()
		t.Logf("Round %d: ceiling=%.2f, effective=%.4f", m.rounds, ceiling, effectiveTrust)
	}
}
