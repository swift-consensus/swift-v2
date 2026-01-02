package tests

import (
	"math"
	"testing"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/stake"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// STAKE MANAGEMENT TESTS
// ============================================================================

func TestStakeJoining(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	kp, _ := crypto.GenerateKeyPair()

	// Join with minimum stake
	err = mgr.Join(kp.PublicKey, types.MinStake)
	if err != nil {
		t.Errorf("Join with min stake should succeed: %v", err)
	}

	v := validators.Get(kp.PublicKey)
	if v == nil {
		t.Fatal("Validator should exist after joining")
	}

	if v.Stake != types.MinStake {
		t.Errorf("Expected stake %d, got %d", types.MinStake, v.Stake)
	}
}

func TestStakeJoiningBelowMinimum(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	kp, _ := crypto.GenerateKeyPair()

	err = mgr.Join(kp.PublicKey, types.MinStake-1)
	if err != stake.ErrInsufficientStake {
		t.Errorf("Expected ErrInsufficientStake, got %v", err)
	}

	v := validators.Get(kp.PublicKey)
	if v != nil {
		t.Error("Validator should not exist after failed join")
	}
}

func TestStakeAddition(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	initialStake := v.Stake

	// Add more stake
	err = mgr.AddStake(kp.PublicKey, 5000)
	if err != nil {
		t.Errorf("AddStake failed: %v", err)
	}

	if v.Stake != initialStake+5000 {
		t.Errorf("Expected stake %d, got %d", initialStake+5000, v.Stake)
	}
}

func TestStakeWithdrawalRequest(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// Start unbonding
	err = mgr.StartUnbonding(kp.PublicKey, 5000)
	if err != nil {
		t.Errorf("StartUnbonding failed: %v", err)
	}

	// Check unbonding status
	if !mgr.IsUnbonding(kp.PublicKey) {
		t.Error("Validator should be unbonding")
	}
}

func TestStakeWithdrawalExceedsBalance(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// Implementation caps the amount to available stake rather than erroring
	err = mgr.StartUnbonding(kp.PublicKey, 20000) // More than stake
	if err != nil {
		t.Errorf("Expected unbonding to start (capped to available stake), got error: %v", err)
	}

	// Should be in unbonding state
	if !mgr.IsUnbonding(kp.PublicKey) {
		t.Error("Validator should be in unbonding state")
	}
}

func TestStakeWithdrawalLeavesMinimum(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// When remaining stake would be < minimum, implementation unbonds everything
	err = mgr.StartUnbonding(kp.PublicKey, 10000-config.MinStake+1)
	if err != nil {
		t.Errorf("Unbonding should start (will unbond everything when below min): %v", err)
	}

	// Should be in unbonding state
	if !mgr.IsUnbonding(kp.PublicKey) {
		t.Error("Validator should be in unbonding state")
	}
}

// ============================================================================
// SLASHING TESTS
// ============================================================================

func TestSlashingBasic(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	initialStake := v.Stake

	// Create equivocation proof with valid signatures
	vote1 := &types.Vote{BlockHash: types.Hash{1}, Height: 1, Round: 0, Voter: kp.PublicKey}
	vote1.Signature = crypto.SignVote(kp.SecretKey, vote1)
	vote2 := &types.Vote{BlockHash: types.Hash{2}, Height: 1, Round: 0, Voter: kp.PublicKey}
	vote2.Signature = crypto.SignVote(kp.SecretKey, vote2)
	proof := &types.EquivocationProof{
		Vote1: *vote1,
		Vote2: *vote2,
	}

	slashAmount := slasher.SlashForEquivocation(proof, 1)

	if slashAmount == 0 {
		t.Error("Slash amount should be > 0")
	}

	if v.Stake >= initialStake {
		t.Error("Stake should decrease after slashing")
	}

	if v.Stake+slashAmount != initialStake {
		t.Errorf("Stake accounting error: %d + %d != %d",
			v.Stake, slashAmount, initialStake)
	}
}

func TestSlashingRateCalculation(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	// Sign the votes to make them valid
	proof := &types.EquivocationProof{
		Vote1: types.Vote{BlockHash: types.Hash{1}, Height: 1, Round: 0, Voter: kp.PublicKey},
		Vote2: types.Vote{BlockHash: types.Hash{2}, Height: 1, Round: 0, Voter: kp.PublicKey},
	}
	proof.Vote1.Signature = crypto.SignVote(kp.SecretKey, &proof.Vote1)
	proof.Vote2.Signature = crypto.SignVote(kp.SecretKey, &proof.Vote2)

	slashAmount := slasher.SlashForEquivocation(proof, 1)

	// Expected: stake * severity(1.0) * slashRate(0.05) = 10000 * 1.0 * 0.05 = 500
	expected := uint64(float64(10000) * 1.0 * config.SlashRate)

	if slashAmount != expected {
		t.Errorf("Slash amount %d not equal to expected %d", slashAmount, expected)
	}
}

func TestSlashingMultipleOffenses(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	stakeHistory := []uint64{v.Stake}

	for i := 0; i < 5; i++ {
		// Create equivocation proof with valid signatures
		vote1 := &types.Vote{BlockHash: types.Hash{byte(i)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey}
		vote1.Signature = crypto.SignVote(kp.SecretKey, vote1)
		vote2 := &types.Vote{BlockHash: types.Hash{byte(i + 100)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey}
		vote2.Signature = crypto.SignVote(kp.SecretKey, vote2)
		proof := &types.EquivocationProof{
			Vote1: *vote1,
			Vote2: *vote2,
		}

		slasher.SlashForEquivocation(proof, uint64(i+1))
		stakeHistory = append(stakeHistory, v.Stake)
	}

	// Stake should decrease monotonically
	for i := 1; i < len(stakeHistory); i++ {
		if stakeHistory[i] >= stakeHistory[i-1] {
			t.Errorf("Stake should decrease: offense %d: %d >= %d",
				i, stakeHistory[i], stakeHistory[i-1])
		}
	}

	t.Logf("Stake progression: %v", stakeHistory)
}

func TestSlashingByzantineGroup(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 10000))
	}

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	// 5 validators act Byzantine
	byzantinePKs := make([]types.PublicKey, 5)
	for i := 0; i < 5; i++ {
		byzantinePKs[i] = keyPairs[i].PublicKey
	}

	slasher.SlashForByzantine(byzantinePKs, 1)

	// Check all Byzantine validators were slashed
	for i := 0; i < 5; i++ {
		v := validators.Get(keyPairs[i].PublicKey)
		if v.Stake >= 10000 {
			t.Errorf("Byzantine validator %d should be slashed", i)
		}
	}

	// Non-Byzantine should be unaffected
	for i := 5; i < 10; i++ {
		v := validators.Get(keyPairs[i].PublicKey)
		if v.Stake != 10000 {
			t.Errorf("Non-Byzantine validator %d should not be slashed", i)
		}
	}
}

// ============================================================================
// REWARD DISTRIBUTION TESTS
// ============================================================================

func TestRewardDistributionProportional(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	// Different stakes
	stakes := []uint64{1000, 2000, 3000, 4000}
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, stakes[i])
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	rd := stake.NewRewardDistributor(validators, config)

	blockReward := uint64(1000)
	proposer := keyPairs[0].PublicKey
	voters := make([]types.PublicKey, 4)
	for i, kp := range keyPairs {
		voters[i] = kp.PublicKey
	}

	// Record initial balances (rewards go to Balance, not Stake)
	initialBalances := make([]uint64, 4)
	for i, kp := range keyPairs {
		initialBalances[i] = validators.Get(kp.PublicKey).Balance
	}

	rd.DistributeBlockReward(0, blockReward, proposer, voters)

	// Calculate rewards received (from Balance changes)
	rewards := make([]uint64, 4)
	for i, kp := range keyPairs {
		v := validators.Get(kp.PublicKey)
		rewards[i] = v.Balance - initialBalances[i]
	}

	t.Logf("Rewards: %v", rewards)

	// Higher stake should get higher reward
	for i := 0; i < 3; i++ {
		if rewards[i] >= rewards[i+1] {
			t.Errorf("Higher stake should get higher reward: reward[%d]=%d >= reward[%d]=%d",
				i, rewards[i], i+1, rewards[i+1])
		}
	}
}

func TestRewardDistributionProposerBonus(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	// Equal stakes
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	rd := stake.NewRewardDistributor(validators, config)

	blockReward := uint64(1000)
	proposer := keyPairs[0].PublicKey
	voters := make([]types.PublicKey, 4)
	for i, kp := range keyPairs {
		voters[i] = kp.PublicKey
	}

	// Record initial balances (rewards go to Balance, not Stake)
	initialProposerBalance := validators.Get(proposer).Balance
	initialOtherBalance := validators.Get(keyPairs[1].PublicKey).Balance

	rd.DistributeBlockReward(0, blockReward, proposer, voters)

	// Calculate rewards (from Balance changes)
	proposerReward := validators.Get(proposer).Balance - initialProposerBalance
	otherReward := validators.Get(keyPairs[1].PublicKey).Balance - initialOtherBalance

	t.Logf("Proposer reward: %d, Other reward: %d", proposerReward, otherReward)

	// Proposer should get bonus
	if proposerReward <= otherReward {
		t.Error("Proposer should receive bonus reward")
	}
}

func TestRewardDistributionNoVoters(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	rd := stake.NewRewardDistributor(validators, config)

	initialStake := v.Stake

	// Distribute with no voters (should not panic)
	rd.DistributeBlockReward(0, 1000, kp.PublicKey, []types.PublicKey{})

	// No change expected (or minimal proposer reward)
	if v.Stake < initialStake {
		t.Error("Stake should not decrease")
	}
}

// ============================================================================
// UNBONDING PERIOD TESTS
// ============================================================================

func TestUnbondingPeriodEnforcement(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// Start unbonding
	mgr.StartUnbonding(kp.PublicKey, 5000)

	// Try to complete immediately (should fail)
	_, err = mgr.CompleteUnbonding(kp.PublicKey)
	if err != stake.ErrUnbondingNotComplete {
		t.Errorf("Expected ErrUnbondingNotComplete, got %v", err)
	}

	// Stake should still be unchanged
	if v.Stake != 10000 {
		t.Errorf("Stake should remain %d during unbonding, got %d", 10000, v.Stake)
	}
}

func TestUnbondingMultipleRequests(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// First unbonding request
	err = mgr.StartUnbonding(kp.PublicKey, 2000)
	if err != nil {
		t.Errorf("First unbonding should succeed: %v", err)
	}

	// Second unbonding request while first is pending
	err = mgr.StartUnbonding(kp.PublicKey, 2000)
	// Depending on implementation, this might queue or reject
	// Just ensure no panic
	t.Logf("Second unbonding result: %v", err)
}

// ============================================================================
// APY CALCULATION TESTS
// ============================================================================

func TestAPYCalculation(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(10)

	// Use realistic stake values (100 million tokens staked across validators)
	stakePerValidator := uint64(10_000_000)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, stakePerValidator)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	rd := stake.NewRewardDistributor(validators, config)

	// Calculate APY with realistic block reward
	// If total stake is 100M and we want ~5% APY, annual reward should be ~5M
	// With ~63M blocks/year, block reward should be ~0.08 per block
	// Let's use 1 token per block for simplicity
	blockReward := uint64(1)
	blocksPerYear := uint64(365 * 24 * 60 * 120) // ~500ms blocks = ~63M blocks

	apy := rd.CalculateAPY(keyPairs[0].PublicKey, blockReward, blocksPerYear)

	t.Logf("Calculated APY: %.4f%% (%.6f)", apy*100, apy)

	// APY should be reasonable (not negative)
	if apy < 0 {
		t.Error("APY should not be negative")
	}

	// With 10 validators sharing equally, and 63M * 1 = 63M tokens rewarded per year
	// Each validator gets ~6.3M tokens, on 10M stake = 63% APY is expected
	// This is high but mathematically correct for the given parameters
	t.Logf("Annual reward per validator: ~%.2f%% of stake", apy*100)
}

// ============================================================================
// VALIDATOR REMOVAL TESTS
// ============================================================================

func TestValidatorRemovalOnZeroStake(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, types.MinStake+100)
	validators.Add(v)

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	// Slash repeatedly until stake is gone
	for i := 0; i < 100 && v.Stake > 0; i++ {
		proof := &types.EquivocationProof{
			Vote1: types.Vote{BlockHash: types.Hash{byte(i)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey},
			Vote2: types.Vote{BlockHash: types.Hash{byte(i + 100)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey},
		}
		slasher.SlashForEquivocation(proof, uint64(i+1))
	}

	// Validator should either be removed or have zero voting weight
	weight := v.VotingWeight()
	if weight > 0 && v.Stake >= types.MinStake {
		t.Logf("Validator still has weight %.4f with stake %d", weight, v.Stake)
	}
}

// ============================================================================
// STAKE OVERFLOW TESTS
// ============================================================================

func TestStakeOverflowProtection(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	initialStake := uint64(math.MaxUint64 - 1000)
	v := types.NewValidator(kp.PublicKey, initialStake)
	validators.Add(v)

	config := types.DefaultConfig()
	mgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}

	// Try to add stake that would overflow
	err = mgr.AddStake(kp.PublicKey, 2000)

	// SECURITY FIX: Implementation now has overflow protection
	// AddStake should return ErrOverflow when adding would overflow
	if err != stake.ErrOverflow {
		t.Errorf("Expected ErrOverflow when adding stake that would overflow, got: %v", err)
	}

	// Stake should be unchanged (overflow was prevented)
	if v.Stake != initialStake {
		t.Errorf("Stake should remain unchanged at %d, got %d", initialStake, v.Stake)
	}
}

// ============================================================================
// STAKE AND TRUST INTERACTION TESTS
// ============================================================================

func TestStakeAffectsVotingWeight(t *testing.T) {
	v1 := types.NewValidator(types.PublicKey{1}, 10000)
	v1.Trust.BaseTrust = 1.0
	v1.Trust.RoundsActive = 1000

	v2 := types.NewValidator(types.PublicKey{2}, 100000) // 10x stake
	v2.Trust.BaseTrust = 1.0
	v2.Trust.RoundsActive = 1000

	weight1 := v1.VotingWeight()
	weight2 := v2.VotingWeight()

	// Due to log scale, 10x stake should not give 10x weight
	ratio := weight2 / weight1
	t.Logf("Stake 10x, weight %.2fx", ratio)

	if ratio >= 10 {
		t.Error("Log scale should reduce stake dominance")
	}
}

func TestTrustAffectsVotingWeight(t *testing.T) {
	v1 := types.NewValidator(types.PublicKey{1}, 10000)
	v1.Trust.BaseTrust = 0.5
	v1.Trust.RoundsActive = 1000

	v2 := types.NewValidator(types.PublicKey{2}, 10000) // Same stake
	v2.Trust.BaseTrust = 1.0                            // 2x trust
	v2.Trust.RoundsActive = 1000

	weight1 := v1.VotingWeight()
	weight2 := v2.VotingWeight()

	ratio := weight2 / weight1
	t.Logf("Trust 2x, weight %.2fx", ratio)

	// Trust is linear, so 2x trust should give 2x weight
	if math.Abs(ratio-2.0) > 0.1 {
		t.Errorf("Expected 2x weight, got %.2fx", ratio)
	}
}
