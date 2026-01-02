package tests

import (
	"math"
	"testing"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// VALIDATOR COUNT BOUNDARY TESTS
// ============================================================================

func TestMinimumValidators(t *testing.T) {
	// Minimum is 4 validators for BFT (3f+1 where f=1)
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	if validators.Size() != 4 {
		t.Errorf("Expected 4 validators, got %d", validators.Size())
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	// With 4 validators, quorum should require 3 (67%)
	info := qc.GetQuorumInfo()
	t.Logf("4 validators: quorum=%.4f, total=%.4f", info.Quorum, info.TotalWeight)

	// Create votes from 3 validators
	block := types.NewBlock(0, 0, types.EmptyHash, keyPairs[0].PublicKey)
	votes := make([]*types.Vote, 3)
	for i := 0; i < 3; i++ {
		votes[i] = types.NewVote(block.Hash(), 0, 0, keyPairs[i].PublicKey)
		votes[i].Signature = crypto.SignVote(keyPairs[i].SecretKey, votes[i])
	}

	weight := qc.CalculateVoteWeight(votes)
	if !qc.HasQuorum(weight) {
		t.Error("3 out of 4 validators should have quorum")
	}

	// 2 validators should NOT have quorum
	twoVotes := votes[:2]
	twoWeight := qc.CalculateVoteWeight(twoVotes)
	if qc.HasQuorum(twoWeight) {
		t.Error("2 out of 4 validators should NOT have quorum")
	}
}

func TestMaximumValidators(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := types.MaxValidators // 1000
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	if validators.Size() != numValidators {
		t.Errorf("Expected %d validators, got %d", numValidators, validators.Size())
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	info := qc.GetQuorumInfo()
	t.Logf("1000 validators: total weight=%.4f, quorum=%.4f", info.TotalWeight, info.Quorum)

	// With 1000 validators, should need ~670 for quorum
	needed := int(math.Ceil(float64(numValidators) * 0.67))
	t.Logf("Estimated validators needed for quorum: %d", needed)
}

func TestSingleValidator(t *testing.T) {
	// Edge case: single validator (not BFT safe, but should work)
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	// Single validator should have quorum with just their vote
	block := types.NewBlock(0, 0, types.EmptyHash, kp.PublicKey)
	vote := types.NewVote(block.Hash(), 0, 0, kp.PublicKey)
	vote.Signature = crypto.SignVote(kp.SecretKey, vote)

	weight := qc.CalculateVoteWeight([]*types.Vote{vote})
	if !qc.HasQuorum(weight) {
		t.Error("Single validator should have quorum with their own vote")
	}
}

// ============================================================================
// TRUST BOUNDARY TESTS
// ============================================================================

func TestZeroTrust(t *testing.T) {
	v := types.NewValidator(types.PublicKey{}, 10000)
	v.Trust.BaseTrust = 0.0
	v.Trust.RoundsActive = 1000

	weight := v.VotingWeight()
	if weight != 0 {
		t.Errorf("Zero trust should give zero voting weight, got %.4f", weight)
	}

	effectiveTrust := v.EffectiveTrust()
	if effectiveTrust != 0 {
		t.Errorf("Effective trust should be 0, got %.4f", effectiveTrust)
	}
}

func TestMaxTrust(t *testing.T) {
	v := types.NewValidator(types.PublicKey{}, 10000)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 10000

	effectiveTrust := v.EffectiveTrust()
	if effectiveTrust != 1.0 {
		t.Errorf("Max trust should be 1.0, got %.4f", effectiveTrust)
	}

	// Weight should be positive
	weight := v.VotingWeight()
	if weight <= 0 {
		t.Errorf("Max trust should give positive weight, got %.4f", weight)
	}
}

func TestNegativeTrustClamped(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.05 // Very low trust
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply many penalties
	for i := 0; i < 100; i++ {
		mgr.PenaltyMiss(kp.PublicKey)
	}

	// Trust should be clamped to 0, not negative
	if v.Trust.BaseTrust < 0 {
		t.Errorf("Trust should not go negative, got %.4f", v.Trust.BaseTrust)
	}
}

func TestTrustAboveOneClamped(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.99
	v.Trust.RoundsActive = 10000 // Max ceiling
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply many rewards
	for i := 0; i < 100; i++ {
		mgr.RewardVote(kp.PublicKey, uint64(i))
	}

	// Trust should be clamped to 1.0
	if v.Trust.BaseTrust > 1.0 {
		t.Errorf("Trust should not exceed 1.0, got %.4f", v.Trust.BaseTrust)
	}

	if v.EffectiveTrust() > 1.0 {
		t.Errorf("Effective trust should not exceed 1.0, got %.4f", v.EffectiveTrust())
	}
}

// ============================================================================
// STAKE BOUNDARY TESTS
// ============================================================================

func TestMinimumStake(t *testing.T) {
	v := types.NewValidator(types.PublicKey{}, types.MinStake)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000

	weight := v.VotingWeight()
	if weight <= 0 {
		t.Errorf("Minimum stake should give positive weight, got %.4f", weight)
	}

	// log2(1000/1000 + 1) * 1.0 = log2(2) * 1.0 = 1.0
	expected := 1.0
	if math.Abs(weight-expected) > 0.001 {
		t.Errorf("Expected weight %.4f, got %.4f", expected, weight)
	}
}

func TestBelowMinimumStake(t *testing.T) {
	v := types.NewValidator(types.PublicKey{}, types.MinStake-1)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000

	weight := v.VotingWeight()
	if weight != 0 {
		t.Errorf("Below minimum stake should give zero weight, got %.4f", weight)
	}
}

func TestZeroStake(t *testing.T) {
	v := types.NewValidator(types.PublicKey{}, 0)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000

	weight := v.VotingWeight()
	if weight != 0 {
		t.Errorf("Zero stake should give zero weight, got %.4f", weight)
	}
}

func TestVeryLargeStake(t *testing.T) {
	// Test with very large stake (1 billion)
	v := types.NewValidator(types.PublicKey{}, 1_000_000_000)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000

	weight := v.VotingWeight()

	// Weight should be reasonable due to log scale
	// log2(1B/1000 + 1) = log2(1000001) ≈ 19.9
	maxExpected := 25.0
	if weight > maxExpected {
		t.Errorf("Large stake weight should be bounded by log scale, got %.4f", weight)
	}

	// Compare to minimum stake
	minV := types.NewValidator(types.PublicKey{}, types.MinStake)
	minV.Trust.BaseTrust = 1.0
	minV.Trust.RoundsActive = 1000
	minWeight := minV.VotingWeight()

	ratio := weight / minWeight
	t.Logf("1B stake / min stake weight ratio: %.2f", ratio)

	// Whale should have at most 20x the weight of min stake
	if ratio > 25 {
		t.Errorf("Whale dominance too high, ratio: %.2f", ratio)
	}
}

// ============================================================================
// QUORUM BOUNDARY TESTS
// ============================================================================

func TestExactlyAtQuorum(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(100)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	quorum := qc.GetQuorum()
	t.Logf("Quorum threshold: %.4f", quorum)

	// SECURITY FIX: HasQuorum now requires weight >= quorum + epsilon (1e-9)
	// to prevent floating point precision from allowing sub-quorum weights.
	// This is a deliberate safety-over-liveness tradeoff for BFT.

	// Exactly at quorum now fails (by design - safety margin)
	if qc.HasQuorum(quorum) {
		t.Error("Exactly at quorum should now fail due to safety epsilon")
	}

	// At quorum + safety margin should pass
	if !qc.HasQuorum(quorum + 1e-8) {
		t.Error("At quorum + safety margin should pass")
	}

	// Just below quorum should fail
	if qc.HasQuorum(quorum - 0.001) {
		t.Error("Just below quorum should fail")
	}

	// Just above quorum should pass
	if !qc.HasQuorum(quorum + 0.001) {
		t.Error("Just above quorum should pass")
	}
}

func TestQuorumWithAllOffline(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = false // All offline
		validators.Add(v)
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	info := qc.GetQuorumInfo()
	t.Logf("Online weight: %.4f, Safety floor: %.4f", info.OnlineWeight, info.SafetyFloor)

	// Should use safety floor since no one is online
	// But total weight still exists
	if info.Quorum <= 0 {
		t.Error("Quorum should still be positive based on total stake")
	}
}

func TestQuorumWithPartialOnline(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(10)

	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = i < 5 // Only first 5 online
		validators.Add(v)
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	info := qc.GetQuorumInfo()
	t.Logf("Online: %.4f, Total: %.4f, Adaptive: %.4f, Floor: %.4f",
		info.OnlineWeight, info.TotalWeight, info.AdaptiveQuorum, info.SafetyFloor)

	// Quorum should be max of adaptive and safety floor
	expectedQuorum := math.Max(
		config.AdaptiveQuorum*info.OnlineWeight,
		config.SafetyFloor*info.TotalWeight,
	)

	if math.Abs(info.Quorum-expectedQuorum) > 0.001 {
		t.Errorf("Expected quorum %.4f, got %.4f", expectedQuorum, info.Quorum)
	}
}

// ============================================================================
// ROUND AND HEIGHT BOUNDARY TESTS
// ============================================================================

func TestHeightZero(t *testing.T) {
	block := types.NewBlock(0, 0, types.EmptyHash, types.PublicKey{})

	if block.Height != 0 {
		t.Errorf("Height should be 0, got %d", block.Height)
	}

	if !block.IsGenesis() {
		t.Error("Block at height 0 with empty parent should be genesis")
	}
}

func TestRoundZero(t *testing.T) {
	block := types.NewBlock(10, 0, types.Hash{1}, types.PublicKey{})

	if block.Round != 0 {
		t.Errorf("Round should be 0, got %d", block.Round)
	}
}

func TestMaxRound(t *testing.T) {
	maxRound := uint32(0xFFFFFFFF)
	block := types.NewBlock(10, maxRound, types.Hash{1}, types.PublicKey{})

	if block.Round != maxRound {
		t.Errorf("Round should be %d, got %d", maxRound, block.Round)
	}
}

func TestMaxHeight(t *testing.T) {
	maxHeight := uint64(0xFFFFFFFFFFFFFFFF)
	block := types.NewBlock(maxHeight, 0, types.Hash{1}, types.PublicKey{})

	if block.Height != maxHeight {
		t.Errorf("Height should be %d, got %d", maxHeight, block.Height)
	}
}

func TestRoundIncrement(t *testing.T) {
	state := consensus.NewState()

	// Initial round should be 0
	if state.GetRound() != 0 {
		t.Errorf("Initial round should be 0, got %d", state.GetRound())
	}

	// Increment round
	state.NewRound(1)
	if state.GetRound() != 1 {
		t.Errorf("Round should be 1, got %d", state.GetRound())
	}

	// Jump to high round
	state.NewRound(100)
	if state.GetRound() != 100 {
		t.Errorf("Round should be 100, got %d", state.GetRound())
	}
}

// ============================================================================
// COOLDOWN BOUNDARY TESTS
// ============================================================================

func TestLeaderCooldownBoundary(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(10)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	ls := consensus.NewLeaderSelector(validators, config)

	// Select and record a leader at round 0
	leader := ls.SelectLeader(0, 0, types.EmptyHash)
	ls.RecordLeader(leader.PublicKey, 0)

	// Check rounds 1 through cooldown-1 (should be ineligible)
	for round := uint32(1); round < config.LeaderCooldown; round++ {
		l := ls.SelectLeader(0, round, types.EmptyHash)
		if l.PublicKey == leader.PublicKey {
			t.Errorf("Leader should be on cooldown at round %d", round)
		}
	}

	// At exactly cooldown, still on cooldown
	l := ls.SelectLeader(0, config.LeaderCooldown, types.EmptyHash)
	if l.PublicKey == leader.PublicKey {
		t.Errorf("Leader should still be on cooldown at round %d", config.LeaderCooldown)
	}

	// After cooldown, might be eligible again
	// (depends on VRF, so we just check it doesn't panic)
	_ = ls.SelectLeader(0, config.LeaderCooldown+1, types.EmptyHash)
}

// ============================================================================
// VOUCHING BOUNDARY TESTS
// ============================================================================

func TestMaxVouchBonus(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(10)

	// Create vouchers with high trust
	for i := 0; i < 5; i++ {
		v := types.NewValidator(keyPairs[i].PublicKey, 10000)
		v.Trust.BaseTrust = 0.9
		v.Trust.RoundsActive = 2000
		validators.Add(v)
	}

	// Create vouchee
	voucheeKP := keyPairs[5]
	vouchee := types.NewValidator(voucheeKP.PublicKey, 10000)
	vouchee.Trust.BaseTrust = 0.1
	vouchee.Trust.RoundsActive = 0
	validators.Add(vouchee)

	vm := trust.NewVouchingManager(validators)

	// Apply max vouches
	for i := 0; i < 5; i++ {
		err := vm.Vouch(keyPairs[i].PublicKey, voucheeKP.PublicKey, 0)
		if err != nil && i < 3 {
			t.Errorf("Vouch %d should succeed: %v", i, err)
		}
	}

	// Check ceiling
	ceiling := vouchee.TrustCeiling()
	maxBonus := types.CeilingRound100 + types.MaxVouchBonus

	if ceiling > maxBonus {
		t.Errorf("Ceiling %.2f should not exceed max %.2f", ceiling, maxBonus)
	}

	t.Logf("Final ceiling with max vouches: %.2f", ceiling)
}

func TestVouchFromLowTrustValidator(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(2)

	// Low trust validator
	v1 := types.NewValidator(keyPairs[0].PublicKey, 10000)
	v1.Trust.BaseTrust = 0.3 // Below VoucherMinTrust (0.70)
	v1.Trust.RoundsActive = 1000
	validators.Add(v1)

	// New validator
	v2 := types.NewValidator(keyPairs[1].PublicKey, 10000)
	v2.Trust.BaseTrust = 0.1
	v2.Trust.RoundsActive = 0
	validators.Add(v2)

	vm := trust.NewVouchingManager(validators)

	err := vm.Vouch(keyPairs[0].PublicKey, keyPairs[1].PublicKey, 0)
	if err != trust.ErrInvalidVoucher {
		t.Errorf("Expected ErrInvalidVoucher, got %v", err)
	}
}

// ============================================================================
// EMPTY AND NIL TESTS
// ============================================================================

func TestEmptyValidatorSet(t *testing.T) {
	validators := types.NewValidatorSet()

	if validators.Size() != 0 {
		t.Errorf("Empty validator set should have size 0, got %d", validators.Size())
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	// Should not panic
	info := qc.GetQuorumInfo()
	if info.TotalWeight != 0 {
		t.Errorf("Empty set should have 0 total weight, got %.4f", info.TotalWeight)
	}
}

func TestEmptyVoteSlice(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	weight := qc.CalculateVoteWeight([]*types.Vote{})
	if weight != 0 {
		t.Errorf("Empty votes should have 0 weight, got %.4f", weight)
	}

	if qc.HasQuorum(weight) {
		t.Error("Empty votes should not have quorum")
	}
}

func TestNilBlockHash(t *testing.T) {
	var emptyHash types.Hash
	block := types.NewBlock(0, 0, emptyHash, types.PublicKey{})

	// Should still compute a valid hash
	hash := block.Hash()
	if hash == types.EmptyHash {
		// This is acceptable for genesis
		t.Log("Block hash is empty (acceptable for genesis)")
	}
}

// ============================================================================
// HASH COLLISION TESTS
// ============================================================================

func TestDifferentBlocksDifferentHashes(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block1 := types.NewBlock(0, 0, types.EmptyHash, kp.PublicKey)
	block1.TxRoot = types.Hash{1}

	block2 := types.NewBlock(0, 0, types.EmptyHash, kp.PublicKey)
	block2.TxRoot = types.Hash{2}

	hash1 := block1.Hash()
	hash2 := block2.Hash()

	if hash1 == hash2 {
		t.Error("Different blocks should have different hashes")
	}
}

func TestSameBlockSameHash(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block1 := types.NewBlock(0, 0, types.EmptyHash, kp.PublicKey)
	block1.Timestamp = 12345
	block1.TxRoot = types.Hash{1, 2, 3}

	block2 := types.NewBlock(0, 0, types.EmptyHash, kp.PublicKey)
	block2.Timestamp = 12345
	block2.TxRoot = types.Hash{1, 2, 3}

	hash1 := block1.Hash()
	hash2 := block2.Hash()

	if hash1 != hash2 {
		t.Error("Identical blocks should have same hash")
	}
}

func TestVoteHashDeterminism(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	vote1 := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    10,
		Round:     5,
		Voter:     kp.PublicKey,
	}

	vote2 := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    10,
		Round:     5,
		Voter:     kp.PublicKey,
	}

	hash1 := vote1.Hash()
	hash2 := vote2.Hash()

	if hash1 != hash2 {
		t.Error("Identical votes should have same hash")
	}
}
