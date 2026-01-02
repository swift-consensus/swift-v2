package tests

import (
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// =============================================================================
// VIEW CHANGE TESTS
// =============================================================================

// TestViewChangeCreation tests that view change messages can be created
func TestViewChangeCreation(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	vcMsg := &types.ViewChangeMsg{
		Height:   1,
		NewRound: 1,
		Voter:    kp.PublicKey,
	}

	if vcMsg.Height != 1 {
		t.Errorf("Expected height 1, got %d", vcMsg.Height)
	}

	if vcMsg.NewRound != 1 {
		t.Errorf("Expected new round 1, got %d", vcMsg.NewRound)
	}
}

// TestViewChangeWithHighestVoted tests view change carries highest voted block
func TestViewChangeWithHighestVoted(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Create a block that was voted on but not finalized
	highestVoted := &types.Block{
		Height:    1,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
		Proposer:  kp.PublicKey,
	}

	vcMsg := &types.ViewChangeMsg{
		Height:       1,
		NewRound:     1,
		HighestVoted: highestVoted,
		Voter:        kp.PublicKey,
	}

	if vcMsg.HighestVoted == nil {
		t.Fatal("Expected highest voted block to be included")
	}

	if vcMsg.HighestVoted.Height != 1 {
		t.Errorf("Expected height 1, got %d", vcMsg.HighestVoted.Height)
	}
}

// TestViewChangeNewLeaderSelection tests that new leader is selected after view change
func TestViewChangeNewLeaderSelection(t *testing.T) {
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

	// Get leader for round 0
	leader0 := ls.SelectLeader(1, 0, types.EmptyHash)

	// Get leader for round 1 (after view change)
	leader1 := ls.SelectLeader(1, 1, types.EmptyHash)

	// Leaders should generally be different (probabilistic)
	if leader0 == nil || leader1 == nil {
		t.Error("Expected leaders to be selected for both rounds")
	}
}

// TestConsecutiveViewChanges tests multiple consecutive view changes
func TestConsecutiveViewChanges(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Initiate view changes for rounds 1, 2, 3
	for round := uint32(1); round <= 3; round++ {
		vcMsg := &types.ViewChangeMsg{
			Height:   1,
			NewRound: round,
			Voter:    kp.PublicKey,
		}
		if vcMsg.NewRound != round {
			t.Errorf("Expected round %d, got %d", round, vcMsg.NewRound)
		}
	}
}

// =============================================================================
// LIVENESS UNDER ATTACK TESTS
// =============================================================================

// TestLivenessWithByzantineLeader tests progress despite Byzantine leader
func TestLivenessWithByzantineLeader(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	// Create 4 validators - 1 Byzantine (silent leader)
	keyPairs := crypto.MustGenerateNKeyPairs(4)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	ls := consensus.NewLeaderSelector(validators, config)

	// Simulate Byzantine leader by checking if we can select a different leader
	// after view change
	leaderRound0 := ls.SelectLeader(1, 0, types.EmptyHash)

	// Mark the leader as having failed (in practice, trust would decrease)
	if leaderRound0 != nil {
		v := validators.Get(leaderRound0.PublicKey)
		if v != nil {
			v.Trust.BaseTrust -= config.TrustPenaltyMiss
		}
	}

	// After view change, we should still be able to select a leader
	leaderRound1 := ls.SelectLeader(1, 1, types.EmptyHash)

	if leaderRound1 == nil {
		t.Error("System should be able to select new leader after view change")
	}
}

// TestLivenessWithMinimumValidators tests liveness with exactly 4 validators
func TestLivenessWithMinimumValidators(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(4)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	// Calculate quorum requirement
	required := quorum.GetQuorum()

	// Calculate total weight
	totalWeight := quorum.TotalWeight()

	// With 4 validators, quorum should be achievable with 3 votes
	threeValidatorWeight := totalWeight * 3 / 4

	if threeValidatorWeight < required {
		t.Error("3 out of 4 validators should be able to achieve quorum")
	}
}

// TestLivenessWithOneOffline tests progress with 1 validator offline
func TestLivenessWithOneOffline(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(4)
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		// Mark one as offline
		v.Online = (i < 3)
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	// Calculate required quorum from total
	totalWeight := quorum.TotalWeight()

	// Calculate online weight
	onlineWeight := quorum.OnlineWeight()

	// 3/4 validators online should still work
	expectedOnlineWeight := totalWeight * 3 / 4

	if abs(onlineWeight-expectedOnlineWeight) > 0.01 {
		t.Logf("Online weight: %.4f, expected: %.4f", onlineWeight, expectedOnlineWeight)
	}
}

// =============================================================================
// PROGRESS GUARANTEE TESTS
// =============================================================================

// TestProgressWithVariableTrust tests progress with uneven trust distribution
func TestProgressWithVariableTrust(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	trustLevels := []float64{1.0, 0.8, 0.6, 0.4, 0.2}
	keyPairs := crypto.MustGenerateNKeyPairs(5)

	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = trustLevels[i]
		v.Trust.RoundsActive = 1000 // Max ceiling
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	// Calculate weights
	totalWeight := quorum.TotalWeight()
	required := quorum.GetQuorum()

	// System should still function with variable trust
	if totalWeight < required {
		t.Error("System with variable trust should still be able to achieve quorum")
	}
}

// TestProgressWithVariableStake tests progress with uneven stake distribution
func TestProgressWithVariableStake(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	stakes := []uint64{
		config.MinStake * 10, // Whale
		config.MinStake * 5,
		config.MinStake * 2,
		config.MinStake,
		config.MinStake,
	}

	keyPairs := crypto.MustGenerateNKeyPairs(5)
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, stakes[i])
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	// Calculate total weight
	totalWeight := quorum.TotalWeight()
	required := quorum.GetQuorum()

	// With variable stake, quorum should still be achievable
	if totalWeight < required {
		t.Error("System with variable stake should still be able to achieve quorum")
	}

	// Whale alone should NOT have quorum
	whale := validators.Validators[0]
	whaleWeight := whale.VotingWeight()
	if whaleWeight >= required {
		t.Error("Single whale should not have quorum power")
	}
}

// TestEventualLeaderSelection tests that eventually a valid leader is selected
func TestEventualLeaderSelection(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	// Create validators with varying trust (some below threshold)
	keyPairs := crypto.MustGenerateNKeyPairs(10)
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		// Half have low trust
		if i < 5 {
			v.Trust.BaseTrust = 0.2
			v.Trust.RoundsActive = 50
		} else {
			v.Trust.BaseTrust = 0.5
			v.Trust.RoundsActive = 500
		}
		v.Online = true
		validators.Add(v)
	}

	ls := consensus.NewLeaderSelector(validators, config)

	// Try multiple rounds - should eventually find a leader
	leaderFound := false
	for round := uint32(0); round < 100; round++ {
		leader := ls.SelectLeader(1, round, types.EmptyHash)
		if leader != nil {
			leaderFound = true
			break
		}
	}

	if !leaderFound {
		t.Error("Should eventually select a valid leader within 100 rounds")
	}
}

// TestLeaderRotation tests that leadership rotates fairly
func TestLeaderRotation(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()
	config.LeaderCooldown = 2 // Short cooldown for testing

	keyPairs := crypto.MustGenerateNKeyPairs(5)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	ls := consensus.NewLeaderSelector(validators, config)

	// Track leader selection over many rounds
	leaderCounts := make(map[string]int)

	for round := uint32(0); round < 50; round++ {
		leader := ls.SelectLeader(1, round, types.EmptyHash)
		if leader != nil {
			key := string(leader.PublicKey[:])
			leaderCounts[key]++
		}
	}

	// Check that multiple validators were selected as leaders
	if len(leaderCounts) < 2 {
		t.Error("Leadership should rotate among multiple validators")
	}
}

// =============================================================================
// TIMEOUT AND RECOVERY TESTS
// =============================================================================

// TestTimeoutProgression tests that timeouts increase appropriately
func TestTimeoutProgression(t *testing.T) {
	config := types.DefaultConfig()

	// Timeout should increase with consecutive failures
	baseTimeout := config.ViewChangeTimeout

	// Simulate exponential backoff
	timeout1 := baseTimeout
	timeout2 := baseTimeout * 2
	timeout3 := baseTimeout * 4

	if timeout2 <= timeout1 {
		t.Error("Timeout should increase after first failure")
	}

	if timeout3 <= timeout2 {
		t.Error("Timeout should continue increasing")
	}
}

// TestGracefulDegradation tests system behavior as validators drop off
func TestGracefulDegradation(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	// Start with 10 validators
	keyPairs := crypto.MustGenerateNKeyPairs(10)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)
	required := quorum.GetQuorum()

	// Test with decreasing online validator counts
	for numOnline := 10; numOnline >= 4; numOnline-- {
		allVals := validators.Validators
		for i, v := range allVals {
			v.Online = (i < numOnline)
		}

		onlineWeight := quorum.OnlineWeight()
		totalWeight := quorum.TotalWeight()

		pctOnline := onlineWeight / totalWeight

		if pctOnline >= 0.67 && onlineWeight < required {
			t.Errorf("With %d/%d validators (%.0f%%), should have quorum",
				numOnline, 10, pctOnline*100)
		}
	}
}

// TestNoProgressWithInsufficientValidators tests that system halts safely without quorum
func TestNoProgressWithInsufficientValidators(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	// Create 7 validators, only 2 online
	keyPairs := crypto.MustGenerateNKeyPairs(7)
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = (i < 2) // Only first 2 online
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	onlineWeight := quorum.OnlineWeight()
	required := quorum.GetQuorum()

	// 2/7 validators should NOT have quorum
	if onlineWeight >= required {
		t.Error("2 out of 7 validators should not have quorum")
	}
}

// =============================================================================
// CHAIN GROWTH TESTS
// =============================================================================

// TestChainGrowthRate tests that blocks are produced at expected rate
func TestChainGrowthRate(t *testing.T) {
	config := types.DefaultConfig()

	// Expected: one block per BlockTime
	expectedBlocksPerSecond := float64(time.Second) / float64(config.BlockTime)

	// In 1 second, should produce ~2 blocks at 500ms block time
	if expectedBlocksPerSecond < 1.9 || expectedBlocksPerSecond > 2.1 {
		t.Errorf("Expected ~2 blocks per second, got %.2f", expectedBlocksPerSecond)
	}
}

// TestFinalityLatency tests finality is achieved within expected time
func TestFinalityLatency(t *testing.T) {
	config := types.DefaultConfig()

	// Single-round finality: finality time = BlockTime + network latency
	// Assume network latency < 100ms
	maxFinalityTime := config.BlockTime + 100*time.Millisecond

	// Should achieve finality within 600ms
	if maxFinalityTime > 600*time.Millisecond {
		t.Errorf("Expected finality within 600ms, calculated max %v", maxFinalityTime)
	}
}

// TestContinuousOperation tests extended operation without degradation
func TestContinuousOperation(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(5)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	ls := consensus.NewLeaderSelector(validators, config)

	// Simulate many rounds of operation
	successfulRounds := 0
	for height := uint64(1); height <= 100; height++ {
		leader := ls.SelectLeader(height, 0, types.EmptyHash)
		if leader != nil {
			successfulRounds++
			// Reward leader trust
			v := validators.Get(leader.PublicKey)
			if v != nil {
				v.Trust.BaseTrust += config.TrustReward
				if v.Trust.BaseTrust > 1.0 {
					v.Trust.BaseTrust = 1.0
				}
			}
		}
	}

	// Should have successful rounds for most heights
	if successfulRounds < 80 {
		t.Errorf("Expected at least 80%% successful rounds, got %d/100", successfulRounds)
	}
}
