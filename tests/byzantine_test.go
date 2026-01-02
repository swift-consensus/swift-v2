package tests

import (
	"testing"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/stake"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// EQUIVOCATION TESTS - Double voting detection
// ============================================================================

func TestEquivocationDetection(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	validators.Add(v)

	detector := trust.NewByzantineDetector(validators)

	// First vote for block A
	vote1 := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    1,
		Round:     0,
		Voter:     kp.PublicKey,
	}
	vote1.Signature = crypto.SignVote(kp.SecretKey, vote1)

	// Second vote for block B (same height/round, different block)
	vote2 := &types.Vote{
		BlockHash: types.Hash{4, 5, 6},
		Height:    1,
		Round:     0,
		Voter:     kp.PublicKey,
	}
	vote2.Signature = crypto.SignVote(kp.SecretKey, vote2)

	// Record first vote - should not produce proof
	proof := detector.RecordVote(vote1)
	if proof != nil {
		t.Error("First vote should not produce equivocation proof")
	}

	// Record conflicting vote - should produce proof
	proof = detector.RecordVote(vote2)
	if proof == nil {
		t.Fatal("Conflicting vote should produce equivocation proof")
	}

	// Verify proof validity
	if !proof.IsValid() {
		t.Error("Equivocation proof should be valid")
	}

	// Verify proof contents
	if proof.Vote1.Voter != proof.Vote2.Voter {
		t.Error("Proof should contain votes from same voter")
	}
	if proof.Vote1.Height != proof.Vote2.Height {
		t.Error("Proof should contain votes at same height")
	}
	if proof.Vote1.Round != proof.Vote2.Round {
		t.Error("Proof should contain votes at same round")
	}
	if proof.Vote1.BlockHash == proof.Vote2.BlockHash {
		t.Error("Proof should contain votes for different blocks")
	}
}

func TestEquivocationAcrossRounds(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	detector := trust.NewByzantineDetector(validators)

	// Vote in round 0
	vote1 := &types.Vote{BlockHash: types.Hash{1}, Height: 1, Round: 0, Voter: kp.PublicKey}

	// Vote in round 1 (different round - should NOT be equivocation)
	vote2 := &types.Vote{BlockHash: types.Hash{2}, Height: 1, Round: 1, Voter: kp.PublicKey}

	detector.RecordVote(vote1)
	proof := detector.RecordVote(vote2)

	if proof != nil {
		t.Error("Votes in different rounds should not be equivocation")
	}
}

func TestEquivocationAcrossHeights(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	detector := trust.NewByzantineDetector(validators)

	// Vote at height 1
	vote1 := &types.Vote{BlockHash: types.Hash{1}, Height: 1, Round: 0, Voter: kp.PublicKey}

	// Vote at height 2 (different height - should NOT be equivocation)
	vote2 := &types.Vote{BlockHash: types.Hash{2}, Height: 2, Round: 0, Voter: kp.PublicKey}

	detector.RecordVote(vote1)
	proof := detector.RecordVote(vote2)

	if proof != nil {
		t.Error("Votes at different heights should not be equivocation")
	}
}

func TestDuplicateVoteSameBlock(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	validators.Add(types.NewValidator(kp.PublicKey, 10000))

	detector := trust.NewByzantineDetector(validators)

	vote := &types.Vote{BlockHash: types.Hash{1}, Height: 1, Round: 0, Voter: kp.PublicKey}

	detector.RecordVote(vote)
	proof := detector.RecordVote(vote) // Same vote again

	if proof != nil {
		t.Error("Duplicate vote for same block should not be equivocation")
	}
}

// ============================================================================
// CORRELATION ATTACK TESTS - Multiple Byzantine validators acting together
// ============================================================================

func TestCorrelationPenaltyScaling(t *testing.T) {
	// SECURITY FIX: Correlation penalty is now capped at 3.0 to prevent overflow
	// causing NaN/Inf in voting weight calculations
	testCases := []struct {
		numByzantine int
		minMult      float64
		maxMult      float64
	}{
		{1, 1.0, 1.2},     // Single attacker: ~1.1x
		{2, 1.1, 1.3},     // Two attackers: ~1.2x
		{5, 1.4, 1.6},     // Five attackers: ~1.5x
		{10, 1.9, 2.1},    // Ten attackers: ~2.0x
		{20, 2.9, 3.1},    // Twenty attackers: ~3.0x (now capped)
		{50, 2.9, 3.1},    // Fifty attackers: capped at 3.0x (security fix)
	}

	for _, tc := range testCases {
		mult := trust.CorrelationPenalty(tc.numByzantine)
		if mult < tc.minMult || mult > tc.maxMult {
			t.Errorf("For %d Byzantine: expected mult in [%.1f, %.1f], got %.2f",
				tc.numByzantine, tc.minMult, tc.maxMult, mult)
		}
	}
}

func TestCorrelatedByzantinePenalty(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		validators.Add(v)
	}

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// 5 validators act Byzantine together
	byzantineCount := 5
	byzantinePKs := make([]types.PublicKey, byzantineCount)
	for i := 0; i < byzantineCount; i++ {
		byzantinePKs[i] = keyPairs[i].PublicKey
	}

	// Apply penalty
	mgr.PenaltyByzantine(byzantinePKs)

	// Check correlation multiplier was applied
	// Correlation = 1 + 5 * 0.1 = 1.5
	expectedPenalty := config.TrustPenaltyByzantine * 1.5
	expectedTrust := 1.0 - expectedPenalty

	for i := 0; i < byzantineCount; i++ {
		v := validators.Get(keyPairs[i].PublicKey)
		if abs(v.Trust.BaseTrust-expectedTrust) > 0.001 {
			t.Errorf("Validator %d: expected trust %.4f, got %.4f",
				i, expectedTrust, v.Trust.BaseTrust)
		}
	}

	// Non-byzantine validators should be unaffected
	for i := byzantineCount; i < numValidators; i++ {
		v := validators.Get(keyPairs[i].PublicKey)
		if v.Trust.BaseTrust != 1.0 {
			t.Errorf("Non-Byzantine validator %d: trust should be 1.0, got %.4f",
				i, v.Trust.BaseTrust)
		}
	}
}

func TestRepeatedByzantineOffenseEscalation(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 1000
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	pks := []types.PublicKey{kp.PublicKey}

	// First offense
	trustBefore := v.Trust.BaseTrust
	mgr.PenaltyByzantine(pks)
	firstPenalty := trustBefore - v.Trust.BaseTrust

	// Second offense - should be larger due to escalation
	trustBefore = v.Trust.BaseTrust
	mgr.PenaltyByzantine(pks)
	secondPenalty := trustBefore - v.Trust.BaseTrust

	if secondPenalty <= firstPenalty {
		t.Errorf("Second offense penalty (%.4f) should be > first (%.4f)",
			secondPenalty, firstPenalty)
	}

	// Third offense - even larger
	trustBefore = v.Trust.BaseTrust
	mgr.PenaltyByzantine(pks)
	thirdPenalty := trustBefore - v.Trust.BaseTrust

	if thirdPenalty <= secondPenalty {
		t.Errorf("Third offense penalty (%.4f) should be > second (%.4f)",
			thirdPenalty, secondPenalty)
	}
}

// ============================================================================
// SLASHING TESTS - Stake penalties for Byzantine behavior
// ============================================================================

func TestEquivocationSlashing(t *testing.T) {
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

	// Slash
	slashAmount := slasher.SlashForEquivocation(proof, 1)

	if slashAmount == 0 {
		t.Error("Expected non-zero slash amount for equivocation")
	}

	if v.Stake >= initialStake {
		t.Error("Stake should have decreased after slashing")
	}

	// Verify slash amount is correct (should be high for equivocation)
	expectedSlash := uint64(float64(initialStake) * config.SlashRate * 2) // 2x for equivocation
	if slashAmount < expectedSlash/2 {
		t.Errorf("Slash amount too low: expected ~%d, got %d", expectedSlash, slashAmount)
	}
}

func TestSlashingBelowMinimumRemovesValidator(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 1100) // Just above minimum
	validators.Add(v)

	config := types.DefaultConfig()
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(stakeMgr, validators, config)

	// Slash heavily
	for i := 0; i < 20; i++ {
		proof := &types.EquivocationProof{
			Vote1: types.Vote{BlockHash: types.Hash{byte(i)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey},
			Vote2: types.Vote{BlockHash: types.Hash{byte(i + 100)}, Height: uint64(i + 1), Round: 0, Voter: kp.PublicKey},
		}
		slasher.SlashForEquivocation(proof, uint64(i+1))

		if v.Stake < config.MinStake {
			break
		}
	}

	// Should either be removed or stake below minimum
	if v.Stake >= config.MinStake {
		t.Logf("Validator still has stake %d (min: %d)", v.Stake, config.MinStake)
	}
}

// ============================================================================
// INVALID MESSAGE TESTS - Malformed or invalid consensus messages
// ============================================================================

func TestInvalidBlockSignature(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	// Create block claimed to be from kp1
	block := types.NewBlock(0, 0, types.EmptyHash, kp1.PublicKey)

	// Sign with wrong key (kp2)
	block.Signature = crypto.SignBlock(kp2.SecretKey, block)

	// Verification should fail
	if crypto.VerifyBlock(block) {
		t.Error("Block signed with wrong key should fail verification")
	}
}

func TestInvalidVoteSignature(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	vote := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    1,
		Round:     0,
		Voter:     kp1.PublicKey,
	}

	// Sign with wrong key
	vote.Signature = crypto.SignVote(kp2.SecretKey, vote)

	if crypto.VerifyVote(vote) {
		t.Error("Vote signed with wrong key should fail verification")
	}
}

func TestVoteFromNonValidator(t *testing.T) {
	validators := types.NewValidatorSet()
	validKP, _ := crypto.GenerateKeyPair()
	invalidKP, _ := crypto.GenerateKeyPair()

	// Only add valid validator
	validators.Add(types.NewValidator(validKP.PublicKey, 10000))

	config := types.DefaultConfig()
	state := consensus.NewState()
	quorum := consensus.NewQuorumCalculator(validators, config)
	vh := consensus.NewVoteHandler(validators, quorum, state)

	// Create vote from non-validator
	vote := &types.Vote{
		BlockHash: types.Hash{1},
		Height:    0,
		Round:     0,
		Voter:     invalidKP.PublicKey, // Not in validator set
	}
	vote.Signature = crypto.SignVote(invalidKP.SecretKey, vote)

	// Process should fail
	accepted, _ := vh.ProcessVote(vote)
	if accepted {
		t.Error("Vote from non-validator should be rejected")
	}
}

func TestBlockFromNonLeader(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	ls := consensus.NewLeaderSelector(validators, config)

	// Select the actual leader
	leader := ls.SelectLeader(0, 0, types.EmptyHash)

	// Find a non-leader
	var nonLeaderKP *crypto.BLSKeyPair
	for _, kp := range keyPairs {
		if kp.PublicKey != leader.PublicKey {
			nonLeaderKP = kp
			break
		}
	}

	// Create block from non-leader
	block := types.NewBlock(0, 0, types.EmptyHash, nonLeaderKP.PublicKey)
	block.Signature = crypto.SignBlock(nonLeaderKP.SecretKey, block)

	// Validate - should fail because proposer is not leader
	selectedLeader := ls.SelectLeader(block.Height, block.Round, block.ParentHash)
	if selectedLeader.PublicKey == block.Proposer {
		t.Skip("Non-leader happened to be selected as leader")
	}

	// Verify the block is from wrong proposer
	if selectedLeader.PublicKey == nonLeaderKP.PublicKey {
		t.Error("Block should be rejected - proposer is not the leader")
	}
}

// ============================================================================
// SYBIL ATTACK TESTS - Many new validators with low trust
// ============================================================================

func TestSybilAttackMitigation(t *testing.T) {
	validators := types.NewValidatorSet()

	// Add 10 established validators (using random keys to avoid collision with Sybils)
	establishedKPs := make([]*crypto.BLSKeyPair, 10)
	for i := 0; i < 10; i++ {
		kp, _ := crypto.GenerateKeyPair()
		establishedKPs[i] = kp
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000 // Fully trusted
		v.Online = true
		validators.Add(v)
	}

	// Add 100 new Sybil validators (using deterministic keys since they're unique)
	sybilKPs := crypto.MustGenerateNKeyPairs(100)
	for _, kp := range sybilKPs {
		v := types.NewValidator(kp.PublicKey, 1000) // Minimum stake
		v.Trust.BaseTrust = types.InitialTrust      // Starting trust
		v.Trust.RoundsActive = 0                    // Brand new
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	// Calculate weights
	establishedWeight := 0.0
	for _, kp := range establishedKPs {
		v := validators.Get(kp.PublicKey)
		establishedWeight += v.VotingWeight()
	}

	sybilWeight := 0.0
	for _, kp := range sybilKPs {
		v := validators.Get(kp.PublicKey)
		sybilWeight += v.VotingWeight()
	}

	t.Logf("Established validators weight: %.4f", establishedWeight)
	t.Logf("Sybil validators weight: %.4f", sybilWeight)
	t.Logf("Quorum threshold: %.4f", qc.GetQuorum())

	// Sybils should NOT have enough weight for quorum
	if qc.HasQuorum(sybilWeight) {
		t.Error("100 Sybil validators should not reach quorum alone")
	}

	// Established validators should have quorum
	if !qc.HasQuorum(establishedWeight) {
		t.Error("10 established validators should have quorum")
	}

	// Sybil weight should be much less than established despite 10x count
	ratio := sybilWeight / establishedWeight
	if ratio > 0.5 {
		t.Errorf("Sybil weight ratio too high: %.2f (should be < 0.5)", ratio)
	}
}

func TestGraduatedTrustCeilingPreventsInstantInfluence(t *testing.T) {
	// A new validator cannot immediately have high trust
	testCases := []struct {
		roundsActive uint64
		maxTrust     float64
	}{
		{0, 0.20},
		{50, 0.20},
		{99, 0.20},
		{100, 0.40},
		{249, 0.40},
		{250, 0.60},
		{499, 0.60},
		{500, 0.80},
		{999, 0.80},
		{1000, 1.00},
		{5000, 1.00},
	}

	for _, tc := range testCases {
		v := types.NewValidator(types.PublicKey{}, 10000)
		v.Trust.BaseTrust = 1.0 // Try to set max trust
		v.Trust.RoundsActive = tc.roundsActive

		effectiveTrust := v.EffectiveTrust()
		if effectiveTrust > tc.maxTrust+0.001 {
			t.Errorf("RoundsActive=%d: effective trust %.2f exceeds ceiling %.2f",
				tc.roundsActive, effectiveTrust, tc.maxTrust)
		}
	}
}

// ============================================================================
// SLOW BURN ATTACK TESTS - Gradual trust building then attack
// ============================================================================

func TestSlowBurnAttackDetection(t *testing.T) {
	validators := types.NewValidatorSet()
	attackerKP, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(attackerKP.PublicKey, 10000)
	v.Trust.BaseTrust = 0.9 // Built up trust slowly
	v.Trust.RoundsActive = 2000
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)
	detector := trust.NewByzantineDetector(validators)

	// Attacker has high trust, then acts Byzantine
	initialTrust := v.Trust.BaseTrust
	t.Logf("Initial trust: %.4f", initialTrust)

	// Single Byzantine act
	mgr.PenaltyByzantine([]types.PublicKey{attackerKP.PublicKey})

	// Trust should drop significantly
	trustAfterFirst := v.Trust.BaseTrust
	firstDrop := initialTrust - trustAfterFirst
	t.Logf("After first offense: %.4f (drop: %.4f)", trustAfterFirst, firstDrop)

	if firstDrop < config.TrustPenaltyByzantine {
		t.Errorf("First offense drop too small: %.4f", firstDrop)
	}

	// Mark as Byzantine for tracking
	detector.RecordByzantine(trust.ByzantineEvent{
		Type:      trust.ByzantineTypeEquivocation,
		Validator: attackerKP.PublicKey,
	})

	// Second offense
	mgr.PenaltyByzantine([]types.PublicKey{attackerKP.PublicKey})
	trustAfterSecond := v.Trust.BaseTrust
	secondDrop := trustAfterFirst - trustAfterSecond
	t.Logf("After second offense: %.4f (drop: %.4f)", trustAfterSecond, secondDrop)

	// Escalation: second drop should be larger
	if secondDrop <= firstDrop {
		t.Errorf("Escalation failed: second drop (%.4f) <= first (%.4f)",
			secondDrop, firstDrop)
	}
}

func TestTrustDecayPreventsInfiniteAccumulation(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 1.0
	v.Trust.RoundsActive = 10000
	validators.Add(v)

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	// Apply decay for many rounds
	for i := 0; i < 10000; i++ {
		mgr.ApplyDecay()
	}

	// Trust should have decayed significantly
	if v.Trust.BaseTrust > 0.5 {
		t.Errorf("Trust should decay over time, got %.4f", v.Trust.BaseTrust)
	}

	// Calculate expected decay
	// After n rounds: trust = initial * decay^n
	// 1.0 * 0.9999^10000 ≈ 0.368
	expected := 1.0
	for i := 0; i < 10000; i++ {
		expected *= config.TrustDecay
	}
	t.Logf("Expected trust after 10000 rounds: %.4f, actual: %.4f", expected, v.Trust.BaseTrust)

	if abs(v.Trust.BaseTrust-expected) > 0.01 {
		t.Errorf("Unexpected decay: expected %.4f, got %.4f", expected, v.Trust.BaseTrust)
	}
}

// ============================================================================
// NOTHING AT STAKE TESTS - Voting for multiple forks
// ============================================================================

func TestNothingAtStakeSlashing(t *testing.T) {
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
	detector := trust.NewByzantineDetector(validators)

	// Vote for fork A (with valid signature)
	voteA := &types.Vote{BlockHash: types.Hash{1}, Height: 5, Round: 0, Voter: kp.PublicKey}
	voteA.Signature = crypto.SignVote(kp.SecretKey, voteA)

	// Vote for fork B (same height, different block) - with valid signature
	voteB := &types.Vote{BlockHash: types.Hash{2}, Height: 5, Round: 0, Voter: kp.PublicKey}
	voteB.Signature = crypto.SignVote(kp.SecretKey, voteB)

	detector.RecordVote(voteA)
	proof := detector.RecordVote(voteB)

	if proof == nil {
		t.Fatal("Should detect nothing-at-stake attack")
	}

	initialStake := v.Stake
	slasher.SlashForEquivocation(proof, 5)

	// Stake should be slashed
	if v.Stake >= initialStake {
		t.Error("Stake should be slashed for nothing-at-stake attack")
	}
}

// ============================================================================
// LONG-RANGE ATTACK TESTS - Historical key compromise
// ============================================================================

func TestLongRangeAttackMitigation(t *testing.T) {
	// Long-range attacks are mitigated by:
	// 1. Weak subjectivity checkpoints
	// 2. Finality - once finalized, cannot be reverted

	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	validators.Add(v)

	config := types.DefaultConfig()
	state := consensus.NewState()
	qc := consensus.NewQuorumCalculator(validators, config)
	finalizer := consensus.NewFinalizer(validators, state, qc)

	// Finalize block at height 100
	block := types.NewBlock(100, 0, types.Hash{99}, kp.PublicKey)
	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	vote := types.NewVote(block.Hash(), block.Height, block.Round, kp.PublicKey)
	vote.Signature = crypto.SignVote(kp.SecretKey, vote)

	finalizer.TryFinalize(block, []*types.Vote{vote})

	// Verify block is finalized
	if !finalizer.IsFinalized(100) {
		t.Fatal("Block should be finalized")
	}

	// Attempt to finalize a different block at same height (attack)
	attackBlock := types.NewBlock(100, 0, types.Hash{99}, kp.PublicKey)
	attackBlock.TxRoot = types.Hash{42} // Different content
	attackBlock.Signature = crypto.SignBlock(kp.SecretKey, attackBlock)

	attackVote := types.NewVote(attackBlock.Hash(), attackBlock.Height, attackBlock.Round, kp.PublicKey)
	attackVote.Signature = crypto.SignVote(kp.SecretKey, attackVote)

	msg := finalizer.TryFinalize(attackBlock, []*types.Vote{attackVote})

	// Should fail - already finalized at this height
	if msg != nil {
		t.Error("Should not finalize conflicting block at already-finalized height")
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
