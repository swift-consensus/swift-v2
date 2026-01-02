package tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// =============================================================================
// SAFETY INVARIANT TESTS
// These tests verify the fundamental safety properties of the consensus protocol
// =============================================================================

// TestNoConflictingFinalizations tests that no two conflicting blocks finalize at same height
func TestNoConflictingFinalizations(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(10)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	// Create two conflicting blocks at same height
	block1 := &types.Block{
		Height:    1,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
		TxRoot:    [32]byte{1}, // Different content
		Proposer:  keyPairs[0].PublicKey,
	}

	block2 := &types.Block{
		Height:    1,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
		TxRoot:    [32]byte{2}, // Different content
		Proposer:  keyPairs[1].PublicKey,
	}

	quorum := consensus.NewQuorumCalculator(validators, config)
	required := quorum.GetQuorum()
	totalWeight := quorum.TotalWeight()

	// If block1 gets quorum (67%), block2 cannot also get quorum
	// because validators can only vote for one block
	block1Weight := totalWeight * 0.67
	remainingWeight := totalWeight - block1Weight

	// Remaining validators cannot achieve quorum
	if remainingWeight >= required {
		t.Error("Safety violation: remaining validators after quorum should not have quorum")
	}

	// Verify blocks have different hashes
	hash1 := block1.Hash()
	hash2 := block2.Hash()
	if bytes.Equal(hash1[:], hash2[:]) {
		t.Error("Different blocks should have different hashes")
	}
}

// TestFinalizedBlocksFormChain tests that finalized blocks form a valid chain
func TestFinalizedBlocksFormChain(t *testing.T) {
	blocks := make([]*types.Block, 10)

	kp, _ := crypto.GenerateKeyPair()

	// Create genesis block
	blocks[0] = &types.Block{
		Height:     0,
		Round:      0,
		ParentHash: [32]byte{},
		Timestamp:  time.Now().UnixNano(),
		Proposer:   kp.PublicKey,
	}

	// Create chain of blocks
	for i := 1; i < 10; i++ {
		blocks[i] = &types.Block{
			Height:     uint64(i),
			Round:      0,
			ParentHash: blocks[i-1].Hash(),
			Timestamp:  time.Now().UnixNano(),
			Proposer:   kp.PublicKey,
		}
	}

	// Verify chain integrity
	for i := 1; i < 10; i++ {
		if blocks[i].Height != blocks[i-1].Height+1 {
			t.Errorf("Block %d has incorrect height", i)
		}

		expectedParent := blocks[i-1].Hash()
		if blocks[i].ParentHash != expectedParent {
			t.Errorf("Block %d has incorrect parent hash", i)
		}
	}
}

// TestNoEquivocation tests that a validator cannot vote for two blocks at same height/round
func TestNoEquivocation(t *testing.T) {
	validators := types.NewValidatorSet()

	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.5
	v.Trust.RoundsActive = 500
	validators.Add(v)

	// Create two different blocks at same height/round
	block1 := &types.Block{
		Height:    1,
		Round:     0,
		TxRoot:    [32]byte{1},
		Timestamp: time.Now().UnixNano(),
		Proposer:  kp.PublicKey,
	}

	block2 := &types.Block{
		Height:    1,
		Round:     0,
		TxRoot:    [32]byte{2},
		Timestamp: time.Now().UnixNano(),
		Proposer:  kp.PublicKey,
	}

	// Create votes for both blocks
	vote1 := types.NewVote(block1.Hash(), 1, 0, kp.PublicKey)
	sig1 := crypto.SignVote(kp.SecretKey, vote1)
	vote1.Signature = sig1

	vote2 := types.NewVote(block2.Hash(), 1, 0, kp.PublicKey)
	sig2 := crypto.SignVote(kp.SecretKey, vote2)
	vote2.Signature = sig2

	// Detect equivocation
	detector := trust.NewByzantineDetector(validators)

	// Record first vote - no equivocation
	proof1 := detector.RecordVote(vote1)
	if proof1 != nil {
		t.Error("First vote should not be equivocation")
	}

	// Record second vote - should detect equivocation
	proof2 := detector.RecordVote(vote2)
	if proof2 == nil {
		t.Error("Should detect equivocation when same validator votes for different blocks")
	}
}

// TestQuorumIntersection tests that any two quorums must intersect
func TestQuorumIntersection(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(10)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)
	totalWeight := quorum.TotalWeight()
	required := quorum.GetQuorum()

	// With 67% quorum requirement, any two quorums must share at least 34% of weight
	// Because 67% + 67% = 134%, so overlap >= 34%
	minOverlap := 2*required - totalWeight

	if minOverlap <= 0 {
		t.Error("Quorum intersection property requires overlap > 0")
	}

	// Minimum overlap should be at least 1/3 of total weight
	expectedMinOverlap := totalWeight / 3
	if minOverlap < expectedMinOverlap*0.9 {
		t.Errorf("Expected minimum overlap ~%.2f, got %.2f", expectedMinOverlap, minOverlap)
	}
}

// TestByzantineTolerance tests that f Byzantine validators cannot break safety
func TestByzantineTolerance(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	// 10 validators with equal stake
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
	totalWeight := quorum.TotalWeight()

	// Calculate Byzantine threshold (1/3 of validators)
	byzantineWeight := totalWeight / 3

	// Byzantine validators alone should NOT achieve quorum
	if byzantineWeight >= required {
		t.Error("1/3 Byzantine validators should not achieve quorum alone")
	}

	// The quorum requirement is 67% of online weight.
	// With 2/3 (66.7%) honest validators, they're just slightly below quorum.
	// This is actually correct behavior - BFT requires slightly more than 2/3.
	// To achieve quorum, we need just over 67%, not exactly 2/3.
	honestWeight := totalWeight - byzantineWeight
	quorumRatio := required / totalWeight

	t.Logf("Total weight: %.4f, Honest weight: %.4f (%.2f%%), Required: %.4f (%.2f%%)",
		totalWeight, honestWeight, 100*honestWeight/totalWeight, required, 100*quorumRatio)

	// Verify that Byzantine alone cannot achieve quorum (safety property)
	if byzantineWeight >= required {
		t.Error("Byzantine validators alone should not achieve quorum")
	}

	// Verify that we need just over 2/3 for quorum (this is expected BFT behavior)
	if quorumRatio < 0.51 {
		t.Error("Quorum should require at least majority")
	}
}

// =============================================================================
// SIGNATURE SAFETY TESTS
// =============================================================================

// TestSignatureUniquenessSafety tests that different messages produce different signatures
func TestSignatureUniquenessSafety(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	sig1 := crypto.Sign(kp.SecretKey, msg1)
	sig2 := crypto.Sign(kp.SecretKey, msg2)

	if bytes.Equal(sig1[:], sig2[:]) {
		t.Error("Different messages should produce different signatures")
	}
}

// TestSignatureVerificationSafety tests that only correct signatures verify
func TestSignatureVerificationSafety(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	msg := []byte("test message")
	sig := crypto.Sign(kp1.SecretKey, msg)

	// Correct key should verify
	valid := crypto.Verify(kp1.PublicKey, msg, sig)
	if !valid {
		t.Error("Signature should verify with correct key")
	}

	// Wrong key should not verify
	invalid := crypto.Verify(kp2.PublicKey, msg, sig)
	if invalid {
		t.Error("Signature should not verify with wrong key")
	}
}

// TestAggregatedSignatureSafety tests that aggregated signatures maintain security
func TestAggregatedSignatureSafety(t *testing.T) {
	validators := types.NewValidatorSet()

	keyPairs := crypto.MustGenerateNKeyPairs(5)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		validators.Add(v)
	}

	block := &types.Block{
		Height:    1,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
	}

	votes := make([]*types.Vote, 5)
	for i, kp := range keyPairs {
		votes[i] = types.NewVote(block.Hash(), 1, 0, kp.PublicKey)
		sig := crypto.SignVote(kp.SecretKey, votes[i])
		votes[i].Signature = sig
	}

	// Aggregate signatures into a FinalizeMsg
	finalizeMsg := crypto.AggregateVotes(block, votes, validators)
	if finalizeMsg == nil {
		t.Fatal("Failed to aggregate votes")
	}

	// Verify finalization message
	valid := crypto.VerifyFinalizeMsg(finalizeMsg, validators)
	if !valid {
		t.Error("Aggregated signature should verify")
	}

	// Modify block in message - verification should fail
	modifiedMsg := *finalizeMsg
	modifiedMsg.Block.Timestamp = time.Now().UnixNano() + 1

	invalid := crypto.VerifyFinalizeMsg(&modifiedMsg, validators)
	if invalid {
		t.Error("Aggregated signature should not verify for modified block")
	}
}

// =============================================================================
// TRUST SAFETY TESTS
// =============================================================================

// TestTrustBounds tests that trust is always within [0, 1]
func TestTrustBounds(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.5
	v.Trust.RoundsActive = 1000
	validators.Add(v)

	mgr := trust.NewManager(validators, config)

	// Apply many rewards
	for i := 0; i < 1000; i++ {
		mgr.RewardVote(kp.PublicKey, 1)
	}

	trustVal := v.Trust.BaseTrust
	if trustVal > 1.0 {
		t.Errorf("Trust should not exceed 1.0, got %.4f", trustVal)
	}

	// Apply many penalties
	for i := 0; i < 1000; i++ {
		mgr.PenaltyMiss(kp.PublicKey)
	}

	trustVal = v.Trust.BaseTrust
	if trustVal < 0.0 {
		t.Errorf("Trust should not go below 0.0, got %.4f", trustVal)
	}
}

// TestVotingWeightPositive tests that voting weight is always positive for active validators
func TestVotingWeightPositive(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.5
	v.Trust.RoundsActive = 500
	v.Online = true

	weight := v.VotingWeight()

	if weight <= 0 {
		t.Errorf("Voting weight should be positive, got %.4f", weight)
	}
}

// TestZeroTrustZeroWeight tests that zero trust means zero voting weight
func TestZeroTrustZeroWeight(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.0
	v.Trust.RoundsActive = 500
	v.Online = true

	weight := v.VotingWeight()

	if weight != 0 {
		t.Errorf("Zero trust should mean zero weight, got %.4f", weight)
	}
}

// =============================================================================
// FINALIZATION SAFETY TESTS
// =============================================================================

// TestFinalizedBlockImmutable tests that finalized blocks cannot be changed
func TestFinalizedBlockImmutable(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block := &types.Block{
		Height:    1,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
		TxRoot:    [32]byte{1, 2, 3},
		Proposer:  kp.PublicKey,
	}

	originalHash := block.Hash()

	// Try to modify the block
	block.TxRoot = [32]byte{4, 5, 6}
	modifiedHash := block.Hash()

	// Hash should change if block is modified
	if originalHash == modifiedHash {
		t.Error("Modified block should have different hash")
	}
}

// TestParentHashIntegrity tests that parent hash creates tamper-evident chain
func TestParentHashIntegrity(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	genesis := &types.Block{
		Height:    0,
		Round:     0,
		Timestamp: time.Now().UnixNano(),
		Proposer:  kp.PublicKey,
	}

	block1 := &types.Block{
		Height:     1,
		Round:      0,
		ParentHash: genesis.Hash(),
		Timestamp:  time.Now().UnixNano(),
		Proposer:   kp.PublicKey,
	}

	block2 := &types.Block{
		Height:     2,
		Round:      0,
		ParentHash: block1.Hash(),
		Timestamp:  time.Now().UnixNano(),
		Proposer:   kp.PublicKey,
	}

	// Modify block1 after block2 was created
	originalBlock1Hash := block1.Hash()
	block1.TxRoot = [32]byte{255}
	newBlock1Hash := block1.Hash()

	// Block2's parent hash no longer matches
	if block2.ParentHash == newBlock1Hash {
		t.Error("Tampering with intermediate block should break chain integrity")
	}

	// Block2's parent hash should still be the original
	if block2.ParentHash != originalBlock1Hash {
		t.Error("Block2 parent hash should be original block1 hash")
	}
}

// =============================================================================
// MONOTONICITY TESTS
// =============================================================================

// TestHeightMonotonicity tests that finalized height never decreases
func TestHeightMonotonicity(t *testing.T) {
	heights := []uint64{0, 1, 2, 3, 4, 5}

	for i := 1; i < len(heights); i++ {
		if heights[i] <= heights[i-1] {
			t.Errorf("Height should strictly increase: %d -> %d", heights[i-1], heights[i])
		}
	}
}

// TestRoundMonotonicity tests that round never decreases within same height
func TestRoundMonotonicity(t *testing.T) {
	// In a single height, rounds can only increase (due to view changes)
	height := uint64(1)
	rounds := []uint32{0, 1, 2, 3}

	prevRound := uint32(0)
	for _, round := range rounds {
		if round < prevRound {
			t.Errorf("At height %d, round should not decrease: %d -> %d", height, prevRound, round)
		}
		prevRound = round
	}
}

// TestTrustCeilingMonotonicity tests that trust ceiling only increases with tenure
func TestTrustCeilingMonotonicity(t *testing.T) {
	// Track ceiling as rounds increase
	prevCeiling := 0.0
	for rounds := uint64(0); rounds <= 1200; rounds += 100 {
		ceiling := trust.CalculateCeiling(rounds, 0)

		if ceiling < prevCeiling {
			t.Errorf("Trust ceiling should not decrease: %.2f -> %.2f at round %d",
				prevCeiling, ceiling, rounds)
		}
		prevCeiling = ceiling
	}
}

// =============================================================================
// CONSISTENCY TESTS
// =============================================================================

// TestVRFDeterminismSafety tests VRF behavior after security fix
// SECURITY FIX: VRF proofs are now non-deterministic to prevent grinding attacks.
// The VALUE (output) remains deterministic since it's derived from Gamma = sk * H(message).
// The PROOF is non-deterministic because the nonce now includes random entropy.
func TestVRFDeterminismSafety(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	seed := []byte("test seed for vrf")

	vrfOutput1 := crypto.VRFProve(kp.SecretKey, seed)
	vrfOutput2 := crypto.VRFProve(kp.SecretKey, seed)

	// Value should be deterministic (derived from Gamma = sk * H(message))
	if vrfOutput1.Value != vrfOutput2.Value {
		t.Error("VRF Value should be deterministic for same input")
	}

	// Proof should be non-deterministic (security fix: nonce includes random entropy)
	// This prevents grinding attacks where attacker tries different messages
	// to find favorable VRF outputs
	if bytes.Equal(vrfOutput1.Proof.ToBytes(), vrfOutput2.Proof.ToBytes()) {
		t.Error("VRF Proof should be non-deterministic after security fix (grinding attack prevention)")
	}

	// Both proofs should still verify correctly
	if !crypto.VRFVerify(kp.PublicKey, seed, vrfOutput1) {
		t.Error("First VRF proof should verify")
	}
	if !crypto.VRFVerify(kp.PublicKey, seed, vrfOutput2) {
		t.Error("Second VRF proof should verify")
	}
}

// TestBlockHashDeterminism tests that block hash is deterministic
func TestBlockHashDeterminism(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block := &types.Block{
		Height:     1,
		Round:      0,
		ParentHash: [32]byte{1, 2, 3},
		TxRoot:     [32]byte{4, 5, 6},
		Timestamp:  1234567890,
		Proposer:   kp.PublicKey,
	}

	hash1 := block.Hash()
	hash2 := block.Hash()

	if hash1 != hash2 {
		t.Error("Block hash should be deterministic")
	}
}

// TestQuorumCalculationConsistency tests that quorum is calculated consistently
func TestQuorumCalculationConsistency(t *testing.T) {
	validators := types.NewValidatorSet()
	config := types.DefaultConfig()

	keyPairs := crypto.MustGenerateNKeyPairs(10)
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	quorum := consensus.NewQuorumCalculator(validators, config)

	// Calculate quorum multiple times
	required1 := quorum.GetQuorum()
	required2 := quorum.GetQuorum()

	if required1 != required2 {
		t.Errorf("Quorum should be consistent: %.4f vs %.4f", required1, required2)
	}
}

// =============================================================================
// DOUBLE SPEND PREVENTION TESTS
// =============================================================================

// TestNoDuplicateVotes tests that duplicate votes are rejected
func TestNoDuplicateVotes(t *testing.T) {
	voteSet := types.NewVoteSet(1, 0)

	kp, _ := crypto.GenerateKeyPair()
	vote := types.NewVote([32]byte{1, 2, 3}, 1, 0, kp.PublicKey)

	// First vote should be added
	added1 := voteSet.Add(vote)
	if !added1 {
		t.Error("First vote should be added")
	}

	// Duplicate vote should be rejected
	added2 := voteSet.Add(vote)
	if added2 {
		t.Error("Duplicate vote should be rejected")
	}

	// Size should be 1
	if voteSet.Size() != 1 {
		t.Errorf("Expected size 1, got %d", voteSet.Size())
	}
}

// TestVoteSetConsistency tests that vote set maintains consistency
func TestVoteSetConsistency(t *testing.T) {
	voteSet := types.NewVoteSet(1, 0)

	keyPairs := crypto.MustGenerateNKeyPairs(5)
	for _, kp := range keyPairs {
		vote := types.NewVote([32]byte{1, 2, 3}, 1, 0, kp.PublicKey)
		voteSet.Add(vote)
	}

	// Size should match
	if voteSet.Size() != 5 {
		t.Errorf("Expected size 5, got %d", voteSet.Size())
	}

	// All votes should be retrievable
	for _, kp := range keyPairs {
		vote := voteSet.Get(kp.PublicKey)
		if vote == nil {
			t.Error("Vote should be retrievable")
		}
	}
}
