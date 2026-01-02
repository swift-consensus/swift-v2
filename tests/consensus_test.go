package tests

import (
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/network"
	"github.com/swift-consensus/swift-v2/types"
)

func TestBasicConsensus(t *testing.T) {
	// This is a simplified test that verifies the core voting and finalization mechanism
	// without running the full consensus loop to avoid timing complexities

	// Create 4 validators
	numValidators := 4
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	// Create validator set
	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()

	// Create a quorum calculator
	qc := consensus.NewQuorumCalculator(validators, config)

	// Verify quorum calculation
	info := qc.GetQuorumInfo()
	t.Logf("Total weight: %.4f, Online weight: %.4f, Quorum: %.4f",
		info.TotalWeight, info.OnlineWeight, info.Quorum)

	// Create a block
	leader := validators.GetByIndex(0)
	block := types.NewBlock(0, 0, types.EmptyHash, leader.PublicKey)
	block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

	// Create votes from all validators
	votes := make([]*types.Vote, numValidators)
	for i, kp := range keyPairs {
		vote := types.NewVote(block.Hash(), block.Height, block.Round, kp.PublicKey)
		vote.Signature = crypto.SignVote(kp.SecretKey, vote)
		votes[i] = vote
	}

	// Calculate vote weight
	voteWeight := qc.CalculateVoteWeight(votes)
	t.Logf("Vote weight from %d votes: %.4f", len(votes), voteWeight)

	// Check quorum with all votes
	if !qc.HasQuorum(voteWeight) {
		t.Errorf("Expected quorum with all votes, weight=%.4f, quorum=%.4f", voteWeight, info.Quorum)
	}

	// Check quorum with just 3 votes (should still pass)
	threeVotes := votes[:3]
	threeWeight := qc.CalculateVoteWeight(threeVotes)
	t.Logf("Vote weight from 3 votes: %.4f", threeWeight)
	if !qc.HasQuorum(threeWeight) {
		t.Errorf("Expected quorum with 3 votes, weight=%.4f, quorum=%.4f", threeWeight, info.Quorum)
	}

	// Check quorum with just 2 votes (should fail)
	twoVotes := votes[:2]
	twoWeight := qc.CalculateVoteWeight(twoVotes)
	t.Logf("Vote weight from 2 votes: %.4f", twoWeight)
	if qc.HasQuorum(twoWeight) {
		t.Errorf("Expected no quorum with 2 votes, weight=%.4f, quorum=%.4f", twoWeight, info.Quorum)
	}

	// Test finalizer
	state := consensus.NewState()
	finalizer := consensus.NewFinalizer(validators, state, qc)

	finalized := false
	finalizer.SetFinalizedCallback(func(msg *types.FinalizeMsg) {
		finalized = true
		t.Logf("Block finalized at height %d", msg.Block.Height)
	})

	// Try to finalize with votes
	msg := finalizer.TryFinalize(block, votes)
	if msg == nil {
		t.Error("Expected finalize message, got nil")
	}
	if !finalized {
		t.Error("Expected finalized callback to be called")
	}

	// Verify the finalized block
	if !finalizer.IsFinalized(block.Height) {
		t.Error("Expected block to be marked as finalized")
	}
}

func TestQuorumCalculation(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	qc := consensus.NewQuorumCalculator(validators, config)

	// Get quorum info
	info := qc.GetQuorumInfo()

	// With 4 validators at equal weight, total weight should be ~4
	if info.TotalWeight == 0 {
		t.Error("Expected non-zero total weight")
	}

	// Adaptive quorum should be 67% of online
	expectedAdaptive := 0.67 * info.OnlineWeight
	if info.AdaptiveQuorum != expectedAdaptive {
		t.Errorf("Expected adaptive quorum %.2f, got %.2f", expectedAdaptive, info.AdaptiveQuorum)
	}

	// Test HasQuorum
	// Note: Due to SECURITY FIX for floating point precision, HasQuorum requires
	// weight >= quorum + epsilon (1e-9), so exact quorum doesn't pass.
	// We test with quorum + small margin instead.
	if !qc.HasQuorum(info.Quorum + 1e-8) {
		t.Error("Expected HasQuorum to return true slightly above quorum threshold")
	}

	if qc.HasQuorum(info.Quorum - 0.1) {
		t.Error("Expected HasQuorum to return false below threshold")
	}
}

func TestLeaderSelection(t *testing.T) {
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

	lastHash := types.Hash{}

	// Select leaders for multiple rounds
	leaders := make(map[string]int)
	for round := uint32(0); round < 100; round++ {
		leader := ls.SelectLeader(0, round, lastHash)
		if leader == nil {
			t.Errorf("No leader selected for round %d", round)
			continue
		}
		leaders[string(leader.PublicKey[:])]++
	}

	// Check that multiple validators were selected as leader
	if len(leaders) < 3 {
		t.Errorf("Expected at least 3 different leaders, got %d", len(leaders))
	}
}

func TestLeaderCooldown(t *testing.T) {
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

	lastHash := types.Hash{}

	// Record a leader
	leader1 := ls.SelectLeader(0, 0, lastHash)
	ls.RecordLeader(leader1.PublicKey, 0)

	// The same leader should not be selected for next few rounds (cooldown)
	sameLeaderCount := 0
	for round := uint32(1); round <= config.LeaderCooldown; round++ {
		leader := ls.SelectLeader(0, round, lastHash)
		if leader.PublicKey == leader1.PublicKey {
			sameLeaderCount++
		}
	}

	if sameLeaderCount > 0 {
		t.Errorf("Leader was selected %d times during cooldown period", sameLeaderCount)
	}
}

func TestVotingWeight(t *testing.T) {
	testCases := []struct {
		stake         uint64
		trust         float64
		expectedGt0   bool
	}{
		{1000, 1.0, true},   // Minimum stake, max trust
		{10000, 1.0, true},  // 10x stake, max trust
		{1000, 0.5, true},   // Minimum stake, half trust
		{500, 1.0, false},   // Below minimum stake
		{1000, 0.0, false},  // Zero trust
	}

	for i, tc := range testCases {
		v := types.NewValidator(types.PublicKey{}, tc.stake)
		v.Trust.BaseTrust = tc.trust
		v.Trust.RoundsActive = 1000 // Max ceiling

		weight := v.VotingWeight()

		if tc.expectedGt0 && weight <= 0 {
			t.Errorf("Case %d: expected positive weight, got %.4f", i, weight)
		}
		if !tc.expectedGt0 && weight > 0 {
			t.Errorf("Case %d: expected zero weight, got %.4f", i, weight)
		}
	}
}

func TestBLSSignatures(t *testing.T) {
	// Generate key pair
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a block
	block := types.NewBlock(1, 0, types.Hash{}, kp.PublicKey)

	// Sign
	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	// Verify
	if !crypto.VerifyBlock(block) {
		t.Error("Block signature verification failed")
	}
}

func TestSignatureAggregation(t *testing.T) {
	numSigners := 5
	keyPairs := crypto.MustGenerateNKeyPairs(numSigners)

	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 1000))
	}

	// Create a block
	block := types.NewBlock(1, 0, types.Hash{}, keyPairs[0].PublicKey)
	block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

	// Create votes
	votes := make([]*types.Vote, numSigners)
	for i, kp := range keyPairs {
		vote := types.NewVote(block.Hash(), block.Height, block.Round, kp.PublicKey)
		vote.Signature = crypto.SignVote(kp.SecretKey, vote)
		votes[i] = vote
	}

	// Aggregate
	finalizeMsg := crypto.AggregateVotes(block, votes, validators)
	if finalizeMsg == nil {
		t.Fatal("Failed to aggregate votes")
	}

	// Verify
	if !crypto.VerifyFinalizeMsg(finalizeMsg, validators) {
		t.Error("Finalize message verification failed")
	}

	// Check voters
	voters := finalizeMsg.GetVoters(validators.Size())
	if len(voters) != numSigners {
		t.Errorf("Expected %d voters, got %d", numSigners, len(voters))
	}
}

func TestMerkleRoot(t *testing.T) {
	// Create some transactions
	txs := []types.Transaction{
		{From: types.PublicKey{1}, To: types.PublicKey{2}, Amount: 100},
		{From: types.PublicKey{2}, To: types.PublicKey{3}, Amount: 200},
		{From: types.PublicKey{3}, To: types.PublicKey{4}, Amount: 300},
	}

	root := crypto.TransactionsMerkleRoot(txs)

	// Root should be non-zero
	if root == types.EmptyHash {
		t.Error("Expected non-zero merkle root")
	}

	// Same transactions should produce same root
	root2 := crypto.TransactionsMerkleRoot(txs)
	if root != root2 {
		t.Error("Same transactions produced different merkle roots")
	}

	// Different transactions should produce different root
	txs[0].Amount = 101
	root3 := crypto.TransactionsMerkleRoot(txs)
	if root == root3 {
		t.Error("Different transactions produced same merkle root")
	}
}

func TestMockNetwork(t *testing.T) {
	// Create network
	mockNetwork := network.NewMockNetwork()

	// Add nodes
	keys := crypto.MustGenerateNKeyPairs(3)
	for _, kp := range keys {
		mockNetwork.AddNode(kp.PublicKey)
	}

	// Get transports
	t1 := mockNetwork.GetTransport(keys[0].PublicKey)
	t2 := mockNetwork.GetTransport(keys[1].PublicKey)

	// Set up receiver
	received := make(chan bool, 1)
	t2.OnReceive(func(msg *network.Message) {
		received <- true
	})

	// Start transports
	t1.Start()
	t2.Start()

	// Send message
	t1.Broadcast("test message")

	// Wait for receipt
	select {
	case <-received:
		// Success
	case <-time.After(time.Second):
		t.Error("Message not received within timeout")
	}

	// Check stats
	stats := t1.Stats()
	if stats.MessagesSent == 0 {
		t.Error("Expected messages sent > 0")
	}
}
