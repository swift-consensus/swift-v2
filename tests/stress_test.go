package tests

import (
	"sync"
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// HIGH VOLUME VOTE TESTS
// ============================================================================

func TestHighVolumeVoteProcessing(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 100
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	state := consensus.NewState()
	qc := consensus.NewQuorumCalculator(validators, config)
	vh := consensus.NewVoteHandler(validators, qc, state)

	// Create a block
	block := types.NewBlock(0, 0, types.EmptyHash, keyPairs[0].PublicKey)
	block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

	quorumReached := false
	vh.SetQuorumCallback(func(h uint64, r uint32, votes []*types.Vote) {
		quorumReached = true
		t.Logf("Quorum reached with %d votes", len(votes))
	})

	// Process votes from all validators
	start := time.Now()
	for _, kp := range keyPairs {
		vote := types.NewVote(block.Hash(), block.Height, block.Round, kp.PublicKey)
		vote.Signature = crypto.SignVote(kp.SecretKey, vote)
		vh.ProcessVote(vote)
	}
	elapsed := time.Since(start)

	t.Logf("Processed %d votes in %v (%.2f votes/ms)",
		numValidators, elapsed, float64(numValidators)/float64(elapsed.Milliseconds()))

	if !quorumReached {
		t.Error("Quorum should have been reached")
	}
}

func TestConcurrentVoteProcessing(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 50
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	state := consensus.NewState()
	qc := consensus.NewQuorumCalculator(validators, config)
	vh := consensus.NewVoteHandler(validators, qc, state)

	block := types.NewBlock(0, 0, types.EmptyHash, keyPairs[0].PublicKey)
	block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

	var wg sync.WaitGroup
	var quorumCount int32
	var mu sync.Mutex

	vh.SetQuorumCallback(func(h uint64, r uint32, votes []*types.Vote) {
		mu.Lock()
		quorumCount++
		mu.Unlock()
	})

	// Process votes concurrently
	for _, kp := range keyPairs {
		wg.Add(1)
		go func(kp *crypto.BLSKeyPair) {
			defer wg.Done()
			vote := types.NewVote(block.Hash(), block.Height, block.Round, kp.PublicKey)
			vote.Signature = crypto.SignVote(kp.SecretKey, vote)
			vh.ProcessVote(vote)
		}(kp)
	}

	wg.Wait()

	if quorumCount == 0 {
		t.Error("Quorum callback should have fired at least once")
	}
}

// ============================================================================
// RAPID ROUND CHANGE TESTS
// ============================================================================

func TestRapidRoundChanges(t *testing.T) {
	state := consensus.NewState()
	numRounds := 10000

	start := time.Now()
	for i := 0; i < numRounds; i++ {
		state.NewRound(uint32(i))
	}
	elapsed := time.Since(start)

	t.Logf("Processed %d round changes in %v (%.2f rounds/ms)",
		numRounds, elapsed, float64(numRounds)/float64(elapsed.Milliseconds()))

	if state.GetRound() != uint32(numRounds-1) {
		t.Errorf("Expected round %d, got %d", numRounds-1, state.GetRound())
	}
}

func TestRapidHeightAdvance(t *testing.T) {
	state := consensus.NewState()
	numHeights := 10000

	start := time.Now()
	for i := 0; i < numHeights; i++ {
		state.NewHeight(uint64(i), types.Hash{byte(i % 256)})
	}
	elapsed := time.Since(start)

	t.Logf("Processed %d height advances in %v (%.2f heights/ms)",
		numHeights, elapsed, float64(numHeights)/float64(elapsed.Milliseconds()))

	if state.GetHeight() != uint64(numHeights-1) {
		t.Errorf("Expected height %d, got %d", numHeights-1, state.GetHeight())
	}
}

// ============================================================================
// TRUST SYSTEM STRESS TESTS
// ============================================================================

func TestMassiveTrustUpdates(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 1000
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		validators.Add(v)
	}

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	numRounds := 1000

	start := time.Now()
	for round := 0; round < numRounds; round++ {
		// Random rewards and penalties
		for i := 0; i < numValidators; i++ {
			if i%10 == 0 {
				mgr.PenaltyMiss(keyPairs[i].PublicKey)
			} else {
				mgr.RewardVote(keyPairs[i].PublicKey, uint64(round))
			}
		}
		mgr.ApplyDecay()
	}
	elapsed := time.Since(start)

	updates := numRounds * numValidators
	t.Logf("Processed %d trust updates in %v (%.2f updates/ms)",
		updates, elapsed, float64(updates)/float64(elapsed.Milliseconds()))
}

func TestConcurrentTrustUpdates(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 100
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		validators.Add(v)
	}

	config := types.DefaultConfig()
	mgr := trust.NewManager(validators, config)

	var wg sync.WaitGroup
	numGoroutines := 100
	updatesPerGoroutine := 100

	start := time.Now()
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < updatesPerGoroutine; i++ {
				idx := (gid + i) % numValidators
				if i%2 == 0 {
					mgr.RewardVote(keyPairs[idx].PublicKey, uint64(i))
				} else {
					mgr.PenaltyMiss(keyPairs[idx].PublicKey)
				}
			}
		}(g)
	}
	wg.Wait()
	elapsed := time.Since(start)

	totalUpdates := numGoroutines * updatesPerGoroutine
	t.Logf("Processed %d concurrent trust updates in %v (%.2f updates/ms)",
		totalUpdates, elapsed, float64(totalUpdates)/float64(elapsed.Milliseconds()))
}

// ============================================================================
// LEADER SELECTION STRESS TESTS
// ============================================================================

func TestRapidLeaderSelection(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 100
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	ls := consensus.NewLeaderSelector(validators, config)

	numSelections := 10000

	start := time.Now()
	lastHash := types.EmptyHash
	for round := uint32(0); round < uint32(numSelections); round++ {
		leader := ls.SelectLeader(0, round, lastHash)
		if leader != nil {
			ls.RecordLeader(leader.PublicKey, round)
		}
	}
	elapsed := time.Since(start)

	t.Logf("Performed %d leader selections in %v (%.2f selections/ms)",
		numSelections, elapsed, float64(numSelections)/float64(elapsed.Milliseconds()))
}

func TestLeaderDistribution(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 20
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.5
		v.Trust.RoundsActive = 500
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	ls := consensus.NewLeaderSelector(validators, config)

	leaderCounts := make(map[string]int)
	numRounds := 10000

	lastHash := types.EmptyHash
	for round := uint32(0); round < uint32(numRounds); round++ {
		leader := ls.SelectLeader(0, round, lastHash)
		if leader != nil {
			key := string(leader.PublicKey[:8])
			leaderCounts[key]++
		}
	}

	// Check distribution
	expectedAvg := numRounds / numValidators
	minCount := expectedAvg / 3
	maxCount := expectedAvg * 3

	t.Logf("Expected ~%d selections per validator", expectedAvg)

	for key, count := range leaderCounts {
		if count < minCount || count > maxCount {
			t.Logf("Validator %s: %d selections (outside expected range [%d, %d])",
				key[:4], count, minCount, maxCount)
		}
	}
}

// ============================================================================
// MEMORY STRESS TESTS
// ============================================================================

func TestVoteSetMemoryCleanup(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	state := consensus.NewState()
	qc := consensus.NewQuorumCalculator(validators, config)
	vh := consensus.NewVoteHandler(validators, qc, state)

	// Process votes for many heights
	numHeights := 1000
	for height := uint64(0); height < uint64(numHeights); height++ {
		block := types.NewBlock(height, 0, types.Hash{byte(height % 256)}, keyPairs[0].PublicKey)

		for _, kp := range keyPairs {
			vote := types.NewVote(block.Hash(), height, 0, kp.PublicKey)
			vote.Signature = crypto.SignVote(kp.SecretKey, vote)
			vh.ProcessVote(vote)
		}

		// Periodically cleanup
		if height > 100 && height%100 == 0 {
			vh.Cleanup(height, 100)
		}
	}

	// Verify old votes are cleaned
	oldVotes := vh.GetVotes(0, 0)
	if len(oldVotes) > 0 {
		t.Logf("Old votes not cleaned up: height 0 has %d votes", len(oldVotes))
	}

	// Recent votes should still exist
	recentVotes := vh.GetVotes(uint64(numHeights-1), 0)
	if len(recentVotes) != numValidators {
		t.Errorf("Recent votes should exist: expected %d, got %d",
			numValidators, len(recentVotes))
	}
}

func TestByzantineDetectorMemoryCleanup(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 10000))
	}

	detector := trust.NewByzantineDetector(validators)

	// Record votes for many heights
	numHeights := 1000
	for height := uint64(0); height < uint64(numHeights); height++ {
		for _, kp := range keyPairs {
			vote := &types.Vote{
				BlockHash: types.Hash{byte(height % 256)},
				Height:    height,
				Round:     0,
				Voter:     kp.PublicKey,
			}
			detector.RecordVote(vote)
		}

		// Periodically cleanup
		if height > 100 && height%100 == 0 {
			detector.Cleanup(height, 100)
		}
	}
}

// ============================================================================
// SIGNATURE STRESS TESTS
// ============================================================================

func TestMassiveSignatureGeneration(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	numSigs := 10000

	start := time.Now()
	for i := 0; i < numSigs; i++ {
		message := []byte{byte(i % 256), byte((i >> 8) % 256)}
		_ = crypto.Sign(kp.SecretKey, message)
	}
	elapsed := time.Since(start)

	t.Logf("Generated %d signatures in %v (%.2f sigs/ms)",
		numSigs, elapsed, float64(numSigs)/float64(elapsed.Milliseconds()))
}

func TestMassiveSignatureVerification(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	numSigs := 10000

	// Pre-generate signatures
	messages := make([][]byte, numSigs)
	signatures := make([]types.Signature, numSigs)
	for i := 0; i < numSigs; i++ {
		messages[i] = []byte{byte(i % 256), byte((i >> 8) % 256)}
		signatures[i] = crypto.Sign(kp.SecretKey, messages[i])
	}

	start := time.Now()
	for i := 0; i < numSigs; i++ {
		crypto.Verify(kp.PublicKey, messages[i], signatures[i])
	}
	elapsed := time.Since(start)

	t.Logf("Verified %d signatures in %v (%.2f sigs/ms)",
		numSigs, elapsed, float64(numSigs)/float64(elapsed.Milliseconds()))
}

func TestMassiveAggregation(t *testing.T) {
	numValidators := 100
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 10000))
	}

	// Create block and votes
	block := types.NewBlock(0, 0, types.EmptyHash, keyPairs[0].PublicKey)
	votes := make([]*types.Vote, numValidators)
	for i, kp := range keyPairs {
		votes[i] = types.NewVote(block.Hash(), 0, 0, kp.PublicKey)
		votes[i].Signature = crypto.SignVote(kp.SecretKey, votes[i])
	}

	numAggregations := 1000

	start := time.Now()
	for i := 0; i < numAggregations; i++ {
		_ = crypto.AggregateVotes(block, votes, validators)
	}
	elapsed := time.Since(start)

	t.Logf("Performed %d aggregations of %d votes in %v (%.2f agg/ms)",
		numAggregations, numValidators, elapsed,
		float64(numAggregations)/float64(elapsed.Milliseconds()))
}

// ============================================================================
// HASH STRESS TESTS
// ============================================================================

func TestMassiveBlockHashing(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	numBlocks := 10000

	blocks := make([]*types.Block, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blocks[i] = types.NewBlock(uint64(i), 0, types.Hash{byte(i % 256)}, kp.PublicKey)
	}

	start := time.Now()
	for _, block := range blocks {
		_ = block.Hash()
	}
	elapsed := time.Since(start)

	t.Logf("Hashed %d blocks in %v (%.2f hashes/ms)",
		numBlocks, elapsed, float64(numBlocks)/float64(elapsed.Milliseconds()))
}

func TestMassiveMerkleRoot(t *testing.T) {
	numTrees := 1000
	txPerTree := 100

	// Pre-generate transactions
	trees := make([][]types.Transaction, numTrees)
	for i := 0; i < numTrees; i++ {
		trees[i] = make([]types.Transaction, txPerTree)
		for j := 0; j < txPerTree; j++ {
			trees[i][j] = types.Transaction{
				Amount: uint64(j),
				Nonce:  uint64(i),
			}
		}
	}

	start := time.Now()
	for i := 0; i < numTrees; i++ {
		_ = crypto.TransactionsMerkleRoot(trees[i])
	}
	elapsed := time.Since(start)

	t.Logf("Computed %d merkle roots (%d tx each) in %v (%.2f roots/ms)",
		numTrees, txPerTree, elapsed, float64(numTrees)/float64(elapsed.Milliseconds()))
}

// ============================================================================
// FINALIZATION STRESS TESTS
// ============================================================================

func TestRapidFinalization(t *testing.T) {
	validators := types.NewValidatorSet()
	numValidators := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numValidators)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	state := consensus.NewState()
	qc := consensus.NewQuorumCalculator(validators, config)
	finalizer := consensus.NewFinalizer(validators, state, qc)

	numBlocks := 1000
	finalizedCount := 0

	start := time.Now()
	for height := uint64(0); height < uint64(numBlocks); height++ {
		block := types.NewBlock(height, 0, types.Hash{byte(height % 256)}, keyPairs[0].PublicKey)
		block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

		// Create votes
		votes := make([]*types.Vote, numValidators)
		for i, kp := range keyPairs {
			votes[i] = types.NewVote(block.Hash(), height, 0, kp.PublicKey)
			votes[i].Signature = crypto.SignVote(kp.SecretKey, votes[i])
		}

		msg := finalizer.TryFinalize(block, votes)
		if msg != nil {
			finalizedCount++
		}
	}
	elapsed := time.Since(start)

	t.Logf("Finalized %d blocks in %v (%.2f blocks/ms)",
		finalizedCount, elapsed, float64(finalizedCount)/float64(elapsed.Milliseconds()))

	if finalizedCount != numBlocks {
		t.Errorf("Expected %d finalized, got %d", numBlocks, finalizedCount)
	}
}
