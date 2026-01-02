package tests

import (
	"testing"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/stake"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// ISSUE #1: Vote Signature Height/Round Binding Tests
// ============================================================================

// TestVoteSignatureIncludesHeightRound verifies that vote signatures
// are bound to height and round, preventing replay attacks
func TestVoteSignatureIncludesHeightRound(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	blockHash := types.Hash{1, 2, 3, 4, 5}

	// Create and sign a vote at height 10, round 0
	vote := &types.Vote{
		BlockHash: blockHash,
		Height:    10,
		Round:     0,
		Voter:     kp.PublicKey,
	}
	vote.Signature = crypto.SignVote(kp.SecretKey, vote)

	// Original vote should verify
	if !crypto.VerifyVote(vote) {
		t.Fatal("Original vote should verify")
	}

	t.Run("replay_different_height_fails", func(t *testing.T) {
		// Try to replay at different height (same block hash)
		replayVote := &types.Vote{
			BlockHash: blockHash, // Same block hash
			Height:    11,        // Different height
			Round:     0,
			Voter:     kp.PublicKey,
			Signature: vote.Signature, // Reuse original signature
		}

		if crypto.VerifyVote(replayVote) {
			t.Error("SECURITY VULNERABILITY: Vote replay at different height should NOT verify")
		}
	})

	t.Run("replay_different_round_fails", func(t *testing.T) {
		// Try to replay at different round (same block hash)
		replayVote := &types.Vote{
			BlockHash: blockHash, // Same block hash
			Height:    10,        // Same height
			Round:     5,         // Different round
			Voter:     kp.PublicKey,
			Signature: vote.Signature, // Reuse original signature
		}

		if crypto.VerifyVote(replayVote) {
			t.Error("SECURITY VULNERABILITY: Vote replay at different round should NOT verify")
		}
	})

	t.Run("same_params_verifies", func(t *testing.T) {
		// Create identical vote - should verify with same signature
		identicalVote := &types.Vote{
			BlockHash: blockHash,
			Height:    10,
			Round:     0,
			Voter:     kp.PublicKey,
			Signature: vote.Signature,
		}

		if !crypto.VerifyVote(identicalVote) {
			t.Error("Identical vote should verify")
		}
	})

	t.Run("different_block_fails", func(t *testing.T) {
		// Different block hash should not verify
		differentBlockVote := &types.Vote{
			BlockHash: types.Hash{9, 9, 9}, // Different hash
			Height:    10,
			Round:     0,
			Voter:     kp.PublicKey,
			Signature: vote.Signature,
		}

		if crypto.VerifyVote(differentBlockVote) {
			t.Error("Vote with different block hash should NOT verify")
		}
	})
}

// TestVoteSigningMessageUniqueness verifies that signing messages
// are unique for different height/round combinations
func TestVoteSigningMessageUniqueness(t *testing.T) {
	blockHash := types.Hash{1, 2, 3}
	voter := types.PublicKey{4, 5, 6}

	vote1 := &types.Vote{BlockHash: blockHash, Height: 10, Round: 0, Voter: voter}
	vote2 := &types.Vote{BlockHash: blockHash, Height: 10, Round: 1, Voter: voter}
	vote3 := &types.Vote{BlockHash: blockHash, Height: 11, Round: 0, Voter: voter}

	msg1 := vote1.SigningMessage()
	msg2 := vote2.SigningMessage()
	msg3 := vote3.SigningMessage()

	// All messages should be different
	if string(msg1) == string(msg2) {
		t.Error("Signing messages for different rounds should be different")
	}
	if string(msg1) == string(msg3) {
		t.Error("Signing messages for different heights should be different")
	}
	if string(msg2) == string(msg3) {
		t.Error("Signing messages should be unique")
	}

	// Same vote should produce same message
	vote1Copy := &types.Vote{BlockHash: blockHash, Height: 10, Round: 0, Voter: voter}
	if string(vote1.SigningMessage()) != string(vote1Copy.SigningMessage()) {
		t.Error("Identical votes should produce identical signing messages")
	}
}

// TestCrossRoundVoteReplayAttack simulates a realistic attack scenario
func TestCrossRoundVoteReplayAttack(t *testing.T) {
	// Setup: 4 validators, need 3 for quorum (67%)
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	blockHash := types.Hash{1, 1, 1, 1}

	// Round 0: Validator 0 votes for block
	originalVote := &types.Vote{
		BlockHash: blockHash,
		Height:    100,
		Round:     0,
		Voter:     keyPairs[0].PublicKey,
	}
	originalVote.Signature = crypto.SignVote(keyPairs[0].SecretKey, originalVote)

	// Verify original vote works
	if !crypto.VerifyVote(originalVote) {
		t.Fatal("Original vote should verify")
	}

	// Attack scenario: View change happens, same block proposed in round 5
	// Attacker tries to replay validator 0's vote from round 0

	attackVote := &types.Vote{
		BlockHash: blockHash,          // Same block
		Height:    100,                 // Same height
		Round:     5,                   // Different round (after view change)
		Voter:     keyPairs[0].PublicKey,
		Signature: originalVote.Signature, // REPLAYED signature
	}

	// This MUST fail to prevent the attack
	if crypto.VerifyVote(attackVote) {
		t.Fatal("CRITICAL SECURITY FAILURE: Cross-round vote replay attack succeeded!")
	}

	// Legitimate vote for round 5 should still work
	legitimateVote := &types.Vote{
		BlockHash: blockHash,
		Height:    100,
		Round:     5,
		Voter:     keyPairs[0].PublicKey,
	}
	legitimateVote.Signature = crypto.SignVote(keyPairs[0].SecretKey, legitimateVote)

	if !crypto.VerifyVote(legitimateVote) {
		t.Error("Legitimate vote for new round should verify")
	}
}

// ============================================================================
// ISSUE #2: Equivocation Proof Signature Verification Tests
// ============================================================================

// TestEquivocationProofRequiresValidSignatures verifies that equivocation
// proofs must have valid signatures to be considered valid
func TestEquivocationProofRequiresValidSignatures(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	victimPK := kp.PublicKey

	// Create two fake votes with garbage signatures
	fakeVote1 := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    100,
		Round:     5,
		Voter:     victimPK,
		Signature: types.Signature{0xFF, 0xFF, 0xFF}, // Garbage
	}

	fakeVote2 := &types.Vote{
		BlockHash: types.Hash{4, 5, 6}, // Different block
		Height:    100,
		Round:     5,
		Voter:     victimPK,
		Signature: types.Signature{0xAA, 0xBB, 0xCC}, // Garbage
	}

	proof := &types.EquivocationProof{
		Vote1: *fakeVote1,
		Vote2: *fakeVote2,
	}

	// Structural validation should pass (same voter, same height/round, different blocks)
	if !proof.IsValid() {
		t.Error("Structural validation should pass for well-formed proof")
	}

	// But cryptographic verification should FAIL due to invalid signatures
	if crypto.VerifyEquivocationProof(proof) {
		t.Fatal("SECURITY VULNERABILITY: Forged equivocation proof was accepted!")
	}

	// Individual votes should not verify
	if crypto.VerifyVote(&proof.Vote1) {
		t.Error("Fake vote 1 should not verify")
	}
	if crypto.VerifyVote(&proof.Vote2) {
		t.Error("Fake vote 2 should not verify")
	}
}

// TestEquivocationProofWithValidSignatures verifies legitimate proofs work
func TestEquivocationProofWithValidSignatures(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Create two REAL votes with valid signatures (actual equivocation)
	vote1 := &types.Vote{
		BlockHash: types.Hash{1, 2, 3},
		Height:    100,
		Round:     5,
		Voter:     kp.PublicKey,
	}
	vote1.Signature = crypto.SignVote(kp.SecretKey, vote1)

	vote2 := &types.Vote{
		BlockHash: types.Hash{4, 5, 6}, // Different block
		Height:    100,
		Round:     5,
		Voter:     kp.PublicKey,
	}
	vote2.Signature = crypto.SignVote(kp.SecretKey, vote2)

	proof := &types.EquivocationProof{
		Vote1: *vote1,
		Vote2: *vote2,
	}

	// Both individual votes should verify
	if !crypto.VerifyVote(&proof.Vote1) {
		t.Error("Vote1 should have valid signature")
	}
	if !crypto.VerifyVote(&proof.Vote2) {
		t.Error("Vote2 should have valid signature")
	}

	// Structural validation should pass
	if !proof.IsValid() {
		t.Error("Structural validation should pass")
	}

	// Full cryptographic verification should pass
	if !crypto.VerifyEquivocationProof(proof) {
		t.Error("Legitimate equivocation proof with valid signatures should verify")
	}
}

// TestEquivocationProofSlashingRejectsForgedProofs verifies the slasher
// rejects forged equivocation proofs
func TestEquivocationProofSlashingRejectsForgedProofs(t *testing.T) {
	// Setup validator set and slasher
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	validators.Add(v)

	config := types.DefaultConfig()
	manager, err := stake.NewManager(validators, config)
	if err != nil {
		t.Fatal(err)
	}
	slasher := stake.NewSlasher(manager, validators, config)

	initialStake := v.Stake

	// Create forged proof (garbage signatures)
	forgedProof := &types.EquivocationProof{
		Vote1: types.Vote{
			BlockHash: types.Hash{1, 2, 3},
			Height:    100,
			Round:     5,
			Voter:     kp.PublicKey,
			Signature: types.Signature{0xFF, 0xFF}, // Garbage
		},
		Vote2: types.Vote{
			BlockHash: types.Hash{4, 5, 6},
			Height:    100,
			Round:     5,
			Voter:     kp.PublicKey,
			Signature: types.Signature{0xAA, 0xBB}, // Garbage
		},
	}

	// Slasher should reject forged proof
	slashAmount := slasher.SlashForEquivocation(forgedProof, 100)
	if slashAmount != 0 {
		t.Errorf("Forged proof should not result in slashing, got slashAmount=%d", slashAmount)
	}

	// Validator stake should be unchanged
	if v.Stake != initialStake {
		t.Errorf("Validator stake should be unchanged after forged proof, got %d want %d", v.Stake, initialStake)
	}
}

// ============================================================================
// ISSUE #3: Aggregate Signature Silent Skip Tests
// ============================================================================

// TestAggregateSignaturesRejectsInvalid verifies that aggregate signature
// fails on ANY invalid signature (no silent skipping)
func TestAggregateSignaturesRejectsInvalid(t *testing.T) {
	keyPairs := crypto.MustGenerateNKeyPairs(5)
	message := []byte("test message")

	// Create valid signatures
	signatures := make([]types.Signature, 5)
	for i, kp := range keyPairs {
		signatures[i] = crypto.Sign(kp.SecretKey, message)
	}

	t.Run("all_valid_succeeds", func(t *testing.T) {
		aggSig, err := crypto.AggregateSignatures(signatures)
		if err != nil {
			t.Errorf("Aggregation of valid signatures should succeed: %v", err)
		}

		// Aggregated signature should be non-zero
		zeroSig := types.Signature{}
		if aggSig == zeroSig {
			t.Error("Aggregated signature should be non-zero")
		}
	})

	t.Run("one_invalid_fails", func(t *testing.T) {
		// Copy signatures and corrupt one
		corruptSigs := make([]types.Signature, 5)
		copy(corruptSigs, signatures)
		corruptSigs[2] = types.Signature{0xFF, 0xFF, 0xFF} // Garbage signature

		_, err := crypto.AggregateSignatures(corruptSigs)
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Aggregation should fail with invalid signature")
		}
	})

	t.Run("first_invalid_fails", func(t *testing.T) {
		corruptSigs := make([]types.Signature, 5)
		copy(corruptSigs, signatures)
		corruptSigs[0] = types.Signature{0xAA, 0xBB, 0xCC} // Corrupt first signature

		_, err := crypto.AggregateSignatures(corruptSigs)
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Aggregation should fail with invalid first signature")
		}
	})

	t.Run("last_invalid_fails", func(t *testing.T) {
		corruptSigs := make([]types.Signature, 5)
		copy(corruptSigs, signatures)
		corruptSigs[4] = types.Signature{0x11, 0x22, 0x33} // Corrupt last signature

		_, err := crypto.AggregateSignatures(corruptSigs)
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Aggregation should fail with invalid last signature")
		}
	})

	t.Run("empty_signature_fails", func(t *testing.T) {
		corruptSigs := make([]types.Signature, 5)
		copy(corruptSigs, signatures)
		corruptSigs[3] = types.Signature{} // Empty signature

		_, err := crypto.AggregateSignatures(corruptSigs)
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Aggregation should fail with empty signature")
		}
	})
}

// TestAggregateVotesRejectsInvalid verifies that AggregateVotes returns nil
// when any vote has an invalid signature (prevents vote padding attack)
func TestAggregateVotesRejectsInvalid(t *testing.T) {
	keyPairs := crypto.MustGenerateNKeyPairs(4)
	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 10000))
	}

	block := types.NewBlock(100, 5, types.EmptyHash, keyPairs[0].PublicKey)

	// Create votes with valid signatures
	votes := make([]*types.Vote, 4)
	for i, kp := range keyPairs {
		vote := types.NewVote(block.Hash(), 100, 5, kp.PublicKey)
		vote.Signature = crypto.SignVote(kp.SecretKey, vote)
		votes[i] = vote
	}

	t.Run("all_valid_succeeds", func(t *testing.T) {
		msg := crypto.AggregateVotes(block, votes, validators)
		if msg == nil {
			t.Error("AggregateVotes should succeed with valid votes")
		}
	})

	t.Run("one_invalid_returns_nil", func(t *testing.T) {
		// Corrupt one vote's signature
		corruptVotes := make([]*types.Vote, 4)
		for i, v := range votes {
			corruptVote := *v
			corruptVotes[i] = &corruptVote
		}
		corruptVotes[2].Signature = types.Signature{0xFF, 0xFF} // Garbage

		msg := crypto.AggregateVotes(block, corruptVotes, validators)
		if msg != nil {
			t.Error("SECURITY VULNERABILITY: AggregateVotes should return nil with invalid signature")
		}
	})
}

// TestVotePaddingAttackPrevented tests the vote padding attack scenario
// Attacker tries to include garbage signatures to inflate vote count
func TestVotePaddingAttackPrevented(t *testing.T) {
	// Setup: 4 validators, need 3 for quorum (67%)
	keyPairs := crypto.MustGenerateNKeyPairs(4)
	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		validators.Add(v)
	}

	block := types.NewBlock(100, 5, types.EmptyHash, keyPairs[0].PublicKey)

	// Attacker has only 2 valid votes (not enough for quorum)
	validVotes := make([]*types.Vote, 2)
	for i := 0; i < 2; i++ {
		vote := types.NewVote(block.Hash(), 100, 5, keyPairs[i].PublicKey)
		vote.Signature = crypto.SignVote(keyPairs[i].SecretKey, vote)
		validVotes[i] = vote
	}

	// Attacker tries to pad with garbage signatures
	paddedVotes := make([]*types.Vote, 4)
	paddedVotes[0] = validVotes[0]
	paddedVotes[1] = validVotes[1]
	// Fake votes with garbage signatures
	paddedVotes[2] = &types.Vote{
		BlockHash: block.Hash(),
		Height:    100,
		Round:     5,
		Voter:     keyPairs[2].PublicKey,
		Signature: types.Signature{0xFF, 0xFF, 0xFF}, // Garbage
	}
	paddedVotes[3] = &types.Vote{
		BlockHash: block.Hash(),
		Height:    100,
		Round:     5,
		Voter:     keyPairs[3].PublicKey,
		Signature: types.Signature{0xAA, 0xBB, 0xCC}, // Garbage
	}

	// Attack should fail - aggregation should reject the garbage signatures
	msg := crypto.AggregateVotes(block, paddedVotes, validators)
	if msg != nil {
		t.Fatal("CRITICAL SECURITY FAILURE: Vote padding attack succeeded!")
	}
}
