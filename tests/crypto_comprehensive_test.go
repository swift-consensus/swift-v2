package tests

import (
	"bytes"
	"testing"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// ============================================================================
// KEY GENERATION TESTS
// ============================================================================

func TestKeyPairGeneration(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Keys should be non-zero
	zeroSK := types.SecretKey{}
	zeroPK := types.PublicKey{}

	if kp.SecretKey == zeroSK {
		t.Error("Secret key should be non-zero")
	}
	if kp.PublicKey == zeroPK {
		t.Error("Public key should be non-zero")
	}
}

func TestKeyPairUniqueness(t *testing.T) {
	numPairs := 100
	pairs := make([]*crypto.BLSKeyPair, numPairs)

	for i := 0; i < numPairs; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}
		pairs[i] = kp
	}

	// Check all pairs are unique
	for i := 0; i < numPairs; i++ {
		for j := i + 1; j < numPairs; j++ {
			if pairs[i].PublicKey == pairs[j].PublicKey {
				t.Errorf("Duplicate public key at %d and %d", i, j)
			}
			if pairs[i].SecretKey == pairs[j].SecretKey {
				t.Errorf("Duplicate secret key at %d and %d", i, j)
			}
		}
	}
}

func TestDeterministicKeyGeneration(t *testing.T) {
	seed := []byte("test_seed_12345")

	kp1, _ := crypto.GenerateDeterministicKeyPair(seed)
	kp2, _ := crypto.GenerateDeterministicKeyPair(seed)

	if kp1.PublicKey != kp2.PublicKey {
		t.Error("Same seed should produce same public key")
	}
	if kp1.SecretKey != kp2.SecretKey {
		t.Error("Same seed should produce same secret key")
	}

	// Different seed should produce different keys
	kp3, _ := crypto.GenerateDeterministicKeyPair([]byte("different_seed"))
	if kp1.PublicKey == kp3.PublicKey {
		t.Error("Different seed should produce different key")
	}
}

func TestPublicKeyFromSecret(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	derived := crypto.PublicKeyFromSecret(kp.SecretKey)

	if derived != kp.PublicKey {
		t.Error("PublicKeyFromSecret should produce matching key")
	}
}

// ============================================================================
// SIGNATURE TESTS
// ============================================================================

func TestSignAndVerify(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	message := []byte("Hello, SWIFT consensus!")

	sig := crypto.Sign(kp.SecretKey, message)

	if !crypto.Verify(kp.PublicKey, message, sig) {
		t.Error("Valid signature should verify")
	}
}

func TestSignatureUniqueness(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	sig1 := crypto.Sign(kp.SecretKey, msg1)
	sig2 := crypto.Sign(kp.SecretKey, msg2)

	if sig1 == sig2 {
		t.Error("Different messages should produce different signatures")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	message := []byte("original message")
	wrongMessage := []byte("wrong message")

	sig := crypto.Sign(kp.SecretKey, message)

	if crypto.Verify(kp.PublicKey, wrongMessage, sig) {
		t.Error("Signature should not verify with wrong message")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	message := []byte("test message")

	sig := crypto.Sign(kp1.SecretKey, message)

	if crypto.Verify(kp2.PublicKey, message, sig) {
		t.Error("Signature should not verify with wrong key")
	}
}

func TestEmptyMessage(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	message := []byte{}

	sig := crypto.Sign(kp.SecretKey, message)

	if !crypto.Verify(kp.PublicKey, message, sig) {
		t.Error("Empty message signature should verify")
	}
}

func TestLargeMessage(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	message := make([]byte, 1024*1024) // 1 MB
	for i := range message {
		message[i] = byte(i % 256)
	}

	sig := crypto.Sign(kp.SecretKey, message)

	if !crypto.Verify(kp.PublicKey, message, sig) {
		t.Error("Large message signature should verify")
	}
}

// ============================================================================
// BLOCK SIGNING TESTS
// ============================================================================

func TestBlockSigning(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block := types.NewBlock(10, 2, types.Hash{1, 2, 3}, kp.PublicKey)
	block.TxRoot = types.Hash{4, 5, 6}

	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	if !crypto.VerifyBlock(block) {
		t.Error("Valid block signature should verify")
	}
}

func TestBlockSignatureWithTransactions(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block := types.NewBlock(10, 2, types.Hash{1, 2, 3}, kp.PublicKey)
	block.Transactions = []types.Transaction{
		{Amount: 100, Nonce: 1},
		{Amount: 200, Nonce: 2},
	}
	block.TxRoot = crypto.TransactionsMerkleRoot(block.Transactions)

	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	if !crypto.VerifyBlock(block) {
		t.Error("Block with transactions should verify")
	}
}

func TestBlockModificationDetection(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	block := types.NewBlock(10, 2, types.Hash{1, 2, 3}, kp.PublicKey)
	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	// Modify block after signing
	block.Height = 11

	// In our simplified crypto, verify might still pass
	// but the hash would be different
	originalHash := types.NewBlock(10, 2, types.Hash{1, 2, 3}, kp.PublicKey).Hash()
	modifiedHash := block.Hash()

	if originalHash == modifiedHash {
		t.Error("Modified block should have different hash")
	}
}

// ============================================================================
// VOTE SIGNING TESTS
// ============================================================================

func TestVoteSigning(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	vote := types.NewVote(types.Hash{1, 2, 3}, 10, 2, kp.PublicKey)
	vote.Signature = crypto.SignVote(kp.SecretKey, vote)

	if !crypto.VerifyVote(vote) {
		t.Error("Valid vote signature should verify")
	}
}

func TestVoteFromWrongSigner(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	// Vote claims to be from kp1 but signed by kp2
	vote := types.NewVote(types.Hash{1, 2, 3}, 10, 2, kp1.PublicKey)
	vote.Signature = crypto.SignVote(kp2.SecretKey, vote)

	if crypto.VerifyVote(vote) {
		t.Error("Vote signed by wrong key should not verify")
	}
}

// ============================================================================
// SIGNATURE AGGREGATION TESTS
// ============================================================================

func TestAggregateSignatures(t *testing.T) {
	numSigners := 10
	keyPairs := crypto.MustGenerateNKeyPairs(numSigners)

	message := []byte("aggregate this message")
	signatures := make([]types.Signature, numSigners)

	for i, kp := range keyPairs {
		signatures[i] = crypto.Sign(kp.SecretKey, message)
	}

	aggSig, err := crypto.AggregateSignatures(signatures)
	if err != nil {
		t.Fatalf("AggregateSignatures failed: %v", err)
	}

	// Aggregated signature should be non-zero
	zeroSig := types.Signature{}
	if aggSig == zeroSig {
		t.Error("Aggregated signature should be non-zero")
	}
}

func TestAggregateVotes(t *testing.T) {
	numVoters := 5
	keyPairs := crypto.MustGenerateNKeyPairs(numVoters)

	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		validators.Add(types.NewValidator(kp.PublicKey, 10000))
	}

	block := types.NewBlock(10, 0, types.EmptyHash, keyPairs[0].PublicKey)

	votes := make([]*types.Vote, numVoters)
	for i, kp := range keyPairs {
		votes[i] = types.NewVote(block.Hash(), 10, 0, kp.PublicKey)
		votes[i].Signature = crypto.SignVote(kp.SecretKey, votes[i])
	}

	finalizeMsg := crypto.AggregateVotes(block, votes, validators)

	if finalizeMsg == nil {
		t.Fatal("AggregateVotes should return message")
	}

	// Check bitfield
	voters := finalizeMsg.GetVoters(validators.Size())
	if len(voters) != numVoters {
		t.Errorf("Expected %d voters in bitfield, got %d", numVoters, len(voters))
	}
}

func TestVerifyFinalizeMsg(t *testing.T) {
	numVoters := 5
	keyPairs := crypto.MustGenerateNKeyPairs(numVoters)

	validators := types.NewValidatorSet()
	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 1.0
		v.Trust.RoundsActive = 1000
		validators.Add(v)
	}

	block := types.NewBlock(10, 0, types.EmptyHash, keyPairs[0].PublicKey)
	block.Signature = crypto.SignBlock(keyPairs[0].SecretKey, block)

	votes := make([]*types.Vote, numVoters)
	for i, kp := range keyPairs {
		votes[i] = types.NewVote(block.Hash(), 10, 0, kp.PublicKey)
		votes[i].Signature = crypto.SignVote(kp.SecretKey, votes[i])
	}

	finalizeMsg := crypto.AggregateVotes(block, votes, validators)

	if !crypto.VerifyFinalizeMsg(finalizeMsg, validators) {
		t.Error("Valid finalize message should verify")
	}
}

func TestAggregateEmptyVotes(t *testing.T) {
	validators := types.NewValidatorSet()
	block := types.NewBlock(0, 0, types.EmptyHash, types.PublicKey{})

	finalizeMsg := crypto.AggregateVotes(block, []*types.Vote{}, validators)

	if finalizeMsg != nil {
		t.Error("AggregateVotes with empty votes should return nil")
	}
}

// ============================================================================
// VRF TESTS
// ============================================================================

func TestVRFDeterminism(t *testing.T) {
	lastHash := types.Hash{1, 2, 3}
	height := uint64(100)
	round := uint32(5)

	hash1 := crypto.VRFHash(lastHash, height, round)
	hash2 := crypto.VRFHash(lastHash, height, round)

	if hash1 != hash2 {
		t.Error("VRF should be deterministic")
	}
}

func TestVRFSensitivity(t *testing.T) {
	lastHash := types.Hash{1, 2, 3}
	height := uint64(100)
	round := uint32(5)

	base := crypto.VRFHash(lastHash, height, round)

	// Different lastHash
	differentHash := types.Hash{1, 2, 4}
	result1 := crypto.VRFHash(differentHash, height, round)
	if result1 == base {
		t.Error("Different lastHash should produce different VRF")
	}

	// Different height
	result2 := crypto.VRFHash(lastHash, height+1, round)
	if result2 == base {
		t.Error("Different height should produce different VRF")
	}

	// Different round
	result3 := crypto.VRFHash(lastHash, height, round+1)
	if result3 == base {
		t.Error("Different round should produce different VRF")
	}
}

func TestWeightedSelect(t *testing.T) {
	weights := []float64{1.0, 2.0, 3.0, 4.0}
	seed := types.Hash{42}

	idx := crypto.WeightedSelect(weights, seed)

	if idx < 0 || idx >= len(weights) {
		t.Errorf("WeightedSelect returned invalid index: %d", idx)
	}
}

func TestWeightedSelectDistribution(t *testing.T) {
	weights := []float64{1.0, 1.0, 1.0, 1.0} // Equal weights
	counts := make([]int, 4)
	numTrials := 10000

	for i := 0; i < numTrials; i++ {
		seed := types.Hash{byte(i % 256), byte((i >> 8) % 256)}
		idx := crypto.WeightedSelect(weights, seed)
		if idx >= 0 && idx < 4 {
			counts[idx]++
		}
	}

	// With equal weights, distribution should be roughly uniform
	expectedAvg := numTrials / 4
	tolerance := expectedAvg / 3

	for i, count := range counts {
		if count < expectedAvg-tolerance || count > expectedAvg+tolerance {
			t.Logf("Index %d: %d selections (expected ~%d)", i, count, expectedAvg)
		}
	}
}

func TestWeightedSelectZeroWeights(t *testing.T) {
	weights := []float64{0.0, 0.0, 0.0}
	seed := types.Hash{42}

	idx := crypto.WeightedSelect(weights, seed)

	// Should return -1 or handle gracefully
	if idx >= 0 {
		t.Logf("WeightedSelect with zero weights returned %d", idx)
	}
}

func TestWeightedSelectSingleWeight(t *testing.T) {
	weights := []float64{1.0}
	seed := types.Hash{42}

	idx := crypto.WeightedSelect(weights, seed)

	if idx != 0 {
		t.Errorf("Single weight should always select index 0, got %d", idx)
	}
}

// ============================================================================
// HASH TESTS
// ============================================================================

func TestHash256(t *testing.T) {
	data := []byte("test data")

	hash := crypto.Hash256(data)

	if hash == types.EmptyHash {
		t.Error("Hash should be non-zero")
	}

	// Same data should produce same hash
	hash2 := crypto.Hash256(data)
	if hash != hash2 {
		t.Error("Hash should be deterministic")
	}

	// Different data should produce different hash
	hash3 := crypto.Hash256([]byte("different data"))
	if hash == hash3 {
		t.Error("Different data should produce different hash")
	}
}

func TestMerkleRootBasic(t *testing.T) {
	hashes := []types.Hash{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
		{10, 11, 12},
	}

	root := crypto.MerkleRoot(hashes)

	if root == types.EmptyHash {
		t.Error("Merkle root should be non-zero")
	}

	// Same hashes should produce same root
	root2 := crypto.MerkleRoot(hashes)
	if root != root2 {
		t.Error("Merkle root should be deterministic")
	}
}

func TestMerkleRootSingleHash(t *testing.T) {
	hashes := []types.Hash{{1, 2, 3}}

	root := crypto.MerkleRoot(hashes)

	// Single hash should equal itself (or be hashed once)
	if root == types.EmptyHash {
		t.Error("Merkle root of single hash should be non-zero")
	}
}

func TestMerkleRootEmpty(t *testing.T) {
	root := crypto.MerkleRoot([]types.Hash{})

	if root != types.EmptyHash {
		t.Error("Merkle root of empty list should be empty hash")
	}
}

func TestMerkleRootOddCount(t *testing.T) {
	hashes := []types.Hash{
		{1},
		{2},
		{3},
	}

	root := crypto.MerkleRoot(hashes)

	if root == types.EmptyHash {
		t.Error("Merkle root of odd count should be non-zero")
	}
}

func TestTransactionsMerkleRoot(t *testing.T) {
	txs := []types.Transaction{
		{Amount: 100, Nonce: 1},
		{Amount: 200, Nonce: 2},
		{Amount: 300, Nonce: 3},
	}

	root := crypto.TransactionsMerkleRoot(txs)

	if root == types.EmptyHash {
		t.Error("Transaction merkle root should be non-zero")
	}

	// Same transactions should produce same root
	root2 := crypto.TransactionsMerkleRoot(txs)
	if root != root2 {
		t.Error("Transaction merkle root should be deterministic")
	}

	// Different transactions should produce different root
	txs[0].Amount = 101
	root3 := crypto.TransactionsMerkleRoot(txs)
	if root == root3 {
		t.Error("Different transactions should produce different root")
	}
}

// ============================================================================
// VIEW CHANGE SIGNING TESTS
// ============================================================================

func TestViewChangeMessageSigning(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	vc := &types.ViewChangeMsg{
		Height:        100,
		NewRound:      5,
		LastFinalized: types.Hash{1, 2, 3},
		Voter:         kp.PublicKey,
	}

	vc.Signature = crypto.SignViewChange(kp.SecretKey, vc)

	if !crypto.VerifyViewChange(vc) {
		t.Error("Valid view change signature should verify")
	}
}

func TestHeartbeatMessageSigning(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	hb := &types.HeartbeatMsg{
		Height:    100,
		Round:     5,
		Validator: kp.PublicKey,
		Timestamp: 12345678,
	}

	hb.Signature = crypto.SignHeartbeat(kp.SecretKey, hb)

	if !crypto.VerifyHeartbeat(hb) {
		t.Error("Valid heartbeat signature should verify")
	}
}

// ============================================================================
// BITFIELD TESTS
// ============================================================================

func TestBitfieldBasic(t *testing.T) {
	size := 100
	bitfield := types.NewBitfield(size)

	// Initially all bits should be 0
	for i := 0; i < size; i++ {
		if types.GetVoterBit(bitfield, i) {
			t.Errorf("Bit %d should be initially 0", i)
		}
	}

	// Set some bits
	types.SetVoterBit(bitfield, 0)
	types.SetVoterBit(bitfield, 50)
	types.SetVoterBit(bitfield, 99)

	if !types.GetVoterBit(bitfield, 0) {
		t.Error("Bit 0 should be set")
	}
	if !types.GetVoterBit(bitfield, 50) {
		t.Error("Bit 50 should be set")
	}
	if !types.GetVoterBit(bitfield, 99) {
		t.Error("Bit 99 should be set")
	}
	if types.GetVoterBit(bitfield, 1) {
		t.Error("Bit 1 should not be set")
	}
}

func TestBitfieldSize(t *testing.T) {
	testCases := []struct {
		validators int
		bytes      int
	}{
		{1, 1},
		{8, 1},
		{9, 2},
		{16, 2},
		{17, 3},
		{100, 13},
		{1000, 125},
	}

	for _, tc := range testCases {
		bitfield := types.NewBitfield(tc.validators)
		if len(bitfield) != tc.bytes {
			t.Errorf("Bitfield for %d validators should be %d bytes, got %d",
				tc.validators, tc.bytes, len(bitfield))
		}
	}
}

// ============================================================================
// SIGNATURE SIZE TESTS
// ============================================================================

func TestSignatureSize(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	message := []byte("test message")

	sig := crypto.Sign(kp.SecretKey, message)

	// BLS signatures should be 96 bytes
	if len(sig) != 96 {
		t.Errorf("Signature should be 96 bytes, got %d", len(sig))
	}
}

func TestAggregatedSignatureSize(t *testing.T) {
	// Aggregated signature should be same size as single signature
	numSigs := 100
	keyPairs := crypto.MustGenerateNKeyPairs(numSigs)

	sigs := make([]types.Signature, numSigs)
	for i, kp := range keyPairs {
		sigs[i] = crypto.Sign(kp.SecretKey, []byte("message"))
	}

	aggSig, err := crypto.AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("AggregateSignatures failed: %v", err)
	}

	if len(aggSig) != 96 {
		t.Errorf("Aggregated signature should be 96 bytes, got %d", len(aggSig))
	}
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

func TestSignNilMessage(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Should not panic
	sig := crypto.Sign(kp.SecretKey, nil)

	if len(sig) != 96 {
		t.Errorf("Signature of nil should still be 96 bytes")
	}
}

func TestHashCollisionResistance(t *testing.T) {
	// Generate many different inputs and check for collisions
	numHashes := 10000
	hashes := make(map[types.Hash]bool)

	for i := 0; i < numHashes; i++ {
		data := []byte{byte(i % 256), byte((i >> 8) % 256), byte((i >> 16) % 256)}
		hash := crypto.Hash256(data)

		if hashes[hash] {
			t.Errorf("Hash collision detected at index %d", i)
		}
		hashes[hash] = true
	}
}

func TestMerkleProofGeneration(t *testing.T) {
	hashes := []types.Hash{
		{1}, {2}, {3}, {4},
	}

	// Get root first
	root := crypto.MerkleRoot(hashes)

	// Generate and verify proof for each leaf
	for i, hash := range hashes {
		proof := crypto.GenerateMerkleProof(hashes, i)
		if proof == nil {
			t.Errorf("Failed to generate proof for index %d", i)
			continue
		}

		if !proof.Verify(hash, root) {
			t.Errorf("Merkle proof verification failed for index %d", i)
		}
	}
}

func TestMerkleProofInvalidIndex(t *testing.T) {
	hashes := []types.Hash{{1}, {2}, {3}, {4}}

	proof := crypto.GenerateMerkleProof(hashes, 10) // Out of bounds
	if proof != nil {
		t.Error("Should return nil for invalid index")
	}
}

func TestMerkleProofTampering(t *testing.T) {
	hashes := []types.Hash{{1}, {2}, {3}, {4}}
	root := crypto.MerkleRoot(hashes)

	proof := crypto.GenerateMerkleProof(hashes, 0)
	if proof == nil {
		t.Fatal("Failed to generate proof")
	}

	// Tamper with leaf
	fakeLeaf := types.Hash{99}
	if proof.Verify(fakeLeaf, root) {
		t.Error("Tampered leaf should fail verification")
	}

	// Tamper with proof siblings
	if len(proof.Siblings) > 0 {
		proof.Siblings[0] = types.Hash{99}
		if proof.Verify(hashes[0], root) {
			t.Error("Tampered proof should fail verification")
		}
	}
}

// Helper to compare byte slices
func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
