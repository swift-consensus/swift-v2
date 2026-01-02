package tests

import (
	"testing"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// FuzzQuorumCalculation tests the quorum calculator with random inputs
func FuzzQuorumCalculation(f *testing.F) {
	// Add seed corpus
	f.Add(uint64(10000), float64(0.5), uint64(5), uint64(10))
	f.Add(uint64(0), float64(0.0), uint64(0), uint64(0))
	f.Add(uint64(1000000000), float64(1.0), uint64(100), uint64(100))
	f.Add(uint64(1), float64(0.1), uint64(1), uint64(1))

	f.Fuzz(func(t *testing.T, totalStake uint64, avgTrust float64, onlineCount uint64, totalCount uint64) {
		// Validate inputs
		if totalCount == 0 || totalCount > 1000 || onlineCount > totalCount {
			t.Skip("Invalid input bounds")
		}
		if avgTrust < 0 || avgTrust > 1.0 {
			t.Skip("Invalid trust range")
		}
		if totalStake == 0 {
			t.Skip("Zero stake")
		}

		// Create validators
		validators := types.NewValidatorSet()
		stakePerValidator := totalStake / totalCount
		if stakePerValidator < types.MinStake {
			stakePerValidator = types.MinStake
		}

		for i := uint64(0); i < totalCount; i++ {
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				t.Skip("Key generation failed")
			}
			v := types.NewValidator(kp.PublicKey, stakePerValidator)
			v.Trust.BaseTrust = avgTrust
			v.Trust.RoundsActive = 1000
			v.Online = i < onlineCount
			validators.Add(v)
		}

		config := types.DefaultConfig()
		quorum := consensus.NewQuorumCalculator(validators, config)

		// Calculate quorum - should never panic
		onlineWeight := quorum.OnlineWeight()
		requiredQuorum := quorum.GetQuorum()

		// Basic invariants
		if requiredQuorum < 0 {
			t.Errorf("Negative required quorum: %f", requiredQuorum)
		}
		if onlineWeight < 0 {
			t.Errorf("Negative online weight: %f", onlineWeight)
		}

		// Check HasQuorum logic consistency
		hasQuorum := quorum.HasQuorum(onlineWeight)
		expectedQuorum := onlineWeight >= requiredQuorum
		if hasQuorum != expectedQuorum {
			t.Errorf("HasQuorum mismatch: got %v, weight %f >= required %f",
				hasQuorum, onlineWeight, requiredQuorum)
		}
	})
}

// FuzzSignatureVerification tests signature verification with random data
func FuzzSignatureVerification(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("test message"))
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte("a very long message that spans many bytes and tests the hashing"))

	f.Fuzz(func(t *testing.T, message []byte) {
		// Generate key pair
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		// Sign message
		sig := crypto.Sign(kp.SecretKey, message)

		// Valid signature should verify
		if !crypto.Verify(kp.PublicKey, message, sig) {
			t.Error("Valid signature failed verification")
		}

		// Different message should not verify
		if len(message) > 0 {
			modifiedMsg := append([]byte{}, message...)
			modifiedMsg[0] ^= 0xFF // Flip bits
			if crypto.Verify(kp.PublicKey, modifiedMsg, sig) {
				t.Error("Modified message incorrectly verified")
			}
		}

		// Different key should not verify
		kp2, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Second key generation failed")
		}
		if crypto.Verify(kp2.PublicKey, message, sig) {
			t.Error("Wrong key incorrectly verified")
		}
	})
}

// FuzzBlockSignature tests block signing and verification
func FuzzBlockSignature(f *testing.F) {
	// Add seed corpus
	f.Add(uint64(0), uint32(0), byte(0))
	f.Add(uint64(1000), uint32(5), byte(1))
	f.Add(uint64(18446744073709551615), uint32(4294967295), byte(255)) // Max values

	f.Fuzz(func(t *testing.T, height uint64, round uint32, parentByte byte) {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		parentHash := types.Hash{}
		parentHash[0] = parentByte

		block := types.NewBlock(height, round, parentHash, kp.PublicKey)
		block.Signature = crypto.SignBlock(kp.SecretKey, block)

		// Should verify
		if !crypto.VerifyBlock(block) {
			t.Error("Valid block signature failed verification")
		}

		// Modify block should not verify
		block.Height++
		if crypto.VerifyBlock(block) {
			t.Error("Modified block incorrectly verified")
		}
	})
}

// FuzzVoteSignature tests vote signing and verification
func FuzzVoteSignature(f *testing.F) {
	// Add seed corpus
	f.Add(uint64(0), uint32(0), byte(0))
	f.Add(uint64(1000), uint32(5), byte(1))

	f.Fuzz(func(t *testing.T, height uint64, round uint32, hashByte byte) {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		blockHash := types.Hash{}
		blockHash[0] = hashByte

		vote := &types.Vote{
			Height:    height,
			Round:     round,
			BlockHash: blockHash,
			Voter:     kp.PublicKey,
		}
		vote.Signature = crypto.SignVote(kp.SecretKey, vote)

		// Should verify
		if !crypto.VerifyVote(vote) {
			t.Error("Valid vote signature failed verification")
		}

		// Note: Vote signature only covers BlockHash, not height/round
		// Modify BlockHash should not verify
		vote.BlockHash[0] ^= 0xFF
		if crypto.VerifyVote(vote) {
			t.Error("Modified vote BlockHash incorrectly verified")
		}
	})
}

// FuzzViewChangeSignature tests view change signing and verification
func FuzzViewChangeSignature(f *testing.F) {
	// Add seed corpus
	f.Add(uint64(0), uint32(0))
	f.Add(uint64(1000), uint32(5))

	f.Fuzz(func(t *testing.T, height uint64, newRound uint32) {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		msg := &types.ViewChangeMsg{
			Height:   height,
			NewRound: newRound,
			Voter:    kp.PublicKey,
		}
		msg.Signature = crypto.SignViewChange(kp.SecretKey, msg)

		// Should verify
		if !crypto.VerifyViewChange(msg) {
			t.Error("Valid view change signature failed verification")
		}

		// Modify should not verify
		msg.Height++
		if crypto.VerifyViewChange(msg) {
			t.Error("Modified view change incorrectly verified")
		}
	})
}

// FuzzVotingWeight tests voting weight calculation
func FuzzVotingWeight(f *testing.F) {
	// Add seed corpus
	f.Add(uint64(types.MinStake), float64(0.5), uint64(100))
	f.Add(uint64(types.MinStake*1000), float64(1.0), uint64(1000))
	f.Add(uint64(types.MinStake), float64(0.0), uint64(0))

	f.Fuzz(func(t *testing.T, stake uint64, baseTrust float64, roundsActive uint64) {
		// Validate inputs
		if stake < types.MinStake || stake > 1e18 {
			t.Skip("Invalid stake")
		}
		if baseTrust < 0 || baseTrust > 1.0 {
			t.Skip("Invalid trust")
		}
		if roundsActive > 10000 {
			t.Skip("Too many rounds")
		}

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		v := types.NewValidator(kp.PublicKey, stake)
		v.Trust.BaseTrust = baseTrust
		v.Trust.RoundsActive = roundsActive

		// VotingWeight should never panic and should be non-negative
		weight := v.VotingWeight()
		if weight < 0 {
			t.Errorf("Negative voting weight: %f", weight)
		}

		// EffectiveTrust should be in [0, 1]
		effective := v.EffectiveTrust()
		if effective < 0 || effective > 1.0 {
			t.Errorf("EffectiveTrust out of range: %f", effective)
		}
	})
}

// FuzzTrustUpdates tests trust update operations
func FuzzTrustUpdates(f *testing.F) {
	// Add seed corpus
	f.Add(float64(0.5), int32(100), int32(50), int32(5))
	f.Add(float64(0.0), int32(0), int32(0), int32(0))
	f.Add(float64(1.0), int32(1000), int32(500), int32(100))

	f.Fuzz(func(t *testing.T, initialTrust float64, rewards int32, misses int32, byzantine int32) {
		// Validate inputs
		if initialTrust < 0 || initialTrust > 1.0 {
			t.Skip("Invalid initial trust")
		}
		if rewards < 0 || rewards > 10000 {
			t.Skip("Invalid rewards count")
		}
		if misses < 0 || misses > 10000 {
			t.Skip("Invalid misses count")
		}
		if byzantine < 0 || byzantine > 100 {
			t.Skip("Invalid byzantine count")
		}

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = initialTrust

		// Apply trust changes
		for i := int32(0); i < rewards; i++ {
			v.Trust.BaseTrust += types.TrustReward
			if v.Trust.BaseTrust > types.TrustMax {
				v.Trust.BaseTrust = types.TrustMax
			}
		}

		for i := int32(0); i < misses; i++ {
			v.Trust.BaseTrust -= types.TrustPenaltyMiss
			if v.Trust.BaseTrust < types.TrustMin {
				v.Trust.BaseTrust = types.TrustMin
			}
		}

		for i := int32(0); i < byzantine; i++ {
			v.Trust.BaseTrust -= types.TrustPenaltyByzantine
			if v.Trust.BaseTrust < types.TrustMin {
				v.Trust.BaseTrust = types.TrustMin
			}
		}

		// Trust should always be in [0, 1]
		if v.Trust.BaseTrust < 0 || v.Trust.BaseTrust > 1.0 {
			t.Errorf("Trust out of bounds: %f", v.Trust.BaseTrust)
		}
	})
}

// FuzzAggregateSignatures tests signature aggregation
func FuzzAggregateSignatures(f *testing.F) {
	// Add seed corpus
	f.Add(uint8(2), []byte("message"))
	f.Add(uint8(10), []byte("test"))
	f.Add(uint8(1), []byte{})

	f.Fuzz(func(t *testing.T, numSigners uint8, message []byte) {
		// Limit signers
		if numSigners == 0 || numSigners > 20 {
			t.Skip("Invalid signer count")
		}

		keyPairs := crypto.MustGenerateNKeyPairs(int(numSigners))
		sigs := make([]types.Signature, len(keyPairs))
		pks := make([]types.PublicKey, len(keyPairs))

		for i, kp := range keyPairs {
			sigs[i] = crypto.Sign(kp.SecretKey, message)
			pks[i] = kp.PublicKey
		}

		// Aggregate should not panic and should not error on valid signatures
		aggSig, err := crypto.AggregateSignatures(sigs)
		if err != nil {
			t.Errorf("AggregateSignatures failed on valid signatures: %v", err)
		}

		// Verify aggregated signature with all public keys
		if !crypto.VerifyAggregateSignature(pks, message, aggSig) {
			t.Error("Aggregated signature verification failed")
		}
	})
}

// FuzzVRF tests VRF generation and verification
func FuzzVRF(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("seed data"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	f.Fuzz(func(t *testing.T, seed []byte) {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Key generation failed")
		}

		// VRF should not panic
		output := crypto.VRFProve(kp.SecretKey, seed)

		// Output should be deterministic
		output2 := crypto.VRFProve(kp.SecretKey, seed)
		if output.Value != output2.Value {
			t.Error("VRF not deterministic")
		}

		// Should verify
		if !crypto.VRFVerify(kp.PublicKey, seed, output) {
			t.Error("VRF verification failed")
		}

		// Modified seed should not verify
		if len(seed) > 0 {
			modifiedSeed := append([]byte{}, seed...)
			modifiedSeed[0] ^= 0xFF
			if crypto.VRFVerify(kp.PublicKey, modifiedSeed, output) {
				t.Error("Modified VRF incorrectly verified")
			}
		}

		// Different key should not verify
		kp2, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Skip("Second key generation failed")
		}
		if crypto.VRFVerify(kp2.PublicKey, seed, output) {
			t.Error("Wrong key VRF incorrectly verified")
		}
	})
}
