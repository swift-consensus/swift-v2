package crypto

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/swift-consensus/swift-v2/types"
)

// ErrInvalidSignatureInAggregate is returned when aggregation includes invalid signatures
var ErrInvalidSignatureInAggregate = errors.New("invalid signature in aggregate")

// AggregateSignatures aggregates multiple BLS signatures into one
// Uses real BLS12-381 point addition on G2
// SECURITY: Returns error if ANY signature is invalid to prevent vote padding attacks
func AggregateSignatures(signatures []types.Signature) (types.Signature, error) {
	if len(signatures) == 0 {
		return types.Signature{}, nil
	}

	if len(signatures) == 1 {
		// Validate the single signature before returning
		_, err := signatureToG2(signatures[0])
		if err != nil {
			return types.Signature{}, ErrInvalidSignatureInAggregate
		}
		return signatures[0], nil
	}

	// Convert first signature to G2 point
	var aggPoint bls12381.G2Affine
	firstSig, err := signatureToG2(signatures[0])
	if err != nil {
		return types.Signature{}, ErrInvalidSignatureInAggregate
	}
	aggPoint = firstSig

	// Add remaining signatures (in Jacobian for efficiency)
	var aggJac bls12381.G2Jac
	aggJac.FromAffine(&aggPoint)

	for i := 1; i < len(signatures); i++ {
		sigPoint, err := signatureToG2(signatures[i])
		if err != nil {
			// SECURITY: Do NOT silently skip - fail the entire aggregation
			return types.Signature{}, ErrInvalidSignatureInAggregate
		}
		var sigJac bls12381.G2Jac
		sigJac.FromAffine(&sigPoint)
		aggJac.AddAssign(&sigJac)
	}

	// Convert back to affine
	aggPoint.FromJacobian(&aggJac)

	// Convert to our type
	var aggSig types.Signature
	sigBytes := aggPoint.Bytes()
	copy(aggSig[:], sigBytes[:])

	return aggSig, nil
}

// AggregatePublicKeys aggregates multiple public keys into one
// Used for batch verification optimization
// SECURITY: Returns error if ANY public key is invalid to prevent key manipulation attacks
func AggregatePublicKeys(publicKeys []types.PublicKey) (types.PublicKey, error) {
	if len(publicKeys) == 0 {
		return types.PublicKey{}, ErrInvalidPublicKey
	}

	if len(publicKeys) == 1 {
		// Validate the single key before returning
		_, err := publicKeyToG1(publicKeys[0])
		if err != nil {
			return types.PublicKey{}, ErrInvalidPublicKey
		}
		return publicKeys[0], nil
	}

	// Convert first public key to G1 point
	var aggPoint bls12381.G1Affine
	firstPk, err := publicKeyToG1(publicKeys[0])
	if err != nil {
		return types.PublicKey{}, err
	}
	aggPoint = firstPk

	// Add remaining public keys (in Jacobian for efficiency)
	var aggJac bls12381.G1Jac
	aggJac.FromAffine(&aggPoint)

	for i := 1; i < len(publicKeys); i++ {
		pkPoint, err := publicKeyToG1(publicKeys[i])
		if err != nil {
			// SECURITY: Do NOT silently skip - fail the entire aggregation
			return types.PublicKey{}, ErrInvalidPublicKey
		}
		var pkJac bls12381.G1Jac
		pkJac.FromAffine(&pkPoint)
		aggJac.AddAssign(&pkJac)
	}

	// Convert back to affine
	aggPoint.FromJacobian(&aggJac)

	// Convert to our type
	var aggPk types.PublicKey
	pkBytes := aggPoint.Bytes()
	copy(aggPk[:], pkBytes[:])

	return aggPk, nil
}

// VerifyAggregateSignature verifies an aggregated signature against multiple public keys
// All public keys must have signed the same message
// Uses real BLS pairing verification: e(aggPk, H(msg)) == e(G1, aggSig)
func VerifyAggregateSignature(publicKeys []types.PublicKey, message []byte, aggSig types.Signature) bool {
	if len(publicKeys) == 0 {
		return false
	}

	// Check for zero signature
	allZero := true
	for _, b := range aggSig {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Aggregate public keys
	aggPk, err := AggregatePublicKeys(publicKeys)
	if err != nil {
		return false
	}

	// Verify aggregated signature with aggregated public key
	return Verify(aggPk, message, aggSig)
}

// VerifyAggregateSignatureDistinct verifies an aggregated signature where each signer
// signed a different message. Uses multi-pairing for efficiency.
func VerifyAggregateSignatureDistinct(publicKeys []types.PublicKey, messages [][]byte, aggSig types.Signature) bool {
	if len(publicKeys) != len(messages) || len(publicKeys) == 0 {
		return false
	}

	// Convert aggregated signature
	sigPoint, err := signatureToG2(aggSig)
	if err != nil {
		return false
	}

	// Build pairing arguments
	// We verify: ∏ e(pk_i, H(msg_i)) == e(G1, aggSig)
	// Which is: ∏ e(pk_i, H(msg_i)) * e(-G1, aggSig) == 1
	g1Points := make([]bls12381.G1Affine, len(publicKeys)+1)
	g2Points := make([]bls12381.G2Affine, len(publicKeys)+1)

	for i, pk := range publicKeys {
		pkPoint, err := publicKeyToG1(pk)
		if err != nil {
			return false
		}
		g1Points[i] = pkPoint
		// SECURITY FIX #18: Handle hash-to-curve error
		g2Point, err := hashToG2(messages[i])
		if err != nil {
			return false
		}
		g2Points[i] = g2Point
	}

	// Add negative G1 generator paired with aggregated signature
	g1 := G1Generator()
	var g1Neg bls12381.G1Affine
	g1Neg.Neg(&g1)
	g1Points[len(publicKeys)] = g1Neg
	g2Points[len(publicKeys)] = sigPoint

	// Multi-pairing check
	ok, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false
	}

	return ok
}

// AggregateVotes aggregates votes and creates a finalization message
// SECURITY: Returns nil if any signature is invalid (no silent failures)
func AggregateVotes(block *types.Block, votes []*types.Vote, validators *types.ValidatorSet) *types.FinalizeMsg {
	if len(votes) == 0 {
		return nil
	}

	// Collect signatures
	signatures := make([]types.Signature, len(votes))
	for i, vote := range votes {
		signatures[i] = vote.Signature
	}

	// Aggregate - fail if any signature is invalid
	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		return nil // SECURITY: Do not create finalize message with invalid signatures
	}

	// Create bitfield
	bitfield := types.NewBitfield(validators.Size())
	for _, vote := range votes {
		idx := validators.IndexOf(vote.Voter)
		if idx >= 0 {
			types.SetVoterBit(bitfield, idx)
		}
	}

	return &types.FinalizeMsg{
		Block:         *block,
		AggSignature:  aggSig,
		VoterBitfield: bitfield,
	}
}

// VerifyFinalizeMsg verifies a finalization message
// SECURITY: Verifies against signing message (BlockHash || Height || Round) not just hash
func VerifyFinalizeMsg(msg *types.FinalizeMsg, validators *types.ValidatorSet) bool {
	// Get public keys of voters
	voterIndices := msg.GetVoters(validators.Size())
	if len(voterIndices) == 0 {
		return false
	}

	publicKeys := make([]types.PublicKey, len(voterIndices))
	for i, idx := range voterIndices {
		v := validators.GetByIndex(idx)
		if v == nil {
			return false
		}
		publicKeys[i] = v.PublicKey
	}

	// Verify aggregate signature using the correct signing message
	// Votes are signed with BlockHash || Height || Round
	vote := &types.Vote{
		BlockHash: msg.Block.Hash(),
		Height:    msg.Block.Height,
		Round:     msg.Block.Round,
	}
	return VerifyAggregateSignature(publicKeys, vote.SigningMessage(), msg.AggSignature)
}

// AggregateViewChanges aggregates view change messages
// SECURITY: Returns nil if any signature is invalid (no silent failures)
func AggregateViewChanges(messages []*types.ViewChangeMsg, validators *types.ValidatorSet) *types.ViewChangeCert {
	if len(messages) == 0 {
		return nil
	}

	// Collect signatures
	signatures := make([]types.Signature, len(messages))
	for i, msg := range messages {
		signatures[i] = msg.Signature
	}

	// Aggregate - fail if any signature is invalid
	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		return nil // SECURITY: Do not create certificate with invalid signatures
	}

	// Create bitfield
	bitfield := types.NewBitfield(validators.Size())
	for _, msg := range messages {
		idx := validators.IndexOf(msg.Voter)
		if idx >= 0 {
			types.SetVoterBit(bitfield, idx)
		}
	}

	return &types.ViewChangeCert{
		Height:       messages[0].Height,
		Round:        messages[0].NewRound,
		Messages:     messages,
		AggSignature: aggSig,
		Bitfield:     bitfield,
	}
}

// VerifyViewChangeCert verifies a view change certificate
func VerifyViewChangeCert(cert *types.ViewChangeCert, validators *types.ValidatorSet) bool {
	if len(cert.Messages) == 0 {
		return false
	}

	// Get public keys and messages for aggregate verification
	publicKeys := make([]types.PublicKey, len(cert.Messages))
	messages := make([][]byte, len(cert.Messages))

	for i, msg := range cert.Messages {
		v := validators.Get(msg.Voter)
		if v == nil {
			return false
		}
		publicKeys[i] = msg.Voter
		messages[i] = msg.SigningMessage()
	}

	// Use distinct message verification since each view change message is different
	return VerifyAggregateSignatureDistinct(publicKeys, messages, cert.AggSignature)
}
