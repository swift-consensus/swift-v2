// Package crypto provides cryptographic primitives for SWIFT v2 consensus.
// This package implements BLS12-381 signatures using gnark-crypto.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/swift-consensus/swift-v2/types"
)

var (
	// ErrInvalidSignature is returned when signature verification fails
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidPublicKey is returned when a public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrSignatureMismatch is returned when signatures don't match
	ErrSignatureMismatch = errors.New("signature mismatch")

	// Domain separation tag for BLS signatures
	dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_SWIFT_V2")
)

// BLSKeyPair represents a BLS key pair
type BLSKeyPair struct {
	SecretKey types.SecretKey
	PublicKey types.PublicKey
	// Internal representations for crypto operations
	sk fr.Element
	pk bls12381.G1Affine
}

// G1Generator returns the generator point for G1
func G1Generator() bls12381.G1Affine {
	_, _, g1, _ := bls12381.Generators()
	return g1
}

// GenerateKeyPair generates a new BLS key pair using real BLS12-381
func GenerateKeyPair() (*BLSKeyPair, error) {
	return GenerateKeyPairWithReader(rand.Reader)
}

// GenerateKeyPairWithReader generates a BLS key pair using a specific random source
func GenerateKeyPairWithReader(reader io.Reader) (*BLSKeyPair, error) {
	// Generate random secret key scalar
	var sk fr.Element
	var skBytes [32]byte
	if _, err := io.ReadFull(reader, skBytes[:]); err != nil {
		return nil, err
	}
	sk.SetBytes(skBytes[:])

	// Compute public key: pk = sk * G1
	g1 := G1Generator()
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1, sk.BigInt(new(big.Int)))

	// Convert to our types
	var secretKey types.SecretKey
	skBytesFinal := sk.Bytes()
	copy(secretKey[:], skBytesFinal[:])

	var publicKey types.PublicKey
	pkBytes := pk.Bytes()
	copy(publicKey[:], pkBytes[:])

	return &BLSKeyPair{
		SecretKey: secretKey,
		PublicKey: publicKey,
		sk:        sk,
		pk:        pk,
	}, nil
}

// secretKeyToScalar converts our SecretKey type to fr.Element
func secretKeyToScalar(sk types.SecretKey) fr.Element {
	var scalar fr.Element
	scalar.SetBytes(sk[:])
	return scalar
}

// publicKeyToG1 converts our PublicKey type to G1Affine
func publicKeyToG1(pk types.PublicKey) (bls12381.G1Affine, error) {
	var g1 bls12381.G1Affine
	_, err := g1.SetBytes(pk[:])
	if err != nil {
		return g1, ErrInvalidPublicKey
	}
	return g1, nil
}

// signatureToG2 converts our Signature type to G2Affine
func signatureToG2(sig types.Signature) (bls12381.G2Affine, error) {
	var g2 bls12381.G2Affine
	_, err := g2.SetBytes(sig[:])
	if err != nil {
		return g2, ErrInvalidSignature
	}
	return g2, nil
}

// ErrHashToCurveFailed is returned when hash-to-curve operation fails
var ErrHashToCurveFailed = errors.New("hash-to-curve operation failed")

// hashToG2 hashes a message to a point on G2 using the domain separation tag
// SECURITY FIX #18: Returns error instead of silently ignoring failure
func hashToG2(message []byte) (bls12381.G2Affine, error) {
	point, err := bls12381.HashToG2(message, dst)
	if err != nil {
		log.Printf("[BLS] SECURITY: HashToG2 failed for message of length %d: %v. "+
			"This should not happen with valid inputs.", len(message), err)
		return bls12381.G2Affine{}, ErrHashToCurveFailed
	}
	return point, nil
}

// Sign signs a message using BLS12-381
// Signature = sk * H(message) where H maps to G2
// SECURITY FIX #18: Returns zero signature if hash-to-curve fails
func Sign(sk types.SecretKey, message []byte) types.Signature {
	// Convert secret key to scalar
	scalar := secretKeyToScalar(sk)

	// Hash message to G2
	msgPoint, err := hashToG2(message)
	if err != nil {
		// SECURITY: Return zero signature - will fail verification
		log.Printf("[BLS] CRITICAL: Signing failed due to hash-to-curve error. Returning zero signature.")
		return types.Signature{}
	}

	// Compute signature: sig = sk * H(msg)
	var sig bls12381.G2Affine
	sig.ScalarMultiplication(&msgPoint, scalar.BigInt(new(big.Int)))

	// Convert to our type
	var signature types.Signature
	sigBytes := sig.Bytes()
	copy(signature[:], sigBytes[:])

	return signature
}

// Verify verifies a BLS signature using pairing check
// Verifies: e(pk, H(msg)) == e(G1, sig)
func Verify(pk types.PublicKey, message []byte, sig types.Signature) bool {
	// Check for zero signature
	allZero := true
	for _, b := range sig {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Convert public key
	pkPoint, err := publicKeyToG1(pk)
	if err != nil {
		return false
	}

	// Convert signature
	sigPoint, err := signatureToG2(sig)
	if err != nil {
		return false
	}

	// Hash message to G2
	// SECURITY FIX #18: Handle hash-to-curve error
	msgPoint, err := hashToG2(message)
	if err != nil {
		return false
	}

	// Get G1 generator
	g1 := G1Generator()
	var g1Neg bls12381.G1Affine
	g1Neg.Neg(&g1)

	// Verify pairing: e(pk, H(msg)) * e(-G1, sig) == 1
	// Equivalent to: e(pk, H(msg)) == e(G1, sig)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pkPoint, g1Neg},
		[]bls12381.G2Affine{msgPoint, sigPoint},
	)
	if err != nil {
		return false
	}

	return ok
}

// SignBlock signs a block with a secret key
func SignBlock(sk types.SecretKey, block *types.Block) types.Signature {
	blockHash := block.Hash()
	return Sign(sk, blockHash[:])
}

// VerifyBlock verifies a block's signature
func VerifyBlock(block *types.Block) bool {
	blockHash := block.Hash()
	return Verify(block.Proposer, blockHash[:], block.Signature)
}

// SignVote signs a vote with a secret key
// SECURITY: Signs full message including Height and Round to prevent replay attacks
func SignVote(sk types.SecretKey, vote *types.Vote) types.Signature {
	return Sign(sk, vote.SigningMessage())
}

// VerifyVote verifies a vote's signature
// SECURITY: Verifies against full message including Height and Round
func VerifyVote(vote *types.Vote) bool {
	return Verify(vote.Voter, vote.SigningMessage(), vote.Signature)
}

// SignViewChange signs a view change message
func SignViewChange(sk types.SecretKey, vc *types.ViewChangeMsg) types.Signature {
	return Sign(sk, vc.SigningMessage())
}

// VerifyViewChange verifies a view change message signature
func VerifyViewChange(vc *types.ViewChangeMsg) bool {
	return Verify(vc.Voter, vc.SigningMessage(), vc.Signature)
}

// SignHeartbeat signs a heartbeat message
func SignHeartbeat(sk types.SecretKey, hb *types.HeartbeatMsg) types.Signature {
	return Sign(sk, hb.SigningMessage())
}

// VerifyHeartbeat verifies a heartbeat message signature
func VerifyHeartbeat(hb *types.HeartbeatMsg) bool {
	return Verify(hb.Validator, hb.SigningMessage(), hb.Signature)
}

// VerifyEquivocationProof verifies an equivocation proof is valid
// SECURITY: This verifies BOTH signatures to prevent forgery attacks
// An attacker cannot create a fake proof to slash honest validators
func VerifyEquivocationProof(proof *types.EquivocationProof) bool {
	// First check structural validity
	if !proof.IsValid() {
		return false
	}

	// CRITICAL: Verify both signatures
	// Without this, attackers could forge proofs with garbage signatures
	if !VerifyVote(&proof.Vote1) {
		return false
	}
	if !VerifyVote(&proof.Vote2) {
		return false
	}

	return true
}

// PublicKeyFromSecret derives a public key from a secret key
func PublicKeyFromSecret(sk types.SecretKey) types.PublicKey {
	scalar := secretKeyToScalar(sk)
	g1 := G1Generator()
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1, scalar.BigInt(new(big.Int)))

	var publicKey types.PublicKey
	pkBytes := pk.Bytes()
	copy(publicKey[:], pkBytes[:])
	return publicKey
}

// GenerateDeterministicKeyPair generates a deterministic key pair from a seed
func GenerateDeterministicKeyPair(seed []byte) (*BLSKeyPair, error) {
	// Hash seed to get 32 bytes
	h := sha256.Sum256(seed)

	var sk fr.Element
	sk.SetBytes(h[:])

	// Compute public key
	g1 := G1Generator()
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1, sk.BigInt(new(big.Int)))

	var secretKey types.SecretKey
	skBytes := sk.Bytes()
	copy(secretKey[:], skBytes[:])

	var publicKey types.PublicKey
	pkBytes := pk.Bytes()
	copy(publicKey[:], pkBytes[:])

	return &BLSKeyPair{
		SecretKey: secretKey,
		PublicKey: publicKey,
		sk:        sk,
		pk:        pk,
	}, nil
}

// GenerateNKeyPairs generates n key pairs deterministically for testing
// SECURITY FIX #19: Returns error instead of silently ignoring key generation failures
func GenerateNKeyPairs(n int) ([]*BLSKeyPair, error) {
	pairs := make([]*BLSKeyPair, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, 8)
		binary.BigEndian.PutUint64(seed, uint64(i))
		kp, err := GenerateDeterministicKeyPair(seed)
		if err != nil {
			return nil, err
		}
		pairs[i] = kp
	}
	return pairs, nil
}

// MustGenerateNKeyPairs is a helper for tests that panics on error
// Use GenerateNKeyPairs for production code that requires proper error handling
func MustGenerateNKeyPairs(n int) []*BLSKeyPair {
	pairs, err := GenerateNKeyPairs(n)
	if err != nil {
		panic("GenerateNKeyPairs failed: " + err.Error())
	}
	return pairs
}
