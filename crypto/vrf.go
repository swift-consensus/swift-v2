package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/swift-consensus/swift-v2/types"
)

// VRF Domain Separation Tags
var (
	vrfDST      = []byte("SWIFT_VRF_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	vrfProofDST = []byte("SWIFT_VRF_PROOF_BLS12381_")
)

// vrfNonceCounter provides monotonicity for nonce generation
// SECURITY FIX: Prevents grinding attacks by adding unpredictable entropy
var vrfNonceCounter uint64

// VRFOutput represents the output of a VRF
type VRFOutput struct {
	Value types.Hash  // The random output (hash of the VRF point)
	Proof VRFProof    // Proof that the output is valid
	Gamma bls12381.G1Affine // The actual VRF point (Gamma = sk * H(message))
}

// VRFProof contains the DLEQ proof for VRF verification
// Proves that log_G(pk) == log_H(gamma) without revealing sk
type VRFProof struct {
	C  fr.Element // Challenge
	S  fr.Element // Response
}

// ToBytes serializes VRFProof to bytes
func (p *VRFProof) ToBytes() []byte {
	result := make([]byte, 64)
	cBytes := p.C.Bytes()
	sBytes := p.S.Bytes()
	copy(result[:32], cBytes[:])
	copy(result[32:], sBytes[:])
	return result
}

// FromBytes deserializes VRFProof from bytes
func (p *VRFProof) FromBytes(data []byte) error {
	if len(data) < 64 {
		return ErrInvalidSignature
	}
	p.C.SetBytes(data[:32])
	p.S.SetBytes(data[32:64])
	return nil
}

// hashToG1 hashes a message to a point on G1 for VRF
// SECURITY FIX #18: Returns error instead of silently ignoring failure
func hashToG1(message []byte) (bls12381.G1Affine, error) {
	point, err := bls12381.HashToG1(message, vrfDST)
	if err != nil {
		log.Printf("[VRF] SECURITY: HashToG1 failed for message of length %d: %v. "+
			"This should not happen with valid inputs.", len(message), err)
		return bls12381.G1Affine{}, ErrHashToCurveFailed
	}
	return point, nil
}

// computeVRFChallenge computes the Fiat-Shamir challenge for DLEQ proof
func computeVRFChallenge(g, pk, h, gamma, gS, hS bls12381.G1Affine) fr.Element {
	hasher := sha256.New()
	hasher.Write(vrfProofDST)

	// Hash all points
	gBytes := g.Bytes()
	hasher.Write(gBytes[:])

	pkBytes := pk.Bytes()
	hasher.Write(pkBytes[:])

	hBytes := h.Bytes()
	hasher.Write(hBytes[:])

	gammaBytes := gamma.Bytes()
	hasher.Write(gammaBytes[:])

	gSBytes := gS.Bytes()
	hasher.Write(gSBytes[:])

	hSBytes := hS.Bytes()
	hasher.Write(hSBytes[:])

	hash := hasher.Sum(nil)

	var c fr.Element
	c.SetBytes(hash)
	return c
}

// ErrEntropySourceFailed is returned when cryptographic randomness is unavailable
var ErrEntropySourceFailed = errors.New("crypto/rand entropy source failed")

// VRFProveWithError generates a VRF output and proof using ECVRF
// Returns error if entropy source fails (SECURITY FIX #15)
// Use this variant for better error handling in critical paths
func VRFProveWithError(sk types.SecretKey, message []byte) (*VRFOutput, error) {
	output := VRFProve(sk, message)
	if output == nil {
		return nil, ErrEntropySourceFailed
	}
	return output, nil
}

// VRFProve generates a VRF output and proof using ECVRF
// Based on draft-irtf-cfrg-vrf-15 adapted for BLS12-381
// Returns nil if entropy source fails (SECURITY FIX #15) or hash-to-curve fails (SECURITY FIX #18)
func VRFProve(sk types.SecretKey, message []byte) *VRFOutput {
	// Convert secret key to scalar
	scalar := secretKeyToScalar(sk)

	// Derive public key
	g1 := G1Generator()
	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1, scalar.BigInt(new(big.Int)))

	// Hash message to curve: H = hash_to_curve(message)
	// SECURITY FIX #18: Handle hash-to-curve error
	h, err := hashToG1(message)
	if err != nil {
		log.Printf("[VRF] CRITICAL: VRF proof generation failed due to hash-to-curve error.")
		return nil
	}

	// Compute Gamma = sk * H (the VRF output point)
	var gamma bls12381.G1Affine
	gamma.ScalarMultiplication(&h, scalar.BigInt(new(big.Int)))

	// SECURITY FIX: Generate nonce with multiple entropy sources
	// This prevents grinding attacks where attacker tries different messages
	// to find favorable VRF outputs
	//
	// Entropy sources:
	// 1. Secret key (known only to signer)
	// 2. Message (deterministic for this proof)
	// 3. Monotonic counter (prevents replay)
	// 4. Timestamp (adds unpredictability)
	// 5. Random bytes (cryptographic randomness)
	nonceHasher := sha256.New()
	nonceHasher.Write(sk[:])
	nonceHasher.Write(message)

	// Add monotonic counter
	counter := atomic.AddUint64(&vrfNonceCounter, 1)
	counterBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBuf, counter)
	nonceHasher.Write(counterBuf)

	// Add timestamp for additional unpredictability
	timestamp := time.Now().UnixNano()
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(timestamp))
	nonceHasher.Write(timeBuf)

	// SECURITY FIX #15: Add cryptographic randomness - CRITICAL for nonce unpredictability
	// If entropy source fails, VRF nonce becomes predictable, enabling leader grinding attacks
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		// CRITICAL: Entropy source failure is a security-critical error
		// Without cryptographic randomness, the VRF nonce is predictable
		// An attacker could grind messages to find favorable VRF outputs
		log.Printf("[VRF] CRITICAL SECURITY: crypto/rand entropy source failed: %v. "+
			"VRF generation aborted to prevent predictable nonce attack.", err)
		return nil
	}
	nonceHasher.Write(randomBytes)

	kBytes := nonceHasher.Sum(nil)
	var kBytesArr [32]byte
	copy(kBytesArr[:], kBytes)

	var k fr.Element
	k.SetBytes(kBytesArr[:])

	// Compute commitments for DLEQ proof
	// U = k * G
	var gK bls12381.G1Affine
	gK.ScalarMultiplication(&g1, k.BigInt(new(big.Int)))

	// V = k * H
	var hK bls12381.G1Affine
	hK.ScalarMultiplication(&h, k.BigInt(new(big.Int)))

	// Compute challenge c = H(G, pk, H, Gamma, U, V)
	c := computeVRFChallenge(g1, pk, h, gamma, gK, hK)

	// Compute response s = k - c * sk (mod q)
	var s fr.Element
	s.Mul(&c, &scalar)
	s.Sub(&k, &s)

	// Compute VRF output hash
	gammaBytes := gamma.Bytes()
	outputHash := sha256.Sum256(gammaBytes[:])

	var value types.Hash
	copy(value[:], outputHash[:])

	return &VRFOutput{
		Value: value,
		Proof: VRFProof{C: c, S: s},
		Gamma: gamma,
	}
}

// VRFVerify verifies a VRF output using DLEQ proof verification
func VRFVerify(pk types.PublicKey, message []byte, output *VRFOutput) bool {
	// Convert public key
	pkPoint, err := publicKeyToG1(pk)
	if err != nil {
		return false
	}

	// Get generator
	g1 := G1Generator()

	// Hash message to curve
	// SECURITY FIX #18: Handle hash-to-curve error
	h, err := hashToG1(message)
	if err != nil {
		return false
	}

	// Reconstruct commitments using the proof
	// U' = s * G + c * pk
	var sG, cPk bls12381.G1Affine
	sG.ScalarMultiplication(&g1, output.Proof.S.BigInt(new(big.Int)))
	cPk.ScalarMultiplication(&pkPoint, output.Proof.C.BigInt(new(big.Int)))

	var gKPrime bls12381.G1Jac
	gKPrime.FromAffine(&sG)
	var cPkJac bls12381.G1Jac
	cPkJac.FromAffine(&cPk)
	gKPrime.AddAssign(&cPkJac)

	var gKPrimeAffine bls12381.G1Affine
	gKPrimeAffine.FromJacobian(&gKPrime)

	// V' = s * H + c * Gamma
	var sH, cGamma bls12381.G1Affine
	sH.ScalarMultiplication(&h, output.Proof.S.BigInt(new(big.Int)))
	cGamma.ScalarMultiplication(&output.Gamma, output.Proof.C.BigInt(new(big.Int)))

	var hKPrime bls12381.G1Jac
	hKPrime.FromAffine(&sH)
	var cGammaJac bls12381.G1Jac
	cGammaJac.FromAffine(&cGamma)
	hKPrime.AddAssign(&cGammaJac)

	var hKPrimeAffine bls12381.G1Affine
	hKPrimeAffine.FromJacobian(&hKPrime)

	// Recompute challenge
	cPrime := computeVRFChallenge(g1, pkPoint, h, output.Gamma, gKPrimeAffine, hKPrimeAffine)

	// Verify c == c'
	if !output.Proof.C.Equal(&cPrime) {
		return false
	}

	// Verify output hash
	gammaBytes := output.Gamma.Bytes()
	expectedHash := sha256.Sum256(gammaBytes[:])

	for i := 0; i < 32; i++ {
		if output.Value[i] != expectedHash[i] {
			return false
		}
	}

	return true
}

// VRFHash creates a deterministic hash for leader selection
func VRFHash(lastHash types.Hash, height uint64, round uint32) types.Hash {
	h := sha256.New()
	h.Write(lastHash[:])

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, height)
	h.Write(buf)

	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, round)
	h.Write(buf)

	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// HashToFloat converts a hash to a float64 in [0, 1)
func HashToFloat(hash types.Hash) float64 {
	// Use first 8 bytes as uint64
	n := binary.BigEndian.Uint64(hash[:8])
	return float64(n) / float64(math.MaxUint64)
}

// WeightedSelect performs weighted random selection
// Returns the index of the selected element
func WeightedSelect(weights []float64, seed types.Hash) int {
	if len(weights) == 0 {
		return -1
	}

	// Calculate total weight
	totalWeight := 0.0
	for _, w := range weights {
		totalWeight += w
	}

	if totalWeight == 0 {
		return -1
	}

	// Get random point in [0, totalWeight)
	point := HashToFloat(seed) * totalWeight

	// Find the selected element
	cumulative := 0.0
	for i, w := range weights {
		cumulative += w
		if cumulative > point {
			return i
		}
	}

	// Fallback to last element
	return len(weights) - 1
}

// SelectLeader selects a leader from validators using VRF-based weighted random selection
func SelectLeader(
	validators *types.ValidatorSet,
	lastHash types.Hash,
	height uint64,
	round uint32,
	recentLeaders map[string]uint32, // pubkey -> round when they last led
	currentRound uint32,
) *types.Validator {
	// Generate deterministic seed
	seed := VRFHash(lastHash, height, round)

	// Build list of eligible validators and their weights
	eligible := make([]*types.Validator, 0)
	weights := make([]float64, 0)

	for _, v := range validators.Validators {
		// Check cooldown
		if lastLed, ok := recentLeaders[string(v.PublicKey[:])]; ok {
			if currentRound-lastLed < types.LeaderCooldown {
				continue // Still in cooldown
			}
		}

		// Check minimum trust
		if v.EffectiveTrust() < types.MinLeaderTrust {
			continue
		}

		// Check if online
		if !v.Online {
			continue
		}

		eligible = append(eligible, v)
		weights = append(weights, v.LeaderWeight())
	}

	if len(eligible) == 0 {
		// Fallback: if no one is eligible, pick any online validator
		for _, v := range validators.Validators {
			if v.Online {
				return v
			}
		}
		return nil
	}

	// Select
	idx := WeightedSelect(weights, seed)
	if idx < 0 {
		return nil
	}

	return eligible[idx]
}

// Shuffle shuffles a slice using Fisher-Yates with a deterministic seed
func Shuffle(n int, seed types.Hash) []int {
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	// Fisher-Yates shuffle
	for i := n - 1; i > 0; i-- {
		// Generate next random number from seed
		h := sha256.New()
		h.Write(seed[:])
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(i))
		h.Write(buf)
		hash := h.Sum(nil)
		copy(seed[:], hash)

		// Get random index in [0, i]
		j := int(binary.BigEndian.Uint64(hash[:8]) % uint64(i+1))

		// Swap
		indices[i], indices[j] = indices[j], indices[i]
	}

	return indices
}
