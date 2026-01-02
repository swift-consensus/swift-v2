package types

import (
	"encoding/hex"
	"math"
)

// PublicKey represents a BLS public key (48 bytes)
type PublicKey [48]byte

// Signature represents a BLS signature (96 bytes)
type Signature [96]byte

// SecretKey represents a BLS secret key (32 bytes)
type SecretKey [32]byte

// String returns the hex representation of a public key
func (pk PublicKey) String() string {
	return hex.EncodeToString(pk[:])
}

// Short returns a short representation of a public key
func (pk PublicKey) Short() string {
	s := pk.String()
	if len(s) > 8 {
		return s[:8] + "..."
	}
	return s
}

// Equal checks if two public keys are equal
func (pk PublicKey) Equal(other PublicKey) bool {
	return pk == other
}

// IsZero returns true if the public key is all zeros
func (pk PublicKey) IsZero() bool {
	for _, b := range pk {
		if b != 0 {
			return false
		}
	}
	return true
}

// TrustInfo holds trust-related information for a validator
type TrustInfo struct {
	BaseTrust    float64     // Current base trust score [0, 1]
	RoundsActive uint64      // Number of rounds this validator has been active
	Vouchers     []PublicKey // Validators who vouched for this validator
	OffenseCount int         // Number of Byzantine offenses
	LastVoteRound uint64     // Last round the validator voted
}

// Validator represents a validator in the SWIFT network
type Validator struct {
	PublicKey PublicKey // BLS public key
	Stake     uint64    // Staked amount
	Trust     TrustInfo // Trust information
	Balance   uint64    // Reward balance
	Online    bool      // Whether validator is considered online
}

// NewValidator creates a new validator
func NewValidator(pubKey PublicKey, stake uint64) *Validator {
	return &Validator{
		PublicKey: pubKey,
		Stake:     stake,
		Trust: TrustInfo{
			BaseTrust:    InitialTrust,
			RoundsActive: 0,
			Vouchers:     make([]PublicKey, 0),
			OffenseCount: 0,
		},
		Balance: 0,
		Online:  true,
	}
}

// TrustCeiling calculates the maximum trust this validator can have
func (v *Validator) TrustCeiling() float64 {
	// Base ceiling from tenure
	var base float64
	switch {
	case v.Trust.RoundsActive < 100:
		base = CeilingRound100
	case v.Trust.RoundsActive < 250:
		base = CeilingRound250
	case v.Trust.RoundsActive < 500:
		base = CeilingRound500
	case v.Trust.RoundsActive < 1000:
		base = CeilingRound1000
	default:
		base = CeilingMax
	}

	// Vouching bonus (capped)
	vouchBonus := math.Min(MaxVouchBonus, float64(len(v.Trust.Vouchers))*VouchBonus)

	return math.Min(TrustMax, base+vouchBonus)
}

// EffectiveTrust returns the effective trust (bounded by ceiling)
func (v *Validator) EffectiveTrust() float64 {
	return math.Min(v.Trust.BaseTrust, v.TrustCeiling())
}

// VotingWeight calculates the validator's voting weight
func (v *Validator) VotingWeight() float64 {
	if v.Stake < MinStake {
		return 0
	}

	// Log scale for stake (reduces whale dominance)
	stakeWeight := math.Log2(float64(v.Stake)/float64(MinStake) + 1)

	// Multiply by effective trust
	return stakeWeight * v.EffectiveTrust()
}

// CanLead returns true if the validator can be a leader
func (v *Validator) CanLead(roundsSinceLastLead uint32) bool {
	return v.EffectiveTrust() >= MinLeaderTrust &&
		roundsSinceLastLead >= LeaderCooldown &&
		v.Online
}

// LeaderWeight returns the trust used for leader selection (capped)
func (v *Validator) LeaderWeight() float64 {
	return math.Min(v.EffectiveTrust(), LeaderTrustCap)
}

// ValidatorSet represents the set of all validators
type ValidatorSet struct {
	Validators []*Validator          // Ordered list of validators
	ByPubKey   map[string]*Validator // Index by public key
}

// NewValidatorSet creates a new validator set
func NewValidatorSet() *ValidatorSet {
	return &ValidatorSet{
		Validators: make([]*Validator, 0),
		ByPubKey:   make(map[string]*Validator),
	}
}

// Add adds a validator to the set
func (vs *ValidatorSet) Add(v *Validator) {
	key := string(v.PublicKey[:])
	if _, exists := vs.ByPubKey[key]; exists {
		return // Already exists
	}
	vs.Validators = append(vs.Validators, v)
	vs.ByPubKey[key] = v
}

// Remove removes a validator from the set
func (vs *ValidatorSet) Remove(pubKey PublicKey) {
	key := string(pubKey[:])
	delete(vs.ByPubKey, key)

	for i, v := range vs.Validators {
		if v.PublicKey == pubKey {
			vs.Validators = append(vs.Validators[:i], vs.Validators[i+1:]...)
			break
		}
	}
}

// Get retrieves a validator by public key
func (vs *ValidatorSet) Get(pubKey PublicKey) *Validator {
	return vs.ByPubKey[string(pubKey[:])]
}

// GetByIndex retrieves a validator by index
func (vs *ValidatorSet) GetByIndex(index int) *Validator {
	if index < 0 || index >= len(vs.Validators) {
		return nil
	}
	return vs.Validators[index]
}

// IndexOf returns the index of a validator
func (vs *ValidatorSet) IndexOf(pubKey PublicKey) int {
	for i, v := range vs.Validators {
		if v.PublicKey == pubKey {
			return i
		}
	}
	return -1
}

// Size returns the number of validators
func (vs *ValidatorSet) Size() int {
	return len(vs.Validators)
}

// TotalStake returns the total stake of all validators
func (vs *ValidatorSet) TotalStake() uint64 {
	var total uint64
	for _, v := range vs.Validators {
		total += v.Stake
	}
	return total
}

// TotalVotingWeight returns the total voting weight of all validators
func (vs *ValidatorSet) TotalVotingWeight() float64 {
	var total float64
	for _, v := range vs.Validators {
		total += v.VotingWeight()
	}
	return total
}

// OnlineVotingWeight returns the voting weight of online validators
func (vs *ValidatorSet) OnlineVotingWeight() float64 {
	var total float64
	for _, v := range vs.Validators {
		if v.Online {
			total += v.VotingWeight()
		}
	}
	return total
}

// GetPublicKeys returns all public keys
func (vs *ValidatorSet) GetPublicKeys() []PublicKey {
	keys := make([]PublicKey, len(vs.Validators))
	for i, v := range vs.Validators {
		keys[i] = v.PublicKey
	}
	return keys
}
