package trust

import (
	"errors"
	"sync"

	"github.com/swift-consensus/swift-v2/types"
)

var (
	// ErrInvalidVoucher is returned when voucher doesn't meet requirements
	ErrInvalidVoucher = errors.New("voucher does not meet minimum trust requirement")

	// ErrSelfVouch is returned when trying to vouch for oneself
	ErrSelfVouch = errors.New("cannot vouch for oneself")

	// ErrAlreadyVouched is returned when already vouching for validator
	ErrAlreadyVouched = errors.New("already vouching for this validator")

	// ErrVoucherNotFound is returned when voucher is not a validator
	ErrVoucherNotFound = errors.New("voucher is not a validator")

	// ErrVoucheeNotFound is returned when vouchee is not a validator
	ErrVoucheeNotFound = errors.New("vouchee is not a validator")
)

// VouchRecord represents a vouching relationship
type VouchRecord struct {
	Voucher     types.PublicKey
	Vouchee     types.PublicKey
	RoundMade   uint64
	VoucherTrustAtVouch float64
}

// VouchingManager manages vouching relationships
type VouchingManager struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet

	// vouches tracks who has vouched for whom
	// map[vouchee] -> []voucher
	vouches map[string][]VouchRecord

	// vouchersFor tracks who a validator is vouching for
	// map[voucher] -> []vouchee
	vouchersFor map[string][]types.PublicKey

	// Configuration
	minVoucherTrust float64
	maxVouchesPerValidator int
}

// NewVouchingManager creates a new vouching manager
func NewVouchingManager(validators *types.ValidatorSet) *VouchingManager {
	return &VouchingManager{
		validators:             validators,
		vouches:                make(map[string][]VouchRecord),
		vouchersFor:            make(map[string][]types.PublicKey),
		minVoucherTrust:        types.VoucherMinTrust,
		maxVouchesPerValidator: 10,
	}
}

// Vouch adds a vouching relationship
func (vm *VouchingManager) Vouch(voucher, vouchee types.PublicKey, currentRound uint64) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check self-vouch
	if voucher == vouchee {
		return ErrSelfVouch
	}

	// Check voucher exists and meets trust requirement
	voucherVal := vm.validators.Get(voucher)
	if voucherVal == nil {
		return ErrVoucherNotFound
	}

	if voucherVal.EffectiveTrust() < vm.minVoucherTrust {
		return ErrInvalidVoucher
	}

	// Check vouchee exists
	voucheeVal := vm.validators.Get(vouchee)
	if voucheeVal == nil {
		return ErrVoucheeNotFound
	}

	// Check not already vouching
	voucheeKey := string(vouchee[:])
	for _, record := range vm.vouches[voucheeKey] {
		if record.Voucher == voucher {
			return ErrAlreadyVouched
		}
	}

	// Check max vouches per voucher
	voucherKey := string(voucher[:])
	if len(vm.vouchersFor[voucherKey]) >= vm.maxVouchesPerValidator {
		// Remove oldest vouch
		vm.removeOldestVouch(voucher)
	}

	// Create vouch record
	record := VouchRecord{
		Voucher:             voucher,
		Vouchee:             vouchee,
		RoundMade:           currentRound,
		VoucherTrustAtVouch: voucherVal.EffectiveTrust(),
	}

	// Add to maps
	vm.vouches[voucheeKey] = append(vm.vouches[voucheeKey], record)
	vm.vouchersFor[voucherKey] = append(vm.vouchersFor[voucherKey], vouchee)

	// Update validator's voucher list
	voucheeVal.Trust.Vouchers = append(voucheeVal.Trust.Vouchers, voucher)

	return nil
}

// Unvouch removes a vouching relationship
func (vm *VouchingManager) Unvouch(voucher, vouchee types.PublicKey) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.removeVouch(voucher, vouchee)
}

// removeVouch removes a vouching relationship (internal, no lock)
func (vm *VouchingManager) removeVouch(voucher, vouchee types.PublicKey) {
	voucheeKey := string(vouchee[:])
	voucherKey := string(voucher[:])

	// Remove from vouches
	records := vm.vouches[voucheeKey]
	for i, record := range records {
		if record.Voucher == voucher {
			vm.vouches[voucheeKey] = append(records[:i], records[i+1:]...)
			break
		}
	}

	// Remove from vouchersFor
	vouchees := vm.vouchersFor[voucherKey]
	for i, pk := range vouchees {
		if pk == vouchee {
			vm.vouchersFor[voucherKey] = append(vouchees[:i], vouchees[i+1:]...)
			break
		}
	}

	// Update validator's voucher list
	voucheeVal := vm.validators.Get(vouchee)
	if voucheeVal != nil {
		vouchers := voucheeVal.Trust.Vouchers
		for i, pk := range vouchers {
			if pk == voucher {
				voucheeVal.Trust.Vouchers = append(vouchers[:i], vouchers[i+1:]...)
				break
			}
		}
	}
}

// removeOldestVouch removes the oldest vouch from a voucher
func (vm *VouchingManager) removeOldestVouch(voucher types.PublicKey) {
	voucherKey := string(voucher[:])
	vouchees := vm.vouchersFor[voucherKey]

	if len(vouchees) == 0 {
		return
	}

	// Find oldest
	var oldest types.PublicKey
	oldestRound := uint64(^uint64(0))

	for _, vouchee := range vouchees {
		voucheeKey := string(vouchee[:])
		for _, record := range vm.vouches[voucheeKey] {
			if record.Voucher == voucher && record.RoundMade < oldestRound {
				oldestRound = record.RoundMade
				oldest = vouchee
			}
		}
	}

	if oldestRound != ^uint64(0) {
		vm.removeVouch(voucher, oldest)
	}
}

// GetVouchers returns the vouchers for a validator
func (vm *VouchingManager) GetVouchers(vouchee types.PublicKey) []VouchRecord {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return vm.vouches[string(vouchee[:])]
}

// GetVouchees returns validators that a voucher is vouching for
func (vm *VouchingManager) GetVouchees(voucher types.PublicKey) []types.PublicKey {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return vm.vouchersFor[string(voucher[:])]
}

// VoucherCount returns the number of valid vouchers for a validator
func (vm *VouchingManager) VoucherCount(vouchee types.PublicKey) int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	records := vm.vouches[string(vouchee[:])]
	count := 0

	for _, record := range records {
		voucher := vm.validators.Get(record.Voucher)
		if voucher != nil && voucher.EffectiveTrust() >= vm.minVoucherTrust {
			count++
		}
	}

	return count
}

// OnByzantine handles when a validator is Byzantine
// Vouchers also lose some trust for vouching for a Byzantine validator
func (vm *VouchingManager) OnByzantine(byzantine types.PublicKey, trustManager *Manager) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	byzantineKey := string(byzantine[:])
	records := vm.vouches[byzantineKey]

	// Penalize vouchers
	for _, record := range records {
		voucher := vm.validators.Get(record.Voucher)
		if voucher != nil {
			// Voucher loses 50% of what byzantine loses
			penalty := types.TrustPenaltyByzantine * 0.5
			voucher.Trust.BaseTrust -= penalty
			if voucher.Trust.BaseTrust < types.TrustMin {
				voucher.Trust.BaseTrust = types.TrustMin
			}
		}
	}

	// Remove all vouches for the Byzantine validator
	for _, record := range records {
		vm.removeVouch(record.Voucher, byzantine)
	}
}

// Cleanup removes vouches from validators who no longer meet trust requirements
func (vm *VouchingManager) Cleanup() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	for voucheeKey, records := range vm.vouches {
		validRecords := make([]VouchRecord, 0)

		for _, record := range records {
			voucher := vm.validators.Get(record.Voucher)
			if voucher != nil && voucher.EffectiveTrust() >= vm.minVoucherTrust {
				validRecords = append(validRecords, record)
			} else {
				// Remove from vouchersFor
				voucherKey := string(record.Voucher[:])
				vouchees := vm.vouchersFor[voucherKey]
				var vouchee types.PublicKey
				copy(vouchee[:], voucheeKey)

				for i, pk := range vouchees {
					if pk == vouchee {
						vm.vouchersFor[voucherKey] = append(vouchees[:i], vouchees[i+1:]...)
						break
					}
				}
			}
		}

		vm.vouches[voucheeKey] = validRecords

		// Update validator's voucher list
		var vouchee types.PublicKey
		copy(vouchee[:], voucheeKey)
		voucheeVal := vm.validators.Get(vouchee)
		if voucheeVal != nil {
			voucheeVal.Trust.Vouchers = make([]types.PublicKey, len(validRecords))
			for i, record := range validRecords {
				voucheeVal.Trust.Vouchers[i] = record.Voucher
			}
		}
	}
}
