package consensus

import (
	"sync"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// ViewChangeHandler handles view change protocol
type ViewChangeHandler struct {
	mu         sync.RWMutex
	validators *types.ValidatorSet
	state      *State
	quorum     *QuorumCalculator
	leader     *LeaderSelector

	// View change messages per height/round
	viewChanges map[uint64]map[uint32][]*types.ViewChangeMsg

	// Certificates
	certificates map[uint64]map[uint32]*types.ViewChangeCert

	// Callbacks
	onViewChange     func(height uint64, newRound uint32)
	onCertComplete   func(cert *types.ViewChangeCert)
}

// NewViewChangeHandler creates a new view change handler
func NewViewChangeHandler(
	validators *types.ValidatorSet,
	state *State,
	quorum *QuorumCalculator,
	leader *LeaderSelector,
) *ViewChangeHandler {
	return &ViewChangeHandler{
		validators:   validators,
		state:        state,
		quorum:       quorum,
		leader:       leader,
		viewChanges:  make(map[uint64]map[uint32][]*types.ViewChangeMsg),
		certificates: make(map[uint64]map[uint32]*types.ViewChangeCert),
	}
}

// SetViewChangeCallback sets the callback for view changes
func (vc *ViewChangeHandler) SetViewChangeCallback(cb func(uint64, uint32)) {
	vc.onViewChange = cb
}

// SetCertCompleteCallback sets the callback for certificate completion
func (vc *ViewChangeHandler) SetCertCompleteCallback(cb func(*types.ViewChangeCert)) {
	vc.onCertComplete = cb
}

// CreateViewChangeMsg creates a view change message
func (vc *ViewChangeHandler) CreateViewChangeMsg(
	height uint64,
	newRound uint32,
	lastFinalized types.Hash,
	highestVoted *types.Block,
	sk types.SecretKey,
	pk types.PublicKey,
) *types.ViewChangeMsg {
	msg := &types.ViewChangeMsg{
		Height:        height,
		NewRound:      newRound,
		LastFinalized: lastFinalized,
		HighestVoted:  highestVoted,
		Voter:         pk,
	}
	msg.Signature = crypto.SignViewChange(sk, msg)
	return msg
}

// ProcessViewChangeMsg processes an incoming view change message
func (vc *ViewChangeHandler) ProcessViewChangeMsg(msg *types.ViewChangeMsg) (*types.ViewChangeCert, bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Validate
	if !vc.validateViewChangeMsg(msg) {
		return nil, false
	}

	// Initialize maps
	if vc.viewChanges[msg.Height] == nil {
		vc.viewChanges[msg.Height] = make(map[uint32][]*types.ViewChangeMsg)
	}

	// Check for duplicates
	for _, existing := range vc.viewChanges[msg.Height][msg.NewRound] {
		if existing.Voter == msg.Voter {
			return nil, false // Duplicate
		}
	}

	// Add message
	vc.viewChanges[msg.Height][msg.NewRound] = append(
		vc.viewChanges[msg.Height][msg.NewRound],
		msg,
	)

	// Check for quorum
	messages := vc.viewChanges[msg.Height][msg.NewRound]
	voters := make([]types.PublicKey, len(messages))
	for i, m := range messages {
		voters[i] = m.Voter
	}

	weight := vc.quorum.CalculateVoterWeight(voters)
	if vc.quorum.HasQuorum(weight) {
		// Create certificate
		cert := crypto.AggregateViewChanges(messages, vc.validators)
		if cert != nil {
			// Store certificate
			if vc.certificates[msg.Height] == nil {
				vc.certificates[msg.Height] = make(map[uint32]*types.ViewChangeCert)
			}
			vc.certificates[msg.Height][msg.NewRound] = cert

			// Callback
			if vc.onCertComplete != nil {
				vc.onCertComplete(cert)
			}

			return cert, true
		}
	}

	return nil, false
}

// validateViewChangeMsg validates a view change message
func (vc *ViewChangeHandler) validateViewChangeMsg(msg *types.ViewChangeMsg) bool {
	// Check voter exists
	v := vc.validators.Get(msg.Voter)
	if v == nil {
		return false
	}

	// Verify signature
	if !crypto.VerifyViewChange(msg) {
		return false
	}

	return true
}

// GetCertificate returns a view change certificate
func (vc *ViewChangeHandler) GetCertificate(height uint64, round uint32) *types.ViewChangeCert {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if vc.certificates[height] == nil {
		return nil
	}
	return vc.certificates[height][round]
}

// HasCertificate checks if a certificate exists
func (vc *ViewChangeHandler) HasCertificate(height uint64, round uint32) bool {
	return vc.GetCertificate(height, round) != nil
}

// GetHighestVotedBlock returns the highest voted block from a certificate
func (vc *ViewChangeHandler) GetHighestVotedBlock(cert *types.ViewChangeCert) *types.Block {
	if cert == nil {
		return nil
	}
	return cert.HighestVotedBlock()
}

// GetViewChangeCount returns the number of view changes for a height/round
func (vc *ViewChangeHandler) GetViewChangeCount(height uint64, round uint32) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if vc.viewChanges[height] == nil {
		return 0
	}
	return len(vc.viewChanges[height][round])
}

// TriggerViewChange triggers a view change
func (vc *ViewChangeHandler) TriggerViewChange(
	sk types.SecretKey,
	pk types.PublicKey,
) *types.ViewChangeMsg {
	height := vc.state.GetHeight()
	round := vc.state.GetRound() + 1
	lastFinalized := vc.state.GetLastFinalized()
	proposedBlock := vc.state.GetProposedBlock()

	// Create and process our own view change
	msg := vc.CreateViewChangeMsg(height, round, lastFinalized, proposedBlock, sk, pk)

	// Callback
	if vc.onViewChange != nil {
		vc.onViewChange(height, round)
	}

	return msg
}

// Cleanup removes old view change data
func (vc *ViewChangeHandler) Cleanup(currentHeight uint64, keepHeights uint64) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	cutoff := int64(currentHeight) - int64(keepHeights)
	if cutoff < 0 {
		cutoff = 0
	}

	for height := range vc.viewChanges {
		if height < uint64(cutoff) {
			delete(vc.viewChanges, height)
		}
	}

	for height := range vc.certificates {
		if height < uint64(cutoff) {
			delete(vc.certificates, height)
		}
	}
}

// Note: TimeoutManager was removed as part of concurrency hardening.
// Timeouts are now handled directly in the main consensus loop using time.Timer,
// which avoids race conditions from callbacks running in separate goroutines.
