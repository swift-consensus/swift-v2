package consensus

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/stake"
	"github.com/swift-consensus/swift-v2/storage"
	"github.com/swift-consensus/swift-v2/trust"
	"github.com/swift-consensus/swift-v2/types"
)

// SwiftConsensus is the main SWIFT v2 consensus engine
type SwiftConsensus struct {
	mu sync.RWMutex

	// Identity
	secretKey types.SecretKey
	publicKey types.PublicKey

	// Validators
	validators *types.ValidatorSet

	// Configuration
	config types.Config

	// State
	state *State

	// Persistence layer (optional, can be nil for in-memory only)
	// SECURITY FIX: Added storage integration per Gemini audit
	store *storage.Store

	// Components
	leader     *LeaderSelector
	quorum     *QuorumCalculator
	votes      *VoteHandler
	finalizer  *Finalizer
	viewChange *ViewChangeHandler
	trustMgr   *trust.Manager
	stakeMgr   *stake.Manager
	rewards    *stake.RewardDistributor
	slasher    *stake.Slasher
	byzantine  *trust.ByzantineDetector

	// Network (interface for sending messages)
	transport Transport

	// Transaction pool
	txPool   []types.Transaction
	txPoolMu sync.Mutex // Separate mutex for tx pool

	// Event channels - all state mutations happen via these
	proposeChan    chan *types.ProposeMsg
	voteChan       chan *types.Vote
	finalizeChan   chan *types.FinalizeMsg
	viewChangeChan chan *types.ViewChangeMsg
	cmdChan        chan consensusCmd // Internal command channel

	// Control
	running bool
	stopCh  chan struct{}

	// Metrics
	metrics   *Metrics
	metricsMu sync.RWMutex
}

// consensusCmd represents internal commands sent to the main loop
type consensusCmd struct {
	cmdType cmdType
	data    interface{}
}

type cmdType int

const (
	cmdTriggerViewChange cmdType = iota
	cmdProcessVote
)

// Transport is the interface for network communication
type Transport interface {
	Broadcast(msg interface{})
	SendTo(peer types.PublicKey, msg interface{})
}

// Metrics tracks consensus metrics
type Metrics struct {
	BlocksFinalized  uint64
	RoundsCompleted  uint64
	ViewChanges      uint64
	AvgFinalityTime  time.Duration
	LastFinalityTime time.Duration
	DroppedMessages  uint64 // Track dropped messages
}

// ConsensusOption is a functional option for configuring SwiftConsensus
type ConsensusOption func(*SwiftConsensus) error

// WithStore configures the consensus engine to use persistent storage
// SECURITY FIX: Enables persistence per Gemini audit
func WithStore(store *storage.Store) ConsensusOption {
	return func(sc *SwiftConsensus) error {
		sc.store = store
		return nil
	}
}

// NewSwiftConsensus creates a new SWIFT consensus engine
// Returns error if stake overflow is detected during initialization
// Accepts optional ConsensusOption functions for configuration
func NewSwiftConsensus(
	sk types.SecretKey,
	validators *types.ValidatorSet,
	config types.Config,
	transport Transport,
	opts ...ConsensusOption,
) (*SwiftConsensus, error) {
	pk := crypto.PublicKeyFromSecret(sk)

	state := NewState()
	quorum := NewQuorumCalculator(validators, config)
	leader := NewLeaderSelector(validators, config)
	votes := NewVoteHandler(validators, quorum, state)
	finalizer := NewFinalizer(validators, state, quorum)
	viewChange := NewViewChangeHandler(validators, state, quorum, leader)
	trustMgr := trust.NewManager(validators, config)
	stakeMgr, err := stake.NewManager(validators, config)
	if err != nil {
		return nil, err
	}
	rewards := stake.NewRewardDistributor(validators, config)
	slasher := stake.NewSlasher(stakeMgr, validators, config)
	byzantine := trust.NewByzantineDetector(validators)

	// STABILITY FIX: Wire PruneValidator calls to prevent memory leaks
	// When a validator is removed (e.g., after unbonding), clean up their history
	stakeMgr.SetOnValidatorRemoved(func(pubKey types.PublicKey) {
		trustMgr.PruneValidator(pubKey)
		slasher.PruneValidator(pubKey)
	})

	sc := &SwiftConsensus{
		secretKey:      sk,
		publicKey:      pk,
		validators:     validators,
		config:         config,
		state:          state,
		leader:         leader,
		quorum:         quorum,
		votes:          votes,
		finalizer:      finalizer,
		viewChange:     viewChange,
		trustMgr:       trustMgr,
		stakeMgr:       stakeMgr,
		rewards:        rewards,
		slasher:        slasher,
		byzantine:      byzantine,
		transport:      transport,
		txPool:         make([]types.Transaction, 0),
		proposeChan:    make(chan *types.ProposeMsg, 100),
		voteChan:       make(chan *types.Vote, 1000),
		finalizeChan:   make(chan *types.FinalizeMsg, 100),
		viewChangeChan: make(chan *types.ViewChangeMsg, 1000),
		cmdChan:        make(chan consensusCmd, 100),
		stopCh:         make(chan struct{}),
		metrics:        &Metrics{},
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(sc); err != nil {
			return nil, err
		}
	}

	// Load state from storage if available
	// SECURITY FIX: Restore state from disk per Gemini audit
	if sc.store != nil {
		if err := sc.loadStateFromStorage(); err != nil {
			log.Printf("Warning: Failed to load state from storage: %v (starting fresh)", err)
		}
	}

	// Setup callbacks
	sc.setupCallbacks()

	return sc, nil
}

// loadStateFromStorage loads consensus state from persistent storage
func (sc *SwiftConsensus) loadStateFromStorage() error {
	// Load last consensus state
	savedState, err := sc.store.GetConsensusState()
	if err == storage.ErrNotFound {
		// Fresh start, no state to load
		return nil
	}
	if err != nil {
		return err
	}

	// Restore state
	sc.state.SetHeight(savedState.Height)
	sc.state.SetRound(0) // Start at round 0 for new consensus round
	sc.state.SetLastFinalized(savedState.LastFinalizedHash)

	log.Printf("Restored consensus state: height=%d, last_finalized=%x",
		savedState.Height, savedState.LastFinalizedHash[:8])

	// Load validators from storage if available
	storedValidators, err := sc.store.LoadValidatorSet()
	if err == nil && len(storedValidators.Validators) > 0 {
		// Merge trust scores from stored validators
		for _, stored := range storedValidators.Validators {
			if v := sc.validators.Get(stored.PublicKey); v != nil {
				v.Trust = stored.Trust
				v.Balance = stored.Balance
			}
		}
		log.Printf("Restored trust scores for %d validators", len(storedValidators.Validators))
	}

	return nil
}

// setupCallbacks sets up internal callbacks
func (sc *SwiftConsensus) setupCallbacks() {
	// When quorum is reached, try to finalize
	sc.votes.SetQuorumCallback(func(height uint64, round uint32, votes []*types.Vote) {
		sc.onQuorumReached(height, round, votes)
	})

	// When block is finalized
	sc.finalizer.SetFinalizedCallback(func(msg *types.FinalizeMsg) {
		sc.onBlockFinalized(msg)
	})

	// NOTE: View change certificate callback is NOT set here.
	// View changes are processed in doProcessViewChange() in the main loop,
	// which calls onViewChangeCertificate() directly. This avoids race conditions
	// from callbacks running outside the main goroutine.
}

// Start starts the consensus engine
func (sc *SwiftConsensus) Start(ctx context.Context) {
	sc.mu.Lock()
	if sc.running {
		sc.mu.Unlock()
		return
	}
	sc.running = true
	sc.mu.Unlock()

	go sc.run(ctx)
}

// Stop stops the consensus engine
func (sc *SwiftConsensus) Stop() {
	sc.mu.Lock()
	if !sc.running {
		sc.mu.Unlock()
		return
	}
	sc.running = false
	sc.mu.Unlock()

	close(sc.stopCh)
}

// run is the main consensus loop - ALL state mutations happen here
func (sc *SwiftConsensus) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sc.stopCh:
			return
		case cmd := <-sc.cmdChan:
			sc.handleCommand(cmd)
		default:
			sc.runRound(ctx)
		}
	}
}

// handleCommand processes internal commands in the main loop
func (sc *SwiftConsensus) handleCommand(cmd consensusCmd) {
	switch cmd.cmdType {
	case cmdTriggerViewChange:
		sc.doTriggerViewChange()
	case cmdProcessVote:
		if vote, ok := cmd.data.(*types.Vote); ok {
			sc.doProcessVote(vote)
		}
	}
}

// runRound runs a single consensus round
func (sc *SwiftConsensus) runRound(ctx context.Context) {
	height := sc.state.GetHeight()
	round := sc.state.GetRound()
	lastHash := sc.state.GetLastFinalized()

	// Step 1: Select leader
	leader := sc.leader.SelectLeader(height, round, lastHash)
	if leader == nil {
		time.Sleep(sc.config.BlockTime)
		return
	}

	// Step 2: Propose (if we're leader)
	var proposal *types.ProposeMsg
	if leader.PublicKey == sc.publicKey {
		proposal = sc.propose()
	}

	// Step 3: Wait for proposal or timeout
	sc.state.SetStep(types.StepPropose)

	proposeTimeout := time.NewTimer(sc.config.BlockTime)
	defer proposeTimeout.Stop()

	// If we're the leader, we already have the proposal
	if proposal != nil {
		sc.onProposal(proposal)
	} else {
		// Wait for proposal from network
		select {
		case proposeMsg := <-sc.proposeChan:
			proposeTimeout.Stop()
			sc.onProposal(proposeMsg)
		case vcMsg := <-sc.viewChangeChan:
			// Process view change in main loop (per Gemini review fix)
			proposeTimeout.Stop()
			sc.doProcessViewChange(vcMsg)
			return
		case <-proposeTimeout.C:
			sc.doTriggerViewChange()
			return
		case cmd := <-sc.cmdChan:
			proposeTimeout.Stop()
			sc.handleCommand(cmd)
			return
		case <-sc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}

	// Step 4: Vote phase
	sc.state.SetStep(types.StepVote)

	// Start finalize timeout
	finalizeTimeout := time.NewTimer(sc.config.ViewChangeTimeout)
	defer finalizeTimeout.Stop()

	// Wait for finalization or timeout
	for {
		select {
		case finalizeMsg := <-sc.finalizeChan:
			finalizeTimeout.Stop()
			sc.onFinalize(finalizeMsg)
			sc.incrementRoundsCompleted()
			return
		case vote := <-sc.voteChan:
			// Process votes inline in main loop
			sc.doProcessVote(vote)
		case vcMsg := <-sc.viewChangeChan:
			// Process view change in main loop (per Gemini review fix)
			sc.doProcessViewChange(vcMsg)
		case cmd := <-sc.cmdChan:
			sc.handleCommand(cmd)
		case <-finalizeTimeout.C:
			sc.doTriggerViewChange()
			return
		case <-sc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// propose creates and broadcasts a block proposal
func (sc *SwiftConsensus) propose() *types.ProposeMsg {
	height := sc.state.GetHeight()
	round := sc.state.GetRound()
	lastHash := sc.state.GetLastFinalized()

	// Create block
	block := types.NewBlock(height, round, lastHash, sc.publicKey)

	// Add transactions from pool (separate lock)
	sc.txPoolMu.Lock()
	txCount := len(sc.txPool)
	if txCount > types.MaxTransactionsPerBlock {
		txCount = types.MaxTransactionsPerBlock
	}
	block.Transactions = make([]types.Transaction, txCount)
	copy(block.Transactions, sc.txPool[:txCount])
	sc.txPool = sc.txPool[txCount:]
	sc.txPoolMu.Unlock()

	// Compute tx root
	block.TxRoot = crypto.TransactionsMerkleRoot(block.Transactions)

	// Sign block
	block.Signature = crypto.SignBlock(sc.secretKey, block)

	// Store and broadcast
	sc.state.SetProposedBlock(block)

	msg := &types.ProposeMsg{Block: *block}
	sc.transport.Broadcast(msg)

	// Record as leader
	sc.leader.RecordLeader(sc.publicKey, round)

	return msg
}

// onProposal handles a received proposal
func (sc *SwiftConsensus) onProposal(msg *types.ProposeMsg) {
	block := &msg.Block

	// Validate block with ViewChangeCert if present
	// SECURITY FIX: Pass certificate for validation
	if !sc.validateBlock(block, msg.ViewChangeCert) {
		return
	}

	// Store proposed block
	sc.state.SetProposedBlock(block)

	// Create and send vote
	vote := sc.votes.CreateVote(block, sc.secretKey, sc.publicKey)
	sc.transport.Broadcast(vote)

	// Process our own vote
	sc.votes.ProcessVote(vote)
}

// validateBlock validates a proposed block
// SECURITY FIX: Now validates ViewChangeCert when present
func (sc *SwiftConsensus) validateBlock(block *types.Block, cert *types.ViewChangeCert) bool {
	// Check height and round
	if block.Height != sc.state.GetHeight() {
		return false
	}
	if block.Round != sc.state.GetRound() {
		return false
	}

	// SECURITY FIX: If this is a view change proposal (round > 0), verify the certificate
	if cert != nil {
		// Verify the certificate has valid signatures and sufficient weight
		if !crypto.VerifyViewChangeCert(cert, sc.validators) {
			return false
		}

		// Verify certificate matches block's height and round
		if cert.Height != block.Height || cert.Round != block.Round {
			return false
		}

		// Verify block extends from the highest voted block in the certificate
		// (or from last finalized if no one voted)
		highestVoted := cert.HighestVotedBlock()
		if highestVoted != nil {
			if block.ParentHash != highestVoted.Hash() {
				return false
			}
		} else {
			// No one voted in previous round, must extend from last finalized
			if block.ParentHash != sc.state.GetLastFinalized() {
				return false
			}
		}
	} else {
		// No certificate - check normal parent hash requirement
		if block.ParentHash != sc.state.GetLastFinalized() {
			return false
		}
	}

	// Verify proposer is leader for this height/round
	leader := sc.leader.SelectLeader(block.Height, block.Round, sc.state.GetLastFinalized())
	if leader == nil || leader.PublicKey != block.Proposer {
		return false
	}

	// Verify block signature
	if !crypto.VerifyBlock(block) {
		return false
	}

	return true
}

// onQuorumReached is called when vote quorum is reached
func (sc *SwiftConsensus) onQuorumReached(height uint64, round uint32, votes []*types.Vote) {
	block := sc.state.GetProposedBlock()
	if block == nil || block.Height != height || block.Round != round {
		return
	}

	// Try to finalize
	msg := sc.finalizer.TryFinalize(block, votes)
	if msg != nil {
		// Broadcast finalization to network
		sc.transport.Broadcast(msg)

		// Send to our own channel - use non-blocking with metrics
		select {
		case sc.finalizeChan <- msg:
		default:
			sc.incrementDroppedMessages()
		}
	}
}

// onFinalize handles a finalization message
func (sc *SwiftConsensus) onFinalize(msg *types.FinalizeMsg) {
	if !sc.finalizer.ProcessFinalizeMsg(msg) {
		return
	}
	// Block is finalized, handled by callback
}

// onBlockFinalized is called when a block is finalized
func (sc *SwiftConsensus) onBlockFinalized(msg *types.FinalizeMsg) {
	startTime := sc.state.RoundDuration()

	// Update trust
	voters := sc.finalizer.GetVoters(msg.Block.Height)
	sc.trustMgr.ProcessRoundEnd(voters, msg.Block.Height)

	// Distribute rewards (configurable via Config.BlockReward)
	blockReward := sc.config.BlockReward
	if blockReward == 0 {
		blockReward = 1000 // Default fallback
	}
	sc.rewards.DistributeBlockReward(msg.Block.Height, blockReward, msg.Block.Proposer, voters)

	// Update quorum cache
	sc.quorum.InvalidateCache()

	// SECURITY FIX: Persist to storage before advancing state (per Gemini audit)
	if sc.store != nil {
		sc.persistFinalizedBlock(msg)
	}

	// Advance to next height
	sc.state.NewHeight(msg.Block.Height+1, msg.Block.Hash())

	// Update metrics
	sc.metricsMu.Lock()
	sc.metrics.BlocksFinalized++
	sc.metrics.LastFinalityTime = startTime
	sc.metricsMu.Unlock()

	// Cleanup old data
	sc.cleanup(msg.Block.Height)
}

// persistFinalizedBlock persists a finalized block and state to storage
// SECURITY FIX: Added persistence per Gemini audit
func (sc *SwiftConsensus) persistFinalizedBlock(msg *types.FinalizeMsg) {
	// Save the finalized block
	if err := sc.store.SaveBlock(&msg.Block); err != nil {
		log.Printf("Error saving finalized block %d: %v", msg.Block.Height, err)
	}

	// Save the finalization message (includes aggregate signature)
	if err := sc.store.SaveFinalizeMsg(msg); err != nil {
		log.Printf("Error saving finalize msg for block %d: %v", msg.Block.Height, err)
	}

	// Save consensus state
	blockHash := msg.Block.Hash()
	consensusState := &storage.ConsensusState{
		Height:              msg.Block.Height + 1, // Next height
		Round:               0,                     // Start at round 0
		LastFinalizedHash:   blockHash,
		LastFinalizedHeight: msg.Block.Height,
	}
	if err := sc.store.SaveConsensusState(consensusState); err != nil {
		log.Printf("Error saving consensus state: %v", err)
	}

	// Save validator set (to preserve trust scores)
	if err := sc.store.SaveValidatorSet(sc.validators); err != nil {
		log.Printf("Error saving validator set: %v", err)
	}

	// Sync WAL to disk for crash recovery
	if err := sc.store.Sync(); err != nil {
		log.Printf("Error syncing storage: %v", err)
	}
}

// doTriggerViewChange performs the view change (called in main loop only)
// SECURITY FIX: Ensure round is advanced and state is consistent
func (sc *SwiftConsensus) doTriggerViewChange() {
	// Create view change message FIRST (this calculates newRound = current + 1)
	msg := sc.viewChange.TriggerViewChange(sc.secretKey, sc.publicKey)

	// CRITICAL: Advance state to the new round BEFORE processing
	// This ensures state.Round matches msg.NewRound during processing
	sc.state.NewRound(msg.NewRound)

	// Broadcast the message
	sc.transport.Broadcast(msg)

	// Process our own view change through the main loop handler
	// Note: onViewChangeCertificate checks cert.Round > currentRound before updating,
	// so it won't double-increment since we already set state to msg.NewRound
	sc.doProcessViewChange(msg)
}

// doProcessVote processes a vote in the main loop
func (sc *SwiftConsensus) doProcessVote(vote *types.Vote) {
	// Check for equivocation
	proof := sc.byzantine.RecordVote(vote)
	if proof != nil {
		// Handle equivocation
		sc.slasher.SlashForEquivocation(proof, vote.Height)
		sc.trustMgr.PenaltyByzantine([]types.PublicKey{vote.Voter})
	}

	// Process vote
	sc.votes.ProcessVote(vote)
}

// doProcessViewChange processes a view change message in the main loop
// This ensures all state mutations happen in a single goroutine
func (sc *SwiftConsensus) doProcessViewChange(msg *types.ViewChangeMsg) {
	cert, created := sc.viewChange.ProcessViewChangeMsg(msg)
	if created && cert != nil {
		// Certificate was just created, handle it in this context
		sc.onViewChangeCertificate(cert)
	}
}

// onViewChangeCertificate is called when a view change certificate is complete
// SECURITY FIX: Update state round BEFORE processing to prevent state inconsistency
func (sc *SwiftConsensus) onViewChangeCertificate(cert *types.ViewChangeCert) {
	// CRITICAL: Update state to the new round BEFORE any processing
	// Without this, receiving view changes from other nodes would leave our
	// state at the old round while processing a certificate for the new round
	currentRound := sc.state.GetRound()
	if cert.Round > currentRound {
		sc.state.NewRound(cert.Round)
	}

	// Find highest voted block
	highestVoted := cert.HighestVotedBlock()

	// If we're the new leader, propose with certificate
	leader := sc.leader.SelectLeader(cert.Height, cert.Round, sc.state.GetLastFinalized())
	if leader != nil && leader.PublicKey == sc.publicKey {
		sc.proposeWithCert(cert, highestVoted)
	}

	// Update metrics
	sc.metricsMu.Lock()
	sc.metrics.ViewChanges++
	sc.metricsMu.Unlock()
}

// proposeWithCert proposes a block with a view change certificate
func (sc *SwiftConsensus) proposeWithCert(cert *types.ViewChangeCert, highestVoted *types.Block) {
	height := cert.Height
	round := cert.Round
	var parentHash types.Hash

	if highestVoted != nil {
		parentHash = highestVoted.Hash()
	} else {
		parentHash = sc.state.GetLastFinalized()
	}

	// Create block
	block := types.NewBlock(height, round, parentHash, sc.publicKey)
	block.Signature = crypto.SignBlock(sc.secretKey, block)

	// Store and broadcast
	sc.state.SetProposedBlock(block)

	msg := &types.ProposeMsg{Block: *block, ViewChangeCert: cert}
	sc.transport.Broadcast(msg)
}

// cleanup removes old data to prevent memory leaks
func (sc *SwiftConsensus) cleanup(currentHeight uint64) {
	keepHeights := uint64(100)
	sc.votes.Cleanup(currentHeight, keepHeights)
	sc.finalizer.Cleanup(currentHeight, keepHeights)
	sc.viewChange.Cleanup(currentHeight, keepHeights)
	sc.byzantine.Cleanup(currentHeight, keepHeights)
}

// incrementRoundsCompleted safely increments metrics
func (sc *SwiftConsensus) incrementRoundsCompleted() {
	sc.metricsMu.Lock()
	sc.metrics.RoundsCompleted++
	sc.metricsMu.Unlock()
}

// incrementDroppedMessages tracks dropped messages
func (sc *SwiftConsensus) incrementDroppedMessages() {
	sc.metricsMu.Lock()
	sc.metrics.DroppedMessages++
	sc.metricsMu.Unlock()
}

// Transaction pool configuration
const (
	// MaxTxPoolSize is the maximum number of transactions in the pool
	MaxTxPoolSize = 10000

	// MaxTxDataSize is the maximum size of transaction data in bytes
	MaxTxDataSize = 64 * 1024 // 64KB
)

// Transaction pool errors
var (
	ErrPoolFull        = errors.New("transaction pool is full")
	ErrTxTooLarge      = errors.New("transaction data exceeds size limit")
	ErrInvalidTxSig    = errors.New("invalid transaction signature")
	ErrDuplicateTx     = errors.New("duplicate transaction in pool")
)

// SubmitTransaction adds a transaction to the pool with DoS protection
// SECURITY FIX: Validates transaction before adding to prevent DoS attacks
func (sc *SwiftConsensus) SubmitTransaction(tx types.Transaction) error {
	// 1. Verify transaction signature BEFORE acquiring lock
	txHash := tx.Hash()
	if !crypto.Verify(tx.From, txHash[:], tx.Signature) {
		return ErrInvalidTxSig
	}

	// 2. Check transaction data size limit
	if len(tx.Data) > MaxTxDataSize {
		return ErrTxTooLarge
	}

	sc.txPoolMu.Lock()
	defer sc.txPoolMu.Unlock()

	// 3. Check pool capacity
	if len(sc.txPool) >= MaxTxPoolSize {
		return ErrPoolFull
	}

	// 4. Check for duplicate (same hash already in pool)
	for _, existingTx := range sc.txPool {
		if existingTx.Hash() == txHash {
			return ErrDuplicateTx
		}
	}

	sc.txPool = append(sc.txPool, tx)
	return nil
}

// GetState returns the current consensus state
func (sc *SwiftConsensus) GetState() StateSnapshot {
	return sc.state.Snapshot()
}

// GetMetrics returns consensus metrics
func (sc *SwiftConsensus) GetMetrics() *Metrics {
	sc.metricsMu.RLock()
	defer sc.metricsMu.RUnlock()
	// Return a copy
	return &Metrics{
		BlocksFinalized:  sc.metrics.BlocksFinalized,
		RoundsCompleted:  sc.metrics.RoundsCompleted,
		ViewChanges:      sc.metrics.ViewChanges,
		AvgFinalityTime:  sc.metrics.AvgFinalityTime,
		LastFinalityTime: sc.metrics.LastFinalityTime,
		DroppedMessages:  sc.metrics.DroppedMessages,
	}
}

// IsRunning returns whether the consensus is running
func (sc *SwiftConsensus) IsRunning() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.running
}

// GetValidators returns the validator set
func (sc *SwiftConsensus) GetValidators() *types.ValidatorSet {
	return sc.validators
}

// GetConfig returns the configuration
func (sc *SwiftConsensus) GetConfig() types.Config {
	return sc.config
}

// OnReceivePropose handles incoming propose messages from network
func (sc *SwiftConsensus) OnReceivePropose(msg *types.ProposeMsg) {
	select {
	case sc.proposeChan <- msg:
	default:
		sc.incrementDroppedMessages()
	}
}

// OnReceiveVote handles incoming vote messages from network
// Routes to main loop via channel for safe state mutation
func (sc *SwiftConsensus) OnReceiveVote(vote *types.Vote) {
	select {
	case sc.voteChan <- vote:
	default:
		sc.incrementDroppedMessages()
	}
}

// OnReceiveFinalize handles incoming finalize messages from network
func (sc *SwiftConsensus) OnReceiveFinalize(msg *types.FinalizeMsg) {
	select {
	case sc.finalizeChan <- msg:
	default:
		sc.incrementDroppedMessages()
	}
}

// OnReceiveViewChange handles incoming view change messages from network
// Routes to main loop via channel for safe state mutation
func (sc *SwiftConsensus) OnReceiveViewChange(msg *types.ViewChangeMsg) {
	select {
	case sc.viewChangeChan <- msg:
	default:
		sc.incrementDroppedMessages()
	}
}
