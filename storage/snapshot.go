package storage

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

// SECURITY FIX #16: Snapshot integrity verification errors
var (
	// ErrSnapshotNoSignature is returned when importing an unsigned snapshot
	ErrSnapshotNoSignature = errors.New("snapshot has no signature - cannot verify integrity")

	// ErrSnapshotInvalidSignature is returned when snapshot signature verification fails
	ErrSnapshotInvalidSignature = errors.New("snapshot signature verification failed - possible tampering")

	// ErrSnapshotNoTrustedSigners is returned when no trusted signers are configured
	ErrSnapshotNoTrustedSigners = errors.New("no trusted snapshot signers configured")
)

// Snapshot represents a point-in-time snapshot of consensus state
type Snapshot struct {
	Height        uint64                `json:"height"`
	Timestamp     time.Time             `json:"timestamp"`
	Validators    []*types.Validator    `json:"validators"`
	State         *ConsensusState       `json:"state"`
	LastFinalized *types.Block          `json:"last_finalized,omitempty"`

	// SECURITY FIX #16: Cryptographic integrity verification
	// Signer is the public key of the entity that created this snapshot
	Signer types.PublicKey `json:"signer,omitempty"`
	// Signature is the BLS signature over the snapshot hash (excluding signature fields)
	Signature types.Signature `json:"signature,omitempty"`
}

// Hash computes the hash of the snapshot content (excluding signature fields)
// Used for signing and verification
func (s *Snapshot) Hash() types.Hash {
	h := sha256.New()

	// Hash height
	heightBytes := make([]byte, 8)
	heightBytes[0] = byte(s.Height >> 56)
	heightBytes[1] = byte(s.Height >> 48)
	heightBytes[2] = byte(s.Height >> 40)
	heightBytes[3] = byte(s.Height >> 32)
	heightBytes[4] = byte(s.Height >> 24)
	heightBytes[5] = byte(s.Height >> 16)
	heightBytes[6] = byte(s.Height >> 8)
	heightBytes[7] = byte(s.Height)
	h.Write(heightBytes)

	// Hash timestamp
	tsBytes, _ := s.Timestamp.MarshalBinary()
	h.Write(tsBytes)

	// Hash validators (just their public keys and stakes for determinism)
	for _, v := range s.Validators {
		h.Write(v.PublicKey[:])
		stakeBytes := make([]byte, 8)
		stakeBytes[0] = byte(v.Stake >> 56)
		stakeBytes[1] = byte(v.Stake >> 48)
		stakeBytes[2] = byte(v.Stake >> 40)
		stakeBytes[3] = byte(v.Stake >> 32)
		stakeBytes[4] = byte(v.Stake >> 24)
		stakeBytes[5] = byte(v.Stake >> 16)
		stakeBytes[6] = byte(v.Stake >> 8)
		stakeBytes[7] = byte(v.Stake)
		h.Write(stakeBytes)
	}

	// Hash state
	if s.State != nil {
		stateBytes, _ := json.Marshal(s.State)
		h.Write(stateBytes)
	}

	// Hash last finalized block hash if present
	if s.LastFinalized != nil {
		blockHash := s.LastFinalized.Hash()
		h.Write(blockHash[:])
	}

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// IsSigned returns true if the snapshot has a signature
func (s *Snapshot) IsSigned() bool {
	var emptyPK types.PublicKey
	var emptySig types.Signature
	return s.Signer != emptyPK && s.Signature != emptySig
}

// SnapshotManager handles snapshot creation and restoration
type SnapshotManager struct {
	store            *Store
	snapshotDir      string
	maxSnapshots     int
	snapshotInterval uint64 // Create snapshot every N blocks

	// SECURITY FIX #16: Snapshot signing and verification
	// signingKey is used to sign snapshots we create (optional)
	signingKey *crypto.BLSKeyPair
	// trustedSigners is the list of public keys allowed to sign imported snapshots
	trustedSigners []types.PublicKey
	// requireSignature controls whether ImportSnapshot requires a valid signature
	requireSignature bool
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(store *Store, snapshotDir string) *SnapshotManager {
	return &SnapshotManager{
		store:            store,
		snapshotDir:      snapshotDir,
		maxSnapshots:     5,
		snapshotInterval: 1000,
		requireSignature: true, // SECURITY FIX #16: Default to requiring signatures
	}
}

// SetSigningKey sets the key pair used to sign snapshots we create
func (m *SnapshotManager) SetSigningKey(kp *crypto.BLSKeyPair) {
	m.signingKey = kp
}

// AddTrustedSigner adds a public key to the list of trusted snapshot signers
func (m *SnapshotManager) AddTrustedSigner(pk types.PublicKey) {
	m.trustedSigners = append(m.trustedSigners, pk)
}

// SetRequireSignature controls whether imported snapshots must have valid signatures
// WARNING: Setting this to false bypasses security verification and is only safe
// for trusted local snapshots or testing
func (m *SnapshotManager) SetRequireSignature(require bool) {
	m.requireSignature = require
}

// isTrustedSigner returns true if the public key is in the trusted signers list
func (m *SnapshotManager) isTrustedSigner(pk types.PublicKey) bool {
	for _, trusted := range m.trustedSigners {
		if trusted == pk {
			return true
		}
	}
	return false
}

// SetMaxSnapshots sets the maximum number of snapshots to retain
func (m *SnapshotManager) SetMaxSnapshots(n int) {
	m.maxSnapshots = n
}

// SetSnapshotInterval sets the block interval for automatic snapshots
func (m *SnapshotManager) SetSnapshotInterval(n uint64) {
	m.snapshotInterval = n
}

// CreateSnapshot creates a new snapshot at the current height
func (m *SnapshotManager) CreateSnapshot() (*Snapshot, error) {
	// Ensure snapshot directory exists
	if err := os.MkdirAll(m.snapshotDir, 0755); err != nil {
		return nil, err
	}

	// Load current state
	state, err := m.store.GetConsensusState()
	if err != nil && err != ErrNotFound {
		return nil, err
	}
	if state == nil {
		state = &ConsensusState{}
	}

	// Load validators
	vs, err := m.store.LoadValidatorSet()
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	validators := make([]*types.Validator, 0)
	if vs != nil {
		validators = vs.Validators
	}

	// Load last finalized block
	var lastFinalized *types.Block
	if state.LastFinalizedHeight > 0 {
		lastFinalized, _ = m.store.GetBlock(state.LastFinalizedHeight)
	}

	snapshot := &Snapshot{
		Height:        state.Height,
		Timestamp:     time.Now().UTC(),
		Validators:    validators,
		State:         state,
		LastFinalized: lastFinalized,
	}

	// SECURITY FIX #16: Sign snapshot if we have a signing key
	if m.signingKey != nil {
		hash := snapshot.Hash()
		snapshot.Signer = m.signingKey.PublicKey
		snapshot.Signature = crypto.Sign(m.signingKey.SecretKey, hash[:])
	}

	// Save snapshot to file
	filename := m.snapshotFilename(snapshot.Height)
	if err := m.writeSnapshot(filename, snapshot); err != nil {
		return nil, err
	}

	// Prune old snapshots
	if err := m.pruneSnapshots(); err != nil {
		// Log error but don't fail
		fmt.Printf("Warning: failed to prune snapshots: %v\n", err)
	}

	return snapshot, nil
}

// RestoreSnapshot restores state from a snapshot
func (m *SnapshotManager) RestoreSnapshot(height uint64) error {
	filename := m.snapshotFilename(height)
	snapshot, err := m.readSnapshot(filename)
	if err != nil {
		return err
	}

	return m.ApplySnapshot(snapshot)
}

// RestoreLatest restores from the latest snapshot
func (m *SnapshotManager) RestoreLatest() error {
	snapshots, err := m.ListSnapshots()
	if err != nil {
		return err
	}

	if len(snapshots) == 0 {
		return ErrNotFound
	}

	// Sort by height descending
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Height > snapshots[j].Height
	})

	return m.ApplySnapshot(snapshots[0])
}

// ApplySnapshot applies a snapshot to restore state
func (m *SnapshotManager) ApplySnapshot(snapshot *Snapshot) error {
	// Save validators
	for _, v := range snapshot.Validators {
		if err := m.store.SaveValidator(v); err != nil {
			return err
		}
	}

	// Save consensus state
	if err := m.store.SaveConsensusState(snapshot.State); err != nil {
		return err
	}

	// Save last finalized block if present
	if snapshot.LastFinalized != nil {
		if err := m.store.SaveBlock(snapshot.LastFinalized); err != nil {
			return err
		}
	}

	return nil
}

// ListSnapshots returns all available snapshots
func (m *SnapshotManager) ListSnapshots() ([]*Snapshot, error) {
	entries, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var snapshots []*Snapshot
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".snapshot.gz") {
			continue
		}

		// Extract height from filename
		heightStr := strings.TrimPrefix(entry.Name(), "snapshot-")
		heightStr = strings.TrimSuffix(heightStr, ".snapshot.gz")
		height, err := strconv.ParseUint(heightStr, 10, 64)
		if err != nil {
			continue
		}

		snapshot, err := m.readSnapshot(m.snapshotFilename(height))
		if err != nil {
			continue
		}
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

// ShouldSnapshot returns true if a snapshot should be created at this height
func (m *SnapshotManager) ShouldSnapshot(height uint64) bool {
	return height > 0 && height%m.snapshotInterval == 0
}

// snapshotFilename generates the filename for a snapshot at the given height
func (m *SnapshotManager) snapshotFilename(height uint64) string {
	return filepath.Join(m.snapshotDir, fmt.Sprintf("snapshot-%012d.snapshot.gz", height))
}

// writeSnapshot writes a snapshot to a gzipped file
func (m *SnapshotManager) writeSnapshot(filename string, snapshot *Snapshot) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	encoder := json.NewEncoder(gzWriter)
	return encoder.Encode(snapshot)
}

// readSnapshot reads a snapshot from a gzipped file
func (m *SnapshotManager) readSnapshot(filename string) (*Snapshot, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var snapshot Snapshot
	decoder := json.NewDecoder(gzReader)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}

	return &snapshot, nil
}

// pruneSnapshots removes old snapshots, keeping only maxSnapshots
func (m *SnapshotManager) pruneSnapshots() error {
	snapshots, err := m.ListSnapshots()
	if err != nil {
		return err
	}

	if len(snapshots) <= m.maxSnapshots {
		return nil
	}

	// Sort by height ascending (oldest first)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Height < snapshots[j].Height
	})

	// Remove oldest snapshots
	toRemove := len(snapshots) - m.maxSnapshots
	for i := 0; i < toRemove; i++ {
		filename := m.snapshotFilename(snapshots[i].Height)
		if err := os.Remove(filename); err != nil {
			return err
		}
	}

	return nil
}

// DeleteSnapshot deletes a specific snapshot
func (m *SnapshotManager) DeleteSnapshot(height uint64) error {
	filename := m.snapshotFilename(height)
	return os.Remove(filename)
}

// ExportSnapshot exports a snapshot to a writer
func (m *SnapshotManager) ExportSnapshot(height uint64, w io.Writer) error {
	filename := m.snapshotFilename(height)
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(w, file)
	return err
}

// ImportSnapshot imports a snapshot from a reader
// SECURITY FIX #16: Verifies signature before accepting the snapshot
func (m *SnapshotManager) ImportSnapshot(r io.Reader) (*Snapshot, error) {
	// Ensure snapshot directory exists
	if err := os.MkdirAll(m.snapshotDir, 0755); err != nil {
		return nil, err
	}

	// Read and parse snapshot
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var snapshot Snapshot
	decoder := json.NewDecoder(gzReader)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}

	// SECURITY FIX #16: Verify snapshot integrity before accepting
	if m.requireSignature {
		if !snapshot.IsSigned() {
			log.Printf("[Snapshot] SECURITY: Rejected unsigned snapshot at height %d. "+
				"Snapshots must be signed by a trusted signer.", snapshot.Height)
			return nil, ErrSnapshotNoSignature
		}

		// Check if signer is trusted
		if len(m.trustedSigners) == 0 {
			log.Printf("[Snapshot] SECURITY: No trusted signers configured. "+
				"Cannot verify snapshot at height %d.", snapshot.Height)
			return nil, ErrSnapshotNoTrustedSigners
		}

		if !m.isTrustedSigner(snapshot.Signer) {
			log.Printf("[Snapshot] SECURITY: Rejected snapshot at height %d signed by "+
				"untrusted signer. This may indicate a malicious snapshot.", snapshot.Height)
			return nil, ErrSnapshotInvalidSignature
		}

		// Verify the signature
		hash := snapshot.Hash()
		if !crypto.Verify(snapshot.Signer, hash[:], snapshot.Signature) {
			log.Printf("[Snapshot] SECURITY: Signature verification FAILED for snapshot at "+
				"height %d. This indicates tampering or corruption.", snapshot.Height)
			return nil, ErrSnapshotInvalidSignature
		}

		log.Printf("[Snapshot] Verified snapshot at height %d from trusted signer.", snapshot.Height)
	} else {
		log.Printf("[Snapshot] WARNING: Accepting unverified snapshot at height %d. "+
			"Signature verification is disabled.", snapshot.Height)
	}

	// Write to file
	filename := m.snapshotFilename(snapshot.Height)

	// Re-read and write to file
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	encoder := json.NewEncoder(gzWriter)
	if err := encoder.Encode(&snapshot); err != nil {
		return nil, err
	}

	return &snapshot, nil
}
