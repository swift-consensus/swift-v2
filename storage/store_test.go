package storage

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/types"
)

func TestStoreBasicOperations(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "swift-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create store
	config := DefaultStoreConfig(tmpDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Test block storage
	kp, _ := crypto.GenerateKeyPair()
	block := &types.Block{
		Height:     1,
		Round:      0,
		ParentHash: [32]byte{1, 2, 3},
		TxRoot:     [32]byte{4, 5, 6},
		Timestamp:  1234567890,
		Proposer:   kp.PublicKey,
	}
	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	if err := store.SaveBlock(block); err != nil {
		t.Fatalf("SaveBlock failed: %v", err)
	}

	// Retrieve by height
	retrieved, err := store.GetBlock(1)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}

	if retrieved.Height != block.Height {
		t.Errorf("Height mismatch: got %d, want %d", retrieved.Height, block.Height)
	}

	// Retrieve by hash
	hash := block.Hash()
	retrievedByHash, err := store.GetBlockByHash(hash)
	if err != nil {
		t.Fatalf("GetBlockByHash failed: %v", err)
	}

	if retrievedByHash.Height != block.Height {
		t.Errorf("Height mismatch by hash: got %d, want %d", retrievedByHash.Height, block.Height)
	}
}

func TestStoreValidators(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := DefaultStoreConfig(tmpDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Create validators
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	v1 := types.NewValidator(kp1.PublicKey, 10000)
	v1.Trust.BaseTrust = 0.5
	v1.Trust.RoundsActive = 100

	v2 := types.NewValidator(kp2.PublicKey, 20000)
	v2.Trust.BaseTrust = 0.7
	v2.Trust.RoundsActive = 500

	// Save validators
	if err := store.SaveValidator(v1); err != nil {
		t.Fatalf("SaveValidator failed: %v", err)
	}
	if err := store.SaveValidator(v2); err != nil {
		t.Fatalf("SaveValidator failed: %v", err)
	}

	// Retrieve individual validator
	retrieved, err := store.GetValidator(kp1.PublicKey)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}

	if retrieved.Stake != v1.Stake {
		t.Errorf("Stake mismatch: got %d, want %d", retrieved.Stake, v1.Stake)
	}

	// Load all validators
	vs, err := store.LoadValidatorSet()
	if err != nil {
		t.Fatalf("LoadValidatorSet failed: %v", err)
	}

	if vs.Size() != 2 {
		t.Errorf("Expected 2 validators, got %d", vs.Size())
	}
}

func TestStoreConsensusState(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := DefaultStoreConfig(tmpDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	state := &ConsensusState{
		Height:              100,
		Round:               5,
		LastFinalizedHash:   [32]byte{1, 2, 3, 4, 5},
		LastFinalizedHeight: 99,
	}

	if err := store.SaveConsensusState(state); err != nil {
		t.Fatalf("SaveConsensusState failed: %v", err)
	}

	retrieved, err := store.GetConsensusState()
	if err != nil {
		t.Fatalf("GetConsensusState failed: %v", err)
	}

	if retrieved.Height != state.Height {
		t.Errorf("Height mismatch: got %d, want %d", retrieved.Height, state.Height)
	}

	if retrieved.Round != state.Round {
		t.Errorf("Round mismatch: got %d, want %d", retrieved.Round, state.Round)
	}

	if retrieved.LastFinalizedHeight != state.LastFinalizedHeight {
		t.Errorf("LastFinalizedHeight mismatch: got %d, want %d", retrieved.LastFinalizedHeight, state.LastFinalizedHeight)
	}
}

func TestWALRecovery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create store and write data
	config := DefaultStoreConfig(tmpDir)
	config.WALEnabled = true
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}

	kp, _ := crypto.GenerateKeyPair()
	block := &types.Block{
		Height:     1,
		Round:      0,
		Timestamp:  1234567890,
		Proposer:   kp.PublicKey,
	}
	block.Signature = crypto.SignBlock(kp.SecretKey, block)

	if err := store.SaveBlock(block); err != nil {
		t.Fatal(err)
	}

	// Close store
	store.Close()

	// Reopen store (should recover from WAL)
	store2, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()

	// Verify data is still there
	retrieved, err := store2.GetBlock(1)
	if err != nil {
		t.Fatalf("Block not recovered: %v", err)
	}

	if retrieved.Height != block.Height {
		t.Errorf("Height mismatch after recovery")
	}
}

func TestSnapshotManager(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-snapshot-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	storeDir := tmpDir + "/store"
	snapshotDir := tmpDir + "/snapshots"

	config := DefaultStoreConfig(storeDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Create validators and state
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.5

	store.SaveValidator(v)
	store.SaveConsensusState(&ConsensusState{
		Height: 1000,
		Round:  0,
	})

	// Create snapshot
	sm := NewSnapshotManager(store, snapshotDir)
	snapshot, err := sm.CreateSnapshot()
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	if snapshot.Height != 1000 {
		t.Errorf("Snapshot height mismatch: got %d, want %d", snapshot.Height, 1000)
	}

	// List snapshots
	snapshots, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}

	if len(snapshots) != 1 {
		t.Errorf("Expected 1 snapshot, got %d", len(snapshots))
	}

	// Create new store and restore
	storeDir2 := tmpDir + "/store2"
	config2 := DefaultStoreConfig(storeDir2)
	store2, err := NewStore(config2)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()

	sm2 := NewSnapshotManager(store2, snapshotDir)
	if err := sm2.RestoreSnapshot(1000); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	// Verify restored data
	restoredState, err := store2.GetConsensusState()
	if err != nil {
		t.Fatalf("GetConsensusState after restore failed: %v", err)
	}

	if restoredState.Height != 1000 {
		t.Errorf("Restored height mismatch: got %d, want %d", restoredState.Height, 1000)
	}

	restoredVs, err := store2.LoadValidatorSet()
	if err != nil {
		t.Fatalf("LoadValidatorSet after restore failed: %v", err)
	}

	if restoredVs.Size() != 1 {
		t.Errorf("Restored validator count mismatch: got %d, want 1", restoredVs.Size())
	}
}

func TestSnapshotPruning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-snapshot-prune-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	storeDir := tmpDir + "/store"
	snapshotDir := tmpDir + "/snapshots"

	config := DefaultStoreConfig(storeDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sm := NewSnapshotManager(store, snapshotDir)
	sm.SetMaxSnapshots(3)

	// Create 5 snapshots
	for i := uint64(1000); i <= 5000; i += 1000 {
		store.SaveConsensusState(&ConsensusState{Height: i})
		_, err := sm.CreateSnapshot()
		if err != nil {
			t.Fatalf("CreateSnapshot failed at height %d: %v", i, err)
		}
	}

	// Should only have 3 snapshots (the newest ones)
	snapshots, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}

	if len(snapshots) != 3 {
		t.Errorf("Expected 3 snapshots after pruning, got %d", len(snapshots))
	}

	// Verify we kept the newest snapshots
	for _, snap := range snapshots {
		if snap.Height < 3000 {
			t.Errorf("Old snapshot at height %d should have been pruned", snap.Height)
		}
	}
}

// TestGetBlockByHashConcurrent tests concurrent access to GetBlockByHash
// This test verifies the fix for the deadlock issue where GetBlockByHash
// used to manually unlock/relock around a call to GetBlock
func TestGetBlockByHashConcurrent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := DefaultStoreConfig(tmpDir)
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Create and save some blocks
	kp, _ := crypto.GenerateKeyPair()
	blocks := make([]*types.Block, 10)
	for i := 0; i < 10; i++ {
		blocks[i] = &types.Block{
			Height:     uint64(i + 1),
			Round:      0,
			ParentHash: [32]byte{byte(i)},
			TxRoot:     [32]byte{byte(i + 100)},
			Timestamp:  int64(1234567890 + i),
			Proposer:   kp.PublicKey,
		}
		blocks[i].Signature = crypto.SignBlock(kp.SecretKey, blocks[i])
		if err := store.SaveBlock(blocks[i]); err != nil {
			t.Fatalf("SaveBlock failed: %v", err)
		}
	}

	// Concurrent access - this would previously deadlock
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				// Mix of GetBlock and GetBlockByHash calls
				_, err := store.GetBlock(uint64(idx + 1))
				if err != nil {
					t.Errorf("GetBlock failed: %v", err)
				}
				hash := blocks[idx].Hash()
				_, err = store.GetBlockByHash(hash)
				if err != nil {
					t.Errorf("GetBlockByHash failed: %v", err)
				}
			}
		}(i)
	}

	// Wait for all goroutines with timeout
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("DEADLOCK DETECTED: Concurrent access to GetBlockByHash timed out")
		}
	}
}

// =============================================================================
// SECURITY FIX #14: WAL Entry Size Validation Tests
// These tests verify that the WAL rejects entries that exceed size limits,
// preventing memory exhaustion DoS attacks from malicious WAL files.
// =============================================================================

// TestWALAppendRejectsOversizedKey verifies Append rejects keys > MaxWALKeySize
func TestWALAppendRejectsOversizedKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-wal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	// Create entry with key exceeding maximum
	oversizedKey := make([]byte, MaxWALKeySize+1)
	for i := range oversizedKey {
		oversizedKey[i] = byte(i % 256)
	}

	entry := WALEntry{
		Type: WALTypeBlock,
		Key:  oversizedKey,
		Data: []byte("normal data"),
	}

	err = wal.Append(entry)
	if err == nil {
		t.Fatal("Expected error for oversized key, got nil")
	}

	if !errors.Is(err, ErrWALKeyTooLarge) {
		t.Fatalf("Expected ErrWALKeyTooLarge, got: %v", err)
	}
}

// TestWALAppendRejectsOversizedData verifies Append rejects data > MaxWALDataSize
func TestWALAppendRejectsOversizedData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-wal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	// Create entry with data exceeding maximum
	// Note: We can't actually allocate 16MB+ in a test, so we test the limit check
	// by creating a smaller test with a temporarily reduced limit
	// Instead, we'll test with the actual limit by creating a data slice just over

	// For practical testing, we verify the error path works
	entry := WALEntry{
		Type: WALTypeBlock,
		Key:  []byte("normal-key"),
		Data: make([]byte, MaxWALDataSize+1), // Just over the limit
	}

	err = wal.Append(entry)
	if err == nil {
		t.Fatal("Expected error for oversized data, got nil")
	}

	if !errors.Is(err, ErrWALDataTooLarge) {
		t.Fatalf("Expected ErrWALDataTooLarge, got: %v", err)
	}
}

// TestWALAppendAcceptsValidSizes verifies normal entries work correctly
func TestWALAppendAcceptsValidSizes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-wal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	// Test at maximum allowed key size
	maxKey := make([]byte, MaxWALKeySize)
	for i := range maxKey {
		maxKey[i] = byte(i % 256)
	}

	entry := WALEntry{
		Type: WALTypeBlock,
		Key:  maxKey,
		Data: []byte("test data"),
	}

	err = wal.Append(entry)
	if err != nil {
		t.Fatalf("Expected success for max-size key, got: %v", err)
	}

	// Verify it was written correctly
	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	if len(entries[0].Key) != MaxWALKeySize {
		t.Fatalf("Key size mismatch: got %d, want %d", len(entries[0].Key), MaxWALKeySize)
	}
}

// TestWALReadAllRejectsMalformedKeyLength tests that ReadAll validates key length
// from the file and rejects entries with maliciously large key lengths
func TestWALReadAllRejectsMalformedKeyLength(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-wal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// First create a valid WAL with one entry
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	validEntry := WALEntry{
		Type: WALTypeBlock,
		Key:  []byte("valid-key"),
		Data: []byte("valid-data"),
	}
	if err := wal.Append(validEntry); err != nil {
		t.Fatal(err)
	}
	wal.Close()

	// Now manually craft a malicious entry with huge key length
	walFile := tmpDir + "/wal.log"
	f, err := os.OpenFile(walFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Write a malicious entry header:
	// - 4 bytes CRC (fake)
	// - 1 byte type
	// - 4 bytes key length (maliciously large: 0x10000000 = 256MB)
	malicious := []byte{
		0x00, 0x00, 0x00, 0x00, // CRC (won't be validated if key length check fires first)
		0x01,                   // Type: WALTypeBlock
		0x10, 0x00, 0x00, 0x00, // Key length: 256MB (big endian)
	}
	if _, err := f.Write(malicious); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Reopen and try to read
	wal2, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal2.Close()

	// ReadAll should fail on the malicious entry
	_, err = wal2.ReadAll()
	if err == nil {
		t.Fatal("Expected error for malformed key length, got nil")
	}

	if !errors.Is(err, ErrWALKeyTooLarge) {
		t.Fatalf("Expected ErrWALKeyTooLarge, got: %v", err)
	}
}

// TestWALReadAllRejectsMalformedDataLength tests that ReadAll validates data length
func TestWALReadAllRejectsMalformedDataLength(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swift-wal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create malicious WAL directly - entry with valid key length but huge data length
	walFile := tmpDir + "/wal.log"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(walFile)
	if err != nil {
		t.Fatal(err)
	}

	// Write entry with valid key but malicious data length:
	// - 4 bytes CRC (fake)
	// - 1 byte type
	// - 4 bytes key length (valid: 4)
	// - 4 bytes key data
	// - 4 bytes data length (maliciously large: 256MB)
	malicious := []byte{
		0x00, 0x00, 0x00, 0x00, // CRC
		0x01,                   // Type: WALTypeBlock
		0x00, 0x00, 0x00, 0x04, // Key length: 4 bytes
		't', 'e', 's', 't', // Key data
		0x10, 0x00, 0x00, 0x00, // Data length: 256MB (big endian)
	}
	if _, err := f.Write(malicious); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Open and try to read
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	// ReadAll should fail on the malicious entry
	_, err = wal.ReadAll()
	if err == nil {
		t.Fatal("Expected error for malformed data length, got nil")
	}

	if !errors.Is(err, ErrWALDataTooLarge) {
		t.Fatalf("Expected ErrWALDataTooLarge, got: %v", err)
	}
}

// TestWALSecurityConstants verifies the size limits are sensible
func TestWALSecurityConstants(t *testing.T) {
	// Key size should be reasonable (1KB)
	if MaxWALKeySize != 1024 {
		t.Errorf("MaxWALKeySize should be 1024, got %d", MaxWALKeySize)
	}

	// Data size should be reasonable for blocks (16MB)
	if MaxWALDataSize != 16*1024*1024 {
		t.Errorf("MaxWALDataSize should be 16MB, got %d", MaxWALDataSize)
	}

	// Entry size should be sum of key + data + overhead
	expectedEntrySize := MaxWALKeySize + MaxWALDataSize + 13
	if MaxWALEntrySize != expectedEntrySize {
		t.Errorf("MaxWALEntrySize should be %d, got %d", expectedEntrySize, MaxWALEntrySize)
	}
}
