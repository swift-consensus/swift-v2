// Package storage provides persistent storage for SWIFT v2 consensus state.
package storage

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/swift-consensus/swift-v2/types"
)

var (
	// ErrNotFound is returned when a key is not found
	ErrNotFound = errors.New("key not found")

	// ErrClosed is returned when the store is closed
	ErrClosed = errors.New("store is closed")

	// Key prefixes for different data types
	prefixBlock      = []byte("b") // b + height -> Block
	prefixBlockHash  = []byte("h") // h + hash -> height
	prefixValidator  = []byte("v") // v + pubkey -> Validator
	prefixState      = []byte("s") // s + key -> state data
	prefixTrust      = []byte("t") // t + pubkey -> TrustInfo
	prefixFinalizer  = []byte("f") // f + height -> FinalizeMsg
	prefixMeta       = []byte("m") // m + key -> metadata
)

// Store provides persistent storage for consensus state
type Store struct {
	mu     sync.RWMutex
	db     *leveldb.DB
	wal    *WAL
	closed bool
	path   string
}

// StoreConfig configures the store
type StoreConfig struct {
	Path           string
	WALEnabled     bool
	WriteBuffer    int // LevelDB write buffer size in MB
	CacheSize      int // LevelDB cache size in MB
}

// DefaultStoreConfig returns a default configuration
func DefaultStoreConfig(path string) StoreConfig {
	return StoreConfig{
		Path:        path,
		WALEnabled:  true,
		WriteBuffer: 16,
		CacheSize:   64,
	}
}

// NewStore creates a new persistent store
func NewStore(config StoreConfig) (*Store, error) {
	opts := &opt.Options{
		WriteBuffer: config.WriteBuffer * opt.MiB,
		BlockCacheCapacity: config.CacheSize * opt.MiB,
	}

	db, err := leveldb.OpenFile(config.Path, opts)
	if err != nil {
		return nil, err
	}

	store := &Store{
		db:   db,
		path: config.Path,
	}

	// Initialize WAL if enabled
	if config.WALEnabled {
		walPath := filepath.Join(config.Path, "wal")
		wal, err := NewWAL(walPath)
		if err != nil {
			db.Close()
			return nil, err
		}
		store.wal = wal

		// Recover from WAL if needed
		if err := store.recoverFromWAL(); err != nil {
			wal.Close()
			db.Close()
			return nil, err
		}
	}

	return store, nil
}

// Close closes the store
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	if s.wal != nil {
		if err := s.wal.Close(); err != nil {
			return err
		}
	}

	return s.db.Close()
}

// heightKey creates a key for block height
func heightKey(height uint64) []byte {
	key := make([]byte, 9)
	key[0] = prefixBlock[0]
	binary.BigEndian.PutUint64(key[1:], height)
	return key
}

// hashKey creates a key for block hash
func hashKey(hash types.Hash) []byte {
	key := make([]byte, 33)
	key[0] = prefixBlockHash[0]
	copy(key[1:], hash[:])
	return key
}

// validatorKey creates a key for validator public key
func validatorKey(pubKey types.PublicKey) []byte {
	key := make([]byte, 49)
	key[0] = prefixValidator[0]
	copy(key[1:], pubKey[:])
	return key
}

// trustKey creates a key for trust info
func trustKey(pubKey types.PublicKey) []byte {
	key := make([]byte, 49)
	key[0] = prefixTrust[0]
	copy(key[1:], pubKey[:])
	return key
}

// finalizerKey creates a key for finalize message
func finalizerKey(height uint64) []byte {
	key := make([]byte, 9)
	key[0] = prefixFinalizer[0]
	binary.BigEndian.PutUint64(key[1:], height)
	return key
}

// metaKey creates a key for metadata
func metaKey(name string) []byte {
	key := make([]byte, 1+len(name))
	key[0] = prefixMeta[0]
	copy(key[1:], name)
	return key
}

// SaveBlock saves a block to storage
func (s *Store) SaveBlock(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	// Write to WAL first
	if s.wal != nil {
		entry := WALEntry{
			Type: WALTypeBlock,
			Key:  heightKey(block.Height),
			Data: data,
		}
		if err := s.wal.Append(entry); err != nil {
			return err
		}
	}

	// Write block by height
	batch := new(leveldb.Batch)
	batch.Put(heightKey(block.Height), data)

	// Write hash -> height index
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Height)
	hash := block.Hash()
	batch.Put(hashKey(hash), heightBytes)

	return s.db.Write(batch, nil)
}

// GetBlock retrieves a block by height
func (s *Store) GetBlock(height uint64) (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	data, err := s.db.Get(heightKey(height), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var block types.Block
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

// GetBlockByHash retrieves a block by its hash
// SECURITY FIX: Removed manual unlock/relock that caused potential deadlock
func (s *Store) GetBlockByHash(hash types.Hash) (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	// Get height from hash index
	heightBytes, err := s.db.Get(hashKey(hash), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	height := binary.BigEndian.Uint64(heightBytes)

	// Directly access the database while holding the lock
	// instead of calling GetBlock which would try to acquire another lock
	data, err := s.db.Get(heightKey(height), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var block types.Block
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

// SaveValidator saves validator state
func (s *Store) SaveValidator(v *types.Validator) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	key := validatorKey(v.PublicKey)

	// Write to WAL
	if s.wal != nil {
		entry := WALEntry{
			Type: WALTypeValidator,
			Key:  key,
			Data: data,
		}
		if err := s.wal.Append(entry); err != nil {
			return err
		}
	}

	return s.db.Put(key, data, nil)
}

// GetValidator retrieves a validator by public key
func (s *Store) GetValidator(pubKey types.PublicKey) (*types.Validator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	data, err := s.db.Get(validatorKey(pubKey), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var v types.Validator
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

// SaveValidatorSet saves the entire validator set
func (s *Store) SaveValidatorSet(vs *types.ValidatorSet) error {
	for _, v := range vs.Validators {
		if err := s.SaveValidator(v); err != nil {
			return err
		}
	}
	return nil
}

// LoadValidatorSet loads all validators
func (s *Store) LoadValidatorSet() (*types.ValidatorSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	vs := types.NewValidatorSet()

	iter := s.db.NewIterator(util.BytesPrefix(prefixValidator), nil)
	defer iter.Release()

	for iter.Next() {
		var v types.Validator
		if err := json.Unmarshal(iter.Value(), &v); err != nil {
			return nil, err
		}
		vs.Add(&v)
	}

	if err := iter.Error(); err != nil {
		return nil, err
	}

	return vs, nil
}

// SaveFinalizeMsg saves a finalization message
func (s *Store) SaveFinalizeMsg(msg *types.FinalizeMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	key := finalizerKey(msg.Block.Height)

	if s.wal != nil {
		entry := WALEntry{
			Type: WALTypeFinalize,
			Key:  key,
			Data: data,
		}
		if err := s.wal.Append(entry); err != nil {
			return err
		}
	}

	return s.db.Put(key, data, nil)
}

// GetFinalizeMsg retrieves a finalization message by height
func (s *Store) GetFinalizeMsg(height uint64) (*types.FinalizeMsg, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	data, err := s.db.Get(finalizerKey(height), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var msg types.FinalizeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// ConsensusState holds the current consensus state for persistence
type ConsensusState struct {
	Height          uint64     `json:"height"`
	Round           uint32     `json:"round"`
	LastFinalizedHash types.Hash `json:"last_finalized_hash"`
	LastFinalizedHeight uint64 `json:"last_finalized_height"`
}

// SaveConsensusState saves the consensus state
func (s *Store) SaveConsensusState(state *ConsensusState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	key := metaKey("consensus_state")

	if s.wal != nil {
		entry := WALEntry{
			Type: WALTypeMeta,
			Key:  key,
			Data: data,
		}
		if err := s.wal.Append(entry); err != nil {
			return err
		}
	}

	return s.db.Put(key, data, nil)
}

// GetConsensusState retrieves the consensus state
func (s *Store) GetConsensusState() (*ConsensusState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrClosed
	}

	data, err := s.db.Get(metaKey("consensus_state"), nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var state ConsensusState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// GetLatestHeight returns the latest block height
func (s *Store) GetLatestHeight() (uint64, error) {
	state, err := s.GetConsensusState()
	if err == ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return state.Height, nil
}

// recoverFromWAL replays WAL entries to recover from crash
func (s *Store) recoverFromWAL() error {
	if s.wal == nil {
		return nil
	}

	entries, err := s.wal.ReadAll()
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	batch := new(leveldb.Batch)
	for _, entry := range entries {
		batch.Put(entry.Key, entry.Data)
	}

	if err := s.db.Write(batch, nil); err != nil {
		return err
	}

	// Clear WAL after successful recovery
	return s.wal.Truncate()
}

// Sync forces a sync of the WAL to disk
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	if s.wal != nil {
		return s.wal.Sync()
	}

	return nil
}

// Compact triggers LevelDB compaction
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	return s.db.CompactRange(util.Range{})
}
