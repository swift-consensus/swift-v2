package storage

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

var (
	// ErrWALKeyTooLarge is returned when WAL key exceeds MaxWALKeySize
	ErrWALKeyTooLarge = errors.New("WAL key size exceeds maximum")

	// ErrWALDataTooLarge is returned when WAL data exceeds MaxWALDataSize
	ErrWALDataTooLarge = errors.New("WAL data size exceeds maximum")
)

// WAL entry types
const (
	WALTypeBlock     byte = 1
	WALTypeValidator byte = 2
	WALTypeFinalize  byte = 3
	WALTypeMeta      byte = 4
	WALTypeTrust     byte = 5
)

// SECURITY: WAL entry size limits to prevent memory exhaustion DoS
const (
	// MaxWALKeySize is the maximum allowed key size (1KB)
	MaxWALKeySize = 1024

	// MaxWALDataSize is the maximum allowed data size (16MB)
	// This accommodates large blocks with many transactions
	MaxWALDataSize = 16 * 1024 * 1024

	// MaxWALEntrySize is the maximum total entry size
	MaxWALEntrySize = MaxWALKeySize + MaxWALDataSize + 13 // +13 for CRC, type, lengths
)

// WALEntry represents a single write-ahead log entry
type WALEntry struct {
	Type byte   // Entry type
	Key  []byte // Key being written
	Data []byte // Data being written
}

// WAL provides write-ahead logging for crash recovery
type WAL struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	path     string
	segmentSize int64
	currentSize int64
}

// WAL file format per entry:
// - 4 bytes: CRC32 checksum
// - 1 byte:  Entry type
// - 4 bytes: Key length
// - N bytes: Key
// - 4 bytes: Data length
// - M bytes: Data

// NewWAL creates a new WAL at the given path
func NewWAL(path string) (*WAL, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}

	walFile := filepath.Join(path, "wal.log")
	file, err := os.OpenFile(walFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// Get current file size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	return &WAL{
		file:        file,
		writer:      bufio.NewWriter(file),
		path:        path,
		segmentSize: 64 * 1024 * 1024, // 64MB segments
		currentSize: info.Size(),
	}, nil
}

// Append adds an entry to the WAL
func (w *WAL) Append(entry WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// SECURITY FIX #14: Validate entry sizes before writing
	if len(entry.Key) > MaxWALKeySize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrWALKeyTooLarge, len(entry.Key), MaxWALKeySize)
	}
	if len(entry.Data) > MaxWALDataSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrWALDataTooLarge, len(entry.Data), MaxWALDataSize)
	}

	// Calculate entry size
	entrySize := 4 + 1 + 4 + len(entry.Key) + 4 + len(entry.Data)

	// Build entry buffer
	buf := make([]byte, entrySize)
	offset := 4 // Skip CRC for now

	buf[offset] = entry.Type
	offset++

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(entry.Key)))
	offset += 4

	copy(buf[offset:], entry.Key)
	offset += len(entry.Key)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(entry.Data)))
	offset += 4

	copy(buf[offset:], entry.Data)

	// Calculate CRC32 over entry content (excluding CRC itself)
	crc := crc32.ChecksumIEEE(buf[4:])
	binary.BigEndian.PutUint32(buf[0:4], crc)

	// Write to WAL
	n, err := w.writer.Write(buf)
	if err != nil {
		return err
	}
	w.currentSize += int64(n)

	// Flush writer
	return w.writer.Flush()
}

// ReadAll reads all entries from the WAL
func (w *WAL) ReadAll() ([]WALEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Seek to beginning
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var entries []WALEntry
	reader := bufio.NewReader(w.file)

	for {
		// Read CRC
		crcBuf := make([]byte, 4)
		_, err := io.ReadFull(reader, crcBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		expectedCRC := binary.BigEndian.Uint32(crcBuf)

		// Read type
		typeBuf := make([]byte, 1)
		if _, err := io.ReadFull(reader, typeBuf); err != nil {
			return nil, err
		}

		// Read key length
		keyLenBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, keyLenBuf); err != nil {
			return nil, err
		}
		keyLen := binary.BigEndian.Uint32(keyLenBuf)

		// SECURITY FIX #14: Validate key length to prevent memory exhaustion DoS
		if keyLen > MaxWALKeySize {
			log.Printf("[WAL] SECURITY: Rejected entry %d with key size %d (max: %d). "+
				"This may indicate WAL corruption or attack. Stopping recovery.",
				len(entries), keyLen, MaxWALKeySize)
			return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrWALKeyTooLarge, keyLen, MaxWALKeySize)
		}

		// Read key
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(reader, key); err != nil {
			return nil, err
		}

		// Read data length
		dataLenBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, dataLenBuf); err != nil {
			return nil, err
		}
		dataLen := binary.BigEndian.Uint32(dataLenBuf)

		// SECURITY FIX #14: Validate data length to prevent memory exhaustion DoS
		if dataLen > MaxWALDataSize {
			log.Printf("[WAL] SECURITY: Rejected entry %d with data size %d (max: %d). "+
				"This may indicate WAL corruption or attack. Stopping recovery.",
				len(entries), dataLen, MaxWALDataSize)
			return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrWALDataTooLarge, dataLen, MaxWALDataSize)
		}

		// Read data
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}

		// Verify CRC
		contentLen := 1 + 4 + len(key) + 4 + len(data)
		content := make([]byte, contentLen)
		content[0] = typeBuf[0]
		copy(content[1:5], keyLenBuf)
		copy(content[5:5+keyLen], key)
		copy(content[5+keyLen:9+keyLen], dataLenBuf)
		copy(content[9+keyLen:], data)

		actualCRC := crc32.ChecksumIEEE(content)
		if actualCRC != expectedCRC {
			// SECURITY FIX: Alert operators on WAL corruption
			// CRC mismatch indicates either:
			// 1. Partial write during crash (expected during recovery)
			// 2. Data corruption (requires investigation)
			log.Printf("[WAL] CORRUPTION DETECTED: CRC mismatch at entry %d (expected: %x, actual: %x). "+
				"Recovery stopped with %d valid entries. This may indicate partial write during crash "+
				"or storage corruption. Investigate if unexpected.",
				len(entries), expectedCRC, actualCRC, len(entries))
			break
		}

		entries = append(entries, WALEntry{
			Type: typeBuf[0],
			Key:  key,
			Data: data,
		})
	}

	return entries, nil
}

// Sync flushes the WAL to disk
func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// Truncate clears the WAL
func (w *WAL) Truncate() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Flush and sync first
	if err := w.writer.Flush(); err != nil {
		return err
	}

	// Close current file
	if err := w.file.Close(); err != nil {
		return err
	}

	// Truncate file
	walFile := filepath.Join(w.path, "wal.log")
	file, err := os.OpenFile(walFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	w.file = file
	w.writer = bufio.NewWriter(file)
	w.currentSize = 0

	return nil
}

// Close closes the WAL
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}

	return w.file.Close()
}

// Size returns the current WAL size in bytes
func (w *WAL) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentSize
}
