// Package network provides network transport interfaces for SWIFT v2 consensus.
package network

import (
	"github.com/swift-consensus/swift-v2/types"
)

// MessageType identifies the type of network message
type MessageType int

const (
	MessageTypePropose MessageType = iota
	MessageTypeVote
	MessageTypeFinalize
	MessageTypeViewChange
	MessageTypeViewChangeCert
	MessageTypeHeartbeat
	MessageTypeSyncRequest
	MessageTypeSyncResponse
)

// Message is a wrapper for network messages
type Message struct {
	Type    MessageType
	From    types.PublicKey
	Payload interface{}
}

// Transport is the interface for network communication
type Transport interface {
	// Broadcast sends a message to all peers
	Broadcast(msg interface{})

	// SendTo sends a message to a specific peer
	SendTo(peer types.PublicKey, msg interface{})

	// OnReceive registers a callback for incoming messages
	OnReceive(handler MessageHandler)

	// Start starts the transport
	Start() error

	// Stop stops the transport
	Stop() error

	// Peers returns the list of connected peers
	Peers() []types.PublicKey

	// IsConnected checks if connected to a specific peer
	IsConnected(peer types.PublicKey) bool
}

// MessageHandler is a callback for handling messages
type MessageHandler func(msg *Message)

// PeerInfo contains information about a peer
type PeerInfo struct {
	PublicKey types.PublicKey
	Address   string
	Latency   int64 // Latency in milliseconds
	Connected bool
}

// AdvancedTransport extends Transport with additional features
type AdvancedTransport interface {
	Transport

	// GetPeerInfo returns detailed peer information
	GetPeerInfo(peer types.PublicKey) *PeerInfo

	// GetAllPeerInfo returns information about all peers
	GetAllPeerInfo() []PeerInfo

	// SetLatencySimulation enables latency simulation (for testing)
	SetLatencySimulation(minMs, maxMs int)

	// SetPacketLoss enables packet loss simulation (for testing)
	SetPacketLoss(rate float64)

	// Stats returns transport statistics
	Stats() TransportStats
}

// TransportStats contains transport statistics
type TransportStats struct {
	MessagesSent     uint64
	MessagesReceived uint64
	BytesSent        uint64
	BytesReceived    uint64
	ActivePeers      int
	AvgLatency       int64
}

// SyncRequest is a request for block sync
type SyncRequest struct {
	FromHeight uint64
	ToHeight   uint64
	Requester  types.PublicKey
}

// SyncResponse is a response to a sync request
type SyncResponse struct {
	Blocks []types.Block
	From   types.PublicKey
}
