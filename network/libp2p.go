package network

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/swift-consensus/swift-v2/types"
)

const (
	// Protocol ID for SWIFT consensus messages
	ProtocolID = protocol.ID("/swift/consensus/1.0.0")

	// Topic name for gossip
	TopicName = "swift-consensus"

	// Discovery service tag
	DiscoveryServiceTag = "swift-discovery"
)

// LibP2PConfig configures the libp2p transport
type LibP2PConfig struct {
	ListenAddrs    []string
	BootstrapPeers []string
	PrivateKey     []byte           // Optional: if nil, generates new key
	ValidatorKey   types.PublicKey  // Our validator public key
	EnableMDNS     bool             // Enable local network discovery
	EnableRelay    bool             // Enable relay for NAT traversal
}

// DefaultLibP2PConfig returns a default configuration
func DefaultLibP2PConfig() LibP2PConfig {
	return LibP2PConfig{
		ListenAddrs: []string{"/ip4/0.0.0.0/tcp/9000"},
		EnableMDNS:  true,
		EnableRelay: true,
	}
}

// LibP2PTransport implements Transport using libp2p
type LibP2PTransport struct {
	mu sync.RWMutex

	config  LibP2PConfig
	host    host.Host
	pubsub  *pubsub.PubSub
	topic   *pubsub.Topic
	sub     *pubsub.Subscription
	ctx     context.Context
	cancel  context.CancelFunc
	handler MessageHandler

	// Peer management
	peers       map[string]types.PublicKey // libp2p peer ID -> validator key
	peersByKey  map[string]peer.ID         // validator key hex -> libp2p peer ID
	peerLatency map[string]int64           // peer ID -> latency in ms

	// Stats
	stats TransportStats
}

// NewLibP2PTransport creates a new libp2p-based transport
func NewLibP2PTransport(config LibP2PConfig) (*LibP2PTransport, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create or use provided private key
	var priv crypto.PrivKey
	var err error
	if config.PrivateKey != nil {
		priv, err = crypto.UnmarshalPrivateKey(config.PrivateKey)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
	} else {
		priv, _, err = crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
	}

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(config.ListenAddrs...),
	}

	if config.EnableRelay {
		opts = append(opts, libp2p.EnableRelay())
	}

	// Create libp2p host
	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create pubsub
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create gossipsub: %w", err)
	}

	// Join topic
	topic, err := ps.Join(TopicName)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to join topic: %w", err)
	}

	// Subscribe to topic
	sub, err := topic.Subscribe()
	if err != nil {
		topic.Close()
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	t := &LibP2PTransport{
		config:      config,
		host:        h,
		pubsub:      ps,
		topic:       topic,
		sub:         sub,
		ctx:         ctx,
		cancel:      cancel,
		peers:       make(map[string]types.PublicKey),
		peersByKey:  make(map[string]peer.ID),
		peerLatency: make(map[string]int64),
	}

	// Set up connection notifier
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			t.onPeerConnected(c.RemotePeer())
		},
		DisconnectedF: func(n network.Network, c network.Conn) {
			t.onPeerDisconnected(c.RemotePeer())
		},
	})

	return t, nil
}

// Start starts the transport
func (t *LibP2PTransport) Start() error {
	// Set up mDNS discovery if enabled
	if t.config.EnableMDNS {
		if err := t.setupMDNS(); err != nil {
			return fmt.Errorf("failed to setup mDNS: %w", err)
		}
	}

	// Connect to bootstrap peers
	for _, addr := range t.config.BootstrapPeers {
		if err := t.connectToPeer(addr); err != nil {
			// Log error but continue - not fatal
			fmt.Printf("Failed to connect to bootstrap peer %s: %v\n", addr, err)
		}
	}

	// Start message reading goroutine
	go t.readMessages()

	return nil
}

// Stop stops the transport
func (t *LibP2PTransport) Stop() error {
	t.cancel()

	if t.sub != nil {
		t.sub.Cancel()
	}
	if t.topic != nil {
		t.topic.Close()
	}
	if t.host != nil {
		return t.host.Close()
	}
	return nil
}

// Broadcast sends a message to all peers via gossip
func (t *LibP2PTransport) Broadcast(msg interface{}) {
	data, err := t.serializeMessage(msg)
	if err != nil {
		fmt.Printf("Failed to serialize message: %v\n", err)
		return
	}

	if err := t.topic.Publish(t.ctx, data); err != nil {
		fmt.Printf("Failed to publish message: %v\n", err)
		return
	}

	t.mu.Lock()
	t.stats.MessagesSent++
	t.stats.BytesSent += uint64(len(data))
	t.mu.Unlock()
}

// SendTo sends a message to a specific peer
func (t *LibP2PTransport) SendTo(peerKey types.PublicKey, msg interface{}) {
	t.mu.RLock()
	peerID, exists := t.peersByKey[string(peerKey[:])]
	t.mu.RUnlock()

	if !exists {
		return
	}

	data, err := t.serializeMessage(msg)
	if err != nil {
		return
	}

	// Open stream to peer
	stream, err := t.host.NewStream(t.ctx, peerID, ProtocolID)
	if err != nil {
		return
	}
	defer stream.Close()

	// Send message
	_, err = stream.Write(data)
	if err != nil {
		return
	}

	t.mu.Lock()
	t.stats.MessagesSent++
	t.stats.BytesSent += uint64(len(data))
	t.mu.Unlock()
}

// OnReceive registers a callback for incoming messages
func (t *LibP2PTransport) OnReceive(handler MessageHandler) {
	t.mu.Lock()
	t.handler = handler
	t.mu.Unlock()
}

// Peers returns the list of connected peers
func (t *LibP2PTransport) Peers() []types.PublicKey {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peers := make([]types.PublicKey, 0, len(t.peers))
	for _, pk := range t.peers {
		peers = append(peers, pk)
	}
	return peers
}

// IsConnected checks if connected to a specific peer
func (t *LibP2PTransport) IsConnected(peerKey types.PublicKey) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, exists := t.peersByKey[string(peerKey[:])]
	return exists
}

// GetPeerInfo returns detailed peer information
func (t *LibP2PTransport) GetPeerInfo(peerKey types.PublicKey) *PeerInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peerID, exists := t.peersByKey[string(peerKey[:])]
	if !exists {
		return nil
	}

	addrs := t.host.Peerstore().Addrs(peerID)
	addrStr := ""
	if len(addrs) > 0 {
		addrStr = addrs[0].String()
	}

	latency := t.peerLatency[peerID.String()]

	return &PeerInfo{
		PublicKey: peerKey,
		Address:   addrStr,
		Latency:   latency,
		Connected: true,
	}
}

// GetAllPeerInfo returns information about all peers
func (t *LibP2PTransport) GetAllPeerInfo() []PeerInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	infos := make([]PeerInfo, 0, len(t.peers))
	for peerIDStr, pk := range t.peers {
		peerID, _ := peer.Decode(peerIDStr)
		addrs := t.host.Peerstore().Addrs(peerID)
		addrStr := ""
		if len(addrs) > 0 {
			addrStr = addrs[0].String()
		}

		infos = append(infos, PeerInfo{
			PublicKey: pk,
			Address:   addrStr,
			Latency:   t.peerLatency[peerIDStr],
			Connected: true,
		})
	}
	return infos
}

// SetLatencySimulation is not supported in production transport
func (t *LibP2PTransport) SetLatencySimulation(minMs, maxMs int) {
	// No-op in production
}

// SetPacketLoss is not supported in production transport
func (t *LibP2PTransport) SetPacketLoss(rate float64) {
	// No-op in production
}

// Stats returns transport statistics
func (t *LibP2PTransport) Stats() TransportStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := t.stats
	stats.ActivePeers = len(t.peers)

	// Calculate average latency
	if len(t.peerLatency) > 0 {
		var total int64
		for _, l := range t.peerLatency {
			total += l
		}
		stats.AvgLatency = total / int64(len(t.peerLatency))
	}

	return stats
}

// HostID returns the libp2p host ID
func (t *LibP2PTransport) HostID() peer.ID {
	return t.host.ID()
}

// HostAddrs returns the addresses the host is listening on
func (t *LibP2PTransport) HostAddrs() []string {
	addrs := t.host.Addrs()
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = fmt.Sprintf("%s/p2p/%s", addr.String(), t.host.ID().String())
	}
	return result
}

// RegisterValidatorKey registers the mapping between libp2p peer ID and validator key
func (t *LibP2PTransport) RegisterValidatorKey(peerID peer.ID, validatorKey types.PublicKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.peers[peerID.String()] = validatorKey
	t.peersByKey[string(validatorKey[:])] = peerID
}

// readMessages reads messages from the subscription
func (t *LibP2PTransport) readMessages() {
	for {
		msg, err := t.sub.Next(t.ctx)
		if err != nil {
			if t.ctx.Err() != nil {
				return // Context cancelled
			}
			continue
		}

		// Skip self messages
		if msg.ReceivedFrom == t.host.ID() {
			continue
		}

		t.mu.Lock()
		t.stats.MessagesReceived++
		t.stats.BytesReceived += uint64(len(msg.Data))
		t.mu.Unlock()

		// Deserialize and handle
		parsedMsg, err := t.deserializeMessage(msg.Data, msg.ReceivedFrom)
		if err != nil {
			continue
		}

		t.mu.RLock()
		handler := t.handler
		t.mu.RUnlock()

		if handler != nil {
			handler(parsedMsg)
		}
	}
}

// GossipMessage wraps a message for gossip with type info
type GossipMessage struct {
	Type          MessageType `json:"type"`
	ValidatorKey  []byte      `json:"validator_key"`
	Payload       []byte      `json:"payload"`
}

// serializeMessage serializes a message for transmission
func (t *LibP2PTransport) serializeMessage(msg interface{}) ([]byte, error) {
	var msgType MessageType
	switch msg.(type) {
	case *types.Block:
		msgType = MessageTypePropose
	case *types.Vote:
		msgType = MessageTypeVote
	case *types.FinalizeMsg:
		msgType = MessageTypeFinalize
	case *types.ViewChangeMsg:
		msgType = MessageTypeViewChange
	case *types.ViewChangeCert:
		msgType = MessageTypeViewChangeCert
	case *types.HeartbeatMsg:
		msgType = MessageTypeHeartbeat
	case *SyncRequest:
		msgType = MessageTypeSyncRequest
	case *SyncResponse:
		msgType = MessageTypeSyncResponse
	default:
		return nil, fmt.Errorf("unknown message type: %T", msg)
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	gossipMsg := GossipMessage{
		Type:         msgType,
		ValidatorKey: t.config.ValidatorKey[:],
		Payload:      payload,
	}

	return json.Marshal(gossipMsg)
}

// deserializeMessage deserializes a received message
func (t *LibP2PTransport) deserializeMessage(data []byte, from peer.ID) (*Message, error) {
	var gossipMsg GossipMessage
	if err := json.Unmarshal(data, &gossipMsg); err != nil {
		return nil, err
	}

	var fromKey types.PublicKey
	copy(fromKey[:], gossipMsg.ValidatorKey)

	var payload interface{}
	var err error

	switch gossipMsg.Type {
	case MessageTypePropose:
		var block types.Block
		err = json.Unmarshal(gossipMsg.Payload, &block)
		payload = &block
	case MessageTypeVote:
		var vote types.Vote
		err = json.Unmarshal(gossipMsg.Payload, &vote)
		payload = &vote
	case MessageTypeFinalize:
		var msg types.FinalizeMsg
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	case MessageTypeViewChange:
		var msg types.ViewChangeMsg
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	case MessageTypeViewChangeCert:
		var msg types.ViewChangeCert
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	case MessageTypeHeartbeat:
		var msg types.HeartbeatMsg
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	case MessageTypeSyncRequest:
		var msg SyncRequest
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	case MessageTypeSyncResponse:
		var msg SyncResponse
		err = json.Unmarshal(gossipMsg.Payload, &msg)
		payload = &msg
	default:
		return nil, fmt.Errorf("unknown message type: %d", gossipMsg.Type)
	}

	if err != nil {
		return nil, err
	}

	// Register the peer's validator key if not already known
	t.RegisterValidatorKey(from, fromKey)

	return &Message{
		Type:    gossipMsg.Type,
		From:    fromKey,
		Payload: payload,
	}, nil
}

// connectToPeer connects to a peer by multiaddr string
func (t *LibP2PTransport) connectToPeer(addr string) error {
	maddr, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()

	return t.host.Connect(ctx, *maddr)
}

// onPeerConnected handles new peer connections
func (t *LibP2PTransport) onPeerConnected(peerID peer.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Start latency measurement
	go t.measureLatency(peerID)
}

// onPeerDisconnected handles peer disconnections
func (t *LibP2PTransport) onPeerDisconnected(peerID peer.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	peerIDStr := peerID.String()
	if pk, exists := t.peers[peerIDStr]; exists {
		delete(t.peers, peerIDStr)
		delete(t.peersByKey, string(pk[:]))
		delete(t.peerLatency, peerIDStr)
	}
}

// measureLatency measures latency to a peer
func (t *LibP2PTransport) measureLatency(peerID peer.ID) {
	// Simple ping-based latency measurement
	start := time.Now()

	ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()

	// Try to open a stream as a simple connectivity check
	stream, err := t.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return
	}
	stream.Close()

	latency := time.Since(start).Milliseconds()

	t.mu.Lock()
	t.peerLatency[peerID.String()] = latency
	t.mu.Unlock()
}

// setupMDNS sets up mDNS discovery for local network peers
func (t *LibP2PTransport) setupMDNS() error {
	s := mdns.NewMdnsService(t.host, DiscoveryServiceTag, t)
	return s.Start()
}

// HandlePeerFound implements mdns.Notifee interface
func (t *LibP2PTransport) HandlePeerFound(info peer.AddrInfo) {
	if info.ID == t.host.ID() {
		return // Skip self
	}

	ctx, cancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer cancel()

	if err := t.host.Connect(ctx, info); err != nil {
		fmt.Printf("Failed to connect to discovered peer %s: %v\n", info.ID, err)
	}
}
