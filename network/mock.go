package network

import (
	"math/rand"
	"sync"
	"time"

	"github.com/swift-consensus/swift-v2/types"
)

// MockTransport is a mock transport for testing
type MockTransport struct {
	mu sync.RWMutex

	// Identity
	localKey types.PublicKey

	// Peers
	peers map[string]*MockTransport // pubkey hex -> transport

	// Message handler
	handler MessageHandler

	// Message queues
	inbox chan *Message

	// Simulation settings
	minLatencyMs int
	maxLatencyMs int
	packetLoss   float64

	// State
	running bool
	stopCh  chan struct{}

	// Stats
	stats TransportStats
}

// NewMockTransport creates a new mock transport
func NewMockTransport(localKey types.PublicKey) *MockTransport {
	return &MockTransport{
		localKey:     localKey,
		peers:        make(map[string]*MockTransport),
		inbox:        make(chan *Message, 10000),
		minLatencyMs: 0,
		maxLatencyMs: 0,
		packetLoss:   0,
		stopCh:       make(chan struct{}),
	}
}

// Connect connects this transport to another
func (mt *MockTransport) Connect(other *MockTransport) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	key := string(other.localKey[:])
	mt.peers[key] = other

	// Bidirectional connection
	other.mu.Lock()
	other.peers[string(mt.localKey[:])] = mt
	other.mu.Unlock()

	mt.stats.ActivePeers++
}

// Disconnect disconnects from a peer
func (mt *MockTransport) Disconnect(peer types.PublicKey) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	key := string(peer[:])
	if other, ok := mt.peers[key]; ok {
		delete(mt.peers, key)
		mt.stats.ActivePeers--

		// Remove bidirectional connection
		other.mu.Lock()
		delete(other.peers, string(mt.localKey[:]))
		other.stats.ActivePeers--
		other.mu.Unlock()
	}
}

// Broadcast sends a message to all peers
func (mt *MockTransport) Broadcast(payload interface{}) {
	mt.mu.RLock()
	peers := make([]*MockTransport, 0, len(mt.peers))
	for _, p := range mt.peers {
		peers = append(peers, p)
	}
	mt.mu.RUnlock()

	msg := &Message{
		Type:    mt.getMessageType(payload),
		From:    mt.localKey,
		Payload: payload,
	}

	for _, peer := range peers {
		mt.sendToPeer(peer, msg)
	}

	mt.mu.Lock()
	mt.stats.MessagesSent += uint64(len(peers))
	mt.mu.Unlock()
}

// SendTo sends a message to a specific peer
func (mt *MockTransport) SendTo(peer types.PublicKey, payload interface{}) {
	mt.mu.RLock()
	target := mt.peers[string(peer[:])]
	mt.mu.RUnlock()

	if target == nil {
		return
	}

	msg := &Message{
		Type:    mt.getMessageType(payload),
		From:    mt.localKey,
		Payload: payload,
	}

	mt.sendToPeer(target, msg)

	mt.mu.Lock()
	mt.stats.MessagesSent++
	mt.mu.Unlock()
}

// sendToPeer sends a message to a peer with simulated latency and packet loss
func (mt *MockTransport) sendToPeer(peer *MockTransport, msg *Message) {
	// Simulate packet loss
	if mt.packetLoss > 0 && rand.Float64() < mt.packetLoss {
		return
	}

	// Simulate latency
	if mt.maxLatencyMs > mt.minLatencyMs {
		latency := mt.minLatencyMs + rand.Intn(mt.maxLatencyMs-mt.minLatencyMs)
		go func() {
			time.Sleep(time.Duration(latency) * time.Millisecond)
			peer.deliver(msg)
		}()
	} else if mt.minLatencyMs > 0 {
		go func() {
			time.Sleep(time.Duration(mt.minLatencyMs) * time.Millisecond)
			peer.deliver(msg)
		}()
	} else {
		go peer.deliver(msg)
	}
}

// deliver delivers a message to the inbox
func (mt *MockTransport) deliver(msg *Message) {
	mt.mu.Lock()
	mt.stats.MessagesReceived++
	mt.mu.Unlock()

	select {
	case mt.inbox <- msg:
	default:
		// Queue full, drop message
	}
}

// OnReceive registers a message handler
func (mt *MockTransport) OnReceive(handler MessageHandler) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.handler = handler
}

// Start starts the transport
func (mt *MockTransport) Start() error {
	mt.mu.Lock()
	if mt.running {
		mt.mu.Unlock()
		return nil
	}
	mt.running = true
	mt.stopCh = make(chan struct{})
	mt.mu.Unlock()

	go mt.processInbox()
	return nil
}

// Stop stops the transport
func (mt *MockTransport) Stop() error {
	mt.mu.Lock()
	if !mt.running {
		mt.mu.Unlock()
		return nil
	}
	mt.running = false
	close(mt.stopCh)
	mt.mu.Unlock()
	return nil
}

// processInbox processes incoming messages
func (mt *MockTransport) processInbox() {
	for {
		select {
		case <-mt.stopCh:
			return
		case msg := <-mt.inbox:
			mt.mu.RLock()
			handler := mt.handler
			mt.mu.RUnlock()

			if handler != nil {
				handler(msg)
			}
		}
	}
}

// Peers returns the list of connected peers
func (mt *MockTransport) Peers() []types.PublicKey {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	peers := make([]types.PublicKey, 0, len(mt.peers))
	for _, p := range mt.peers {
		peers = append(peers, p.localKey)
	}
	return peers
}

// IsConnected checks if connected to a peer
func (mt *MockTransport) IsConnected(peer types.PublicKey) bool {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	_, ok := mt.peers[string(peer[:])]
	return ok
}

// GetPeerInfo returns information about a peer
func (mt *MockTransport) GetPeerInfo(peer types.PublicKey) *PeerInfo {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	p, ok := mt.peers[string(peer[:])]
	if !ok {
		return nil
	}

	return &PeerInfo{
		PublicKey: p.localKey,
		Address:   "mock://" + p.localKey.Short(),
		Latency:   int64((mt.minLatencyMs + mt.maxLatencyMs) / 2),
		Connected: true,
	}
}

// GetAllPeerInfo returns information about all peers
func (mt *MockTransport) GetAllPeerInfo() []PeerInfo {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	infos := make([]PeerInfo, 0, len(mt.peers))
	for _, p := range mt.peers {
		infos = append(infos, PeerInfo{
			PublicKey: p.localKey,
			Address:   "mock://" + p.localKey.Short(),
			Latency:   int64((mt.minLatencyMs + mt.maxLatencyMs) / 2),
			Connected: true,
		})
	}
	return infos
}

// SetLatencySimulation sets simulated latency
func (mt *MockTransport) SetLatencySimulation(minMs, maxMs int) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.minLatencyMs = minMs
	mt.maxLatencyMs = maxMs
}

// SetPacketLoss sets simulated packet loss rate
func (mt *MockTransport) SetPacketLoss(rate float64) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.packetLoss = rate
}

// Stats returns transport statistics
func (mt *MockTransport) Stats() TransportStats {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.stats
}

// getMessageType determines the message type from payload
func (mt *MockTransport) getMessageType(payload interface{}) MessageType {
	switch payload.(type) {
	case *types.ProposeMsg:
		return MessageTypePropose
	case *types.Vote:
		return MessageTypeVote
	case *types.FinalizeMsg:
		return MessageTypeFinalize
	case *types.ViewChangeMsg:
		return MessageTypeViewChange
	case *types.ViewChangeCert:
		return MessageTypeViewChangeCert
	case *types.HeartbeatMsg:
		return MessageTypeHeartbeat
	case *SyncRequest:
		return MessageTypeSyncRequest
	case *SyncResponse:
		return MessageTypeSyncResponse
	default:
		return -1
	}
}

// MockNetwork creates a network of connected mock transports
type MockNetwork struct {
	mu         sync.RWMutex
	transports map[string]*MockTransport
}

// NewMockNetwork creates a new mock network
func NewMockNetwork() *MockNetwork {
	return &MockNetwork{
		transports: make(map[string]*MockTransport),
	}
}

// AddNode adds a node to the network
func (mn *MockNetwork) AddNode(key types.PublicKey) *MockTransport {
	mn.mu.Lock()
	defer mn.mu.Unlock()

	transport := NewMockTransport(key)
	keyStr := string(key[:])
	mn.transports[keyStr] = transport

	// Connect to all existing nodes
	for _, existing := range mn.transports {
		if string(existing.localKey[:]) != keyStr {
			transport.Connect(existing)
		}
	}

	return transport
}

// RemoveNode removes a node from the network
func (mn *MockNetwork) RemoveNode(key types.PublicKey) {
	mn.mu.Lock()
	defer mn.mu.Unlock()

	keyStr := string(key[:])
	transport, ok := mn.transports[keyStr]
	if !ok {
		return
	}

	// Disconnect from all peers
	for _, peer := range mn.transports {
		if string(peer.localKey[:]) != keyStr {
			transport.Disconnect(peer.localKey)
		}
	}

	delete(mn.transports, keyStr)
}

// GetTransport returns the transport for a node
func (mn *MockNetwork) GetTransport(key types.PublicKey) *MockTransport {
	mn.mu.RLock()
	defer mn.mu.RUnlock()
	return mn.transports[string(key[:])]
}

// SetGlobalLatency sets latency for all transports
func (mn *MockNetwork) SetGlobalLatency(minMs, maxMs int) {
	mn.mu.RLock()
	defer mn.mu.RUnlock()

	for _, t := range mn.transports {
		t.SetLatencySimulation(minMs, maxMs)
	}
}

// SetGlobalPacketLoss sets packet loss for all transports
func (mn *MockNetwork) SetGlobalPacketLoss(rate float64) {
	mn.mu.RLock()
	defer mn.mu.RUnlock()

	for _, t := range mn.transports {
		t.SetPacketLoss(rate)
	}
}

// Partition creates a network partition
func (mn *MockNetwork) Partition(group1, group2 []types.PublicKey) {
	mn.mu.Lock()
	defer mn.mu.Unlock()

	// Disconnect group1 from group2
	for _, pk1 := range group1 {
		t1 := mn.transports[string(pk1[:])]
		if t1 == nil {
			continue
		}

		for _, pk2 := range group2 {
			t1.Disconnect(pk2)
		}
	}
}

// Heal heals a network partition
func (mn *MockNetwork) Heal() {
	mn.mu.Lock()
	defer mn.mu.Unlock()

	// Reconnect all nodes
	keys := make([]string, 0, len(mn.transports))
	for k := range mn.transports {
		keys = append(keys, k)
	}

	for i, k1 := range keys {
		for j := i + 1; j < len(keys); j++ {
			k2 := keys[j]
			t1 := mn.transports[k1]
			t2 := mn.transports[k2]

			if !t1.IsConnected(t2.localKey) {
				t1.Connect(t2)
			}
		}
	}
}

// StartAll starts all transports
func (mn *MockNetwork) StartAll() {
	mn.mu.RLock()
	defer mn.mu.RUnlock()

	for _, t := range mn.transports {
		t.Start()
	}
}

// StopAll stops all transports
func (mn *MockNetwork) StopAll() {
	mn.mu.RLock()
	defer mn.mu.RUnlock()

	for _, t := range mn.transports {
		t.Stop()
	}
}
