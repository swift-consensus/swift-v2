// Package main is the entry point for the SWIFT v2 consensus node.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/network"
	"github.com/swift-consensus/swift-v2/storage"
	"github.com/swift-consensus/swift-v2/types"
)

func main() {
	// Parse flags
	nodeID := flag.Int("id", 0, "Node ID (0-based)")
	numValidators := flag.Int("validators", 4, "Number of validators")
	stakeAmount := flag.Uint64("stake", 10000, "Stake amount per validator")
	blockTimeMs := flag.Int("block-time", 500, "Block time in milliseconds")
	networkMode := flag.String("network", "mock", "Network mode: 'mock' or 'libp2p'")
	p2pPort := flag.Int("p2p-port", 9000, "LibP2P listen port")
	dataDir := flag.String("data-dir", "", "Data directory for persistent storage (empty = in-memory)")
	flag.Parse()

	fmt.Println("===========================================")
	fmt.Println("       SWIFT v2 Consensus Node")
	fmt.Println("  Simple Weighted Instant Finality Trust")
	fmt.Println("===========================================")
	fmt.Println()

	// Configuration
	config := types.DefaultConfig()
	config.BlockTime = time.Duration(*blockTimeMs) * time.Millisecond

	// Generate deterministic keys for all validators
	keyPairs, err := crypto.GenerateNKeyPairs(*numValidators)
	if err != nil {
		fmt.Printf("Error: Failed to generate key pairs: %v\n", err)
		os.Exit(1)
	}

	// Get our key pair
	if *nodeID < 0 || *nodeID >= len(keyPairs) {
		fmt.Printf("Error: Invalid node ID %d (must be 0-%d)\n", *nodeID, len(keyPairs)-1)
		os.Exit(1)
	}
	myKeyPair := keyPairs[*nodeID]

	fmt.Printf("Node ID:       %d\n", *nodeID)
	fmt.Printf("Public Key:    %s\n", myKeyPair.PublicKey.Short())
	fmt.Printf("Validators:    %d\n", *numValidators)
	fmt.Printf("Stake:         %d\n", *stakeAmount)
	fmt.Printf("Block Time:    %v\n", config.BlockTime)
	fmt.Printf("Network:       %s\n", *networkMode)
	if *dataDir != "" {
		fmt.Printf("Data Dir:      %s\n", *dataDir)
	} else {
		fmt.Printf("Data Dir:      (in-memory)\n")
	}
	fmt.Println()

	// Create validator set
	validators := types.NewValidatorSet()
	for i, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, *stakeAmount)
		v.Trust.BaseTrust = 0.5                       // Start with 50% trust for demo
		v.Trust.RoundsActive = 500                    // Pretend they've been active
		v.Online = true
		validators.Add(v)
		fmt.Printf("Validator %d: %s (stake: %d, trust: %.2f)\n",
			i, kp.PublicKey.Short(), v.Stake, v.EffectiveTrust())
	}
	fmt.Println()

	// Create transport based on network mode
	// SECURITY FIX: Allow production libp2p transport (per Gemini audit)
	var transport network.Transport
	var mockTransport *network.MockTransport
	var libp2pTransport *network.LibP2PTransport

	switch *networkMode {
	case "libp2p":
		fmt.Println("Initializing LibP2P transport...")
		p2pConfig := network.DefaultLibP2PConfig()
		p2pConfig.ListenAddrs = []string{fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *p2pPort)}
		p2pConfig.ValidatorKey = myKeyPair.PublicKey

		var err error
		libp2pTransport, err = network.NewLibP2PTransport(p2pConfig)
		if err != nil {
			log.Fatalf("Failed to create LibP2P transport: %v", err)
		}
		transport = libp2pTransport

		// Print listen addresses
		for _, addr := range libp2pTransport.HostAddrs() {
			fmt.Printf("  Listening on: %s\n", addr)
		}
		fmt.Println()

	case "mock":
		fmt.Println("Using mock network (simulation mode)")
		mockNetwork := network.NewMockNetwork()

		// Add all nodes to network
		transports := make([]*network.MockTransport, *numValidators)
		for i, kp := range keyPairs {
			transports[i] = mockNetwork.AddNode(kp.PublicKey)
		}

		// Set simulated latency (50-100ms)
		mockNetwork.SetGlobalLatency(50, 100)
		mockTransport = transports[*nodeID]
		transport = mockTransport

	default:
		log.Fatalf("Invalid network mode: %s (use 'mock' or 'libp2p')", *networkMode)
	}

	// Initialize storage if data directory is provided
	// SECURITY FIX: Enable persistence (per Gemini audit)
	var store *storage.Store
	var consensusOpts []consensus.ConsensusOption

	if *dataDir != "" {
		nodePath := filepath.Join(*dataDir, fmt.Sprintf("node-%d", *nodeID))
		storeConfig := storage.DefaultStoreConfig(nodePath)

		var err error
		store, err = storage.NewStore(storeConfig)
		if err != nil {
			log.Fatalf("Failed to initialize storage: %v", err)
		}
		defer store.Close()

		consensusOpts = append(consensusOpts, consensus.WithStore(store))
		fmt.Printf("Storage initialized at: %s\n\n", nodePath)
	}

	// Create our consensus engine
	engine, err := consensus.NewSwiftConsensus(
		myKeyPair.SecretKey,
		validators,
		config,
		transport,
		consensusOpts...,
	)
	if err != nil {
		log.Fatalf("Failed to create consensus engine: %v", err)
	}

	// Set up message handler
	transport.OnReceive(func(msg *network.Message) {
		switch payload := msg.Payload.(type) {
		case *types.ProposeMsg:
			engine.OnReceivePropose(payload)
		case *types.Vote:
			engine.OnReceiveVote(payload)
		case *types.FinalizeMsg:
			engine.OnReceiveFinalize(payload)
		case *types.ViewChangeMsg:
			engine.OnReceiveViewChange(payload)
		}
	})

	// Start transport
	if err := transport.Start(); err != nil {
		fmt.Printf("Error starting transport: %v\n", err)
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Start consensus engine
	engine.Start(ctx)

	fmt.Println("Consensus engine started.")
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	// Print status periodically
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		// Get advanced transport for stats (both mock and libp2p implement this)
		advTransport, hasStats := transport.(network.AdvancedTransport)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printStatus(engine, advTransport, hasStats)
			}
		}
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println()
	fmt.Println("Shutting down...")

	// Stop
	cancel()
	engine.Stop()
	transport.Stop()

	// Print final status
	fmt.Println()
	printFinalStatus(engine)

	fmt.Println("Goodbye!")
}

func printStatus(engine *consensus.SwiftConsensus, transport network.AdvancedTransport, hasStats bool) {
	state := engine.GetState()
	metrics := engine.GetMetrics()

	if hasStats && transport != nil {
		stats := transport.Stats()
		fmt.Printf("[Status] Height: %d | Round: %d | Step: %s | Finalized: %d | ViewChanges: %d | Msgs: S:%d/R:%d | Peers: %d\n",
			state.Height,
			state.Round,
			state.Step,
			metrics.BlocksFinalized,
			metrics.ViewChanges,
			stats.MessagesSent,
			stats.MessagesReceived,
			stats.ActivePeers,
		)
	} else {
		fmt.Printf("[Status] Height: %d | Round: %d | Step: %s | Finalized: %d | ViewChanges: %d\n",
			state.Height,
			state.Round,
			state.Step,
			metrics.BlocksFinalized,
			metrics.ViewChanges,
		)
	}
}

func printFinalStatus(engine *consensus.SwiftConsensus) {
	metrics := engine.GetMetrics()
	validators := engine.GetValidators()

	fmt.Println("=== Final Status ===")
	fmt.Printf("Blocks Finalized:  %d\n", metrics.BlocksFinalized)
	fmt.Printf("Rounds Completed:  %d\n", metrics.RoundsCompleted)
	fmt.Printf("View Changes:      %d\n", metrics.ViewChanges)
	fmt.Printf("Last Finality:     %v\n", metrics.LastFinalityTime)
	fmt.Println()

	fmt.Println("=== Validator Trust ===")
	for i, v := range validators.Validators {
		fmt.Printf("Validator %d: trust=%.3f, effective=%.3f, stake=%d, balance=%d\n",
			i,
			v.Trust.BaseTrust,
			v.EffectiveTrust(),
			v.Stake,
			v.Balance,
		)
	}
}
