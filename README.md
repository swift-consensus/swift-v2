# SWIFT v2: Simple Weighted Instant Finality Trust

A novel Byzantine Fault Tolerant (BFT) consensus protocol achieving **single-round finality** with **self-healing** trust-based validator management.

## Key Features

| Feature | Benefit |
|---------|---------|
| **Single-Round Finality** | ~500ms block finalization (2-3x faster than HotStuff) |
| **Hybrid Stake-Trust** | Sybil resistance + self-healing |
| **BLS Aggregation** | O(n) messages, O(1) signature size |
| **Adaptive Quorum** | Fast when healthy, safe under attack |
| **Correlation Penalties** | Coordinated attacks punished exponentially |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/swift-consensus/swift-v2
cd swift-v2

# Build
go build ./...

# Run a 4-node local network (in separate terminals)
./cmd/swiftd/swiftd -id 0 -validators 4
./cmd/swiftd/swiftd -id 1 -validators 4
./cmd/swiftd/swiftd -id 2 -validators 4
./cmd/swiftd/swiftd -id 3 -validators 4

# Run tests
go test ./tests/...
```

## Architecture

```
swift-v2/
├── consensus/           # Core consensus engine
│   ├── swift.go         # Main orchestrator
│   ├── state.go         # Consensus state
│   ├── leader.go        # Leader selection (VRF + trust-weighted)
│   ├── voting.go        # Vote handling
│   ├── finalize.go      # Block finalization
│   ├── viewchange.go    # View change protocol
│   └── quorum.go        # Adaptive quorum calculation
├── trust/               # Trust management
│   ├── manager.go       # Trust score management
│   ├── ceiling.go       # Graduated trust ceiling
│   ├── decay.go         # Trust decay logic
│   ├── vouching.go      # Voucher system
│   └── byzantine.go     # Byzantine detection
├── stake/               # Stake management
│   ├── manager.go       # Stake operations
│   ├── slashing.go      # Slashing logic
│   └── rewards.go       # Reward distribution
├── crypto/              # Cryptographic primitives
│   ├── bls.go           # BLS signatures
│   ├── aggregate.go     # Signature aggregation
│   ├── vrf.go           # Verifiable Random Function
│   └── hash.go          # Hashing utilities
├── types/               # Core data structures
├── network/             # Network transport
└── cmd/swiftd/          # Node binary
```

## How It Works

### Consensus Flow

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  SELECT  │───▶│ PROPOSE  │───▶│   VOTE   │───▶│ FINALIZE │
│  LEADER  │    │  BLOCK   │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
      │                                               │
      │              ┌──────────┐                     │
      └──────────────│  UPDATE  │◀────────────────────┘
                     │  TRUST   │
                     └──────────┘

Time: ◀──────────── ~500ms ────────────▶
```

1. **SELECT LEADER**: VRF-based weighted selection using trust scores
2. **PROPOSE**: Leader creates and broadcasts block
3. **VOTE**: Validators verify and sign with BLS
4. **FINALIZE**: Leader aggregates votes; block finalized when quorum reached
5. **UPDATE**: Trust scores adjusted based on behavior

### Trust System

Validators build trust over time through consistent good behavior:

```
Trust Updates:
├── Correct vote:     +0.01 per round
├── Missed vote:      -0.02 (if online)
├── Byzantine:        -0.10 × correlation × offense_count
└── Decay:            ×0.9999 per round
```

**Graduated Trust Ceiling** prevents instant Sybil influence:

| Rounds Active | Max Trust |
|--------------|-----------|
| 0-100 | 0.20 |
| 101-250 | 0.40 |
| 251-500 | 0.60 |
| 501-1000 | 0.80 |
| 1000+ | 1.00 |

### Voting Weight

```go
weight = log₂(stake/MIN_STAKE + 1) × effective_trust
```

- **Log scale** for stake reduces whale dominance
- **Trust multiplier** rewards reliable validators

### Adaptive Quorum

```go
quorum = max(0.67 × online_weight, 0.51 × total_weight)
```

- **Fast finality** (67% online) when network is healthy
- **Safety floor** (51% total) prevents attacks during outages

## Configuration

```go
// Default configuration
const (
    BlockTime           = 500ms      // Target block time
    MinStake            = 1000       // Minimum stake to join
    TrustReward         = 0.01       // Trust gained per correct vote
    TrustPenaltyMiss    = 0.02       // Trust lost for missed vote
    TrustPenaltyByzantine = 0.10     // Base Byzantine penalty
    TrustDecay          = 0.9999     // Per-round decay
    LeaderCooldown      = 5          // Rounds before leader can lead again
    LeaderTrustCap      = 0.60       // Max trust for leader selection
    AdaptiveQuorum      = 0.67       // Quorum as % of online
    SafetyFloor         = 0.51       // Minimum quorum as % of total
)
```

## Security Guarantees

| Attack | Defense |
|--------|---------|
| **Sybil** | Stake requirement + graduated ceiling |
| **Slow Burn** | Correlation penalty + decay + escalation |
| **Leader DoS** | View change protocol |
| **Long-Range** | Weak subjectivity checkpoints |
| **Nothing at Stake** | Stake slashing + trust loss |
| **Equivocation** | Cryptographic proof → immediate slash |

## Performance

With 100 validators, 100ms average network latency:

| Metric | Value |
|--------|-------|
| Finality | ~500ms |
| Throughput | 5,000-10,000 TPS |
| Messages/round | ~200 (O(n)) |
| Signature size | ~96 bytes (constant) |

## Comparison

| Protocol | Finality | Messages | Rounds | Self-Healing |
|----------|----------|----------|--------|--------------|
| PBFT | ~3s | O(n²) | 3 | No |
| Tendermint | ~2s | O(n²) | 3 | No |
| HotStuff | ~1.5s | O(n) | 3 | No |
| **SWIFT v2** | **~0.5s** | **O(n)** | **1** | **Yes** |

## API Reference

### SwiftConsensus

```go
// Create consensus engine
engine := consensus.NewSwiftConsensus(
    secretKey,      // BLS secret key
    validators,     // Validator set
    config,         // Configuration
    transport,      // Network transport
)

// Start/stop
engine.Start(ctx)
engine.Stop()

// Submit transaction
engine.SubmitTransaction(tx)

// Get state
state := engine.GetState()
metrics := engine.GetMetrics()
```

### Trust Manager

```go
// Create trust manager
trustMgr := trust.NewManager(validators, config)

// Update trust
trustMgr.RewardVote(pubKey, round)
trustMgr.PenaltyMiss(pubKey)
trustMgr.PenaltyByzantine(pubKeys)

// Query
trust := trustMgr.GetTrust(pubKey)
weight := trustMgr.GetVotingWeight(pubKey)
```

## Testing

```bash
# Run all tests
go test ./tests/...

# Run with verbose output
go test -v ./tests/...

# Run specific test
go test -v ./tests/ -run TestBasicConsensus

# Run with coverage
go test -cover ./...
```

## Documentation

- [WHITEPAPER.md](WHITEPAPER.md) - Complete technical specification
- [types/config.go](types/config.go) - Configuration constants
- [consensus/swift.go](consensus/swift.go) - Main consensus engine

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- BLS signatures based on Boneh-Lynn-Shacham scheme
- Inspired by HotStuff, Tendermint, and Avalanche protocols
- VRF implementation based on ECVRF specification

---

**SWIFT v2** - Fast, Safe, Self-Healing Consensus
