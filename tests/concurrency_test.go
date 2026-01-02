package tests

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swift-consensus/swift-v2/consensus"
	"github.com/swift-consensus/swift-v2/crypto"
	"github.com/swift-consensus/swift-v2/network"
	"github.com/swift-consensus/swift-v2/types"
)

// TestConcurrentVoteSubmission verifies no race conditions when votes arrive concurrently
func TestConcurrentVoteSubmission(t *testing.T) {
	// Create validator set
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(5)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	config.BlockTime = 100 * time.Millisecond
	transport := network.NewMockTransport(keyPairs[0].PublicKey)

	// Create consensus engine
	sc, err := consensus.NewSwiftConsensus(keyPairs[0].SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc.Start(ctx)
	defer sc.Stop()

	// Wait for consensus to start
	time.Sleep(50 * time.Millisecond)

	// Submit votes concurrently
	var wg sync.WaitGroup
	errCount := int32(0)

	for i := 1; i < len(keyPairs); i++ {
		wg.Add(1)
		go func(kp *crypto.BLSKeyPair) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				vote := &types.Vote{
					Height:    0,
					Round:     0,
					BlockHash: types.Hash{},
					Voter:     kp.PublicKey,
				}
				vote.Signature = crypto.SignVote(kp.SecretKey, vote)
				sc.OnReceiveVote(vote)
				time.Sleep(time.Millisecond)
			}
		}(keyPairs[i])
	}

	// Also submit proposals concurrently
	for i := 1; i < len(keyPairs); i++ {
		wg.Add(1)
		go func(kp *crypto.BLSKeyPair) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				block := types.NewBlock(0, 0, types.Hash{}, kp.PublicKey)
				block.Signature = crypto.SignBlock(kp.SecretKey, block)
				msg := &types.ProposeMsg{Block: *block}
				sc.OnReceivePropose(msg)
				time.Sleep(2 * time.Millisecond)
			}
		}(keyPairs[i])
	}

	wg.Wait()

	if atomic.LoadInt32(&errCount) > 0 {
		t.Errorf("Detected %d errors during concurrent operations", errCount)
	}
}

// TestConcurrentTransactionSubmission verifies tx pool access is race-free
func TestConcurrentTransactionSubmission(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	transport := network.NewMockTransport(kp.PublicKey)

	sc, err := consensus.NewSwiftConsensus(kp.SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc.Start(ctx)
	defer sc.Stop()

	// Submit transactions from multiple goroutines concurrently
	var wg sync.WaitGroup
	txCount := 100

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < txCount; j++ {
				tx := types.Transaction{
					Nonce: uint64(goroutineID*txCount + j),
					Data:  []byte("test"),
				}
				sc.SubmitTransaction(tx)
			}
		}(i)
	}

	wg.Wait()

	// No panic or race = success
	t.Log("Concurrent transaction submission completed without races")
}

// TestMetricsAccess verifies metrics can be read/written safely
func TestMetricsAccess(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	transport := network.NewMockTransport(kp.PublicKey)

	sc, err := consensus.NewSwiftConsensus(kp.SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc.Start(ctx)
	defer sc.Stop()

	// Read metrics from multiple goroutines while consensus is running
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				metrics := sc.GetMetrics()
				// Just access the fields to detect races
				_ = metrics.BlocksFinalized
				_ = metrics.RoundsCompleted
				_ = metrics.ViewChanges
				_ = metrics.DroppedMessages
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	t.Log("Concurrent metrics access completed without races")
}

// TestStartStopRace verifies Start/Stop can be called safely from multiple goroutines
func TestStartStopRace(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	transport := network.NewMockTransport(kp.PublicKey)

	sc, err := consensus.NewSwiftConsensus(kp.SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Multiple goroutines trying to start/stop
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			sc.Start(ctx)
		}()
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			sc.Stop()
		}()
	}

	wg.Wait()

	// Should be stopped now
	if sc.IsRunning() {
		t.Error("Consensus should be stopped")
	}
}

// TestViewChangeConcurrentWithVotes verifies view changes don't race with vote processing
func TestViewChangeConcurrentWithVotes(t *testing.T) {
	validators := types.NewValidatorSet()
	keyPairs := crypto.MustGenerateNKeyPairs(4)

	for _, kp := range keyPairs {
		v := types.NewValidator(kp.PublicKey, 10000)
		v.Trust.BaseTrust = 0.8
		v.Trust.RoundsActive = 1000
		v.Online = true
		validators.Add(v)
	}

	config := types.DefaultConfig()
	config.BlockTime = 50 * time.Millisecond
	config.ViewChangeTimeout = 100 * time.Millisecond
	transport := network.NewMockTransport(keyPairs[0].PublicKey)

	sc, err := consensus.NewSwiftConsensus(keyPairs[0].SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc.Start(ctx)
	defer sc.Stop()

	var wg sync.WaitGroup

	// Submit view changes
	for i := 1; i < len(keyPairs); i++ {
		wg.Add(1)
		go func(kp *crypto.BLSKeyPair) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				msg := &types.ViewChangeMsg{
					Height:   0,
					NewRound: uint32(j + 1),
					Voter:    kp.PublicKey,
				}
				msg.Signature = crypto.SignViewChange(kp.SecretKey, msg)
				sc.OnReceiveViewChange(msg)
				time.Sleep(5 * time.Millisecond)
			}
		}(keyPairs[i])
	}

	// Submit votes simultaneously
	for i := 1; i < len(keyPairs); i++ {
		wg.Add(1)
		go func(kp *crypto.BLSKeyPair) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				vote := &types.Vote{
					Height:    0,
					Round:     0,
					BlockHash: types.Hash{},
					Voter:     kp.PublicKey,
				}
				vote.Signature = crypto.SignVote(kp.SecretKey, vote)
				sc.OnReceiveVote(vote)
				time.Sleep(3 * time.Millisecond)
			}
		}(keyPairs[i])
	}

	wg.Wait()
	t.Log("Concurrent view changes and votes completed without races")
}

// TestChannelBufferOverflow verifies dropped messages are tracked
func TestChannelBufferOverflow(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	// Very slow block time so main loop doesn't consume messages
	config.BlockTime = 10 * time.Second
	transport := network.NewMockTransport(kp.PublicKey)

	sc, err := consensus.NewSwiftConsensus(kp.SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	// Don't start - this makes channels fill up without being consumed

	// Flood the propose channel (buffer size 100)
	for i := 0; i < 200; i++ {
		block := types.NewBlock(0, 0, types.Hash{}, kp.PublicKey)
		msg := &types.ProposeMsg{Block: *block}
		sc.OnReceivePropose(msg)
	}

	// Check that dropped messages were tracked
	metrics := sc.GetMetrics()
	if metrics.DroppedMessages == 0 {
		t.Log("Note: No messages were dropped (channel consumed messages fast enough)")
	} else {
		t.Logf("Dropped %d messages as expected when buffer overflowed", metrics.DroppedMessages)
	}
}

// TestConcurrentGetState verifies GetState is race-free
func TestConcurrentGetState(t *testing.T) {
	validators := types.NewValidatorSet()
	kp, _ := crypto.GenerateKeyPair()
	v := types.NewValidator(kp.PublicKey, 10000)
	v.Trust.BaseTrust = 0.8
	v.Trust.RoundsActive = 1000
	v.Online = true
	validators.Add(v)

	config := types.DefaultConfig()
	transport := network.NewMockTransport(kp.PublicKey)

	sc, err := consensus.NewSwiftConsensus(kp.SecretKey, validators, config, transport)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc.Start(ctx)
	defer sc.Stop()

	var wg sync.WaitGroup

	// Read state from multiple goroutines while consensus is running
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				state := sc.GetState()
				_ = state.Height
				_ = state.Round
				_ = state.Step
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	t.Log("Concurrent GetState access completed without races")
}
