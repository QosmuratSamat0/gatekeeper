package password

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestArgon2idFormatAndUniqueness(t *testing.T) {
	// Use small parameters for quick unit test
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	ctx := context.Background()

	pw := "example-secret-password"
	hash1, err := hasher.Hash(ctx, pw)
	if err != nil {
		t.Fatalf("unexpected error hashing: %v", err)
	}

	expectedPrefix := "$argon2id$v=19$m=1024,t=1,p=1$"
	if !strings.HasPrefix(hash1, expectedPrefix) {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, hash1)
	}

	hash2, err := hasher.Hash(ctx, pw)
	if err != nil {
		t.Fatalf("unexpected error hashing: %v", err)
	}

	if hash1 == hash2 {
		t.Error("hashes for the same password must differ due to unique salts")
	}
}

func TestArgon2idContextCancellation(t *testing.T) {
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 1)

	// Block the single semaphore slot manually
	hasher.sem <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := hasher.Hash(ctx, "any-password")
	if err == nil {
		t.Fatal("expected error when context is cancelled while waiting for semaphore")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	// Release manual slot
	<-hasher.sem
}

func TestArgon2idAlreadyCancelledContext(t *testing.T) {
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)

	started := false
	hasher.SetObserver(
		func() { started = true },
		nil,
	)

	// Context is cancelled before calling Hash while slots in semaphore are completely free
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Calling Hash on an already cancelled context with free slots
	// must immediately return context.Canceled without starting Argon2 computation
	_, err := hasher.Hash(ctx, "any-password")
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	if started {
		t.Error("computation was started despite cancelled context")
	}

	// Verify semaphore slot was not leaked
	if len(hasher.sem) != 0 {
		t.Errorf("expected 0 items in semaphore channel, found %d", len(hasher.sem))
	}
}

func TestArgon2idConcurrencyBounded(t *testing.T) {
	concurrencyLimit := 2
	// Use realistic memory/iterations so hashing takes measurable time without artificial sleeps
	hasher := NewArgon2idHasherWithParams(8192, 2, 1, 16, 32, concurrencyLimit)

	var mu sync.Mutex
	activeCount := 0
	maxObserved := 0

	hasher.SetObserver(
		func() {
			mu.Lock()
			activeCount++
			if activeCount > maxObserved {
				maxObserved = activeCount
			}
			mu.Unlock()
		},
		func() {
			mu.Lock()
			activeCount--
			mu.Unlock()
		},
	)

	var wg sync.WaitGroup
	totalCalls := 6
	errCh := make(chan error, totalCalls)

	for i := 0; i < totalCalls; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Call the real Hash function under concurrent load
			_, err := hasher.Hash(ctx, "concurrent-test-password-15")
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent hash call failed: %v", err)
	}

	if maxObserved > concurrencyLimit {
		t.Fatalf("expected max concurrency %d, but observed %d concurrent computations", concurrencyLimit, maxObserved)
	}
	if maxObserved < 2 {
		t.Errorf("expected at least 2 concurrent operations to be observed, got %d", maxObserved)
	}
}

func BenchmarkArgon2id(b *testing.B) {
	// Standard AUTH-01 production parameters (64 MiB, 3 iterations, 1 parallelism)
	hasher := NewArgon2idHasher(2)
	ctx := context.Background()
	pw := "secure-test-password-12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.Hash(ctx, pw)
		if err != nil {
			b.Fatalf("hashing failed: %v", err)
		}
	}
}

func TestArgon2idVerify_SuccessAndFailure(t *testing.T) {
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	ctx := context.Background()

	pw := "correct-password-123"
	hash, err := hasher.Hash(ctx, pw)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// 1. Correct password matches
	match, err := hasher.Verify(ctx, pw, hash)
	if err != nil {
		t.Fatalf("unexpected error on verify: %v", err)
	}
	if !match {
		t.Error("expected valid password to match hash")
	}

	// 2. Incorrect password fails match without error
	matchWrong, err := hasher.Verify(ctx, "wrong-password-999", hash)
	if err != nil {
		t.Fatalf("unexpected error on verify with wrong password: %v", err)
	}
	if matchWrong {
		t.Error("expected wrong password not to match hash")
	}
}

func TestArgon2idVerify_StrictPHCParsingAndParameterRejection(t *testing.T) {
	// Hasher with specific parameters (1024 KiB, 1 iter, 1 parallelism, 16-byte salt, 32-byte key)
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	ctx := context.Background()

	tests := []struct {
		name    string
		phc     string
		wantErr string
	}{
		{
			name:    "unsupported algorithm",
			phc:     "$bcrypt$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unsupported algorithm identifier",
		},
		{
			name:    "wrong part count",
			phc:     "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA",
			wantErr: "invalid phc format structure",
		},
		{
			name:    "unsupported version",
			phc:     "$argon2id$v=16$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unsupported argon2 version",
		},
		{
			name:    "mismatched memory parameter (DoS protection)",
			phc:     "$argon2id$v=19$m=262144,t=1,p=1$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unsupported or mismatched argon2id parameters",
		},
		{
			name:    "mismatched iterations parameter",
			phc:     "$argon2id$v=19$m=1024,t=10,p=1$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unsupported or mismatched argon2id parameters",
		},
		{
			name:    "mismatched parallelism parameter",
			phc:     "$argon2id$v=19$m=1024,t=1,p=4$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unsupported or mismatched argon2id parameters",
		},
		{
			name:    "parallelism parameter overflow p=257",
			phc:     "$argon2id$v=19$m=1024,t=1,p=257$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "parallelism parameter exceeds uint8",
		},
		{
			name:    "corrupted salt base64",
			phc:     "$argon2id$v=19$m=1024,t=1,p=1$not!valid!base64$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "failed to decode base64 salt",
		},
		{
			name:    "invalid salt length (too short)",
			phc:     "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoMzI",
			wantErr: "unexpected salt length",
		},
		{
			name:    "invalid hash length (too short)",
			phc:     "$argon2id$v=19$m=1024,t=1,p=1$MTIzNDU2Nzg5MDEyMzQ1Ng$c2hvcnRoYXNo",
			wantErr: "unexpected hash length",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hasher.Verify(ctx, "any-password", tc.phc)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestArgon2idVerify_SharedConcurrencyLimiter(t *testing.T) {
	// Concurrency limit of 1: only one operation (Hash OR Verify) may run at a time
	hasher := NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 1)
	ctx := context.Background()

	hash, err := hasher.Hash(ctx, "test-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Manually fill the single semaphore slot
	hasher.sem <- struct{}{}

	// Verify should block and respect timeout
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = hasher.Verify(timeoutCtx, "test-password", hash)
	if err == nil {
		t.Fatal("expected timeout error when semaphore is full")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	// Release semaphore slot
	<-hasher.sem

	// Now verify must succeed
	match, err := hasher.Verify(ctx, "test-password", hash)
	if err != nil {
		t.Fatalf("verify failed after semaphore release: %v", err)
	}
	if !match {
		t.Error("expected password to match")
	}
}
