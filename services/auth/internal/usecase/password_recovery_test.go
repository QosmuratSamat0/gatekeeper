package usecase_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockPasswordResetRepo struct {
	issueFn         func(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error)
	isTokenActiveFn func(ctx context.Context, tokenHash []byte) (bool, error)
	confirmFn       func(ctx context.Context, tokenHash []byte, newPasswordHash string) error
}

func (m *mockPasswordResetRepo) IssueResetToken(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error) {
	if m.issueFn != nil {
		return m.issueFn(ctx, email, tokenHash, ttl, cooldown)
	}
	return usecase.IssuePasswordResetTokenResult{}, nil
}

func (m *mockPasswordResetRepo) IsTokenActive(ctx context.Context, tokenHash []byte) (bool, error) {
	if m.isTokenActiveFn != nil {
		return m.isTokenActiveFn(ctx, tokenHash)
	}
	return true, nil
}

func (m *mockPasswordResetRepo) ConfirmReset(ctx context.Context, tokenHash []byte, newPasswordHash string) error {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, tokenHash, newPasswordHash)
	}
	return nil
}

type mockPasswordResetTokenGen struct {
	rawToken  string
	tokenHash []byte
	genErr    error
	valErr    error
}

func (m *mockPasswordResetTokenGen) Generate() (string, []byte, error) {
	return m.rawToken, m.tokenHash, m.genErr
}

func (m *mockPasswordResetTokenGen) ValidateAndHash(rawToken string) ([]byte, error) {
	if m.valErr != nil {
		return nil, m.valErr
	}
	return m.tokenHash, nil
}

type mockDispatcher struct {
	enqueued []usecase.PasswordResetDeliveryTask
	mu       sync.Mutex
}

func (m *mockDispatcher) Enqueue(task usecase.PasswordResetDeliveryTask) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueued = append(m.enqueued, task)
	return true
}

type mockResetEmailSender struct {
	sentEmails []string
	sendErr    error
	sendFn     func(ctx context.Context, recipientEmail string, rawToken string, expiresAt time.Time) error
	mu         sync.Mutex
}

func (m *mockResetEmailSender) SendVerificationEmail(ctx context.Context, recipientEmail string, rawToken string, expiresAt time.Time) error {
	return nil
}

func (m *mockResetEmailSender) SendPasswordResetEmail(ctx context.Context, recipientEmail string, rawToken string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendFn != nil {
		return m.sendFn(ctx, recipientEmail, rawToken, expiresAt)
	}
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentEmails = append(m.sentEmails, recipientEmail)
	return nil
}

type mockPasswordHasher struct {
	hashResult string
	err        error
}

func (m *mockPasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.hashResult, nil
}

func TestRequestPasswordResetUsecase(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid email syntax returns ErrInvalidEmail", func(t *testing.T) {
		uc := usecase.NewRequestPasswordResetUsecase(nil, nil, nil, 0, 0)
		err := uc.Execute(ctx, usecase.RequestPasswordResetInput{Email: "invalid-email"})
		if !errors.Is(err, domain.ErrInvalidEmail) {
			t.Fatalf("expected ErrInvalidEmail, got %v", err)
		}
	})

	t.Run("ineligible account returns nil without dispatching email", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			issueFn: func(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error) {
				return usecase.IssuePasswordResetTokenResult{Eligible: false}, nil
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			rawToken:  "test-token",
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		disp := &mockDispatcher{}
		uc := usecase.NewRequestPasswordResetUsecase(repo, tokenGen, disp, 30*time.Minute, 60*time.Second)

		err := uc.Execute(ctx, usecase.RequestPasswordResetInput{Email: "unknown@example.com"})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(disp.enqueued) != 0 {
			t.Fatalf("expected 0 enqueued tasks, got %d", len(disp.enqueued))
		}
	})

	t.Run("cooldown active returns nil without dispatching email", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			issueFn: func(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error) {
				return usecase.IssuePasswordResetTokenResult{
					Eligible:       true,
					CooldownActive: true,
					RecipientEmail: email,
				}, nil
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			rawToken:  "test-token",
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		disp := &mockDispatcher{}
		uc := usecase.NewRequestPasswordResetUsecase(repo, tokenGen, disp, 30*time.Minute, 60*time.Second)

		err := uc.Execute(ctx, usecase.RequestPasswordResetInput{Email: "user@example.com"})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(disp.enqueued) != 0 {
			t.Fatalf("expected 0 enqueued tasks, got %d", len(disp.enqueued))
		}
	})

	t.Run("eligible account enqueues email delivery task", func(t *testing.T) {
		expTime := time.Now().Add(30 * time.Minute)
		repo := &mockPasswordResetRepo{
			issueFn: func(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error) {
				return usecase.IssuePasswordResetTokenResult{
					Eligible:       true,
					CooldownActive: false,
					RecipientEmail: email,
					ExpiresAt:      expTime,
				}, nil
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			rawToken:  "valid-raw-token",
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		disp := &mockDispatcher{}
		uc := usecase.NewRequestPasswordResetUsecase(repo, tokenGen, disp, 30*time.Minute, 60*time.Second)

		err := uc.Execute(ctx, usecase.RequestPasswordResetInput{Email: "User@Example.com "})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(disp.enqueued) != 1 {
			t.Fatalf("expected 1 enqueued task, got %d", len(disp.enqueued))
		}
		if disp.enqueued[0].RecipientEmail != "user@example.com" {
			t.Fatalf("expected canonical email user@example.com, got %s", disp.enqueued[0].RecipientEmail)
		}
		if disp.enqueued[0].RawToken != "valid-raw-token" {
			t.Fatalf("expected raw token valid-raw-token, got %s", disp.enqueued[0].RawToken)
		}
	})

	t.Run("database failure propagates error", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			issueFn: func(ctx context.Context, email string, tokenHash []byte, ttl time.Duration, cooldown time.Duration) (usecase.IssuePasswordResetTokenResult, error) {
				return usecase.IssuePasswordResetTokenResult{}, domain.ErrDatabaseUnavailable
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			rawToken:  "test-token",
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		disp := &mockDispatcher{}
		uc := usecase.NewRequestPasswordResetUsecase(repo, tokenGen, disp, 30*time.Minute, 60*time.Second)

		err := uc.Execute(ctx, usecase.RequestPasswordResetInput{Email: "user@example.com"})
		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatalf("expected ErrDatabaseUnavailable, got %v", err)
		}
	})
}

func TestInProcessPasswordResetDispatcher(t *testing.T) {
	t.Run("delivers email when token is active", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			isTokenActiveFn: func(ctx context.Context, tokenHash []byte) (bool, error) {
				return true, nil
			},
		}
		sender := &mockResetEmailSender{}
		disp := usecase.NewInProcessPasswordResetDispatcher(repo, sender, nil)

		workerCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		disp.Start(workerCtx, 2)

		task := usecase.PasswordResetDeliveryTask{
			RecipientEmail: "user@example.com",
			RawToken:       "raw-token",
			TokenHash:      []byte("token-hash-32-bytes-long-12345678"),
			ExpiresAt:      time.Now().Add(30 * time.Minute),
		}

		if !disp.Enqueue(task) {
			t.Fatal("expected task to be enqueued")
		}

		disp.Stop(2 * time.Second)

		sender.mu.Lock()
		defer sender.mu.Unlock()
		if len(sender.sentEmails) != 1 || sender.sentEmails[0] != "user@example.com" {
			t.Fatalf("expected 1 sent email to user@example.com, got %v", sender.sentEmails)
		}
	})

	t.Run("discards delivery when token is inactive in database", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			isTokenActiveFn: func(ctx context.Context, tokenHash []byte) (bool, error) {
				return false, nil
			},
		}
		sender := &mockResetEmailSender{}
		disp := usecase.NewInProcessPasswordResetDispatcher(repo, sender, nil)

		workerCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		disp.Start(workerCtx, 2)

		task := usecase.PasswordResetDeliveryTask{
			RecipientEmail: "stale@example.com",
			RawToken:       "stale-token",
			TokenHash:      []byte("token-hash-32-bytes-long-12345678"),
			ExpiresAt:      time.Now().Add(30 * time.Minute),
		}

		if !disp.Enqueue(task) {
			t.Fatal("expected task to be enqueued")
		}

		disp.Stop(2 * time.Second)

		sender.mu.Lock()
		defer sender.mu.Unlock()
		if len(sender.sentEmails) != 0 {
			t.Fatalf("expected 0 sent emails for stale token, got %v", sender.sentEmails)
		}
	})

	t.Run("drops task on queue overflow without blocking", func(t *testing.T) {
		// Create dispatcher without starting workers so queue fills up to 8.
		disp := usecase.NewInProcessPasswordResetDispatcher(nil, nil, nil)

		for i := 0; i < 8; i++ {
			ok := disp.Enqueue(usecase.PasswordResetDeliveryTask{
				RecipientEmail: "overflow@example.com",
			})
			if !ok {
				t.Fatalf("expected task %d to be enqueued", i)
			}
		}

		// 9th task must drop immediately
		ok := disp.Enqueue(usecase.PasswordResetDeliveryTask{
			RecipientEmail: "overflow-9@example.com",
		})
		if ok {
			t.Fatal("expected 9th task to be dropped due to queue overflow")
		}

		disp.Stop(100 * time.Millisecond)
	})

	t.Run("concurrent enqueue and stop never panics and rejects tasks after stop", func(t *testing.T) {
		sender := &mockResetEmailSender{}
		disp := usecase.NewInProcessPasswordResetDispatcher(nil, sender, nil)

		workerCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		disp.Start(workerCtx, 4)

		const numProducers = 20
		const operationsPerProducer = 200

		var startWg sync.WaitGroup
		startWg.Add(numProducers + 1)

		var producersDone sync.WaitGroup
		producersDone.Add(numProducers)

		// Producers continually enqueue tasks
		for i := 0; i < numProducers; i++ {
			go func(workerID int) {
				defer producersDone.Done()
				startWg.Done()
				startWg.Wait()

				for j := 0; j < operationsPerProducer; j++ {
					disp.Enqueue(usecase.PasswordResetDeliveryTask{
						RecipientEmail: fmt.Sprintf("race-%d-%d@example.com", workerID, j),
						RawToken:       "raw-token",
						TokenHash:      []byte("hash-32-bytes-test-hash-12345678"),
						ExpiresAt:      time.Now().Add(30 * time.Minute),
					})
				}
			}(i)
		}

		// Stopper triggers stop concurrently while producers are active
		var stopDone sync.WaitGroup
		stopDone.Add(1)
		go func() {
			defer stopDone.Done()
			startWg.Done()
			startWg.Wait()

			time.Sleep(2 * time.Millisecond)
			disp.Stop(1 * time.Second)
		}()

		producersDone.Wait()
		stopDone.Wait()

		// Any enqueue after Stop must safely return false
		afterStopOk := disp.Enqueue(usecase.PasswordResetDeliveryTask{
			RecipientEmail: "post-stop@example.com",
		})
		if afterStopOk {
			t.Fatal("expected enqueue after stop to return false")
		}
	})

	t.Run("respects custom taskTimeout", func(t *testing.T) {
		timeoutChan := make(chan time.Duration, 1)
		sender := &mockResetEmailSender{
			sendFn: func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
				deadline, ok := ctx.Deadline()
				if ok {
					timeoutChan <- time.Until(deadline)
				}
				return nil
			},
		}
		// Custom timeout of 25 seconds
		customTimeout := 25 * time.Second
		disp := usecase.NewInProcessPasswordResetDispatcher(nil, sender, nil, customTimeout)

		workerCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		disp.Start(workerCtx, 1)

		disp.Enqueue(usecase.PasswordResetDeliveryTask{
			RecipientEmail: "custom-timeout@example.com",
			RawToken:       "raw",
			ExpiresAt:      time.Now().Add(30 * time.Minute),
		})

		disp.Stop(2 * time.Second)

		select {
		case remaining := <-timeoutChan:
			if remaining < 20*time.Second || remaining > 26*time.Second {
				t.Fatalf("expected remaining timeout near 25s, got %v", remaining)
			}
		default:
			t.Fatal("expected email sender to receive context with deadline")
		}
	})

	t.Run("drain timeout cancels workers and awaits their termination before returning", func(t *testing.T) {
		var poolClosed atomic.Bool
		var workerRan atomic.Int32
		var activeWorkers atomic.Int32

		repo := &mockPasswordResetRepo{
			isTokenActiveFn: func(ctx context.Context, tokenHash []byte) (bool, error) {
				activeWorkers.Add(1)
				defer activeWorkers.Add(-1)

				workerRan.Add(1)
				if poolClosed.Load() {
					t.Errorf("worker accessed database pool after pool closure")
					return false, errors.New("pool closed")
				}

				// Simulate slow query that exceeds drain timeout unless canceled.
				select {
				case <-ctx.Done():
					return false, ctx.Err()
				case <-time.After(2 * time.Second):
					return true, nil
				}
			},
		}

		disp := usecase.NewInProcessPasswordResetDispatcher(repo, nil, nil)

		workerCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		disp.Start(workerCtx, 2)

		// Enqueue 4 tasks so queue is partially full
		for i := 0; i < 4; i++ {
			disp.Enqueue(usecase.PasswordResetDeliveryTask{
				RecipientEmail: fmt.Sprintf("slow-%d@example.com", i),
				TokenHash:      []byte("hash-32-bytes-test-hash-12345678"),
				ExpiresAt:      time.Now().Add(30 * time.Minute),
			})
		}

		// Trigger Stop with a very short drain timeout (20ms)
		drainTimeout := 20 * time.Millisecond
		disp.Stop(drainTimeout)

		// Immediately simulate closing the database connection pool as done in wiring.go / app shutdown
		poolClosed.Store(true)

		// Assert that Stop() waited for all workers to finish:
		// Active workers MUST be exactly 0 when Stop returns!
		if active := activeWorkers.Load(); active != 0 {
			t.Fatalf("expected 0 active workers when Stop returns, got %d", active)
		}

		// Verify that workers actually ran and observed cancellation
		if workerRan.Load() == 0 {
			t.Fatal("expected at least one worker to have run")
		}
	})
}

func TestConfirmPasswordResetUsecase(t *testing.T) {
	ctx := context.Background()

	t.Run("password shorter than 8 characters returns ErrInvalidPassword", func(t *testing.T) {
		uc := usecase.NewConfirmPasswordResetUsecase(nil, nil, nil)
		err := uc.Execute(ctx, usecase.ConfirmPasswordResetInput{
			Token:       "valid-token",
			NewPassword: "short",
		})
		if !errors.Is(err, domain.ErrInvalidPassword) {
			t.Fatalf("expected ErrInvalidPassword, got %v", err)
		}
	})

	t.Run("malformed token returns ErrInvalidPasswordResetToken", func(t *testing.T) {
		tokenGen := &mockPasswordResetTokenGen{
			valErr: errors.New("malformed base64"),
		}
		uc := usecase.NewConfirmPasswordResetUsecase(nil, tokenGen, nil)
		err := uc.Execute(ctx, usecase.ConfirmPasswordResetInput{
			Token:       "invalid!token",
			NewPassword: "newSecurePassword123!",
		})
		if !errors.Is(err, domain.ErrInvalidPasswordResetToken) {
			t.Fatalf("expected ErrInvalidPasswordResetToken, got %v", err)
		}
	})

	t.Run("successful password reset updates password and revokes sessions", func(t *testing.T) {
		var confirmedCalled atomic.Bool
		repo := &mockPasswordResetRepo{
			confirmFn: func(ctx context.Context, tokenHash []byte, newPasswordHash string) error {
				confirmedCalled.Store(true)
				if newPasswordHash != "hashed-new-password" {
					t.Fatalf("unexpected password hash: %s", newPasswordHash)
				}
				return nil
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		hasher := &mockPasswordHasher{
			hashResult: "hashed-new-password",
		}

		uc := usecase.NewConfirmPasswordResetUsecase(repo, tokenGen, hasher)
		err := uc.Execute(ctx, usecase.ConfirmPasswordResetInput{
			Token:       "valid-token-string",
			NewPassword: "newSecurePassword123!",
		})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !confirmedCalled.Load() {
			t.Fatal("expected ConfirmReset to be called on repo")
		}
	})

	t.Run("repo ErrInvalidPasswordResetToken propagates generic error", func(t *testing.T) {
		repo := &mockPasswordResetRepo{
			confirmFn: func(ctx context.Context, tokenHash []byte, newPasswordHash string) error {
				return domain.ErrInvalidPasswordResetToken
			},
		}
		tokenGen := &mockPasswordResetTokenGen{
			tokenHash: []byte("hash-32-bytes-test-hash-12345678"),
		}
		hasher := &mockPasswordHasher{
			hashResult: "hashed-new-password",
		}

		uc := usecase.NewConfirmPasswordResetUsecase(repo, tokenGen, hasher)
		err := uc.Execute(ctx, usecase.ConfirmPasswordResetInput{
			Token:       "valid-token-string",
			NewPassword: "newSecurePassword123!",
		})
		if !errors.Is(err, domain.ErrInvalidPasswordResetToken) {
			t.Fatalf("expected ErrInvalidPasswordResetToken, got %v", err)
		}
	})
}
