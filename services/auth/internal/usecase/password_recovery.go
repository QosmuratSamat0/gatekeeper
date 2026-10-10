package usecase

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// PasswordResetDeliveryTask carries data for background email delivery.
type PasswordResetDeliveryTask struct {
	RecipientEmail string
	RawToken       string
	TokenHash      []byte
	ExpiresAt      time.Time
}

// PasswordResetDeliveryDispatcher defines the contract for asynchronously enqueueing reset emails.
type PasswordResetDeliveryDispatcher interface {
	Enqueue(task PasswordResetDeliveryTask) bool
}

// InProcessPasswordResetDispatcher delivers password reset emails asynchronously via a bounded queue and worker pool.
type InProcessPasswordResetDispatcher struct {
	queue        chan PasswordResetDeliveryTask
	workerWg     sync.WaitGroup
	repo         PasswordResetRepository
	emailSender  EmailSender
	logger       *slog.Logger
	taskTimeout  time.Duration
	mu           sync.RWMutex
	closed       bool
	stopOnce     sync.Once
	workerCancel context.CancelFunc
}

// NewInProcessPasswordResetDispatcher constructs an InProcessPasswordResetDispatcher with a bounded buffer of 8 tasks.
// If taskTimeout is omitted or <= 0, it defaults to 13 seconds (covering default DB and SMTP timeouts).
func NewInProcessPasswordResetDispatcher(
	repo PasswordResetRepository,
	emailSender EmailSender,
	logger *slog.Logger,
	taskTimeout ...time.Duration,
) *InProcessPasswordResetDispatcher {
	timeout := 13 * time.Second
	if len(taskTimeout) > 0 && taskTimeout[0] > 0 {
		timeout = taskTimeout[0]
	}

	return &InProcessPasswordResetDispatcher{
		queue:       make(chan PasswordResetDeliveryTask, 8),
		repo:        repo,
		emailSender: emailSender,
		logger:      logger,
		taskTimeout: timeout,
	}
}

// Start spawns the background worker pool using workerCtx.
func (d *InProcessPasswordResetDispatcher) Start(workerCtx context.Context, numWorkers int) {
	if numWorkers <= 0 {
		numWorkers = 4
	}
	ctx, cancel := context.WithCancel(workerCtx)
	d.workerCancel = cancel

	for i := 0; i < numWorkers; i++ {
		d.workerWg.Add(1)
		go d.workerLoop(ctx)
	}
}

func (d *InProcessPasswordResetDispatcher) workerLoop(workerCtx context.Context) {
	defer d.workerWg.Done()

	for task := range d.queue {
		if workerCtx.Err() != nil {
			// Context canceled (drain timed out or shutdown forced); discard remaining tasks.
			return
		}
		d.processTask(workerCtx, task)
	}
}

func (d *InProcessPasswordResetDispatcher) processTask(workerCtx context.Context, task PasswordResetDeliveryTask) {
	if workerCtx.Err() != nil {
		return
	}

	// Bounded context covering PostgreSQL token lookup and SMTP network I/O based on configured timeouts.
	taskCtx, cancel := context.WithTimeout(workerCtx, d.taskTimeout)
	defer cancel()

	if d.repo != nil {
		active, err := d.repo.IsTokenActive(taskCtx, task.TokenHash)
		if err != nil {
			if d.logger != nil {
				d.logger.ErrorContext(taskCtx, "failed to check password reset token active state in worker",
					slog.String("category", "db_error"),
				)
			}
			return
		}
		if !active {
			// Token was superseded, consumed, or expired while queued; skip sending.
			return
		}
	}

	if workerCtx.Err() != nil {
		return
	}

	if d.emailSender != nil {
		if err := d.emailSender.SendPasswordResetEmail(taskCtx, task.RecipientEmail, task.RawToken, task.ExpiresAt); err != nil {
			if d.logger != nil {
				d.logger.ErrorContext(taskCtx, "password reset email delivery failed in worker",
					slog.String("category", "email_delivery_failure"),
				)
			}
		}
	}
}

// Enqueue submits a delivery task to the bounded channel without blocking.
// If the buffer is full or dispatcher is stopped, the task is dropped and logged, returning false.
// Synchronized with RWMutex to prevent sending on a closed channel during concurrent Stop calls.
func (d *InProcessPasswordResetDispatcher) Enqueue(task PasswordResetDeliveryTask) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return false
	}

	select {
	case d.queue <- task:
		return true
	default:
		if d.logger != nil {
			d.logger.Warn("password reset delivery queue full, dropping task",
				slog.String("category", "queue_overflow_drop"),
			)
		}
		return false
	}
}

// Stop safely closes the queue under write lock, waits for workers to drain up to drainTimeout,
// and if drainTimeout is exceeded, cancels the worker context and waits for all active worker goroutines
// to cleanly exit before returning. This guarantees no worker can access dependencies (such as the database
// connection pool) after Stop returns.
func (d *InProcessPasswordResetDispatcher) Stop(drainTimeout time.Duration) {
	d.stopOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.queue)
		d.mu.Unlock()

		done := make(chan struct{})
		go func() {
			d.workerWg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Drained cleanly within allocated timeout.
		case <-time.After(drainTimeout):
			if d.logger != nil {
				d.logger.Warn("password reset delivery dispatcher drain timed out, cancelling workers",
					slog.String("category", "shutdown_timeout"),
				)
			}
			if d.workerCancel != nil {
				d.workerCancel()
			}
			// Wait for workers to observe context cancellation, release any active resources, and terminate.
			<-done
		}
	})
}

// RequestPasswordResetInput carries parameters for initiating a password reset.
type RequestPasswordResetInput struct {
	Email string
}

// RequestPasswordResetUsecase coordinates requesting a password reset email.
type RequestPasswordResetUsecase struct {
	repo       PasswordResetRepository
	tokenGen   PasswordResetTokenGenerator
	dispatcher PasswordResetDeliveryDispatcher
	tokenTTL   time.Duration
	cooldown   time.Duration
}

// NewRequestPasswordResetUsecase constructs a RequestPasswordResetUsecase.
func NewRequestPasswordResetUsecase(
	repo PasswordResetRepository,
	tokenGen PasswordResetTokenGenerator,
	dispatcher PasswordResetDeliveryDispatcher,
	tokenTTL time.Duration,
	cooldown time.Duration,
) *RequestPasswordResetUsecase {
	if tokenTTL <= 0 {
		tokenTTL = 30 * time.Minute
	}
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}
	return &RequestPasswordResetUsecase{
		repo:       repo,
		tokenGen:   tokenGen,
		dispatcher: dispatcher,
		tokenTTL:   tokenTTL,
		cooldown:   cooldown,
	}
}

// Execute performs canonical email validation, token issuance, and asynchronous delivery dispatch.
// Always returns nil for valid emails regardless of whether an eligible account exists or cooldown is active.
func (uc *RequestPasswordResetUsecase) Execute(ctx context.Context, input RequestPasswordResetInput) error {
	canonicalEmail, err := validateAndCanonicalizeEmail(input.Email)
	if err != nil {
		return domain.ErrInvalidEmail
	}

	rawToken, tokenHash, err := uc.tokenGen.Generate()
	if err != nil {
		return fmt.Errorf("generating password reset token: %w", err)
	}

	result, err := uc.repo.IssueResetToken(ctx, canonicalEmail, tokenHash, uc.tokenTTL, uc.cooldown)
	if err != nil {
		return err
	}

	if result.Eligible && !result.CooldownActive && uc.dispatcher != nil {
		uc.dispatcher.Enqueue(PasswordResetDeliveryTask{
			RecipientEmail: result.RecipientEmail,
			RawToken:       rawToken,
			TokenHash:      tokenHash,
			ExpiresAt:      result.ExpiresAt,
		})
	}

	return nil
}

// ConfirmPasswordResetInput carries parameters for completing a password reset.
type ConfirmPasswordResetInput struct {
	Token       string
	NewPassword string
}

// ConfirmPasswordResetUsecase coordinates password update and all-session revocation.
type ConfirmPasswordResetUsecase struct {
	repo           PasswordResetRepository
	tokenValidator PasswordResetTokenGenerator
	hasher         PasswordHasher
}

// NewConfirmPasswordResetUsecase constructs a ConfirmPasswordResetUsecase.
func NewConfirmPasswordResetUsecase(
	repo PasswordResetRepository,
	tokenValidator PasswordResetTokenGenerator,
	hasher PasswordHasher,
) *ConfirmPasswordResetUsecase {
	return &ConfirmPasswordResetUsecase{
		repo:           repo,
		tokenValidator: tokenValidator,
		hasher:         hasher,
	}
}

// Execute validates the new password, hashes it using Argon2id, verifies the token,
// updates the account credentials, and revokes all active sessions atomically.
func (uc *ConfirmPasswordResetUsecase) Execute(ctx context.Context, input ConfirmPasswordResetInput) error {
	if err := validatePassword(input.NewPassword); err != nil {
		return domain.ErrInvalidPassword
	}

	tokenHash, err := uc.tokenValidator.ValidateAndHash(input.Token)
	if err != nil {
		return domain.ErrInvalidPasswordResetToken
	}

	// Compute Argon2id hash before entering database transactions to prevent holding DB row locks during CPU hashing.
	newPasswordHash, err := uc.hasher.Hash(ctx, input.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	if err := uc.repo.ConfirmReset(ctx, tokenHash, newPasswordHash); err != nil {
		return err
	}

	return nil
}
