package integration_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	tokenplatform "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
)

func createTestAccountInDB(t *testing.T, pool repo.PgxPoolExecutor) (string, string) {
	t.Helper()
	accountID := newUUID(t)
	email := fmt.Sprintf("test-%s@example.com", accountID[:8])
	_, err := pool.Exec(context.Background(), `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'dummy_hash', 'active', false, clock_timestamp(), clock_timestamp())
	`, accountID, email)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}
	return accountID, email
}

func generateValidTokenAndHash(t *testing.T) (string, []byte) {
	t.Helper()
	mgr := tokenplatform.NewEmailVerificationTokenManager()
	raw, hash, err := mgr.Generate()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return raw, hash
}

// TestPostgres_ConfirmToken_SupersededWhileWaitingOnAccountLock tests that a confirmation request
// that resolves an account by an old token but blocks waiting for the account row lock will
// discover that the token was superseded by a concurrent resend and fail cleanly with ErrInvalidVerificationToken.
func TestPostgres_ConfirmToken_SupersededWhileWaitingOnAccountLock(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, _ := createTestAccountInDB(t, pool)
	_, hash1 := generateValidTokenAndHash(t)
	_, hash2 := generateValidTokenAndHash(t)

	// Insert initial Token 1
	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)
	res, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash1, 24*time.Hour, 60*time.Second)
	if err != nil || !res.Created {
		t.Fatalf("failed to issue initial token: %v", err)
	}

	resendLockedChan := make(chan struct{})
	releaseResendChan := make(chan struct{})
	resendErrChan := make(chan error, 1)

	confirmPIDChan := make(chan uint32, 1)
	confirmErrChan := make(chan error, 1)

	// 1. Goroutine Resend: holds accounts row lock before replacing the token
	go func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			resendErrChan <- fmt.Errorf("resend begin failed: %w", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		// Acquire row lock on accounts
		var dummy string
		if err := tx.QueryRow(ctx, "SELECT id FROM accounts WHERE id = $1 FOR UPDATE", accountID).Scan(&dummy); err != nil {
			resendErrChan <- fmt.Errorf("resend lock account failed: %w", err)
			return
		}

		// Signal that account lock has been acquired
		close(resendLockedChan)

		// Wait until Confirm has started and verified as waiting in pg_locks
		select {
		case <-releaseResendChan:
		case <-ctx.Done():
			resendErrChan <- ctx.Err()
			return
		}

		// Replace Token 1 with Token 2
		_, err = tx.Exec(ctx, `
			UPDATE email_verification_tokens
			SET token_hash = $1, created_at = clock_timestamp(), expires_at = clock_timestamp() + interval '24 hours'
			WHERE account_id = $2
		`, hash2, accountID)
		if err != nil {
			resendErrChan <- fmt.Errorf("resend update token failed: %w", err)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			resendErrChan <- fmt.Errorf("resend commit failed: %w", err)
			return
		}

		resendErrChan <- nil
	}()

	// Wait for Resend to acquire the row lock
	select {
	case <-resendLockedChan:
	case err := <-resendErrChan:
		t.Fatalf("resend failed before lock acquisition: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for resend lock: %v", ctx.Err())
	}

	// 2. Intercept ConfirmToken transaction to capture its exact backend PID
	confirmRepo := repo.NewEmailVerificationRepository(&txInterceptorDB{
		PgxPoolExecutor: pool,
		onBegin: func(tx pgx.Tx) pgx.Tx {
			if conn := tx.Conn(); conn != nil && conn.PgConn() != nil {
				confirmPIDChan <- conn.PgConn().PID()
			}
			return tx
		},
	}, 5*time.Second)

	// Confirm begins, finds account by Token 1, and blocks on accounts FOR UPDATE
	go func() {
		confirmErrChan <- confirmRepo.ConfirmToken(ctx, hash1)
	}()

	var confirmPID uint32
	select {
	case confirmPID = <-confirmPIDChan:
	case <-ctx.Done():
		t.Fatalf("timeout waiting for confirm PID: %v", ctx.Err())
	}

	// 3. Verify via pg_locks that Confirm is actively waiting on the row lock held by Resend
	if err := verifyLockWait(ctx, pool, confirmPID); err != nil {
		t.Fatalf("confirm did not enter pg_locks wait state: %v", err)
	}

	// 4. Release Resend to update token to Token 2 and commit
	close(releaseResendChan)

	select {
	case err := <-resendErrChan:
		if err != nil {
			t.Fatalf("resend commit failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for resend commit: %v", ctx.Err())
	}

	// 5. Confirm unblocks and must return ErrInvalidVerificationToken
	select {
	case confirmErr := <-confirmErrChan:
		if confirmErr == nil || confirmErr != domain.ErrInvalidVerificationToken {
			t.Fatalf("expected ErrInvalidVerificationToken, got %v", confirmErr)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for confirm: %v", ctx.Err())
	}

	// 6. Verify database state
	var verified bool
	err = pool.QueryRow(ctx, "SELECT email_verified FROM accounts WHERE id = $1", accountID).Scan(&verified)
	if err != nil || verified {
		t.Fatalf("account must not be verified by superseded token, err: %v", err)
	}

	var storedHash []byte
	err = pool.QueryRow(ctx, "SELECT token_hash FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&storedHash)
	if err != nil || string(storedHash) != string(hash2) {
		t.Fatalf("Token 2 must be stored in database, err: %v", err)
	}

	// 7. Verifying with Token 2 succeeds and cleans up token
	directRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)
	if err := directRepo.ConfirmToken(ctx, hash2); err != nil {
		t.Fatalf("confirming with Token 2 failed: %v", err)
	}

	err = pool.QueryRow(ctx, "SELECT email_verified FROM accounts WHERE id = $1", accountID).Scan(&verified)
	if err != nil || !verified {
		t.Fatalf("account must now be email_verified=true")
	}

	var tokenCount int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&tokenCount)
	if err != nil || tokenCount != 0 {
		t.Fatalf("consumed token must be deleted, count: %d, err: %v", tokenCount, err)
	}
}

// TestPostgres_ConfirmToken_ConcurrentRace tests that 10 concurrent confirmations of the same token
// result in exactly 1 success (204) and 9 failures (ErrInvalidVerificationToken), with zero deadlocks.
func TestPostgres_ConfirmToken_ConcurrentRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, _ := createTestAccountInDB(t, pool)
	_, tokenHash := generateValidTokenAndHash(t)

	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)
	res, err := verificationRepo.IssueVerificationToken(ctx, accountID, tokenHash, 24*time.Hour, 60*time.Second)
	if err != nil || !res.Created {
		t.Fatalf("failed to issue initial token: %v", err)
	}

	numWorkers := 10
	var successCount atomic.Int32
	var invalidCount atomic.Int32
	var otherErrorCount atomic.Int32

	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneGroup sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		doneGroup.Add(1)
		go func() {
			defer doneGroup.Done()
			startBarrier.Wait()

			err := verificationRepo.ConfirmToken(ctx, tokenHash)
			switch err {
			case nil:
				successCount.Add(1)
			case domain.ErrInvalidVerificationToken:
				invalidCount.Add(1)
			default:
				otherErrorCount.Add(1)
			}
		}()
	}

	startBarrier.Done()
	doneGroup.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successCount.Load())
	}
	if invalidCount.Load() != int32(numWorkers-1) {
		t.Fatalf("expected exactly %d invalid token failures, got %d", numWorkers-1, invalidCount.Load())
	}
	if otherErrorCount.Load() != 0 {
		t.Fatalf("expected 0 other errors, got %d", otherErrorCount.Load())
	}

	// Verify account state
	var verified bool
	err = pool.QueryRow(ctx, "SELECT email_verified FROM accounts WHERE id = $1", accountID).Scan(&verified)
	if err != nil || !verified {
		t.Fatalf("account must be verified")
	}

	// Verify token row was deleted
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&count)
	if err != nil || count != 0 {
		t.Fatalf("consumed token row must be deleted, count=%d", count)
	}
}

// TestPostgres_IssueVerificationToken_CooldownAndReplacement tests the 60s cooldown
// and ensures concurrent resend attempts yield exactly 1 issuance.
func TestPostgres_IssueVerificationToken_CooldownAndReplacement(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, _ := createTestAccountInDB(t, pool)
	_, hash1 := generateValidTokenAndHash(t)
	_, hash2 := generateValidTokenAndHash(t)

	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)

	// First issue
	res1, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash1, 24*time.Hour, 60*time.Second)
	if err != nil || !res1.Created {
		t.Fatalf("first issuance failed: %v", err)
	}

	// Second issue immediately: must be suppressed by cooldown
	res2, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash2, 24*time.Hour, 60*time.Second)
	if err != nil || !res2.CooldownActive || res2.Created {
		t.Fatalf("expected cooldown active, got res2: %+v, err: %v", res2, err)
	}

	// Token 1 hash must still be in database
	var storedHash []byte
	err = pool.QueryRow(ctx, "SELECT token_hash FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&storedHash)
	if err != nil || string(storedHash) != string(hash1) {
		t.Fatalf("Token 1 must remain stored, got %x", storedHash)
	}

	// Simulate expired cooldown in database
	_, err = pool.Exec(ctx, `
		UPDATE email_verification_tokens
		SET created_at = clock_timestamp() - interval '65 seconds'
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		t.Fatalf("failed to update created_at: %v", err)
	}

	// Issuance after cooldown succeeds and replaces the token
	res3, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash2, 24*time.Hour, 60*time.Second)
	if err != nil || !res3.Created {
		t.Fatalf("expected replacement to succeed after cooldown, got: %+v, err: %v", res3, err)
	}

	err = pool.QueryRow(ctx, "SELECT token_hash FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&storedHash)
	if err != nil || string(storedHash) != string(hash2) {
		t.Fatalf("Token 2 must now be stored, got %x", storedHash)
	}

	// Exactly 1 row in table for this account
	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("expected exactly 1 token row, got %d", count)
	}
}

// TestPostgres_ConfirmToken_ExpiredAndBoundary tests strict expiration (clock_timestamp() < expires_at).
func TestPostgres_ConfirmToken_ExpiredAndBoundary(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, _ := createTestAccountInDB(t, pool)
	_, hash := generateValidTokenAndHash(t)

	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)

	// Issue token with 1 second TTL
	res, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash, 1*time.Second, 0)
	if err != nil || !res.Created {
		t.Fatalf("issue failed: %v", err)
	}

	// Force expiration in database
	_, err = pool.Exec(ctx, `
		UPDATE email_verification_tokens
		SET expires_at = clock_timestamp() - interval '1 second'
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		t.Fatalf("failed to expire token in DB: %v", err)
	}

	// Attempt confirm: must fail with ErrInvalidVerificationToken
	err = verificationRepo.ConfirmToken(ctx, hash)
	if err != domain.ErrInvalidVerificationToken {
		t.Fatalf("expected ErrInvalidVerificationToken for expired token, got: %v", err)
	}

	// Test boundary equality: token expiring exactly at clock_timestamp() must also be expired
	_, err = pool.Exec(ctx, `
		UPDATE email_verification_tokens
		SET expires_at = clock_timestamp()
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		t.Fatalf("failed to update token to boundary: %v", err)
	}

	err = verificationRepo.ConfirmToken(ctx, hash)
	if err != domain.ErrInvalidVerificationToken {
		t.Fatalf("expected ErrInvalidVerificationToken at boundary equality, got: %v", err)
	}
}

// TestPostgres_IssueVerificationToken_AlreadyVerified tests that verified accounts
// do not generate new tokens or insert records.
func TestPostgres_IssueVerificationToken_AlreadyVerified(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, _ := createTestAccountInDB(t, pool)

	// Set email_verified = true
	_, err := pool.Exec(ctx, "UPDATE accounts SET email_verified = true WHERE id = $1", accountID)
	if err != nil {
		t.Fatalf("failed to set email_verified: %v", err)
	}

	_, hash := generateValidTokenAndHash(t)
	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)

	res, err := verificationRepo.IssueVerificationToken(ctx, accountID, hash, 24*time.Hour, 60*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.AlreadyVerified {
		t.Errorf("expected AlreadyVerified=true")
	}
	if res.Created {
		t.Errorf("expected Created=false for already verified account")
	}

	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE account_id = $1", accountID).Scan(&count)
	if err != nil || count != 0 {
		t.Fatalf("expected 0 token rows for verified account, got %d", count)
	}
}
