package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	tokenplatform "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
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

type mockIntegrationEmailSender struct {
	mu        sync.Mutex
	sentCount int
}

func (m *mockIntegrationEmailSender) SendVerificationEmail(ctx context.Context, toEmail, token string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentCount++
	return nil
}

func (m *mockIntegrationEmailSender) SendPasswordResetEmail(ctx context.Context, toEmail, token string, expiresAt time.Time) error {
	return nil
}

// TestPostgres_EmailVerificationRequest_RevokedSessionReturns401 tests that requesting an email
// verification token using an access token whose session was revoked via logout-all returns 401
// Unauthorized and sends zero emails, whereas an active valid session succeeds with 202 Accepted.
func TestPostgres_EmailVerificationRequest_RevokedSessionReturns401(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	accountRepo := repo.NewAccountRepository(pool, 5*time.Second)
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)
	verificationRepo := repo.NewEmailVerificationRepository(pool, 5*time.Second)

	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	dummyHash, err := hasher.Hash(ctx, "dummy-test-password")
	if err != nil {
		t.Fatalf("failed to create dummy hash: %v", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	tokenSvc, err := tokenplatform.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-1", privKey, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	sender := &mockIntegrationEmailSender{}
	emailTokenMgr := tokenplatform.NewEmailVerificationTokenManager()
	refreshMgr := tokenplatform.NewRefreshTokenManager()

	registerUC := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil, verificationRepo, emailTokenMgr, sender, 24*time.Hour)
	loginUC, err := usecase.NewLoginUsecase(accountRepo, sessionRepo, hasher, tokenSvc, refreshMgr, dummyHash, 10*time.Minute, 720*time.Hour, nil, nil)
	if err != nil {
		t.Fatalf("failed to create login usecase: %v", err)
	}
	meUC, _ := usecase.NewCurrentAccountUsecase(sessionRepo, nil)
	logoutAllUC, _ := usecase.NewLogoutAllUsecase(sessionRepo)
	emailVerificationUC := usecase.NewEmailVerificationUsecase(verificationRepo, emailTokenMgr, sender, 24*time.Hour, 60*time.Second)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, pool, registerUC, loginUC, nil, meUC, nil, &testTokenAdapter{tokenSvc: tokenSvc}, tokenSvc, nil, nil, nil).
		WithSessionManagement(nil, nil, logoutAllUC).
		WithEmailVerification(emailVerificationUC, emailVerificationUC, nil)
	router := handler.Routes()

	// 1. Register new account (sends initial verification email)
	regBody := `{"email":"resend.test@example.com","password":"valid-password-123"}`
	regReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	router.ServeHTTP(wReg, regReq)

	if wReg.Code != http.StatusCreated {
		t.Fatalf("registration failed: %d: %s", wReg.Code, wReg.Body.String())
	}
	sender.mu.Lock()
	if sender.sentCount != 1 {
		t.Fatalf("expected 1 verification email sent on registration, got %d", sender.sentCount)
	}
	sender.mu.Unlock()

	// 2. Login to obtain access token
	loginBody := `{"email":"resend.test@example.com","password":"valid-password-123"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	router.ServeHTTP(wLogin, loginReq)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", wLogin.Code, wLogin.Body.String())
	}

	var loginResp struct {
		AccessToken string `json:"access_token"`
		Account     struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(wLogin.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}

	// 3. Reset cooldown in database to allow immediate resend
	_, err = pool.Exec(ctx, "UPDATE email_verification_tokens SET created_at = clock_timestamp() - interval '2 minutes' WHERE account_id = $1", loginResp.Account.ID)
	if err != nil {
		t.Fatalf("failed to reset cooldown: %v", err)
	}

	// 4. Request email verification resend with active session -> must return 202 Accepted
	resendReq := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
	resendReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	wResend := httptest.NewRecorder()
	router.ServeHTTP(wResend, resendReq)

	if wResend.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted with active session, got %d: %s", wResend.Code, wResend.Body.String())
	}
	sender.mu.Lock()
	if sender.sentCount != 2 {
		t.Fatalf("expected 2 total emails sent, got %d", sender.sentCount)
	}
	sender.mu.Unlock()

	// 5. Revoke all sessions via logout-all
	logoutReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	wLogout := httptest.NewRecorder()
	router.ServeHTTP(wLogout, logoutReq)

	if wLogout.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for logout-all, got %d: %s", wLogout.Code, wLogout.Body.String())
	}

	// 6. Reset cooldown again in database so cooldown does not mask the session check
	_, err = pool.Exec(ctx, "UPDATE email_verification_tokens SET created_at = clock_timestamp() - interval '2 minutes' WHERE account_id = $1", loginResp.Account.ID)
	if err != nil {
		t.Fatalf("failed to reset cooldown: %v", err)
	}

	// 7. Request email verification resend with the revoked session's token -> MUST return 401 Unauthorized
	resendReqRevoked := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
	resendReqRevoked.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	wResendRevoked := httptest.NewRecorder()
	router.ServeHTTP(wResendRevoked, resendReqRevoked)

	if wResendRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for revoked session, got %d: %s", wResendRevoked.Code, wResendRevoked.Body.String())
	}

	// CRITICAL: zero additional emails sent after revoked session attempt!
	sender.mu.Lock()
	if sender.sentCount != 2 {
		t.Fatalf("expected sentCount to remain 2, got %d (email was sent for revoked session!)", sender.sentCount)
	}
	sender.mu.Unlock()
}
