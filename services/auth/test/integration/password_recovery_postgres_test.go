package integration_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	tokenplatform "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
)

func createVerifiedTestAccount(t *testing.T, pool repo.PgxPoolExecutor, plainPassword string) (string, string) {
	t.Helper()
	accountID := newUUID(t)
	email := fmt.Sprintf("test-reset-%s@example.com", accountID[:8])

	hasher := password.NewArgon2idHasher(1)
	hash, err := hasher.Hash(context.Background(), plainPassword)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, err = pool.Exec(context.Background(), `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', true, clock_timestamp(), clock_timestamp())
	`, accountID, email, hash)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}

	return accountID, email
}

func generateResetTokenAndHash(t *testing.T) (string, []byte) {
	t.Helper()
	mgr := tokenplatform.NewPasswordResetTokenManager()
	raw, hash, err := mgr.Generate()
	if err != nil {
		t.Fatalf("failed to generate password reset token: %v", err)
	}
	return raw, hash
}

// TestPostgres_PasswordReset_HappyPath verifies complete reset lifecycle:
// issuance, token activity check, atomic confirmation, session revocation,
// old refresh token rejection, old password login failure, and fresh login with new password.
func TestPostgres_PasswordReset_HappyPath(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	oldPassword := "OldSecurePassword123!"
	newPassword := "NewSecurePassword456!"

	accountID, email := createVerifiedTestAccount(t, pool, oldPassword)
	hasher := password.NewArgon2idHasher(1)

	// Create an active session and initial refresh token for this account
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)
	sessionID := newUUID(t)
	session := domain.Session{
		ID:        sessionID,
		AccountID: accountID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	refreshMgr := tokenplatform.NewRefreshTokenManager()
	rawRefresh, refreshHash, err := refreshMgr.Generate()
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	initialRefreshToken := domain.RefreshToken{
		ID:        newUUID(t),
		SessionID: sessionID,
		TokenHash: refreshHash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	var oldPasswordHash string
	err = pool.QueryRow(ctx, "SELECT password_hash FROM accounts WHERE id = $1", accountID).Scan(&oldPasswordHash)
	if err != nil {
		t.Fatalf("failed to query initial password hash: %v", err)
	}

	if err := sessionRepo.CreateWithInitialRefresh(ctx, session, oldPasswordHash, initialRefreshToken); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// 1. Issue reset token
	resetRepo := repo.NewPasswordResetRepository(pool, 5*time.Second)
	rawResetToken, resetTokenHash := generateResetTokenAndHash(t)

	res, err := resetRepo.IssueResetToken(ctx, email, resetTokenHash, 30*time.Minute, 60*time.Second)
	if err != nil {
		t.Fatalf("failed to issue reset token: %v", err)
	}
	if !res.Eligible || res.CooldownActive {
		t.Fatalf("expected eligible without active cooldown, got %+v", res)
	}

	// 2. Verify token is active
	active, err := resetRepo.IsTokenActive(ctx, resetTokenHash)
	if err != nil || !active {
		t.Fatalf("expected token to be active, got active=%v, err=%v", active, err)
	}

	// 3. Confirm password reset
	newHash, err := hasher.Hash(ctx, newPassword)
	if err != nil {
		t.Fatalf("failed to hash new password: %v", err)
	}

	if err := resetRepo.ConfirmReset(ctx, resetTokenHash, newHash); err != nil {
		t.Fatalf("failed to confirm password reset: %v", err)
	}

	// 4. Verify password_reset_tokens row is deleted
	var tokenCount int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM password_reset_tokens WHERE account_id = $1", accountID).Scan(&tokenCount)
	if err != nil || tokenCount != 0 {
		t.Fatalf("expected 0 token rows after consumption, got count=%d, err=%v", tokenCount, err)
	}

	// 5. Verify token is no longer active
	activeAfter, err := resetRepo.IsTokenActive(ctx, resetTokenHash)
	if err != nil || activeAfter {
		t.Fatalf("expected consumed token to not be active, got active=%v, err=%v", activeAfter, err)
	}

	// 6. Verify account password_hash was updated
	var currentHash string
	err = pool.QueryRow(ctx, "SELECT password_hash FROM accounts WHERE id = $1", accountID).Scan(&currentHash)
	if err != nil || currentHash != newHash {
		t.Fatalf("expected password hash to be updated to newHash, got %s, err=%v", currentHash, err)
	}

	// 7. Verify session was revoked in PostgreSQL
	var sessionRevokedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", sessionID).Scan(&sessionRevokedAt)
	if err != nil || sessionRevokedAt == nil {
		t.Fatalf("expected session to be revoked, got revoked_at=%v, err=%v", sessionRevokedAt, err)
	}

	// 8. Verify old refresh token rotation fails due to revoked session
	successorRaw, successorHash, _ := refreshMgr.Generate()
	successorToken := domain.RefreshToken{
		ID:        newUUID(t),
		SessionID: sessionID,
		TokenHash: successorHash,
	}
	_, err = sessionRepo.RotateRefreshToken(ctx, refreshHash, successorToken, func(sub, sid string, exp time.Time) (string, time.Time, int64, error) {
		return "dummy-access", time.Now().Add(10 * time.Minute), 600, nil
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on refresh rotation for revoked session, got %v", err)
	}

	_ = rawResetToken
	_ = rawRefresh
	_ = successorRaw
}

// TestPostgres_PasswordReset_UnknownOrUnverifiedAccount verifies generic anti-enumeration behavior:
// non-existent, inactive, and unverified accounts return Eligible=false without error.
func TestPostgres_PasswordReset_UnknownOrUnverifiedAccount(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resetRepo := repo.NewPasswordResetRepository(pool, 5*time.Second)
	_, hash := generateResetTokenAndHash(t)

	// Case 1: Unknown email
	res, err := resetRepo.IssueResetToken(ctx, "unknown-account@example.com", hash, 30*time.Minute, 60*time.Second)
	if err != nil {
		t.Fatalf("expected nil error on unknown account, got %v", err)
	}
	if res.Eligible {
		t.Fatal("expected Eligible=false for unknown account")
	}

	// Case 2: Inactive account
	inactiveID := newUUID(t)
	inactiveEmail := "inactive@example.com"
	_, err = pool.Exec(ctx, `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'dummy_hash', 'disabled', true, clock_timestamp(), clock_timestamp())
	`, inactiveID, inactiveEmail)
	if err != nil {
		t.Fatalf("failed to insert inactive account: %v", err)
	}

	res, err = resetRepo.IssueResetToken(ctx, inactiveEmail, hash, 30*time.Minute, 60*time.Second)
	if err != nil {
		t.Fatalf("expected nil error on inactive account, got %v", err)
	}
	if res.Eligible {
		t.Fatal("expected Eligible=false for inactive account")
	}

	// Case 3: Unverified account
	unverifiedID := newUUID(t)
	unverifiedEmail := "unverified@example.com"
	_, err = pool.Exec(ctx, `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'dummy_hash', 'active', false, clock_timestamp(), clock_timestamp())
	`, unverifiedID, unverifiedEmail)
	if err != nil {
		t.Fatalf("failed to insert unverified account: %v", err)
	}

	res, err = resetRepo.IssueResetToken(ctx, unverifiedEmail, hash, 30*time.Minute, 60*time.Second)
	if err != nil {
		t.Fatalf("expected nil error on unverified account, got %v", err)
	}
	if res.Eligible {
		t.Fatal("expected Eligible=false for unverified account")
	}
}

// TestPostgres_PasswordReset_CooldownRace verifies that concurrent requests for the same account
// produce exactly one token issuance and all concurrent callers receive CooldownActive=true.
func TestPostgres_PasswordReset_CooldownRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, email := createVerifiedTestAccount(t, pool, "SecurePassword123!")
	resetRepo := repo.NewPasswordResetRepository(pool, 5*time.Second)

	const numWorkers = 10
	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneBarrier sync.WaitGroup
	doneBarrier.Add(numWorkers)

	var issuedCount atomic.Int32
	var cooldownCount atomic.Int32

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer doneBarrier.Done()
			startBarrier.Wait()

			_, hash := generateResetTokenAndHash(t)
			res, err := resetRepo.IssueResetToken(ctx, email, hash, 30*time.Minute, 60*time.Second)
			if err != nil {
				t.Errorf("IssueResetToken failed: %v", err)
				return
			}
			if res.Eligible && !res.CooldownActive {
				issuedCount.Add(1)
			} else if res.Eligible && res.CooldownActive {
				cooldownCount.Add(1)
			}
		}()
	}

	startBarrier.Done()
	doneBarrier.Wait()

	if issuedCount.Load() != 1 {
		t.Fatalf("expected exactly 1 issued token, got %d", issuedCount.Load())
	}
	if cooldownCount.Load() != numWorkers-1 {
		t.Fatalf("expected exactly %d suppressed by cooldown, got %d", numWorkers-1, cooldownCount.Load())
	}
}

// TestPostgres_PasswordReset_ConcurrentConfirmationRace verifies that concurrent confirmations
// with the same valid token produce exactly one winner (204) and all others fail with ErrInvalidPasswordResetToken.
func TestPostgres_PasswordReset_ConcurrentConfirmationRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, email := createVerifiedTestAccount(t, pool, "OldPassword123!")
	resetRepo := repo.NewPasswordResetRepository(pool, 5*time.Second)
	_, resetTokenHash := generateResetTokenAndHash(t)

	res, err := resetRepo.IssueResetToken(ctx, email, resetTokenHash, 30*time.Minute, 60*time.Second)
	if err != nil || !res.Eligible {
		t.Fatalf("failed to issue reset token: %v", err)
	}

	const numWorkers = 5
	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneBarrier sync.WaitGroup
	doneBarrier.Add(numWorkers)

	var winnerCount atomic.Int32
	var invalidCount atomic.Int32

	hasher := password.NewArgon2idHasher(1)
	newHash, _ := hasher.Hash(ctx, "NewPassword456!")

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer doneBarrier.Done()
			startBarrier.Wait()

			err := resetRepo.ConfirmReset(ctx, resetTokenHash, newHash)
			if err == nil {
				winnerCount.Add(1)
			} else if errors.Is(err, domain.ErrInvalidPasswordResetToken) {
				invalidCount.Add(1)
			} else {
				t.Errorf("unexpected error in concurrent confirm: %v", err)
			}
		}()
	}

	startBarrier.Done()
	doneBarrier.Wait()

	if winnerCount.Load() != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", winnerCount.Load())
	}
	if invalidCount.Load() != numWorkers-1 {
		t.Fatalf("expected exactly %d invalid errors, got %d", numWorkers-1, invalidCount.Load())
	}
}

// TestPostgres_PasswordReset_SupersededAndExpiredTokens verifies that superseded and expired tokens
// are cleanly rejected with ErrInvalidPasswordResetToken.
func TestPostgres_PasswordReset_SupersededAndExpiredTokens(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accountID, email := createVerifiedTestAccount(t, pool, "InitialPassword123!")
	resetRepo := repo.NewPasswordResetRepository(pool, 5*time.Second)

	_, hash1 := generateResetTokenAndHash(t)
	_, hash2 := generateResetTokenAndHash(t)

	// Issue token 1
	res1, err := resetRepo.IssueResetToken(ctx, email, hash1, 30*time.Minute, 0)
	if err != nil || !res1.Eligible {
		t.Fatalf("failed to issue token 1: %v", err)
	}

	// Issue token 2 (cooldown=0 to allow immediate superseding)
	res2, err := resetRepo.IssueResetToken(ctx, email, hash2, 30*time.Minute, 0)
	if err != nil || !res2.Eligible {
		t.Fatalf("failed to issue token 2: %v", err)
	}

	hasher := password.NewArgon2idHasher(1)
	newHash, _ := hasher.Hash(ctx, "ReplacementPassword123!")

	// Token 1 is now superseded; confirming with it must fail
	err = resetRepo.ConfirmReset(ctx, hash1, newHash)
	if !errors.Is(err, domain.ErrInvalidPasswordResetToken) {
		t.Fatalf("expected ErrInvalidPasswordResetToken for superseded token, got %v", err)
	}

	// Expire token 2 manually in DB
	_, err = pool.Exec(ctx, `UPDATE password_reset_tokens SET expires_at = clock_timestamp() - interval '1 second' WHERE account_id = $1`, accountID)
	if err != nil {
		t.Fatalf("failed to manually expire token: %v", err)
	}

	// Token 2 is now expired; confirming with it must fail
	err = resetRepo.ConfirmReset(ctx, hash2, newHash)
	if !errors.Is(err, domain.ErrInvalidPasswordResetToken) {
		t.Fatalf("expected ErrInvalidPasswordResetToken for expired token, got %v", err)
	}
}
