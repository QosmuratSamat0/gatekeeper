package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// EmailVerificationRepository manages atomic operations on email verification tokens and accounts in PostgreSQL.
type EmailVerificationRepository struct {
	db           PgxPoolExecutor
	queryTimeout time.Duration
}

// NewEmailVerificationRepository constructs an EmailVerificationRepository with an enforced query timeout.
func NewEmailVerificationRepository(db PgxPoolExecutor, queryTimeout ...time.Duration) *EmailVerificationRepository {
	timeout := 3 * time.Second
	if len(queryTimeout) > 0 && queryTimeout[0] > 0 {
		timeout = queryTimeout[0]
	}
	return &EmailVerificationRepository{
		db:           db,
		queryTimeout: timeout,
	}
}

// IssueVerificationToken atomically locks the account row, validates account state and cooldown,
// and inserts or replaces the verification token digest within a single transaction.
func (r *EmailVerificationRepository) IssueVerificationToken(
	ctx context.Context,
	accountID string,
	tokenHash []byte,
	ttl time.Duration,
	cooldown time.Duration,
) (usecase.IssueVerificationTokenResult, error) {
	// Bound query execution time to prevent deadlocks or network partitions from blocking indefinitely.
	txCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(txCtx)
	if err != nil {
		return usecase.IssueVerificationTokenResult{}, mapDBError(err)
	}
	defer tx.Rollback(txCtx) //nolint:errcheck

	// Step 1: Lock the account row first (canonical lock order: accounts then tokens).
	// Locking accounts serializes concurrent confirmation and resend requests for the same account.
	var status string
	var emailVerified bool
	var email string
	queryAccount := `
		SELECT status, email_verified, email
		FROM accounts
		WHERE id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryAccount, accountID).Scan(&status, &emailVerified, &email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return usecase.IssueVerificationTokenResult{}, domain.ErrAccountNotFound
		}
		return usecase.IssueVerificationTokenResult{}, mapDBError(err)
	}

	// Verify that the account is active. Inactive accounts cannot request email verification tokens.
	if status != string(domain.AccountStatusActive) {
		return usecase.IssueVerificationTokenResult{}, domain.ErrInvalidCredentials
	}

	// If the account is already verified, do not generate a token or send an email.
	// Returning AlreadyVerified=true allows the usecase to exit cleanly with generic 202 without leaking state.
	if emailVerified {
		if err := tx.Commit(txCtx); err != nil {
			return usecase.IssueVerificationTokenResult{}, mapDBError(err)
		}
		return usecase.IssueVerificationTokenResult{
			AlreadyVerified: true,
			RecipientEmail:  email,
		}, nil
	}

	// Step 2: Check for existing verification token under lock to enforce the 60-second cooldown.
	// Checking cooldown under the accounts lock guarantees race-free enforcement across multiple replicas.
	var cooldownActive bool
	queryCooldown := `
		SELECT clock_timestamp() < created_at + ($2 * interval '1 second')
		FROM email_verification_tokens
		WHERE account_id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryCooldown, accountID, cooldown.Seconds()).Scan(&cooldownActive)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return usecase.IssueVerificationTokenResult{}, mapDBError(err)
	}

	// If a token was issued recently and cooldown has not elapsed, suppress issuing a new token.
	if cooldownActive {
		if err := tx.Commit(txCtx); err != nil {
			return usecase.IssueVerificationTokenResult{}, mapDBError(err)
		}
		return usecase.IssueVerificationTokenResult{
			CooldownActive: true,
			RecipientEmail: email,
		}, nil
	}

	// Step 3: Insert or update the token row. The ON CONFLICT clause guarantees that
	// at most one token record exists per account, preventing storage accumulation.
	var expiresAt time.Time
	queryUpsert := `
		INSERT INTO email_verification_tokens (account_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, clock_timestamp(), clock_timestamp() + ($3 * interval '1 second'))
		ON CONFLICT (account_id) DO UPDATE SET
			token_hash = EXCLUDED.token_hash,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at
		RETURNING expires_at;
	`
	err = tx.QueryRow(txCtx, queryUpsert, accountID, tokenHash, ttl.Seconds()).Scan(&expiresAt)
	if err != nil {
		return usecase.IssueVerificationTokenResult{}, mapDBError(err)
	}

	if err := tx.Commit(txCtx); err != nil {
		return usecase.IssueVerificationTokenResult{}, mapDBError(err)
	}

	return usecase.IssueVerificationTokenResult{
		Created:        true,
		RecipientEmail: email,
		ExpiresAt:      expiresAt,
	}, nil
}

// ConfirmToken verifies the provided token hash, marks the account as verified,
// and deletes the consumed token within a single atomic transaction.
func (r *EmailVerificationRepository) ConfirmToken(ctx context.Context, tokenHash []byte) error {
	txCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(txCtx)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(txCtx) //nolint:errcheck

	// Step 1: Locate the account by the presented token digest.
	// Only valid digests find a row; unknown or already deleted tokens fail immediately.
	var accountID string
	queryFindAccount := `
		SELECT account_id
		FROM email_verification_tokens
		WHERE token_hash = $1;
	`
	err = tx.QueryRow(txCtx, queryFindAccount, tokenHash).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Unknown or deleted token: return domain.ErrInvalidVerificationToken (mapped to 400).
			return domain.ErrInvalidVerificationToken
		}
		// Database connection failure or timeout: preserve infrastructure error for 503/500 mapping.
		return mapDBError(err)
	}

	// Step 2: Acquire lock on the account row (canonical lock order: accounts first, then tokens).
	// This serializes verification with concurrent resend and registration operations.
	var status string
	var emailVerified bool
	queryLockAccount := `
		SELECT status, email_verified
		FROM accounts
		WHERE id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryLockAccount, accountID).Scan(&status, &emailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidVerificationToken
		}
		return mapDBError(err)
	}

	// Reject if account is not active or already verified.
	// A repeated confirmation is invalid and must not change state again.
	if status != string(domain.AccountStatusActive) || emailVerified {
		return domain.ErrInvalidVerificationToken
	}

	// Step 3: Re-verify the specific token_hash under the row lock.
	// We strictly require clock_timestamp() < expires_at so tokens are expired at equality.
	// Checking the exact token_hash prevents race conditions where a concurrent resend
	// replaced the token while this transaction waited for the account lock.
	var expiresAt time.Time
	queryCheckToken := `
		SELECT expires_at
		FROM email_verification_tokens
		WHERE account_id = $1
		  AND token_hash = $2
		  AND clock_timestamp() < expires_at
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryCheckToken, accountID, tokenHash).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Token was replaced, expired, or removed: return invalid token error.
			return domain.ErrInvalidVerificationToken
		}
		return mapDBError(err)
	}

	// Step 4: Mark the account verified using fresh database wall-clock time.
	queryUpdateAccount := `
		UPDATE accounts
		SET email_verified = true, updated_at = clock_timestamp()
		WHERE id = $1;
	`
	_, err = tx.Exec(txCtx, queryUpdateAccount, accountID)
	if err != nil {
		return mapDBError(err)
	}

	// Step 5: Delete the consumed token.
	// Verified accounts retain zero token records, bounding table size strictly to unverified accounts.
	queryDeleteToken := `
		DELETE FROM email_verification_tokens
		WHERE account_id = $1 AND token_hash = $2;
	`
	_, err = tx.Exec(txCtx, queryDeleteToken, accountID, tokenHash)
	if err != nil {
		return mapDBError(err)
	}

	if err := tx.Commit(txCtx); err != nil {
		return mapDBError(err)
	}

	return nil
}

// mapDBError maps connection and timeout failures to domain.ErrDatabaseUnavailable.
func mapDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
		return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
	}
	return err
}
