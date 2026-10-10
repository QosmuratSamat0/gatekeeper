package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// PasswordResetRepository manages atomic password reset tokens and session revocations in PostgreSQL.
type PasswordResetRepository struct {
	db           PgxPoolExecutor
	queryTimeout time.Duration
}

// NewPasswordResetRepository constructs a PasswordResetRepository with an enforced query timeout.
func NewPasswordResetRepository(db PgxPoolExecutor, queryTimeout ...time.Duration) *PasswordResetRepository {
	timeout := 3 * time.Second
	if len(queryTimeout) > 0 && queryTimeout[0] > 0 {
		timeout = queryTimeout[0]
	}
	return &PasswordResetRepository{
		db:           db,
		queryTimeout: timeout,
	}
}

// IssueResetToken atomically locks the account row by normalized email, checks active status and email verification,
// enforces the per-account cooldown, and upserts the reset token digest within a single database transaction.
func (r *PasswordResetRepository) IssueResetToken(
	ctx context.Context,
	email string,
	tokenHash []byte,
	ttl time.Duration,
	cooldown time.Duration,
) (usecase.IssuePasswordResetTokenResult, error) {
	txCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	email = strings.ToLower(strings.TrimSpace(email))

	tx, err := r.db.Begin(txCtx)
	if err != nil {
		return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
	}
	defer tx.Rollback(txCtx) //nolint:errcheck

	// Step 1: Lock the account row first (canonical lock order: accounts -> tokens -> sessions).
	var accountID string
	var status string
	var emailVerified bool
	queryAccount := `
		SELECT id, status, email_verified
		FROM accounts
		WHERE email = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryAccount, email).Scan(&accountID, &status, &emailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Account does not exist. Return non-eligible outcome without disclosing existence.
			return usecase.IssuePasswordResetTokenResult{
				Eligible: false,
			}, nil
		}
		return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
	}

	// Verify that the account is active and email has been verified.
	// Inactive or unverified accounts are ineligible for password recovery.
	if status != string(domain.AccountStatusActive) || !emailVerified {
		return usecase.IssuePasswordResetTokenResult{
			Eligible: false,
		}, nil
	}

	// Step 2: Check for existing reset token under lock to enforce the 60-second cooldown.
	var cooldownActive bool
	queryCooldown := `
		SELECT clock_timestamp() < created_at + ($2 * interval '1 second')
		FROM password_reset_tokens
		WHERE account_id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryCooldown, accountID, cooldown.Seconds()).Scan(&cooldownActive)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
	}

	// If cooldown is active, suppress issuing a new token while preserving generic success.
	if cooldownActive {
		if err := tx.Commit(txCtx); err != nil {
			return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
		}
		return usecase.IssuePasswordResetTokenResult{
			Eligible:       true,
			CooldownActive: true,
			RecipientEmail: email,
		}, nil
	}

	// Step 3: Insert or update the token row. The ON CONFLICT clause guarantees at most
	// one token record exists per account, bounding table size.
	var expiresAt time.Time
	queryUpsert := `
		INSERT INTO password_reset_tokens (account_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, clock_timestamp(), clock_timestamp() + ($3 * interval '1 second'))
		ON CONFLICT (account_id) DO UPDATE SET
			token_hash = EXCLUDED.token_hash,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at
		RETURNING expires_at;
	`
	err = tx.QueryRow(txCtx, queryUpsert, accountID, tokenHash, ttl.Seconds()).Scan(&expiresAt)
	if err != nil {
		return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
	}

	if err := tx.Commit(txCtx); err != nil {
		return usecase.IssuePasswordResetTokenResult{}, mapDBError(err)
	}

	return usecase.IssuePasswordResetTokenResult{
		Eligible:       true,
		RecipientEmail: email,
		ExpiresAt:      expiresAt,
	}, nil
}

// IsTokenActive checks whether the given tokenHash is still valid, unexpired, and associated with an active, verified account.
func (r *PasswordResetRepository) IsTokenActive(ctx context.Context, tokenHash []byte) (bool, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var active bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM password_reset_tokens prt
			JOIN accounts a ON a.id = prt.account_id
			WHERE prt.token_hash = $1
			  AND clock_timestamp() < prt.expires_at
			  AND a.status = 'active'
			  AND a.email_verified = true
		);
	`
	err := r.db.QueryRow(queryCtx, query, tokenHash).Scan(&active)
	if err != nil {
		return false, mapDBError(err)
	}
	return active, nil
}

// ConfirmReset verifies the presented token hash, updates the account password hash, deletes the consumed token,
// and atomically revokes all unrevoked sessions for the account in a single transaction.
// Row lock order: accounts -> password_reset_tokens -> sessions (ORDER BY id).
func (r *PasswordResetRepository) ConfirmReset(ctx context.Context, tokenHash []byte, newPasswordHash string) error {
	txCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(txCtx)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(txCtx) //nolint:errcheck

	// Step 1: Locate the account by the presented token digest.
	var accountID string
	queryFindAccount := `
		SELECT account_id
		FROM password_reset_tokens
		WHERE token_hash = $1;
	`
	err = tx.QueryRow(txCtx, queryFindAccount, tokenHash).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidPasswordResetToken
		}
		return mapDBError(err)
	}

	// Step 2: Acquire lock on the account row (canonical order: accounts first).
	var status string
	queryLockAccount := `
		SELECT status
		FROM accounts
		WHERE id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryLockAccount, accountID).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidPasswordResetToken
		}
		return mapDBError(err)
	}

	if status != string(domain.AccountStatusActive) {
		return domain.ErrInvalidPasswordResetToken
	}

	// Step 3: Re-verify and lock the token row in password_reset_tokens.
	// Requires clock_timestamp() < expires_at.
	var expiresAt time.Time
	queryCheckToken := `
		SELECT expires_at
		FROM password_reset_tokens
		WHERE account_id = $1
		  AND token_hash = $2
		  AND clock_timestamp() < expires_at
		FOR UPDATE;
	`
	err = tx.QueryRow(txCtx, queryCheckToken, accountID, tokenHash).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidPasswordResetToken
		}
		return mapDBError(err)
	}

	// Step 4: Lock all unrevoked sessions for this account in ascending UUID order.
	queryLockSessions := `
		SELECT id
		FROM sessions
		WHERE account_id = $1 AND revoked_at IS NULL
		ORDER BY id
		FOR UPDATE;
	`
	rows, err := tx.Query(txCtx, queryLockSessions, accountID)
	if err != nil {
		return mapDBError(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return mapDBError(err)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapDBError(err)
	}
	rows.Close()

	// Step 5: Update the account password hash using database wall-clock time.
	queryUpdateAccount := `
		UPDATE accounts
		SET password_hash = $2, updated_at = clock_timestamp()
		WHERE id = $1;
	`
	_, err = tx.Exec(txCtx, queryUpdateAccount, accountID, newPasswordHash)
	if err != nil {
		return mapDBError(err)
	}

	// Step 6: Delete the consumed reset token.
	queryDeleteToken := `
		DELETE FROM password_reset_tokens
		WHERE account_id = $1 AND token_hash = $2;
	`
	_, err = tx.Exec(txCtx, queryDeleteToken, accountID, tokenHash)
	if err != nil {
		return mapDBError(err)
	}

	// Step 7: Revoke all unrevoked sessions for this account in a single atomic update.
	queryRevokeSessions := `
		UPDATE sessions
		SET revoked_at = clock_timestamp()
		WHERE account_id = $1 AND revoked_at IS NULL;
	`
	_, err = tx.Exec(txCtx, queryRevokeSessions, accountID)
	if err != nil {
		return mapDBError(err)
	}

	if err := tx.Commit(txCtx); err != nil {
		return mapDBError(err)
	}

	return nil
}
