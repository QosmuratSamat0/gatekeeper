package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// PgxPoolExecutor defines the subset of pgxpool.Pool needed by SessionRepository.
type PgxPoolExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SessionRepository manages persistent session storage in PostgreSQL.
type SessionRepository struct {
	db           PgxPoolExecutor
	queryTimeout time.Duration
}

// NewSessionRepository constructs a SessionRepository with enforced query timeout.
func NewSessionRepository(db PgxPoolExecutor, queryTimeout time.Duration) *SessionRepository {
	if queryTimeout <= 0 {
		queryTimeout = 3 * time.Second
	}
	return &SessionRepository{
		db:           db,
		queryTimeout: queryTimeout,
	}
}

// CreateAtomic inserts a new session within a transaction while locking the account row
// to ensure the account remains active and its credential hash has not changed concurrently.
func (r *SessionRepository) CreateAtomic(ctx context.Context, session domain.Session, expectedHash string) error {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("starting session transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// Lock the account row FOR UPDATE to verify active status and unchanged credentials atomically.
	var status string
	var currentHash string
	checkQuery := `SELECT status, password_hash FROM accounts WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, checkQuery, session.AccountID).Scan(&status, &currentHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("checking account state for session: %w", err)
	}

	if status != string(domain.AccountStatusActive) || currentHash != expectedHash {
		return domain.ErrInvalidCredentials
	}

	insertQuery := `
		INSERT INTO sessions (id, account_id, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, NULL)
	`
	_, err = tx.Exec(queryCtx, insertQuery, session.ID, session.AccountID, session.CreatedAt, session.ExpiresAt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("inserting session record: %w", err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("committing session transaction: %w", err)
	}

	return nil
}

// GetWithAccount joins the session with its owning account.
func (r *SessionRepository) GetWithAccount(ctx context.Context, sessionID string) (domain.Session, domain.Account, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	query := `
		SELECT
			s.id, s.account_id, s.created_at, s.expires_at, s.revoked_at,
			a.id, a.email, a.password_hash, a.status, a.email_verified, a.created_at, a.updated_at
		FROM sessions s
		JOIN accounts a ON s.account_id = a.id
		WHERE s.id = $1
	`

	var sess domain.Session
	var acc domain.Account
	var status string
	err := r.db.QueryRow(queryCtx, query, sessionID).Scan(
		&sess.ID,
		&sess.AccountID,
		&sess.CreatedAt,
		&sess.ExpiresAt,
		&sess.RevokedAt,
		&acc.ID,
		&acc.Email,
		&acc.PasswordHash,
		&status,
		&acc.EmailVerified,
		&acc.CreatedAt,
		&acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, domain.Account{}, domain.ErrSessionNotFound
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return domain.Session{}, domain.Account{}, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return domain.Session{}, domain.Account{}, fmt.Errorf("getting session with account: %w", err)
	}

	acc.Status = domain.AccountStatus(status)
	return sess, acc, nil
}

// Revoke atomically revokes an active session.
// Returns alreadyRevoked=true if the session was found and was already revoked.
// Returns domain.ErrSessionNotFound if no session matches the given sessionID and accountID.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID string, accountID string) (bool, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	query := `
		WITH target AS (
			SELECT id, revoked_at FROM sessions WHERE id = $1 AND account_id = $2 FOR UPDATE
		),
		updated AS (
			UPDATE sessions
			SET revoked_at = NOW()
			WHERE id IN (SELECT id FROM target WHERE revoked_at IS NULL)
			RETURNING id
		)
		SELECT
			EXISTS(SELECT 1 FROM target) AS found,
			COALESCE((SELECT revoked_at IS NOT NULL FROM target), false) AS was_revoked;
	`

	var found bool
	var wasRevoked bool
	err := r.db.QueryRow(queryCtx, query, sessionID, accountID).Scan(&found, &wasRevoked)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("revoking session: %w", err)
	}

	if !found {
		return false, domain.ErrSessionNotFound
	}

	return wasRevoked, nil
}

// CreateWithInitialRefresh inserts a new session and its initial unconsumed refresh token
// within a single database transaction while locking the account row to verify that the
// account is active and its password hash matches expectedHash.
func (r *SessionRepository) CreateWithInitialRefresh(
	ctx context.Context,
	session domain.Session,
	expectedHash string,
	initialToken domain.RefreshToken,
) error {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("starting session transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// Lock the account row FOR UPDATE to verify active status and unchanged credentials atomically.
	var status string
	var currentHash string
	checkQuery := `SELECT status, password_hash FROM accounts WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, checkQuery, session.AccountID).Scan(&status, &currentHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("checking account state for session: %w", err)
	}

	if status != string(domain.AccountStatusActive) || currentHash != expectedHash {
		return domain.ErrInvalidCredentials
	}

	insertSessionQuery := `
		INSERT INTO sessions (id, account_id, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, NULL)
	`
	_, err = tx.Exec(queryCtx, insertSessionQuery, session.ID, session.AccountID, session.CreatedAt, session.ExpiresAt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("inserting session record: %w", err)
	}

	insertTokenQuery := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, NULL)
	`
	_, err = tx.Exec(queryCtx, insertTokenQuery, initialToken.ID, session.ID, initialToken.TokenHash, initialToken.CreatedAt, initialToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("inserting refresh token record: %w", err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("committing session transaction: %w", err)
	}

	return nil
}

// RevokeByRefreshTokenHash locates the session family by the presented token digest
// and atomically revokes the session if the token is known and not expired.
// Works even if the token was already consumed or the session was already revoked.
func (r *SessionRepository) RevokeByRefreshTokenHash(ctx context.Context, tokenHash []byte) (bool, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("starting refresh revoke transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// Discover session_id and token metadata
	var tokenID string
	var sessionID string
	var tokenExpiresAt time.Time
	findQuery := `SELECT id, session_id, expires_at FROM refresh_tokens WHERE token_hash = $1`
	err = tx.QueryRow(queryCtx, findQuery, tokenHash).Scan(&tokenID, &sessionID, &tokenExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("finding refresh token for revoke: %w", err)
	}

	// Check token expiry before lock
	now := time.Now().UTC()
	if now.After(tokenExpiresAt) || now.Equal(tokenExpiresAt) {
		return false, domain.ErrInvalidCredentials
	}

	// Lock the session row FOR UPDATE
	var sessionRevokedAt *time.Time
	var sessionExpiresAt time.Time
	sessQuery := `SELECT revoked_at, expires_at FROM sessions WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, sessQuery, sessionID).Scan(&sessionRevokedAt, &sessionExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("locking session for revoke: %w", err)
	}

	// Check actual wall-clock time after lock
	nowAfterLock := time.Now().UTC()
	if nowAfterLock.After(sessionExpiresAt) || nowAfterLock.Equal(sessionExpiresAt) {
		return false, domain.ErrInvalidCredentials
	}

	if sessionRevokedAt != nil {
		// Already revoked; commit and return alreadyRevoked=true for idempotent 204
		_ = tx.Commit(queryCtx)
		return true, nil
	}

	revokeQuery := `UPDATE sessions SET revoked_at = clock_timestamp() WHERE id = $1`
	_, err = tx.Exec(queryCtx, revokeQuery, sessionID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("revoking session by refresh token: %w", err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("committing session revoke: %w", err)
	}

	return false, nil
}

// RotateRefreshToken atomically performs refresh token rotation or replay revocation:
// Follows strict lock order: accounts (FOR SHARE) -> sessions (FOR UPDATE) -> refresh_tokens (FOR UPDATE).
// Re-verifies actual wall-clock time and state after locks are acquired.
func (r *SessionRepository) RotateRefreshToken(
	ctx context.Context,
	presentedHash []byte,
	successorToken domain.RefreshToken,
	signFn usecase.SignSuccessorCallback,
) (*usecase.RotationResult, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("starting refresh rotation transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// 1. Locate token metadata and associated session & account without locking yet
	var tokenID string
	var sessionID string
	var accountID string
	discoverQuery := `
		SELECT rt.id, rt.session_id, s.account_id
		FROM refresh_tokens rt
		JOIN sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
	`
	err = tx.QueryRow(queryCtx, discoverQuery, presentedHash).Scan(&tokenID, &sessionID, &accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("discovering refresh token family: %w", err)
	}

	// 2. Acquire locks in strict hierarchical order:
	// A. Lock account row (FOR SHARE) to verify active status
	var accountStatus string
	accLockQuery := `SELECT status FROM accounts WHERE id = $1 FOR SHARE`
	err = tx.QueryRow(queryCtx, accLockQuery, accountID).Scan(&accountStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("locking account for refresh: %w", err)
	}
	if accountStatus != string(domain.AccountStatusActive) {
		return nil, domain.ErrInvalidCredentials
	}

	// B. Lock session row (FOR UPDATE)
	var sessionExpiresAt time.Time
	var sessionRevokedAt *time.Time
	sessLockQuery := `SELECT expires_at, revoked_at FROM sessions WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, sessLockQuery, sessionID).Scan(&sessionExpiresAt, &sessionRevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("locking session for refresh: %w", err)
	}

	// C. Lock refresh token row (FOR UPDATE)
	var tokenExpiresAt time.Time
	var tokenConsumedAt *time.Time
	tokLockQuery := `SELECT expires_at, consumed_at FROM refresh_tokens WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, tokLockQuery, tokenID).Scan(&tokenExpiresAt, &tokenConsumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("locking refresh token row: %w", err)
	}

	// 3. Re-verify actual wall-clock time and revocation under the acquired locks
	now := time.Now().UTC()
	if sessionRevokedAt != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if now.After(sessionExpiresAt) || now.Equal(sessionExpiresAt) {
		return nil, domain.ErrInvalidCredentials
	}
	if now.After(tokenExpiresAt) || now.Equal(tokenExpiresAt) {
		return nil, domain.ErrInvalidCredentials
	}

	// 4. Replay Detection: if token was already consumed, revoke the entire session family immediately!
	if tokenConsumedAt != nil {
		revokeFamilyQuery := `UPDATE sessions SET revoked_at = clock_timestamp() WHERE id = $1 AND revoked_at IS NULL`
		_, execErr := tx.Exec(queryCtx, revokeFamilyQuery, sessionID)
		if execErr != nil {
			if errors.Is(execErr, context.DeadlineExceeded) || isConnectionOrTimeout(execErr) {
				return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, execErr)
			}
			return nil, fmt.Errorf("revoking compromised session family: %w", execErr)
		}
		// MUST COMMIT the revocation to ensure the replay is permanently stored in the DB!
		if commitErr := tx.Commit(queryCtx); commitErr != nil {
			if errors.Is(commitErr, context.DeadlineExceeded) || isConnectionOrTimeout(commitErr) {
				return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, commitErr)
			}
			return nil, fmt.Errorf("committing replay revocation: %w", commitErr)
		}
		return nil, domain.ErrCompromisedSessionReplay
	}

	// 5. Valid Rotation: sign the successor access JWT via signFn while holding row locks.
	// signFn receives the locked session's exact expiration time.
	// If after integer-second truncation exp <= iat, signFn returns an error, rolling back the transaction.
	accessToken, accessExpiresAt, expiresIn, signErr := signFn(accountID, sessionID, sessionExpiresAt)
	if signErr != nil {
		// Rollback occurs via defer. Refresh token remains unconsumed.
		if errors.Is(signErr, domain.ErrSessionExpired) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, signErr
	}

	// Re-verify actual wall-clock time immediately before performing database mutations.
	// If the session expired while waiting for signing, inserting successor token with expires_at <= clock_timestamp()
	// would violate database constraint chk_refresh_tokens_expiry_order and trigger a 500 error.
	nowBeforeMutations := time.Now().UTC()
	if !nowBeforeMutations.Before(sessionExpiresAt) || !nowBeforeMutations.Before(tokenExpiresAt) {
		// Rollback occurs via defer. Refresh token remains unconsumed.
		return nil, domain.ErrInvalidCredentials
	}

	// Mark presented token as consumed
	consumeQuery := `UPDATE refresh_tokens SET consumed_at = clock_timestamp() WHERE id = $1`
	_, err = tx.Exec(queryCtx, consumeQuery, tokenID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("consuming presented refresh token: %w", err)
	}

	// Insert successor refresh token with expires_at set strictly to sessionExpiresAt
	insertSuccessorQuery := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at)
		VALUES ($1, $2, $3, clock_timestamp(), $4, NULL)
	`
	_, err = tx.Exec(queryCtx, insertSuccessorQuery, successorToken.ID, sessionID, successorToken.TokenHash, sessionExpiresAt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("inserting successor refresh token: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return nil, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return nil, fmt.Errorf("committing refresh rotation: %w", err)
	}

	refreshExpiresIn := int64(sessionExpiresAt.Sub(time.Now().UTC()).Seconds())
	if refreshExpiresIn < 0 {
		refreshExpiresIn = 0
	}

	return &usecase.RotationResult{
		AccessToken:      accessToken,
		AccessTokenExp:   accessExpiresAt,
		ExpiresIn:        expiresIn,
		RefreshExpiresIn: refreshExpiresIn,
	}, nil
}
