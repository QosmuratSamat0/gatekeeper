package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
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

// ListActiveSessions lists active sessions owned by accountID with keyset pagination.
// It verifies in a single query that the caller session exists, is owned, is unrevoked,
// is unexpired, and the owning account is active, using a single timestamp for consistent evaluation.
func (r *SessionRepository) ListActiveSessions(
	ctx context.Context,
	accountID string,
	callerSessionID string,
	filter usecase.SessionListFilter,
) (usecase.SessionListPage, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)

	hasCursor := filter.Cursor != nil
	var cursorCreatedAt any = nil
	var cursorID any = nil
	if hasCursor {
		cursorCreatedAt = filter.Cursor.CreatedAt
		cursorID = strings.ToLower(filter.Cursor.ID)
	}
	fetchLimit := filter.Limit + 1

	// Single statement with CTEs:
	// - now_t calculates one reference timestamp for all expiry comparisons.
	// - caller checks the caller's session existence, account status, and expiry.
	// - page selects active unrevoked sessions matching keyset criteria.
	// - The outer SELECT guarantees deterministic ordering and distinguishes an invalid caller from an empty page.
	query := `
		WITH now_t AS (
			SELECT clock_timestamp() AS now
		),
		caller AS (
			SELECT
				s.id,
				s.expires_at,
				s.revoked_at,
				a.status AS account_status
			FROM sessions s
			JOIN accounts a ON s.account_id = a.id
			WHERE s.id = $1 AND s.account_id = $2
		),
		page AS (
			SELECT s.id, s.created_at, s.expires_at
			FROM sessions s, now_t
			WHERE s.account_id = $2
			  AND s.revoked_at IS NULL
			  AND s.expires_at > now_t.now
			  AND (
				  $3::boolean = false
				  OR (s.created_at < $4 OR (s.created_at = $4 AND s.id < $5))
			  )
			ORDER BY s.created_at DESC, s.id DESC
			LIMIT $6
		)
		SELECT
			EXISTS(SELECT 1 FROM caller) AS caller_found,
			COALESCE((SELECT account_status = 'active' FROM caller), false) AS account_active,
			COALESCE((SELECT revoked_at IS NULL FROM caller), false) AS caller_unrevoked,
			COALESCE((SELECT expires_at > (SELECT now FROM now_t) FROM caller), false) AS caller_unexpired,
			p.id,
			p.created_at,
			p.expires_at
		FROM (SELECT 1) _
		LEFT JOIN page p ON (
			EXISTS(SELECT 1 FROM caller)
			AND (SELECT account_status = 'active' FROM caller)
			AND (SELECT revoked_at IS NULL FROM caller)
			AND (SELECT expires_at > (SELECT now FROM now_t) FROM caller)
		)
		ORDER BY p.created_at DESC NULLS LAST, p.id DESC NULLS LAST;
	`

	rows, err := r.db.Query(queryCtx, query, callerSessionID, accountID, hasCursor, cursorCreatedAt, cursorID, fetchLimit)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return usecase.SessionListPage{}, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return usecase.SessionListPage{}, fmt.Errorf("querying active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []usecase.SessionSummary
	firstRow := true

	for rows.Next() {
		var (
			callerFound     bool
			accountActive   bool
			callerUnrevoked bool
			callerUnexpired bool
			sessionID       *string
			createdAt       *time.Time
			expiresAt       *time.Time
		)

		err := rows.Scan(
			&callerFound,
			&accountActive,
			&callerUnrevoked,
			&callerUnexpired,
			&sessionID,
			&createdAt,
			&expiresAt,
		)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return usecase.SessionListPage{}, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return usecase.SessionListPage{}, fmt.Errorf("scanning session row: %w", err)
		}

		if firstRow {
			firstRow = false
			if !callerFound {
				return usecase.SessionListPage{}, domain.ErrCallerSessionNotFound
			}
			if !accountActive {
				return usecase.SessionListPage{}, domain.ErrInvalidCredentials
			}
			if !callerUnrevoked {
				return usecase.SessionListPage{}, domain.ErrSessionRevoked
			}
			if !callerUnexpired {
				return usecase.SessionListPage{}, domain.ErrSessionExpired
			}
		}

		if sessionID != nil && createdAt != nil && expiresAt != nil {
			sessions = append(sessions, usecase.SessionSummary{
				ID:        *sessionID,
				CreatedAt: *createdAt,
				ExpiresAt: *expiresAt,
				IsCurrent: strings.ToLower(*sessionID) == callerSessionID,
			})
		}
	}

	if err := rows.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return usecase.SessionListPage{}, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return usecase.SessionListPage{}, fmt.Errorf("iterating session rows: %w", err)
	}

	if firstRow {
		return usecase.SessionListPage{}, domain.ErrCallerSessionNotFound
	}

	var nextCursor *usecase.SessionCursor
	if len(sessions) > filter.Limit {
		lastItem := sessions[filter.Limit-1]
		nextCursor = &usecase.SessionCursor{
			CreatedAt: lastItem.CreatedAt,
			ID:        lastItem.ID,
		}
		sessions = sessions[:filter.Limit]
	}

	if sessions == nil {
		sessions = []usecase.SessionSummary{}
	}

	return usecase.SessionListPage{
		Sessions:   sessions,
		NextCursor: nextCursor,
	}, nil
}

// RevokeSessionTarget atomically revokes a target session owned by accountID.
// It acquires accounts row (FOR SHARE) and locks sessions in ascending UUID order with
// pre-lock ownership filtering (account_id = $1), ensuring foreign sessions are never locked.
// Returns alreadyRevoked=true if the target was already revoked, or domain.ErrSessionNotFound if target does not exist or is foreign.
func (r *SessionRepository) RevokeSessionTarget(
	ctx context.Context,
	accountID string,
	callerSessionID string,
	targetSessionID string,
) (bool, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)
	targetSessionID = strings.ToLower(targetSessionID)

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("starting revoke transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// 1. Lock account row (FOR SHARE) to verify active status.
	// FOR SHARE serializes with logout-all (which takes FOR UPDATE) while permitting concurrent logins and single revokes.
	var accountStatus string
	accLockQuery := `SELECT status FROM accounts WHERE id = $1 FOR SHARE`
	err = tx.QueryRow(queryCtx, accLockQuery, accountID).Scan(&accountStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("locking account for session revocation: %w", err)
	}
	if accountStatus != string(domain.AccountStatusActive) {
		return false, domain.ErrInvalidCredentials
	}

	type lockedSessionRow struct {
		id        string
		expiresAt time.Time
		revokedAt *time.Time
	}

	// 2. Lock session rows in ascending UUID order with pre-lock ownership filtering.
	// By filtering by account_id = $1, another user's session row is never locked.
	// Ordering in ascending UUID order prevents opposite-direction deadlocks between concurrent revocations.
	lockedRows := make(map[string]lockedSessionRow)

	if callerSessionID == targetSessionID {
		var row lockedSessionRow
		row.id = callerSessionID
		singleLockQuery := `
			SELECT expires_at, revoked_at
			FROM sessions
			WHERE id = $1 AND account_id = $2
			FOR UPDATE
		`
		err = tx.QueryRow(queryCtx, singleLockQuery, callerSessionID, accountID).Scan(&row.expiresAt, &row.revokedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, domain.ErrCallerSessionNotFound
			}
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return false, fmt.Errorf("locking caller session: %w", err)
		}
		lockedRows[callerSessionID] = row
	} else {
		firstID, secondID := callerSessionID, targetSessionID
		if firstID > secondID {
			firstID, secondID = secondID, firstID
		}

		multiLockQuery := `
			SELECT id, expires_at, revoked_at
			FROM sessions
			WHERE account_id = $1 AND id IN ($2, $3)
			ORDER BY id
			FOR UPDATE
		`
		rows, err := tx.Query(queryCtx, multiLockQuery, accountID, firstID, secondID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return false, fmt.Errorf("locking session rows: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var row lockedSessionRow
			if err := rows.Scan(&row.id, &row.expiresAt, &row.revokedAt); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
					return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
				}
				return false, fmt.Errorf("scanning locked session row: %w", err)
			}
			lockedRows[strings.ToLower(row.id)] = row
		}
		if err := rows.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return false, fmt.Errorf("iterating locked session rows: %w", err)
		}
	}

	// 3. Post-lock re-verification of caller state using fresh wall-clock time.
	callerRow, ok := lockedRows[callerSessionID]
	if !ok {
		return false, domain.ErrCallerSessionNotFound
	}

	now := time.Now().UTC()
	if callerRow.revokedAt != nil {
		return false, domain.ErrSessionRevoked
	}
	if !now.Before(callerRow.expiresAt) {
		return false, domain.ErrSessionExpired
	}

	// 4. Validate target session ownership and state.
	targetRow, ok := lockedRows[targetSessionID]
	if !ok {
		// Target does not exist or belongs to another account.
		// Returns 404 domain.ErrSessionNotFound without leaking existence.
		return false, domain.ErrSessionNotFound
	}

	alreadyRevoked := targetRow.revokedAt != nil
	if !alreadyRevoked {
		updateQuery := `
			UPDATE sessions
			SET revoked_at = clock_timestamp()
			WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL
		`
		_, err = tx.Exec(queryCtx, updateQuery, targetSessionID, accountID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return false, fmt.Errorf("updating target session revocation: %w", err)
		}
	}

	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return false, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return false, fmt.Errorf("committing session revocation: %w", err)
	}

	return alreadyRevoked, nil
}

// RevokeAllSessions atomically revokes all unrevoked sessions owned by accountID.
// It acquires accounts row (FOR UPDATE) to serialize with login and refresh,
// locks all unrevoked sessions in ascending UUID order, validates caller from locked rows,
// and revokes all sessions using clock_timestamp().
func (r *SessionRepository) RevokeAllSessions(
	ctx context.Context,
	accountID string,
	callerSessionID string,
) error {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)

	tx, err := r.db.Begin(queryCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("starting logout-all transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(queryCtx)
	}()

	// 1. Acquire account lock (FOR UPDATE) to serialize with concurrent logins and refreshes.
	var accountStatus string
	accLockQuery := `SELECT status FROM accounts WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(queryCtx, accLockQuery, accountID).Scan(&accountStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCredentials
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("locking account for logout-all: %w", err)
	}
	if accountStatus != string(domain.AccountStatusActive) {
		return domain.ErrInvalidCredentials
	}

	// 2. Lock all unrevoked sessions for this account in ascending UUID order.
	lockSessionsQuery := `
		SELECT id, expires_at
		FROM sessions
		WHERE account_id = $1 AND revoked_at IS NULL
		ORDER BY id
		FOR UPDATE
	`
	rows, err := tx.Query(queryCtx, lockSessionsQuery, accountID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("locking unrevoked sessions for logout-all: %w", err)
	}
	defer rows.Close()

	type unrevokedRow struct {
		id        string
		expiresAt time.Time
	}
	var callerRow *unrevokedRow

	for rows.Next() {
		var row unrevokedRow
		if err := rows.Scan(&row.id, &row.expiresAt); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
				return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
			}
			return fmt.Errorf("scanning unrevoked session row: %w", err)
		}
		if strings.ToLower(row.id) == callerSessionID {
			callerCopy := row
			callerRow = &callerCopy
		}
	}
	if err := rows.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("iterating unrevoked session rows: %w", err)
	}

	// 3. Validate caller directly from the locked unrevoked rows.
	// If caller is not in unrevokedSessions, it is already revoked or foreign.
	if callerRow == nil {
		return domain.ErrSessionRevoked
	}

	now := time.Now().UTC()
	if !now.Before(callerRow.expiresAt) {
		return domain.ErrSessionExpired
	}

	// 4. Revoke all unrevoked sessions for this account in a single atomic update.
	updateQuery := `
		UPDATE sessions
		SET revoked_at = clock_timestamp()
		WHERE account_id = $1 AND revoked_at IS NULL
	`
	_, err = tx.Exec(queryCtx, updateQuery, accountID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("updating sessions for logout-all: %w", err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return fmt.Errorf("committing logout-all transaction: %w", err)
	}

	return nil
}
