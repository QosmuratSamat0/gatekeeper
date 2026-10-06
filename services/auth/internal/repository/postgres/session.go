package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
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
