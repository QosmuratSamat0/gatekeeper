package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

const (
	// EmailUniqueConstraint matches the constraint name defined in 000001_accounts.up.sql.
	EmailUniqueConstraint = "accounts_email_unique"
	// PGUniqueViolationCode is the PostgreSQL error code for unique_violation.
	PGUniqueViolationCode = "23505"
)

// DBExecutor abstracts pgxpool.Pool and pgx.Tx for execution.
type DBExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// AccountRepository manages persistent account storage in PostgreSQL.
type AccountRepository struct {
	db           DBExecutor
	queryTimeout time.Duration
}

// NewAccountRepository creates a new AccountRepository with an enforced query timeout.
// The query timeout prevents hanging queries from exhausting connection pools or request workers.
func NewAccountRepository(db DBExecutor, queryTimeout time.Duration) *AccountRepository {
	if queryTimeout <= 0 {
		queryTimeout = 3 * time.Second
	}
	return &AccountRepository{
		db:           db,
		queryTimeout: queryTimeout,
	}
}

// GetByEmail retrieves an account by its unique email address.
func (r *AccountRepository) GetByEmail(ctx context.Context, email string) (domain.Account, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	query := `
		SELECT id, email, password_hash, status, email_verified, created_at, updated_at
		FROM accounts
		WHERE email = $1
	`

	var acc domain.Account
	var status string
	err := r.db.QueryRow(queryCtx, query, email).Scan(
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
			return domain.Account{}, domain.ErrAccountNotFound
		}
		if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
			return domain.Account{}, fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
		}
		return domain.Account{}, fmt.Errorf("failed to get account by email: %w", err)
	}

	acc.Status = domain.AccountStatus(status)
	return acc, nil
}

// Create inserts a new account into the database with a bounded query timeout.
// Only email unique constraint violations map to domain.ErrAccountExists;
// connection and timeout failures map to domain.ErrDatabaseUnavailable;
// unexpected SQL or infrastructure errors remain wrapped internal errors.
func (r *AccountRepository) Create(ctx context.Context, account domain.Account) error {
	// Bound query execution time so slow or deadlocked database calls do not block indefinitely.
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	query := `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.Exec(queryCtx, query,
		account.ID,
		account.Email,
		account.PasswordHash,
		string(account.Status),
		account.EmailVerified,
		account.CreatedAt,
		account.UpdatedAt,
	)

	if err != nil {
		return mapInsertError(err)
	}

	return nil
}

// mapInsertError maps database errors to appropriate domain errors.
func mapInsertError(err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Strict check: only email unique constraint violation means account already exists.
		// UUID primary key collision (e.g. constraint "accounts_pkey") is an infrastructure error, NOT ErrAccountExists.
		if pgErr.Code == PGUniqueViolationCode && pgErr.ConstraintName == EmailUniqueConstraint {
			return domain.ErrAccountExists
		}
	}

	// Distinguish transient availability and timeout failures from permanent bugs.
	// This ensures clients receive 503 Service Unavailable when the database is unreachable,
	// rather than receiving 500 Internal Error or 409 Conflict.
	if errors.Is(err, context.DeadlineExceeded) || isConnectionOrTimeout(err) {
		return fmt.Errorf("%w: %w", domain.ErrDatabaseUnavailable, err)
	}

	return fmt.Errorf("failed to insert account: %w", err)
}

func isConnectionOrTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var pgConnErr *pgconn.ConnectError
	return errors.As(err, &pgConnErr)
}
