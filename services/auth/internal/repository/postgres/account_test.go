package postgres

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

type mockDBExecutor struct {
	execFn     func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
}

func (m *mockDBExecutor) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return m.execFn(ctx, sql, arguments...)
}

func (m *mockDBExecutor) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, sql, args...)
	}
	return nil
}

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

var _ net.Error = fakeTimeoutError{}

func TestMapInsertError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		if err := mapInsertError(nil); err != nil {
			t.Errorf("expected nil, got: %v", err)
		}
	})

	t.Run("email unique constraint returns domain.ErrAccountExists", func(t *testing.T) {
		pgErr := &pgconn.PgError{
			Code:           PGUniqueViolationCode,
			ConstraintName: EmailUniqueConstraint,
		}

		err := mapInsertError(pgErr)
		if !errors.Is(err, domain.ErrAccountExists) {
			t.Errorf("expected domain.ErrAccountExists, got: %v", err)
		}
	})

	t.Run("UUID primary key conflict does NOT return domain.ErrAccountExists", func(t *testing.T) {
		// PostgreSQL pkey constraint violation on UUID column
		pgErr := &pgconn.PgError{
			Code:           PGUniqueViolationCode,
			ConstraintName: "accounts_pkey",
		}

		err := mapInsertError(pgErr)
		if errors.Is(err, domain.ErrAccountExists) {
			t.Fatal("UUID primary key conflict must NOT be mapped to domain.ErrAccountExists")
		}
	})

	t.Run("deadline exceeded returns domain.ErrDatabaseUnavailable", func(t *testing.T) {
		err := mapInsertError(context.DeadlineExceeded)
		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Errorf("expected ErrDatabaseUnavailable for timeout, got: %v", err)
		}
	})

	t.Run("network timeout returns domain.ErrDatabaseUnavailable", func(t *testing.T) {
		err := mapInsertError(fakeTimeoutError{})
		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Errorf("expected ErrDatabaseUnavailable for net.Error timeout, got: %v", err)
		}
	})

	t.Run("generic SQL error is wrapped and not ErrAccountExists or ErrDatabaseUnavailable", func(t *testing.T) {
		genericErr := errors.New("syntax error at or near 'INVALID'")
		err := mapInsertError(genericErr)
		if errors.Is(err, domain.ErrAccountExists) {
			t.Fatal("generic error must not be mapped to ErrAccountExists")
		}
		if errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatal("generic syntax error must not be mapped to ErrDatabaseUnavailable")
		}
	})
}

func TestAccountRepository_Create(t *testing.T) {
	account := domain.Account{
		ID:            "a0000000-0000-4000-8000-000000000001",
		Email:         "test@example.com",
		PasswordHash:  "$argon2id$v=19$...",
		Status:        domain.AccountStatusActive,
		EmailVerified: false,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	t.Run("successful insert", func(t *testing.T) {
		mockDB := &mockDBExecutor{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				if len(arguments) != 7 {
					t.Errorf("expected 7 arguments, got %d", len(arguments))
				}
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			},
		}

		repo := NewAccountRepository(mockDB, 2*time.Second)
		if err := repo.Create(context.Background(), account); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("email duplicate returns ErrAccountExists", func(t *testing.T) {
		mockDB := &mockDBExecutor{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, &pgconn.PgError{
					Code:           "23505",
					ConstraintName: "accounts_email_unique",
				}
			},
		}

		repo := NewAccountRepository(mockDB, 2*time.Second)
		err := repo.Create(context.Background(), account)
		if !errors.Is(err, domain.ErrAccountExists) {
			t.Fatalf("expected ErrAccountExists, got: %v", err)
		}
	})

	t.Run("query timeout triggers context deadline in exec", func(t *testing.T) {
		mockDB := &mockDBExecutor{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				// Verify context has deadline
				if _, hasDeadline := ctx.Deadline(); !hasDeadline {
					t.Error("expected query context to have deadline")
				}
				return pgconn.CommandTag{}, context.DeadlineExceeded
			},
		}

		repo := NewAccountRepository(mockDB, 50*time.Millisecond)
		err := repo.Create(context.Background(), account)
		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatalf("expected ErrDatabaseUnavailable on timeout, got: %v", err)
		}
	})
}
