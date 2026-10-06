package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool initializes and validates a new PostgreSQL connection pool.
// It establishes a verified connection using a bounded ping. If connection fails,
// the pool is closed immediately and any credentials embedded in error messages
// are sanitized before returning to caller.
func NewPool(ctx context.Context, databaseURL string, connectTimeout time.Duration) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database configuration: %w", SanitizeError(err))
	}

	if connectTimeout > 0 {
		poolConfig.ConnConfig.ConnectTimeout = connectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", SanitizeError(err))
	}

	// Verify connectivity with a bounded ping so startup fails fast if the database is unreachable,
	// rather than accepting client requests that immediately fail.
	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", SanitizeError(err))
	}

	return pool, nil
}
