package usecase

import (
	"context"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// AccountRepository defines persistent storage operations for accounts.
type AccountRepository interface {
	Create(ctx context.Context, account domain.Account) error
	GetByEmail(ctx context.Context, email string) (domain.Account, error)
}

// SessionRepository defines persistent storage operations for user sessions.
type SessionRepository interface {
	// CreateAtomic inserts a session while atomically verifying that the account
	// is active and that its password hash has not changed concurrently.
	CreateAtomic(ctx context.Context, session domain.Session, expectedHash string) error

	// GetWithAccount retrieves the session and its linked account for /me endpoint.
	GetWithAccount(ctx context.Context, sessionID string) (domain.Session, domain.Account, error)

	// Revoke idempotently revokes a session identified by sessionID and accountID.
	// Returns alreadyRevoked=true if the session was already revoked.
	// Returns domain.ErrSessionNotFound if the session does not exist or belongs to another account.
	Revoke(ctx context.Context, sessionID string, accountID string) (alreadyRevoked bool, err error)
}

// PasswordHasher defines the contract for securely hashing passwords during registration.
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
}

// PasswordVerifier defines the contract for verifying passwords against stored PHC hashes during login.
type PasswordVerifier interface {
	Verify(ctx context.Context, password string, phcHash string) (bool, error)
}

// TokenSigner defines the contract for issuing signed access JWTs.
type TokenSigner interface {
	SignAccessToken(subject, sessionID string) (token string, expiresAt time.Time, expiresIn int64, err error)
}
