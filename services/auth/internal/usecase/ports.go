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

// SignSuccessorCallback defines the signing function invoked while holding the session row lock.
// It receives accountID, sessionID, and the verified absolute session expiration from the database row.
// It returns the signed access token JWT, its exact expiration timestamp, and expires_in duration in seconds.
type SignSuccessorCallback func(accountID, sessionID string, sessionExpiresAt time.Time) (token string, tokenExpiresAt time.Time, expiresIn int64, err error)

// RotationResult contains the signed access token and exact expiration metadata returned by the repository.
// Note: Raw refresh token is generated and kept in the usecase layer; it is never handled by the repository.
type RotationResult struct {
	AccessToken      string
	AccessTokenExp   time.Time
	ExpiresIn        int64
	RefreshExpiresIn int64
}

// SessionRepository defines persistent storage operations for user sessions.
type SessionRepository interface {
	// CreateAtomic inserts a session while atomically verifying that the account
	// is active and that its password hash has not changed concurrently.
	CreateAtomic(ctx context.Context, session domain.Session, expectedHash string) error

	// CreateWithInitialRefresh atomically verifies active account and password hash,
	// inserts the session, and inserts the initial unconsumed refresh token.
	CreateWithInitialRefresh(ctx context.Context, session domain.Session, expectedHash string, initialToken domain.RefreshToken) error

	// GetWithAccount retrieves the session and its linked account for /me endpoint.
	GetWithAccount(ctx context.Context, sessionID string) (domain.Session, domain.Account, error)

	// Revoke idempotently revokes a session identified by sessionID and accountID.
	// Returns alreadyRevoked=true if the session was already revoked.
	// Returns domain.ErrSessionNotFound if the session does not exist or belongs to another account.
	Revoke(ctx context.Context, sessionID string, accountID string) (alreadyRevoked bool, err error)

	// RevokeByRefreshTokenHash locates the session family by the presented token digest
	// and atomically revokes the session if the token is valid and unexpired.
	// Returns alreadyRevoked=true if the session was already revoked.
	// Returns domain.ErrSessionNotFound or domain.ErrInvalidCredentials if unknown or expired.
	RevokeByRefreshTokenHash(ctx context.Context, tokenHash []byte) (alreadyRevoked bool, err error)

	// RotateRefreshToken atomically performs refresh token rotation or replay revocation:
	// 1. Locks accounts, sessions, and refresh_tokens in canonical order.
	// 2. Re-verifies account active status, session revocation, session expiration, and token expiration using current time.
	// 3. If replay is detected (consumed_at IS NOT NULL), commits revocation of the family and returns ErrCompromisedSessionReplay.
	// 4. If valid, signs access token via signFn, marks old token consumed, inserts successor digest, and commits.
	RotateRefreshToken(ctx context.Context, presentedHash []byte, successorToken domain.RefreshToken, signFn SignSuccessorCallback) (*RotationResult, error)
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
	SignAccessTokenWithExpiry(subject, sessionID string, maxExpiry time.Time) (token string, expiresAt time.Time, expiresIn int64, err error)
}

// RefreshTokenGenerator defines generation of cryptographically secure refresh tokens and their SHA-256 digests.
type RefreshTokenGenerator interface {
	Generate() (rawToken string, hash []byte, err error)
}

// RefreshTokenValidator defines validation and hashing of client-presented refresh tokens.
type RefreshTokenValidator interface {
	ValidateAndHash(rawToken string) (hash []byte, err error)
}

// RefreshTokenManager combines refresh token generation and validation operations.
type RefreshTokenManager interface {
	RefreshTokenGenerator
	RefreshTokenValidator
}
