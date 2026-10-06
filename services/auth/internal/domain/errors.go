package domain

import "errors"

var (
	// ErrAccountExists indicates that the canonical email is already registered.
	// We return this typed error so the HTTP layer can emit a 409 Conflict status.
	ErrAccountExists = errors.New("account already exists")

	// ErrInvalidEmail indicates that the email does not meet validation criteria
	// (such as invalid syntax, non-ASCII characters, or exceeding 254 bytes).
	ErrInvalidEmail = errors.New("invalid email")

	// ErrInvalidPassword indicates that the password does not satisfy length or encoding
	// requirements (must be valid UTF-8 and between 8 and 128 Unicode code points).
	ErrInvalidPassword = errors.New("invalid password")

	// ErrDatabaseUnavailable indicates that PostgreSQL cannot be reached or the query
	// timed out. The HTTP layer maps this to 503 Service Unavailable so clients know
	// the outage is transient and may be retried.
	ErrDatabaseUnavailable = errors.New("database is unavailable or query timed out")

	// ErrAccountNotFound indicates that no account exists with the provided identifier.
	ErrAccountNotFound = errors.New("account not found")

	// ErrInvalidCredentials indicates authentication failure (unknown email, incorrect password,
	// or disabled account). A generic error prevents account enumeration or status disclosure.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrSessionNotFound indicates that the session specified in the token does not exist in storage.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionRevoked indicates that the session was explicitly terminated before its expiration.
	ErrSessionRevoked = errors.New("session has been revoked")

	// ErrSessionExpired indicates that the session has passed its expiration timestamp.
	ErrSessionExpired = errors.New("session has expired")

	// ErrRateLimited indicates that the caller exceeded the allowed request frequency limit.
	ErrRateLimited = errors.New("rate limit exceeded")

	// ErrInternalCredentialFailure indicates that a stored password hash was malformed or corrupted.
	ErrInternalCredentialFailure = errors.New("internal credential storage failure")
)
