package domain

import (
	"time"
)

// Session represents an authenticated user session associated with an issued access token.
// The session lifecycle is tied to the access token's expiry in AUTH-02.
// Revocation invalidates the session immediately for protected endpoints like /me.
type Session struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive checks whether the session is currently valid at the given time.
// A session is active only if it has not been revoked and has not passed its expiration time.
func (s Session) IsActive(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// RefreshToken represents a persisted cryptographic digest of a refresh token in a session family.
// Only the SHA-256 digest is stored; raw tokens are never persisted in the database.
type RefreshToken struct {
	ID         string     `json:"id"`
	SessionID  string     `json:"session_id"`
	TokenHash  []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// IsActive checks whether the refresh token has not been consumed and has not expired.
func (r RefreshToken) IsActive(now time.Time) bool {
	if r.ConsumedAt != nil {
		return false
	}
	return now.Before(r.ExpiresAt)
}
