package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidTokenFormat indicates that the refresh token does not conform to the strict format
	// (strictly 43 ASCII characters, unpadded Base64URL, decoding to 32 bytes with canonical round-trip).
	ErrInvalidTokenFormat = errors.New("invalid refresh token format")
)

const (
	// RefreshTokenEntropyBytes defines the raw cryptographic entropy: 32 bytes (256 bits).
	RefreshTokenEntropyBytes = 32

	// RefreshTokenEncodedLength defines the expected length of 32 unpadded base64url bytes: ceil(32 * 4 / 3) = 43.
	RefreshTokenEncodedLength = 43
)

// GenerateRefreshToken generates a new cryptographically secure opaque refresh token.
// It returns the 43-character canonical unpadded base64url raw token and its 32-byte SHA-256 digest.
func GenerateRefreshToken() (string, []byte, error) {
	rawBytes := make([]byte, RefreshTokenEntropyBytes)
	if _, err := io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", nil, fmt.Errorf("generating secure random refresh token bytes: %w", err)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(rawBytes)
	hash := sha256.Sum256(rawBytes)
	return rawToken, hash[:], nil
}

// ValidateAndHashRefreshToken strictly validates a refresh token string:
// 1. Enforces length is exactly 43 ASCII characters without whitespace or padding '='.
// 2. Decodes via base64.RawURLEncoding to exactly 32 bytes.
// 3. Verifies canonical round-trip encoding to reject alternative encodings.
// 4. Returns the 32-byte SHA-256 digest for database lookup.
func ValidateAndHashRefreshToken(token string) ([]byte, error) {
	if len(token) != RefreshTokenEncodedLength {
		return nil, ErrInvalidTokenFormat
	}

	// Verify all characters belong to the strict unpadded base64url alphabet [A-Za-z0-9_-]
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return nil, ErrInvalidTokenFormat
		}
	}

	rawBytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, ErrInvalidTokenFormat
	}

	if len(rawBytes) != RefreshTokenEntropyBytes {
		return nil, ErrInvalidTokenFormat
	}

	// Enforce canonical round-trip encoding (rejects non-canonical bit representations)
	if base64.RawURLEncoding.EncodeToString(rawBytes) != token {
		return nil, ErrInvalidTokenFormat
	}

	hash := sha256.Sum256(rawBytes)
	return hash[:], nil
}

// RefreshTokenManager implements usecase.RefreshTokenManager using crypto/rand and SHA-256.
type RefreshTokenManager struct{}

// NewRefreshTokenManager constructs a RefreshTokenManager instance.
func NewRefreshTokenManager() *RefreshTokenManager {
	return &RefreshTokenManager{}
}

// Generate creates a cryptographically random 32-byte refresh token and its SHA-256 digest.
func (m *RefreshTokenManager) Generate() (string, []byte, error) {
	return GenerateRefreshToken()
}

// ValidateAndHash validates canonical unpadded base64url encoding and returns its 32-byte SHA-256 digest.
func (m *RefreshTokenManager) ValidateAndHash(token string) ([]byte, error) {
	return ValidateAndHashRefreshToken(token)
}
