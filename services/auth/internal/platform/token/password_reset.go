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
	// ErrInvalidPasswordResetTokenFormat indicates that the password reset token is not a valid
	// 43-character canonical unpadded base64url string.
	ErrInvalidPasswordResetTokenFormat = errors.New("invalid password reset token format")
)

const (
	// PasswordResetTokenEntropyBytes defines the raw cryptographic entropy: 32 bytes (256 bits).
	PasswordResetTokenEntropyBytes = 32

	// PasswordResetTokenEncodedLength defines the expected length of 32 unpadded base64url bytes: ceil(32 * 4 / 3) = 43.
	PasswordResetTokenEncodedLength = 43
)

// GeneratePasswordResetToken generates 32 cryptographically random bytes,
// encodes them as a 43-character canonical unpadded base64url token, and computes its 32-byte SHA-256 digest.
func GeneratePasswordResetToken() (string, []byte, error) {
	// Generate 32 bytes of cryptographically secure random entropy.
	// This ensures brute force attacks require 2^256 attempts, making guessing impossible.
	rawBytes := make([]byte, PasswordResetTokenEntropyBytes)
	if _, err := io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", nil, fmt.Errorf("generating secure random password reset token: %w", err)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(rawBytes)
	hash := sha256.Sum256(rawBytes)
	return rawToken, hash[:], nil
}

// ValidateAndHashPasswordResetToken strictly validates the password reset token:
// 1. Enforces length is exactly 43 ASCII characters.
// 2. Verifies that all characters belong to the strict unpadded base64url alphabet [A-Za-z0-9_-].
// 3. Decodes strictly to 32 bytes.
// 4. Verifies canonical round-trip encoding to reject alternative encodings or non-zero padding bits.
// 5. Computes the 32-byte SHA-256 digest.
func ValidateAndHashPasswordResetToken(token string) ([]byte, error) {
	// Reject tokens that do not match the exact 43-character length.
	// This immediately filters out truncated strings or oversized payloads.
	if len(token) != PasswordResetTokenEncodedLength {
		return nil, ErrInvalidPasswordResetTokenFormat
	}

	// Reject any character outside the RFC 4648 base64url alphabet.
	// This prevents whitespace injection or control characters from being processed.
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return nil, ErrInvalidPasswordResetTokenFormat
		}
	}

	// Strictly decode the unpadded base64url string.
	// Strict decoding ensures standard compliance and rejects padded strings.
	rawBytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, ErrInvalidPasswordResetTokenFormat
	}

	// Ensure the decoded secret is exactly 32 bytes (256 bits).
	// This prevents malformed lengths from entering the cryptographic pipeline.
	if len(rawBytes) != PasswordResetTokenEntropyBytes {
		return nil, ErrInvalidPasswordResetTokenFormat
	}

	// Re-encode and compare with the input string.
	// In unpadded base64url, the 43rd character has 2 unused bits that must be 0.
	// This check prevents attackers from submitting non-canonical bit variations.
	if base64.RawURLEncoding.EncodeToString(rawBytes) != token {
		return nil, ErrInvalidPasswordResetTokenFormat
	}

	hash := sha256.Sum256(rawBytes)
	return hash[:], nil
}

// PasswordResetTokenManager implements usecase.PasswordResetTokenGenerator.
type PasswordResetTokenManager struct{}

// NewPasswordResetTokenManager creates a new PasswordResetTokenManager instance.
func NewPasswordResetTokenManager() *PasswordResetTokenManager {
	return &PasswordResetTokenManager{}
}

// Generate creates a 43-character base64url token and its 32-byte SHA-256 digest.
func (m *PasswordResetTokenManager) Generate() (string, []byte, error) {
	return GeneratePasswordResetToken()
}

// ValidateAndHash validates canonical RFC 4648 format and returns the 32-byte SHA-256 digest.
func (m *PasswordResetTokenManager) ValidateAndHash(token string) ([]byte, error) {
	return ValidateAndHashPasswordResetToken(token)
}
