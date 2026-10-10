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
	// ErrInvalidVerificationTokenFormat indicates that the verification token is not a valid
	// 43-character canonical unpadded base64url string.
	ErrInvalidVerificationTokenFormat = errors.New("invalid verification token format")
)

const (
	// EmailVerificationTokenEntropyBytes defines the raw cryptographic entropy: 32 bytes (256 bits).
	EmailVerificationTokenEntropyBytes = 32

	// EmailVerificationTokenEncodedLength defines the expected length of 32 unpadded base64url bytes: ceil(32 * 4 / 3) = 43.
	EmailVerificationTokenEncodedLength = 43
)

// GenerateEmailVerificationToken generates 32 cryptographically random bytes,
// encodes them as a 43-character canonical unpadded base64url token, and computes its 32-byte SHA-256 digest.
func GenerateEmailVerificationToken() (string, []byte, error) {
	// Generate 32 bytes of cryptographically secure random entropy.
	// This ensures brute force attacks require 2^256 attempts, making guessing impossible.
	rawBytes := make([]byte, EmailVerificationTokenEntropyBytes)
	if _, err := io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", nil, fmt.Errorf("generating secure random email verification token: %w", err)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(rawBytes)
	hash := sha256.Sum256(rawBytes)
	return rawToken, hash[:], nil
}

// ValidateAndHashEmailVerificationToken strictly validates the verification token:
// 1. Enforces length is exactly 43 ASCII characters.
// 2. Verifies that all characters belong to the strict unpadded base64url alphabet [A-Za-z0-9_-].
// 3. Decodes strictly to 32 bytes.
// 4. Verifies canonical round-trip encoding to reject alternative encodings or non-zero padding bits.
// 5. Computes the 32-byte SHA-256 digest.
func ValidateAndHashEmailVerificationToken(token string) ([]byte, error) {
	// Reject tokens that do not match the exact 43-character length.
	// This immediately filters out truncated strings or oversized payloads.
	if len(token) != EmailVerificationTokenEncodedLength {
		return nil, ErrInvalidVerificationTokenFormat
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
			return nil, ErrInvalidVerificationTokenFormat
		}
	}

	// Strictly decode the unpadded base64url string.
	// Strict decoding ensures standard compliance and rejects padded strings.
	rawBytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, ErrInvalidVerificationTokenFormat
	}

	// Ensure the decoded secret is exactly 32 bytes (256 bits).
	// This prevents malformed lengths from entering the cryptographic pipeline.
	if len(rawBytes) != EmailVerificationTokenEntropyBytes {
		return nil, ErrInvalidVerificationTokenFormat
	}

	// Re-encode and compare with the input string.
	// In unpadded base64url, the 43rd character has 2 unused bits that must be 0.
	// This check prevents attackers from submitting non-canonical bit variations.
	if base64.RawURLEncoding.EncodeToString(rawBytes) != token {
		return nil, ErrInvalidVerificationTokenFormat
	}

	hash := sha256.Sum256(rawBytes)
	return hash[:], nil
}

// EmailVerificationTokenManager implements usecase.EmailVerificationTokenGenerator.
type EmailVerificationTokenManager struct{}

// NewEmailVerificationTokenManager creates a new EmailVerificationTokenManager instance.
func NewEmailVerificationTokenManager() *EmailVerificationTokenManager {
	return &EmailVerificationTokenManager{}
}

// Generate creates a 43-character base64url token and its 32-byte SHA-256 digest.
func (m *EmailVerificationTokenManager) Generate() (string, []byte, error) {
	return GenerateEmailVerificationToken()
}

// ValidateAndHash validates canonical RFC 4648 format and returns the 32-byte SHA-256 digest.
func (m *EmailVerificationTokenManager) ValidateAndHash(token string) ([]byte, error) {
	return ValidateAndHashEmailVerificationToken(token)
}
