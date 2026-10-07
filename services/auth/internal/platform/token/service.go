package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// Clock abstracts time for deterministic testing.
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

// MaxClockSkew defines the maximum tolerated time discrepancy (30 seconds) per specification.
const MaxClockSkew = 30 * time.Second

// TokenService issues, validates, and manages Ed25519 JWT access tokens and JWKS key sets.
type TokenService struct {
	issuer     string
	audience   string
	activeKid  string
	privateKey ed25519.PrivateKey
	publicKeys map[string]ed25519.PublicKey
	ttl        time.Duration
	clock      Clock
}

// NewTokenService creates a new TokenService with validated configuration.
func NewTokenService(
	issuer, audience, activeKid string,
	privateKey ed25519.PrivateKey,
	archivedPublicKeys map[string]ed25519.PublicKey,
	ttl time.Duration,
	clock Clock,
) (*TokenService, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	if activeKid == "" {
		return nil, errors.New("active kid is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if clock == nil {
		clock = RealClock{}
	}

	keys := make(map[string]ed25519.PublicKey)
	for kid, pub := range archivedPublicKeys {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size for kid %s", kid)
		}
		keys[kid] = pub
	}

	// Active public key derived from private key
	activePub := privateKey.Public().(ed25519.PublicKey)
	if existingPub, exists := keys[activeKid]; exists {
		if !bytes.Equal(existingPub, activePub) {
			return nil, fmt.Errorf("active key kid %q conflicts with a different archived public key", activeKid)
		}
	}
	keys[activeKid] = activePub

	return &TokenService{
		issuer:     issuer,
		audience:   audience,
		activeKid:  activeKid,
		privateKey: privateKey,
		publicKeys: keys,
		ttl:        ttl,
		clock:      clock,
	}, nil
}

// SignAccessToken creates an asymmetrically signed Ed25519 JWT access token with the configured default TTL.
func (s *TokenService) SignAccessToken(subject, sessionID string) (string, time.Time, int64, error) {
	return s.SignAccessTokenWithExpiry(subject, sessionID, time.Time{})
}

// SignAccessTokenWithExpiry creates an asymmetrically signed Ed25519 JWT access token
// with expiration clamped to maxExpiry if provided.
// If after integer-second truncation/rounding exp <= iat, it returns domain.ErrSessionExpired.
func (s *TokenService) SignAccessTokenWithExpiry(subject, sessionID string, maxExpiry time.Time) (string, time.Time, int64, error) {
	if !IsValidUUID(subject) {
		return "", time.Time{}, 0, fmt.Errorf("%w: invalid subject uuid", ErrInvalidClaimValue)
	}
	if !IsValidUUID(sessionID) {
		return "", time.Time{}, 0, fmt.Errorf("%w: invalid session uuid", ErrInvalidClaimValue)
	}

	now := s.clock.Now().UTC()
	iat := now.Unix()
	targetExp := now.Add(s.ttl)
	if !maxExpiry.IsZero() && targetExp.After(maxExpiry) {
		targetExp = maxExpiry
	}
	exp := targetExp.Unix()
	if exp <= iat {
		return "", time.Time{}, 0, domain.ErrSessionExpired
	}
	expiresAt := time.Unix(exp, 0).UTC()
	expiresIn := exp - iat

	jti, err := generateUUID()
	if err != nil {
		return "", time.Time{}, 0, fmt.Errorf("generating jti: %w", err)
	}

	claims := AccessClaims{
		Subject:   subject,
		SessionID: sessionID,
		Issuer:    s.issuer,
		Audience:  s.audience,
		IssuedAt:  iat,
		ExpiresAt: exp,
		TokenID:   jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.activeKid
	token.Header["typ"] = "JWT"

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, 0, fmt.Errorf("signing access token: %w", err)
	}

	return tokenString, expiresAt, expiresIn, nil
}

// VerifyAccessToken strictly parses and verifies an access token:
// 1. Enforces header typ=JWT and alg=EdDSA.
// 2. Looks up public key by kid without trusting embedded keys.
// 3. Verifies cryptographic signature using the matching Ed25519 public key.
// 4. Verifies presence and UUID validity of sub, sid, jti.
// 5. Enforces exact iss and aud match.
// 6. Validates ordering exp > iat.
// 7. Enforces expiration and rejects future iat with at most 30s clock skew tolerance.
func (s *TokenService) VerifyAccessToken(tokenString string) (AccessClaims, error) {
	if tokenString == "" {
		return AccessClaims{}, errors.New("token is empty")
	}

	var claims AccessClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		// Disable default claims validation so we can apply our strict negative checks
		jwt.WithoutClaimsValidation(),
	)

	token, err := parser.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		// Verify algorithm strictly
		if token.Method.Alg() != "EdDSA" {
			return nil, fmt.Errorf("%w: expected EdDSA, got %s", ErrUnsupportedAlgorithm, token.Method.Alg())
		}

		// Verify typ header strictly
		typ, ok := token.Header["typ"].(string)
		if !ok || typ != "JWT" {
			return nil, fmt.Errorf("%w: expected typ JWT, got %v", ErrInvalidHeader, token.Header["typ"])
		}

		// Verify kid header strictly
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("%w: missing or empty kid", ErrInvalidHeader)
		}

		pubKey, exists := s.publicKeys[kid]
		if !exists {
			return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, kid)
		}

		return pubKey, nil
	})

	if err != nil {
		return AccessClaims{}, fmt.Errorf("verifying token: %w", err)
	}

	if !token.Valid {
		return AccessClaims{}, errors.New("token is invalid")
	}

	// Semantic claim validations
	if !IsValidUUID(claims.Subject) {
		return AccessClaims{}, fmt.Errorf("%w: invalid sub uuid", ErrInvalidUUID)
	}
	if !IsValidUUID(claims.SessionID) {
		return AccessClaims{}, fmt.Errorf("%w: invalid sid uuid", ErrInvalidUUID)
	}
	if !IsValidUUID(claims.TokenID) {
		return AccessClaims{}, fmt.Errorf("%w: invalid jti uuid", ErrInvalidUUID)
	}

	if claims.Issuer != s.issuer {
		return AccessClaims{}, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch, s.issuer, claims.Issuer)
	}
	if claims.Audience != s.audience {
		return AccessClaims{}, fmt.Errorf("%w: expected %s, got %s", ErrAudienceMismatch, s.audience, claims.Audience)
	}

	// Temporal ordering check: exp must be strictly greater than iat
	if claims.ExpiresAt <= claims.IssuedAt {
		return AccessClaims{}, ErrInvalidClaimOrder
	}

	now := s.clock.Now().UTC()

	// Reject tokens issued in the future (allowing at most 30s clock skew)
	if claims.IssuedAt > now.Add(MaxClockSkew).Unix() {
		return AccessClaims{}, fmt.Errorf("%w: issued at %d, current %d", ErrFutureIssuedAt, claims.IssuedAt, now.Unix())
	}

	// Reject expired tokens (allowing at most 30s clock skew)
	if now.Add(-MaxClockSkew).Unix() >= claims.ExpiresAt {
		return AccessClaims{}, fmt.Errorf("%w: expired at %d, current %d", ErrTokenExpired, claims.ExpiresAt, now.Unix())
	}

	return claims, nil
}

// IsValidUUID validates that a string is a 36-character hexadecimal UUID format.
func IsValidUUID(u string) bool {
	if len(u) != 36 {
		return false
	}
	for i, c := range u {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'f':
			case c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
	}
	return true
}

func generateUUID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
