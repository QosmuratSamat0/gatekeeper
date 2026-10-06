package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingRequiredClaim = errors.New("missing required jwt claim")
	ErrInvalidClaimValue    = errors.New("invalid jwt claim value")
	ErrTokenExpired         = errors.New("jwt token has expired")
	ErrFutureIssuedAt       = errors.New("jwt issued in the future")
	ErrInvalidClaimOrder    = errors.New("jwt exp must be strictly greater than iat")
	ErrInvalidUUID          = errors.New("jwt claim must be a valid UUID")
	ErrIssuerMismatch       = errors.New("jwt issuer mismatch")
	ErrAudienceMismatch     = errors.New("jwt audience mismatch")
	ErrInvalidHeader        = errors.New("invalid jwt header")
	ErrUnsupportedAlgorithm = errors.New("unsupported jwt signing algorithm")
	ErrUnknownKeyID         = errors.New("unknown jwt key id")
)

// AccessClaims holds validated access token claims.
type AccessClaims struct {
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	TokenID   string `json:"jti"`
}

// rawAccessClaims uses pointers to differentiate between explicitly present zero-values
// and completely omitted claims in the token payload.
type rawAccessClaims struct {
	Subject   *string `json:"sub"`
	SessionID *string `json:"sid"`
	Issuer    *string `json:"iss"`
	Audience  *string `json:"aud"`
	IssuedAt  *int64  `json:"iat"`
	ExpiresAt *int64  `json:"exp"`
	TokenID   *string `json:"jti"`
}

func (c *AccessClaims) UnmarshalJSON(data []byte) error {
	var raw rawAccessClaims
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decoding claims: %w", err)
	}

	// Strictly verify that every required claim is physically present in the JSON payload
	if raw.Subject == nil {
		return fmt.Errorf("%w: sub", ErrMissingRequiredClaim)
	}
	if raw.SessionID == nil {
		return fmt.Errorf("%w: sid", ErrMissingRequiredClaim)
	}
	if raw.Issuer == nil {
		return fmt.Errorf("%w: iss", ErrMissingRequiredClaim)
	}
	if raw.Audience == nil {
		return fmt.Errorf("%w: aud", ErrMissingRequiredClaim)
	}
	if raw.IssuedAt == nil {
		return fmt.Errorf("%w: iat", ErrMissingRequiredClaim)
	}
	if raw.ExpiresAt == nil {
		return fmt.Errorf("%w: exp", ErrMissingRequiredClaim)
	}
	if raw.TokenID == nil {
		return fmt.Errorf("%w: jti", ErrMissingRequiredClaim)
	}

	c.Subject = *raw.Subject
	c.SessionID = *raw.SessionID
	c.Issuer = *raw.Issuer
	c.Audience = *raw.Audience
	c.IssuedAt = *raw.IssuedAt
	c.ExpiresAt = *raw.ExpiresAt
	c.TokenID = *raw.TokenID

	return nil
}

// Implement jwt.Claims interface
func (c AccessClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c AccessClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c AccessClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c AccessClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c AccessClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c AccessClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}
