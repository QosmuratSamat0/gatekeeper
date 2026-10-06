package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type mockClock struct {
	currentTime time.Time
}

func (m mockClock) Now() time.Time {
	return m.currentTime
}

func generateTestKeyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	return priv, pub
}

func TestTokenService_SignAndVerify_Success(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{currentTime: now}

	svc, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-2026-1", priv, nil, 10*time.Minute, clock)
	if err != nil {
		t.Fatalf("unexpected error creating token service: %v", err)
	}

	sub := "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
	sid := "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e"

	tokenStr, expAt, expiresIn, err := svc.SignAccessToken(sub, sid)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}
	if expiresIn != 600 {
		t.Errorf("expected expiresIn 600, got %d", expiresIn)
	}
	expectedExp := now.Add(10 * time.Minute).Truncate(time.Second)
	if !expAt.Equal(expectedExp) {
		t.Errorf("expected expAt %v, got %v", expectedExp, expAt)
	}

	claims, err := svc.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify valid access token: %v", err)
	}

	if claims.Subject != sub {
		t.Errorf("expected subject %s, got %s", sub, claims.Subject)
	}
	if claims.SessionID != sid {
		t.Errorf("expected session %s, got %s", sid, claims.SessionID)
	}
	if claims.Issuer != "gatekeeper-auth" {
		t.Errorf("expected issuer gatekeeper-auth, got %s", claims.Issuer)
	}
	if claims.Audience != "gatekeeper-services" {
		t.Errorf("expected audience gatekeeper-services, got %s", claims.Audience)
	}
	if claims.IssuedAt != now.Unix() {
		t.Errorf("expected iat %d, got %d", now.Unix(), claims.IssuedAt)
	}
	if claims.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Errorf("expected exp %d, got %d", now.Add(10*time.Minute).Unix(), claims.ExpiresAt)
	}
	if !IsValidUUID(claims.TokenID) {
		t.Errorf("expected valid jti uuid, got %s", claims.TokenID)
	}
}

func TestTokenService_VerifyAccessToken_MissingClaimsNegativeMatrix(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{currentTime: now}

	svc, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-2026-1", priv, nil, 10*time.Minute, clock)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	validClaims := map[string]any{
		"sub": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
		"sid": "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e",
		"iss": "gatekeeper-auth",
		"aud": "gatekeeper-services",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"jti": "c3d4e5f6-a1b2-4c3d-ae4f-5a6b7c8d9e0f",
	}

	requiredClaims := []string{"sub", "sid", "iss", "aud", "iat", "exp", "jti"}

	for _, claimToOmit := range requiredClaims {
		t.Run("missing_"+claimToOmit, func(t *testing.T) {
			tokenMap := make(map[string]any)
			for k, v := range validClaims {
				if k != claimToOmit {
					tokenMap[k] = v
				}
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(tokenMap))
			token.Header["kid"] = "key-2026-1"
			token.Header["typ"] = "JWT"
			signed, err := token.SignedString(priv)
			if err != nil {
				t.Fatalf("failed to sign token: %v", err)
			}

			_, err = svc.VerifyAccessToken(signed)
			if err == nil {
				t.Fatalf("expected error when %s is missing, got nil", claimToOmit)
			}
			if !errors.Is(err, ErrMissingRequiredClaim) {
				t.Errorf("expected ErrMissingRequiredClaim, got: %v", err)
			}
		})
	}
}

func TestTokenService_VerifyAccessToken_TemporalAndOrderingRules(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{currentTime: now}

	svc, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-2026-1", priv, nil, 10*time.Minute, clock)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	makeToken := func(iat, exp time.Time) string {
		claims := jwt.MapClaims{
			"sub": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
			"sid": "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e",
			"iss": "gatekeeper-auth",
			"aud": "gatekeeper-services",
			"iat": iat.Unix(),
			"exp": exp.Unix(),
			"jti": "c3d4e5f6-a1b2-4c3d-ae4f-5a6b7c8d9e0f",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["kid"] = "key-2026-1"
		token.Header["typ"] = "JWT"
		s, err := token.SignedString(priv)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		return s
	}

	// 1. exp <= iat order check
	t.Run("exp_equal_iat", func(t *testing.T) {
		tokenStr := makeToken(now, now)
		_, err := svc.VerifyAccessToken(tokenStr)
		if !errors.Is(err, ErrInvalidClaimOrder) {
			t.Errorf("expected ErrInvalidClaimOrder, got: %v", err)
		}
	})

	t.Run("exp_before_iat", func(t *testing.T) {
		tokenStr := makeToken(now, now.Add(-5*time.Minute))
		_, err := svc.VerifyAccessToken(tokenStr)
		if !errors.Is(err, ErrInvalidClaimOrder) {
			t.Errorf("expected ErrInvalidClaimOrder, got: %v", err)
		}
	})

	// 2. Future iat beyond clock skew (> 30s)
	t.Run("future_iat_rejected", func(t *testing.T) {
		tokenStr := makeToken(now.Add(35*time.Second), now.Add(10*time.Minute))
		_, err := svc.VerifyAccessToken(tokenStr)
		if !errors.Is(err, ErrFutureIssuedAt) {
			t.Errorf("expected ErrFutureIssuedAt, got: %v", err)
		}
	})

	// 3. Expired token (past expiry + 30s clock skew)
	t.Run("expired_token_rejected", func(t *testing.T) {
		tokenStr := makeToken(now.Add(-15*time.Minute), now.Add(-35*time.Second))
		_, err := svc.VerifyAccessToken(tokenStr)
		if !errors.Is(err, ErrTokenExpired) {
			t.Errorf("expected ErrTokenExpired, got: %v", err)
		}
	})

	// 4. Token within allowable 30s clock skew accepted
	t.Run("within_clock_skew_accepted", func(t *testing.T) {
		// exp was 10 seconds ago (within 30s skew tolerance)
		tokenStr := makeToken(now.Add(-10*time.Minute), now.Add(-10*time.Second))
		_, err := svc.VerifyAccessToken(tokenStr)
		if err != nil {
			t.Errorf("expected token within clock skew to be accepted, got error: %v", err)
		}
	})
}

func TestTokenService_VerifyAccessToken_HeaderAndAlgorithmSecurity(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{currentTime: now}

	svc, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-2026-1", priv, nil, 10*time.Minute, clock)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	validClaims := jwt.MapClaims{
		"sub": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
		"sid": "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e",
		"iss": "gatekeeper-auth",
		"aud": "gatekeeper-services",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"jti": "c3d4e5f6-a1b2-4c3d-ae4f-5a6b7c8d9e0f",
	}

	// 1. Missing typ header
	t.Run("missing_typ_header", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims)
		token.Header["kid"] = "key-2026-1"
		delete(token.Header, "typ")
		s, _ := token.SignedString(priv)
		_, err := svc.VerifyAccessToken(s)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("expected ErrInvalidHeader for missing typ, got: %v", err)
		}
	})

	// 2. Wrong typ header
	t.Run("wrong_typ_header", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims)
		token.Header["kid"] = "key-2026-1"
		token.Header["typ"] = "JOSE"
		s, _ := token.SignedString(priv)
		_, err := svc.VerifyAccessToken(s)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("expected ErrInvalidHeader for wrong typ, got: %v", err)
		}
	})

	// 3. Unknown kid
	t.Run("unknown_kid", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims)
		token.Header["kid"] = "non-existent-kid"
		token.Header["typ"] = "JWT"
		s, _ := token.SignedString(priv)
		_, err := svc.VerifyAccessToken(s)
		if !errors.Is(err, ErrUnknownKeyID) {
			t.Errorf("expected ErrUnknownKeyID, got: %v", err)
		}
	})

	// 4. Algorithm none rejection
	t.Run("alg_none_rejected", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims)
		token.Header["kid"] = "key-2026-1"
		token.Header["typ"] = "JWT"
		s, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		_, err := svc.VerifyAccessToken(s)
		if err == nil {
			t.Fatal("expected rejection for alg: none")
		}
	})

	// 5. Signature tampering
	t.Run("tampered_signature", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims)
		token.Header["kid"] = "key-2026-1"
		token.Header["typ"] = "JWT"
		s, _ := token.SignedString(priv)

		tampered := s[:len(s)-4] + "ABCD"
		_, err := svc.VerifyAccessToken(tampered)
		if err == nil {
			t.Fatal("expected error on tampered signature")
		}
	})
}

func TestTokenService_JWKSProjection(t *testing.T) {
	priv1, pub1 := generateTestKeyPair(t)
	_, pub2 := generateTestKeyPair(t)

	archived := map[string]ed25519.PublicKey{
		"old-key-2025": pub2,
	}

	svc, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "active-key-2026", priv1, archived, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	jwks := svc.JWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS, got %d", len(jwks.Keys))
	}

	// Deterministic sort: active-key-2026 before old-key-2025
	if jwks.Keys[0].Kid != "active-key-2026" || jwks.Keys[1].Kid != "old-key-2025" {
		t.Errorf("unexpected key order: %s, %s", jwks.Keys[0].Kid, jwks.Keys[1].Kid)
	}

	for _, k := range jwks.Keys {
		if k.Kty != "OKP" {
			t.Errorf("expected kty OKP, got %s", k.Kty)
		}
		if k.Crv != "Ed25519" {
			t.Errorf("expected crv Ed25519, got %s", k.Crv)
		}
		if k.Use != "sig" {
			t.Errorf("expected use sig, got %s", k.Use)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(decoded) != 32 {
			t.Errorf("invalid public key in JWKS X: %v", err)
		}
	}

	// Verify active key matches pub1
	decodedActive, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	if string(decodedActive) != string(pub1) {
		t.Error("active key X does not match private key's public key")
	}

	// Verify JSON output has no private fields (such as RFC 8037 "d" parameter)
	jsonBytes, err := svc.JWKSJSON()
	if err != nil {
		t.Fatalf("failed to marshal jwks: %v", err)
	}
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, `"d":`) || strings.Contains(jsonStr, `"private"`) {
		t.Errorf("jwks json contains unexpected private field markers: %s", jsonStr)
	}
}

func TestKeys_PKCS8PEMParsing(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	parsed, err := ParsePKCS8PrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 PEM: %v", err)
	}

	if string(parsed) != string(priv) {
		t.Error("parsed key does not match original")
	}
}

func TestTokenService_KeyIDCollision(t *testing.T) {
	priv1, _ := generateTestKeyPair(t)
	_, pub2 := generateTestKeyPair(t)

	// Attempting to register an archived key with the same kid as the active key,
	// but with different public key material must return an error.
	archived := map[string]ed25519.PublicKey{
		"key-active": pub2,
	}

	_, err := NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-active", priv1, archived, 10*time.Minute, nil)
	if err == nil {
		t.Fatal("expected error on kid conflict with differing key material, got nil")
	}
	if !strings.Contains(err.Error(), "conflicts with a different archived public key") {
		t.Errorf("unexpected error message: %v", err)
	}
}
