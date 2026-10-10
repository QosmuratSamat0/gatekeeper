package config_test

import (
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config"
)

func TestConfigLoad(t *testing.T) {
	t.Run("fails when DATABASE_URL is missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "dummy.pem")
		_, err := config.Load()
		if err == nil {
			t.Fatal("expected error when DATABASE_URL is missing")
		}
	})

	t.Run("fails when JWT_PRIVATE_KEY_FILE is missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "")
		_, err := config.Load()
		if err == nil {
			t.Fatal("expected error when JWT_PRIVATE_KEY_FILE is missing")
		}
	})

	t.Run("loads defaults with valid DATABASE_URL and key file", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "keys/private.pem")
		t.Setenv("HTTP_ADDR", "")
		t.Setenv("DB_CONNECT_TIMEOUT", "")
		t.Setenv("DB_QUERY_TIMEOUT", "")
		t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "")
		t.Setenv("PASSWORD_HASH_CONCURRENCY", "")
		t.Setenv("JWT_ISSUER", "")
		t.Setenv("JWT_AUDIENCE", "")
		t.Setenv("JWT_ACTIVE_KID", "")
		t.Setenv("ACCESS_TOKEN_TTL", "")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.HTTPAddr != ":8080" {
			t.Errorf("expected :8080, got %s", cfg.HTTPAddr)
		}
		if cfg.DBConnectTimeout != 5*time.Second {
			t.Errorf("expected 5s, got %v", cfg.DBConnectTimeout)
		}
		if cfg.DBQueryTimeout != 3*time.Second {
			t.Errorf("expected 3s, got %v", cfg.DBQueryTimeout)
		}
		if cfg.HTTPShutdownTimeout != 10*time.Second {
			t.Errorf("expected 10s, got %v", cfg.HTTPShutdownTimeout)
		}
		if cfg.PasswordHashConcurrency != 2 {
			t.Errorf("expected 2, got %d", cfg.PasswordHashConcurrency)
		}
		if cfg.JWTIssuer != "gatekeeper-auth" {
			t.Errorf("expected gatekeeper-auth, got %s", cfg.JWTIssuer)
		}
		if cfg.JWTAudience != "gatekeeper-services" {
			t.Errorf("expected gatekeeper-services, got %s", cfg.JWTAudience)
		}
		if cfg.JWTActiveKid != "gatekeeper-key-1" {
			t.Errorf("expected gatekeeper-key-1, got %s", cfg.JWTActiveKid)
		}
		if cfg.AccessTokenTTL != 10*time.Minute {
			t.Errorf("expected 10m, got %v", cfg.AccessTokenTTL)
		}
		if cfg.LoginRateLimitAttempts != 10 {
			t.Errorf("expected 10, got %d", cfg.LoginRateLimitAttempts)
		}
	})

	t.Run("validates custom valid parameters", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "keys/private.pem")
		t.Setenv("HTTP_ADDR", "127.0.0.1:9090")
		t.Setenv("DB_CONNECT_TIMEOUT", "10s")
		t.Setenv("DB_QUERY_TIMEOUT", "2s")
		t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "15s")
		t.Setenv("PASSWORD_HASH_CONCURRENCY", "4")
		t.Setenv("ACCESS_TOKEN_TTL", "15m")
		t.Setenv("JWT_ISSUER", "custom-issuer")
		t.Setenv("JWT_AUDIENCE", "custom-audience")
		t.Setenv("JWT_ACTIVE_KID", "key-custom")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.HTTPAddr != "127.0.0.1:9090" {
			t.Errorf("expected 127.0.0.1:9090, got %s", cfg.HTTPAddr)
		}
		if cfg.AccessTokenTTL != 15*time.Minute {
			t.Errorf("expected 15m, got %v", cfg.AccessTokenTTL)
		}
		if cfg.JWTIssuer != "custom-issuer" {
			t.Errorf("expected custom-issuer, got %s", cfg.JWTIssuer)
		}
	})

	t.Run("rejects invalid ACCESS_TOKEN_TTL", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "keys/private.pem")

		// Too short (< 1m)
		t.Setenv("ACCESS_TOKEN_TTL", "30s")
		_, err := config.Load()
		if err == nil {
			t.Error("expected error for ACCESS_TOKEN_TTL < 1m")
		}

		// Too long (> 15m)
		t.Setenv("ACCESS_TOKEN_TTL", "20m")
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for ACCESS_TOKEN_TTL > 15m")
		}
	})

	t.Run("loads default SMTP and email verification settings", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "keys/private.pem")
		t.Setenv("SMTP_HOST", "")
		t.Setenv("SMTP_PORT", "")
		t.Setenv("SMTP_FROM", "")
		t.Setenv("SMTP_SEND_TIMEOUT", "")
		t.Setenv("EMAIL_VERIFICATION_TOKEN_TTL", "")
		t.Setenv("EMAIL_VERIFICATION_COOLDOWN", "")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SMTPHost != "localhost" {
			t.Errorf("expected localhost, got %s", cfg.SMTPHost)
		}
		if cfg.SMTPPort != 1025 {
			t.Errorf("expected 1025, got %d", cfg.SMTPPort)
		}
		if cfg.SMTPFrom != "no-reply@gatekeeper.local" {
			t.Errorf("expected no-reply@gatekeeper.local, got %s", cfg.SMTPFrom)
		}
		if cfg.SMTPSendTimeout != 10*time.Second {
			t.Errorf("expected 10s, got %v", cfg.SMTPSendTimeout)
		}
		if cfg.EmailVerificationTokenTTL != 24*time.Hour {
			t.Errorf("expected 24h, got %v", cfg.EmailVerificationTokenTTL)
		}
		if cfg.EmailVerificationCooldown != 60*time.Second {
			t.Errorf("expected 60s, got %v", cfg.EmailVerificationCooldown)
		}
		if cfg.PasswordResetTokenTTL != 30*time.Minute {
			t.Errorf("expected 30m, got %v", cfg.PasswordResetTokenTTL)
		}
		if cfg.PasswordResetCooldown != 60*time.Second {
			t.Errorf("expected 60s, got %v", cfg.PasswordResetCooldown)
		}
		if cfg.PasswordResetQueueDrainTimeout != 45*time.Second {
			t.Errorf("expected 45s, got %v", cfg.PasswordResetQueueDrainTimeout)
		}
	})

	t.Run("rejects invalid SMTP_PORT and TTL durations", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/auth?sslmode=disable")
		t.Setenv("JWT_PRIVATE_KEY_FILE", "keys/private.pem")

		t.Setenv("SMTP_PORT", "99999")
		_, err := config.Load()
		if err == nil {
			t.Error("expected error for SMTP_PORT > 65535")
		}

		t.Setenv("SMTP_PORT", "1025")
		t.Setenv("EMAIL_VERIFICATION_TOKEN_TTL", "30m") // < 1h
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for EMAIL_VERIFICATION_TOKEN_TTL < 1h")
		}

		t.Setenv("EMAIL_VERIFICATION_TOKEN_TTL", "24h")
		t.Setenv("EMAIL_VERIFICATION_COOLDOWN", "5s") // < 10s
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for EMAIL_VERIFICATION_COOLDOWN < 10s")
		}

		t.Setenv("EMAIL_VERIFICATION_COOLDOWN", "60s")
		t.Setenv("PASSWORD_RESET_TOKEN_TTL", "1m") // < 5m
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for PASSWORD_RESET_TOKEN_TTL < 5m")
		}

		t.Setenv("PASSWORD_RESET_TOKEN_TTL", "30m")
		t.Setenv("PASSWORD_RESET_COOLDOWN", "2s") // < 10s
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for PASSWORD_RESET_COOLDOWN < 10s")
		}

		t.Setenv("PASSWORD_RESET_COOLDOWN", "60s")
		t.Setenv("PASSWORD_RESET_QUEUE_DRAIN_TIMEOUT", "1s") // < 5s
		_, err = config.Load()
		if err == nil {
			t.Error("expected error for PASSWORD_RESET_QUEUE_DRAIN_TIMEOUT < 5s")
		}
	})
}
