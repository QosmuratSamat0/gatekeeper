package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// Config holds validated service configuration.
type Config struct {
	HTTPAddr                string
	DatabaseURL             string
	DBConnectTimeout        time.Duration
	DBQueryTimeout          time.Duration
	HTTPShutdownTimeout     time.Duration
	PasswordHashConcurrency int

	// JWT and Key Configuration
	JWTIssuer         string
	JWTAudience       string
	JWTActiveKid      string
	JWTPrivateKeyFile string
	JWTPublicKeysFile string
	AccessTokenTTL    time.Duration

	// Rate Limiting Configuration
	LoginRateLimitAttempts int
	LoginRateLimitWindow   time.Duration

	// Refresh Token and Session Family Configuration
	RefreshSessionTTL time.Duration

	// SMTP and Email Verification Configuration
	SMTPHost                  string
	SMTPPort                  int
	SMTPUsername              string
	SMTPPassword              string
	SMTPFrom                  string
	SMTPCAFile                string
	SMTPSendTimeout           time.Duration
	EmailVerificationTokenTTL time.Duration
	EmailVerificationCooldown time.Duration
}

// Load reads and validates configuration from environment variables.
func Load() (Config, error) {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	} else {
		// Validate host:port format if host is provided or just port :XXXX
		if _, _, err := net.SplitHostPort(addr); err != nil && addr[0] != ':' {
			return Config{}, fmt.Errorf("invalid HTTP_ADDR format: %w", err)
		}
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	connectTimeout := 5 * time.Second
	if val := os.Getenv("DB_CONNECT_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("invalid DB_CONNECT_TIMEOUT: must be a positive duration, got %q", val)
		}
		connectTimeout = d
	}

	queryTimeout := 3 * time.Second
	if val := os.Getenv("DB_QUERY_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("invalid DB_QUERY_TIMEOUT: must be a positive duration, got %q", val)
		}
		queryTimeout = d
	}

	shutdownTimeout := 10 * time.Second
	if val := os.Getenv("HTTP_SHUTDOWN_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("invalid HTTP_SHUTDOWN_TIMEOUT: must be a positive duration, got %q", val)
		}
		shutdownTimeout = d
	}

	hashConcurrency := 2
	if val := os.Getenv("PASSWORD_HASH_CONCURRENCY"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 32 {
			return Config{}, fmt.Errorf("PASSWORD_HASH_CONCURRENCY must be an integer between 1 and 32, got %q", val)
		}
		hashConcurrency = n
	}

	jwtIssuer := os.Getenv("JWT_ISSUER")
	if jwtIssuer == "" {
		jwtIssuer = "gatekeeper-auth"
	}

	jwtAudience := os.Getenv("JWT_AUDIENCE")
	if jwtAudience == "" {
		jwtAudience = "gatekeeper-services"
	}

	jwtActiveKid := os.Getenv("JWT_ACTIVE_KID")
	if jwtActiveKid == "" {
		jwtActiveKid = "gatekeeper-key-1"
	}

	jwtPrivateKeyFile := os.Getenv("JWT_PRIVATE_KEY_FILE")
	if jwtPrivateKeyFile == "" {
		return Config{}, fmt.Errorf("JWT_PRIVATE_KEY_FILE is required")
	}

	jwtPublicKeysFile := os.Getenv("JWT_PUBLIC_KEYS_FILE")

	tokenTTL := 10 * time.Minute
	if val := os.Getenv("ACCESS_TOKEN_TTL"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d < time.Minute || d > 15*time.Minute {
			return Config{}, fmt.Errorf("ACCESS_TOKEN_TTL must be a duration between 1m and 15m, got %q", val)
		}
		tokenTTL = d
	}

	rateLimitAttempts := 10
	if val := os.Getenv("LOGIN_RATE_LIMIT_ATTEMPTS"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 1000 {
			return Config{}, fmt.Errorf("LOGIN_RATE_LIMIT_ATTEMPTS must be an integer between 1 and 1000, got %q", val)
		}
		rateLimitAttempts = n
	}

	rateLimitWindow := time.Minute
	if val := os.Getenv("LOGIN_RATE_LIMIT_WINDOW"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("invalid LOGIN_RATE_LIMIT_WINDOW: %w", err)
		}
		rateLimitWindow = d
	}

	refreshSessionTTL := 720 * time.Hour
	if val := os.Getenv("REFRESH_SESSION_TTL"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d < 24*time.Hour || d > 720*time.Hour {
			return Config{}, fmt.Errorf("REFRESH_SESSION_TTL must be a duration between 24h and 720h, got %q", val)
		}
		refreshSessionTTL = d
	}

	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "localhost"
	}

	smtpPort := 1025
	if val := os.Getenv("SMTP_PORT"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("SMTP_PORT must be an integer between 1 and 65535, got %q", val)
		}
		smtpPort = n
	}

	smtpUsername := os.Getenv("SMTP_USERNAME")
	smtpPassword := os.Getenv("SMTP_PASSWORD")

	smtpFrom := os.Getenv("SMTP_FROM")
	if smtpFrom == "" {
		smtpFrom = "no-reply@gatekeeper.local"
	}

	smtpCAFile := os.Getenv("SMTP_CA_FILE")

	smtpSendTimeout := 10 * time.Second
	if val := os.Getenv("SMTP_SEND_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d < time.Second || d > time.Minute {
			return Config{}, fmt.Errorf("SMTP_SEND_TIMEOUT must be a duration between 1s and 1m, got %q", val)
		}
		smtpSendTimeout = d
	}

	emailVerificationTokenTTL := 24 * time.Hour
	if val := os.Getenv("EMAIL_VERIFICATION_TOKEN_TTL"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d < time.Hour || d > 168*time.Hour {
			return Config{}, fmt.Errorf("EMAIL_VERIFICATION_TOKEN_TTL must be a duration between 1h and 168h, got %q", val)
		}
		emailVerificationTokenTTL = d
	}

	emailVerificationCooldown := 60 * time.Second
	if val := os.Getenv("EMAIL_VERIFICATION_COOLDOWN"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil || d < 10*time.Second || d > 10*time.Minute {
			return Config{}, fmt.Errorf("EMAIL_VERIFICATION_COOLDOWN must be a duration between 10s and 10m, got %q", val)
		}
		emailVerificationCooldown = d
	}

	return Config{
		HTTPAddr:                  addr,
		DatabaseURL:               dbURL,
		DBConnectTimeout:          connectTimeout,
		DBQueryTimeout:            queryTimeout,
		HTTPShutdownTimeout:       shutdownTimeout,
		PasswordHashConcurrency:   hashConcurrency,
		JWTIssuer:                 jwtIssuer,
		JWTAudience:               jwtAudience,
		JWTActiveKid:              jwtActiveKid,
		JWTPrivateKeyFile:         jwtPrivateKeyFile,
		JWTPublicKeysFile:         jwtPublicKeysFile,
		AccessTokenTTL:            tokenTTL,
		LoginRateLimitAttempts:    rateLimitAttempts,
		LoginRateLimitWindow:      rateLimitWindow,
		RefreshSessionTTL:         refreshSessionTTL,
		SMTPHost:                  smtpHost,
		SMTPPort:                  smtpPort,
		SMTPUsername:              smtpUsername,
		SMTPPassword:              smtpPassword,
		SMTPFrom:                  smtpFrom,
		SMTPCAFile:                smtpCAFile,
		SMTPSendTimeout:           smtpSendTimeout,
		EmailVerificationTokenTTL: emailVerificationTokenTTL,
		EmailVerificationCooldown: emailVerificationCooldown,
	}, nil
}
