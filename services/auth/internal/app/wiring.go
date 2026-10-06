package app

import (
	"context"
	"fmt"
	"log/slog"

	deliveryhttp "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	accountrepo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type tokenAuthAdapter struct {
	tokenSvc *token.TokenService
}

func (a *tokenAuthAdapter) VerifyToken(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
	claims, err := a.tokenSvc.VerifyAccessToken(tokenString)
	if err != nil {
		return authmiddleware.AuthIdentity{}, err
	}
	return authmiddleware.AuthIdentity{
		AccountID: claims.Subject,
		SessionID: claims.SessionID,
	}, nil
}

// Wire constructs the application object graph by assembling configuration,
// database pool, repositories, password hashing/verification, token management, and HTTP delivery.
func Wire(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	// Open the database pool with a connection timeout to avoid hanging startup forever.
	dbPool, err := postgres.NewPool(ctx, cfg.DatabaseURL, cfg.DBConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("wiring database pool: %w", err)
	}

	accountRepo := accountrepo.NewAccountRepository(dbPool, cfg.DBQueryTimeout)
	sessionRepo := accountrepo.NewSessionRepository(dbPool, cfg.DBQueryTimeout)

	hasher := password.NewArgon2idHasher(cfg.PasswordHashConcurrency)

	// Precompute production dummy hash once at startup for timing mitigation on missing accounts.
	// This uses a fixed random password with current production parameters.
	dummyHash, err := hasher.Hash(ctx, "startup-gatekeeper-dummy-password")
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("generating startup dummy password hash: %w", err)
	}

	// Load Ed25519 private key from external PEM file.
	// Report safe category without logging raw path or key content.
	privKey, err := token.LoadPrivateKeyFromFile(cfg.JWTPrivateKeyFile)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("failed to load JWT private key: %w", err)
	}

	// Load optional archived public keys for key rotation
	archivedPubKeys, err := token.LoadArchivedPublicKeysFromFile(cfg.JWTPublicKeysFile)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("failed to load archived public keys: %w", err)
	}

	tokenSvc, err := token.NewTokenService(
		cfg.JWTIssuer,
		cfg.JWTAudience,
		cfg.JWTActiveKid,
		privKey,
		archivedPubKeys,
		cfg.AccessTokenTTL,
		nil,
	)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("initializing token service: %w", err)
	}

	registerUC := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil)
	loginUC, err := usecase.NewLoginUsecase(accountRepo, sessionRepo, hasher, tokenSvc, dummyHash, cfg.AccessTokenTTL, nil, nil)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("initializing login usecase: %w", err)
	}

	currentAccountUC, err := usecase.NewCurrentAccountUsecase(sessionRepo, nil)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("initializing current account usecase: %w", err)
	}

	logoutUC, err := usecase.NewLogoutUsecase(sessionRepo)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("initializing logout usecase: %w", err)
	}

	rateLimiter := authmiddleware.NewIPRateLimiter(cfg.LoginRateLimitAttempts, cfg.LoginRateLimitWindow, 10000)

	authAdapter := &tokenAuthAdapter{tokenSvc: tokenSvc}

	handler := deliveryhttp.NewHandler(
		logger,
		dbPool,
		registerUC,
		loginUC,
		currentAccountUC,
		logoutUC,
		authAdapter,
		tokenSvc,
		rateLimiter,
	)
	router := handler.Routes()

	// Register database pool closure as a cleanup callback.
	application := New(cfg, logger, router, func() {
		logger.Info("closing database connection pool")
		dbPool.Close()
	})

	return application, nil
}
