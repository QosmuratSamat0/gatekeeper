package http

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/QosmuratSamat0/gatekeeper/services/auth/api"
	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// RegistrationService defines the registration usecase contract.
type RegistrationService interface {
	Execute(ctx context.Context, input usecase.RegisterInput) (domain.Account, error)
}

// LoginService defines the login usecase contract.
type LoginService interface {
	Execute(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error)
}

// CurrentAccountService defines the profile retrieval usecase contract.
type CurrentAccountService interface {
	Execute(ctx context.Context, accountID, sessionID string) (domain.Account, error)
}

// LogoutService defines the session revocation usecase contract.
type LogoutService interface {
	Execute(ctx context.Context, accountID, sessionID string) error
}

// Handler holds HTTP dependencies and endpoints.
type Handler struct {
	logger           *slog.Logger
	readiness        ReadinessChecker
	registerUC       RegistrationService
	loginUC          LoginService
	currentAccountUC CurrentAccountService
	logoutUC         LogoutService
	tokenVerifier    authmiddleware.TokenVerifier
	jwksProvider     JWKSProvider
	rateLimiter      *authmiddleware.IPRateLimiter
}

// NewHandler creates a new Handler instance with all injected usecases and platform adapters.
func NewHandler(
	logger *slog.Logger,
	readiness ReadinessChecker,
	registerUC RegistrationService,
	loginUC LoginService,
	currentAccountUC CurrentAccountService,
	logoutUC LogoutService,
	tokenVerifier authmiddleware.TokenVerifier,
	jwksProvider JWKSProvider,
	rateLimiter *authmiddleware.IPRateLimiter,
) *Handler {
	return &Handler{
		logger:           logger,
		readiness:        readiness,
		registerUC:       registerUC,
		loginUC:          loginUC,
		currentAccountUC: currentAccountUC,
		logoutUC:         logoutUC,
		tokenVerifier:    tokenVerifier,
		jwksProvider:     jwksProvider,
		rateLimiter:      rateLimiter,
	}
}

// Routes constructs the HTTP router and registers public and probe routes.
func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()

	// Apply standard request tracing and recovery middleware.
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.Recoverer)

	// Apply custom structured logging middleware.
	if h.logger != nil {
		r.Use(authmiddleware.Logging(h.logger))
	}

	// Infrastructure probes
	r.Get("/healthz", h.Healthz)
	r.Get("/readyz", h.Readyz)

	// Interactive Swagger UI documentation.
	// Serves assets from the ready-made http-swagger library without custom HTML templates.
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
	})
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Public key set (JWKS)
	if h.jwksProvider != nil {
		r.Get("/.well-known/jwks.json", h.JWKS)
	}

	// Public registration endpoint
	if h.registerUC != nil {
		r.Post("/v1/auth/register", h.Register)
	}

	// Public login endpoint with per-IP rate limiting applied before password verification
	if h.loginUC != nil {
		if h.rateLimiter != nil {
			r.With(authmiddleware.RateLimitLoginMiddleware(h.rateLimiter)).Post("/v1/auth/login", h.Login)
		} else {
			r.Post("/v1/auth/login", h.Login)
		}
	}

	// Protected endpoints (require verified Bearer token)
	if h.tokenVerifier != nil {
		r.Group(func(protected chi.Router) {
			protected.Use(authmiddleware.BearerAuth(h.tokenVerifier))

			if h.currentAccountUC != nil {
				protected.Get("/v1/auth/me", h.Me)
			}

			if h.logoutUC != nil {
				protected.Post("/v1/auth/logout", h.Logout)
			}
		})
	}

	return r
}
