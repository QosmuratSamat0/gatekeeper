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
	ExecuteByRefreshToken(ctx context.Context, rawRefreshToken string) error
}

// RefreshService defines the token rotation usecase contract.
type RefreshService interface {
	Execute(ctx context.Context, input usecase.RefreshInput) (usecase.RefreshOutput, error)
}

// ListSessionsService defines the active sessions listing usecase contract.
type ListSessionsService interface {
	Execute(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error)
}

// RevokeSessionService defines the single session revocation usecase contract.
type RevokeSessionService interface {
	Execute(ctx context.Context, accountID, callerSessionID, targetSessionID string) error
}

// LogoutAllService defines the logout-all revocation usecase contract.
type LogoutAllService interface {
	Execute(ctx context.Context, accountID, callerSessionID string) error
}

// EmailVerificationRequestService defines the email verification request usecase contract.
type EmailVerificationRequestService interface {
	RequestVerification(ctx context.Context, accountID string) error
}

// EmailVerificationConfirmService defines the email verification confirm usecase contract.
type EmailVerificationConfirmService interface {
	ConfirmVerification(ctx context.Context, rawToken string) error
}

// Handler holds HTTP dependencies and endpoints.
type Handler struct {
	logger                  *slog.Logger
	readiness               ReadinessChecker
	registerUC              RegistrationService
	loginUC                 LoginService
	refreshUC               RefreshService
	currentAccountUC        CurrentAccountService
	logoutUC                LogoutService
	tokenVerifier           authmiddleware.TokenVerifier
	jwksProvider            JWKSProvider
	rateLimiter             *authmiddleware.IPRateLimiter
	refreshLimiter          *authmiddleware.IPRateLimiter
	logoutLimiter           *authmiddleware.IPRateLimiter
	listSessionsUC          ListSessionsService
	revokeSessionUC         RevokeSessionService
	logoutAllUC             LogoutAllService
	emailVerificationReqUC  EmailVerificationRequestService
	emailVerificationConfUC EmailVerificationConfirmService
	confirmLimiter          *authmiddleware.IPRateLimiter
}

// NewHandler creates a new Handler instance with all injected usecases and platform adapters.
func NewHandler(
	logger *slog.Logger,
	readiness ReadinessChecker,
	registerUC RegistrationService,
	loginUC LoginService,
	refreshUC RefreshService,
	currentAccountUC CurrentAccountService,
	logoutUC LogoutService,
	tokenVerifier authmiddleware.TokenVerifier,
	jwksProvider JWKSProvider,
	rateLimiter *authmiddleware.IPRateLimiter,
	refreshLimiter *authmiddleware.IPRateLimiter,
	logoutLimiter *authmiddleware.IPRateLimiter,
) *Handler {
	return &Handler{
		logger:           logger,
		readiness:        readiness,
		registerUC:       registerUC,
		loginUC:          loginUC,
		refreshUC:        refreshUC,
		currentAccountUC: currentAccountUC,
		logoutUC:         logoutUC,
		tokenVerifier:    tokenVerifier,
		jwksProvider:     jwksProvider,
		rateLimiter:      rateLimiter,
		refreshLimiter:   refreshLimiter,
		logoutLimiter:    logoutLimiter,
	}
}

// WithSessionManagement configures session management use cases on the Handler.
func (h *Handler) WithSessionManagement(
	listUC ListSessionsService,
	revokeUC RevokeSessionService,
	logoutAllUC LogoutAllService,
) *Handler {
	h.listSessionsUC = listUC
	h.revokeSessionUC = revokeUC
	h.logoutAllUC = logoutAllUC
	return h
}

// WithEmailVerification configures email verification use cases and confirm rate limiter on the Handler.
func (h *Handler) WithEmailVerification(
	requestUC EmailVerificationRequestService,
	confirmUC EmailVerificationConfirmService,
	confirmLimiter *authmiddleware.IPRateLimiter,
) *Handler {
	h.emailVerificationReqUC = requestUC
	h.emailVerificationConfUC = confirmUC
	h.confirmLimiter = confirmLimiter
	return h
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

	// Public refresh endpoint with per-IP rate limiting applied before DB lookup
	if h.refreshUC != nil {
		if h.refreshLimiter != nil {
			r.With(authmiddleware.RateLimitMiddleware(h.refreshLimiter, "Too many refresh attempts. Please try again later.")).Post("/v1/auth/refresh", h.Refresh)
		} else {
			r.Post("/v1/auth/refresh", h.Refresh)
		}
	}

	// Dual-mode logout endpoint (Bearer or refresh_token body) with per-IP rate limiting
	// Placed outside unconditional BearerAuth middleware so refresh-mode logout is supported after access token expiry.
	if h.logoutUC != nil {
		if h.logoutLimiter != nil {
			r.With(authmiddleware.RateLimitMiddleware(h.logoutLimiter, "Too many logout attempts. Please try again later.")).Post("/v1/auth/logout", h.Logout)
		} else {
			r.Post("/v1/auth/logout", h.Logout)
		}
	}

	// Public email verification confirmation endpoint with per-IP rate limiting
	if h.emailVerificationConfUC != nil {
		if h.confirmLimiter != nil {
			r.With(authmiddleware.RateLimitMiddleware(h.confirmLimiter, "Too many verification attempts. Please try again later.")).
				Post("/v1/auth/email/verification/confirm", h.ConfirmEmailVerification)
		} else {
			r.Post("/v1/auth/email/verification/confirm", h.ConfirmEmailVerification)
		}
	}

	// Protected endpoints (require verified Bearer token)
	if h.tokenVerifier != nil {
		r.Group(func(protected chi.Router) {
			// Apply Cache-Control: no-store FIRST so all responses (including 401s from BearerAuth) receive it
			protected.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "no-store")
					next.ServeHTTP(w, r)
				})
			})

			protected.Use(authmiddleware.BearerAuth(h.tokenVerifier))

			if h.currentAccountUC != nil {
				protected.Get("/v1/auth/me", h.Me)
			}
			if h.listSessionsUC != nil {
				protected.Get("/v1/auth/sessions", h.ListSessions)
			}
			if h.revokeSessionUC != nil {
				protected.Delete("/v1/auth/sessions/{session_id}", h.RevokeSession)
			}
			if h.logoutAllUC != nil {
				protected.Post("/v1/auth/logout-all", h.LogoutAll)
			}
			if h.emailVerificationReqUC != nil {
				protected.Post("/v1/auth/email/verification/request", h.RequestEmailVerification)
			}
		})
	}

	return r
}
