package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// meResponseEnvelope defines the response structure for /v1/auth/me per AUTH-02.
type meResponseEnvelope struct {
	Account accountResponse `json:"account"`
}

// Me handles profile retrieval for authenticated users.
//
// @Summary Get current user profile
// @Description Retrieves the authenticated account information using verified token claims and persisted active session state.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} meResponseEnvelope "Account profile details"
// @Failure 401 {object} errorResponse "Unauthorized or session revoked/expired"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/me [get]
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	acc, err := h.currentAccountUC.Execute(r.Context(), identity.AccountID, identity.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSessionNotFound),
			errors.Is(err, domain.ErrSessionRevoked),
			errors.Is(err, domain.ErrSessionExpired),
			errors.Is(err, domain.ErrInvalidCredentials):
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return
		case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
			h.logSafeError("database_unavailable", r)
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Database is temporarily unavailable")
		default:
			h.logSafeError("system_internal_failure", r)
			writeError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := accountResponse{
		ID:            acc.ID,
		Email:         acc.Email,
		Status:        string(acc.Status),
		EmailVerified: acc.EmailVerified,
		CreatedAt:     acc.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	_ = json.NewEncoder(w).Encode(meResponseEnvelope{
		Account: resp,
	})
}
