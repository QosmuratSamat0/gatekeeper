package http

import (
	"context"
	"errors"
	"net/http"

	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// Logout revokes the authenticated user session identified by the token.
//
// @Summary Log out current session
// @Description Revokes the active session associated with the bearer access token. Idempotent: repeating logout with an unexpired token returns 204 if already revoked.
// @Tags auth
// @Security BearerAuth
// @Success 204 "Session successfully revoked"
// @Failure 401 {object} errorResponse "Unauthorized or session does not exist"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	err := h.logoutUC.Execute(r.Context(), identity.AccountID, identity.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSessionNotFound):
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

	w.WriteHeader(http.StatusNoContent)
}
