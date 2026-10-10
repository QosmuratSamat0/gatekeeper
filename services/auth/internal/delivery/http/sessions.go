package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// SessionItemResponse represents a sanitized session item in the listing response.
type SessionItemResponse struct {
	ID        string `json:"id" example:"c1f7a0b2-3c4d-4e5f-a6b7-c8d9e0f1a2b3"`
	CreatedAt string `json:"created_at" example:"2026-10-07T12:00:00Z"`
	ExpiresAt string `json:"expires_at" example:"2026-10-08T12:00:00Z"`
	Current   bool   `json:"current" example:"true"`
}

// ListSessionsResponse represents the paginated session listing response.
type ListSessionsResponse struct {
	Sessions   []SessionItemResponse `json:"sessions"`
	NextCursor *string               `json:"next_cursor" extensions:"x-nullable"`
}

// requireEmptyBody reads the request body up to maxRequestBodyBytes (4096 bytes) and verifies it is empty.
// If the body exceeds the limit, it emits 413 payload_too_large. If any data is present, it emits 400 invalid_request.
func (h *Handler) requireEmptyBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must not exceed 4 KiB")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Failed to read request body")
		return false
	}
	if len(bodyBytes) > 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be empty")
		return false
	}
	return true
}

// ListSessions handles GET /v1/auth/sessions.
//
// @Summary List active sessions
// @Description Retrieves active sessions for the authenticated account with keyset pagination.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Maximum number of sessions to return (1..100)" default(20)
// @Param cursor query string false "Opaque keyset pagination cursor"
// @Success 200 {object} ListSessionsResponse "Active sessions list"
// @Failure 400 {object} errorResponse "Invalid query parameters, malformed cursor, or non-empty body"
// @Failure 401 {object} errorResponse "Unauthorized or session revoked/expired"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/sessions [get]
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if !h.requireEmptyBody(w, r) {
		return
	}

	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	var queryParams url.Values
	if r.URL.RawQuery != "" {
		parsed, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid query parameter syntax")
			return
		}
		queryParams = parsed
	}

	for key := range queryParams {
		if key != "limit" && key != "cursor" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Unknown query parameter")
			return
		}
	}

	limit := 20
	if limitVals, ok := queryParams["limit"]; ok {
		if len(limitVals) > 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Repeated query parameters are not allowed")
			return
		}
		if limitVals[0] == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "limit must not be empty")
			return
		}
		parsedLimit, err := strconv.Atoi(limitVals[0])
		if err != nil || parsedLimit < 1 || parsedLimit > 100 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "limit must be an integer between 1 and 100")
			return
		}
		limit = parsedLimit
	}

	var cursor *usecase.SessionCursor
	if cursorVals, ok := queryParams["cursor"]; ok {
		if len(cursorVals) > 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Repeated query parameters are not allowed")
			return
		}
		if cursorVals[0] == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "cursor must not be empty")
			return
		}
		decodedCursor, err := decodeSessionCursor(cursorVals[0])
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Malformed pagination cursor")
			return
		}
		cursor = decodedCursor
	}

	filter := usecase.SessionListFilter{
		Limit:  limit,
		Cursor: cursor,
	}

	page, err := h.listSessionsUC.Execute(r.Context(), identity.AccountID, identity.SessionID, filter)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrCallerSessionNotFound),
			errors.Is(err, domain.ErrSessionRevoked),
			errors.Is(err, domain.ErrSessionExpired),
			errors.Is(err, domain.ErrInvalidCredentials):
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return
		case errors.Is(err, domain.ErrDatabaseUnavailable),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(r.Context().Err(), context.DeadlineExceeded):
			h.logSafeError("database_unavailable", r)
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Database is temporarily unavailable")
		default:
			h.logSafeError("system_internal_failure", r)
			writeError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	var nextCursorStr *string
	if page.NextCursor != nil {
		encoded := encodeSessionCursor(*page.NextCursor)
		nextCursorStr = &encoded
	}

	respItems := make([]SessionItemResponse, 0, len(page.Sessions))
	for _, sess := range page.Sessions {
		respItems = append(respItems, SessionItemResponse{
			ID:        sess.ID,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
			Current:   sess.IsCurrent,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ListSessionsResponse{
		Sessions:   respItems,
		NextCursor: nextCursorStr,
	})
}

// RevokeSession handles DELETE /v1/auth/sessions/{session_id}.
//
// @Summary Revoke a session
// @Description Terminates an active or expired session owned by the authenticated account.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Param session_id path string true "Session UUID to revoke"
// @Success 204 "Session successfully revoked"
// @Failure 400 {object} errorResponse "Invalid UUID format or non-empty body"
// @Failure 401 {object} errorResponse "Unauthorized or caller session revoked/expired"
// @Failure 404 {object} errorResponse "Session not found or belongs to another account"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/sessions/{session_id} [delete]
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	if !h.requireEmptyBody(w, r) {
		return
	}

	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	targetSessionID := chi.URLParam(r, "session_id")
	if !isValidUUID(targetSessionID) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid session ID format")
		return
	}
	targetSessionID = strings.ToLower(targetSessionID)

	err := h.revokeSessionUC.Execute(r.Context(), identity.AccountID, identity.SessionID, targetSessionID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrCallerSessionNotFound),
			errors.Is(err, domain.ErrSessionRevoked),
			errors.Is(err, domain.ErrSessionExpired),
			errors.Is(err, domain.ErrInvalidCredentials):
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		case errors.Is(err, domain.ErrSessionNotFound):
			writeError(w, r, http.StatusNotFound, "session_not_found", "Session not found")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return
		case errors.Is(err, domain.ErrDatabaseUnavailable),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(r.Context().Err(), context.DeadlineExceeded):
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

// LogoutAll handles POST /v1/auth/logout-all.
//
// @Summary Logout all sessions
// @Description Terminates all active sessions owned by the authenticated account, including the caller's session.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 204 "All sessions successfully revoked"
// @Failure 400 {object} errorResponse "Non-empty body"
// @Failure 401 {object} errorResponse "Unauthorized or caller session revoked/expired"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/logout-all [post]
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	if !h.requireEmptyBody(w, r) {
		return
	}

	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	err := h.logoutAllUC.Execute(r.Context(), identity.AccountID, identity.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrCallerSessionNotFound),
			errors.Is(err, domain.ErrSessionRevoked),
			errors.Is(err, domain.ErrSessionExpired),
			errors.Is(err, domain.ErrInvalidCredentials):
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return
		case errors.Is(err, domain.ErrDatabaseUnavailable),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(r.Context().Err(), context.DeadlineExceeded):
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
