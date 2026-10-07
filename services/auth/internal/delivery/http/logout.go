package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// logoutRefreshRequest defines the optional JSON payload for refresh-mode logout.
type logoutRefreshRequest struct {
	RefreshToken *string `json:"refresh_token" example:"u4W78Q9jKl_..."`
}

// Logout revokes the authenticated user session identified by either a Bearer access token or a refresh token.
//
// @Summary Log out current session
// @Description Revokes the active session via either Authorization Bearer header or application/json refresh_token body. Providing both credentials simultaneously returns 400.
// @Tags auth
// @Accept json
// @Param request body logoutRefreshRequest false "Refresh token body (used when logging out without access token)"
// @Success 204 "Session successfully revoked"
// @Failure 400 {object} errorResponse "Ambiguous credentials (both Bearer and body) or malformed JSON"
// @Failure 401 {object} errorResponse "Unauthorized or invalid/expired credentials"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 415 {object} errorResponse "Unsupported media type"
// @Failure 429 {object} errorResponse "Rate limit exceeded"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// 1. Inspect Authorization headers
	authHeaders := r.Header.Values("Authorization")
	if len(authHeaders) > 1 {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Multiple Authorization headers are not allowed")
		return
	}

	// 2. Read optional request body bounded to 4 KiB
	var bodyBytes []byte
	if r.Body != nil {
		var readErr error
		bodyBytes, readErr = io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
		if readErr != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(readErr, &maxBytesErr) {
				writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must not exceed 4 KiB")
				return
			}
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Malformed request body")
			return
		}
	}

	// Strictly verify presence of Authorization header regardless of its content
	// to prevent bypassing mutual exclusivity with an empty or whitespace header.
	hasAuthHeader := len(authHeaders) > 0
	hasBody := len(bodyBytes) > 0

	// 3. Mutual exclusivity: reject combined header and body credentials
	if hasAuthHeader && hasBody {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Ambiguous credentials: provide either Authorization header or refresh_token body, not both")
		return
	}

	// 4. Reject requests with no credentials provided
	if !hasAuthHeader && !hasBody {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	// Mode 2: Refresh mode (JSON body containing refresh_token)
	if hasBody {
		contentType := r.Header.Get("Content-Type")
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		if mediaType != "application/json" {
			writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}

		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()

		var req logoutRefreshRequest
		if err := dec.Decode(&req); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Malformed JSON request body")
			return
		}

		var extra json.RawMessage
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must contain exactly one JSON object")
			return
		}

		if req.RefreshToken == nil || strings.TrimSpace(*req.RefreshToken) == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "refresh_token is required")
			return
		}

		err := h.logoutUC.ExecuteByRefreshToken(r.Context(), *req.RefreshToken)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrInvalidCredentials),
				errors.Is(err, domain.ErrInvalidRefreshToken),
				errors.Is(err, domain.ErrSessionNotFound):
				writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials")
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
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Mode 1: Bearer mode (Authorization: Bearer <access_token>)
	authHeader := authHeaders[0]
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	tokenStr := strings.TrimSpace(parts[1])
	if h.tokenVerifier == nil {
		h.logSafeError("token_verifier_nil", r)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Token verifier unavailable")
		return
	}

	identity, err := h.tokenVerifier.VerifyToken(r.Context(), tokenStr)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}
	if identity.AccountID == "" || identity.SessionID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	err = h.logoutUC.Execute(r.Context(), identity.AccountID, identity.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSessionNotFound), errors.Is(err, domain.ErrInvalidCredentials):
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
	w.WriteHeader(http.StatusNoContent)
}
