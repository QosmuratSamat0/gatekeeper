package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// refreshRequest defines the JSON payload for token rotation.
type refreshRequest struct {
	RefreshToken *string `json:"refresh_token" binding:"required" example:"u4W78Q9jKl_..."`
}

// refreshResponse defines the response containing the new access token and rotated refresh token.
type refreshResponse struct {
	AccessToken      string `json:"access_token" binding:"required" example:"eyJhbGciOiJFZERTQSI..."`
	TokenType        string `json:"token_type" binding:"required" example:"Bearer"`
	ExpiresIn        int64  `json:"expires_in" binding:"required" example:"600"`
	RefreshToken     string `json:"refresh_token" binding:"required" example:"x8K23P9mLz_..."`
	RefreshExpiresIn int64  `json:"refresh_expires_in" binding:"required" example:"2592000"`
}

// Refresh handles rotating refresh token requests and issues successor credentials.
//
// @Summary Rotate refresh token and issue new access JWT
// @Description Rotates a valid unconsumed refresh token, invalidates the old token, and issues a new access JWT and successor refresh token. If a previously consumed token is replayed, the session family is immediately revoked.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body refreshRequest true "Refresh token payload"
// @Success 200 {object} refreshResponse "Rotation successful"
// @Failure 400 {object} errorResponse "Malformed JSON or missing refresh_token"
// @Failure 401 {object} errorResponse "Invalid, expired, revoked, or replayed credentials"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 415 {object} errorResponse "Unsupported media type"
// @Failure 429 {object} errorResponse "Rate limit exceeded"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/refresh [post]
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Verify Content-Type is application/json
	contentType := r.Header.Get("Content-Type")
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// Limit request body to 4 KiB
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req refreshRequest
	if err := dec.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must not exceed 4 KiB")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Malformed JSON request body")
		return
	}

	// Ensure EOF after single JSON object
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must not exceed 4 KiB")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must contain exactly one JSON object")
		return
	}

	// Validate refresh_token field presence and non-emptiness
	if req.RefreshToken == nil || strings.TrimSpace(*req.RefreshToken) == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	out, err := h.refreshUC.Execute(r.Context(), usecase.RefreshInput{
		RefreshToken: *req.RefreshToken,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials),
			errors.Is(err, domain.ErrInvalidRefreshToken),
			errors.Is(err, domain.ErrCompromisedSessionReplay),
			errors.Is(err, domain.ErrSessionExpired),
			errors.Is(err, domain.ErrSessionRevoked),
			errors.Is(err, domain.ErrSessionNotFound):
			// Generic 401 error prevents leaking whether a token was unknown, expired, or replayed.
			writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return
		case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
			h.logSafeError("database_unavailable", r)
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")
		default:
			h.logSafeError("system_internal_failure", r)
			writeError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := refreshResponse{
		AccessToken:      out.AccessToken,
		TokenType:        out.TokenType,
		ExpiresIn:        out.ExpiresIn,
		RefreshToken:     out.RefreshToken,
		RefreshExpiresIn: out.RefreshExpiresIn,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
