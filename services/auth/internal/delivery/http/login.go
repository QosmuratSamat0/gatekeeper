package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

// loginRequest defines the JSON payload for user authentication.
type loginRequest struct {
	Email    string `json:"email" binding:"required" format:"email" maxLength:"254" example:"user@example.com"`
	Password string `json:"password" binding:"required" minLength:"1" maxLength:"128" example:"ExamplePassword123"`
}

// loginResponse defines the successful authentication response.
type loginResponse struct {
	AccessToken string          `json:"access_token" binding:"required" example:"eyJhbGciOiJFZERTQSI..."`
	TokenType   string          `json:"token_type" binding:"required" example:"Bearer"`
	ExpiresIn   int64           `json:"expires_in" binding:"required" example:"600"`
	Account     accountResponse `json:"account" binding:"required"`
}

// Login handles user authentication and access token issuance.
//
// @Summary Authenticate user and issue access JWT
// @Description Authenticates email and password, creates a persistent session, and returns a signed Ed25519 access JWT.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body loginRequest true "User credentials"
// @Success 200 {object} loginResponse "Authentication successful"
// @Failure 400 {object} errorResponse "Malformed JSON or excessive payload"
// @Failure 401 {object} errorResponse "Invalid email or password"
// @Failure 413 {object} errorResponse "Payload too large (> 4 KiB)"
// @Failure 415 {object} errorResponse "Unsupported media type"
// @Failure 429 {object} errorResponse "Rate limit exceeded (too many login attempts)"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
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

	var req loginRequest
	if err := dec.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must not exceed 4 KiB")
			return
		}
		writeError(w, r, http.StatusBadRequest, "bad_request", "Malformed JSON request body")
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
		writeError(w, r, http.StatusBadRequest, "bad_request", "Request body must contain exactly one JSON object")
		return
	}

	out, err := h.loginUC.Execute(r.Context(), usecase.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials), errors.Is(err, domain.ErrAccountNotFound):
			writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			// Client aborted request; no need to send HTTP body to closed socket.
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

	// Ensure access token is never cached by downstream proxies or browsers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := loginResponse{
		AccessToken: out.AccessToken,
		TokenType:   out.TokenType,
		ExpiresIn:   out.ExpiresIn,
		Account: accountResponse{
			ID:            out.Account.ID,
			Email:         out.Account.Email,
			Status:        string(out.Account.Status),
			EmailVerified: out.Account.EmailVerified,
			CreatedAt:     out.Account.CreatedAt.UTC().Format(time.RFC3339),
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) logSafeError(category string, r *http.Request) {
	if h.logger != nil {
		reqID := chimiddleware.GetReqID(r.Context())
		h.logger.Error("handler error encountered",
			slog.String("category", category),
			slog.String("request_id", reqID),
		)
	}
}
