package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

const maxRequestBodyBytes = 4096 // 4 KiB

type registerRequest struct {
	Email    string `json:"email" binding:"required" format:"email" maxLength:"254" example:"user@example.com"`
	Password string `json:"password" binding:"required" minLength:"8" maxLength:"128" example:"securePassword123!"`
}

type accountResponse struct {
	ID            string `json:"id" binding:"required" format:"uuid" example:"550e8400-e29b-41d4-a716-446655440000"`
	Email         string `json:"email" binding:"required" format:"email" example:"user@example.com"`
	Status        string `json:"status" binding:"required" example:"active"`
	EmailVerified bool   `json:"email_verified" binding:"required" example:"false"`
	CreatedAt     string `json:"created_at" binding:"required" format:"date-time" example:"2026-10-04T00:00:00Z"`
}

type registerResponse struct {
	Account accountResponse `json:"account" binding:"required"`
}

// Register handles new account creation.
// It strictly validates content-type, restricts request body to 4 KiB,
// rejects unknown or trailing JSON data, and converts domain outcomes
// to stable public HTTP status codes.
// @Summary Register a new account
// @Description Creates a new registered account with an Argon2id password hash. Body is limited to 4 KiB and unknown fields are rejected.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body registerRequest true "Registration credentials (email and password)"
// @Success 201 {object} registerResponse "Account created successfully"
// @Failure 400 {object} errorResponse "Invalid JSON body, email format, or password length"
// @Failure 409 {object} errorResponse "Account with this canonical email already exists"
// @Failure 413 {object} errorResponse "Request body exceeds limit"
// @Failure 415 {object} errorResponse "Content-Type must be application/json"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Service temporarily unavailable, please retry"
// @Router /v1/auth/register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	// 1. Content-Type must be application/json (allowing charset parameters such as charset=utf-8).
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// 2. Limit request body size to 4 KiB to prevent memory exhaustion attacks.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	// 3. Decode JSON with DisallowUnknownFields to reject unauthorized caller fields (e.g. role, status, id).
	var req registerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds limit")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Verify that no trailing characters, second JSON object or extra tokens exist after the body.
	// A second Decode must return io.EOF.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds limit")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Unexpected trailing data after JSON body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Email and password are required")
		return
	}

	// 4. Delegate to registration usecase
	account, err := h.registerUC.Execute(r.Context(), usecase.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidEmail), errors.Is(err, domain.ErrInvalidPassword):
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid email or password")

		case errors.Is(err, domain.ErrAccountExists):
			writeError(w, r, http.StatusConflict, "account_exists", "Account already exists")

		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			// Client aborted request; no need to send HTTP body to closed socket.
			return

		case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		default:
			// For unexpected internal errors (e.g. database driver or infrastructure failures),
			// log only the safe category and request ID.
			// Never pass error strings or error messages into logs here, as arbitrary error text
			// may contain unscrubbed secrets (such as API keys, tokens, or plaintext credentials).
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "registration internal error",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "system_internal_failure"),
				)
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		}
		return
	}

	// 5. Respond with 201 Created and safe DTO
	resp := registerResponse{
		Account: accountResponse{
			ID:            account.ID,
			Email:         account.Email,
			Status:        string(account.Status),
			EmailVerified: account.EmailVerified,
			CreatedAt:     account.CreatedAt.UTC().Format(time.RFC3339),
		},
	}

	writeJSON(w, http.StatusCreated, resp)
}
