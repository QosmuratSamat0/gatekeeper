package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type passwordResetRequestBody struct {
	Email string `json:"email" binding:"required" format:"email" maxLength:"254" example:"user@example.com"`
}

type passwordResetResponse struct {
	Status string `json:"status" example:"accepted"`
}

type passwordResetConfirmBody struct {
	Token       string `json:"token" binding:"required" example:"_y8k5G3m7Q9zP4rT1wX6sV2bN8cM0kL5jH3dF6gJ9p"`
	NewPassword string `json:"new_password" binding:"required" minLength:"8" maxLength:"128" example:"newSecurePassword123!"`
}

// RequestPasswordReset initiates password recovery by emailing a one-time reset token.
// Always returns generic 202 Accepted for all syntactically valid emails to prevent account enumeration.
// @Summary Request password reset
// @Description Accepts an email and asynchronously dispatches a one-time password reset link if the account exists, is active, and verified.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body passwordResetRequestBody true "Email for password recovery"
// @Success 202 {object} passwordResetResponse "Reset request accepted"
// @Failure 400 {object} errorResponse "Invalid JSON body or invalid email format"
// @Failure 413 {object} errorResponse "Request body exceeds limit"
// @Failure 415 {object} errorResponse "Content-Type must be application/json"
// @Failure 429 {object} errorResponse "Too many password reset requests"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Service temporarily unavailable, please retry"
// @Router /v1/auth/password-reset/request [post]
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// 1. Content-Type must be application/json
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// 2. Limit request body size to 4 KiB
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	// 3. Decode JSON with DisallowUnknownFields
	var req passwordResetRequestBody
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

	if req.Email == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Email is required")
		return
	}

	// 4. Delegate to use case
	err = h.requestResetUC.Execute(r.Context(), usecase.RequestPasswordResetInput{
		Email: req.Email,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidEmail):
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid email format")

		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return

		case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		default:
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "password reset request internal error",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "system_internal_failure"),
				)
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		}
		return
	}

	// 5. Generic 202 Accepted
	writeJSON(w, http.StatusAccepted, passwordResetResponse{
		Status: "accepted",
	})
}

// ConfirmPasswordReset completes password recovery by setting a new password using a valid reset token.
// All invalid, expired, consumed, or unknown tokens return an identical generic 400 error.
// @Summary Confirm password reset
// @Description Verifies a one-time password reset token, updates the Argon2id password hash, and revokes all active sessions for the account.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body passwordResetConfirmBody true "Reset token and new password"
// @Success 204 "Password updated and all sessions revoked successfully"
// @Failure 400 {object} errorResponse "Invalid token or password policy violation"
// @Failure 413 {object} errorResponse "Request body exceeds limit"
// @Failure 415 {object} errorResponse "Content-Type must be application/json"
// @Failure 429 {object} errorResponse "Too many password reset attempts"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Service temporarily unavailable, please retry"
// @Router /v1/auth/password-reset/confirm [post]
func (h *Handler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// 1. Content-Type must be application/json
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// 2. Limit request body size to 4 KiB
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	// 3. Decode JSON with DisallowUnknownFields
	var req passwordResetConfirmBody
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

	if req.Token == "" || req.NewPassword == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Token and new_password are required")
		return
	}

	// 4. Delegate to use case
	err = h.confirmResetUC.Execute(r.Context(), usecase.ConfirmPasswordResetInput{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidPassword):
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Invalid password format or length")

		case errors.Is(err, domain.ErrInvalidPasswordResetToken):
			writeError(w, r, http.StatusBadRequest, "invalid_password_reset_token", "Invalid, expired, or consumed password reset token")

		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return

		case errors.Is(err, domain.ErrDatabaseUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		default:
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "password reset confirmation internal error",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "system_internal_failure"),
				)
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		}
		return
	}

	// 5. Success 204 No Content
	w.WriteHeader(http.StatusNoContent)
}
