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

	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

type confirmEmailVerificationRequest struct {
	Token string `json:"token" binding:"required" example:"dGhpcy1pcy1hLXRlc3QtdmVyaWZpY2F0aW9uLXRva2Vu"`
}

type verificationRequestResponse struct {
	Status string `json:"status" binding:"required" example:"accepted"`
}

// RequestEmailVerification handles POST /v1/auth/email/verification/request.
// It requires an authenticated Bearer token and an empty request body.
// It enforces a database-backed 60-second cooldown and returns a generic 202 Accepted.
//
// @Summary Request email verification
// @Description Issues a single-use verification token and delivers it to the account email. Body must be empty.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 202 {object} verificationRequestResponse "Verification request accepted"
// @Failure 400 {object} errorResponse "Non-empty request body"
// @Failure 401 {object} errorResponse "Unauthorized or session revoked/expired"
// @Failure 413 {object} errorResponse "Request body exceeds limit"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Email delivery or database unavailable"
// @Router /v1/auth/email/verification/request [post]
func (h *Handler) RequestEmailVerification(w http.ResponseWriter, r *http.Request) {
	// Enforce strict empty body policy (4 KiB bound, 400 on unexpected content, 413 if oversized).
	if !h.requireEmptyBody(w, r) {
		return
	}

	// Derive caller identity exclusively from the verified Bearer token session.
	// We never accept an email address or account ID from request parameters.
	identity, ok := authmiddleware.GetAuthIdentity(r.Context())
	if !ok || identity.AccountID == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}

	if h.emailVerificationReqUC == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		return
	}

	err := h.emailVerificationReqUC.RequestVerification(r.Context(), identity.AccountID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrAccountNotFound):
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized")

		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			// Client aborted request; no need to send HTTP body to closed socket.
			return

		case errors.Is(err, domain.ErrVerificationEmailFailed):
			// Log safe category and request ID without exposing email or token.
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "resend verification email delivery failed",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "email_delivery_failure"),
				)
			}
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		case errors.Is(err, domain.ErrDatabaseUnavailable),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(r.Context().Err(), context.DeadlineExceeded):
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		default:
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "resend verification internal error",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "system_internal_failure"),
				)
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		}
		return
	}

	writeJSON(w, http.StatusAccepted, verificationRequestResponse{Status: "accepted"})
}

// ConfirmEmailVerification handles POST /v1/auth/email/verification/confirm.
// It is public, rate-limited per IP, and confirms mailbox ownership using a one-time token.
//
// @Summary Confirm email verification
// @Description Confirms account email with a 43-character base64url token. Rate limited to 10 requests/minute per IP.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body confirmEmailVerificationRequest true "Verification token payload"
// @Success 204 "Email successfully verified"
// @Failure 400 {object} errorResponse "Invalid, expired, or malformed verification token"
// @Failure 413 {object} errorResponse "Request body exceeds limit"
// @Failure 415 {object} errorResponse "Content-Type must be application/json"
// @Failure 429 {object} errorResponse "Rate limit exceeded"
// @Failure 500 {object} errorResponse "Internal server error"
// @Failure 503 {object} errorResponse "Database unavailable"
// @Router /v1/auth/email/verification/confirm [post]
func (h *Handler) ConfirmEmailVerification(w http.ResponseWriter, r *http.Request) {
	// Content-Type must strictly be application/json.
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// Limit request body size to 4 KiB to prevent denial-of-service memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req confirmEmailVerificationRequest
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

	// Verify that no trailing data exists after the JSON body.
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

	if req.Token == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_verification_token", "Invalid or expired verification token")
		return
	}

	if h.emailVerificationConfUC == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		return
	}

	err = h.emailVerificationConfUC.ConfirmVerification(r.Context(), req.Token)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidVerificationToken):
			// For unknown, malformed, expired, already used, superseded or otherwise invalid tokens
			// return the exact same public status code and message. Never disclose if an account exists.
			writeError(w, r, http.StatusBadRequest, "invalid_verification_token", "Invalid or expired verification token")

		case errors.Is(err, context.Canceled), errors.Is(r.Context().Err(), context.Canceled):
			return

		case errors.Is(err, domain.ErrDatabaseUnavailable),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(r.Context().Err(), context.DeadlineExceeded):
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable, please retry")

		default:
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "email confirmation internal error",
					slog.String("request_id", chimiddleware.GetReqID(r.Context())),
					slog.String("category", "system_internal_failure"),
				)
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
