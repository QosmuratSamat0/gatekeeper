package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

type mockEmailVerificationReqService struct {
	requestFn func(ctx context.Context, accountID string) error
}

func (m *mockEmailVerificationReqService) RequestVerification(ctx context.Context, accountID string) error {
	if m.requestFn != nil {
		return m.requestFn(ctx, accountID)
	}
	return nil
}

type mockEmailVerificationConfService struct {
	confirmFn func(ctx context.Context, rawToken string) error
}

func (m *mockEmailVerificationConfService) ConfirmVerification(ctx context.Context, rawToken string) error {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, rawToken)
	}
	return nil
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func setupEmailVerificationTestRouter(
	reqUC delivery.EmailVerificationRequestService,
	confUC delivery.EmailVerificationConfirmService,
	verifier authmiddleware.TokenVerifier,
	limiter *authmiddleware.IPRateLimiter,
) http.Handler {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := delivery.NewHandler(
		logger,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		verifier,
		nil,
		nil,
		nil,
		nil,
	).WithEmailVerification(
		reqUC,
		confUC,
		limiter,
	)
	return handler.Routes()
}

func parseErrorEnvelope(t *testing.T, body []byte) errorEnvelope {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("failed to parse error envelope from %s: %v", string(body), err)
	}
	return env
}

func TestEmailVerificationHandler_Request(t *testing.T) {
	mockVerifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			return authmiddleware.AuthIdentity{
				AccountID: "11111111-2222-3333-4444-555555555555",
				SessionID: "66666666-7777-8888-9999-000000000000",
			}, nil
		},
	}

	t.Run("success returns 202 accepted and generic status body", func(t *testing.T) {
		var receivedAccountID string
		mockReq := &mockEmailVerificationReqService{
			requestFn: func(ctx context.Context, accountID string) error {
				receivedAccountID = accountID
				return nil
			},
		}

		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", rec.Code)
		}
		if receivedAccountID != "11111111-2222-3333-4444-555555555555" {
			t.Errorf("expected account ID from claims, got %s", receivedAccountID)
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp["status"] != "accepted" {
			t.Errorf("expected status 'accepted', got %s", resp["status"])
		}
	})

	t.Run("non-empty body rejected with 400 invalid_request", func(t *testing.T) {
		mockReq := &mockEmailVerificationReqService{}
		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", strings.NewReader(`{"extra":"field"}`))
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "invalid_request" {
			t.Errorf("expected code invalid_request, got %s", env.Error.Code)
		}
		if env.Error.RequestID == "" {
			t.Errorf("expected non-empty request_id")
		}
	})

	t.Run("missing bearer token returns 401 unauthorized", func(t *testing.T) {
		mockReq := &mockEmailVerificationReqService{}
		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "unauthorized" {
			t.Errorf("expected code unauthorized, got %s", env.Error.Code)
		}
	})

	t.Run("delivery failure returns 503 service_unavailable", func(t *testing.T) {
		mockReq := &mockEmailVerificationReqService{
			requestFn: func(ctx context.Context, accountID string) error {
				return domain.ErrVerificationEmailFailed
			},
		}
		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "service_unavailable" {
			t.Errorf("expected code service_unavailable, got %s", env.Error.Code)
		}
	})

	t.Run("client cancellation during delivery writes no body and does not return 503", func(t *testing.T) {
		mockReq := &mockEmailVerificationReqService{
			requestFn: func(ctx context.Context, accountID string) error {
				// Simulate delivery error wrapping context.Canceled
				return fmt.Errorf("%w: %w", domain.ErrVerificationEmailFailed, context.Canceled)
			},
		}
		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Client aborted request

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Body.Len() > 0 {
			t.Fatalf("expected no body written on client cancellation, got %s", rec.Body.String())
		}
		if rec.Code == http.StatusServiceUnavailable {
			t.Fatalf("expected cancellation not to be treated as 503 Service Unavailable")
		}
	})

	t.Run("usecase context.Canceled directly writes no body", func(t *testing.T) {
		mockReq := &mockEmailVerificationReqService{
			requestFn: func(ctx context.Context, accountID string) error {
				return context.Canceled
			},
		}
		router := setupEmailVerificationTestRouter(mockReq, nil, mockVerifier, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/request", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Body.Len() > 0 {
			t.Fatalf("expected no body written on usecase cancellation, got %s", rec.Body.String())
		}
		if rec.Code == http.StatusServiceUnavailable {
			t.Fatalf("expected cancellation not to be treated as 503 Service Unavailable")
		}
	})
}

func TestEmailVerificationHandler_Confirm(t *testing.T) {
	t.Run("success returns 204 no content", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{
			confirmFn: func(ctx context.Context, rawToken string) error {
				if rawToken != "valid-token-string" {
					t.Errorf("expected valid-token-string, got %s", rawToken)
				}
				return nil
			},
		}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		body := `{"token":"valid-token-string"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid token returns 400 invalid_verification_token", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{
			confirmFn: func(ctx context.Context, rawToken string) error {
				return domain.ErrInvalidVerificationToken
			},
		}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		body := `{"token":"invalid-token-string"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "invalid_verification_token" {
			t.Errorf("expected code invalid_verification_token, got %s", env.Error.Code)
		}
		if env.Error.Message != "Invalid or expired verification token" {
			t.Errorf("expected 'Invalid or expired verification token', got %s", env.Error.Message)
		}
		if env.Error.RequestID == "" {
			t.Errorf("expected non-empty request_id")
		}
	})

	t.Run("missing content-type returns 415", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(`{"token":"abc"}`))
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 Unsupported Media Type, got %d", rec.Code)
		}
	})

	t.Run("unknown JSON field returns 400 invalid_request", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		body := `{"token":"abc","role":"admin"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "invalid_request" {
			t.Errorf("expected code invalid_request, got %s", env.Error.Code)
		}
	})

	t.Run("trailing data returns 400 invalid_request", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		body := `{"token":"abc"} trailing`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("oversized body returns 413 request_too_large", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		largePayload := `{"token":"` + strings.Repeat("x", 5000) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(largePayload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 Request Entity Too Large, got %d", rec.Code)
		}
	})

	t.Run("database failure preserves 503 service_unavailable", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{
			confirmFn: func(ctx context.Context, rawToken string) error {
				return domain.ErrDatabaseUnavailable
			},
		}
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, nil)

		body := `{"token":"valid-token-string"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d", rec.Code)
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "service_unavailable" {
			t.Errorf("expected code service_unavailable, got %s", env.Error.Code)
		}
	})

	t.Run("rate limit returns 429 rate_limited", func(t *testing.T) {
		mockConf := &mockEmailVerificationConfService{
			confirmFn: func(ctx context.Context, rawToken string) error {
				return nil
			},
		}
		limiter := authmiddleware.NewIPRateLimiter(2, time.Minute, 100)
		router := setupEmailVerificationTestRouter(nil, mockConf, nil, limiter)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", bytes.NewBufferString(`{"token":"abc"}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.0.2.1:12345"
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected 204 on attempt %d, got %d", i+1, rec.Code)
			}
		}

		// 3rd attempt: blocked by rate limiter
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verification/confirm", bytes.NewBufferString(`{"token":"abc"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests, got %d", rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Errorf("expected Retry-After header on 429")
		}
		env := parseErrorEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != "rate_limited" {
			t.Errorf("expected code rate_limited, got %s", env.Error.Code)
		}
	})
}
