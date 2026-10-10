package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	deliveryhttp "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockPasswordResetRequestService struct {
	execFn func(ctx context.Context, input usecase.RequestPasswordResetInput) error
}

func (m *mockPasswordResetRequestService) Execute(ctx context.Context, input usecase.RequestPasswordResetInput) error {
	if m.execFn != nil {
		return m.execFn(ctx, input)
	}
	return nil
}

type mockPasswordResetConfirmService struct {
	execFn func(ctx context.Context, input usecase.ConfirmPasswordResetInput) error
}

func (m *mockPasswordResetConfirmService) Execute(ctx context.Context, input usecase.ConfirmPasswordResetInput) error {
	if m.execFn != nil {
		return m.execFn(ctx, input)
	}
	return nil
}

func TestRequestPasswordReset_HTTP(t *testing.T) {
	t.Run("unsupported media type returns 415", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(&mockPasswordResetRequestService{}, nil, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader("email=test@example.com"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", rec.Code)
		}
	})

	t.Run("request body exceeding 4 KiB returns 413", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(&mockPasswordResetRequestService{}, nil, nil, nil)
		r := h.Routes()

		largeBody := `{"email":"` + strings.Repeat("a", 5000) + `@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", rec.Code)
		}
	})

	t.Run("trailing data returns 400", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(&mockPasswordResetRequestService{}, nil, nil, nil)
		r := h.Routes()

		body := `{"email":"test@example.com"} extra`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("empty email returns 400", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(&mockPasswordResetRequestService{}, nil, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(`{"email":""}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("invalid email syntax returns 400", func(t *testing.T) {
		svc := &mockPasswordResetRequestService{
			execFn: func(ctx context.Context, input usecase.RequestPasswordResetInput) error {
				return domain.ErrInvalidEmail
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(svc, nil, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(`{"email":"not-an-email"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("database unavailable returns 503", func(t *testing.T) {
		svc := &mockPasswordResetRequestService{
			execFn: func(ctx context.Context, input usecase.RequestPasswordResetInput) error {
				return domain.ErrDatabaseUnavailable
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(svc, nil, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(`{"email":"user@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
	})

	t.Run("valid email returns 202 with accepted status and no-store header", func(t *testing.T) {
		svc := &mockPasswordResetRequestService{
			execFn: func(ctx context.Context, input usecase.RequestPasswordResetInput) error {
				return nil
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(svc, nil, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/request", strings.NewReader(`{"email":"user@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %s", cc)
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed unmarshaling json response: %v", err)
		}
		if resp["status"] != "accepted" {
			t.Fatalf("expected status accepted, got %s", resp["status"])
		}
	})
}

func TestConfirmPasswordReset_HTTP(t *testing.T) {
	t.Run("missing token or password returns 400", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, &mockPasswordResetConfirmService{}, nil, nil)
		r := h.Routes()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(`{"token":"","new_password":""}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("password policy violation returns 400 invalid_request", func(t *testing.T) {
		svc := &mockPasswordResetConfirmService{
			execFn: func(ctx context.Context, input usecase.ConfirmPasswordResetInput) error {
				return domain.ErrInvalidPassword
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, svc, nil, nil)
		r := h.Routes()

		body := `{"token":"valid-token","new_password":"short"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		if errResp.Error.Code != "invalid_request" {
			t.Fatalf("expected code invalid_request, got %v", errResp.Error.Code)
		}
	})

	t.Run("invalid token returns 400 invalid_password_reset_token", func(t *testing.T) {
		svc := &mockPasswordResetConfirmService{
			execFn: func(ctx context.Context, input usecase.ConfirmPasswordResetInput) error {
				return domain.ErrInvalidPasswordResetToken
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, svc, nil, nil)
		r := h.Routes()

		body := `{"token":"invalid-or-expired-token","new_password":"newSecurePassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
		var invalidErrResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &invalidErrResp)
		if invalidErrResp.Error.Code != "invalid_password_reset_token" {
			t.Fatalf("expected code invalid_password_reset_token, got %v", invalidErrResp.Error.Code)
		}
	})

	t.Run("database unavailable returns 503", func(t *testing.T) {
		svc := &mockPasswordResetConfirmService{
			execFn: func(ctx context.Context, input usecase.ConfirmPasswordResetInput) error {
				return domain.ErrDatabaseUnavailable
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, svc, nil, nil)
		r := h.Routes()

		body := `{"token":"valid-token","new_password":"newSecurePassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
	})

	t.Run("successful confirmation returns 204 with no-store header", func(t *testing.T) {
		svc := &mockPasswordResetConfirmService{
			execFn: func(ctx context.Context, input usecase.ConfirmPasswordResetInput) error {
				return nil
			},
		}
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, svc, nil, nil)
		r := h.Routes()

		body := `{"token":"valid-token","new_password":"newSecurePassword123!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %s", cc)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("expected empty body on 204, got %d bytes", rec.Body.Len())
		}
	})

	t.Run("unknown fields rejected with 400", func(t *testing.T) {
		h := deliveryhttp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).
			WithPasswordRecovery(nil, &mockPasswordResetConfirmService{}, nil, nil)
		r := h.Routes()

		body := `{"token":"valid-token","new_password":"newSecurePassword123!","extra":"field"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-reset/confirm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
}

func unusedBuffers() {
	_ = bytes.NewBuffer(nil)
	_ = errors.New("")
}
