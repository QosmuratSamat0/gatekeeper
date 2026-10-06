package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockRegistrationService struct {
	executeFn func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error)
}

func (m *mockRegistrationService) Execute(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
	return m.executeFn(ctx, input)
}

func newTestRouter(regSvc delivery.RegistrationService) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, nil, regSvc, nil, nil, nil, nil, nil, nil)
	return handler.Routes()
}

func TestRegisterHandler_Success(t *testing.T) {
	fixedTime := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			return domain.Account{
				ID:            "a0000000-0000-4000-8000-000000000001",
				Email:         "person@example.com",
				Status:        domain.AccountStatusActive,
				EmailVerified: false,
				CreatedAt:     fixedTime,
				UpdatedAt:     fixedTime,
			}, nil
		},
	}

	router := newTestRouter(mockSvc)

	body := `{"email":"person@example.com","password":"a-long-example-password"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	// Verify support for content-type parameters like charset=utf-8
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d, body: %s", w.Code, w.Body.String())
	}

	// Verify no Location header per AUTH-01 spec
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location header should not be present, got %q", loc)
	}

	var resp struct {
		Account struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			Status        string `json:"status"`
			EmailVerified bool   `json:"email_verified"`
			CreatedAt     string `json:"created_at"`
		} `json:"account"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Account.ID != "a0000000-0000-4000-8000-000000000001" {
		t.Errorf("expected id a0000000-0000-4000-8000-000000000001, got %s", resp.Account.ID)
	}
	if resp.Account.Email != "person@example.com" {
		t.Errorf("expected email person@example.com, got %s", resp.Account.Email)
	}
	if resp.Account.Status != "active" {
		t.Errorf("expected status active, got %s", resp.Account.Status)
	}
	if resp.Account.EmailVerified != false {
		t.Errorf("expected email_verified false, got %v", resp.Account.EmailVerified)
	}
	if resp.Account.CreatedAt != "2026-10-04T12:00:00Z" {
		t.Errorf("expected created_at '2026-10-04T12:00:00Z', got %s", resp.Account.CreatedAt)
	}

	// Ensure no password or hash leaked
	bodyStr := w.Body.String()
	if strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "hash") {
		t.Errorf("response contains leaked sensitive field: %s", bodyStr)
	}
}

func TestRegisterHandler_UnsupportedMediaType(t *testing.T) {
	router := newTestRouter(&mockRegistrationService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status 415, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unsupported_media_type") {
		t.Errorf("expected error code unsupported_media_type, got: %s", w.Body.String())
	}
}

func TestRegisterHandler_RequestTooLarge(t *testing.T) {
	router := newTestRouter(&mockRegistrationService{})

	// Body exceeding 4096 bytes
	largeBody := `{"email":"test@example.com","password":"` + strings.Repeat("x", 5000) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413, got %d, body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "request_too_large") {
		t.Errorf("expected code request_too_large, got: %s", w.Body.String())
	}
}

func TestRegisterHandler_RequestTooLarge_TrailingWhitespace(t *testing.T) {
	router := newTestRouter(&mockRegistrationService{})

	// Valid JSON followed by spaces pushing total body over 4096 bytes
	validJSONWithTrailingSpaces := `{"email":"test@example.com","password":"valid-password-15chars"}` + strings.Repeat(" ", 4500)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(validJSONWithTrailingSpaces))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413 when trailing whitespace exceeds limit, got %d", w.Code)
	}
}

func TestRegisterHandler_UnknownFieldsRejected(t *testing.T) {
	router := newTestRouter(&mockRegistrationService{})

	body := `{"email":"test@example.com","password":"valid-password-15chars","role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_request") {
		t.Errorf("expected code invalid_request, got: %s", w.Body.String())
	}
}

func TestRegisterHandler_TrailingDataRejected(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"second JSON object", `{"email":"test@example.com","password":"valid-password-15chars"} {"extra":true}`},
		{"trailing numbers", `{"email":"test@example.com","password":"valid-password-15chars"} 12345`},
		{"trailing array", `{"email":"test@example.com","password":"valid-password-15chars"} [1, 2]`},
		{"trailing punctuation", `{"email":"test@example.com","password":"valid-password-15chars"} ;`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			router := newTestRouter(&mockRegistrationService{})
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), "invalid_request") {
				t.Errorf("expected code invalid_request, got: %s", w.Body.String())
			}
		})
	}
}

func TestRegisterHandler_AccountExists(t *testing.T) {
	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			return domain.Account{}, domain.ErrAccountExists
		},
	}

	router := newTestRouter(mockSvc)

	body := `{"email":"existing@example.com","password":"valid-password-15chars"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "account_exists") {
		t.Errorf("expected code account_exists, got: %s", w.Body.String())
	}
}

func TestRegisterHandler_ServiceUnavailableOnDatabaseOutage(t *testing.T) {
	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			return domain.Account{}, domain.ErrDatabaseUnavailable
		},
	}

	router := newTestRouter(mockSvc)

	body := `{"email":"test@example.com","password":"valid-password-15chars"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "service_unavailable") {
		t.Errorf("expected code service_unavailable, got: %s", w.Body.String())
	}
}

func TestRegisterHandler_InternalServerErrorSanitized(t *testing.T) {
	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			return domain.Account{}, errors.New("pq: password authentication failed for user postgres")
		},
	}

	router := newTestRouter(mockSvc)

	body := `{"email":"test@example.com","password":"valid-password-15chars"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
	respStr := w.Body.String()
	if strings.Contains(respStr, "postgres") || strings.Contains(respStr, "authentication failed") {
		t.Errorf("internal database details leaked to client: %s", respStr)
	}
	if !strings.Contains(respStr, "internal_error") {
		t.Errorf("expected code internal_error, got: %s", respStr)
	}
}

func TestRegisterHandler_LogSafety_NoSecretsLeaked(t *testing.T) {
	var logBuf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	secretURLPass := "SuperSecretPassword123"
	secretQueryPass := "QuerySecret456"
	secretKVPass := "KeyValueSecret789"
	secretToken := "MySuperSecretToken12345"
	secretAPIKey := "SensitiveInternalKey67890"

	leakError := errors.New("connection failed: postgres://app_user:" + secretURLPass + "@db.internal:5432/auth?password=" + secretQueryPass + " and DSN password=" + secretKVPass + " token: " + secretToken + " apiKey: " + secretAPIKey)

	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			return domain.Account{}, leakError
		},
	}

	handler := delivery.NewHandler(testLogger, nil, mockSvc, nil, nil, nil, nil, nil, nil)
	router := handler.Routes()

	body := `{"email":"test@example.com","password":"valid-password-15chars"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	logs := logBuf.String()

	// Verify all secrets (known DSN format or arbitrary tokens) are strictly excluded from log output
	if strings.Contains(logs, secretURLPass) {
		t.Errorf("URL password leaked in logs: %s", logs)
	}
	if strings.Contains(logs, secretQueryPass) {
		t.Errorf("Query password leaked in logs: %s", logs)
	}
	if strings.Contains(logs, secretKVPass) {
		t.Errorf("Key-value password leaked in logs: %s", logs)
	}
	if strings.Contains(logs, secretToken) {
		t.Errorf("Arbitrary token leaked in logs: %s", logs)
	}
	if strings.Contains(logs, secretAPIKey) {
		t.Errorf("Arbitrary API key leaked in logs: %s", logs)
	}

	// Verify safe category and request_id are logged
	if !strings.Contains(logs, `"category":"system_internal_failure"`) {
		t.Errorf("expected category system_internal_failure in logs, got: %s", logs)
	}
	if !strings.Contains(logs, `"request_id"`) {
		t.Errorf("expected request_id in logs, got: %s", logs)
	}
}

func TestRegisterHandler_PasswordLengthBoundary(t *testing.T) {
	mockSvc := &mockRegistrationService{
		executeFn: func(ctx context.Context, input usecase.RegisterInput) (domain.Account, error) {
			if len(input.Password) < 8 {
				return domain.Account{}, domain.ErrInvalidPassword
			}
			return domain.Account{
				ID:            "a0000000-0000-4000-8000-000000000001",
				Email:         input.Email,
				Status:        domain.AccountStatusActive,
				EmailVerified: false,
				CreatedAt:     time.Now().UTC(),
			}, nil
		},
	}

	router := newTestRouter(mockSvc)

	// 1. Password with 7 characters must be rejected with 400 Bad Request
	body7 := `{"email":"user7@example.com","password":"1234567"}`
	req7 := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body7))
	req7.Header.Set("Content-Type", "application/json")
	w7 := httptest.NewRecorder()
	router.ServeHTTP(w7, req7)

	if w7.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for 7-character password, got %d", w7.Code)
	}
	if !strings.Contains(w7.Body.String(), "invalid_request") {
		t.Errorf("expected invalid_request error code for 7-character password, got: %s", w7.Body.String())
	}

	// 2. Password with 8 characters must be accepted with 201 Created
	body8 := `{"email":"user8@example.com","password":"12345678"}`
	req8 := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body8))
	req8.Header.Set("Content-Type", "application/json")
	w8 := httptest.NewRecorder()
	router.ServeHTTP(w8, req8)

	if w8.Code != http.StatusCreated {
		t.Errorf("expected status 201 for 8-character password, got %d, body: %s", w8.Code, w8.Body.String())
	}
}

func TestRouter_SwaggerUIEndpoints(t *testing.T) {
	router := newTestRouter(&mockRegistrationService{})

	// 1. GET /swagger redirects to /swagger/index.html
	reqRedirect := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	wRedirect := httptest.NewRecorder()
	router.ServeHTTP(wRedirect, reqRedirect)

	if wRedirect.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301 Moved Permanently for /swagger, got %d", wRedirect.Code)
	}
	if loc := wRedirect.Header().Get("Location"); loc != "/swagger/index.html" {
		t.Errorf("expected Location /swagger/index.html, got %s", loc)
	}

	// 2. GET /swagger/doc.json returns 200 OK with Swagger 2.0 JSON specification
	reqDoc := httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	wDoc := httptest.NewRecorder()
	router.ServeHTTP(wDoc, reqDoc)

	if wDoc.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /swagger/doc.json, got %d", wDoc.Code)
	}
	bodyDoc := wDoc.Body.String()
	if !strings.Contains(bodyDoc, `"swagger": "2.0"`) && !strings.Contains(bodyDoc, `"swagger":"2.0"`) {
		t.Errorf("expected swagger: 2.0 in doc.json, got: %s", bodyDoc)
	}
	if !strings.Contains(bodyDoc, "Gatekeeper Auth Service API") {
		t.Errorf("expected API title in doc.json, got: %s", bodyDoc)
	}

	// 3. GET /swagger/index.html returns 200 OK with ready-made Swagger UI HTML
	reqUI := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
	wUI := httptest.NewRecorder()
	router.ServeHTTP(wUI, reqUI)

	if wUI.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /swagger/index.html, got %d", wUI.Code)
	}
	bodyUI := wUI.Body.String()
	if !strings.Contains(bodyUI, "swagger-ui") {
		t.Errorf("expected swagger-ui container in index.html, got: %s", bodyUI)
	}
}
