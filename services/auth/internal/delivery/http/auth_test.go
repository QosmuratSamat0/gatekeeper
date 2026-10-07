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
	"strconv"
	"strings"
	"testing"
	"time"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockLoginService struct {
	executeFn func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error)
}

func (m *mockLoginService) Execute(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
	return m.executeFn(ctx, input)
}

type mockCurrentAccountService struct {
	executeFn func(ctx context.Context, accountID, sessionID string) (domain.Account, error)
}

func (m *mockCurrentAccountService) Execute(ctx context.Context, accountID, sessionID string) (domain.Account, error) {
	return m.executeFn(ctx, accountID, sessionID)
}

type mockLogoutService struct {
	executeFn        func(ctx context.Context, accountID, sessionID string) error
	executeRefreshFn func(ctx context.Context, rawRefreshToken string) error
}

func (m *mockLogoutService) Execute(ctx context.Context, accountID, sessionID string) error {
	if m.executeFn != nil {
		return m.executeFn(ctx, accountID, sessionID)
	}
	return nil
}

func (m *mockLogoutService) ExecuteByRefreshToken(ctx context.Context, rawRefreshToken string) error {
	if m.executeRefreshFn != nil {
		return m.executeRefreshFn(ctx, rawRefreshToken)
	}
	return nil
}

type mockRefreshService struct {
	executeFn func(ctx context.Context, input usecase.RefreshInput) (usecase.RefreshOutput, error)
}

func (m *mockRefreshService) Execute(ctx context.Context, input usecase.RefreshInput) (usecase.RefreshOutput, error) {
	if m.executeFn != nil {
		return m.executeFn(ctx, input)
	}
	return usecase.RefreshOutput{}, nil
}

type mockTokenVerifier struct {
	verifyFn func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error)
}

func (m *mockTokenVerifier) VerifyToken(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
	return m.verifyFn(ctx, tokenString)
}

type mockJWKSProvider struct {
	jsonBytes []byte
	err       error
}

func (m *mockJWKSProvider) JWKSJSON() ([]byte, error) {
	return m.jsonBytes, m.err
}

func setupFullTestRouter(
	loginSvc delivery.LoginService,
	refreshSvc delivery.RefreshService,
	meSvc delivery.CurrentAccountService,
	logoutSvc delivery.LogoutService,
	verifier authmiddleware.TokenVerifier,
	jwks delivery.JWKSProvider,
	limiter *authmiddleware.IPRateLimiter,
) http.Handler {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, nil, nil, loginSvc, refreshSvc, meSvc, logoutSvc, verifier, jwks, limiter, limiter, limiter)
	return handler.Routes()
}

func TestLoginHandler_Success(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{
				AccessToken: "test.jwt.token",
				TokenType:   "Bearer",
				ExpiresIn:   600,
				Account: domain.Account{
					ID:            "11111111-2222-4333-8444-555555555555",
					Email:         input.Email,
					Status:        domain.AccountStatusActive,
					EmailVerified: false,
					CreatedAt:     time.Now().UTC(),
					UpdatedAt:     time.Now().UTC(),
				},
			}, nil
		},
	}

	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, nil)

	body := `{"email":"user@example.com","password":"ValidPassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %s", w.Header().Get("Cache-Control"))
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Account     struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"account"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken != "test.jwt.token" {
		t.Errorf("expected token test.jwt.token, got %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("expected expires_in 600, got %d", resp.ExpiresIn)
	}
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{}, domain.ErrInvalidCredentials
		},
	}

	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, nil)

	body := `{"email":"unknown@example.com","password":"any-password"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d: %s", w.Code, w.Body.String())
	}

	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "invalid_credentials" {
		t.Errorf("expected code invalid_credentials, got %s", errResp.Error.Code)
	}
}

func TestLoginHandler_PayloadTooLarge(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{}, nil
		},
	}
	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, nil)

	// Body exceeding 4 KiB in trailing data
	oversizedBody := `{"email":"user@example.com","password":"ValidPassword123"}` + strings.Repeat(" ", 5000)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginHandler_ContextCancellation(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{}, context.Canceled
		},
	}
	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, nil)

	t.Run("client aborted context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // client aborted request

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"ValidPassword123"}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Body.Len() > 0 {
			t.Errorf("expected no body written on client cancellation, got %s", w.Body.String())
		}
	})

	t.Run("usecase returned context.Canceled directly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"ValidPassword123"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Body.Len() > 0 {
			t.Errorf("expected no body written on usecase cancellation, got %s", w.Body.String())
		}
	})
}

func TestLoginHandler_Timeout(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{}, context.DeadlineExceeded
		},
	}
	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, nil)

	t.Run("usecase returned context.DeadlineExceeded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"ValidPassword123"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable on timeout, got %d: %s", w.Code, w.Body.String())
		}

		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("failed to decode error body: %v", err)
		}
		if errResp.Error.Code != "service_unavailable" {
			t.Errorf("expected error code 'service_unavailable', got %s", errResp.Error.Code)
		}
	})

	t.Run("request context deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"ValidPassword123"}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable on expired context, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestLoginHandler_RateLimiting(t *testing.T) {
	mockLogin := &mockLoginService{
		executeFn: func(ctx context.Context, input usecase.LoginInput) (usecase.LoginOutput, error) {
			return usecase.LoginOutput{}, domain.ErrInvalidCredentials
		},
	}

	limiter := authmiddleware.NewIPRateLimiter(10, time.Minute, 100)
	router := setupFullTestRouter(mockLogin, nil, nil, nil, nil, nil, limiter)

	// Send 10 failed requests from the same RemoteAddr
	for i := 1; i <= 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"email":"u@e.com","password":"p"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.168.1.50:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("request %d expected 401, got %d", i, w.Code)
		}
	}

	// 11th request must receive 429 Too Many Requests
	req11 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"email":"u@e.com","password":"p"}`))
	req11.Header.Set("Content-Type", "application/json")
	req11.RemoteAddr = "192.168.1.50:12345"
	// Attempt to spoof IP via X-Forwarded-For; limiter MUST ignore it
	req11.Header.Set("X-Forwarded-For", "10.0.0.1")
	w11 := httptest.NewRecorder()
	router.ServeHTTP(w11, req11)

	if w11.Code != http.StatusTooManyRequests {
		t.Fatalf("11th request expected 429 Too Many Requests, got %d: %s", w11.Code, w11.Body.String())
	}
	retryAfter := w11.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header on 429 response")
	}
	if sec, err := strconv.Atoi(retryAfter); err != nil || sec < 1 || sec > 60 {
		t.Errorf("invalid Retry-After value: %s", retryAfter)
	}
}

func TestCurrentAccountHandler(t *testing.T) {
	accID := "11111111-2222-4333-8444-555555555555"
	sessID := "22222222-3333-4444-8555-666666666666"

	mockMe := &mockCurrentAccountService{
		executeFn: func(ctx context.Context, aID, sID string) (domain.Account, error) {
			if aID == accID && sID == sessID {
				return domain.Account{
					ID:            accID,
					Email:         "me@example.com",
					Status:        domain.AccountStatusActive,
					EmailVerified: true,
				}, nil
			}
			return domain.Account{}, domain.ErrSessionNotFound
		},
	}

	mockVerifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			if tokenString == "valid-token" {
				return authmiddleware.AuthIdentity{
					AccountID: accID,
					SessionID: sessID,
				}, nil
			}
			return authmiddleware.AuthIdentity{}, errors.New("invalid token")
		},
	}

	router := setupFullTestRouter(nil, nil, mockMe, nil, mockVerifier, nil, nil)

	// 1. Success with Bearer token (case-insensitive) and envelope response
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.Header.Set("Authorization", "bearer valid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %s", w.Header().Get("Cache-Control"))
	}

	var meResp struct {
		Account struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			Status        string `json:"status"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"account"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("failed to parse /me response envelope: %v", err)
	}
	if meResp.Account.ID != accID || meResp.Account.Email != "me@example.com" {
		t.Errorf("unexpected account data in envelope: %+v", meResp.Account)
	}

	// 2. Missing authorization header
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	wNoAuth := httptest.NewRecorder()
	router.ServeHTTP(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth header, got %d", wNoAuth.Code)
	}

	// 3. Ambiguous multiple authorization headers rejected
	reqMultipleAuth := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	reqMultipleAuth.Header.Add("Authorization", "Bearer valid-token")
	reqMultipleAuth.Header.Add("Authorization", "Bearer second-token")
	wMultipleAuth := httptest.NewRecorder()
	router.ServeHTTP(wMultipleAuth, reqMultipleAuth)
	if wMultipleAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for multiple auth headers, got %d", wMultipleAuth.Code)
	}

	// 4. Invalid token
	reqBadToken := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	reqBadToken.Header.Set("Authorization", "Bearer bad-token")
	wBadToken := httptest.NewRecorder()
	router.ServeHTTP(wBadToken, reqBadToken)
	if wBadToken.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad token, got %d", wBadToken.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	accID := "11111111-2222-4333-8444-555555555555"
	sessID := "22222222-3333-4444-8555-666666666666"

	revokedCount := 0
	mockLogout := &mockLogoutService{
		executeFn: func(ctx context.Context, aID, sID string) error {
			if aID == accID && sID == sessID {
				revokedCount++
				return nil // idempotent success
			}
			return domain.ErrSessionNotFound
		},
		executeRefreshFn: func(ctx context.Context, rawRefreshToken string) error {
			if rawRefreshToken == "valid-refresh-token-43-chars-long-test123" {
				return nil
			}
			return domain.ErrInvalidCredentials
		},
	}

	mockVerifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			if tokenString == "valid-token" {
				return authmiddleware.AuthIdentity{AccountID: accID, SessionID: sessID}, nil
			}
			return authmiddleware.AuthIdentity{}, errors.New("invalid token")
		},
	}

	router := setupFullTestRouter(nil, nil, nil, mockLogout, mockVerifier, nil, nil)

	// 1. Bearer logout -> 204
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() > 0 {
		t.Errorf("expected empty body for 204, got %s", w.Body.String())
	}

	// 2. Repeat Bearer logout -> 204 (idempotent)
	reqRepeat := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	reqRepeat.Header.Set("Authorization", "Bearer valid-token")
	wRepeat := httptest.NewRecorder()
	router.ServeHTTP(wRepeat, reqRepeat)

	if wRepeat.Code != http.StatusNoContent {
		t.Fatalf("repeat logout expected 204 No Content, got %d", wRepeat.Code)
	}

	// 3. Refresh-authenticated logout -> 204
	refreshBody := `{"refresh_token":"valid-refresh-token-43-chars-long-test123"}`
	reqRefresh := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString(refreshBody))
	reqRefresh.Header.Set("Content-Type", "application/json")
	wRefresh := httptest.NewRecorder()
	router.ServeHTTP(wRefresh, reqRefresh)

	if wRefresh.Code != http.StatusNoContent {
		t.Fatalf("refresh logout expected 204 No Content, got %d: %s", wRefresh.Code, wRefresh.Body.String())
	}

	// 4. Ambiguous credentials (both Bearer header and refresh body) -> 400 invalid_request
	reqAmbiguous := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString(refreshBody))
	reqAmbiguous.Header.Set("Authorization", "Bearer valid-token")
	reqAmbiguous.Header.Set("Content-Type", "application/json")
	wAmbiguous := httptest.NewRecorder()
	router.ServeHTTP(wAmbiguous, reqAmbiguous)

	if wAmbiguous.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous credentials expected 400 Bad Request, got %d: %s", wAmbiguous.Code, wAmbiguous.Body.String())
	}
	var errRespAmbiguous struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wAmbiguous.Body.Bytes(), &errRespAmbiguous)
	if errRespAmbiguous.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespAmbiguous.Error.Code)
	}

	// 5. Empty Authorization header with refresh body -> must STILL be rejected with 400 invalid_request
	// to prevent bypassing mutual exclusivity using an empty header.
	reqEmptyAuthWithBody := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString(refreshBody))
	reqEmptyAuthWithBody.Header.Set("Authorization", "   ")
	reqEmptyAuthWithBody.Header.Set("Content-Type", "application/json")
	wEmptyAuthWithBody := httptest.NewRecorder()
	router.ServeHTTP(wEmptyAuthWithBody, reqEmptyAuthWithBody)

	if wEmptyAuthWithBody.Code != http.StatusBadRequest {
		t.Fatalf("empty auth header + body expected 400 Bad Request, got %d: %s", wEmptyAuthWithBody.Code, wEmptyAuthWithBody.Body.String())
	}
	var errRespEmptyAuth struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wEmptyAuthWithBody.Body.Bytes(), &errRespEmptyAuth)
	if errRespEmptyAuth.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespEmptyAuth.Error.Code)
	}

	// 6. Multiple Authorization headers -> 400 invalid_request
	reqMultiAuth := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	reqMultiAuth.Header.Add("Authorization", "Bearer token1")
	reqMultiAuth.Header.Add("Authorization", "Bearer token2")
	wMultiAuth := httptest.NewRecorder()
	router.ServeHTTP(wMultiAuth, reqMultiAuth)

	if wMultiAuth.Code != http.StatusBadRequest {
		t.Fatalf("multiple auth headers expected 400 Bad Request, got %d", wMultiAuth.Code)
	}
	var errRespMultiAuth struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wMultiAuth.Body.Bytes(), &errRespMultiAuth)
	if errRespMultiAuth.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespMultiAuth.Error.Code)
	}

	// 7. Malformed JSON body in refresh logout -> 400 invalid_request
	reqMalformed := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString("{broken-json"))
	reqMalformed.Header.Set("Content-Type", "application/json")
	wMalformed := httptest.NewRecorder()
	router.ServeHTTP(wMalformed, reqMalformed)

	if wMalformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed json expected 400 Bad Request, got %d", wMalformed.Code)
	}
	var errRespMalformed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wMalformed.Body.Bytes(), &errRespMalformed)
	if errRespMalformed.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespMalformed.Error.Code)
	}

	// 8. Missing all credentials -> 401
	reqEmpty := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	wEmpty := httptest.NewRecorder()
	router.ServeHTTP(wEmpty, reqEmpty)

	if wEmpty.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials expected 401 Unauthorized, got %d", wEmpty.Code)
	}
}

func TestRefreshHandler(t *testing.T) {
	mockRefresh := &mockRefreshService{
		executeFn: func(ctx context.Context, input usecase.RefreshInput) (usecase.RefreshOutput, error) {
			if input.RefreshToken == "valid-refresh-token-43-chars-long-test123" {
				return usecase.RefreshOutput{
					AccessToken:      "new.access.jwt",
					TokenType:        "Bearer",
					ExpiresIn:        600,
					RefreshToken:     "successor-refresh-token-43-chars-long-abc",
					RefreshExpiresIn: 2592000,
				}, nil
			}
			if input.RefreshToken == "compromised-token" {
				return usecase.RefreshOutput{}, domain.ErrCompromisedSessionReplay
			}
			return usecase.RefreshOutput{}, domain.ErrInvalidCredentials
		},
	}

	router := setupFullTestRouter(nil, mockRefresh, nil, nil, nil, nil, nil)

	t.Run("successful refresh", func(t *testing.T) {
		body := `{"refresh_token":"valid-refresh-token-43-chars-long-test123"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("expected Cache-Control: no-store, got %s", w.Header().Get("Cache-Control"))
		}
		if w.Header().Get("Pragma") != "no-cache" {
			t.Errorf("expected Pragma: no-cache, got %s", w.Header().Get("Pragma"))
		}

		var resp struct {
			AccessToken      string `json:"access_token"`
			TokenType        string `json:"token_type"`
			ExpiresIn        int64  `json:"expires_in"`
			RefreshToken     string `json:"refresh_token"`
			RefreshExpiresIn int64  `json:"refresh_expires_in"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.AccessToken != "new.access.jwt" {
			t.Errorf("expected access_token 'new.access.jwt', got %s", resp.AccessToken)
		}
		if resp.RefreshToken != "successor-refresh-token-43-chars-long-abc" {
			t.Errorf("expected successor refresh token, got %s", resp.RefreshToken)
		}
	})

	t.Run("missing refresh_token field", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", w.Code)
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error.Code != "invalid_request" {
			t.Errorf("expected error code 'invalid_request', got %s", errResp.Error.Code)
		}
	})

	t.Run("malformed json body", func(t *testing.T) {
		body := `{"refresh_token":`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", w.Code)
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error.Code != "invalid_request" {
			t.Errorf("expected error code 'invalid_request', got %s", errResp.Error.Code)
		}
	})

	t.Run("replay token returns generic 401", func(t *testing.T) {
		body := `{"refresh_token":"compromised-token"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on replay, got %d", w.Code)
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error.Code != "invalid_credentials" {
			t.Errorf("expected generic code 'invalid_credentials', got %s", errResp.Error.Code)
		}
	})

	t.Run("payload too large", func(t *testing.T) {
		oversized := `{"refresh_token":"token"}` + strings.Repeat(" ", 5000)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", w.Code)
		}
	})

	t.Run("unsupported media type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"token"}`))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", w.Code)
		}
	})
}

func TestJWKSHandler(t *testing.T) {
	mockJWKS := &mockJWKSProvider{
		jsonBytes: []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"pubkey","kid":"k1","use":"sig"}]}`),
	}

	router := setupFullTestRouter(nil, nil, nil, nil, nil, mockJWKS, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Errorf("expected Cache-Control: public, max-age=60, got %s", w.Header().Get("Cache-Control"))
	}
	if !strings.Contains(w.Body.String(), `"kty":"OKP"`) {
		t.Errorf("unexpected body content: %s", w.Body.String())
	}
}
