package http_test

import (
	"context"
	"encoding/json"
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
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockListSessionsService struct {
	executeFn func(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error)
}

func (m *mockListSessionsService) Execute(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error) {
	if m.executeFn != nil {
		return m.executeFn(ctx, accountID, callerSessionID, filter)
	}
	return usecase.SessionListPage{}, nil
}

type mockRevokeSessionService struct {
	executeFn func(ctx context.Context, accountID, callerSessionID, targetSessionID string) error
}

func (m *mockRevokeSessionService) Execute(ctx context.Context, accountID, callerSessionID, targetSessionID string) error {
	if m.executeFn != nil {
		return m.executeFn(ctx, accountID, callerSessionID, targetSessionID)
	}
	return nil
}

type mockLogoutAllService struct {
	executeFn func(ctx context.Context, accountID, callerSessionID string) error
}

func (m *mockLogoutAllService) Execute(ctx context.Context, accountID, callerSessionID string) error {
	if m.executeFn != nil {
		return m.executeFn(ctx, accountID, callerSessionID)
	}
	return nil
}

func parseErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var errEnvelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &errEnvelope); err != nil {
		t.Fatalf("failed to unmarshal error envelope %s: %v", string(body), err)
	}
	return errEnvelope.Error.Code
}

func setupSessionTestRouter(
	verifier authmiddleware.TokenVerifier,
	listUC delivery.ListSessionsService,
	revokeUC delivery.RevokeSessionService,
	logoutAllUC delivery.LogoutAllService,
) http.Handler {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, nil, nil, nil, nil, nil, nil, verifier, nil, nil, nil, nil).
		WithSessionManagement(listUC, revokeUC, logoutAllUC)
	return handler.Routes()
}

func TestSessionsHandler_List(t *testing.T) {
	validAccountID := "11111111-2222-4333-8444-555555555555"
	validSessionID := "22222222-3333-4444-8555-666666666666"

	verifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			return authmiddleware.AuthIdentity{
				AccountID: validAccountID,
				SessionID: validSessionID,
			}, nil
		},
	}

	t.Run("missing bearer token returns 401 with no-store", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("expected Cache-Control: no-store on 401, got %q", w.Header().Get("Cache-Control"))
		}
	})

	t.Run("duplicate authorization header returns 401 with no-store", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
		req.Header.Add("Authorization", "Bearer token1")
		req.Header.Add("Authorization", "Bearer token2")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("expected Cache-Control: no-store on 401, got %q", w.Header().Get("Cache-Control"))
		}
	})

	t.Run("non-empty body returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", strings.NewReader("unexpected body"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "invalid_request" {
			t.Fatalf("expected code invalid_request, got %s", code)
		}
	})

	t.Run("body exceeding 4 KiB returns 413 payload_too_large", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		largeBody := strings.Repeat("A", 4097)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", strings.NewReader(largeBody))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", w.Code)
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "payload_too_large" {
			t.Fatalf("expected code payload_too_large, got %s", code)
		}
	})

	t.Run("unknown query parameter returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?unknown_param=true", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("duplicate limit parameter returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit=10&limit=20", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid limit values return 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		for _, lim := range []string{"0", "101", "-5", "abc"} {
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit="+lim, nil)
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for limit=%s, got %d", lim, w.Code)
			}
		}
	})

	t.Run("malformed raw query syntax returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit=%zz", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "invalid_request" {
			t.Fatalf("expected code invalid_request, got %s", code)
		}
	})

	t.Run("empty limit parameter returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit=", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "invalid_request" {
			t.Fatalf("expected code invalid_request, got %s", code)
		}
	})

	t.Run("empty cursor parameter returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?cursor=", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "invalid_request" {
			t.Fatalf("expected code invalid_request, got %s", code)
		}
	})

	t.Run("malformed cursor returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, &mockListSessionsService{}, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?cursor=not-a-valid-cursor", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("successful list returns 200 with sessions and no-store", func(t *testing.T) {
		now := time.Now().UTC()
		listSvc := &mockListSessionsService{
			executeFn: func(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error) {
				return usecase.SessionListPage{
					Sessions: []usecase.SessionSummary{
						{
							ID:        callerSessionID,
							CreatedAt: now,
							ExpiresAt: now.Add(time.Hour),
							IsCurrent: true,
						},
					},
					NextCursor: nil,
				}, nil
			},
		}

		router := setupSessionTestRouter(verifier, listSvc, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("expected Cache-Control: no-store, got %q", w.Header().Get("Cache-Control"))
		}

		var resp delivery.ListSessionsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if len(resp.Sessions) != 1 || !resp.Sessions[0].Current {
			t.Fatalf("unexpected sessions response: %+v", resp)
		}
		if resp.NextCursor != nil {
			t.Fatalf("expected null next_cursor, got %v", resp.NextCursor)
		}
	})

	t.Run("missing caller session returns 401 unauthorized", func(t *testing.T) {
		listSvc := &mockListSessionsService{
			executeFn: func(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error) {
				return usecase.SessionListPage{}, domain.ErrCallerSessionNotFound
			},
		}

		router := setupSessionTestRouter(verifier, listSvc, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestSessionsHandler_Revoke(t *testing.T) {
	validAccountID := "11111111-2222-4333-8444-555555555555"
	validSessionID := "22222222-3333-4444-8555-666666666666"
	targetSessionID := "33333333-4444-4555-8666-777777777777"

	verifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			return authmiddleware.AuthIdentity{
				AccountID: validAccountID,
				SessionID: validSessionID,
			}, nil
		},
	}

	t.Run("malformed uuid path param returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, nil, &mockRevokeSessionService{}, nil)
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/invalid-uuid", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("non-empty body returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, nil, &mockRevokeSessionService{}, nil)
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+targetSessionID, strings.NewReader("some-body"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("foreign or nonexistent target returns 404 session_not_found", func(t *testing.T) {
		revokeSvc := &mockRevokeSessionService{
			executeFn: func(ctx context.Context, accountID, callerSessionID, targetSessionID string) error {
				return domain.ErrSessionNotFound
			},
		}

		router := setupSessionTestRouter(verifier, nil, revokeSvc, nil)
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+targetSessionID, nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
		if code := parseErrorCode(t, w.Body.Bytes()); code != "session_not_found" {
			t.Fatalf("expected code session_not_found, got %s", code)
		}
	})

	t.Run("successful revocation returns 204 no content", func(t *testing.T) {
		called := false
		revokeSvc := &mockRevokeSessionService{
			executeFn: func(ctx context.Context, accountID, callerSessionID, targetSessionID string) error {
				called = true
				return nil
			},
		}

		router := setupSessionTestRouter(verifier, nil, revokeSvc, nil)
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+targetSessionID, nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
		if !called {
			t.Fatal("expected service to be called")
		}
	})

	t.Run("uppercase target session id is normalized and accepted", func(t *testing.T) {
		var receivedTarget string
		revokeSvc := &mockRevokeSessionService{
			executeFn: func(ctx context.Context, accountID, callerSessionID, targetSessionID string) error {
				receivedTarget = targetSessionID
				return nil
			},
		}

		router := setupSessionTestRouter(verifier, nil, revokeSvc, nil)
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+strings.ToUpper(targetSessionID), nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
		if receivedTarget != strings.ToLower(targetSessionID) {
			t.Fatalf("expected normalized lowercase target session ID %q, got %q", strings.ToLower(targetSessionID), receivedTarget)
		}
	})
}

func TestSessionsHandler_LogoutAll(t *testing.T) {
	validAccountID := "11111111-2222-4333-8444-555555555555"
	validSessionID := "22222222-3333-4444-8555-666666666666"

	verifier := &mockTokenVerifier{
		verifyFn: func(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
			return authmiddleware.AuthIdentity{
				AccountID: validAccountID,
				SessionID: validSessionID,
			}, nil
		},
	}

	t.Run("non-empty body returns 400 invalid_request", func(t *testing.T) {
		router := setupSessionTestRouter(verifier, nil, nil, &mockLogoutAllService{})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", strings.NewReader("non-empty"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("caller session revoked returns 401 unauthorized", func(t *testing.T) {
		logoutAllSvc := &mockLogoutAllService{
			executeFn: func(ctx context.Context, accountID, callerSessionID string) error {
				return domain.ErrSessionRevoked
			},
		}

		router := setupSessionTestRouter(verifier, nil, nil, logoutAllSvc)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("successful logout-all returns 204 no content", func(t *testing.T) {
		called := false
		logoutAllSvc := &mockLogoutAllService{
			executeFn: func(ctx context.Context, accountID, callerSessionID string) error {
				called = true
				return nil
			},
		}

		router := setupSessionTestRouter(verifier, nil, nil, logoutAllSvc)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
		if !called {
			t.Fatal("expected service to be called")
		}
	})
}
