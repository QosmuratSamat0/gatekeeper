package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	deliveryhttp "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
)

type healthResponse struct {
	Status string `json:"status"`
}

type mockReadiness struct {
	err error
}

func (m *mockReadiness) Ping(ctx context.Context) error {
	return m.err
}

func setupTestRouter(readiness deliveryhttp.ReadinessChecker) http.Handler {
	discardLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := deliveryhttp.NewHandler(discardLogger, readiness, nil, nil, nil, nil, nil, nil, nil)
	return h.Routes()
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	router := setupTestRouter(nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyz_Healthy(t *testing.T) {
	t.Parallel()

	router := setupTestRouter(&mockReadiness{err: nil})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyz_Unhealthy(t *testing.T) {
	t.Parallel()

	router := setupTestRouter(&mockReadiness{err: errors.New("db disconnected")})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}
