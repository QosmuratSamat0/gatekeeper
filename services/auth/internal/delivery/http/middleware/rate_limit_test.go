package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiter_WindowAndAttempts(t *testing.T) {
	now := time.Now()
	limiter := NewIPRateLimiter(10, time.Minute, 100)

	ip := "192.0.2.1"

	// First 10 attempts should be allowed
	for i := 1; i <= 10; i++ {
		allowed, remaining, _ := limiter.Allow(ip, now.Add(time.Duration(i)*time.Second))
		if !allowed {
			t.Fatalf("attempt %d should be allowed", i)
		}
		if remaining != 10-i {
			t.Errorf("attempt %d: expected remaining %d, got %d", i, 10-i, remaining)
		}
	}

	// 11th attempt within same minute should be rejected
	allowed, remaining, retryAfter := limiter.Allow(ip, now.Add(20*time.Second))
	if allowed {
		t.Fatal("11th attempt within window should be rejected")
	}
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", remaining)
	}
	if retryAfter <= 0 {
		t.Errorf("expected positive retryAfter, got %d", retryAfter)
	}

	// After 1 minute window has passed, attempts should reset
	allowedAfterReset, remainingAfterReset, _ := limiter.Allow(ip, now.Add(65*time.Second))
	if !allowedAfterReset {
		t.Fatal("attempt after window reset should be allowed")
	}
	if remainingAfterReset != 9 {
		t.Errorf("expected 9 remaining after reset, got %d", remainingAfterReset)
	}
}

func TestIPRateLimiter_AntiEvictionProtection(t *testing.T) {
	now := time.Now()
	// Capacity of 2
	limiter := NewIPRateLimiter(10, time.Minute, 2)

	// IP 1 and IP 2 register active attempts
	allowed1, _, _ := limiter.Allow("192.0.2.1", now)
	allowed2, _, _ := limiter.Allow("192.0.2.2", now)
	if !allowed1 || !allowed2 {
		t.Fatal("initial entries within capacity must be allowed")
	}

	// IP 3 arrives while capacity is full and entries are NOT expired
	// Must fail closed, must NOT evict IP 1 or IP 2
	allowed3, _, _ := limiter.Allow("192.0.2.3", now.Add(5*time.Second))
	if allowed3 {
		t.Fatal("untracked IP must fail closed when capacity is reached and no entries are expired")
	}

	// Existing IPs must still be tracked and NOT evicted
	allowed1Again, remaining1, _ := limiter.Allow("192.0.2.1", now.Add(6*time.Second))
	if !allowed1Again {
		t.Fatal("existing tracked IP must remain tracked and allowed within limit")
	}
	if remaining1 != 8 { // 10 - 2 attempts = 8
		t.Errorf("expected remaining 8, got %d", remaining1)
	}

	// After window expires, capacity purge must reclaim space
	allowed3AfterExpiry, _, _ := limiter.Allow("192.0.2.3", now.Add(65*time.Second))
	if !allowed3AfterExpiry {
		t.Fatal("new IP must be allowed after expired entries are purged")
	}
}

func TestRateLimitLoginMiddleware_HTTPHandling(t *testing.T) {
	limiter := NewIPRateLimiter(2, time.Minute, 10)
	handler := RateLimitLoginMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// Attempt 1 from 192.0.2.10:1234
	req1 := httptest.NewRequest(http.MethodPost, "/auth/v1/login", nil)
	req1.RemoteAddr = "192.0.2.10:1234"
	req1.Header.Set("X-Forwarded-For", "10.0.0.1") // must be ignored
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w1.Code)
	}

	// Attempt 2 from same IP different port
	req2 := httptest.NewRequest(http.MethodPost, "/auth/v1/login", nil)
	req2.RemoteAddr = "192.0.2.10:5678"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// Attempt 3 (rate limit exceeded)
	req3 := httptest.NewRequest(http.MethodPost, "/auth/v1/login", nil)
	req3.RemoteAddr = "192.0.2.10:9999"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", w3.Code)
	}
	if w3.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}

	var env errorEnvelope
	if err := json.Unmarshal(w3.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if env.Error.Code != "rate_limited" {
		t.Errorf("expected error code 'rate_limited', got %s", env.Error.Code)
	}
}
