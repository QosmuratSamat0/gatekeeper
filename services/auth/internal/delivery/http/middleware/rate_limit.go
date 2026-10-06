package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// IPAttemptTracker tracks login attempts within a sliding or fixed time window.
type IPAttemptTracker struct {
	Count       int
	WindowStart time.Time
}

// IPRateLimiter tracks and bounds authentication attempts per remote IP.
// To prevent attacker evasion via table displacement, the limiter refuses to evict active entries.
// When capacity is reached, it purges expired windows. If still full, it fails closed for untracked IPs.
type IPRateLimiter struct {
	mu          sync.Mutex
	attempts    map[string]IPAttemptTracker
	maxAttempts int
	window      time.Duration
	capacity    int
}

// NewIPRateLimiter creates an in-memory rate limiter with the specified maximum attempts and capacity.
func NewIPRateLimiter(maxAttempts int, window time.Duration, capacity int) *IPRateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	if capacity <= 0 {
		capacity = 10000
	}
	return &IPRateLimiter{
		attempts:    make(map[string]IPAttemptTracker, capacity),
		maxAttempts: maxAttempts,
		window:      window,
		capacity:    capacity,
	}
}

// Allow checks if the given remote IP address is permitted to perform a login attempt.
// It returns allowed boolean, remaining attempts, and seconds until the window resets.
func (l *IPRateLimiter) Allow(ip string, now time.Time) (bool, int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	tracker, exists := l.attempts[ip]
	if exists {
		// If current window expired, reset counter
		if now.Sub(tracker.WindowStart) >= l.window {
			tracker.Count = 1
			tracker.WindowStart = now
			l.attempts[ip] = tracker
			return true, l.maxAttempts - 1, int(l.window.Seconds())
		}

		// Within window: check count
		if tracker.Count >= l.maxAttempts {
			retryAfter := int((l.window - now.Sub(tracker.WindowStart)).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			return false, 0, retryAfter
		}

		tracker.Count++
		l.attempts[ip] = tracker
		retryAfter := int((l.window - now.Sub(tracker.WindowStart)).Seconds())
		return true, l.maxAttempts - tracker.Count, retryAfter
	}

	// New untracked IP
	if len(l.attempts) >= l.capacity {
		// Attempt to purge expired entries first
		l.purgeExpiredLocked(now)
		// If still at capacity after purge, fail closed to prevent cache displacement attacks
		if len(l.attempts) >= l.capacity {
			return false, 0, int(l.window.Seconds())
		}
	}

	l.attempts[ip] = IPAttemptTracker{
		Count:       1,
		WindowStart: now,
	}
	return true, l.maxAttempts - 1, int(l.window.Seconds())
}

func (l *IPRateLimiter) purgeExpiredLocked(now time.Time) {
	for ip, tracker := range l.attempts {
		if now.Sub(tracker.WindowStart) >= l.window {
			delete(l.attempts, ip)
		}
	}
}

type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// RateLimitLoginMiddleware creates an HTTP middleware applying the 10 attempts/minute IP rate limit.
// It extracts the client IP strictly from r.RemoteAddr without trusting client-controlled headers.
func RateLimitLoginMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract client host from RemoteAddr (stripping port)
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}

			allowed, _, retryAfter := limiter.Allow(host, time.Now())
			if !allowed {
				reqID := middleware.GetReqID(r.Context())
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(errorEnvelope{
					Error: errorDetail{
						Code:      "rate_limited",
						Message:   "Too many login attempts. Please try again later.",
						RequestID: reqID,
					},
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
