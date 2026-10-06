package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// TokenVerifier defines the contract for validating incoming access tokens into an authenticated identity.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, tokenString string) (AuthIdentity, error)
}

// AuthIdentity holds authenticated caller identity extracted from token claims.
type AuthIdentity struct {
	AccountID string
	SessionID string
}

type authCtxKey struct{}

var authIdentityKey = authCtxKey{}

// WithAuthIdentity stores an AuthIdentity in the context.
func WithAuthIdentity(ctx context.Context, id AuthIdentity) context.Context {
	return context.WithValue(ctx, authIdentityKey, id)
}

// GetAuthIdentity retrieves an AuthIdentity from context.
func GetAuthIdentity(ctx context.Context) (AuthIdentity, bool) {
	val, ok := ctx.Value(authIdentityKey).(AuthIdentity)
	return val, ok
}

// BearerAuth validates the incoming Authorization Bearer header.
// It is case-insensitive regarding the Bearer scheme prefix.
// It verifies the cryptographic signature and token claims without evaluating session revocation
// (allowing idempotent operations like logout to process already-revoked sessions).
func BearerAuth(verifier TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaders := r.Header.Values("Authorization")
			if len(authHeaders) == 0 {
				writeAuthError(w, r, "missing authorization header")
				return
			}
			if len(authHeaders) > 1 {
				writeAuthError(w, r, "ambiguous multiple authorization headers")
				return
			}

			authHeader := authHeaders[0]
			// Case-insensitive scheme check
			if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				writeAuthError(w, r, "invalid authorization scheme")
				return
			}

			tokenStr := strings.TrimSpace(authHeader[7:])
			if tokenStr == "" {
				writeAuthError(w, r, "empty bearer token")
				return
			}

			identity, err := verifier.VerifyToken(r.Context(), tokenStr)
			if err != nil {
				writeAuthError(w, r, "invalid or expired token")
				return
			}

			ctx := WithAuthIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, r *http.Request, message string) {
	reqID := middleware.GetReqID(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(errorEnvelope{
		Error: errorDetail{
			Code:      "unauthorized",
			Message:   message,
			RequestID: reqID,
		},
	})
}
