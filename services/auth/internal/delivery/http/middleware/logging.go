package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// Logging returns a middleware that logs each incoming HTTP request with its
// execution duration, HTTP status code and request ID for traceability.
func Logging(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := chimiddleware.GetReqID(r.Context())
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			// Record request metadata for observability without logging request bodies or sensitive headers.
			logger.InfoContext(r.Context(), "http request",
				slog.String("request_id", reqID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int("bytes_written", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}
