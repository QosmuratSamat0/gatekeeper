package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ReadinessChecker checks if critical dependencies are available.
// Both *pgxpool.Pool and test fakes satisfy this interface.
type ReadinessChecker interface {
	Ping(ctx context.Context) error
}

type healthResponse struct {
	Status string `json:"status" binding:"required" example:"ok"`
}

// Healthz responds with process liveness status.
// A 200 response indicates that the HTTP server process is running and not deadlocked.
// @Summary Liveness probe
// @Description Returns 200 OK if the HTTP service process is running and not deadlocked.
// @Tags probes
// @Produce json
// @Success 200 {object} healthResponse "Process is healthy"
// @Router /healthz [get]
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

// Readyz responds with service readiness status.
// It performs a short, bounded ping to PostgreSQL (1 second timeout) so that a hanging
// database query does not stall container orchestration health checks or routing.
// @Summary Readiness probe
// @Description Returns 200 OK if the service and database are ready to accept traffic.
// @Tags probes
// @Produce json
// @Success 200 {object} healthResponse "Service and database are ready"
// @Failure 503 {object} errorResponse "Database connection ping failed or timed out"
// @Router /readyz [get]
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	if h.readiness != nil {
		// Use a dedicated short timeout for the readiness check.
		// If the database does not reply within 1 second, declare unready so
		// load balancers can stop directing registration requests here.
		checkCtx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()

		if err := h.readiness.Ping(checkCtx); err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
