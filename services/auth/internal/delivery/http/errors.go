package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type errorResponse struct {
	Error errorDetail `json:"error" binding:"required"`
}

type errorDetail struct {
	Code      string `json:"code" binding:"required" example:"invalid_request"`
	Message   string `json:"message" binding:"required" example:"Invalid email or password"`
	RequestID string `json:"request_id" binding:"required" example:"c6b8f3a1-4d2e-4f7b-9c1a-2e5f8a9b0c1d"`
}

func writeError(w http.ResponseWriter, r *http.Request, statusCode int, code, message string) {
	reqID := middleware.GetReqID(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error: errorDetail{
			Code:      code,
			Message:   message,
			RequestID: reqID,
		},
	})
}
