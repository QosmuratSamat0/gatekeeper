package http

import (
	"net/http"
)

// JWKSProvider abstracts public key set generation.
type JWKSProvider interface {
	JWKSJSON() ([]byte, error)
}

// JWKS serves public keys in RFC 7517 / RFC 8037 format.
//
// @Summary Get public JSON Web Key Set (JWKS)
// @Description Returns the active and archived public signing keys for asymmetric Ed25519 token verification without disclosing private key material.
// @Tags auth
// @Produce json
// @Success 200 {object} token.JWKS "Public JWKS key set"
// @Failure 500 {object} errorResponse "Internal server error"
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	if h.jwksProvider == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "JWKS provider not initialized")
		return
	}

	data, err := h.jwksProvider.JWKSJSON()
	if err != nil {
		h.logSafeError("system_internal_failure", r)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Failed to generate JWKS")
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
