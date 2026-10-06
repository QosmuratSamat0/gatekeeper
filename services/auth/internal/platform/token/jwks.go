package token

import (
	"encoding/base64"
	"encoding/json"
	"sort"
)

// JWK represents a public key in JSON Web Key format per RFC 7517 and RFC 8037 (OKP for Ed25519).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
}

// JWKS represents a standard JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS projects the current active and archived Ed25519 public keys into a standard JWKS.
// Zero private key material or metadata is ever exposed.
func (s *TokenService) JWKS() JWKS {
	keys := make([]JWK, 0, len(s.publicKeys))
	for kid, pubKey := range s.publicKeys {
		keys = append(keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pubKey),
			Kid: kid,
			Use: "sig",
		})
	}

	// Deterministic sorting by kid
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Kid < keys[j].Kid
	})

	return JWKS{Keys: keys}
}

// JWKSJSON marshals the public JWKS to formatted JSON bytes.
func (s *TokenService) JWKSJSON() ([]byte, error) {
	return json.Marshal(s.JWKS())
}
