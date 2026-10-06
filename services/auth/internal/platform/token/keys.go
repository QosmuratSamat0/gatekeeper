package token

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ParsePKCS8PrivateKeyFromPEM decodes and parses an Ed25519 private key from PKCS#8 PEM bytes.
func ParsePKCS8PrivateKeyFromPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in key data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %T", key)
	}

	if len(edKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unexpected ed25519 private key length: %d", len(edKey))
	}

	return edKey, nil
}

// LoadPrivateKeyFromFile reads an Ed25519 private key from an external PEM file path.
// Error messages omit raw paths or secret content to prevent credential leakage in logs.
func LoadPrivateKeyFromFile(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private key file path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return nil, fmt.Errorf("failed to read private key file: %v", pathErr.Err)
		}
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	return ParsePKCS8PrivateKeyFromPEM(data)
}

// LoadArchivedPublicKeysFromFile reads optional previous public keys from a JSON file in JWKS format.
// This allows graceful token verification during key rotation without restarting all clients simultaneously.
func LoadArchivedPublicKeysFromFile(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return make(map[string]ed25519.PublicKey), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return nil, fmt.Errorf("failed to read archived public keys file: %v", pathErr.Err)
		}
		return nil, fmt.Errorf("failed to read archived public keys file: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("parsing archived public keys JSON: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported key type %s/%s for kid %s", jwk.Kty, jwk.Crv, jwk.Kid)
		}
		if jwk.Kid == "" {
			return nil, errors.New("empty kid in archived public keys")
		}
		if _, exists := keys[jwk.Kid]; exists {
			return nil, fmt.Errorf("duplicate kid in archived keys: %s", jwk.Kid)
		}

		pubBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 public key for kid %s: %w", jwk.Kid, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key size for kid %s: %d", jwk.Kid, len(pubBytes))
		}

		keys[jwk.Kid] = ed25519.PublicKey(pubBytes)
	}

	return keys, nil
}
