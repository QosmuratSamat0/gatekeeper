package token

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenerateAndValidateEmailVerificationToken(t *testing.T) {
	mgr := NewEmailVerificationTokenManager()
	rawToken, hash, err := mgr.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(rawToken) != 43 {
		t.Fatalf("expected raw token length 43, got %d (%q)", len(rawToken), rawToken)
	}

	if len(hash) != 32 {
		t.Fatalf("expected hash length 32, got %d", len(hash))
	}

	// Validate the generated token
	validatedHash, err := mgr.ValidateAndHash(rawToken)
	if err != nil {
		t.Fatalf("ValidateAndHash rejected valid token: %v", err)
	}

	if string(validatedHash) != string(hash) {
		t.Fatalf("hash mismatch between generation and validation")
	}
}

func TestValidateAndHashEmailVerificationToken_InvalidInputs(t *testing.T) {
	mgr := NewEmailVerificationTokenManager()
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty string", token: ""},
		{name: "too short", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NT"},    // 42 chars
		{name: "too long", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA"}, // 44 chars
		{name: "with padding", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NQ="},
		{name: "with standard plus", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0+TY"},
		{name: "with standard slash", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0/TY"},
		{name: "with whitespace", token: " YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NT"},
		{name: "with null byte", token: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0\x00TY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.ValidateAndHash(tt.token)
			if err == nil {
				t.Fatalf("expected error for token %q, got nil", tt.token)
			}
		})
	}
}

func TestValidateAndHashEmailVerificationToken_NonCanonicalRejection(t *testing.T) {
	mgr := NewEmailVerificationTokenManager()

	// 32 zero bytes encodes canonically to 43 'A' characters.
	zeroBytes := make([]byte, 32)
	canonical := base64.RawURLEncoding.EncodeToString(zeroBytes)
	if len(canonical) != 43 {
		t.Fatalf("expected 43 chars, got %d", len(canonical))
	}

	hash, err := mgr.ValidateAndHash(canonical)
	if err != nil {
		t.Fatalf("canonical token rejected: %v", err)
	}
	expectedHash := sha256.Sum256(zeroBytes)
	if string(hash) != string(expectedHash[:]) {
		t.Fatalf("hash mismatch for canonical token")
	}

	// Change the last character from 'A' (bits 000000) to 'B' (bits 000001).
	// Because the last 2 bits are unused padding bits, having them non-zero is non-canonical.
	nonCanonical := canonical[:42] + "B"
	_, err = mgr.ValidateAndHash(nonCanonical)
	if err == nil {
		t.Fatalf("non-canonical token with non-zero padding bits unexpectedly accepted")
	}
}
