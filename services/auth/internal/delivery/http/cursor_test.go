package http

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

func TestCursorEncodingAndDecoding(t *testing.T) {
	validID := "123e4567-e89b-12d3-a456-426614174000"
	validTime := time.Date(2026, 10, 7, 15, 30, 45, 123000, time.UTC) // microsecond precision

	t.Run("round-trip success", func(t *testing.T) {
		cursor := usecase.SessionCursor{
			CreatedAt: validTime,
			ID:        validID,
		}
		encoded := encodeSessionCursor(cursor)
		decoded, err := decodeSessionCursor(encoded)
		if err != nil {
			t.Fatalf("unexpected decode error: %v", err)
		}
		if decoded.ID != validID {
			t.Fatalf("expected ID %s, got %s", validID, decoded.ID)
		}
		if !decoded.CreatedAt.Equal(validTime) {
			t.Fatalf("expected CreatedAt %v, got %v", validTime, decoded.CreatedAt)
		}
	})

	t.Run("reject non-canonical base64url padding", func(t *testing.T) {
		cursor := usecase.SessionCursor{
			CreatedAt: validTime,
			ID:        validID,
		}
		encoded := encodeSessionCursor(cursor)
		padded := encoded + "=="
		_, err := decodeSessionCursor(padded)
		if err == nil {
			t.Fatal("expected error for padded base64url")
		}
	})

	t.Run("reject trailing JSON data", func(t *testing.T) {
		rawJSON := `{"v":1,"created_at":"2026-10-07T15:30:45.000123Z","id":"123e4567-e89b-12d3-a456-426614174000"}{"extra":1}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
		_, err := decodeSessionCursor(encoded)
		if err == nil || !strings.Contains(err.Error(), "trailing data") {
			t.Fatalf("expected trailing data error, got: %v", err)
		}
	})

	t.Run("reject unknown JSON fields", func(t *testing.T) {
		rawJSON := `{"v":1,"created_at":"2026-10-07T15:30:45.000123Z","id":"123e4567-e89b-12d3-a456-426614174000","unknown":"field"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
		_, err := decodeSessionCursor(encoded)
		if err == nil {
			t.Fatal("expected error for unknown JSON fields")
		}
	})

	t.Run("reject invalid version", func(t *testing.T) {
		rawJSON := `{"v":2,"created_at":"2026-10-07T15:30:45.000123Z","id":"123e4567-e89b-12d3-a456-426614174000"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
		_, err := decodeSessionCursor(encoded)
		if err == nil || !strings.Contains(err.Error(), "unsupported cursor version") {
			t.Fatalf("expected unsupported version error, got: %v", err)
		}
	})

	t.Run("reject invalid UUID", func(t *testing.T) {
		rawJSON := `{"v":1,"created_at":"2026-10-07T15:30:45.000123Z","id":"invalid-uuid-string"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
		_, err := decodeSessionCursor(encoded)
		if err == nil || !strings.Contains(err.Error(), "valid uuid") {
			t.Fatalf("expected invalid uuid error, got: %v", err)
		}
	})

	t.Run("reject sub-microsecond precision", func(t *testing.T) {
		// 123456789 ns has sub-microsecond precision (789 ns)
		rawJSON := `{"v":1,"created_at":"2026-10-07T15:30:45.123456789Z","id":"123e4567-e89b-12d3-a456-426614174000"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
		_, err := decodeSessionCursor(encoded)
		if err == nil || !strings.Contains(err.Error(), "microsecond resolution") {
			t.Fatalf("expected microsecond precision error, got: %v", err)
		}
	})
}
