package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

const (
	maxCursorLength = 256
	cursorVersion   = 1
)

type sessionCursorPayload struct {
	Version   int    `json:"v"`
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

// encodeSessionCursor encodes a session cursor payload using strict canonical unpadded base64url.
// Timestamps are formatted with RFC3339Nano in UTC to preserve PostgreSQL microsecond resolution.
func encodeSessionCursor(c usecase.SessionCursor) string {
	payload := sessionCursorPayload{
		Version:   cursorVersion,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID:        strings.ToLower(c.ID),
	}
	data, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeSessionCursor decodes and strictly validates an opaque cursor string.
// It verifies canonical base64url encoding, strict JSON schema with no unknown or trailing data,
// version matching, UUID formatting, and timestamp precision compatibility with PostgreSQL.
func decodeSessionCursor(cursorStr string) (*usecase.SessionCursor, error) {
	if len(cursorStr) == 0 || len(cursorStr) > maxCursorLength {
		return nil, errors.New("cursor length is invalid")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(cursorStr)
	if err != nil {
		return nil, fmt.Errorf("decoding base64url cursor: %w", err)
	}

	// Canonical verification: ensure input string exactly matches canonical base64url encoding
	// to prevent alternative encodings, padding, or whitespace bypasses.
	if base64.RawURLEncoding.EncodeToString(decoded) != cursorStr {
		return nil, errors.New("cursor is not canonically base64url encoded")
	}

	dec := json.NewDecoder(bytes.NewReader(decoded))
	dec.DisallowUnknownFields()

	var payload sessionCursorPayload
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding cursor json: %w", err)
	}

	// Ensure there is no trailing data after the primary JSON payload
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("cursor contains unexpected trailing data")
	}

	if payload.Version != cursorVersion {
		return nil, fmt.Errorf("unsupported cursor version %d", payload.Version)
	}

	if payload.ID == "" || payload.CreatedAt == "" {
		return nil, errors.New("cursor is missing required fields")
	}

	if !isValidUUID(payload.ID) {
		return nil, errors.New("cursor id is not a valid uuid")
	}

	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil {
		createdAt, err = time.Parse(time.RFC3339, payload.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor timestamp format: %w", err)
		}
	}
	createdAt = createdAt.UTC()

	// Reject timestamps that lose precision when converted to PostgreSQL microsecond resolution (1e-6 s)
	if createdAt.Nanosecond()%1000 != 0 {
		return nil, errors.New("cursor timestamp precision exceeds postgresql microsecond resolution")
	}

	return &usecase.SessionCursor{
		CreatedAt: createdAt,
		ID:        strings.ToLower(payload.ID),
	}, nil
}

// isValidUUID validates that a string is a 36-character hexadecimal UUID format.
func isValidUUID(u string) bool {
	if len(u) != 36 {
		return false
	}
	for i, c := range u {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'f':
			case c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
	}
	return true
}
