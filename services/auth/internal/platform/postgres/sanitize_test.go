package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeError(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustContain string
		mustNotHave string
	}{
		{
			name:        "URL-style credentials",
			input:       "connection failed to postgres://app_user:super_secret_password@db.internal:5432/auth",
			mustContain: "postgres://app_user:***@",
			mustNotHave: "super_secret_password",
		},
		{
			name:        "Key-value style password",
			input:       "failed to parse DSN: host=localhost user=admin password=my_db_password port=5432",
			mustContain: "password=***",
			mustNotHave: "my_db_password",
		},
		{
			name:        "Single-quoted key-value password",
			input:       "failed to connect: host=127.0.0.1 password='quoted_secret_value' dbname=auth",
			mustContain: "password=***",
			mustNotHave: "quoted_secret_value",
		},
		{
			name:        "Double-quoted key-value password",
			input:       `failed to connect: password="double_quoted_secret" dbname=auth`,
			mustContain: "password=***",
			mustNotHave: "double_quoted_secret",
		},
		{
			name:        "URL query parameter password",
			input:       "connect error: postgresql://admin@db:5432/auth?password=query_param_secret&sslmode=disable",
			mustContain: "?password=***",
			mustNotHave: "query_param_secret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := SanitizeError(errors.New(tc.input))
			if sanitized == nil {
				t.Fatal("expected non-nil error")
			}
			msg := sanitized.Error()
			if strings.Contains(msg, tc.mustNotHave) {
				t.Errorf("error leaked sensitive secret %q: got %s", tc.mustNotHave, msg)
			}
			if !strings.Contains(msg, tc.mustContain) {
				t.Errorf("expected sanitized error to contain %q, got: %s", tc.mustContain, msg)
			}
		})
	}

	t.Run("nil error returns nil", func(t *testing.T) {
		if err := SanitizeError(nil); err != nil {
			t.Errorf("expected nil for nil error, got: %v", err)
		}
	})
}
