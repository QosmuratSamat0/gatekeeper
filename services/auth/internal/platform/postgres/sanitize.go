package postgres

import (
	"fmt"
	"regexp"
)

var (
	// Matches URL style credentials: postgres://user:password@host
	urlCredsRegex = regexp.MustCompile(`(?i)([a-z0-9+.-]+://)([^:@\s]+):([^@\s]+)@`)

	// Matches key-value DSN style: password=secret or password='secret' or password="secret"
	kvPasswordRegex = regexp.MustCompile(`(?i)\b(password\s*=\s*)(?:'[^']*'|"[^"]*"|\S+)`)

	// Matches query parameter credentials: ?password=secret or &password=secret
	queryPasswordRegex = regexp.MustCompile(`(?i)([?&]password=)(?:[^&\s]+)`)
)

// SanitizeError scrubs sensitive credentials (passwords in URLs, key-value DSNs, and query parameters)
// from error messages before they can be logged or returned.
// This prevents accidental credential disclosure in log aggregators and monitoring systems.
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", SanitizeDSN(err.Error()))
}

// SanitizeDSN scrubs sensitive credentials from connection strings, URLs, and DSNs.
func SanitizeDSN(dsn string) string {
	msg := urlCredsRegex.ReplaceAllString(dsn, "${1}${2}:***@")
	msg = kvPasswordRegex.ReplaceAllString(msg, "${1}***")
	msg = queryPasswordRegex.ReplaceAllString(msg, "${1}***")
	return msg
}
