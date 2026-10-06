package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewPoolUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 127.0.0.1:1 is an invalid/unreachable port
	_, err := NewPool(ctx, "postgres://user:pass@127.0.0.1:1/test?sslmode=disable", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected error connecting to unreachable port")
	}
	if strings.Contains(err.Error(), "pass") && !strings.Contains(err.Error(), "user:***@") {
		t.Errorf("error leaked password: %v", err)
	}
}
