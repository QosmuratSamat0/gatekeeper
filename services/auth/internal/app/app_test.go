package app_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/app"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config"
)

func TestApp_LifecycleCleanupOnShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{HTTPAddr: "127.0.0.1:0"} // ephemeral port

	var cleanedUp atomic.Bool
	cleanupFn := func() {
		cleanedUp.Store(true)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	application := app.New(cfg, logger, dummyHandler, cleanupFn)

	ctx, cancel := context.WithCancel(context.Background())

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(ctx)
	}()

	// Wait briefly for server to start listening
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown
	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("expected clean shutdown, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for application.Run to return")
	}

	if !cleanedUp.Load() {
		t.Error("expected cleanup callback to be called on shutdown")
	}
}

func TestApp_LifecycleCleanupOnStartupFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// An invalid address like 999.999.999.999:80 will fail to listen immediately
	cfg := config.Config{HTTPAddr: "999.999.999.999:80"}

	var cleanedUp atomic.Bool
	cleanupFn := func() {
		cleanedUp.Store(true)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	application := app.New(cfg, logger, dummyHandler, cleanupFn)

	ctx := context.Background()
	err := application.Run(ctx)

	if err == nil {
		t.Fatal("expected server startup error for invalid address")
	}

	// Verify that database connections or resources are released even if listen failed
	if !cleanedUp.Load() {
		t.Error("expected cleanup callback to be called even when startup fails")
	}
}

func TestApp_LifecycleForcedCloseOnShutdownTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Find an available ephemeral local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate test port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Config{
		HTTPAddr:            addr,
		HTTPShutdownTimeout: 50 * time.Millisecond,
	}

	var cleanedUp atomic.Bool
	cleanupFn := func() {
		cleanedUp.Store(true)
	}

	reqStarted := make(chan struct{})
	blockReq := make(chan struct{})
	defer close(blockReq)

	hangingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-reqStarted:
		default:
			close(reqStarted)
		}
		<-blockReq
		w.WriteHeader(http.StatusOK)
	})

	application := app.New(cfg, logger, hangingHandler, cleanupFn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(ctx)
	}()

	// Fire an in-flight request that hangs inside the handler
	client := &http.Client{Timeout: 3 * time.Second}
	var clientErr error
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		// Retry connection briefly until the server begins listening
		for i := 0; i < 30; i++ {
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
			resp, err := client.Do(req)
			if err != nil {
				// If server is not yet accepting connections, retry briefly
				if strings.Contains(err.Error(), "refused") {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				// Connection was established and subsequently severed by Server.Close()
				clientErr = err
				return
			}
			_ = resp.Body.Close()
			return
		}
	}()

	select {
	case <-reqStarted:
		// Active in-flight request is currently blocked inside the handler
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight request to reach handler")
	}

	// Trigger graceful shutdown while the active request is blocked
	cancel()

	// Shutdown should exceed the 50ms timeout and invoke Close()
	select {
	case err := <-runErrCh:
		if err == nil {
			t.Fatal("expected error on timed-out shutdown, got nil")
		}
		if !strings.Contains(err.Error(), "server shutdown") {
			t.Errorf("expected error to mention 'server shutdown', got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for application.Run to return after shutdown timeout")
	}

	// Verify the client request was actively severed by Server.Close()
	select {
	case <-clientDone:
		if clientErr == nil {
			t.Fatal("expected client request to fail due to Server.Close() connection termination, got nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight client request to be terminated by Server.Close()")
	}

	// Database cleanup must still run even when shutdown timed out
	if !cleanedUp.Load() {
		t.Error("expected cleanup callback to be called after forced shutdown")
	}
}
