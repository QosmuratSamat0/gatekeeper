package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config"
)

// App manages the service lifecycle, HTTP server, and cleanup of external resources.
type App struct {
	cfg         config.Config
	logger      *slog.Logger
	httpServer  *http.Server
	cleanup     []func()
	cleanupOnce sync.Once
}

// New constructs an App instance with injected router and cleanup functions.
func New(cfg config.Config, logger *slog.Logger, router http.Handler, cleanup ...func()) *App {
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return &App{
		cfg:        cfg,
		logger:     logger,
		httpServer: server,
		cleanup:    cleanup,
	}
}

// Run starts the HTTP server and manages graceful shutdown.
// Cleanup callbacks (such as closing database connection pools) are guaranteed
// to run upon exit, even if the HTTP server fails to start or shutdown times out.
func (a *App) Run(ctx context.Context) error {
	// Ensure background resources are released even if startup fails or shutdown encounters an error.
	defer a.runCleanup()

	serverErr := make(chan error, 1)

	go func() {
		a.logger.Info("starting auth service", slog.String("addr", a.httpServer.Addr))
		if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case err := <-serverErr:
		// Server failed to start (e.g. port already bound).
		// runCleanup via defer will immediately release database connections.
		return fmt.Errorf("server startup failed: %w", err)

	case <-ctx.Done():
		a.logger.Info("shutting down auth service: stopping incoming HTTP requests")

		// Allow active in-flight requests up to HTTPShutdownTimeout to finish before forcing close.
		shutdownTimeout := a.cfg.HTTPShutdownTimeout
		if shutdownTimeout <= 0 {
			shutdownTimeout = 10 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		shutdownErr := a.httpServer.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			a.logger.Error("server shutdown failed or timed out; forcing socket closure", slog.String("error", shutdownErr.Error()))
			// Force immediate termination of all remaining active connections and listeners.
			// Server.Close() closes network connections and cancels in-flight request contexts,
			// but does not forcibly terminate running goroutines in handlers that do not inspect r.Context().
			_ = a.httpServer.Close()
			return fmt.Errorf("server shutdown: %w", shutdownErr)
		}

		a.logger.Info("auth service stopped cleanly")
		return nil
	}
}

// runCleanup executes all registered cleanup callbacks exactly once.
func (a *App) runCleanup() {
	a.cleanupOnce.Do(func() {
		for _, fn := range a.cleanup {
			if fn != nil {
				fn()
			}
		}
	})
}
