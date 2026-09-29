package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	internalhttp "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/http"
)

type config struct {
	httpAddr string
}

func loadConfig() config {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	return config{
		httpAddr: addr,
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg := loadConfig()

	handler := internalhttp.NewHandler(logger)
	router := handler.Routes()

	server := &http.Server{
		Addr:              cfg.httpAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("starting auth service", slog.String("addr", cfg.httpAddr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("listen and serve: %w", err)
		}
	}()

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server startup failed: %w", err)
	case <-ctx.Done():
		logger.Info("stopping auth service")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}

		logger.Info("auth service stopped cleanly")
		return nil
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("application exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
