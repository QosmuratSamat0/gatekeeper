package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/app"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config"
)

// @title Gatekeeper Auth Service API
// @version 0.2.0
// @description Authentication service for Gatekeeper.
// @description Implements AUTH-01 registration and AUTH-02 authentication (login, access JWT, sessions, profile, logout, JWKS).
// @basePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the access JWT.

func main() {
	// Use structured JSON logging so infrastructure and log forwarders can parse fields.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Load and validate environment variables immediately.
	// Fail early before binding ports or connecting to external systems.
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration loading failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Listen for termination signals from the operating system or container orchestrator.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Wire together the database pool, adapters, use cases and HTTP server.
	application, err := app.Wire(ctx, cfg, logger)
	if err != nil {
		logger.Error("application wiring failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Run starts the HTTP server and blocks until an interrupt signal is received.
	if err := application.Run(ctx); err != nil {
		logger.Error("application stopped with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
