package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/migrations"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: migrate <up|version>\n")
		os.Exit(1)
	}

	command := os.Args[1]

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintf(os.Stderr, "error: DATABASE_URL environment variable is required\n")
		os.Exit(1)
	}

	// Normalize URL scheme so golang-migrate selects the pgx5 driver.
	migURL := databaseURL
	if strings.HasPrefix(migURL, "postgres://") {
		migURL = "pgx5://" + strings.TrimPrefix(migURL, "postgres://")
	} else if strings.HasPrefix(migURL, "postgresql://") {
		migURL = "pgx5://" + strings.TrimPrefix(migURL, "postgresql://")
	}

	sourceDriver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing migration source: %v\n", err)
		os.Exit(1)
	}

	m, err := migrate.NewWithSourceInstance("iofs", sourceDriver, migURL)
	if err != nil {
		// Sanitize credentials so passwords in DATABASE_URL are never written to standard error.
		fmt.Fprintf(os.Stderr, "error connecting to database for migration: %v\n", postgres.SanitizeError(err))
		os.Exit(1)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			fmt.Fprintf(os.Stderr, "error closing source: %v\n", srcErr)
		}
		if dbErr != nil {
			fmt.Fprintf(os.Stderr, "error closing db: %v\n", postgres.SanitizeError(dbErr))
		}
	}()

	switch command {
	case "up":
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fmt.Fprintf(os.Stderr, "migration failed: %v\n", postgres.SanitizeError(err))
			os.Exit(1)
		}
		fmt.Println("migration up completed successfully")
	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				fmt.Println("no migrations applied yet (version 0)")
				return
			}
			fmt.Fprintf(os.Stderr, "error checking migration version: %v\n", postgres.SanitizeError(err))
			os.Exit(1)
		}
		fmt.Printf("current version: %d (dirty: %v)\n", version, dirty)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s. Supported commands: up, version\n", command)
		os.Exit(1)
	}
}
