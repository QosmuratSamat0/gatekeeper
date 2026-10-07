package integration_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	pgplatform "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/postgres"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/migrations"
)

// getOptInTestDatabaseURL requires explicit opt-in via RUN_INTEGRATION_TESTS or INTEGRATION_TEST.
// Without explicit opt-in, tests skip without connecting to any database.
// When enabled, TEST_DATABASE_URL must be specified explicitly (no arbitrary default localhost fallback).
func getOptInTestDatabaseURL(t *testing.T) string {
	t.Helper()
	enabled := os.Getenv("RUN_INTEGRATION_TESTS") == "true" || os.Getenv("INTEGRATION_TEST") == "true"
	if !enabled {
		t.Skip("skipping PostgreSQL integration tests: set RUN_INTEGRATION_TESTS=true or INTEGRATION_TEST=true to enable")
		return ""
	}

	rawURL := os.Getenv("TEST_DATABASE_URL")
	if rawURL == "" {
		t.Fatal("integration tests are explicitly enabled but TEST_DATABASE_URL is not set")
	}
	return rawURL
}

func toMigrateURL(dbURL string) string {
	if strings.HasPrefix(dbURL, "postgres://") {
		return "pgx5://" + strings.TrimPrefix(dbURL, "postgres://")
	}
	if strings.HasPrefix(dbURL, "postgresql://") {
		return "pgx5://" + strings.TrimPrefix(dbURL, "postgresql://")
	}
	return dbURL
}

// setupDisposableTestDB creates an isolated disposable database for each test execution.
// Using a disposable database ensures tests never mutate shared databases or leave leftover
// rows, eliminating the need for destructive TRUNCATE or Down operations on shared state.
// All error messages scrub credentials so raw URLs are never printed in test output.
func setupDisposableTestDB(t *testing.T) (*pgxpool.Pool, string, func()) {
	t.Helper()
	rawURL := getOptInTestDatabaseURL(t)
	if rawURL == "" {
		return nil, "", nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse TEST_DATABASE_URL: %v", pgplatform.SanitizeError(err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Connect to base database to create the disposable test database
	basePool, err := pgplatform.NewPool(ctx, rawURL, 3*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to base PostgreSQL server: %v", pgplatform.SanitizeError(err))
	}

	// 2. Create unique disposable database
	disposableDBName := fmt.Sprintf("gatekeeper_test_%d_%d", os.Getpid(), time.Now().UnixNano()%100000000)
	_, err = basePool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s;", disposableDBName))
	if err != nil {
		basePool.Close()
		t.Fatalf("failed to create disposable database: %v", pgplatform.SanitizeError(err))
	}

	// 3. Form connection URL to the disposable database
	disposableURLObj := *u
	disposableURLObj.Path = "/" + disposableDBName
	disposableURL := disposableURLObj.String()

	// 4. Open pool to the fresh disposable database
	testPool, err := pgplatform.NewPool(ctx, disposableURL, 3*time.Second)
	if err != nil {
		_, _ = basePool.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE);", disposableDBName))
		basePool.Close()
		t.Fatalf("failed to connect to disposable database: %v", pgplatform.SanitizeError(err))
	}

	// 5. Apply migrations UP
	driver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		testPool.Close()
		_, _ = basePool.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE);", disposableDBName))
		basePool.Close()
		t.Fatalf("failed to create migration driver: %v", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", driver, toMigrateURL(disposableURL))
	if err != nil {
		testPool.Close()
		_, _ = basePool.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE);", disposableDBName))
		basePool.Close()
		t.Fatalf("failed to initialize migrate: %v", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		_, _ = m.Close()
		testPool.Close()
		_, _ = basePool.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE);", disposableDBName))
		basePool.Close()
		t.Fatalf("failed to apply migrations up: %v", err)
	}

	// 6. Teardown closes pools and drops the disposable database with FORCE
	teardown := func() {
		_, _ = m.Close()
		testPool.Close()

		dropCtx, dropCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dropCancel()
		_, _ = basePool.Exec(dropCtx, fmt.Sprintf("DROP DATABASE %s WITH (FORCE);", disposableDBName))
		basePool.Close()
	}

	return testPool, disposableURL, teardown
}

func TestPostgres_MigrationsRollback(t *testing.T) {
	pool, disposableURL, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	driver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatalf("migration source err: %v", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", driver, toMigrateURL(disposableURL))
	if err != nil {
		t.Fatalf("migrate err: %v", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	// Verify rollback down works in isolated disposable database
	if err := m.Down(); err != nil {
		t.Fatalf("failed down (rollback): %v", err)
	}

	// Reapply up
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("failed re-up: %v", err)
	}
}

func TestPostgres_ConcurrentDuplicateRegistrationRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	accountRepo := repo.NewAccountRepository(pool, 5*time.Second)
	// Use small Argon2id params for high concurrency testing speed
	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 10)
	uc := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil)

	concurrentAttempts := 10
	var successCount atomic.Int32
	var conflictCount atomic.Int32
	var otherErrors atomic.Int32

	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneWg sync.WaitGroup

	targetEmail := "race.condition.user@example.com"

	for i := 0; i < concurrentAttempts; i++ {
		doneWg.Add(1)
		// Vary case to ensure canonical lowercasing is checked in database
		casedEmail := targetEmail
		if i%2 == 0 {
			casedEmail = strings.ToUpper(targetEmail)
		}

		go func(email string) {
			defer doneWg.Done()
			startBarrier.Wait()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := uc.Execute(ctx, usecase.RegisterInput{
				Email:    email,
				Password: "a-secure-race-password-15chars",
			})

			if err == nil {
				successCount.Add(1)
			} else if errors.Is(err, domain.ErrAccountExists) {
				conflictCount.Add(1)
			} else {
				otherErrors.Add(1)
				t.Logf("unexpected error during race: %v", err)
			}
		}(casedEmail)
	}

	// Release all goroutines at the exact same instant
	startBarrier.Done()
	doneWg.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 successful registration, got %d", successCount.Load())
	}
	if conflictCount.Load() != int32(concurrentAttempts-1) {
		t.Fatalf("expected %d conflict errors, got %d", concurrentAttempts-1, conflictCount.Load())
	}
	if otherErrors.Load() != 0 {
		t.Fatalf("expected 0 other errors, got %d", otherErrors.Load())
	}

	// Verify database row count
	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM accounts WHERE email = $1", strings.ToLower(targetEmail)).Scan(&count)
	if err != nil {
		t.Fatalf("failed to query count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row in DB, found %d", count)
	}
}

func TestPostgres_HTTPRegistrationEndToEnd(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	accountRepo := repo.NewAccountRepository(pool, 5*time.Second)
	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	uc := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil)
	discardLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	handler := delivery.NewHandler(discardLogger, pool, uc, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router := handler.Routes()

	// 1. Initial successful registration
	body := `{"email":"e2e.user@example.com","password":"valid-e2e-password-15"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify in DB that account exists with active status, email_verified=false and argon2id hash
	var (
		dbID            string
		dbEmail         string
		dbHash          string
		dbStatus        string
		dbEmailVerified bool
	)
	err := pool.QueryRow(context.Background(),
		"SELECT id, email, password_hash, status, email_verified FROM accounts WHERE email = 'e2e.user@example.com'").
		Scan(&dbID, &dbEmail, &dbHash, &dbStatus, &dbEmailVerified)
	if err != nil {
		t.Fatalf("failed to query inserted account: %v", err)
	}

	if dbEmail != "e2e.user@example.com" {
		t.Errorf("expected email e2e.user@example.com, got %s", dbEmail)
	}
	if dbStatus != "active" {
		t.Errorf("expected status active, got %s", dbStatus)
	}
	if dbEmailVerified != false {
		t.Errorf("expected email_verified false, got %v", dbEmailVerified)
	}
	if !strings.HasPrefix(dbHash, "$argon2id$") {
		t.Errorf("expected password_hash to start with $argon2id$, got %s", dbHash)
	}

	// 2. Duplicate registration returns 409
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate registration, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "account_exists") {
		t.Errorf("expected error code account_exists, got: %s", w2.Body.String())
	}

	// 3. Readiness check endpoint returns 200 OK
	wReady := httptest.NewRecorder()
	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(wReady, reqReady)

	if wReady.Code != http.StatusOK {
		t.Errorf("expected readyz 200 OK, got %d", wReady.Code)
	}
}
