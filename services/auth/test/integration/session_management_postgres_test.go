package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

func newUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("failed to generate random uuid: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// txInterceptorDB wraps PgxPoolExecutor to intercept transactions for testing without modifying production code.
type txInterceptorDB struct {
	repo.PgxPoolExecutor
	onBegin func(tx pgx.Tx) pgx.Tx
}

func (db *txInterceptorDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := db.PgxPoolExecutor.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if db.onBegin != nil {
		return db.onBegin(tx), nil
	}
	return tx, nil
}

// wrappedTx wraps pgx.Tx to inject faults or synchronization barriers prior to Commit.
type wrappedTx struct {
	pgx.Tx
	beforeCommit func(ctx context.Context, tx pgx.Tx) error
}

func (w *wrappedTx) Commit(ctx context.Context) error {
	if w.beforeCommit != nil {
		if err := w.beforeCommit(ctx, w.Tx); err != nil {
			_ = w.Rollback(ctx)
			return err
		}
	}
	return w.Tx.Commit(ctx)
}

// verifyLockWait verifies that blockedPID has entered PostgreSQL lock wait state (pg_locks WHERE NOT granted).
func verifyLockWait(ctx context.Context, pool *pgxpool.Pool, blockedPID uint32) error {
	if blockedPID == 0 {
		return errors.New("invalid blocked PID 0")
	}
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for pid %d to enter lock wait: %w", blockedPID, ctx.Err())
		case <-ticker.C:
			var waiting bool
			err := pool.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted
				)
			`, blockedPID).Scan(&waiting)
			if err == nil && waiting {
				return nil
			}
		}
	}
}

type raceCoordinator struct {
	tx1Ready   chan struct{}
	releaseTx1 chan struct{}
	tx2Started chan uint32
	mu         sync.Mutex
	isRacing   bool
	callCount  int
}

func newRaceCoordinator() *raceCoordinator {
	return &raceCoordinator{
		tx1Ready:   make(chan struct{}),
		releaseTx1: make(chan struct{}),
		tx2Started: make(chan uint32, 1),
	}
}

func (c *raceCoordinator) StartRacing() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isRacing = true
}

func (c *raceCoordinator) InterceptBegin(tx pgx.Tx) pgx.Tx {
	c.mu.Lock()
	if !c.isRacing {
		c.mu.Unlock()
		return tx
	}
	c.callCount++
	call := c.callCount
	c.mu.Unlock()

	if call == 1 {
		return &wrappedTx{
			Tx: tx,
			beforeCommit: func(ctx context.Context, innerTx pgx.Tx) error {
				close(c.tx1Ready)
				select {
				case <-c.releaseTx1:
					return nil
				case <-time.After(10 * time.Second):
					return errors.New("timed out waiting for releaseTx1 signal")
				}
			},
		}
	}
	if call == 2 {
		var pid uint32
		if conn := tx.Conn(); conn != nil && conn.PgConn() != nil {
			pid = conn.PgConn().PID()
		}
		select {
		case c.tx2Started <- pid:
		default:
		}
		return tx
	}
	return tx
}

func setupSessionMgmtTestHarnessWithDB(
	t *testing.T,
	wrapExecutor func(pool *pgxpool.Pool) repo.PgxPoolExecutor,
) (*pgxpool.Pool, *repo.AccountRepository, *repo.SessionRepository, *token.TokenService, *delivery.Handler, func()) {
	t.Helper()
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return nil, nil, nil, nil, nil, func() {}
	}

	var db repo.PgxPoolExecutor = pool
	if wrapExecutor != nil {
		db = wrapExecutor(pool)
	}

	accountRepo := repo.NewAccountRepository(pool, 10*time.Second)
	sessionRepo := repo.NewSessionRepository(db, 10*time.Second)

	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	dummyHash, err := hasher.Hash(context.Background(), "dummy-test-password")
	if err != nil {
		t.Fatalf("failed to create dummy hash: %v", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	tokenSvc, err := token.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-mgmt", privKey, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	refreshMgr := token.NewRefreshTokenManager()
	registerUC := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil, nil, nil, nil, 0)
	loginUC, err := usecase.NewLoginUsecase(accountRepo, sessionRepo, hasher, tokenSvc, refreshMgr, dummyHash, 10*time.Minute, 720*time.Hour, nil, nil)
	if err != nil {
		t.Fatalf("failed to create login usecase: %v", err)
	}
	refreshUC, err := usecase.NewRefreshUsecase(sessionRepo, tokenSvc, refreshMgr, nil, nil)
	if err != nil {
		t.Fatalf("failed to create refresh usecase: %v", err)
	}
	currentAccountUC, err := usecase.NewCurrentAccountUsecase(sessionRepo, nil)
	if err != nil {
		t.Fatalf("failed to create current account usecase: %v", err)
	}
	logoutUC, err := usecase.NewLogoutUsecase(sessionRepo, refreshMgr)
	if err != nil {
		t.Fatalf("failed to create logout usecase: %v", err)
	}

	listSessionsUC, err := usecase.NewListSessionsUsecase(sessionRepo)
	if err != nil {
		t.Fatalf("failed to create list sessions usecase: %v", err)
	}
	revokeSessionUC, err := usecase.NewRevokeSessionUsecase(sessionRepo)
	if err != nil {
		t.Fatalf("failed to create revoke session usecase: %v", err)
	}
	logoutAllUC, err := usecase.NewLogoutAllUsecase(sessionRepo)
	if err != nil {
		t.Fatalf("failed to create logout-all usecase: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := delivery.NewHandler(
		logger,
		pool,
		registerUC,
		loginUC,
		refreshUC,
		currentAccountUC,
		logoutUC,
		&testTokenAdapter{tokenSvc: tokenSvc},
		tokenSvc,
		nil,
		nil,
		nil,
	).WithSessionManagement(
		listSessionsUC,
		revokeSessionUC,
		logoutAllUC,
	)

	return pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup
}

func setupSessionMgmtTestHarness(t *testing.T) (*repo.AccountRepository, *repo.SessionRepository, *token.TokenService, *delivery.Handler, func()) {
	_, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, nil)
	return accountRepo, sessionRepo, tokenSvc, handler, cleanup
}

func createTestAccount(t *testing.T, accountRepo *repo.AccountRepository, email string) domain.Account {
	t.Helper()
	now := time.Now().UTC()
	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	hash, err := hasher.Hash(context.Background(), "password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	acc := domain.Account{
		ID:           newUUID(t),
		Email:        email,
		PasswordHash: hash,
		Status:       domain.AccountStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := accountRepo.Create(context.Background(), acc); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	return acc
}

func createTestSession(
	t *testing.T,
	sessionRepo *repo.SessionRepository,
	account domain.Account,
	createdAt, expiresAt time.Time,
	revokedAt *time.Time,
) domain.Session {
	t.Helper()
	sessID := newUUID(t)
	tokenID := newUUID(t)
	_, hash, err := token.NewRefreshTokenManager().Generate()
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}

	sess := domain.Session{
		ID:        sessID,
		AccountID: account.ID,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		RevokedAt: revokedAt,
	}
	initialToken := domain.RefreshToken{
		ID:        tokenID,
		SessionID: sessID,
		TokenHash: hash,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	err = sessionRepo.CreateWithInitialRefresh(context.Background(), sess, account.PasswordHash, initialToken)
	if err != nil {
		t.Fatalf("failed to insert test session: %v", err)
	}

	if revokedAt != nil {
		_, err = sessionRepo.Revoke(context.Background(), sessID, account.ID)
		if err != nil {
			t.Fatalf("failed to revoke test session: %v", err)
		}
	}

	return sess
}

func createTestSessionWithToken(
	t *testing.T,
	sessionRepo *repo.SessionRepository,
	account domain.Account,
	createdAt, expiresAt time.Time,
) (domain.Session, string) {
	t.Helper()
	sessID := newUUID(t)
	tokenID := newUUID(t)
	raw, hash, err := token.NewRefreshTokenManager().Generate()
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}

	sess := domain.Session{
		ID:        sessID,
		AccountID: account.ID,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	initialToken := domain.RefreshToken{
		ID:        tokenID,
		SessionID: sessID,
		TokenHash: hash,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	err = sessionRepo.CreateWithInitialRefresh(context.Background(), sess, account.PasswordHash, initialToken)
	if err != nil {
		t.Fatalf("failed to insert test session with refresh token: %v", err)
	}

	return sess, raw
}

func TestPostgres_Sessions_ListingAndPagination(t *testing.T) {
	accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarness(t)
	if accountRepo == nil {
		return
	}
	defer cleanup()

	router := handler.Routes()
	acc1 := createTestAccount(t, accountRepo, "user1@example.com")
	acc2 := createTestAccount(t, accountRepo, "user2@example.com")

	now := time.Now().UTC().Truncate(time.Microsecond)
	t1 := now.Add(-10 * time.Minute)
	t2 := now.Add(-5 * time.Minute) // shared timestamp for tie-breaking test
	t3 := now.Add(-1 * time.Minute)

	// Account 1 sessions:
	s1 := createTestSession(t, sessionRepo, acc1, t1, now.Add(24*time.Hour), nil)
	s2 := createTestSession(t, sessionRepo, acc1, t2, now.Add(24*time.Hour), nil)
	s3 := createTestSession(t, sessionRepo, acc1, t2, now.Add(24*time.Hour), nil) // same creation time as s2
	s4 := createTestSession(t, sessionRepo, acc1, t3, now.Add(24*time.Hour), nil)

	// Inactive sessions for Account 1:
	_ = createTestSession(t, sessionRepo, acc1, t1, now.Add(-1*time.Minute), nil) // expired
	revokedTime := now.Add(-2 * time.Minute)
	_ = createTestSession(t, sessionRepo, acc1, t1, now.Add(24*time.Hour), &revokedTime) // revoked

	// Foreign session for Account 2:
	_ = createTestSession(t, sessionRepo, acc2, t3, now.Add(24*time.Hour), nil)

	// Mint access token for s4 (current session)
	accessToken, _, _, err := tokenSvc.SignAccessToken(acc1.ID, s4.ID)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}

	// 1. Fetch first page with limit=2
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", w.Header().Get("Cache-Control"))
	}

	var page1 delivery.ListSessionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page1); err != nil {
		t.Fatalf("failed to decode page 1 response: %v", err)
	}
	if len(page1.Sessions) != 2 {
		t.Fatalf("expected 2 sessions on page 1, got %d", len(page1.Sessions))
	}
	if page1.NextCursor == nil || *page1.NextCursor == "" {
		t.Fatal("expected next_cursor on page 1")
	}

	// Verify s4 has Current=true and comes first (most recent created_at)
	if page1.Sessions[0].ID != s4.ID || !page1.Sessions[0].Current {
		t.Fatalf("expected first session to be current session %s, got %+v", s4.ID, page1.Sessions[0])
	}

	// 2. Fetch second page with limit=2 and cursor
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions?limit=2&cursor="+*page1.NextCursor, nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on page 2, got %d: %s", w2.Code, w2.Body.String())
	}

	var page2 delivery.ListSessionsResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &page2); err != nil {
		t.Fatalf("failed to decode page 2 response: %v", err)
	}
	if len(page2.Sessions) != 2 {
		t.Fatalf("expected 2 sessions on page 2, got %d", len(page2.Sessions))
	}

	// 3. Since exactly 4 active sessions exist and limit=2, page 2 retrieves the final 2 sessions
	// and its NextCursor must be null (lookahead found no 5th row).
	if page2.NextCursor != nil {
		t.Fatalf("expected null next_cursor on page 2 since all 4 sessions are exhausted, got %v", *page2.NextCursor)
	}

	// Verify all 4 sessions are unique across pages 1 and 2
	seen := make(map[string]bool)
	for _, s := range page1.Sessions {
		seen[s.ID] = true
	}
	for _, s := range page2.Sessions {
		if seen[s.ID] {
			t.Fatalf("duplicate session %s found across keyset pages!", s.ID)
		}
		seen[s.ID] = true
	}
	if !seen[s1.ID] || !seen[s2.ID] || !seen[s3.ID] || !seen[s4.ID] {
		t.Fatalf("expected all 4 sessions to be retrieved across pages, got seen=%v", seen)
	}
}

func TestPostgres_Sessions_RevokeTarget(t *testing.T) {
	accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarness(t)
	if accountRepo == nil {
		return
	}
	defer cleanup()

	router := handler.Routes()
	acc1 := createTestAccount(t, accountRepo, "target-u1@example.com")
	acc2 := createTestAccount(t, accountRepo, "target-u2@example.com")

	now := time.Now().UTC()
	s1 := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)
	s2 := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)
	sForeign := createTestSession(t, sessionRepo, acc2, now, now.Add(24*time.Hour), nil)

	token1, _, _, _ := tokenSvc.SignAccessToken(acc1.ID, s1.ID)

	// 1. Revoke s2 (owned target) -> 204
	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+s2.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on revoke, got %d", w.Code)
	}

	// 2. Repeat revoke on s2 (idempotent for owned) -> 204
	reqRepeat := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+s2.ID, nil)
	reqRepeat.Header.Set("Authorization", "Bearer "+token1)
	wRepeat := httptest.NewRecorder()
	router.ServeHTTP(wRepeat, reqRepeat)

	if wRepeat.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on repeat revoke, got %d", wRepeat.Code)
	}

	// 3. Attempt to revoke foreign session sForeign -> 404 session_not_found
	reqForeign := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+sForeign.ID, nil)
	reqForeign.Header.Set("Authorization", "Bearer "+token1)
	wForeign := httptest.NewRecorder()
	router.ServeHTTP(wForeign, reqForeign)

	if wForeign.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for foreign session revoke, got %d", wForeign.Code)
	}
	var errResp map[string]struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(wForeign.Body.Bytes(), &errResp)
	if errResp["error"].Code != "session_not_found" {
		t.Fatalf("expected code session_not_found, got %s", errResp["error"].Code)
	}

	// Foreign session sForeign remains active in DB
	sessForeignDB, _, err := sessionRepo.GetWithAccount(context.Background(), sForeign.ID)
	if err != nil || sessForeignDB.RevokedAt != nil {
		t.Fatalf("foreign session was modified or revoked!")
	}

	// 4. Revoke active session using uppercase UUID -> 204, session revoked in DB
	sUpper := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)
	reqUpper := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+strings.ToUpper(sUpper.ID), nil)
	reqUpper.Header.Set("Authorization", "Bearer "+token1)
	wUpper := httptest.NewRecorder()
	router.ServeHTTP(wUpper, reqUpper)

	if wUpper.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on uppercase UUID revoke, got %d: %s", wUpper.Code, wUpper.Body.String())
	}
	sUpperDB, _, err := sessionRepo.GetWithAccount(context.Background(), sUpper.ID)
	if err != nil || sUpperDB.RevokedAt == nil {
		t.Fatalf("expected session to be revoked in PostgreSQL after uppercase UUID revocation, got err=%v, revokedAt=%v", err, sUpperDB.RevokedAt)
	}

	// 5. Revoke current session s1 -> 204
	reqSelf := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+s1.ID, nil)
	reqSelf.Header.Set("Authorization", "Bearer "+token1)
	wSelf := httptest.NewRecorder()
	router.ServeHTTP(wSelf, reqSelf)

	if wSelf.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on self revoke, got %d", wSelf.Code)
	}

	// 5. Subsequent request using token1 returns 401
	reqAfter := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
	reqAfter.Header.Set("Authorization", "Bearer "+token1)
	wAfter := httptest.NewRecorder()
	router.ServeHTTP(wAfter, reqAfter)

	if wAfter.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after self revocation, got %d", wAfter.Code)
	}
}

func TestPostgres_Sessions_LogoutAll(t *testing.T) {
	accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarness(t)
	if accountRepo == nil {
		return
	}
	defer cleanup()

	router := handler.Routes()
	acc1 := createTestAccount(t, accountRepo, "logoutall-1@example.com")
	acc2 := createTestAccount(t, accountRepo, "logoutall-2@example.com")

	now := time.Now().UTC()
	s1 := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)
	s2 := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)
	s3 := createTestSession(t, sessionRepo, acc1, now, now.Add(24*time.Hour), nil)

	sOther := createTestSession(t, sessionRepo, acc2, now, now.Add(24*time.Hour), nil)

	token1, _, _, _ := tokenSvc.SignAccessToken(acc1.ID, s1.ID)

	// Call logout-all
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on logout-all, got %d", w.Code)
	}

	// All Account 1 sessions must be revoked in DB
	for _, s := range []domain.Session{s1, s2, s3} {
		sessDB, _, err := sessionRepo.GetWithAccount(context.Background(), s.ID)
		if err != nil {
			t.Fatalf("failed to query session %s: %v", s.ID, err)
		}
		if sessDB.RevokedAt == nil {
			t.Fatalf("session %s was not revoked by logout-all!", s.ID)
		}
	}

	// Account 2 session remains active
	sessOtherDB, _, err := sessionRepo.GetWithAccount(context.Background(), sOther.ID)
	if err != nil || sessOtherDB.RevokedAt != nil {
		t.Fatalf("other account session was affected by logout-all!")
	}

	// Repeat with same token returns 401
	wRepeat := httptest.NewRecorder()
	router.ServeHTTP(wRepeat, req)
	if wRepeat.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on repeat logout-all with revoked token, got %d", wRepeat.Code)
	}
}

func TestPostgres_Sessions_ConcurrentOppositeRevocation(t *testing.T) {
	accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarness(t)
	if accountRepo == nil {
		return
	}
	defer cleanup()

	router := handler.Routes()
	acc := createTestAccount(t, accountRepo, "oppo-race@example.com")

	now := time.Now().UTC()
	sessA := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
	sessB := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)

	tokenA, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sessA.ID)
	tokenB, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sessB.ID)

	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	var codeA, codeB int

	go func() {
		defer wg.Done()
		<-startBarrier
		// Session A revokes Session B
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+sessB.ID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		codeA = w.Code
	}()

	go func() {
		defer wg.Done()
		<-startBarrier
		// Session B revokes Session A
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+sessA.ID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenB)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		codeB = w.Code
	}()

	close(startBarrier)
	wg.Wait()

	// Exactly one must succeed with 204, and the other must discover its caller was revoked and return 401.
	// No deadlock (500/timeout) is allowed.
	if (codeA != 204 || codeB != 401) && (codeA != 401 || codeB != 204) {
		t.Fatalf("expected exactly one 204 and one 401, got codeA=%d, codeB=%d", codeA, codeB)
	}

	// Verify database state: only the losing caller's session is revoked, the winning caller remains active.
	dbA, _, err := sessionRepo.GetWithAccount(context.Background(), sessA.ID)
	if err != nil {
		t.Fatalf("failed to query sessA: %v", err)
	}
	dbB, _, err := sessionRepo.GetWithAccount(context.Background(), sessB.ID)
	if err != nil {
		t.Fatalf("failed to query sessB: %v", err)
	}

	if codeA == 204 {
		// A won, so A revoked B. A remains active, B is revoked.
		if dbA.RevokedAt != nil {
			t.Fatalf("expected winning caller sessA to remain active, but was revoked")
		}
		if dbB.RevokedAt == nil {
			t.Fatalf("expected target sessB to be revoked, but was active")
		}
	} else {
		// B won, so B revoked A. B remains active, A is revoked.
		if dbB.RevokedAt != nil {
			t.Fatalf("expected winning caller sessB to remain active, but was revoked")
		}
		if dbA.RevokedAt == nil {
			t.Fatalf("expected target sessA to be revoked, but was active")
		}
	}
}

func TestPostgres_Sessions_ConcurrentRefreshAndLogoutAll(t *testing.T) {
	t.Run("order1_refresh_holds_lock_before_logout_all", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "refresh-holds-logoutall@example.com")
		now := time.Now().UTC()
		sess1 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		sess2, rawRefresh := createTestSessionWithToken(t, sessionRepo, acc, now, now.Add(24*time.Hour))
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sess1.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var refreshCode int
		var logoutCode int
		var refreshedAccess string

		coord.StartRacing()

		// Goroutine 1: Refresh acquires locks, updates token, and holds before commit
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"refresh_token":%q}`, rawRefresh)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			refreshCode = w.Code

			var resp struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			refreshedAccess = resp.AccessToken
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for refresh tx to hold locks before commit")
		}

		// Goroutine 2: Logout-all attempts execution while Refresh holds locks
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			logoutCode = w.Code
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for logout-all tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("logout-all failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Refresh) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if refreshCode != http.StatusOK {
			t.Fatalf("expected refresh to return 200 OK, got %d", refreshCode)
		}
		if logoutCode != http.StatusNoContent {
			t.Fatalf("expected logout-all to return 204 No Content, got %d", logoutCode)
		}

		// Refresh preserves sess2 ID; Logout-All revokes all sessions including caller sess1 and refreshed sess2
		s1DB, _, _ := sessionRepo.GetWithAccount(context.Background(), sess1.ID)
		s2DB, _, _ := sessionRepo.GetWithAccount(context.Background(), sess2.ID)
		if s1DB.RevokedAt == nil || s2DB.RevokedAt == nil {
			t.Fatalf("sessions were not revoked after logout-all: s1=%v, s2=%v", s1DB.RevokedAt, s2DB.RevokedAt)
		}

		if refreshedAccess != "" {
			reqCheck := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
			reqCheck.Header.Set("Authorization", "Bearer "+refreshedAccess)
			wCheck := httptest.NewRecorder()
			router.ServeHTTP(wCheck, reqCheck)
			if wCheck.Code != http.StatusUnauthorized {
				t.Fatalf("expected rotated access token to be unauthorized after logout-all, got %d", wCheck.Code)
			}
		}
	})

	t.Run("order2_logout_all_holds_lock_before_refresh", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "logoutall-holds-refresh@example.com")
		now := time.Now().UTC()
		sess1 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		_, rawRefresh := createTestSessionWithToken(t, sessionRepo, acc, now, now.Add(24*time.Hour))
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sess1.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var logoutCode int
		var refreshCode int

		coord.StartRacing()

		// Goroutine 1: Logout-all acquires locks, updates sessions, and holds before commit
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			logoutCode = w.Code
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for logout-all tx to hold locks before commit")
		}

		// Goroutine 2: Refresh attempts rotation while Logout-all holds locks
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"refresh_token":%q}`, rawRefresh)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			refreshCode = w.Code
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for refresh tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("refresh failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Logout-all) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if logoutCode != http.StatusNoContent {
			t.Fatalf("expected logout-all to return 204 No Content, got %d", logoutCode)
		}
		if refreshCode != http.StatusUnauthorized {
			t.Fatalf("expected refresh to return 401 Unauthorized after session revoked by logout-all, got %d", refreshCode)
		}
	})
}

func TestPostgres_Sessions_ConcurrentRefreshAndSingleRevoke(t *testing.T) {
	t.Run("order1_refresh_holds_lock_before_single_revoke", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "refresh-holds-revoke@example.com")
		now := time.Now().UTC()
		sessCaller := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		sessTarget, rawRefresh := createTestSessionWithToken(t, sessionRepo, acc, now, now.Add(24*time.Hour))
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sessCaller.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var refreshCode int
		var revokeCode int

		coord.StartRacing()

		// Goroutine 1: Refresh acquires lock on sessTarget and holds before commit
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"refresh_token":%q}`, rawRefresh)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			refreshCode = w.Code
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for refresh tx to hold lock before commit")
		}

		// Goroutine 2: Revoke target session while Refresh holds target lock
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+sessTarget.ID, nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			revokeCode = w.Code
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for revoke tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("revoke failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Refresh) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if refreshCode != http.StatusOK {
			t.Fatalf("expected refresh to return 200 OK, got %d", refreshCode)
		}
		if revokeCode != http.StatusNoContent {
			t.Fatalf("expected revoke to return 204 No Content, got %d", revokeCode)
		}

		sessDB, _, _ := sessionRepo.GetWithAccount(context.Background(), sessTarget.ID)
		if sessDB.RevokedAt == nil {
			t.Fatal("expected target session to be revoked in DB")
		}
	})

	t.Run("order2_single_revoke_holds_lock_before_refresh", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "revoke-holds-refresh@example.com")
		now := time.Now().UTC()
		sessCaller := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		sessTarget, rawRefresh := createTestSessionWithToken(t, sessionRepo, acc, now, now.Add(24*time.Hour))
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, sessCaller.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var revokeCode int
		var refreshCode int

		coord.StartRacing()

		// Goroutine 1: Single-Revoke acquires lock on sessTarget, updates revoked_at, and holds before commit
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+sessTarget.ID, nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			revokeCode = w.Code
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for revoke tx to hold lock before commit")
		}

		// Goroutine 2: Refresh attempts rotation while Single-Revoke holds target lock
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"refresh_token":%q}`, rawRefresh)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			refreshCode = w.Code
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for refresh tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("refresh failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Single-Revoke) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if revokeCode != http.StatusNoContent {
			t.Fatalf("expected revoke to return 204 No Content, got %d", revokeCode)
		}
		if refreshCode != http.StatusUnauthorized {
			t.Fatalf("expected refresh to return 401 Unauthorized after target revoked, got %d", refreshCode)
		}
	})
}

func TestPostgres_Sessions_ConcurrentLoginAndLogoutAll(t *testing.T) {
	t.Run("order1_login_holds_lock_before_logout_all", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "login-holds-logoutall@example.com")
		now := time.Now().UTC()
		callerSess := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, callerSess.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var loginCode int
		var logoutCode int
		var createdSessID string

		coord.StartRacing()

		// Goroutine 1: Login locks account, inserts session, and holds before commit
		go func() {
			defer wg.Done()
			loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, acc.Email, "password123")
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			loginCode = w.Code

			var resp struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.AccessToken != "" {
				claims, _ := tokenSvc.VerifyAccessToken(resp.AccessToken)
				createdSessID = claims.SessionID
			}
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for login tx to hold lock before commit")
		}

		// Goroutine 2: Logout-all attempts execution while Login holds account lock
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			logoutCode = w.Code
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for logout-all tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("logout-all failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Login) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if loginCode != http.StatusOK {
			t.Fatalf("expected login to return 200 OK, got %d", loginCode)
		}
		if logoutCode != http.StatusNoContent {
			t.Fatalf("expected logout-all to return 204 No Content, got %d", logoutCode)
		}

		if createdSessID == "" {
			t.Fatal("expected session to be created by login")
		}
		// The session created by login was committed before logout-all unblocked, so it must now be revoked
		sessDB, _, err := sessionRepo.GetWithAccount(context.Background(), createdSessID)
		if err != nil || sessDB.RevokedAt == nil {
			t.Fatalf("expected session created before logout-all to be revoked, got err=%v, revokedAt=%v", err, sessDB.RevokedAt)
		}
	})

	t.Run("order2_logout_all_holds_lock_before_login", func(t *testing.T) {
		coord := newRaceCoordinator()
		pool, accountRepo, sessionRepo, tokenSvc, handler, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
			return &txInterceptorDB{
				PgxPoolExecutor: p,
				onBegin:         coord.InterceptBegin,
			}
		})
		if pool == nil {
			return
		}
		defer cleanup()

		router := handler.Routes()
		acc := createTestAccount(t, accountRepo, "logoutall-holds-login@example.com")
		now := time.Now().UTC()
		callerSess := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		callerToken, _, _, _ := tokenSvc.SignAccessToken(acc.ID, callerSess.ID)

		var wg sync.WaitGroup
		wg.Add(2)

		var logoutCode int
		var loginCode int
		var newSessID string

		coord.StartRacing()

		// Goroutine 1: Logout-all locks account, revokes sessions, and holds before commit
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
			req.Header.Set("Authorization", "Bearer "+callerToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			logoutCode = w.Code
		}()

		select {
		case <-coord.tx1Ready:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for logout-all tx to hold lock before commit")
		}

		// Goroutine 2: Login attempts execution while Logout-all holds account lock
		go func() {
			defer wg.Done()
			loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, acc.Email, "password123")
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			loginCode = w.Code

			var resp struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.AccessToken != "" {
				claims, _ := tokenSvc.VerifyAccessToken(resp.AccessToken)
				newSessID = claims.SessionID
			}
		}()

		var tx2PID uint32
		select {
		case tx2PID = <-coord.tx2Started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for login tx to start")
		}

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := verifyLockWait(waitCtx, pool, tx2PID); err != nil {
			t.Fatalf("login failed to enter PostgreSQL lock wait: %v", err)
		}

		// Release Goroutine 1 (Logout-all) to commit
		close(coord.releaseTx1)

		wg.Wait()

		if logoutCode != http.StatusNoContent {
			t.Fatalf("expected logout-all to return 204 No Content, got %d", logoutCode)
		}
		if loginCode != http.StatusOK {
			t.Fatalf("expected login to return 200 OK, got %d", loginCode)
		}

		if newSessID == "" {
			t.Fatal("expected session to be created by login")
		}
		// The session created by login occurred AFTER logout-all committed, so it must be active (revoked_at IS NULL)
		sessDB, _, err := sessionRepo.GetWithAccount(context.Background(), newSessID)
		if err != nil || sessDB.RevokedAt != nil {
			t.Fatalf("expected session created after logout-all to remain active, got err=%v, revokedAt=%v", err, sessDB.RevokedAt)
		}
	})
}

func TestPostgres_Sessions_RevocationRollbackOnFailure(t *testing.T) {
	var hookFn func(ctx context.Context, tx pgx.Tx) error
	var hookMu sync.Mutex

	pool, accountRepo, sessionRepo, _, _, cleanup := setupSessionMgmtTestHarnessWithDB(t, func(p *pgxpool.Pool) repo.PgxPoolExecutor {
		return &txInterceptorDB{
			PgxPoolExecutor: p,
			onBegin: func(tx pgx.Tx) pgx.Tx {
				return &wrappedTx{
					Tx: tx,
					beforeCommit: func(ctx context.Context, innerTx pgx.Tx) error {
						hookMu.Lock()
						fn := hookFn
						hookMu.Unlock()
						if fn != nil {
							return fn(ctx, innerTx)
						}
						return nil
					},
				}
			},
		}
	})
	if pool == nil {
		return
	}
	defer cleanup()

	t.Run("single_target_revocation_rollback_after_mutation", func(t *testing.T) {
		acc := createTestAccount(t, accountRepo, "rollback-single@example.com")
		now := time.Now().UTC()
		sess1 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		sess2 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)

		hookCalled := false
		hookMu.Lock()
		hookFn = func(ctx context.Context, tx pgx.Tx) error {
			hookCalled = true
			// CRITICAL ASSERTION: verify that inside the transaction, the mutation HAS ALREADY occurred!
			var revokedAtInsideTx *time.Time
			err := tx.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", sess2.ID).Scan(&revokedAtInsideTx)
			if err != nil {
				return fmt.Errorf("querying revoked_at inside transaction: %w", err)
			}
			if revokedAtInsideTx == nil {
				return errors.New("mutation did not take place yet inside transaction")
			}
			// Inject failure to force rollback after the UPDATE statement executed
			return errors.New("injected post-mutation failure before commit")
		}
		hookMu.Unlock()
		defer func() {
			hookMu.Lock()
			hookFn = nil
			hookMu.Unlock()
		}()

		_, err := sessionRepo.RevokeSessionTarget(context.Background(), acc.ID, sess1.ID, sess2.ID)
		if err == nil || !strings.Contains(err.Error(), "injected post-mutation failure") {
			t.Fatalf("expected injected failure error, got: %v", err)
		}
		if !hookCalled {
			t.Fatal("expected hookFn to be called")
		}

		// Verify sess2 remains completely active in PostgreSQL (mutation was rolled back!)
		sess2DB, _, err := sessionRepo.GetWithAccount(context.Background(), sess2.ID)
		if err != nil {
			t.Fatalf("failed to query sess2: %v", err)
		}
		if sess2DB.RevokedAt != nil {
			t.Fatalf("sess2 was revoked despite transaction rollback! revoked_at: %v", sess2DB.RevokedAt)
		}
	})

	t.Run("logout_all_rollback_after_mutation", func(t *testing.T) {
		acc := createTestAccount(t, accountRepo, "rollback-all@example.com")
		now := time.Now().UTC()
		sess1 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)
		sess2 := createTestSession(t, sessionRepo, acc, now, now.Add(24*time.Hour), nil)

		hookCalled := false
		hookMu.Lock()
		hookFn = func(ctx context.Context, tx pgx.Tx) error {
			hookCalled = true
			// CRITICAL ASSERTION: verify all sessions were updated inside tx before rollback
			var unrevokedCount int
			err := tx.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE account_id = $1 AND revoked_at IS NULL", acc.ID).Scan(&unrevokedCount)
			if err != nil {
				return fmt.Errorf("counting unrevoked sessions inside tx: %w", err)
			}
			if unrevokedCount != 0 {
				return fmt.Errorf("expected 0 unrevoked sessions inside tx after UPDATE, got %d", unrevokedCount)
			}
			return errors.New("injected post-mutation logout-all failure before commit")
		}
		hookMu.Unlock()
		defer func() {
			hookMu.Lock()
			hookFn = nil
			hookMu.Unlock()
		}()

		err := sessionRepo.RevokeAllSessions(context.Background(), acc.ID, sess1.ID)
		if err == nil || !strings.Contains(err.Error(), "injected post-mutation logout-all failure") {
			t.Fatalf("expected injected failure error, got: %v", err)
		}
		if !hookCalled {
			t.Fatal("expected hookFn to be called")
		}

		// Verify both sessions remain completely active in PostgreSQL
		s1DB, _, _ := sessionRepo.GetWithAccount(context.Background(), sess1.ID)
		s2DB, _, _ := sessionRepo.GetWithAccount(context.Background(), sess2.ID)
		if s1DB.RevokedAt != nil || s2DB.RevokedAt != nil {
			t.Fatalf("sessions were revoked despite logout-all rollback! s1=%v, s2=%v", s1DB.RevokedAt, s2DB.RevokedAt)
		}
	})
}
