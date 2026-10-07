package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	authmiddleware "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http/middleware"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type testTokenAdapter struct {
	tokenSvc *token.TokenService
}

func (a *testTokenAdapter) VerifyToken(ctx context.Context, tokenString string) (authmiddleware.AuthIdentity, error) {
	claims, err := a.tokenSvc.VerifyAccessToken(tokenString)
	if err != nil {
		return authmiddleware.AuthIdentity{}, err
	}
	return authmiddleware.AuthIdentity{
		AccountID: claims.Subject,
		SessionID: claims.SessionID,
	}, nil
}

func TestPostgres_LoginAndSessionEndToEnd(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	accountRepo := repo.NewAccountRepository(pool, 5*time.Second)
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)

	// Use fast parameters for tests
	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	dummyHash, err := hasher.Hash(ctx, "dummy-test-password")
	if err != nil {
		t.Fatalf("failed to create dummy hash: %v", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	tokenSvc, err := token.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-1", privKey, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	refreshMgr := token.NewRefreshTokenManager()
	registerUC := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil)
	loginUC, err := usecase.NewLoginUsecase(accountRepo, sessionRepo, hasher, tokenSvc, refreshMgr, dummyHash, 10*time.Minute, 720*time.Hour, nil, nil)
	if err != nil {
		t.Fatalf("failed to create login usecase: %v", err)
	}
	refreshUC, err := usecase.NewRefreshUsecase(sessionRepo, tokenSvc, refreshMgr, nil, nil)
	if err != nil {
		t.Fatalf("failed to create refresh usecase: %v", err)
	}
	meUC, _ := usecase.NewCurrentAccountUsecase(sessionRepo, nil)
	logoutUC, _ := usecase.NewLogoutUsecase(sessionRepo, refreshMgr)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, pool, registerUC, loginUC, refreshUC, meUC, logoutUC, &testTokenAdapter{tokenSvc: tokenSvc}, tokenSvc, nil, nil, nil)
	router := handler.Routes()

	// 1. Register new account
	regBody := `{"email":"test.session@example.com","password":"valid-password-123"}`
	regReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	router.ServeHTTP(wReg, regReq)
	if wReg.Code != http.StatusCreated {
		t.Fatalf("registration failed: %d: %s", wReg.Code, wReg.Body.String())
	}

	// 2. Login to obtain access token
	loginBody := `{"email":"test.session@example.com","password":"valid-password-123"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	router.ServeHTTP(wLogin, loginReq)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", wLogin.Code, wLogin.Body.String())
	}

	var loginResp struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
		Account          struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"account"`
	}
	if err := json.Unmarshal(wLogin.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if loginResp.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if loginResp.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if loginResp.RefreshExpiresIn <= 0 {
		t.Fatalf("expected positive refresh_expires_in, got %d", loginResp.RefreshExpiresIn)
	}

	// Verify session and initial refresh token were created in the database
	var sessCount int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE account_id = $1 AND revoked_at IS NULL", loginResp.Account.ID).Scan(&sessCount)
	if err != nil {
		t.Fatalf("failed to query sessions table: %v", err)
	}
	if sessCount != 1 {
		t.Errorf("expected 1 active session in DB, got %d", sessCount)
	}

	var refreshCount int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM refresh_tokens rt JOIN sessions s ON s.id = rt.session_id WHERE s.account_id = $1 AND rt.consumed_at IS NULL", loginResp.Account.ID).Scan(&refreshCount)
	if err != nil {
		t.Fatalf("failed to query refresh_tokens table: %v", err)
	}
	if refreshCount != 1 {
		t.Errorf("expected 1 active unconsumed refresh token in DB, got %d", refreshCount)
	}

	// 3. Call /v1/auth/me with Bearer token -> 200 OK
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	wMe := httptest.NewRecorder()
	router.ServeHTTP(wMe, meReq)
	if wMe.Code != http.StatusOK {
		t.Fatalf("expected /me to return 200 OK, got %d: %s", wMe.Code, wMe.Body.String())
	}

	var meResp struct {
		Account struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"account"`
	}
	if err := json.Unmarshal(wMe.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("failed to decode /me response: %v", err)
	}
	if meResp.Account.ID != loginResp.Account.ID {
		t.Errorf("expected account ID %s, got %s", loginResp.Account.ID, meResp.Account.ID)
	}

	// 4. Logout -> 204 No Content
	logoutReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	wLogout := httptest.NewRecorder()
	router.ServeHTTP(wLogout, logoutReq)
	if wLogout.Code != http.StatusNoContent {
		t.Fatalf("expected /logout to return 204 No Content, got %d: %s", wLogout.Code, wLogout.Body.String())
	}

	// 5. Subsequent /v1/auth/me with the same token must fail with 401 Unauthorized
	wMeAfter := httptest.NewRecorder()
	router.ServeHTTP(wMeAfter, meReq)
	if wMeAfter.Code != http.StatusUnauthorized {
		t.Fatalf("expected /me after logout to return 401 Unauthorized, got %d: %s", wMeAfter.Code, wMeAfter.Body.String())
	}

	// 6. Repeat logout with same token returns 204 (idempotent)
	wLogoutRepeat := httptest.NewRecorder()
	router.ServeHTTP(wLogoutRepeat, logoutReq)
	if wLogoutRepeat.Code != http.StatusNoContent {
		t.Fatalf("expected repeat logout to return 204 No Content, got %d: %s", wLogoutRepeat.Code, wLogoutRepeat.Body.String())
	}
}

func TestPostgres_SessionCrossAccountRevocationForbidden(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)

	// Create two accounts in DB
	accID1 := "11111111-1111-4111-8111-111111111111"
	accID2 := "22222222-2222-4222-8222-222222222222"
	now := time.Now().UTC()

	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, 'user1@example.com', 'hash1', 'active', false, $3, $3),
		       ($2, 'user2@example.com', 'hash2', 'active', false, $3, $3)
	`, accID1, accID2, now)
	if err != nil {
		t.Fatalf("failed to insert accounts: %v", err)
	}

	// Create session for user 1
	sessID1 := "33333333-3333-4333-8333-333333333333"
	sess1 := domain.Session{
		ID:        sessID1,
		AccountID: accID1,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	if err := sessionRepo.CreateAtomic(ctx, sess1, "hash1"); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// User 2 attempts to revoke User 1's session
	_, err = sessionRepo.Revoke(ctx, sessID1, accID2)
	if err == nil {
		t.Fatal("expected error when revoking another user's session, got nil")
	}
	if err != domain.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got: %v", err)
	}

	// Verify User 1's session remains active
	retrievedSess, _, err := sessionRepo.GetWithAccount(ctx, sessID1)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if retrievedSess.RevokedAt != nil {
		t.Error("expected session 1 to remain unrevoked")
	}
}

func TestPostgres_SessionAtomicAccountDisableCheck(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)

	accID := "55555555-5555-4555-8555-555555555555"
	now := time.Now().UTC()

	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, email, password_hash, status, email_verified, created_at, updated_at)
		VALUES ($1, 'disabled.test@example.com', 'storedhash123', 'active', false, $2, $2)
	`, accID, now)
	if err != nil {
		t.Fatalf("failed to insert account: %v", err)
	}

	// 1. Success when active and hash matches
	sessID1 := "66666666-6666-4666-8666-666666666666"
	sess1 := domain.Session{
		ID:        sessID1,
		AccountID: accID,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	if err := sessionRepo.CreateAtomic(ctx, sess1, "storedhash123"); err != nil {
		t.Fatalf("expected successful atomic session creation: %v", err)
	}

	// 2. Disable account concurrently in DB
	_, err = pool.Exec(ctx, "UPDATE accounts SET status = 'disabled' WHERE id = $1", accID)
	if err != nil {
		t.Fatalf("failed to disable account: %v", err)
	}

	// Attempting to create session for disabled account must fail atomically
	sessID2 := "77777777-7777-4777-8777-777777777777"
	sess2 := domain.Session{
		ID:        sessID2,
		AccountID: accID,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	err = sessionRepo.CreateAtomic(ctx, sess2, "storedhash123")
	if err == nil {
		t.Fatal("expected atomic session creation to fail for disabled account")
	}
	if err != domain.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}

	// 3. Reactivate account but update password hash
	_, err = pool.Exec(ctx, "UPDATE accounts SET status = 'active', password_hash = 'newhash456' WHERE id = $1", accID)
	if err != nil {
		t.Fatalf("failed to update account hash: %v", err)
	}

	// Attempting to create session with old hash must fail atomically
	sessID3 := "88888888-8888-4888-8888-888888888888"
	sess3 := domain.Session{
		ID:        sessID3,
		AccountID: accID,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	err = sessionRepo.CreateAtomic(ctx, sess3, "storedhash123")
	if err == nil {
		t.Fatal("expected atomic session creation to fail for changed password hash")
	}
	if err != domain.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}
