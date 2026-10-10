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

	"github.com/jackc/pgx/v5/pgxpool"

	delivery "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
	repo "github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockPastClock struct {
	pastTime time.Time
}

func (m *mockPastClock) Now() time.Time {
	return m.pastTime
}

type testHarness struct {
	router      http.Handler
	tokenSvc    *token.TokenService
	privKey     ed25519.PrivateKey
	accountRepo *repo.AccountRepository
	sessionRepo *repo.SessionRepository
	loginUC     *usecase.LoginUsecase
	refreshUC   *usecase.RefreshUsecase
	logoutUC    *usecase.LogoutUsecase
}

func setupTestHarness(t *testing.T, pool *pgxpool.Pool) (*testHarness, error) {
	t.Helper()
	ctx := context.Background()
	accountRepo := repo.NewAccountRepository(pool, 5*time.Second)
	sessionRepo := repo.NewSessionRepository(pool, 5*time.Second)

	hasher := password.NewArgon2idHasherWithParams(1024, 1, 1, 16, 32, 2)
	dummyHash, err := hasher.Hash(ctx, "dummy-test-password")
	if err != nil {
		return nil, fmt.Errorf("creating dummy hash: %w", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	tokenSvc, err := token.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-1", privKey, nil, 10*time.Minute, nil)
	if err != nil {
		return nil, fmt.Errorf("creating token service: %w", err)
	}

	refreshMgr := token.NewRefreshTokenManager()
	registerUC := usecase.NewRegisterUsecase(accountRepo, hasher, nil, nil, nil, nil, nil, 0)
	loginUC, err := usecase.NewLoginUsecase(accountRepo, sessionRepo, hasher, tokenSvc, refreshMgr, dummyHash, 10*time.Minute, 720*time.Hour, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating login usecase: %w", err)
	}
	refreshUC, err := usecase.NewRefreshUsecase(sessionRepo, tokenSvc, refreshMgr, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating refresh usecase: %w", err)
	}
	meUC, _ := usecase.NewCurrentAccountUsecase(sessionRepo, nil)
	logoutUC, _ := usecase.NewLogoutUsecase(sessionRepo, refreshMgr)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := delivery.NewHandler(logger, nil, registerUC, loginUC, refreshUC, meUC, logoutUC, &testTokenAdapter{tokenSvc: tokenSvc}, tokenSvc, nil, nil, nil)
	router := handler.Routes()

	return &testHarness{
		router:      router,
		tokenSvc:    tokenSvc,
		privKey:     privKey,
		accountRepo: accountRepo,
		sessionRepo: sessionRepo,
		loginUC:     loginUC,
		refreshUC:   refreshUC,
		logoutUC:    logoutUC,
	}, nil
}

type authCredentials struct {
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int64
	RefreshExpiresIn int64
	AccountID        string
}

func registerAndLogin(t *testing.T, h *testHarness, email, password string) authCredentials {
	t.Helper()

	// 1. Register
	regBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	regReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	h.router.ServeHTTP(wReg, regReq)
	if wReg.Code != http.StatusCreated {
		t.Fatalf("registration failed: code %d, body %s", wReg.Code, wReg.Body.String())
	}

	// 2. Login
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	h.router.ServeHTTP(wLogin, loginReq)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("login failed: code %d, body %s", wLogin.Code, wLogin.Body.String())
	}

	var resp struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
		Account          struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(wLogin.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}

	return authCredentials{
		AccessToken:      resp.AccessToken,
		RefreshToken:     resp.RefreshToken,
		ExpiresIn:        resp.ExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn,
		AccountID:        resp.Account.ID,
	}
}

// TestPostgres_Refresh_SuccessfulRotation verifies that rotating a valid refresh token:
// 1. Returns new access and refresh credentials with positive expirations.
// 2. Marks the previous token as consumed and inserts the successor.
// 3. Maintains the same stable session id across rotated access JWTs.
// 4. Clamps access token expiration so /me continues to accept it.
func TestPostgres_Refresh_SuccessfulRotation(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "rotate.success@example.com", "valid-password-123")
	claims1, err := h.tokenSvc.VerifyAccessToken(creds.AccessToken)
	if err != nil {
		t.Fatalf("failed to verify initial access token: %v", err)
	}

	// Perform refresh
	refreshBody := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var rotResp struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rotResp); err != nil {
		t.Fatalf("failed to parse refresh response: %v", err)
	}

	if rotResp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", rotResp.TokenType)
	}
	if rotResp.ExpiresIn <= 0 || rotResp.RefreshExpiresIn <= 0 {
		t.Errorf("expected positive expirations, got access %d, refresh %d", rotResp.ExpiresIn, rotResp.RefreshExpiresIn)
	}
	if rotResp.RefreshToken == creds.RefreshToken {
		t.Errorf("successor refresh token must differ from presented token")
	}

	claims2, err := h.tokenSvc.VerifyAccessToken(rotResp.AccessToken)
	if err != nil {
		t.Fatalf("failed to verify rotated access token: %v", err)
	}

	// Stable sid and sub across rotation
	if claims2.Subject != claims1.Subject {
		t.Errorf("expected stable subject %s, got %s", claims1.Subject, claims2.Subject)
	}
	if claims2.SessionID != claims1.SessionID {
		t.Errorf("expected stable session ID %s, got %s", claims1.SessionID, claims2.SessionID)
	}
	if claims2.TokenID == claims1.TokenID {
		t.Errorf("new access token must have unique jti")
	}

	// Verify DB state: exactly 1 consumed token and 1 unconsumed token in family
	var consumedCount, activeCount int
	ctx := context.Background()
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM refresh_tokens WHERE session_id = $1 AND consumed_at IS NOT NULL", claims1.SessionID).Scan(&consumedCount)
	if err != nil {
		t.Fatalf("failed to query consumed tokens: %v", err)
	}
	if consumedCount != 1 {
		t.Errorf("expected exactly 1 consumed token, got %d", consumedCount)
	}

	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM refresh_tokens WHERE session_id = $1 AND consumed_at IS NULL", claims1.SessionID).Scan(&activeCount)
	if err != nil {
		t.Fatalf("failed to query active tokens: %v", err)
	}
	if activeCount != 1 {
		t.Errorf("expected exactly 1 active token, got %d", activeCount)
	}

	// Verify /me accepts new access token
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+rotResp.AccessToken)
	wMe := httptest.NewRecorder()
	h.router.ServeHTTP(wMe, meReq)
	if wMe.Code != http.StatusOK {
		t.Errorf("expected /me to return 200 OK with rotated token, got %d", wMe.Code)
	}
}

// TestPostgres_Refresh_ReplayRevocationPersists verifies that replaying an already consumed
// refresh token causes the entire session family to be permanently revoked and committed in DB,
// immediately invalidating both the successor refresh token and active access tokens.
func TestPostgres_Refresh_ReplayRevocationPersists(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "replay.persist@example.com", "valid-password-123")

	// 1. Initial valid rotation: creds.RefreshToken -> successorToken
	refreshBody1 := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(refreshBody1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	h.router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first rotation failed: %d", w1.Code)
	}

	var rotResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &rotResp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// 2. Replay token: present creds.RefreshToken a second time
	reqReplay := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(refreshBody1))
	reqReplay.Header.Set("Content-Type", "application/json")
	wReplay := httptest.NewRecorder()
	h.router.ServeHTTP(wReplay, reqReplay)

	// Replay must return generic 401 Unauthorized without disclosing replay detection
	if wReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected generic 401 Unauthorized on replay, got %d: %s", wReplay.Code, wReplay.Body.String())
	}

	// 3. Verify session revocation is permanently committed to DB
	ctx := context.Background()
	claims, _ := h.tokenSvc.VerifyAccessToken(rotResp.AccessToken)
	var revokedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("failed to query session row: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("session family MUST be revoked in DB upon replay detection")
	}

	// 4. Successor refresh token must now fail with 401
	refreshBody2 := fmt.Sprintf(`{"refresh_token":%q}`, rotResp.RefreshToken)
	reqSuccessor := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(refreshBody2))
	reqSuccessor.Header.Set("Content-Type", "application/json")
	wSuccessor := httptest.NewRecorder()
	h.router.ServeHTTP(wSuccessor, reqSuccessor)
	if wSuccessor.Code != http.StatusUnauthorized {
		t.Errorf("expected successor refresh to fail with 401 after family revocation, got %d", wSuccessor.Code)
	}

	// 5. Active access token must now fail on /v1/auth/me because session was revoked
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+rotResp.AccessToken)
	wMe := httptest.NewRecorder()
	h.router.ServeHTTP(wMe, meReq)
	if wMe.Code != http.StatusUnauthorized {
		t.Errorf("expected /me to reject access token after family revocation, got %d", wMe.Code)
	}
}

// TestPostgres_Refresh_ConcurrentSameTokenRace verifies that when 10 goroutines race to
// refresh using the exact same refresh token concurrently:
// 1. At most 1 rotation can succeed.
// 2. Competing requests detect the replay and revoke the entire family.
// 3. Further refresh is completely blocked.
func TestPostgres_Refresh_ConcurrentSameTokenRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "concurrent.race@example.com", "valid-password-123")

	numWorkers := 10
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	statusCodes := make([]int, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			body := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.router.ServeHTTP(w, req)
			statusCodes[workerID] = w.Code
		}(i)
	}

	// Release all workers simultaneously
	close(startBarrier)
	wg.Wait()

	var successCount, unauthorizedCount int
	for _, code := range statusCodes {
		switch code {
		case http.StatusOK:
			successCount++
		case http.StatusUnauthorized:
			unauthorizedCount++
		default:
			t.Errorf("unexpected status code in race: %d", code)
		}
	}

	if successCount != 1 {
		t.Fatalf("strictly 1 concurrent refresh must succeed (200 OK), but %d succeeded (unauthorized=%d)", successCount, unauthorizedCount)
	}
	if unauthorizedCount != numWorkers-1 {
		t.Fatalf("expected exactly %d workers to receive 401 Unauthorized, got %d", numWorkers-1, unauthorizedCount)
	}

	// After all requests complete, verify family is revoked in DB due to replay from concurrent callers
	ctx := context.Background()
	claims, _ := h.tokenSvc.VerifyAccessToken(creds.AccessToken)
	var revokedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("failed to query session status: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("expected session family to be revoked after concurrent replay race")
	}
}

// TestPostgres_Refresh_ConcurrentWithLogoutRace verifies that under concurrent refresh and logout requests:
// After both requests finish, the family is revoked and further refresh is prohibited.
// (Refresh may succeed first, but logout will subsequently revoke the family).
func TestPostgres_Refresh_ConcurrentWithLogoutRace(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "race.logout@example.com", "valid-password-123")

	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	var refreshCode int
	var logoutCode int
	var rotatedRefreshToken string

	// Goroutine 1: Refresh
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startBarrier

		body := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.router.ServeHTTP(w, req)
		refreshCode = w.Code
		if w.Code == http.StatusOK {
			var resp struct {
				RefreshToken string `json:"refresh_token"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			rotatedRefreshToken = resp.RefreshToken
		}
	}()

	// Goroutine 2: Logout (using Bearer access token)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startBarrier

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
		w := httptest.NewRecorder()
		h.router.ServeHTTP(w, req)
		logoutCode = w.Code
	}()

	close(startBarrier)
	wg.Wait()

	// Logout should succeed with 204 No Content
	if logoutCode != http.StatusNoContent {
		t.Fatalf("logout expected 204 No Content, got %d", logoutCode)
	}

	// Refresh may have succeeded (200) before logout or failed (401) after logout. Both are acceptable.
	if refreshCode != http.StatusOK && refreshCode != http.StatusUnauthorized {
		t.Fatalf("refresh returned unexpected code: %d", refreshCode)
	}

	// Verification condition: after both requests complete, the family MUST be revoked in DB!
	ctx := context.Background()
	claims, _ := h.tokenSvc.VerifyAccessToken(creds.AccessToken)
	var revokedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("failed to query session status: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("session family MUST be revoked after refresh vs logout completion")
	}

	// And further refresh attempts must fail with 401
	tokenToTry := creds.RefreshToken
	if rotatedRefreshToken != "" {
		tokenToTry = rotatedRefreshToken
	}
	tryBody := fmt.Sprintf(`{"refresh_token":%q}`, tokenToTry)
	tryReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(tryBody))
	tryReq.Header.Set("Content-Type", "application/json")
	wTry := httptest.NewRecorder()
	h.router.ServeHTTP(wTry, tryReq)
	if wTry.Code != http.StatusUnauthorized {
		t.Errorf("further refresh after logout MUST return 401, got %d", wTry.Code)
	}
}

// TestPostgres_Refresh_FamilyIsolation verifies that revoking or compromising session family A
// does not affect session family B for the same user account.
func TestPostgres_Refresh_FamilyIsolation(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	// Register account
	credsA := registerAndLogin(t, h, "isolation@example.com", "valid-password-123")

	// Login a second time to create family B
	loginBody := `{"email":"isolation@example.com","password":"valid-password-123"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	h.router.ServeHTTP(wLogin, loginReq)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("second login failed: %d", wLogin.Code)
	}

	var credsB struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(wLogin.Body.Bytes(), &credsB)

	// Revoke Family A via logout
	logoutReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+credsA.AccessToken)
	wLogout := httptest.NewRecorder()
	h.router.ServeHTTP(wLogout, logoutReq)
	if wLogout.Code != http.StatusNoContent {
		t.Fatalf("logout A failed: %d", wLogout.Code)
	}

	// Family A refresh must now fail
	reqA := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, credsA.RefreshToken)))
	reqA.Header.Set("Content-Type", "application/json")
	wA := httptest.NewRecorder()
	h.router.ServeHTTP(wA, reqA)
	if wA.Code != http.StatusUnauthorized {
		t.Errorf("family A refresh expected 401, got %d", wA.Code)
	}

	// Family B must remain active and rotate successfully
	reqB := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, credsB.RefreshToken)))
	reqB.Header.Set("Content-Type", "application/json")
	wB := httptest.NewRecorder()
	h.router.ServeHTTP(wB, reqB)
	if wB.Code != http.StatusOK {
		t.Errorf("family B refresh expected 200, got %d: %s", wB.Code, wB.Body.String())
	}
}

// TestPostgres_Logout_DualModes verifies both Bearer mode and Refresh mode:
// 1. Bearer mode with access token.
// 2. Ambiguous credentials with empty or non-empty Authorization header rejected with 400 invalid_request.
// 3. Refresh mode without access token (specifically after access token expiry).
// 4. Repeated logout with refresh token is idempotent 204.
// 5. Unknown refresh token returns 401.
func TestPostgres_Logout_DualModes(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "dualmodes@example.com", "valid-password-123")
	claims, err := h.tokenSvc.VerifyAccessToken(creds.AccessToken)
	if err != nil {
		t.Fatalf("failed to verify access token: %v", err)
	}

	// 1. Ambiguous credentials (valid Bearer header and refresh body) rejected with 400 invalid_request
	ambiguousReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)))
	ambiguousReq.Header.Set("Authorization", "Bearer "+creds.AccessToken)
	ambiguousReq.Header.Set("Content-Type", "application/json")
	wAmbiguous := httptest.NewRecorder()
	h.router.ServeHTTP(wAmbiguous, ambiguousReq)
	if wAmbiguous.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ambiguous credentials, got %d", wAmbiguous.Code)
	}
	var errRespAmbiguous struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wAmbiguous.Body.Bytes(), &errRespAmbiguous)
	if errRespAmbiguous.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespAmbiguous.Error.Code)
	}

	// 2. Ambiguous credentials with empty Authorization header also rejected with 400 invalid_request
	emptyAuthReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)))
	emptyAuthReq.Header.Set("Authorization", "   ")
	emptyAuthReq.Header.Set("Content-Type", "application/json")
	wEmptyAuth := httptest.NewRecorder()
	h.router.ServeHTTP(wEmptyAuth, emptyAuthReq)
	if wEmptyAuth.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty Authorization header + body, got %d", wEmptyAuth.Code)
	}
	var errRespEmptyAuth struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(wEmptyAuth.Body.Bytes(), &errRespEmptyAuth)
	if errRespEmptyAuth.Error.Code != "invalid_request" {
		t.Errorf("expected error code 'invalid_request', got %s", errRespEmptyAuth.Error.Code)
	}

	// 3. Verify logout via refresh mode AFTER access token has expired:
	// Generate an expired access token using a token service backdated by 2 hours
	pastClock := &mockPastClock{pastTime: time.Now().Add(-2 * time.Hour)}
	expiredTokenSvc, err := token.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-1", h.privKey, nil, 10*time.Minute, pastClock)
	if err != nil {
		t.Fatalf("failed to create expired token service: %v", err)
	}
	expiredAccessToken, _, _, err := expiredTokenSvc.SignAccessToken(creds.AccountID, claims.SessionID)
	if err != nil {
		t.Fatalf("failed to sign expired access token: %v", err)
	}

	// Verify Bearer logout with expired access token fails with 401 Unauthorized
	expiredBearerReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	expiredBearerReq.Header.Set("Authorization", "Bearer "+expiredAccessToken)
	wExpiredBearer := httptest.NewRecorder()
	h.router.ServeHTTP(wExpiredBearer, expiredBearerReq)
	if wExpiredBearer.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired bearer token, got %d", wExpiredBearer.Code)
	}

	// Verify refresh mode logout without Bearer token succeeds with 204 No Content
	refreshLogoutReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)))
	refreshLogoutReq.Header.Set("Content-Type", "application/json")
	wRefreshLogout := httptest.NewRecorder()
	h.router.ServeHTTP(wRefreshLogout, refreshLogoutReq)
	if wRefreshLogout.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for refresh logout after access expiry, got %d: %s", wRefreshLogout.Code, wRefreshLogout.Body.String())
	}

	// Verify session is indeed revoked in DB
	var revokedAt *time.Time
	err = pool.QueryRow(context.Background(), "SELECT revoked_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("failed to query session status: %v", err)
	}
	if revokedAt == nil {
		t.Errorf("expected session to be revoked in DB after refresh logout")
	}

	// 4. Idempotent repeated logout with same refresh token returns 204
	wRepeat := httptest.NewRecorder()
	refreshLogoutReq2 := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)))
	refreshLogoutReq2.Header.Set("Content-Type", "application/json")
	h.router.ServeHTTP(wRepeat, refreshLogoutReq2)
	if wRepeat.Code != http.StatusNoContent {
		t.Errorf("expected idempotent 204 for repeat refresh logout, got %d", wRepeat.Code)
	}

	// 5. Unknown refresh token returns 401
	unknownBody := `{"refresh_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	unknownReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(unknownBody))
	unknownReq.Header.Set("Content-Type", "application/json")
	wUnknown := httptest.NewRecorder()
	h.router.ServeHTTP(wUnknown, unknownReq)
	if wUnknown.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown refresh token, got %d", wUnknown.Code)
	}
}

// TestPostgres_Refresh_DisabledAccount verifies that disabling the account causes refresh to fail with 401.
func TestPostgres_Refresh_DisabledAccount(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "disabled.account@example.com", "valid-password-123")

	// Disable account in DB
	ctx := context.Background()
	_, err = pool.Exec(ctx, "UPDATE accounts SET status = 'disabled' WHERE id = $1", creds.AccountID)
	if err != nil {
		t.Fatalf("failed to disable account: %v", err)
	}

	// Attempt refresh
	body := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled account, got %d", w.Code)
	}
}

// TestPostgres_Refresh_SignerExpLeqIatRollback verifies that when the real TokenService signer
// determines exp <= iat (e.g. session expiration is not strictly after signer's current integer second),
// it returns ErrSessionExpired. RotateRefreshToken catches this, rolls back the transaction, returns
// generic ErrInvalidCredentials (401), leaves the presented refresh token unconsumed, and inserts no successor.
//
// The test is made 100% deterministic by keeping the database session completely valid (long TTL),
// while configuring the TokenService signer callback with a fixed clock set to the session's expiration timestamp,
// asserting that the signer callback was actually called and returned domain.ErrSessionExpired,
// and verifying full rollback in PostgreSQL.
func TestPostgres_Refresh_SignerExpLeqIatRollback(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "rollback.iat@example.com", "valid-password-123")
	presentedHash, err := token.ValidateAndHashRefreshToken(creds.RefreshToken)
	if err != nil {
		t.Fatalf("failed to hash token: %v", err)
	}

	claims, err := h.tokenSvc.VerifyAccessToken(creds.AccessToken)
	if err != nil {
		t.Fatalf("failed to verify access token: %v", err)
	}

	ctx := context.Background()

	// Keep the database session valid: verify that session expires_at is far in the future
	var dbSessionExpiresAt time.Time
	err = pool.QueryRow(ctx, "SELECT expires_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&dbSessionExpiresAt)
	if err != nil {
		t.Fatalf("failed to query session expiry: %v", err)
	}
	if !dbSessionExpiresAt.After(time.Now().UTC().Add(24 * time.Hour)) {
		t.Fatalf("expected database session to remain valid with long TTL, got expires_at: %v", dbSessionExpiresAt)
	}

	// Create a real TokenService with a fixed clock set to dbSessionExpiresAt.
	// Under this fixed clock, now.Unix() == dbSessionExpiresAt.Unix(), so when clamped to maxExpiry (dbSessionExpiresAt),
	// exp == iat, causing TokenService.SignAccessTokenWithExpiry to deterministically return domain.ErrSessionExpired.
	fixedSignerClock := &mockPastClock{pastTime: dbSessionExpiresAt}
	expSigner, err := token.NewTokenService("gatekeeper-auth", "gatekeeper-services", "key-test-1", h.privKey, nil, 10*time.Minute, fixedSignerClock)
	if err != nil {
		t.Fatalf("failed to create TokenService with fixed clock: %v", err)
	}

	successorToken := domain.RefreshToken{
		ID:        "99999999-9999-4999-8999-999999999999",
		TokenHash: []byte("thirty-two-bytes-successor-hash!"),
	}

	var callbackCalled bool
	var capturedSignErr error

	// Real signer callback delegating directly to the real TokenService with fixed clock
	realSignFn := func(accountID, sessionID string, sessionExpiresAt time.Time) (string, time.Time, int64, error) {
		callbackCalled = true
		tok, exp, expIn, signErr := expSigner.SignAccessTokenWithExpiry(accountID, sessionID, sessionExpiresAt)
		capturedSignErr = signErr
		return tok, exp, expIn, signErr
	}

	_, rotErr := h.sessionRepo.RotateRefreshToken(ctx, presentedHash, successorToken, realSignFn)

	// Assert that the real signer callback was called and returned ErrSessionExpired
	if !callbackCalled {
		t.Fatal("expected real signer callback to be called during RotateRefreshToken")
	}
	if !errors.Is(capturedSignErr, domain.ErrSessionExpired) {
		t.Fatalf("expected real signer callback to return domain.ErrSessionExpired, got: %v", capturedSignErr)
	}

	// Assert that repository mapped it to generic 401 domain.ErrInvalidCredentials
	if !errors.Is(rotErr, domain.ErrInvalidCredentials) {
		t.Fatalf("expected RotateRefreshToken to return ErrInvalidCredentials on exp <= iat rollback, got: %v", rotErr)
	}

	// Verify rollback: presented token is NOT consumed in DB
	var consumedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT consumed_at FROM refresh_tokens WHERE token_hash = $1", presentedHash).Scan(&consumedAt)
	if err != nil {
		t.Fatalf("failed to query presented token: %v", err)
	}
	if consumedAt != nil {
		t.Errorf("expected presented token to remain unconsumed after rollback, got %v", consumedAt)
	}

	// Verify successor was NOT inserted
	var successorCount int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM refresh_tokens WHERE id = $1", successorToken.ID).Scan(&successorCount)
	if err != nil {
		t.Fatalf("failed to query successor count: %v", err)
	}
	if successorCount != 0 {
		t.Errorf("successor token must not be inserted on rollback")
	}

	// Verify session was NOT revoked
	var revokedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT revoked_at FROM sessions WHERE id = $1", claims.SessionID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("failed to query session status: %v", err)
	}
	if revokedAt != nil {
		t.Errorf("expected session to remain unrevoked on rollback, got %v", revokedAt)
	}
}

// TestPostgres_Refresh_SuccessorInsertFailureRollback verifies that if inserting the successor token
// fails (e.g. unique constraint violation on successor ID/hash), the transaction rolls back, and
// the old presented refresh token remains unconsumed, valid, and fully usable for a subsequent refresh.
func TestPostgres_Refresh_SuccessorInsertFailureRollback(t *testing.T) {
	pool, _, cleanup := setupDisposableTestDB(t)
	if pool == nil {
		return
	}
	defer cleanup()

	h, err := setupTestHarness(t, pool)
	if err != nil {
		t.Fatalf("failed to setup harness: %v", err)
	}

	creds := registerAndLogin(t, h, "rollback.insert@example.com", "valid-password-123")
	presentedHash, err := token.ValidateAndHashRefreshToken(creds.RefreshToken)
	if err != nil {
		t.Fatalf("failed to hash token: %v", err)
	}

	ctx := context.Background()

	// Query existing refresh token record to get its primary key ID
	var existingTokenID string
	err = pool.QueryRow(ctx, "SELECT id FROM refresh_tokens WHERE token_hash = $1", presentedHash).Scan(&existingTokenID)
	if err != nil {
		t.Fatalf("failed to query existing token id: %v", err)
	}

	// Prepare a successor token with duplicate ID (colliding with existingTokenID) to force INSERT failure
	collidingSuccessor := domain.RefreshToken{
		ID:        existingTokenID,
		TokenHash: []byte("thirty-two-bytes-successor-hash!"),
	}

	normalSignFn := func(accountID, sessionID string, sessionExpiresAt time.Time) (string, time.Time, int64, error) {
		return h.tokenSvc.SignAccessTokenWithExpiry(accountID, sessionID, sessionExpiresAt)
	}

	// Attempt rotation directly via repository
	_, rotErr := h.sessionRepo.RotateRefreshToken(ctx, presentedHash, collidingSuccessor, normalSignFn)
	if rotErr == nil {
		t.Fatal("expected RotateRefreshToken to fail due to primary key conflict on successor insertion")
	}

	// Verify transaction rolled back: presented token's consumed_at is still NULL
	var consumedAt *time.Time
	err = pool.QueryRow(ctx, "SELECT consumed_at FROM refresh_tokens WHERE token_hash = $1", presentedHash).Scan(&consumedAt)
	if err != nil {
		t.Fatalf("failed to query presented token: %v", err)
	}
	if consumedAt != nil {
		t.Fatalf("expected presented token to remain unconsumed after insert failure rollback, got: %v", consumedAt)
	}

	// CRITICAL REQUIREMENT: verify old refresh token remains valid and usable!
	refreshBody := fmt.Sprintf(`{"refresh_token":%q}`, creds.RefreshToken)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected old refresh token to remain usable and return 200 OK after rollback, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse refresh response: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Errorf("expected non-empty rotated credentials, got %+v", resp)
	}
}
