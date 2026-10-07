package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

type mockAccountRepo struct {
	accounts map[string]domain.Account // email -> account
}

func (m *mockAccountRepo) Create(ctx context.Context, account domain.Account) error {
	m.accounts[account.Email] = account
	return nil
}

func (m *mockAccountRepo) GetByEmail(ctx context.Context, email string) (domain.Account, error) {
	acc, exists := m.accounts[email]
	if !exists {
		return domain.Account{}, domain.ErrAccountNotFound
	}
	return acc, nil
}

type mockSessionRepo struct {
	sessions map[string]domain.Session // sessionID -> session
	accounts map[string]domain.Account // accountID -> account
}

func (m *mockSessionRepo) CreateAtomic(ctx context.Context, session domain.Session, expectedHash string) error {
	acc, exists := m.accounts[session.AccountID]
	if !exists || acc.Status != domain.AccountStatusActive || acc.PasswordHash != expectedHash {
		return domain.ErrInvalidCredentials
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepo) CreateWithInitialRefresh(ctx context.Context, session domain.Session, expectedHash string, initialToken domain.RefreshToken) error {
	acc, exists := m.accounts[session.AccountID]
	if !exists || acc.Status != domain.AccountStatusActive || acc.PasswordHash != expectedHash {
		return domain.ErrInvalidCredentials
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepo) GetWithAccount(ctx context.Context, sessionID string) (domain.Session, domain.Account, error) {
	sess, exists := m.sessions[sessionID]
	if !exists {
		return domain.Session{}, domain.Account{}, domain.ErrSessionNotFound
	}
	acc := m.accounts[sess.AccountID]
	return sess, acc, nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, sessionID string, accountID string) (bool, error) {
	sess, exists := m.sessions[sessionID]
	if !exists || sess.AccountID != accountID {
		return false, domain.ErrSessionNotFound
	}
	if sess.RevokedAt != nil {
		return true, nil // already revoked
	}
	now := time.Now()
	sess.RevokedAt = &now
	m.sessions[sessionID] = sess
	return false, nil
}

func (m *mockSessionRepo) RevokeByRefreshTokenHash(ctx context.Context, tokenHash []byte) (bool, error) {
	return false, nil
}

func (m *mockSessionRepo) RotateRefreshToken(ctx context.Context, presentedHash []byte, successorToken domain.RefreshToken, signFn SignSuccessorCallback) (*RotationResult, error) {
	return &RotationResult{}, nil
}

type mockVerifier struct {
	verifyCalls []struct {
		password string
		phcHash  string
	}
	matchResult bool
	verifyErr   error
}

func (m *mockVerifier) Verify(ctx context.Context, password string, phcHash string) (bool, error) {
	m.verifyCalls = append(m.verifyCalls, struct {
		password string
		phcHash  string
	}{password: password, phcHash: phcHash})
	if m.verifyErr != nil {
		return false, m.verifyErr
	}
	return m.matchResult, nil
}

type mockTokenSigner struct {
	tokenToReturn string
	expiresAt     time.Time
}

func (m *mockTokenSigner) SignAccessToken(subject, sessionID string) (string, time.Time, int64, error) {
	expAt := m.expiresAt
	if expAt.IsZero() {
		expAt = time.Now().Add(10 * time.Minute).Truncate(time.Second)
	}
	return m.tokenToReturn, expAt, 600, nil
}

func (m *mockTokenSigner) SignAccessTokenWithExpiry(subject, sessionID string, maxExpiry time.Time) (string, time.Time, int64, error) {
	return m.SignAccessToken(subject, sessionID)
}

type fixedUUIDGen struct {
	id string
}

func (f fixedUUIDGen) Generate() (string, error) {
	return f.id, nil
}

type mockClock struct {
	now time.Time
}

func (m mockClock) Now() time.Time {
	return m.now
}

type mockRefreshTokenManager struct {
	rawToken  string
	tokenHash []byte
	genErr    error
	valErr    error
}

func (m *mockRefreshTokenManager) Generate() (string, []byte, error) {
	if m.genErr != nil {
		return "", nil, m.genErr
	}
	raw := m.rawToken
	if raw == "" {
		raw = "mock-refresh-token-43-chars-long-test123abc"
	}
	hash := m.tokenHash
	if len(hash) == 0 {
		hash = []byte("12345678901234567890123456789012")
	}
	return raw, hash, nil
}

func (m *mockRefreshTokenManager) ValidateAndHash(rawToken string) ([]byte, error) {
	if m.valErr != nil {
		return nil, m.valErr
	}
	if len(m.tokenHash) > 0 {
		return m.tokenHash, nil
	}
	return []byte("12345678901234567890123456789012"), nil
}

func TestLoginUsecase_Success(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{now: now}
	accID := "11111111-1111-4111-8111-111111111111"
	sessID := "22222222-2222-4222-8222-222222222222"

	acc := domain.Account{
		ID:           accID,
		Email:        "user@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=1$fake$storedhash",
		Status:       domain.AccountStatusActive,
	}

	accRepo := &mockAccountRepo{accounts: map[string]domain.Account{acc.Email: acc}}
	sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: map[string]domain.Account{acc.ID: acc}}
	verifier := &mockVerifier{matchResult: true}
	signer := &mockTokenSigner{tokenToReturn: "mock.jwt.token"}

	dummyHash := "$argon2id$v=19$m=65536,t=3,p=1$fake$dummyhash"
	uc, err := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, dummyHash, 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: sessID}, clock)
	if err != nil {
		t.Fatalf("failed to create usecase: %v", err)
	}

	out, err := uc.Execute(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "ValidPassword123",
	})
	if err != nil {
		t.Fatalf("expected login success, got error: %v", err)
	}

	if out.AccessToken != "mock.jwt.token" {
		t.Errorf("expected access token mock.jwt.token, got %s", out.AccessToken)
	}
	if out.ExpiresIn != 600 {
		t.Errorf("expected expiresIn 600, got %d", out.ExpiresIn)
	}
	if len(verifier.verifyCalls) != 1 || verifier.verifyCalls[0].phcHash != acc.PasswordHash {
		t.Errorf("expected verify call with user's stored hash, got calls: %+v", verifier.verifyCalls)
	}
	if sess, exists := sessRepo.sessions[sessID]; !exists || sess.AccountID != accID {
		t.Errorf("expected session %s to be persisted for account %s", sessID, accID)
	}
}

func TestLoginUsecase_MissingAccountRunsDummyVerification(t *testing.T) {
	accRepo := &mockAccountRepo{accounts: make(map[string]domain.Account)}
	sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: make(map[string]domain.Account)}
	verifier := &mockVerifier{matchResult: false}
	signer := &mockTokenSigner{tokenToReturn: "token"}

	dummyHash := "$argon2id$v=19$m=65536,t=3,p=1$fake$dummyhash"
	uc, err := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, dummyHash, 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: "id"}, nil)
	if err != nil {
		t.Fatalf("failed to create usecase: %v", err)
	}

	_, err = uc.Execute(context.Background(), LoginInput{
		Email:    "nonexistent@example.com",
		Password: "some-password-123",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}

	// Verify that dummy hash verification was executed to mitigate timing differences
	if len(verifier.verifyCalls) != 1 {
		t.Fatalf("expected 1 verify call on dummy hash, got %d", len(verifier.verifyCalls))
	}
	if verifier.verifyCalls[0].phcHash != dummyHash {
		t.Errorf("expected verify against dummy hash %s, got %s", dummyHash, verifier.verifyCalls[0].phcHash)
	}
}

func TestLoginUsecase_DisabledAccountRunsStoredHashVerification(t *testing.T) {
	accID := "11111111-1111-4111-8111-111111111111"
	storedHash := "$argon2id$v=19$m=65536,t=3,p=1$fake$disabledhash"
	acc := domain.Account{
		ID:           accID,
		Email:        "disabled@example.com",
		PasswordHash: storedHash,
		Status:       domain.AccountStatusDisabled,
	}

	accRepo := &mockAccountRepo{accounts: map[string]domain.Account{acc.Email: acc}}
	sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: map[string]domain.Account{acc.ID: acc}}
	verifier := &mockVerifier{matchResult: true}
	signer := &mockTokenSigner{tokenToReturn: "token"}

	dummyHash := "$argon2id$v=19$m=65536,t=3,p=1$fake$dummyhash"
	uc, err := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, dummyHash, 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: "id"}, nil)
	if err != nil {
		t.Fatalf("failed to create usecase: %v", err)
	}

	_, err = uc.Execute(context.Background(), LoginInput{
		Email:    "disabled@example.com",
		Password: "user-password-123",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}

	// Per specification: must verify against the user's actual stored hash
	if len(verifier.verifyCalls) != 1 {
		t.Fatalf("expected 1 verify call for disabled account, got %d", len(verifier.verifyCalls))
	}
	if verifier.verifyCalls[0].phcHash != storedHash {
		t.Errorf("expected verify against user's actual stored hash %s, got %s", storedHash, verifier.verifyCalls[0].phcHash)
	}
}

func TestLoginUsecase_BoundaryAndMalformedPasswords(t *testing.T) {
	accRepo := &mockAccountRepo{accounts: make(map[string]domain.Account)}
	sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: make(map[string]domain.Account)}
	verifier := &mockVerifier{matchResult: false}
	signer := &mockTokenSigner{tokenToReturn: "token"}

	dummyHash := "$argon2id$v=19$m=65536,t=3,p=1$fake$dummyhash"
	uc, _ := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, dummyHash, 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: "id"}, nil)

	tests := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"too long in runes (>128)", strings.Repeat("a", 129)},
		{"too long in bytes (>512)", strings.Repeat("世", 175)}, // 175 * 3 = 525 bytes
		{"invalid utf8", string([]byte{0xff, 0xfe, 0xfd})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), LoginInput{
				Email:    "user@example.com",
				Password: tc.password,
			})
			if !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Errorf("expected ErrInvalidCredentials for %s, got: %v", tc.name, err)
			}
		})
	}
}

func TestCurrentAccountUsecase(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := mockClock{now: now}
	accID := "11111111-1111-4111-8111-111111111111"
	sessID := "22222222-2222-4222-8222-222222222222"

	acc := domain.Account{ID: accID, Email: "user@example.com", Status: domain.AccountStatusActive}
	sess := domain.Session{ID: sessID, AccountID: accID, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}

	sessRepo := &mockSessionRepo{
		sessions: map[string]domain.Session{sessID: sess},
		accounts: map[string]domain.Account{accID: acc},
	}

	uc, err := NewCurrentAccountUsecase(sessRepo, clock)
	if err != nil {
		t.Fatalf("failed to create usecase: %v", err)
	}

	// 1. Success
	retrieved, err := uc.Execute(context.Background(), accID, sessID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != accID {
		t.Errorf("expected account ID %s, got %s", accID, retrieved.ID)
	}

	// 2. Mismatched account ID
	_, err = uc.Execute(context.Background(), "wrong-account-id", sessID)
	if !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for mismatched account ID, got: %v", err)
	}

	// 3. Expired session
	expiredSessID := "33333333-3333-4333-8333-333333333333"
	sessRepo.sessions[expiredSessID] = domain.Session{
		ID:        expiredSessID,
		AccountID: accID,
		CreatedAt: now.Add(-20 * time.Minute),
		ExpiresAt: now.Add(-10 * time.Minute),
	}
	_, err = uc.Execute(context.Background(), accID, expiredSessID)
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got: %v", err)
	}

	// 4. Revoked session
	revokedSessID := "44444444-4444-4444-8444-444444444444"
	revokedAt := now.Add(-1 * time.Minute)
	sessRepo.sessions[revokedSessID] = domain.Session{
		ID:        revokedSessID,
		AccountID: accID,
		CreatedAt: now.Add(-5 * time.Minute),
		ExpiresAt: now.Add(5 * time.Minute),
		RevokedAt: &revokedAt,
	}
	_, err = uc.Execute(context.Background(), accID, revokedSessID)
	if !errors.Is(err, domain.ErrSessionRevoked) {
		t.Errorf("expected ErrSessionRevoked, got: %v", err)
	}
}

func TestLogoutUsecase(t *testing.T) {
	accID := "11111111-1111-4111-8111-111111111111"
	sessID := "22222222-2222-4222-8222-222222222222"

	sessRepo := &mockSessionRepo{
		sessions: map[string]domain.Session{
			sessID: {ID: sessID, AccountID: accID, ExpiresAt: time.Now().Add(10 * time.Minute)},
		},
		accounts: make(map[string]domain.Account),
	}

	uc, err := NewLogoutUsecase(sessRepo, &mockRefreshTokenManager{})
	if err != nil {
		t.Fatalf("failed to create logout usecase: %v", err)
	}

	// 1. First logout succeeds
	if err := uc.Execute(context.Background(), accID, sessID); err != nil {
		t.Fatalf("expected logout success, got: %v", err)
	}

	// 2. Repeat logout succeeds (idempotent 204)
	if err := uc.Execute(context.Background(), accID, sessID); err != nil {
		t.Fatalf("expected repeat logout success (idempotent), got: %v", err)
	}

	// 3. Unknown session returns ErrSessionNotFound
	if err := uc.Execute(context.Background(), accID, "unknown-session-id"); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for unknown session, got: %v", err)
	}
}

func TestLoginUsecase_SessionExpiresAtMatchesJWTExactly(t *testing.T) {
	accID := "11111111-1111-4111-8111-111111111111"
	sessID := "22222222-2222-4222-8222-222222222222"
	fixedExp := time.Date(2026, 10, 5, 12, 10, 0, 0, time.UTC)

	acc := domain.Account{
		ID:           accID,
		Email:        "user@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=1$fake$hash",
		Status:       domain.AccountStatusActive,
	}

	accRepo := &mockAccountRepo{accounts: map[string]domain.Account{acc.Email: acc}}
	sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: map[string]domain.Account{acc.ID: acc}}
	verifier := &mockVerifier{matchResult: true}
	signer := &mockTokenSigner{tokenToReturn: "token", expiresAt: fixedExp}

	uc, err := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, "dummy", 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: sessID}, nil)
	if err != nil {
		t.Fatalf("create usecase: %v", err)
	}

	_, err = uc.Execute(context.Background(), LoginInput{Email: "user@example.com", Password: "Password123"})
	if err != nil {
		t.Fatalf("execute login: %v", err)
	}

	sess := sessRepo.sessions[sessID]
	if sess.ExpiresAt.Before(time.Now().Add(719 * time.Hour)) {
		t.Errorf("expected session ExpiresAt to match sessionTTL (approx 720h), got %v", sess.ExpiresAt)
	}
}

func TestLoginUsecase_VerifierErrorPropagation(t *testing.T) {
	accID := "11111111-1111-4111-8111-111111111111"
	sessID := "22222222-2222-4222-8222-222222222222"

	t.Run("dummy_verification_unexpected_error_is_propagated", func(t *testing.T) {
		accRepo := &mockAccountRepo{accounts: make(map[string]domain.Account)}
		sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: make(map[string]domain.Account)}
		verifier := &mockVerifier{verifyErr: errors.New("argon2 allocation failed")}
		signer := &mockTokenSigner{tokenToReturn: "token"}

		uc, _ := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, "dummy", 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: sessID}, nil)
		_, err := uc.Execute(context.Background(), LoginInput{Email: "notfound@example.com", Password: "Password123"})
		if err == nil || errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("expected system verification error to be propagated, got: %v", err)
		}
	})

	t.Run("disabled_account_verification_error_is_propagated", func(t *testing.T) {
		acc := domain.Account{
			ID:           accID,
			Email:        "disabled@example.com",
			PasswordHash: "corrupted_phc",
			Status:       domain.AccountStatusDisabled,
		}
		accRepo := &mockAccountRepo{accounts: map[string]domain.Account{acc.Email: acc}}
		sessRepo := &mockSessionRepo{sessions: make(map[string]domain.Session), accounts: map[string]domain.Account{acc.ID: acc}}
		verifier := &mockVerifier{verifyErr: domain.ErrInternalCredentialFailure}
		signer := &mockTokenSigner{tokenToReturn: "token"}

		uc, _ := NewLoginUsecase(accRepo, sessRepo, verifier, signer, &mockRefreshTokenManager{}, "dummy", 10*time.Minute, 720*time.Hour, fixedUUIDGen{id: sessID}, nil)
		_, err := uc.Execute(context.Background(), LoginInput{Email: "disabled@example.com", Password: "Password123"})
		if err == nil || errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("expected verifier error for disabled account to be propagated, got: %v", err)
		}
	})
}
