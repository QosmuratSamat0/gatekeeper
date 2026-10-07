package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/token"
)

type mockRefreshSessionRepo struct {
	rotateResult   *RotationResult
	rotateErr      error
	capturedSignFn SignSuccessorCallback
}

func (m *mockRefreshSessionRepo) CreateAtomic(ctx context.Context, session domain.Session, expectedHash string) error {
	return nil
}

func (m *mockRefreshSessionRepo) CreateWithInitialRefresh(ctx context.Context, session domain.Session, expectedHash string, initialToken domain.RefreshToken) error {
	return nil
}

func (m *mockRefreshSessionRepo) GetWithAccount(ctx context.Context, sessionID string) (domain.Session, domain.Account, error) {
	return domain.Session{}, domain.Account{}, nil
}

func (m *mockRefreshSessionRepo) Revoke(ctx context.Context, sessionID string, accountID string) (bool, error) {
	return false, nil
}

func (m *mockRefreshSessionRepo) RevokeByRefreshTokenHash(ctx context.Context, tokenHash []byte) (bool, error) {
	return false, nil
}

func (m *mockRefreshSessionRepo) RotateRefreshToken(
	ctx context.Context,
	presentedHash []byte,
	successorToken domain.RefreshToken,
	signFn SignSuccessorCallback,
) (*RotationResult, error) {
	m.capturedSignFn = signFn
	if m.rotateErr != nil {
		return nil, m.rotateErr
	}
	return m.rotateResult, nil
}

func TestRefreshUsecase_Success(t *testing.T) {
	validToken, _, err := token.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	expectedResult := &RotationResult{
		AccessToken:      "mock.new.jwt",
		AccessTokenExp:   time.Now().Add(10 * time.Minute),
		ExpiresIn:        600,
		RefreshExpiresIn: 2592000,
	}

	repo := &mockRefreshSessionRepo{rotateResult: expectedResult}
	signer := &mockTokenSigner{tokenToReturn: "mock.new.jwt"}
	clock := mockClock{now: time.Now()}

	uc, err := NewRefreshUsecase(repo, signer, token.NewRefreshTokenManager(), fixedUUIDGen{id: "new-token-uuid"}, clock)
	if err != nil {
		t.Fatalf("NewRefreshUsecase failed: %v", err)
	}

	out, err := uc.Execute(context.Background(), RefreshInput{
		RefreshToken: validToken,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if out.AccessToken != "mock.new.jwt" {
		t.Errorf("expected access token mock.new.jwt, got %s", out.AccessToken)
	}
	if out.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %s", out.TokenType)
	}
	if out.ExpiresIn != 600 {
		t.Errorf("expected expiresIn 600, got %d", out.ExpiresIn)
	}
	if out.RefreshExpiresIn != 2592000 {
		t.Errorf("expected refreshExpiresIn 2592000, got %d", out.RefreshExpiresIn)
	}
	if len(out.RefreshToken) != 43 {
		t.Errorf("expected successor raw refresh token length 43, got %d (%s)", len(out.RefreshToken), out.RefreshToken)
	}
}

func TestRefreshUsecase_MalformedTokenRejected(t *testing.T) {
	repo := &mockRefreshSessionRepo{}
	signer := &mockTokenSigner{tokenToReturn: "mock.jwt"}

	uc, _ := NewRefreshUsecase(repo, signer, token.NewRefreshTokenManager(), fixedUUIDGen{id: "uuid"}, nil)

	tests := []string{
		"",
		"short",
		"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NQ==",
		"invalid-characters!@#$",
	}

	for _, tokenStr := range tests {
		_, err := uc.Execute(context.Background(), RefreshInput{RefreshToken: tokenStr})
		if !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials for %q, got %v", tokenStr, err)
		}
	}
}

func TestRefreshUsecase_ReplayRevocationPropagated(t *testing.T) {
	validToken, _, _ := token.GenerateRefreshToken()
	repo := &mockRefreshSessionRepo{rotateErr: domain.ErrCompromisedSessionReplay}
	signer := &mockTokenSigner{tokenToReturn: "mock.jwt"}

	uc, _ := NewRefreshUsecase(repo, signer, token.NewRefreshTokenManager(), fixedUUIDGen{id: "uuid"}, nil)

	_, err := uc.Execute(context.Background(), RefreshInput{RefreshToken: validToken})
	if !errors.Is(err, domain.ErrCompromisedSessionReplay) {
		t.Errorf("expected ErrCompromisedSessionReplay, got %v", err)
	}
}
