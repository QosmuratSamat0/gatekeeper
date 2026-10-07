package usecase

import (
	"context"
	"errors"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// LogoutUsecase handles user logout and session revocation.
type LogoutUsecase struct {
	sessionRepo SessionRepository
	refreshVal  RefreshTokenValidator
}

// NewLogoutUsecase constructs a LogoutUsecase.
func NewLogoutUsecase(sessionRepo SessionRepository, refreshVal RefreshTokenValidator) (*LogoutUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	if refreshVal == nil {
		return nil, errors.New("refreshVal is required")
	}
	return &LogoutUsecase{
		sessionRepo: sessionRepo,
		refreshVal:  refreshVal,
	}, nil
}

// Execute revokes the session identified by sessionID and accountID.
// If the session is already revoked, it returns nil (idempotent 204).
// If the session is not found or belongs to another user, it returns domain.ErrSessionNotFound.
func (uc *LogoutUsecase) Execute(ctx context.Context, accountID, sessionID string) error {
	_, err := uc.sessionRepo.Revoke(ctx, sessionID, accountID)
	if err != nil {
		return err
	}
	return nil
}

// ExecuteByRefreshToken revokes the session family identified by the presented refresh token.
// Allows logging out even after access token expiry.
// Returns nil (idempotent 204) if a known unexpired token is presented, even if already consumed or revoked.
// Returns domain.ErrInvalidCredentials if the token is unknown, expired, or malformed.
func (uc *LogoutUsecase) ExecuteByRefreshToken(ctx context.Context, rawRefreshToken string) error {
	tokenHash, err := uc.refreshVal.ValidateAndHash(rawRefreshToken)
	if err != nil {
		return domain.ErrInvalidCredentials
	}

	_, err = uc.sessionRepo.RevokeByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}
	return nil
}
