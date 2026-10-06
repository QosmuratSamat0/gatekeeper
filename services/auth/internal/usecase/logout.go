package usecase

import (
	"context"
	"errors"
)

// LogoutUsecase handles user logout and session revocation.
type LogoutUsecase struct {
	sessionRepo SessionRepository
}

// NewLogoutUsecase constructs a LogoutUsecase.
func NewLogoutUsecase(sessionRepo SessionRepository) (*LogoutUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	return &LogoutUsecase{
		sessionRepo: sessionRepo,
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
