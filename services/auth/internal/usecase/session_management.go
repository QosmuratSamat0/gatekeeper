package usecase

import (
	"context"
	"errors"
	"strings"
)

// ListSessionsUsecase retrieves paginated active sessions for an authenticated account.
type ListSessionsUsecase struct {
	sessionRepo SessionManagementRepository
}

// NewListSessionsUsecase constructs a new ListSessionsUsecase.
func NewListSessionsUsecase(sessionRepo SessionManagementRepository) (*ListSessionsUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	return &ListSessionsUsecase{
		sessionRepo: sessionRepo,
	}, nil
}

// Execute retrieves active sessions for the account, asserting that the caller session remains active.
func (uc *ListSessionsUsecase) Execute(
	ctx context.Context,
	accountID string,
	callerSessionID string,
	filter SessionListFilter,
) (SessionListPage, error) {
	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)
	if accountID == "" || callerSessionID == "" {
		return SessionListPage{}, errors.New("accountID and callerSessionID are required")
	}
	if filter.Cursor != nil {
		filter.Cursor.ID = strings.ToLower(filter.Cursor.ID)
	}
	if filter.Limit <= 0 {
		filter.Limit = 20
	} else if filter.Limit > 100 {
		filter.Limit = 100
	}
	return uc.sessionRepo.ListActiveSessions(ctx, accountID, callerSessionID, filter)
}

// RevokeSessionUsecase atomically revokes a target session owned by the authenticated account.
type RevokeSessionUsecase struct {
	sessionRepo SessionManagementRepository
}

// NewRevokeSessionUsecase constructs a new RevokeSessionUsecase.
func NewRevokeSessionUsecase(sessionRepo SessionManagementRepository) (*RevokeSessionUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	return &RevokeSessionUsecase{
		sessionRepo: sessionRepo,
	}, nil
}

// Execute revokes the target session, ensuring pre-lock ownership filtering and deadlock-free ordering.
func (uc *RevokeSessionUsecase) Execute(
	ctx context.Context,
	accountID string,
	callerSessionID string,
	targetSessionID string,
) error {
	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)
	targetSessionID = strings.ToLower(targetSessionID)
	if accountID == "" || callerSessionID == "" || targetSessionID == "" {
		return errors.New("accountID, callerSessionID, and targetSessionID are required")
	}
	_, err := uc.sessionRepo.RevokeSessionTarget(ctx, accountID, callerSessionID, targetSessionID)
	return err
}

// LogoutAllUsecase atomically revokes all unrevoked sessions for the authenticated account.
type LogoutAllUsecase struct {
	sessionRepo SessionManagementRepository
}

// NewLogoutAllUsecase constructs a new LogoutAllUsecase.
func NewLogoutAllUsecase(sessionRepo SessionManagementRepository) (*LogoutAllUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	return &LogoutAllUsecase{
		sessionRepo: sessionRepo,
	}, nil
}

// Execute revokes all unrevoked sessions owned by the account.
func (uc *LogoutAllUsecase) Execute(
	ctx context.Context,
	accountID string,
	callerSessionID string,
) error {
	accountID = strings.ToLower(accountID)
	callerSessionID = strings.ToLower(callerSessionID)
	if accountID == "" || callerSessionID == "" {
		return errors.New("accountID and callerSessionID are required")
	}
	return uc.sessionRepo.RevokeAllSessions(ctx, accountID, callerSessionID)
}
