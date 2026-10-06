package usecase

import (
	"context"
	"errors"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// CurrentAccountUsecase handles profile retrieval for authenticated users.
type CurrentAccountUsecase struct {
	sessionRepo SessionRepository
	clock       Clock
}

// NewCurrentAccountUsecase creates a new CurrentAccountUsecase.
func NewCurrentAccountUsecase(sessionRepo SessionRepository, clock Clock) (*CurrentAccountUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &CurrentAccountUsecase{
		sessionRepo: sessionRepo,
		clock:       clock,
	}, nil
}

// Execute retrieves account information using validated token claims (accountID and sessionID).
func (uc *CurrentAccountUsecase) Execute(ctx context.Context, accountID, sessionID string) (domain.Account, error) {
	sess, acc, err := uc.sessionRepo.GetWithAccount(ctx, sessionID)
	if err != nil {
		return domain.Account{}, err
	}

	// Session must belong to the subject account in the token
	if sess.AccountID != accountID {
		return domain.Account{}, domain.ErrSessionNotFound
	}

	// Session must be active (not revoked and not expired)
	if !sess.IsActive(uc.clock.Now().UTC()) {
		if sess.RevokedAt != nil {
			return domain.Account{}, domain.ErrSessionRevoked
		}
		return domain.Account{}, domain.ErrSessionExpired
	}

	// Account must remain active
	if acc.Status != domain.AccountStatusActive {
		return domain.Account{}, domain.ErrInvalidCredentials
	}

	return acc, nil
}
