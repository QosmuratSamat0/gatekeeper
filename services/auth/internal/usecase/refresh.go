package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// RefreshInput carries the client-presented opaque refresh token.
type RefreshInput struct {
	RefreshToken string
}

// RefreshOutput carries the rotated access and refresh credentials.
type RefreshOutput struct {
	AccessToken      string
	TokenType        string
	ExpiresIn        int64
	RefreshToken     string
	RefreshExpiresIn int64
}

// RefreshUsecase coordinates atomic refresh token rotation and replay detection.
type RefreshUsecase struct {
	sessionRepo SessionRepository
	tokenSigner TokenSigner
	refreshMgr  RefreshTokenManager
	uuidGen     UUIDGenerator
	clock       Clock
}

// NewRefreshUsecase constructs a RefreshUsecase instance.
func NewRefreshUsecase(
	sessionRepo SessionRepository,
	tokenSigner TokenSigner,
	refreshMgr RefreshTokenManager,
	uuidGen UUIDGenerator,
	clock Clock,
) (*RefreshUsecase, error) {
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	if tokenSigner == nil {
		return nil, errors.New("tokenSigner is required")
	}
	if refreshMgr == nil {
		return nil, errors.New("refreshMgr is required")
	}
	if uuidGen == nil {
		uuidGen = CryptoUUIDGenerator{}
	}
	if clock == nil {
		clock = RealClock{}
	}

	return &RefreshUsecase{
		sessionRepo: sessionRepo,
		tokenSigner: tokenSigner,
		refreshMgr:  refreshMgr,
		uuidGen:     uuidGen,
		clock:       clock,
	}, nil
}

// Execute performs atomic refresh rotation per AUTH-03 specification.
func (uc *RefreshUsecase) Execute(ctx context.Context, input RefreshInput) (RefreshOutput, error) {
	// 1. Validate format and compute SHA-256 digest of presented token via consumer-owned port.
	// Malformed inputs return generic ErrInvalidCredentials to avoid disclosing validation rules.
	presentedHash, err := uc.refreshMgr.ValidateAndHash(input.RefreshToken)
	if err != nil {
		return RefreshOutput{}, domain.ErrInvalidCredentials
	}

	// 2. Generate successor raw refresh token and compute its SHA-256 digest via consumer-owned port.
	successorID, err := uc.uuidGen.Generate()
	if err != nil {
		return RefreshOutput{}, fmt.Errorf("generating successor token id: %w", err)
	}

	successorRawToken, successorHash, err := uc.refreshMgr.Generate()
	if err != nil {
		return RefreshOutput{}, fmt.Errorf("generating successor refresh token: %w", err)
	}

	successorRecord := domain.RefreshToken{
		ID:        successorID,
		TokenHash: successorHash,
	}

	// 3. Define callback to sign successor access JWT while holding row locks.
	// signCallback receives the verified absolute session expiration from the database row.
	signCallback := func(accountID, sessionID string, sessionExpiresAt time.Time) (string, time.Time, int64, error) {
		tokenStr, exp, expIn, signErr := uc.tokenSigner.SignAccessTokenWithExpiry(accountID, sessionID, sessionExpiresAt)
		if signErr != nil {
			return "", time.Time{}, 0, signErr
		}
		return tokenStr, exp, expIn, nil
	}

	// 4. Delegate to repository for atomic verification, locking, signing, and commit.
	rotationResult, err := uc.sessionRepo.RotateRefreshToken(ctx, presentedHash, successorRecord, signCallback)
	if err != nil {
		return RefreshOutput{}, err
	}

	return RefreshOutput{
		AccessToken:      rotationResult.AccessToken,
		TokenType:        "Bearer",
		ExpiresIn:        rotationResult.ExpiresIn,
		RefreshToken:     successorRawToken,
		RefreshExpiresIn: rotationResult.RefreshExpiresIn,
	}, nil
}
