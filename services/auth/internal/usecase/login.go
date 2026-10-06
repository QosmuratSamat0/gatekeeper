package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// LoginInput carries input parameters for authentication.
type LoginInput struct {
	Email    string
	Password string
}

// LoginOutput carries the issued access token and account information.
type LoginOutput struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	Account     domain.Account
}

// LoginUsecase coordinates credential verification and access token issuance.
type LoginUsecase struct {
	accountRepo AccountRepository
	sessionRepo SessionRepository
	verifier    PasswordVerifier
	tokenSigner TokenSigner
	uuidGen     UUIDGenerator
	clock       Clock
	dummyHash   string
	tokenTTL    time.Duration
}

// NewLoginUsecase constructs a LoginUsecase with required ports and configurations.
func NewLoginUsecase(
	accountRepo AccountRepository,
	sessionRepo SessionRepository,
	verifier PasswordVerifier,
	tokenSigner TokenSigner,
	dummyHash string,
	tokenTTL time.Duration,
	uuidGen UUIDGenerator,
	clock Clock,
) (*LoginUsecase, error) {
	if accountRepo == nil {
		return nil, errors.New("accountRepo is required")
	}
	if sessionRepo == nil {
		return nil, errors.New("sessionRepo is required")
	}
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	if tokenSigner == nil {
		return nil, errors.New("tokenSigner is required")
	}
	if dummyHash == "" {
		return nil, errors.New("dummyHash is required")
	}
	if tokenTTL <= 0 {
		tokenTTL = 10 * time.Minute
	}
	if uuidGen == nil {
		uuidGen = CryptoUUIDGenerator{}
	}
	if clock == nil {
		clock = RealClock{}
	}

	return &LoginUsecase{
		accountRepo: accountRepo,
		sessionRepo: sessionRepo,
		verifier:    verifier,
		tokenSigner: tokenSigner,
		uuidGen:     uuidGen,
		clock:       clock,
		dummyHash:   dummyHash,
		tokenTTL:    tokenTTL,
	}, nil
}

// Execute performs login authentication according to AUTH-02 security specification.
func (uc *LoginUsecase) Execute(ctx context.Context, input LoginInput) (LoginOutput, error) {
	// Validate password constraints: nonempty valid UTF-8, max 128 code points / 512 bytes.
	// Short passwords or malformed encoding receive generic ErrInvalidCredentials to avoid leaking account rules.
	if !validateLoginPassword(input.Password) {
		// Run dummy verification to reduce obvious timing differences before denial.
		if err := uc.runDummyVerify(ctx, input.Password); err != nil {
			if ctx.Err() != nil {
				return LoginOutput{}, ctx.Err()
			}
			return LoginOutput{}, fmt.Errorf("verifying credentials: %w", err)
		}
		return LoginOutput{}, domain.ErrInvalidCredentials
	}

	// Validate email syntax; if invalid, run dummy hash and return generic invalid credentials.
	canonicalEmail, err := validateAndCanonicalizeEmail(input.Email)
	if err != nil {
		if dummyErr := uc.runDummyVerify(ctx, input.Password); dummyErr != nil {
			if ctx.Err() != nil {
				return LoginOutput{}, ctx.Err()
			}
			return LoginOutput{}, fmt.Errorf("verifying credentials: %w", dummyErr)
		}
		return LoginOutput{}, domain.ErrInvalidCredentials
	}

	// Query account by email.
	acc, err := uc.accountRepo.GetByEmail(ctx, canonicalEmail)
	if err != nil {
		if errors.Is(err, domain.ErrAccountNotFound) {
			// Account does not exist: verify candidate password against production dummy hash
			// to mitigate user enumeration through timing differences.
			if dummyErr := uc.runDummyVerify(ctx, input.Password); dummyErr != nil {
				if ctx.Err() != nil {
					return LoginOutput{}, ctx.Err()
				}
				return LoginOutput{}, fmt.Errorf("verifying credentials: %w", dummyErr)
			}
			return LoginOutput{}, domain.ErrInvalidCredentials
		}
		return LoginOutput{}, err
	}

	// Account exists: check if account is disabled.
	// Per specification: verify against the user's actual stored hash before returning generic 401.
	if acc.Status == domain.AccountStatusDisabled {
		_, verifyErr := uc.verifier.Verify(ctx, input.Password, acc.PasswordHash)
		if verifyErr != nil {
			if ctx.Err() != nil {
				return LoginOutput{}, ctx.Err()
			}
			return LoginOutput{}, fmt.Errorf("verifying credentials: %w", verifyErr)
		}
		return LoginOutput{}, domain.ErrInvalidCredentials
	}

	// Account is active: verify password against stored Argon2id hash.
	match, err := uc.verifier.Verify(ctx, input.Password, acc.PasswordHash)
	if err != nil {
		if ctx.Err() != nil {
			return LoginOutput{}, ctx.Err()
		}
		return LoginOutput{}, fmt.Errorf("verifying credentials: %w", err)
	}
	if !match {
		return LoginOutput{}, domain.ErrInvalidCredentials
	}

	// Password verified. Generate session ID and sign access JWT before committing session to database.
	sessionID, err := uc.uuidGen.Generate()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("generating session id: %w", err)
	}

	tokenStr, expiresAt, expiresIn, err := uc.tokenSigner.SignAccessToken(acc.ID, sessionID)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("signing access token: %w", err)
	}

	// Ensure session expiration matches the exact expiration claim used in the JWT.
	session := domain.Session{
		ID:        sessionID,
		AccountID: acc.ID,
		CreatedAt: expiresAt.Add(-time.Duration(expiresIn) * time.Second),
		ExpiresAt: expiresAt,
	}

	// Persist session atomically while checking that account remains active and credentials unchanged.
	if err := uc.sessionRepo.CreateAtomic(ctx, session, acc.PasswordHash); err != nil {
		return LoginOutput{}, fmt.Errorf("persisting session: %w", err)
	}

	return LoginOutput{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Account:     acc,
	}, nil
}

func (uc *LoginUsecase) runDummyVerify(ctx context.Context, password string) error {
	_, err := uc.verifier.Verify(ctx, password, uc.dummyHash)
	return err
}

func validateLoginPassword(password string) bool {
	if len(password) == 0 || len(password) > 512 {
		return false
	}
	if !utf8.ValidString(password) {
		return false
	}
	runeCount := utf8.RuneCountInString(password)
	return runeCount >= 1 && runeCount <= 128
}
