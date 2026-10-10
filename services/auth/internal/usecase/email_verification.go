package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// EmailVerificationUsecase coordinates email verification requests and token confirmations.
type EmailVerificationUsecase struct {
	repo        EmailVerificationRepository
	tokenGen    EmailVerificationTokenGenerator
	emailSender EmailSender
	tokenTTL    time.Duration
	cooldown    time.Duration
}

// NewEmailVerificationUsecase constructs a new EmailVerificationUsecase.
func NewEmailVerificationUsecase(
	repo EmailVerificationRepository,
	tokenGen EmailVerificationTokenGenerator,
	emailSender EmailSender,
	tokenTTL time.Duration,
	cooldown time.Duration,
) *EmailVerificationUsecase {
	if tokenTTL <= 0 {
		tokenTTL = 24 * time.Hour
	}
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}
	return &EmailVerificationUsecase{
		repo:        repo,
		tokenGen:    tokenGen,
		emailSender: emailSender,
		tokenTTL:    tokenTTL,
		cooldown:    cooldown,
	}
}

// RequestVerification handles authenticated requests to issue a new verification email.
// It verifies the account state, enforces a database-backed cooldown, and sends email post-commit.
func (uc *EmailVerificationUsecase) RequestVerification(ctx context.Context, accountID string) error {
	// Generate raw token and digest. Raw token is kept in memory and never stored in the database.
	rawToken, hash, err := uc.tokenGen.Generate()
	if err != nil {
		return fmt.Errorf("generating verification token: %w", err)
	}

	// Atomically check account status, existing verification flag, and cooldown under row lock.
	result, err := uc.repo.IssueVerificationToken(ctx, accountID, hash, uc.tokenTTL, uc.cooldown)
	if err != nil {
		return err
	}

	// If the account is already verified or the request is suppressed by cooldown,
	// return success without sending an email. The HTTP handler emits generic 202 Accepted.
	if result.AlreadyVerified || result.CooldownActive {
		return nil
	}

	// Deliver verification email strictly after the database transaction has committed.
	// This prevents holding database connection or row locks during remote SMTP network I/O.
	if err := uc.emailSender.SendVerificationEmail(ctx, result.RecipientEmail, rawToken, result.ExpiresAt); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrVerificationEmailFailed, err)
	}

	return nil
}

// ConfirmVerification validates a client-submitted token and marks the account email as verified.
func (uc *EmailVerificationUsecase) ConfirmVerification(ctx context.Context, rawToken string) error {
	// Strictly validate the canonical RFC 4648 unpadded base64url format before database lookup.
	// Any formatting error returns generic ErrInvalidVerificationToken to prevent enumeration.
	tokenHash, err := uc.tokenGen.ValidateAndHash(rawToken)
	if err != nil {
		return domain.ErrInvalidVerificationToken
	}

	// Atomically lock account, re-verify expiration and token hash, and delete the consumed token.
	// Database connection or query timeout errors are preserved to return 503/500 appropriately.
	return uc.repo.ConfirmToken(ctx, tokenHash)
}
