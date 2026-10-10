package usecase

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

// Clock provides current time.
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using time.Now().UTC().
type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// UUIDGenerator generates UUID v4 strings.
type UUIDGenerator interface {
	Generate() (string, error)
}

// CryptoUUIDGenerator implements UUIDGenerator using crypto/rand.
type CryptoUUIDGenerator struct{}

func (CryptoUUIDGenerator) Generate() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("failed to generate random uuid: %w", err)
	}
	// Set version 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant RFC 4122
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RegisterInput carries parameters for account registration.
type RegisterInput struct {
	Email    string
	Password string
}

// RegisterUsecase coordinates account registration.
type RegisterUsecase struct {
	repo             AccountRepository
	hasher           PasswordHasher
	uuidGen          UUIDGenerator
	clock            Clock
	verificationRepo EmailVerificationRepository
	tokenGen         EmailVerificationTokenGenerator
	emailSender      EmailSender
	tokenTTL         time.Duration
}

// NewRegisterUsecase constructs a new RegisterUsecase.
func NewRegisterUsecase(
	repo AccountRepository,
	hasher PasswordHasher,
	uuidGen UUIDGenerator,
	clock Clock,
	verificationRepo EmailVerificationRepository,
	tokenGen EmailVerificationTokenGenerator,
	emailSender EmailSender,
	tokenTTL time.Duration,
) *RegisterUsecase {
	if uuidGen == nil {
		uuidGen = CryptoUUIDGenerator{}
	}
	if clock == nil {
		clock = RealClock{}
	}
	if tokenTTL <= 0 {
		tokenTTL = 24 * time.Hour
	}
	return &RegisterUsecase{
		repo:             repo,
		hasher:           hasher,
		uuidGen:          uuidGen,
		clock:            clock,
		verificationRepo: verificationRepo,
		tokenGen:         tokenGen,
		emailSender:      emailSender,
		tokenTTL:         tokenTTL,
	}
}

// Execute performs registration flow: validate -> hash -> construct -> persist -> send verification email -> return.
func (uc *RegisterUsecase) Execute(ctx context.Context, input RegisterInput) (domain.Account, error) {
	canonicalEmail, err := validateAndCanonicalizeEmail(input.Email)
	if err != nil {
		return domain.Account{}, err
	}

	if err := validatePassword(input.Password); err != nil {
		return domain.Account{}, err
	}

	id, err := uc.uuidGen.Generate()
	if err != nil {
		return domain.Account{}, fmt.Errorf("failed to generate account id: %w", err)
	}

	hash, err := uc.hasher.Hash(ctx, input.Password)
	if err != nil {
		// Preserve context errors (such as context.Canceled or context.DeadlineExceeded)
		// so the delivery layer can determine if the client aborted or a timeout occurred.
		return domain.Account{}, fmt.Errorf("hashing password: %w", err)
	}

	now := uc.clock.Now().UTC()
	account := domain.Account{
		ID:            id,
		Email:         canonicalEmail,
		PasswordHash:  hash,
		Status:        domain.AccountStatusActive,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := uc.repo.Create(ctx, account); err != nil {
		return domain.Account{}, err
	}

	// Issue verification token and send email post-commit if verification components are configured.
	if uc.verificationRepo != nil && uc.tokenGen != nil && uc.emailSender != nil {
		rawToken, tokenHash, err := uc.tokenGen.Generate()
		if err != nil {
			return account, fmt.Errorf("generating verification token: %w", err)
		}

		result, err := uc.verificationRepo.IssueVerificationToken(ctx, account.ID, tokenHash, uc.tokenTTL, 0)
		if err != nil {
			return account, fmt.Errorf("issuing verification token: %w", err)
		}

		// Remote SMTP delivery happens strictly after database writes commit.
		// If remote email delivery fails, the account remains created and active (email_verified=false),
		// allowing the user to log in and request a replacement verification email via resend.
		if err := uc.emailSender.SendVerificationEmail(ctx, account.Email, rawToken, result.ExpiresAt); err != nil {
			return account, fmt.Errorf("%w: %w", domain.ErrVerificationEmailFailed, err)
		}
	}

	return account, nil
}

func validateAndCanonicalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 254 {
		return "", domain.ErrInvalidEmail
	}

	// ASCII-only requirement
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] > unicode.MaxASCII {
			return "", domain.ErrInvalidEmail
		}
	}

	// Parse using standard net/mail to check RFC 5322 syntax
	addr, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", domain.ErrInvalidEmail
	}

	// Must be a bare address without display name or extra characters
	if addr.Address != trimmed {
		return "", domain.ErrInvalidEmail
	}

	// Basic structural sanity: exactly one @ with non-empty local and domain parts
	parts := strings.Split(trimmed, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", domain.ErrInvalidEmail
	}

	// Domain must contain at least one dot and valid domain label
	domainPart := parts[1]
	if !strings.Contains(domainPart, ".") || strings.HasPrefix(domainPart, ".") || strings.HasSuffix(domainPart, ".") {
		return "", domain.ErrInvalidEmail
	}

	// Explicit product identity policy: lowercase the entire address
	return strings.ToLower(trimmed), nil
}

func validatePassword(pw string) error {
	if !utf8.ValidString(pw) {
		return domain.ErrInvalidPassword
	}

	if len(pw) > 512 {
		return domain.ErrInvalidPassword
	}

	// Enforce 8 to 128 Unicode code points.
	// Minimum of 8 ensures reasonable entropy, while upper bound of 128 prevents
	// CPU/memory exhaustion in Argon2id hashing while accommodating passphrases.
	runeCount := utf8.RuneCountInString(pw)
	if runeCount < 8 || runeCount > 128 {
		return domain.ErrInvalidPassword
	}

	return nil
}
