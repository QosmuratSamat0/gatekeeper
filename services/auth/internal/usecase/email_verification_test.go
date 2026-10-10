package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
)

type mockEVRepo struct {
	issueFn   func(ctx context.Context, accountID string, tokenHash []byte, ttl, cooldown time.Duration) (IssueVerificationTokenResult, error)
	confirmFn func(ctx context.Context, tokenHash []byte) error
}

func (m *mockEVRepo) IssueVerificationToken(ctx context.Context, accountID string, tokenHash []byte, ttl, cooldown time.Duration) (IssueVerificationTokenResult, error) {
	if m.issueFn != nil {
		return m.issueFn(ctx, accountID, tokenHash, ttl, cooldown)
	}
	return IssueVerificationTokenResult{Created: true, RecipientEmail: "test@example.com", ExpiresAt: time.Now().Add(ttl)}, nil
}

func (m *mockEVRepo) ConfirmToken(ctx context.Context, tokenHash []byte) error {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, tokenHash)
	}
	return nil
}

type mockEVTokenGen struct {
	genFn      func() (string, []byte, error)
	validateFn func(rawToken string) ([]byte, error)
}

func (m *mockEVTokenGen) Generate() (string, []byte, error) {
	if m.genFn != nil {
		return m.genFn()
	}
	return "abcdefghijklmnopqrstuvwxyz01234567890123456", []byte("hash32byteslongplaceholder123456"), nil
}

func (m *mockEVTokenGen) ValidateAndHash(rawToken string) ([]byte, error) {
	if m.validateFn != nil {
		return m.validateFn(rawToken)
	}
	if len(rawToken) != 43 {
		return nil, domain.ErrInvalidVerificationToken
	}
	return []byte("hash32byteslongplaceholder123456"), nil
}

type mockEVEmailSender struct {
	sendFn func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error
}

func (m *mockEVEmailSender) SendVerificationEmail(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, recipientEmail, rawToken, expiresAt)
	}
	return nil
}

func TestEmailVerificationUsecase_RequestVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("eligible account issues token and sends email post-commit", func(t *testing.T) {
		repo := &mockEVRepo{}
		tokenGen := &mockEVTokenGen{}
		var emailSent bool
		sender := &mockEVEmailSender{
			sendFn: func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
				emailSent = true
				if recipientEmail != "test@example.com" {
					t.Errorf("expected recipient test@example.com, got %s", recipientEmail)
				}
				return nil
			},
		}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.RequestVerification(ctx, "account-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !emailSent {
			t.Errorf("expected email to be sent")
		}
	})

	t.Run("already verified account suppresses email silently", func(t *testing.T) {
		repo := &mockEVRepo{
			issueFn: func(ctx context.Context, accountID string, tokenHash []byte, ttl, cooldown time.Duration) (IssueVerificationTokenResult, error) {
				return IssueVerificationTokenResult{
					AlreadyVerified: true,
					RecipientEmail:  "test@example.com",
				}, nil
			},
		}
		tokenGen := &mockEVTokenGen{}
		var emailSent bool
		sender := &mockEVEmailSender{
			sendFn: func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
				emailSent = true
				return nil
			},
		}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.RequestVerification(ctx, "account-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if emailSent {
			t.Errorf("expected email NOT to be sent for already verified account")
		}
	})

	t.Run("cooldown active suppresses email silently", func(t *testing.T) {
		repo := &mockEVRepo{
			issueFn: func(ctx context.Context, accountID string, tokenHash []byte, ttl, cooldown time.Duration) (IssueVerificationTokenResult, error) {
				return IssueVerificationTokenResult{
					CooldownActive: true,
					RecipientEmail: "test@example.com",
				}, nil
			},
		}
		tokenGen := &mockEVTokenGen{}
		var emailSent bool
		sender := &mockEVEmailSender{
			sendFn: func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
				emailSent = true
				return nil
			},
		}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.RequestVerification(ctx, "account-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if emailSent {
			t.Errorf("expected email NOT to be sent when cooldown is active")
		}
	})

	t.Run("email sender failure returns ErrVerificationEmailFailed", func(t *testing.T) {
		repo := &mockEVRepo{}
		tokenGen := &mockEVTokenGen{}
		sender := &mockEVEmailSender{
			sendFn: func(ctx context.Context, recipientEmail, rawToken string, expiresAt time.Time) error {
				return errors.New("smtp connection failed")
			},
		}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.RequestVerification(ctx, "account-123")
		if !errors.Is(err, domain.ErrVerificationEmailFailed) {
			t.Fatalf("expected ErrVerificationEmailFailed, got %v", err)
		}
	})
}

func TestEmailVerificationUsecase_ConfirmVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token confirms successfully", func(t *testing.T) {
		var confirmed bool
		repo := &mockEVRepo{
			confirmFn: func(ctx context.Context, tokenHash []byte) error {
				confirmed = true
				return nil
			},
		}
		tokenGen := &mockEVTokenGen{}
		sender := &mockEVEmailSender{}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.ConfirmVerification(ctx, "abcdefghijklmnopqrstuvwxyz01234567890123456")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !confirmed {
			t.Errorf("expected token to be confirmed in repository")
		}
	})

	t.Run("invalid token format returns ErrInvalidVerificationToken", func(t *testing.T) {
		repo := &mockEVRepo{}
		tokenGen := &mockEVTokenGen{
			validateFn: func(rawToken string) ([]byte, error) {
				return nil, domain.ErrInvalidVerificationToken
			},
		}
		sender := &mockEVEmailSender{}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.ConfirmVerification(ctx, "invalid-token")
		if !errors.Is(err, domain.ErrInvalidVerificationToken) {
			t.Fatalf("expected ErrInvalidVerificationToken, got %v", err)
		}
	})

	t.Run("database failure is preserved and not converted to ErrInvalidVerificationToken", func(t *testing.T) {
		repo := &mockEVRepo{
			confirmFn: func(ctx context.Context, tokenHash []byte) error {
				return domain.ErrDatabaseUnavailable
			},
		}
		tokenGen := &mockEVTokenGen{}
		sender := &mockEVEmailSender{}

		uc := NewEmailVerificationUsecase(repo, tokenGen, sender, 24*time.Hour, 60*time.Second)
		err := uc.ConfirmVerification(ctx, "abcdefghijklmnopqrstuvwxyz01234567890123456")
		if !errors.Is(err, domain.ErrDatabaseUnavailable) {
			t.Fatalf("expected ErrDatabaseUnavailable to be preserved, got %v", err)
		}
	})
}
