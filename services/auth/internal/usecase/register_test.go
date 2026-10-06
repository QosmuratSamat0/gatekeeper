package usecase_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockAccountRepo struct {
	createFn func(ctx context.Context, account domain.Account) error
}

func (m *mockAccountRepo) Create(ctx context.Context, account domain.Account) error {
	return m.createFn(ctx, account)
}

func (m *mockAccountRepo) GetByEmail(ctx context.Context, email string) (domain.Account, error) {
	return domain.Account{}, domain.ErrAccountNotFound
}

type mockHasher struct {
	hashFn func(ctx context.Context, password string) (string, error)
}

func (m *mockHasher) Hash(ctx context.Context, password string) (string, error) {
	return m.hashFn(ctx, password)
}

type fixedUUIDGen struct {
	uuid string
}

func (g fixedUUIDGen) Generate() (string, error) {
	return g.uuid, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func TestRegisterUsecase_Success(t *testing.T) {
	fixedTime := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	fixedID := "11111111-2222-4333-8444-555555555555"

	var savedAccount domain.Account
	repo := &mockAccountRepo{
		createFn: func(ctx context.Context, account domain.Account) error {
			savedAccount = account
			return nil
		},
	}
	hasher := &mockHasher{
		hashFn: func(ctx context.Context, password string) (string, error) {
			return "$argon2id$v=19$m=65536,t=3,p=1$fakeSalt$fakeHash", nil
		},
	}

	uc := usecase.NewRegisterUsecase(repo, hasher, fixedUUIDGen{uuid: fixedID}, fixedClock{now: fixedTime})

	input := usecase.RegisterInput{
		Email:    "  User.Name@Example.COM  ",
		Password: "a-very-secure-password-15chars",
	}

	account, err := uc.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if account.ID != fixedID {
		t.Errorf("expected id %s, got %s", fixedID, account.ID)
	}
	// Check canonical lowercased email without whitespace
	if account.Email != "user.name@example.com" {
		t.Errorf("expected canonical lowercase email 'user.name@example.com', got %s", account.Email)
	}
	if account.Status != domain.AccountStatusActive {
		t.Errorf("expected active status, got %s", account.Status)
	}
	if account.EmailVerified != false {
		t.Errorf("expected email_verified to be false, got %v", account.EmailVerified)
	}
	if !account.CreatedAt.Equal(fixedTime) {
		t.Errorf("expected created_at %v, got %v", fixedTime, account.CreatedAt)
	}
	if !account.UpdatedAt.Equal(fixedTime) {
		t.Errorf("expected updated_at %v, got %v", fixedTime, account.UpdatedAt)
	}
	if savedAccount != account {
		t.Errorf("saved account differs from returned account")
	}
}

func TestRegisterUsecase_EmailValidation(t *testing.T) {
	repo := &mockAccountRepo{}
	hasher := &mockHasher{}
	uc := usecase.NewRegisterUsecase(repo, hasher, fixedUUIDGen{uuid: "id"}, fixedClock{now: time.Now()})

	testCases := []struct {
		name  string
		email string
	}{
		{"empty", ""},
		{"only whitespace", "   "},
		{"too long (>254 bytes)", strings.Repeat("a", 245) + "@example.com"},
		{"non-ASCII cyrillic", "пользователь@example.com"},
		{"display name included", "John Doe <john@example.com>"},
		{"missing at", "johnexample.com"},
		{"missing local part", "@example.com"},
		{"missing domain", "john@"},
		{"missing domain dot", "john@localhost"},
		{"trailing dot in domain", "john@example.com."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), usecase.RegisterInput{
				Email:    tc.email,
				Password: "valid-password-over-15-chars",
			})
			if !errors.Is(err, domain.ErrInvalidEmail) {
				t.Errorf("expected ErrInvalidEmail for %q, got: %v", tc.email, err)
			}
		})
	}
}

func TestRegisterUsecase_PasswordValidation(t *testing.T) {
	repo := &mockAccountRepo{}
	hasher := &mockHasher{}
	uc := usecase.NewRegisterUsecase(repo, hasher, fixedUUIDGen{uuid: "id"}, fixedClock{now: time.Now()})

	testCases := []struct {
		name     string
		password string
	}{
		{"too short (7 chars)", "1234567"},
		{"too short (1 char)", "a"},
		{"too long (>128 runes)", strings.Repeat("a", 129)},
		{"too many bytes (>512 bytes)", strings.Repeat("日", 175)}, // 175 3-byte runes = 525 bytes
		{"invalid UTF-8 bytes", string([]byte{0xff, 0xfe, 0xfd})},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), usecase.RegisterInput{
				Email:    "test@example.com",
				Password: tc.password,
			})
			if !errors.Is(err, domain.ErrInvalidPassword) {
				t.Errorf("expected ErrInvalidPassword for case %q, got: %v", tc.name, err)
			}
		})
	}

	// Exact bounds test: 8 runes is valid, 128 runes is valid
	validBoundaries := []string{
		strings.Repeat("a", 8),   // Exactly 8 ASCII chars accepted
		"12345678",               // Exactly 8 numeric chars accepted
		"пароль-8",               // Exactly 8 Cyrillic runes (15 UTF-8 bytes) accepted
		strings.Repeat("a", 128), // Exactly 128 ASCII chars accepted
	}

	for _, pw := range validBoundaries {
		hasher.hashFn = func(ctx context.Context, p string) (string, error) {
			return "hash", nil
		}
		repo.createFn = func(ctx context.Context, a domain.Account) error {
			return nil
		}
		_, err := uc.Execute(context.Background(), usecase.RegisterInput{
			Email:    "test@example.com",
			Password: pw,
		})
		if err != nil {
			t.Errorf("expected valid boundary password of len %d runes to succeed, got: %v", len([]rune(pw)), err)
		}
	}
}

func TestRegisterUsecase_ErrorPropagation(t *testing.T) {
	t.Run("account exists propagates", func(t *testing.T) {
		repo := &mockAccountRepo{
			createFn: func(ctx context.Context, a domain.Account) error {
				return domain.ErrAccountExists
			},
		}
		hasher := &mockHasher{
			hashFn: func(ctx context.Context, p string) (string, error) {
				return "hash", nil
			},
		}
		uc := usecase.NewRegisterUsecase(repo, hasher, nil, nil)
		_, err := uc.Execute(context.Background(), usecase.RegisterInput{
			Email:    "existing@example.com",
			Password: "secure-password-15chars",
		})
		if !errors.Is(err, domain.ErrAccountExists) {
			t.Errorf("expected domain.ErrAccountExists, got: %v", err)
		}
	})

	t.Run("context cancelled during hashing preserves context error", func(t *testing.T) {
		repo := &mockAccountRepo{}
		hasher := &mockHasher{
			hashFn: func(ctx context.Context, p string) (string, error) {
				return "", context.DeadlineExceeded
			},
		}
		uc := usecase.NewRegisterUsecase(repo, hasher, nil, nil)
		_, err := uc.Execute(context.Background(), usecase.RegisterInput{
			Email:    "test@example.com",
			Password: "secure-password-15chars",
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded, got: %v", err)
		}
	})
}
