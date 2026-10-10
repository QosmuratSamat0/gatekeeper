package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/domain"
	"github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase"
)

type mockSessionMgmtRepo struct {
	listFn         func(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error)
	revokeTargetFn func(ctx context.Context, accountID, callerSessionID, targetSessionID string) (bool, error)
	revokeAllFn    func(ctx context.Context, accountID, callerSessionID string) error
}

func (m *mockSessionMgmtRepo) ListActiveSessions(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error) {
	if m.listFn != nil {
		return m.listFn(ctx, accountID, callerSessionID, filter)
	}
	return usecase.SessionListPage{}, nil
}

func (m *mockSessionMgmtRepo) RevokeSessionTarget(ctx context.Context, accountID, callerSessionID, targetSessionID string) (bool, error) {
	if m.revokeTargetFn != nil {
		return m.revokeTargetFn(ctx, accountID, callerSessionID, targetSessionID)
	}
	return false, nil
}

func (m *mockSessionMgmtRepo) RevokeAllSessions(ctx context.Context, accountID, callerSessionID string) error {
	if m.revokeAllFn != nil {
		return m.revokeAllFn(ctx, accountID, callerSessionID)
	}
	return nil
}

func TestListSessionsUsecase(t *testing.T) {
	ctx := context.Background()

	t.Run("nil repo error", func(t *testing.T) {
		_, err := usecase.NewListSessionsUsecase(nil)
		if err == nil {
			t.Fatal("expected error with nil repo")
		}
	})

	t.Run("missing parameters error", func(t *testing.T) {
		uc, err := usecase.NewListSessionsUsecase(&mockSessionMgmtRepo{})
		if err != nil {
			t.Fatalf("unexpected init error: %v", err)
		}
		_, err = uc.Execute(ctx, "", "sess-1", usecase.SessionListFilter{})
		if err == nil {
			t.Fatal("expected error with empty accountID")
		}
		_, err = uc.Execute(ctx, "acc-1", "", usecase.SessionListFilter{})
		if err == nil {
			t.Fatal("expected error with empty callerSessionID")
		}
	})

	t.Run("clamps limits and returns page", func(t *testing.T) {
		var capturedLimit int
		repo := &mockSessionMgmtRepo{
			listFn: func(ctx context.Context, accountID, callerSessionID string, filter usecase.SessionListFilter) (usecase.SessionListPage, error) {
				capturedLimit = filter.Limit
				return usecase.SessionListPage{
					Sessions: []usecase.SessionSummary{
						{
							ID:        callerSessionID,
							CreatedAt: time.Now().UTC(),
							ExpiresAt: time.Now().UTC().Add(time.Hour),
							IsCurrent: true,
						},
					},
				}, nil
			},
		}

		uc, err := usecase.NewListSessionsUsecase(repo)
		if err != nil {
			t.Fatalf("unexpected init error: %v", err)
		}

		// 0 limit defaults to 20
		page, err := uc.Execute(ctx, "acc-1", "sess-1", usecase.SessionListFilter{Limit: 0})
		if err != nil {
			t.Fatalf("unexpected execute error: %v", err)
		}
		if capturedLimit != 20 {
			t.Fatalf("expected limit 20, got %d", capturedLimit)
		}
		if len(page.Sessions) != 1 || !page.Sessions[0].IsCurrent {
			t.Fatalf("unexpected sessions page: %+v", page)
		}

		// limit > 100 clamped to 100
		_, err = uc.Execute(ctx, "acc-1", "sess-1", usecase.SessionListFilter{Limit: 150})
		if err != nil {
			t.Fatalf("unexpected execute error: %v", err)
		}
		if capturedLimit != 100 {
			t.Fatalf("expected limit 100, got %d", capturedLimit)
		}
	})
}

func TestRevokeSessionUsecase(t *testing.T) {
	ctx := context.Background()

	t.Run("nil repo error", func(t *testing.T) {
		_, err := usecase.NewRevokeSessionUsecase(nil)
		if err == nil {
			t.Fatal("expected error with nil repo")
		}
	})

	t.Run("missing parameters", func(t *testing.T) {
		uc, _ := usecase.NewRevokeSessionUsecase(&mockSessionMgmtRepo{})
		if err := uc.Execute(ctx, "", "sess-1", "sess-2"); err == nil {
			t.Fatal("expected error with empty accountID")
		}
		if err := uc.Execute(ctx, "acc-1", "", "sess-2"); err == nil {
			t.Fatal("expected error with empty callerSessionID")
		}
		if err := uc.Execute(ctx, "acc-1", "sess-1", ""); err == nil {
			t.Fatal("expected error with empty targetSessionID")
		}
	})

	t.Run("successful revocation", func(t *testing.T) {
		called := false
		repo := &mockSessionMgmtRepo{
			revokeTargetFn: func(ctx context.Context, accountID, callerSessionID, targetSessionID string) (bool, error) {
				called = true
				return false, nil
			},
		}
		uc, _ := usecase.NewRevokeSessionUsecase(repo)
		if err := uc.Execute(ctx, "acc-1", "sess-1", "sess-2"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Fatal("expected repo method to be called")
		}
	})

	t.Run("error propagation", func(t *testing.T) {
		expectedErr := domain.ErrSessionNotFound
		repo := &mockSessionMgmtRepo{
			revokeTargetFn: func(ctx context.Context, accountID, callerSessionID, targetSessionID string) (bool, error) {
				return false, expectedErr
			},
		}
		uc, _ := usecase.NewRevokeSessionUsecase(repo)
		err := uc.Execute(ctx, "acc-1", "sess-1", "sess-2")
		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected %v, got %v", expectedErr, err)
		}
	})
}

func TestLogoutAllUsecase(t *testing.T) {
	ctx := context.Background()

	t.Run("nil repo error", func(t *testing.T) {
		_, err := usecase.NewLogoutAllUsecase(nil)
		if err == nil {
			t.Fatal("expected error with nil repo")
		}
	})

	t.Run("missing parameters", func(t *testing.T) {
		uc, _ := usecase.NewLogoutAllUsecase(&mockSessionMgmtRepo{})
		if err := uc.Execute(ctx, "", "sess-1"); err == nil {
			t.Fatal("expected error with empty accountID")
		}
		if err := uc.Execute(ctx, "acc-1", ""); err == nil {
			t.Fatal("expected error with empty callerSessionID")
		}
	})

	t.Run("successful revocation of all", func(t *testing.T) {
		called := false
		repo := &mockSessionMgmtRepo{
			revokeAllFn: func(ctx context.Context, accountID, callerSessionID string) error {
				called = true
				return nil
			},
		}
		uc, _ := usecase.NewLogoutAllUsecase(repo)
		if err := uc.Execute(ctx, "acc-1", "sess-1"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Fatal("expected repo method to be called")
		}
	})
}
