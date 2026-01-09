//go:build fuzz

package fuzz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"codex-auth/core/domain"
	coreerrors "codex-auth/core/errors"
	"codex-auth/core/ports"
	"codex-auth/core/service"

	"go.uber.org/mock/gomock"
)

func FuzzValidateEmail(f *testing.F) {
	validator := service.NewValidationService()

	f.Add("test@example.com")
	f.Add("user@domain.org")
	f.Add("")
	f.Add("invalid-email")
	f.Add("test@")
	f.Add("@example.com")
	f.Add(strings.Repeat("a", 256) + "@b")
	f.Add("   ")
	f.Add("valid@email.com")
	f.Add("a@b")

	f.Fuzz(func(t *testing.T, email string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic occurred: %v", r)
			}
		}()

		_ = validator.ValidateEmail(email)
	})
}

func FuzzLogin(f *testing.F) {
	f.Add("test@example.com", "password123")
	f.Add("user@domain.org", "securepass")
	f.Add("", "")
	f.Add("invalid-email", "pass")
	f.Add("test@", "password")
	f.Add("@example.com", "pwd")
	f.Add("valid@email.com", "")
	f.Add("user@test.com", strings.Repeat("a", 100))
	f.Add("a@b", "p")
	f.Add("email@domain.com", "correctpassword")

	f.Fuzz(func(t *testing.T, email, password string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic occurred: %v", r)
			}
		}()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		userRepo := ports.NewMockUserRepository(ctrl)
		hasher := ports.NewMockPasswordHasher(ctrl)
		tokenManager := ports.NewMockTokenManager(ctrl)
		validator := service.NewValidationService()

		hasUser := strings.Contains(email, "@") && len(email) > 3 && password != ""

		if hasUser {
			user := &domain.User{
				ID:           "user-id",
				Email:        email,
				PasswordHash: "hashed_password",
				Role:         "user",
				Metadata:     make(map[string]string),
			}
			userRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(user, nil)
			hasher.EXPECT().Compare("hashed_password", password).Return(errors.New("password mismatch"))
		} else {
			userRepo.EXPECT().GetByEmail(gomock.Any(), email).Return(nil, coreerrors.ErrUserNotFound)
		}

		profileProvider := ports.NewMockProfileProvider(ctrl)
		service := service.NewUserService(userRepo, hasher, tokenManager, validator, profileProvider)
		_, _ = service.Login(context.Background(), email, password)
	})
}
