package ports

import (
	"context"

	"codex-auth/core/domain"
)

//go:generate mockgen -source=interfaces.go -destination=interfaces_mocks.go -package=ports

type AuthService interface {
	Register(ctx context.Context, email, password string) (*domain.User, error)
	Login(ctx context.Context, email, password string) (*domain.TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*domain.TokenPair, error)
	ValidateToken(ctx context.Context, accessToken string) (*domain.Claims, error)
}

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) error
}

type TokenManager interface {
	NewPair(userID, role string) (*domain.TokenPair, error)
	Parse(accessToken string) (*domain.Claims, error)
	ValidateRefreshToken(refreshToken string) (string, error)
}
