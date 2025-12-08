package main

import (
	"context"
	"time"

	hasherAdapter "codex-auth/adapters/hasher"
	httpAdapter "codex-auth/adapters/http"
	postgresAdapter "codex-auth/adapters/storage/postgres"
	tokenAdapter "codex-auth/adapters/token"
	"codex-auth/configs"
	"codex-auth/core/ports"
	"codex-auth/core/service"
	httpServer "codex-auth/servers/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/dig"
)

func BuildContainer() (*dig.Container, error) {
	container := dig.New()

	if err := container.Provide(configs.NewConfig); err != nil {
		return nil, err
	}

	if err := container.Provide(newDBPool); err != nil {
		return nil, err
	}

	if err := container.Provide(postgresAdapter.NewUserRepo, dig.As(new(ports.UserRepository))); err != nil {
		return nil, err
	}

	if err := container.Provide(hasherAdapter.NewBcryptHasher, dig.As(new(ports.PasswordHasher))); err != nil {
		return nil, err
	}

	if err := container.Provide(newTokenManager); err != nil {
		return nil, err
	}

	if err := container.Provide(service.NewValidationService, dig.As(new(ports.ValidationService))); err != nil {
		return nil, err
	}

	if err := container.Provide(service.NewUserService, dig.As(new(ports.AuthService))); err != nil {
		return nil, err
	}

	if err := container.Provide(httpAdapter.NewHandler); err != nil {
		return nil, err
	}

	if err := container.Provide(httpServer.NewServer); err != nil {
		return nil, err
	}

	return container, nil
}

func newDBPool(cfg *configs.Config) (*pgxpool.Pool, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func newTokenManager(cfg *configs.Config) (ports.TokenManager, error) {
	return tokenAdapter.NewJWTManager(cfg.JWTSecret, 15*time.Minute), nil
}
