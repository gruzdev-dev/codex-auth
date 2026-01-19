package main

import (
	"context"
	"time"

	documentsAdapter "github.com/gruzdev-dev/codex-auth/adapters/clients/documents"
	hasherAdapter "github.com/gruzdev-dev/codex-auth/adapters/hasher"
	httpAdapter "github.com/gruzdev-dev/codex-auth/adapters/http"
	postgresAdapter "github.com/gruzdev-dev/codex-auth/adapters/storage/postgres"
	tokenAdapter "github.com/gruzdev-dev/codex-auth/adapters/token"
	"github.com/gruzdev-dev/codex-auth/configs"
	"github.com/gruzdev-dev/codex-auth/core/ports"
	"github.com/gruzdev-dev/codex-auth/core/service"
	httpServer "github.com/gruzdev-dev/codex-auth/servers/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/dig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	if err := container.Provide(newDocumentsClient, dig.As(new(ports.ProfileProvider))); err != nil {
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
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL())
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func newTokenManager(cfg *configs.Config) (ports.TokenManager, error) {
	return tokenAdapter.NewJWTManager(cfg.Auth.JWTSecret, 15*time.Minute), nil
}

func newDocumentsClient(cfg *configs.Config) (ports.ProfileProvider, error) {
	conn, err := grpc.NewClient(cfg.DocumentsService.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return documentsAdapter.NewClient(conn, cfg.Auth.InternalSecret), nil
}
