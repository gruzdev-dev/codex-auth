package main

import (
	httpAdapter "codex-auth/adapters/http"
	storageAdapter "codex-auth/adapters/storage"
	"codex-auth/configs"
	"codex-auth/core/ports"
	"codex-auth/core/service"
	httpServer "codex-auth/servers/http"

	"go.uber.org/dig"
)

func BuildContainer() (*dig.Container, error) {
	container := dig.New()

	if err := container.Provide(configs.NewConfig); err != nil {
		return nil, err
	}
	if err := container.Provide(storageAdapter.NewInMemoryRepo); err != nil {
		return nil, err
	}
	if err := container.Provide(service.NewUserService, dig.As(new(ports.UserService))); err != nil {
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
