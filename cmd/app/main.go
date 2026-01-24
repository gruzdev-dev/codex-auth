package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/gruzdev-dev/codex-auth/adapters/grpc"
	"github.com/gruzdev-dev/codex-auth/proto"
	grpcServer "github.com/gruzdev-dev/codex-auth/servers/grpc"
	httpServer "github.com/gruzdev-dev/codex-auth/servers/http"
)

func main() {
	container, err := BuildContainer()
	if err != nil {
		log.Fatalf("Fatal error building container: %v", err)
	}

	err = container.Invoke(func(
		httpSrv *httpServer.Server,
		grpcSrv *grpcServer.Server,
		handler *grpc.Handler,
	) error {
		proto.RegisterTmpAccessServer(grpcSrv.GetGRPCServer(), handler)

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		g, ctx := errgroup.WithContext(ctx)

		g.Go(func() error {
			return httpSrv.Start()
		})

		g.Go(func() error {
			return grpcSrv.Start(ctx)
		})

		return g.Wait()
	})

	if err != nil {
		log.Fatalf("Application stopped with error: %v", err)
	}
}
