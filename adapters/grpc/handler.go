package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/gruzdev-dev/codex-auth/core/ports"
	"github.com/gruzdev-dev/codex-auth/proto"
)

type Handler struct {
	proto.UnimplementedTmpAccessServer
	service ports.AccessService
}

func NewHandler(service ports.AccessService) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) GenerateTmpToken(ctx context.Context, req *proto.GenerateTmpTokenRequest) (*proto.GenerateTmpTokenResponse, error) {
	token, err := h.service.GrantTmpAccess(req.Payload, time.Duration(req.TtlSeconds))
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}
	return &proto.GenerateTmpTokenResponse{
		Token: token,
	}, nil
}
