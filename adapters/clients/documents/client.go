package documents

import (
	"context"
	"strings"

	"github.com/gruzdev-dev/codex-auth/core/ports"
	"github.com/gruzdev-dev/codex-documents/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type client struct {
	grpcClient     proto.AuthIntegrationClient
	internalSecret string
}

func NewClient(conn grpc.ClientConnInterface, internalSecret string) ports.ProfileProvider {
	return &client{
		grpcClient:     proto.NewAuthIntegrationClient(conn),
		internalSecret: internalSecret,
	}
}

func (c *client) GetExtraClaims(ctx context.Context, email string) (map[string]string, error) {
	md := metadata.New(map[string]string{
		"x-internal-token": c.internalSecret,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &proto.CreatePatientRequest{
		Email: email,
	}

	resp, err := c.grpcClient.CreatePatient(ctx, req)
	if err != nil {
		return nil, err
	}

	metadata := make(map[string]string)
	metadata["patient_id"] = resp.PatientId
	metadata["scopes"] = strings.Join(resp.Scopes, " ")

	return metadata, nil
}
