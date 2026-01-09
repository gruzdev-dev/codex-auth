package ports

import (
	"context"
)

//go:generate mockgen -source=profile.go -destination=profile_mocks.go -package=ports

type ProfileProvider interface {
	GetExtraClaims(ctx context.Context, email string) (map[string]string, error)
}
