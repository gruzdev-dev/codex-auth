//go:build integration

package bdd

import (
	"context"
)

type noopProfileProvider struct{}

func (n *noopProfileProvider) GetExtraClaims(ctx context.Context, email string) (map[string]string, error) {
	return make(map[string]string), nil
}
