package service

import (
	"time"

	"github.com/gruzdev-dev/codex-auth/core/ports"
)

type accessService struct {
	manager ports.TmpTokenManager
}

func NewAccessService(manager ports.TmpTokenManager) *accessService {
	return &accessService{
		manager: manager,
	}
}

func (s *accessService) GrantTmpAccess(payload map[string]string, ttl time.Duration) (string, error) {
	return s.manager.GenerateTmpToken(payload, ttl)
}

func (s *accessService) CheckTmpAccess(tmpToken string) error {
	return s.manager.ValidateTmpToken(tmpToken)
}
