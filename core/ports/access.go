package ports

import "time"

//go:generate mockgen -source=access.go -destination=access_mocks.go -package=ports

type TmpTokenManager interface {
	GenerateTmpToken(payload map[string]string, ttl time.Duration) (string, error)
	ValidateTmpToken(tmpToken string) error
}

type AccessService interface {
	GrantTmpAccess(payload map[string]string, ttl time.Duration) (string, error)
	CheckTmpToken(tmpToken string) error
}
