package domain

import (
	"strings"
	"time"

	"codex-auth/core/errors"

	"github.com/google/uuid"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	Metadata     map[string]string
	CreatedAt    time.Time
}

const (
	UserRole          = "user"
	AdminRole         = "admin"
	MinPasswordLength = 8
	MaxPasswordLength = 72
)

func NewUser(email, passwordHash, role string, metadata map[string]string) (*User, error) {
	email = strings.TrimSpace(email)
	passwordHash = strings.TrimSpace(passwordHash)
	role = strings.TrimSpace(role)

	if email == "" || passwordHash == "" || role == "" {
		return nil, errors.ErrInvalidUser
	}

	if role != UserRole && role != AdminRole {
		return nil, errors.ErrInvalidRole
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}

	return &User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		Metadata:     metadata,
		CreatedAt:    time.Now(),
	}, nil
}
