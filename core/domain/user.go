package domain

import (
	"time"

	"codex-auth/core/errors"

	"github.com/google/uuid"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

func NewUser(email, passwordHash, role string) (*User, error) {
	if email == "" {
		return nil, errors.ErrEmailRequired
	}
	if passwordHash == "" {
		return nil, errors.ErrPasswordRequired
	}
	if role == "" {
		return nil, errors.ErrRoleRequired
	}

	return &User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
	}, nil
}
