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
	CreatedAt    time.Time
}

const (
	UserRole          = "user"
	AdminRole         = "admin"
	MinPasswordLength = 8
	MaxPasswordLength = 72
)

func NewUser(email, passwordHash, role string) (*User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, errors.ErrEmailRequired
	}
	if len(email) > 255 {
		return nil, errors.ErrEmailTooLong
	}
	if !strings.Contains(email, "@") {
		return nil, errors.ErrInvalidEmailFormat
	}

	passwordHash = strings.TrimSpace(passwordHash)
	if passwordHash == "" {
		return nil, errors.ErrPasswordRequired
	}
	if len(passwordHash) < MinPasswordLength {
		return nil, errors.ErrPasswordTooShort
	}
	if len(passwordHash) > MaxPasswordLength {
		return nil, errors.ErrPasswordTooLong
	}

	role = strings.TrimSpace(role)
	if role == "" {
		return nil, errors.ErrRoleRequired
	}
	if role != UserRole && role != AdminRole {
		return nil, errors.ErrInvalidRole
	}

	return &User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
	}, nil
}
