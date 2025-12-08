package service

import (
	"strings"

	"codex-auth/core/domain"
	"codex-auth/core/errors"
	"codex-auth/core/ports"
)

type validationService struct{}

func NewValidationService() ports.ValidationService {
	return &validationService{}
}

func (v *validationService) ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.ErrEmailRequired
	}
	if len(email) > 255 {
		return errors.ErrEmailTooLong
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.ErrInvalidEmailFormat
	}
	return nil
}

func (v *validationService) ValidatePassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return errors.ErrPasswordRequired
	}
	if len(password) < domain.MinPasswordLength {
		return errors.ErrPasswordTooShort
	}
	if len(password) > domain.MaxPasswordLength {
		return errors.ErrPasswordTooLong
	}
	return nil
}
