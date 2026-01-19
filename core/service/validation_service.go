package service

import (
	"strings"

	"github.com/gruzdev-dev/codex-auth/core/domain"
	"github.com/gruzdev-dev/codex-auth/core/errors"
	"github.com/gruzdev-dev/codex-auth/core/ports"
)

type validationService struct{}

func NewValidationService() ports.ValidationService {
	return &validationService{}
}

func (v *validationService) ValidateEmail(email string) error {

	// Внедрение ошибки для проверки фазинга
	// if len(email) == 13 && email[0] == '!' {
	// 	_ = email[15]
	// }

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
