package service

import (
	"strings"
	"testing"

	"github.com/gruzdev-dev/codex-auth/core/domain"
	"github.com/gruzdev-dev/codex-auth/core/errors"

	"github.com/stretchr/testify/assert"
)

func TestValidationService_ValidateEmail_EquivalencePartitioning(t *testing.T) {
	validator := NewValidationService()

	tests := []struct {
		name          string
		email         string
		expectedError error
	}{
		{
			name:          "Valid email",
			email:         "test@example.com",
			expectedError: nil,
		},
		{
			name:          "Empty email",
			email:         "",
			expectedError: errors.ErrEmailRequired,
		},
		{
			name:          "Email without @",
			email:         "invalid-email",
			expectedError: errors.ErrInvalidEmailFormat,
		},
		{
			name:          "Email too long",
			email:         strings.Repeat("a", 254) + "@b",
			expectedError: errors.ErrEmailTooLong,
		},
		{
			name:          "Whitespace email",
			email:         "   ",
			expectedError: errors.ErrEmailRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmail(tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationService_ValidateEmail_BoundaryValueAnalysis(t *testing.T) {
	validator := NewValidationService()

	tests := []struct {
		name          string
		email         string
		expectedError error
		validate      func(t *testing.T, email string, err error)
	}{
		{
			name:          "Exactly 255 characters",
			email:         strings.Repeat("a", 253) + "@b",
			expectedError: nil,
			validate: func(t *testing.T, email string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 255, len(email))
			},
		},
		{
			name:          "256 characters (too long)",
			email:         strings.Repeat("a", 254) + "@b",
			expectedError: errors.ErrEmailTooLong,
			validate: func(t *testing.T, email string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrEmailTooLong, err)
			},
		},
		{
			name:          "1 character (invalid - no @)",
			email:         "a",
			expectedError: errors.ErrInvalidEmailFormat,
			validate: func(t *testing.T, email string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrInvalidEmailFormat, err)
			},
		},
		{
			name:          "Email with @ at start",
			email:         "@example.com",
			expectedError: errors.ErrInvalidEmailFormat,
			validate: func(t *testing.T, email string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrInvalidEmailFormat, err)
			},
		},
		{
			name:          "Email with @ at end",
			email:         "test@",
			expectedError: errors.ErrInvalidEmailFormat,
			validate: func(t *testing.T, email string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrInvalidEmailFormat, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmail(tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, tt.email, err)
			}
		})
	}
}

func TestValidationService_ValidatePassword_EquivalencePartitioning(t *testing.T) {
	validator := NewValidationService()

	tests := []struct {
		name          string
		password      string
		expectedError error
	}{
		{
			name:          "Valid password",
			password:      "password123",
			expectedError: nil,
		},
		{
			name:          "Empty password",
			password:      "",
			expectedError: errors.ErrPasswordRequired,
		},
		{
			name:          "Password too short",
			password:      "short",
			expectedError: errors.ErrPasswordTooShort,
		},
		{
			name:          "Password too long",
			password:      strings.Repeat("a", 73),
			expectedError: errors.ErrPasswordTooLong,
		},
		{
			name:          "Whitespace password",
			password:      "   ",
			expectedError: errors.ErrPasswordRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationService_ValidatePassword_BoundaryValueAnalysis(t *testing.T) {
	validator := NewValidationService()

	tests := []struct {
		name          string
		password      string
		expectedError error
		validate      func(t *testing.T, password string, err error)
	}{
		{
			name:          "7 characters (Min - 1, invalid)",
			password:      strings.Repeat("a", 7),
			expectedError: errors.ErrPasswordTooShort,
			validate: func(t *testing.T, password string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrPasswordTooShort, err)
				assert.Equal(t, 7, len(password))
			},
		},
		{
			name:          "8 characters (Min, valid)",
			password:      strings.Repeat("a", 8),
			expectedError: nil,
			validate: func(t *testing.T, password string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 8, len(password))
			},
		},
		{
			name:          "9 characters (Min + 1, valid)",
			password:      strings.Repeat("a", 9),
			expectedError: nil,
			validate: func(t *testing.T, password string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 9, len(password))
			},
		},
		{
			name:          "72 characters (Max, valid)",
			password:      strings.Repeat("a", domain.MaxPasswordLength),
			expectedError: nil,
			validate: func(t *testing.T, password string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, domain.MaxPasswordLength, len(password))
			},
		},
		{
			name:          "73 characters (Max + 1, invalid)",
			password:      strings.Repeat("a", 73),
			expectedError: errors.ErrPasswordTooLong,
			validate: func(t *testing.T, password string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrPasswordTooLong, err)
				assert.Equal(t, 73, len(password))
			},
		},
		{
			name:          "0 characters (empty, invalid)",
			password:      "",
			expectedError: errors.ErrPasswordRequired,
			validate: func(t *testing.T, password string, err error) {
				assert.Error(t, err)
				assert.Equal(t, errors.ErrPasswordRequired, err)
				assert.Equal(t, 0, len(password))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, tt.password, err)
			}
		})
	}
}
