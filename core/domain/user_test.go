package domain

import (
	"strings"
	"testing"
	"time"

	"codex-auth/core/errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUser_EquivalencePartitioning(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		passwordHash  string
		role          string
		expectedError error
		validate      func(t *testing.T, user *User, err error)
	}{
		{
			name:          "Valid User",
			email:         "a@b.c",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "a@b.c", user.Email)
				assert.Equal(t, "12345678", user.PasswordHash)
				assert.Equal(t, "user", user.Role)
				assert.NotEmpty(t, user.ID)
				_, parseErr := uuid.Parse(user.ID)
				assert.NoError(t, parseErr)
				assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Second)
			},
		},
		{
			name:          "Valid Admin",
			email:         "a@b.c",
			passwordHash:  "12345678",
			role:          "admin",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "admin", user.Role)
			},
		},
		{
			name:          "Invalid Email Format",
			email:         "ab.c",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: errors.ErrInvalidEmailFormat,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidEmailFormat, err)
			},
		},
		{
			name:          "Empty Email",
			email:         "",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: errors.ErrEmailRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailRequired, err)
			},
		},
		{
			name:          "Invalid Role",
			email:         "a@b.c",
			passwordHash:  "12345678",
			role:          "hacker",
			expectedError: errors.ErrInvalidRole,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidRole, err)
			},
		},
		{
			name:          "Whitespace Role",
			email:         "a@b.c",
			passwordHash:  "12345678",
			role:          "   ",
			expectedError: errors.ErrRoleRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrRoleRequired, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.email, tt.passwordHash, tt.role)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, user, err)
			}
		})
	}
}

func TestNewUser_BoundaryValueAnalysis(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		passwordHash  string
		role          string
		expectedError error
		validate      func(t *testing.T, user *User, err error)
	}{
		{
			name:          "Min - 1",
			email:         "a@b.c",
			passwordHash:  strings.Repeat("a", 7),
			role:          "user",
			expectedError: errors.ErrPasswordTooShort,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrPasswordTooShort, err)
			},
		},
		{
			name:          "Min",
			email:         "a@b.c",
			passwordHash:  strings.Repeat("a", 8),
			role:          "user",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, strings.Repeat("a", 8), user.PasswordHash)
			},
		},
		{
			name:          "Min + 1",
			email:         "a@b.c",
			passwordHash:  strings.Repeat("a", 9),
			role:          "user",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, strings.Repeat("a", 9), user.PasswordHash)
			},
		},
		{
			name:          "Max",
			email:         "a@b.c",
			passwordHash:  strings.Repeat("a", 72),
			role:          "user",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, strings.Repeat("a", 72), user.PasswordHash)
			},
		},
		{
			name:          "Max + 1",
			email:         "a@b.c",
			passwordHash:  strings.Repeat("a", 73),
			role:          "user",
			expectedError: errors.ErrPasswordTooLong,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrPasswordTooLong, err)
			},
		},
		{
			name:          "Email boundary - exactly 255 characters",
			email:         strings.Repeat("a", 253) + "@b",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: nil,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, 255, len(user.Email))
			},
		},
		{
			name:          "Email boundary - 256 characters (too long)",
			email:         strings.Repeat("a", 254) + "@b",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: errors.ErrEmailTooLong,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailTooLong, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.email, tt.passwordHash, tt.role)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, user, err)
			}
		})
	}
}
