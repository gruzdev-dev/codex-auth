package domain

import (
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
			expectedError: errors.ErrInvalidUser,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidUser, err)
			},
		},
		{
			name:          "Empty Email",
			email:         "",
			passwordHash:  "12345678",
			role:          "user",
			expectedError: errors.ErrInvalidUser,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidUser, err)
			},
		},
		{
			name:          "Empty PasswordHash",
			email:         "a@b.c",
			passwordHash:  "",
			role:          "user",
			expectedError: errors.ErrInvalidUser,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidUser, err)
			},
		},
		{
			name:          "Empty Role",
			email:         "a@b.c",
			passwordHash:  "12345678",
			role:          "",
			expectedError: errors.ErrInvalidUser,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrInvalidUser, err)
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
