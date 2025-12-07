package domain

import (
	"testing"
	"time"

	"codex-auth/core/errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		passwordHash  string
		role          string
		expectError   bool
		expectedError error
		validate      func(t *testing.T, user *User, err error)
	}{
		{
			name:         "success with valid fields",
			email:        "test@example.com",
			passwordHash: "hashed_password_123",
			role:         "user",
			expectError:  false,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "test@example.com", user.Email)
				assert.Equal(t, "hashed_password_123", user.PasswordHash)
				assert.Equal(t, "user", user.Role)
				assert.NotEmpty(t, user.ID)
				assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Second)

				_, parseErr := uuid.Parse(user.ID)
				assert.NoError(t, parseErr, "ID should be a valid UUID")
			},
		},
		{
			name:          "empty email",
			email:         "",
			passwordHash:  "hashed_password_123",
			role:          "user",
			expectError:   true,
			expectedError: errors.ErrEmailRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailRequired, err)
			},
		},
		{
			name:          "empty password hash",
			email:         "test@example.com",
			passwordHash:  "",
			role:          "user",
			expectError:   true,
			expectedError: errors.ErrPasswordRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrPasswordRequired, err)
			},
		},
		{
			name:          "empty role",
			email:         "test@example.com",
			passwordHash:  "hashed_password_123",
			role:          "",
			expectError:   true,
			expectedError: errors.ErrRoleRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrRoleRequired, err)
			},
		},
		{
			name:          "all fields empty",
			email:         "",
			passwordHash:  "",
			role:          "",
			expectError:   true,
			expectedError: errors.ErrEmailRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailRequired, err)
			},
		},
		{
			name:          "email and password empty",
			email:         "",
			passwordHash:  "",
			role:          "user",
			expectError:   true,
			expectedError: errors.ErrEmailRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailRequired, err)
			},
		},
		{
			name:          "email and role empty",
			email:         "",
			passwordHash:  "hashed_password_123",
			role:          "",
			expectError:   true,
			expectedError: errors.ErrEmailRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrEmailRequired, err)
			},
		},
		{
			name:          "password and role empty",
			email:         "test@example.com",
			passwordHash:  "",
			role:          "",
			expectError:   true,
			expectedError: errors.ErrPasswordRequired,
			validate: func(t *testing.T, user *User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, errors.ErrPasswordRequired, err)
			},
		},
		{
			name:         "whitespace only email",
			email:        "   ",
			passwordHash: "hashed_password_123",
			role:         "user",
			expectError:  false,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "   ", user.Email)
			},
		},
		{
			name:         "whitespace only password hash",
			email:        "test@example.com",
			passwordHash: "   ",
			role:         "user",
			expectError:  false,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "   ", user.PasswordHash)
			},
		},
		{
			name:         "whitespace only role",
			email:        "test@example.com",
			passwordHash: "hashed_password_123",
			role:         "   ",
			expectError:  false,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "   ", user.Role)
			},
		},
		{
			name:         "different roles",
			email:        "test@example.com",
			passwordHash: "hashed_password_123",
			role:         "admin",
			expectError:  false,
			validate: func(t *testing.T, user *User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "admin", user.Role)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.email, tt.passwordHash, tt.role)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, user, err)
			}
		})
	}
}

func TestNewUser_UniqueIDs(t *testing.T) {
	users := make([]*User, 10)
	for i := range 10 {
		user, err := NewUser("test@example.com", "hash", "user")
		require.NoError(t, err)
		require.NotNil(t, user)
		users[i] = user
	}

	for i := range users {
		for j := i + 1; j < len(users); j++ {
			assert.NotEqual(t, users[i].ID, users[j].ID, "Each user should have a unique ID")
		}
	}
}

func TestNewUser_CreatedAt(t *testing.T) {
	beforeCreation := time.Now()
	user, err := NewUser("test@example.com", "hash", "user")
	afterCreation := time.Now()

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, user.CreatedAt.After(beforeCreation) || user.CreatedAt.Equal(beforeCreation))
	assert.True(t, user.CreatedAt.Before(afterCreation) || user.CreatedAt.Equal(afterCreation))
}
