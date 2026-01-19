package service

import (
	"context"
	"errors"
	"testing"

	"github.com/gruzdev-dev/codex-auth/core/domain"
	coreerrors "github.com/gruzdev-dev/codex-auth/core/errors"
	"github.com/gruzdev-dev/codex-auth/core/ports"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestUserService_Register(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		password       string
		setupMocks     func(*ports.MockUserRepository, *ports.MockPasswordHasher, *ports.MockTokenManager, *ports.MockValidationService, *ports.MockProfileProvider)
		expectedError  error
		validateResult func(*testing.T, *domain.User, error)
	}{
		{
			name:     "success path",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, coreerrors.ErrUserNotFound)
				profileProvider.EXPECT().GetExtraClaims(gomock.Any(), "test@example.com").Return(map[string]string{"patient_id": "patient-123", "scopes": "patient/*.read"}, nil)
				hasher.EXPECT().Hash("password123").Return("hashed_password", nil)
				userRepo.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, user *domain.User) error {
					require.NotEmpty(t, user.ID)
					require.Equal(t, "test@example.com", user.Email)
					require.Equal(t, "hashed_password", user.PasswordHash)
					require.Equal(t, "user", user.Role)
					require.NotNil(t, user.Metadata)
					require.Equal(t, "patient-123", user.Metadata["patient_id"])
					require.Equal(t, "patient/*.read", user.Metadata["scopes"])
					return nil
				})
			},
			expectedError: nil,
			validateResult: func(t *testing.T, user *domain.User, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, "test@example.com", user.Email)
				assert.Equal(t, "hashed_password", user.PasswordHash)
				assert.Equal(t, "user", user.Role)
			},
		},
		{
			name:     "user already exists",
			email:    "existing@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("existing@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				existingUser := &domain.User{Email: "existing@example.com", Metadata: make(map[string]string)}
				userRepo.EXPECT().GetByEmail(gomock.Any(), "existing@example.com").Return(existingUser, nil)
			},
			expectedError: coreerrors.ErrUserAlreadyExists,
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, coreerrors.ErrUserAlreadyExists, err)
			},
		},
		{
			name:     "repository error on get by email",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, errors.New("database error"))
			},
			expectedError: errors.New("database error"),
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, "database error", err.Error())
			},
		},
		{
			name:     "hash error",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, coreerrors.ErrUserNotFound)
				profileProvider.EXPECT().GetExtraClaims(gomock.Any(), "test@example.com").Return(map[string]string{"patient_id": "patient-123"}, nil)
				hasher.EXPECT().Hash("password123").Return("", errors.New("hashing failed"))
			},
			expectedError: errors.New("hashing failed"),
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, "hashing failed", err.Error())
			},
		},
		{
			name:     "save error",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, coreerrors.ErrUserNotFound)
				profileProvider.EXPECT().GetExtraClaims(gomock.Any(), "test@example.com").Return(map[string]string{"patient_id": "patient-123"}, nil)
				hasher.EXPECT().Hash("password123").Return("hashed_password", nil)
				userRepo.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))
			},
			expectedError: errors.New("save failed"),
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, "save failed", err.Error())
			},
		},
		{
			name:     "email validation error",
			email:    "invalid-email",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("invalid-email").Return(coreerrors.ErrInvalidEmailFormat)
			},
			expectedError: coreerrors.ErrInvalidEmailFormat,
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, coreerrors.ErrInvalidEmailFormat, err)
			},
		},
		{
			name:     "password validation error",
			email:    "test@example.com",
			password: "bad",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("bad").Return(coreerrors.ErrPasswordTooShort)
			},
			expectedError: coreerrors.ErrPasswordTooShort,
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, coreerrors.ErrPasswordTooShort, err)
			},
		},
		{
			name:     "GetExtraClaims error",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
				profileProvider *ports.MockProfileProvider,
			) {
				validator.EXPECT().ValidateEmail("test@example.com").Return(nil)
				validator.EXPECT().ValidatePassword("password123").Return(nil)
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, coreerrors.ErrUserNotFound)
				profileProvider.EXPECT().GetExtraClaims(gomock.Any(), "test@example.com").Return(nil, errors.New("documents service error"))
			},
			expectedError: errors.New("documents service error"),
			validateResult: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Equal(t, "documents service error", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo := ports.NewMockUserRepository(ctrl)
			hasher := ports.NewMockPasswordHasher(ctrl)
			tokenManager := ports.NewMockTokenManager(ctrl)
			validator := ports.NewMockValidationService(ctrl)

			profileProvider := ports.NewMockProfileProvider(ctrl)

			tt.setupMocks(userRepo, hasher, tokenManager, validator, profileProvider)

			service := NewUserService(userRepo, hasher, tokenManager, validator, profileProvider)
			user, err := service.Register(context.Background(), tt.email, tt.password)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, user, err)
			}
		})
	}
}

func TestUserService_Login(t *testing.T) {
	tests := []struct {
		name           string
		branch         string
		email          string
		password       string
		setupMocks     func(*ports.MockUserRepository, *ports.MockPasswordHasher, *ports.MockTokenManager, *ports.MockValidationService)
		expectedError  error
		validateResult func(*testing.T, *domain.TokenPair, error)
	}{
		{
			name:     "success path",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				user := &domain.User{
					ID:           "user-id",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Role:         "user",
					Metadata:     make(map[string]string),
				}
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(user, nil)
				hasher.EXPECT().Compare("hashed_password", "password123").Return(nil)
				tokenPair := &domain.TokenPair{
					AccessToken:  "access_token",
					RefreshToken: "refresh_token",
				}
				tokenManager.EXPECT().NewPair(gomock.Any()).DoAndReturn(func(u *domain.User) (*domain.TokenPair, error) {
					require.Equal(t, user.ID, u.ID)
					require.Equal(t, user.Role, u.Role)
					return tokenPair, nil
				})
			},
			expectedError: nil,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				require.NoError(t, err)
				require.NotNil(t, tokenPair)
				assert.Equal(t, "access_token", tokenPair.AccessToken)
				assert.Equal(t, "refresh_token", tokenPair.RefreshToken)
			},
		},
		{
			name:     "user not found",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, coreerrors.ErrUserNotFound)
			},
			expectedError: coreerrors.ErrInvalidCredentials,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrInvalidCredentials, err)
			},
		},
		{
			name:     "repository error",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(nil, errors.New("database error"))
			},
			expectedError: coreerrors.ErrInvalidCredentials,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrInvalidCredentials, err)
			},
		},
		{
			name:     "invalid password",
			email:    "test@example.com",
			password: "wrong_password",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				user := &domain.User{
					ID:           "user-id",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Role:         "user",
					Metadata:     make(map[string]string),
				}
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(user, nil)
				hasher.EXPECT().Compare("hashed_password", "wrong_password").Return(errors.New("password mismatch"))
			},
			expectedError: coreerrors.ErrInvalidCredentials,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrInvalidCredentials, err)
			},
		},
		{
			name:     "token generation error",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				user := &domain.User{
					ID:           "user-id",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Role:         "user",
					Metadata:     make(map[string]string),
				}
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(user, nil)
				hasher.EXPECT().Compare("hashed_password", "password123").Return(nil)
				tokenManager.EXPECT().NewPair(gomock.Any()).Return(nil, errors.New("token generation failed"))
			},
			expectedError: errors.New("token generation failed"),
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, "token generation failed", err.Error())
			},
		},
		{
			name:     "repository error with user returned",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				user := &domain.User{
					ID:           "user-id",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Role:         "user",
					Metadata:     make(map[string]string),
				}
				userRepo.EXPECT().GetByEmail(gomock.Any(), "test@example.com").Return(user, errors.New("database error"))
			},
			expectedError: coreerrors.ErrInvalidCredentials,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrInvalidCredentials, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo := ports.NewMockUserRepository(ctrl)
			hasher := ports.NewMockPasswordHasher(ctrl)
			tokenManager := ports.NewMockTokenManager(ctrl)
			validator := ports.NewMockValidationService(ctrl)
			profileProvider := ports.NewMockProfileProvider(ctrl)

			tt.setupMocks(userRepo, hasher, tokenManager, validator)

			service := NewUserService(userRepo, hasher, tokenManager, validator, profileProvider)
			tokenPair, err := service.Login(context.Background(), tt.email, tt.password)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, tokenPair, err)
			}
		})
	}
}

func TestUserService_Refresh(t *testing.T) {
	tests := []struct {
		name           string
		refreshToken   string
		setupMocks     func(*ports.MockUserRepository, *ports.MockPasswordHasher, *ports.MockTokenManager, *ports.MockValidationService)
		expectedError  error
		validateResult func(*testing.T, *domain.TokenPair, error)
	}{
		{
			name:         "success path",
			refreshToken: "valid_refresh_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("valid_refresh_token").Return("user-id", nil)
				user := &domain.User{
					ID:       "user-id",
					Email:    "test@example.com",
					Role:     "user",
					Metadata: make(map[string]string),
				}
				userRepo.EXPECT().GetByID(gomock.Any(), "user-id").Return(user, nil)
				tokenPair := &domain.TokenPair{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
				}
				tokenManager.EXPECT().NewPair(gomock.Any()).DoAndReturn(func(u *domain.User) (*domain.TokenPair, error) {
					require.Equal(t, user.ID, u.ID)
					require.Equal(t, user.Role, u.Role)
					return tokenPair, nil
				})
			},
			expectedError: nil,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				require.NoError(t, err)
				require.NotNil(t, tokenPair)
				assert.Equal(t, "new_access_token", tokenPair.AccessToken)
				assert.Equal(t, "new_refresh_token", tokenPair.RefreshToken)
			},
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("invalid_token").Return("", errors.New("invalid token"))
			},
			expectedError: coreerrors.ErrInvalidToken,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrInvalidToken, err)
			},
		},
		{
			name:         "user not found",
			refreshToken: "valid_refresh_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("valid_refresh_token").Return("user-id", nil)
				userRepo.EXPECT().GetByID(gomock.Any(), "user-id").Return(nil, coreerrors.ErrUserNotFound)
			},
			expectedError: coreerrors.ErrUserNotFound,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrUserNotFound, err)
			},
		},
		{
			name:         "repository error",
			refreshToken: "valid_refresh_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("valid_refresh_token").Return("user-id", nil)
				userRepo.EXPECT().GetByID(gomock.Any(), "user-id").Return(nil, errors.New("database error"))
			},
			expectedError: coreerrors.ErrUserNotFound,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrUserNotFound, err)
			},
		},
		{
			name:         "token generation error",
			refreshToken: "valid_refresh_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("valid_refresh_token").Return("user-id", nil)
				user := &domain.User{
					ID:       "user-id",
					Email:    "test@example.com",
					Role:     "user",
					Metadata: make(map[string]string),
				}
				userRepo.EXPECT().GetByID(gomock.Any(), "user-id").Return(user, nil)
				tokenManager.EXPECT().NewPair(gomock.Any()).Return(nil, errors.New("token generation failed"))
			},
			expectedError: errors.New("token generation failed"),
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, "token generation failed", err.Error())
			},
		},
		{
			name:         "repository error with user returned",
			refreshToken: "valid_refresh_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().ValidateRefreshToken("valid_refresh_token").Return("user-id", nil)
				user := &domain.User{
					ID:       "user-id",
					Email:    "test@example.com",
					Role:     "user",
					Metadata: make(map[string]string),
				}
				userRepo.EXPECT().GetByID(gomock.Any(), "user-id").Return(user, errors.New("database error"))
			},
			expectedError: coreerrors.ErrUserNotFound,
			validateResult: func(t *testing.T, tokenPair *domain.TokenPair, err error) {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				assert.Equal(t, coreerrors.ErrUserNotFound, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo := ports.NewMockUserRepository(ctrl)
			hasher := ports.NewMockPasswordHasher(ctrl)
			tokenManager := ports.NewMockTokenManager(ctrl)
			validator := ports.NewMockValidationService(ctrl)
			profileProvider := ports.NewMockProfileProvider(ctrl)

			tt.setupMocks(userRepo, hasher, tokenManager, validator)

			service := NewUserService(userRepo, hasher, tokenManager, validator, profileProvider)
			tokenPair, err := service.Refresh(context.Background(), tt.refreshToken)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, tokenPair, err)
			}
		})
	}
}

func TestUserService_ValidateToken(t *testing.T) {
	tests := []struct {
		name           string
		branch         string
		accessToken    string
		setupMocks     func(*ports.MockUserRepository, *ports.MockPasswordHasher, *ports.MockTokenManager, *ports.MockValidationService)
		expectedError  error
		validateResult func(*testing.T, *domain.Claims, error)
	}{
		{
			name:        "success",
			branch:      "Success path",
			accessToken: "valid_access_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				claims := &domain.Claims{
					UserID: "user-id",
					Role:   "user",
				}
				tokenManager.EXPECT().Parse("valid_access_token").Return(claims, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, claims *domain.Claims, err error) {
				require.NoError(t, err)
				require.NotNil(t, claims)
				assert.Equal(t, "user-id", claims.UserID)
				assert.Equal(t, "user", claims.Role)
			},
		},
		{
			name:        "invalid token",
			branch:      "Invalid Token",
			accessToken: "invalid_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().Parse("invalid_token").Return(nil, errors.New("token parse error"))
			},
			expectedError: coreerrors.ErrInvalidToken,
			validateResult: func(t *testing.T, claims *domain.Claims, err error) {
				assert.Error(t, err)
				assert.Nil(t, claims)
				assert.Equal(t, coreerrors.ErrInvalidToken, err)
			},
		},
		{
			name:        "expired token",
			accessToken: "expired_token",
			setupMocks: func(
				userRepo *ports.MockUserRepository,
				hasher *ports.MockPasswordHasher,
				tokenManager *ports.MockTokenManager,
				validator *ports.MockValidationService,
			) {
				tokenManager.EXPECT().Parse("expired_token").Return(nil, errors.New("token expired"))
			},
			expectedError: coreerrors.ErrInvalidToken,
			validateResult: func(t *testing.T, claims *domain.Claims, err error) {
				assert.Error(t, err)
				assert.Nil(t, claims)
				assert.Equal(t, coreerrors.ErrInvalidToken, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo := ports.NewMockUserRepository(ctrl)
			hasher := ports.NewMockPasswordHasher(ctrl)
			tokenManager := ports.NewMockTokenManager(ctrl)
			validator := ports.NewMockValidationService(ctrl)
			profileProvider := ports.NewMockProfileProvider(ctrl)

			tt.setupMocks(userRepo, hasher, tokenManager, validator)

			service := NewUserService(userRepo, hasher, tokenManager, validator, profileProvider)
			claims, err := service.ValidateToken(context.Background(), tt.accessToken)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, claims, err)
			}
		})
	}
}
