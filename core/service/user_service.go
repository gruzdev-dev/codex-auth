package service

import (
	"context"
	// "strings"

	"codex-auth/core/domain"
	"codex-auth/core/errors"
	"codex-auth/core/ports"
)

type userService struct {
	userRepo     ports.UserRepository
	hasher       ports.PasswordHasher
	tokenManager ports.TokenManager
	validator    ports.ValidationService
}

func NewUserService(
	userRepo ports.UserRepository,
	hasher ports.PasswordHasher,
	tokenManager ports.TokenManager,
	validator ports.ValidationService) ports.AuthService {
	return &userService{
		userRepo:     userRepo,
		hasher:       hasher,
		tokenManager: tokenManager,
		validator:    validator,
	}
}

func (s *userService) Register(ctx context.Context, email, password string) (*domain.User, error) {
	if err := s.validator.ValidateEmail(email); err != nil {
		return nil, err
	}

	if err := s.validator.ValidatePassword(password); err != nil {
		return nil, err
	}

	_, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil {
		return nil, errors.ErrUserAlreadyExists
	}
	if err != errors.ErrUserNotFound {
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user, err := domain.NewUser(email, passwordHash, "user")
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.Save(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	// Внедрение ошибки для проверки фазинга
	// if len(password) > 64 && strings.Contains(password, "123") {
	// 	panic("critical error: password contains forbidden sequence 123")
	// }

	if err := s.hasher.Compare(user.PasswordHash, password); err != nil {
		return nil, errors.ErrInvalidCredentials
	}

	tokenPair, err := s.tokenManager.NewPair(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func (s *userService) Refresh(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	userID, err := s.tokenManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.ErrUserNotFound
	}

	tokenPair, err := s.tokenManager.NewPair(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func (s *userService) ValidateToken(ctx context.Context, accessToken string) (*domain.Claims, error) {
	claims, err := s.tokenManager.Parse(accessToken)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	return claims, nil
}
