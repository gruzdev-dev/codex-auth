package token

import (
	"time"

	"codex-auth/core/domain"
	"codex-auth/core/errors"
	"codex-auth/core/ports"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	signingKey []byte
	tokenTTL   time.Duration
}

func NewJWTManager(signingKey string, tokenTTL time.Duration) ports.TokenManager {
	return &JWTManager{
		signingKey: []byte(signingKey),
		tokenTTL:   tokenTTL,
	}
}

func (m *JWTManager) NewPair(userID, role string) (*domain.TokenPair, error) {
	now := time.Now()

	accessClaims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"exp":  now.Add(m.tokenTTL).Unix(),
		"iat":  now.Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.signingKey)
	if err != nil {
		return nil, err
	}

	refreshClaims := jwt.MapClaims{
		"sub":  userID,
		"type": "refresh",
		"exp":  now.Add(30 * 24 * time.Hour).Unix(),
		"iat":  now.Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(m.signingKey)
	if err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

func (m *JWTManager) Parse(accessToken string) (*domain.Claims, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.ErrInvalidToken
		}
		return m.signingKey, nil
	})

	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	if !token.Valid {
		return nil, errors.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.ErrInvalidToken
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.ErrInvalidToken
	}

	role, ok := claims["role"].(string)
	if !ok {
		return nil, errors.ErrInvalidToken
	}

	return &domain.Claims{
		UserID: userID,
		Role:   role,
	}, nil
}

func (m *JWTManager) ValidateRefreshToken(refreshToken string) (string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.ErrInvalidToken
		}
		return m.signingKey, nil
	})

	if err != nil {
		return "", errors.ErrInvalidToken
	}

	if !token.Valid {
		return "", errors.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.ErrInvalidToken
	}

	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return "", errors.ErrInvalidToken
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", errors.ErrInvalidToken
	}

	return userID, nil
}
