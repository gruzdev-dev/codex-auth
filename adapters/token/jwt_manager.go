package token

import (
	"fmt"
	"time"

	"github.com/gruzdev-dev/codex-auth/core/domain"
	"github.com/gruzdev-dev/codex-auth/core/errors"
	"github.com/gruzdev-dev/codex-auth/core/ports"

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

func (m *JWTManager) NewPair(user *domain.User) (*domain.TokenPair, error) {
	now := time.Now()

	accessClaims := jwt.MapClaims{
		"sub":  user.ID,
		"role": user.Role,
		"exp":  now.Add(m.tokenTTL).Unix(),
		"iat":  now.Unix(),
		"jti":  fmt.Sprintf("%s-%d-%d", user.ID, now.UnixNano(), now.Nanosecond()),
	}

	for k, v := range user.Metadata {
		accessClaims[k] = v
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.signingKey)
	if err != nil {
		return nil, err
	}

	refreshClaims := jwt.MapClaims{
		"sub":  user.ID,
		"type": "refresh",
		"exp":  now.Add(30 * 24 * time.Hour).Unix(),
		"iat":  now.Unix(),
		"jti":  fmt.Sprintf("%s-refresh-%d-%d", user.ID, now.UnixNano(), now.Nanosecond()),
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

	metadata := make(map[string]string)
	for k, v := range claims {
		if k != "sub" && k != "role" && k != "exp" && k != "iat" && k != "jti" {
			if strVal, ok := v.(string); ok {
				metadata[k] = strVal
			}
		}
	}

	return &domain.Claims{
		UserID:   userID,
		Role:     role,
		Metadata: metadata,
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
