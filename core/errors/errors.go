package errors

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrEmailRequired      = errors.New("email is required")
	ErrPasswordRequired   = errors.New("password hash is required")
	ErrRoleRequired       = errors.New("role is required")
)
