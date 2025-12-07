package errors

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrEmailRequired      = errors.New("email is required")
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrEmailTooLong       = errors.New("email is too long")
	ErrPasswordRequired   = errors.New("password hash is required")
	ErrPasswordTooShort   = errors.New("password is too short")
	ErrPasswordTooLong    = errors.New("password is too long")
	ErrRoleRequired       = errors.New("role is required")
	ErrInvalidRole        = errors.New("invalid role")
)
