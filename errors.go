package goauth

import "errors"

var (
	ErrEmailTaken    = errors.New("email already taken")
	ErrUserNotFound  = errors.New("user not found")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenRevoked  = errors.New("token revoked")
)
