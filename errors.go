package goauth

import "errors"

var (
	ErrEmailTaken         = errors.New("email already taken")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenNotFound      = errors.New("token not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrResetTokenNotFound = errors.New("reset token not found")
	ErrResetTokenExpired  = errors.New("reset token expired")
	ErrResetTokenUsed     = errors.New("reset token already used")
	ErrOAuthLinkNotFound    = errors.New("oauth link not found")
	ErrOAuthProviderUnknown = errors.New("unknown oauth provider")
	ErrOAuthTokenInvalid    = errors.New("invalid oauth token")

	ErrVerificationTokenNotFound = errors.New("verification token not found")
	ErrVerificationTokenExpired  = errors.New("verification token expired")
	ErrVerificationTokenUsed     = errors.New("verification token already used")
	ErrEmailNotVerified          = errors.New("email not verified")
)
