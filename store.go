package goauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated user. The consuming app (e.g. Husboken)
// returns this from its database layer.
type User struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	PasswordHash  string    `json:"-"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	TokenHash string
	UserID    uuid.UUID
	ExpiresAt time.Time
	RevokedAt *time.Time // nil = active, set = revoked
	CreatedAt time.Time
}

// UserStore is what the consuming app must implement to provide user persistence.
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, name string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (User, error)
	GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	VerifyEmail(ctx context.Context, userID uuid.UUID) error
}

// TokenStore is what the consuming app must implement to provide refresh token persistence.
type TokenStore interface {
	SaveRefreshToken(ctx context.Context, token RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error
}

// ResetToken represents a stored password reset token.
type ResetToken struct {
	TokenHash string
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// ResetTokenStore is what the consuming app must implement to provide password reset token persistence.
type ResetTokenStore interface {
	CreateResetToken(ctx context.Context, token ResetToken) error
	GetResetToken(ctx context.Context, tokenHash string) (ResetToken, error)
	MarkResetTokenUsed(ctx context.Context, tokenHash string) error
	HasRecentResetToken(ctx context.Context, userID uuid.UUID, window time.Duration) (bool, error)
}

// PasswordResetSender is what the consuming app must implement to send password reset emails.
type PasswordResetSender interface {
	SendPasswordReset(ctx context.Context, email string, token string) error
}

// VerificationToken represents a stored email verification token.
type VerificationToken struct {
	TokenHash string
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// EmailVerificationTokenStore is what the consuming app must implement to persist verification tokens.
type EmailVerificationTokenStore interface {
	CreateVerificationToken(ctx context.Context, token VerificationToken) error
	GetVerificationToken(ctx context.Context, tokenHash string) (VerificationToken, error)
	MarkVerificationTokenUsed(ctx context.Context, tokenHash string) error
}

// EmailVerificationSender is what the consuming app must implement to send verification emails.
type EmailVerificationSender interface {
	SendEmailVerification(ctx context.Context, email string, token string) error
}

// OAuthUserInfo is the user info returned by an OAuth provider after token validation.
type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
}

// OAuthProvider validates an OAuth ID token and returns user info.
// Each provider (Apple, Google, etc.) implements this interface.
type OAuthProvider interface {
	ValidateToken(ctx context.Context, idToken string) (OAuthUserInfo, error)
}

// OAuthLink represents a link between a user and an OAuth provider account.
type OAuthLink struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       string
	ProviderUserID string
	Email          string
	CreatedAt      time.Time
}

// OAuthStore is what the consuming app must implement to provide OAuth link persistence.
type OAuthStore interface {
	GetOAuthLink(ctx context.Context, provider, providerUserID string) (OAuthLink, error)
	CreateOAuthLink(ctx context.Context, link OAuthLink) error
}
