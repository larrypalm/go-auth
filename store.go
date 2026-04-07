package goauth

import (
	"context"
	"time"
)

// User represents an authenticated user. The consuming app (e.g. Husboken)
// returns this from its database layer.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"` // "-" means never include in JSON output
	CreatedAt    time.Time `json:"created_at"`
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time // nil = active, set = revoked
	CreatedAt time.Time
}

// UserStore is what the consuming app must implement to provide user persistence.
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, name string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)
}

// TokenStore is what the consuming app must implement to provide refresh token persistence.
type TokenStore interface {
	SaveRefreshToken(ctx context.Context, token RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
}
