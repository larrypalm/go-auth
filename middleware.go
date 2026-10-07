package goauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// contextKey is an unexported type for context keys, preventing collisions
// with keys from other packages.
type contextKey string

const userContextKey contextKey = "goauth_user"

// Middleware returns an HTTP middleware that validates the JWT access token
// from the Authorization header and puts the user claims into the request context.
// In cookie mode it reads the access cookie when there is no Authorization header.
//
// Usage:
//
//	protected := auth.Middleware(http.HandlerFunc(myHandler))
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenString string
		header := r.Header.Get("Authorization")
		switch {
		case header != "":
			// Extract token from "Authorization: Bearer <token>"
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				writeError(w, http.StatusUnauthorized, "invalid_header", "Authorization header must be: Bearer <token>")
				return
			}
			tokenString = parts[1]
		case a.config.CookieMode:
			cookie, err := r.Cookie(a.config.AccessCookieName)
			if err != nil || cookie.Value == "" {
				writeError(w, http.StatusUnauthorized, "missing_token", "Authorization header or access cookie is required")
				return
			}
			tokenString = cookie.Value
		default:
			writeError(w, http.StatusUnauthorized, "missing_token", "Authorization header is required")
			return
		}

		// Parse and validate the JWT
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return []byte(a.config.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired access token")
			return
		}

		// Put user claims into context for downstream handlers
		user := User{
			ID:    claims.UserID,
			Email: claims.Email,
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext extracts the authenticated user from the request context.
// Returns the user and true if found, or an empty user and false if not.
//
// Usage in a handler:
//
//	user, ok := goauth.UserFromContext(r.Context())
func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey).(User)
	return user, ok
}

// WithUser puts an authenticated user into the context.
// Useful for testing middleware that depends on goauth.UserFromContext.
func WithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
