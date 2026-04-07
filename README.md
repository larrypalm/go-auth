# go-auth

Mountable authentication handlers for Go APIs. JWT access tokens, bcrypt password hashing, refresh token rotation, and middleware — ready to plug into any `net/http` router.

## Features

- **User registration** with email, password, and display name
- **Login** with bcrypt password verification
- **JWT access tokens** (short-lived, configurable TTL)
- **Refresh token rotation** (long-lived, single-use, hashed in DB)
- **Logout** via refresh token revocation
- **Auth middleware** extracts and validates JWT from `Authorization: Bearer` header
- Anti-enumeration: login returns the same error for wrong email and wrong password
- No database dependency — you provide the storage via interfaces

## Install

```bash
go get github.com/larrypalm/go-auth
```

## Usage

### 1. Implement the storage interfaces

go-auth needs two interfaces: `UserStore` and `TokenStore`. You implement them with your database of choice.

```go
type UserStore interface {
    CreateUser(ctx context.Context, email, passwordHash, name string) (goauth.User, error)
    GetUserByEmail(ctx context.Context, email string) (goauth.User, error)
    GetUserByID(ctx context.Context, id string) (goauth.User, error)
}

type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token goauth.RefreshToken) error
    GetRefreshToken(ctx context.Context, tokenHash string) (goauth.RefreshToken, error)
    RevokeRefreshToken(ctx context.Context, tokenHash string) error
}
```

Return `goauth.ErrEmailTaken`, `goauth.ErrUserNotFound`, or `goauth.ErrTokenNotFound` from your store implementations so go-auth can map them to the correct HTTP status codes.

### 2. Create and mount

```go
package main

import (
    "net/http"
    "time"

    goauth "github.com/larrypalm/go-auth"
)

func main() {
    auth := goauth.New(goauth.Config{
        UserStore:  myUserStore,     // your UserStore implementation
        TokenStore: myTokenStore,    // your TokenStore implementation
        JWTSecret:  "your-secret",   // use a strong secret, load from env
        AccessTTL:  15 * time.Minute,
        RefreshTTL: 30 * 24 * time.Hour,
    })

    router := http.NewServeMux()

    // Mount auth routes (public)
    router.Handle("/auth/", auth.Routes())

    // Protect your own routes with the middleware
    router.Handle("GET /households", auth.Middleware(http.HandlerFunc(listHouseholds)))

    http.ListenAndServe(":8080", router)
}

func listHouseholds(w http.ResponseWriter, r *http.Request) {
    user, ok := goauth.UserFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    // user.ID and user.Email are available
    _ = user
}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create user, returns token pair |
| POST | `/auth/login` | Authenticate, returns token pair |
| POST | `/auth/refresh` | Exchange refresh token for new pair |
| POST | `/auth/logout` | Revoke refresh token |

## Error format

All errors return a consistent JSON structure:

```json
{
  "error": {
    "code": "email_taken",
    "message": "A user with this email already exists"
  }
}
```

## License

MIT
