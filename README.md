# go-auth

Mountable authentication handlers for Go APIs. JWT access tokens, bcrypt password hashing, refresh token rotation, and middleware — ready to plug into any `net/http` router.

## Features

- **User registration** with email, password, and display name
- **Login** with bcrypt password verification
- **JWT access tokens** (short-lived, configurable TTL)
- **Refresh token rotation** (long-lived, single-use, hashed in DB)
- **Logout** via refresh token revocation
- **Auth middleware** extracts and validates JWT from `Authorization: Bearer` header, or from the access cookie in cookie mode
- **Cookie mode** keeps both tokens in httpOnly cookies for browser apps served from the same origin as the API
- **Optional registration route**: set `DisableRegister` to leave `/auth/register` unmounted
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

### 3. Cookie mode for browser apps

A single-page app served from the same origin as the API can keep both tokens in httpOnly cookies, where page scripts can't read them.

```go
auth := goauth.New(goauth.Config{
    UserStore:       myUserStore,
    TokenStore:      myTokenStore,
    JWTSecret:       "your-secret",
    AccessTTL:       15 * time.Minute,
    RefreshTTL:      30 * 24 * time.Hour,
    CookieMode:      true,
    DisableRegister: true, // optional, for apps that create users another way
})
```

In cookie mode:

- Register, login, refresh, email verification and OAuth set two cookies and return only `{"user": ...}`. Both cookies are HttpOnly, Secure and SameSite=Lax. `goauth_access` has path `/` and lives for `AccessTTL`. `goauth_refresh` has path `/auth` and lives for `RefreshTTL`, so the browser sends it only to `/auth/refresh` and `/auth/logout`.
- `/auth/refresh` and `/auth/logout` read the refresh token from the cookie and need no request body. Logout always clears both cookies.
- `Middleware` reads the access cookie when the request has no `Authorization` header. A request with the header works as in bearer mode.
- The auth routes reject unsafe requests from other origins with `403 cross_origin`, and so does `Middleware` when the token came from the cookie. go-auth uses `http.CrossOriginProtection`, which checks the `Sec-Fetch-Site` and `Origin` headers. It also blocks requests from sibling subdomains, which SameSite=Lax lets through. GET, HEAD and OPTIONS always pass, so keep them free of side effects.

| Field | Default | Purpose |
|-------|---------|---------|
| `AccessCookieName` | `goauth_access` | Name of the access cookie |
| `RefreshCookieName` | `goauth_refresh` | Name of the refresh cookie. Browsers reject a `__Host-` cookie unless its path is `/`, so a `__Host-` name also needs `RefreshCookiePath: "/"`. A `__Secure-` name works with any path |
| `RefreshCookiePath` | `/auth` | Change it if you mount the routes under a prefix, for example `/api/auth` with `http.StripPrefix` |
| `InsecureCookies` | `false` | Leaves Secure off for local development over plain http. Safari rejects Secure cookies from `http://localhost`, while Chrome and Firefox accept them. Browsers also reject `__Host-` and `__Secure-` names without Secure. Never set it in production. |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create user, returns token pair. Not mounted when `DisableRegister` is set |
| POST | `/auth/login` | Authenticate, returns token pair |
| POST | `/auth/refresh` | Exchange refresh token for new pair. Reads the refresh cookie in cookie mode |
| POST | `/auth/logout` | Revoke refresh token. Also clears both cookies in cookie mode |

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
