package goauth

import (
	"net/http"
	"time"
)

// Config holds the settings for the auth handler.
type Config struct {
	UserStore  UserStore
	TokenStore TokenStore
	JWTSecret  string        // secret key used to sign JWTs
	AccessTTL  time.Duration // how long access tokens live (e.g. 15 * time.Minute)
	RefreshTTL time.Duration // how long refresh tokens live (e.g. 30 * 24 * time.Hour)
}

// Auth is the main handler that owns all auth routes and logic.
type Auth struct {
	config Config
}

// New creates a new Auth instance with the given config.
func New(cfg Config) *Auth {
	return &Auth{config: cfg}
}

// Routes returns an http.Handler with all auth endpoints mounted.
// The consumer mounts this on their router:
//
//	router.Handle("/auth/", auth.Routes())
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", a.handleRegister)
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("POST /auth/refresh", a.handleRefresh)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)
	return mux
}
