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

	// DisableRegister leaves POST /auth/register unmounted, for apps that create users another way.
	DisableRegister bool

	// Optional. Cookie mode is for a browser app served from the same origin as the API.
	CookieMode        bool   // set the tokens as httpOnly cookies on login, refresh, register and OAuth
	AccessCookieName  string // default "goauth_access"
	RefreshCookieName string // default "goauth_refresh"
	RefreshCookiePath string // default "/auth", which covers /auth/refresh and /auth/logout
	InsecureCookies   bool   // leave Secure off, for local development over plain http only

	// Optional — required only if password reset endpoints are used.
	ResetTokenStore     ResetTokenStore
	PasswordResetSender PasswordResetSender
	ResetTTL            time.Duration // how long reset tokens live (default 1 hour)
	ResetCooldown       time.Duration // minimum time between reset emails per user (default 5 min)

	// Optional — required only if email verification is used.
	EmailVerificationTokenStore EmailVerificationTokenStore
	EmailVerificationSender     EmailVerificationSender
	VerificationTTL             time.Duration // how long verification tokens live (default 24h)

	// Optional — required only if OAuth endpoints are used.
	OAuthStore     OAuthStore
	OAuthProviders map[string]OAuthProvider // keyed by provider name (e.g. "apple", "google")
}

// Auth is the main handler that owns all auth routes and logic.
type Auth struct {
	config Config
}

// New creates a new Auth instance with the given config.
func New(cfg Config) *Auth {
	if cfg.ResetTTL == 0 {
		cfg.ResetTTL = time.Hour
	}
	if cfg.ResetCooldown == 0 {
		cfg.ResetCooldown = 5 * time.Minute
	}
	if cfg.VerificationTTL == 0 {
		cfg.VerificationTTL = 24 * time.Hour
	}
	if cfg.AccessCookieName == "" {
		cfg.AccessCookieName = "goauth_access"
	}
	if cfg.RefreshCookieName == "" {
		cfg.RefreshCookieName = "goauth_refresh"
	}
	if cfg.RefreshCookiePath == "" {
		cfg.RefreshCookiePath = "/auth"
	}
	return &Auth{config: cfg}
}

// Routes returns an http.Handler with all auth endpoints mounted.
// The consumer mounts this on their router:
//
//	router.Handle("/auth/", auth.Routes())
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	if !a.config.DisableRegister {
		mux.HandleFunc("POST /auth/register", a.handleRegister)
	}
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("POST /auth/refresh", a.handleRefresh)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)
	if a.config.ResetTokenStore != nil && a.config.PasswordResetSender != nil {
		mux.HandleFunc("POST /auth/password-reset/request", a.handlePasswordResetRequest)
		mux.HandleFunc("POST /auth/password-reset/confirm", a.handlePasswordResetConfirm)
	}
	if a.config.EmailVerificationTokenStore != nil && a.config.EmailVerificationSender != nil {
		mux.HandleFunc("POST /auth/verify-email", a.handleVerifyEmail)
	}
	if a.config.OAuthStore != nil && len(a.config.OAuthProviders) > 0 {
		mux.HandleFunc("POST /auth/oauth/{provider}", a.handleOAuth)
	}
	return mux
}
