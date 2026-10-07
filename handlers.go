package goauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *Auth) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Validate required fields
	req.Email = strings.TrimSpace(req.Email)
	req.Name = strings.TrimSpace(req.Name)

	if req.Email == "" || req.Password == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "Email, password, and name are required")
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "weak_password", "Password must be at least 8 characters")
		return
	}

	// Hash password
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to hash password")
		return
	}

	// Create user
	user, err := a.config.UserStore.CreateUser(r.Context(), req.Email, hash, req.Name)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			writeError(w, http.StatusConflict, "email_taken", "A user with this email already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to create user")
		return
	}

	// If email verification is configured, send verification email and don't issue tokens yet.
	if a.config.EmailVerificationSender != nil && a.config.EmailVerificationTokenStore != nil {
		rawToken, tokenHash, err := generateRefreshToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to generate verification token")
			return
		}
		err = a.config.EmailVerificationTokenStore.CreateVerificationToken(r.Context(), VerificationToken{
			TokenHash: tokenHash,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(a.config.VerificationTTL),
			CreatedAt: time.Now(),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to save verification token")
			return
		}
		if err := a.config.EmailVerificationSender.SendEmailVerification(r.Context(), user.Email, rawToken); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to send verification email")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{
			"message": "Check your email to verify your account",
		})
		return
	}

	// No email verification — issue tokens immediately.
	a.respondWithTokens(r.Context(), w, http.StatusCreated, user)
}

func (a *Auth) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "Token is required")
		return
	}

	tokenHash := hashToken(req.Token)
	stored, err := a.config.EmailVerificationTokenStore.GetVerificationToken(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token", "Invalid or expired verification token")
		return
	}
	if stored.UsedAt != nil {
		writeError(w, http.StatusBadRequest, "token_used", ErrVerificationTokenUsed.Error())
		return
	}
	if time.Now().After(stored.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "token_expired", ErrVerificationTokenExpired.Error())
		return
	}

	if err := a.config.EmailVerificationTokenStore.MarkVerificationTokenUsed(r.Context(), tokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to mark token used")
		return
	}
	if err := a.config.UserStore.VerifyEmail(r.Context(), stored.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to verify email")
		return
	}

	user, err := a.config.UserStore.GetUserByID(r.Context(), stored.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to load user")
		return
	}

	a.respondWithTokens(r.Context(), w, http.StatusOK, user)
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Look up user by email
	user, err := a.config.UserStore.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Same error for "not found" and "wrong password" to prevent email enumeration
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	// Verify password
	if err := CheckPassword(req.Password, user.PasswordHash); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	a.respondWithTokens(r.Context(), w, http.StatusOK, user)
}

func (a *Auth) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var refreshToken string
	if a.config.CookieMode {
		cookie, err := r.Cookie(a.config.RefreshCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "missing_token", "Refresh token cookie is required")
			return
		}
		refreshToken = cookie.Value
	} else {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
			return
		}

		if req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "missing_fields", "Refresh token is required")
			return
		}
		refreshToken = req.RefreshToken
	}

	// Look up the stored token by hash
	tokenHash := hashToken(refreshToken)
	stored, err := a.config.TokenStore.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid refresh token")
		return
	}

	// Check if revoked
	if stored.RevokedAt != nil {
		writeError(w, http.StatusUnauthorized, "token_revoked", "Refresh token has been revoked")
		return
	}

	// Check if expired
	if time.Now().After(stored.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "token_expired", "Refresh token has expired")
		return
	}

	// Revoke the old refresh token (rotation — each token is single-use)
	if err := a.config.TokenStore.RevokeRefreshToken(r.Context(), tokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to revoke old token")
		return
	}

	// Look up the user
	user, err := a.config.UserStore.GetUserByID(r.Context(), stored.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "User not found")
		return
	}

	// Issue new token pair
	a.respondWithTokens(r.Context(), w, http.StatusOK, user)
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	var refreshToken string
	if a.config.CookieMode {
		// Clear the cookies even when there is no token to revoke, so the browser always ends logged out.
		a.clearAuthCookies(w)
		cookie, err := r.Cookie(a.config.RefreshCookieName)
		if err != nil || cookie.Value == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		refreshToken = cookie.Value
	} else {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
			return
		}

		if req.RefreshToken == "" {
			writeError(w, http.StatusUnauthorized, "missing_fields", "Refresh token is required")
			return
		}
		refreshToken = req.RefreshToken
	}

	tokenHash := hashToken(refreshToken)
	if err := a.config.TokenStore.RevokeRefreshToken(r.Context(), tokenHash); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid refresh token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handleOAuth(w http.ResponseWriter, r *http.Request) {
	// 1. Extract and validate provider.
	providerName := r.PathValue("provider")
	provider, ok := a.config.OAuthProviders[providerName]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown_provider", "Unknown OAuth provider")
		return
	}

	// 2. Decode request body.
	var req struct {
		IDToken string `json:"id_token"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}
	if req.IDToken == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "id_token is required")
		return
	}

	// 3. Validate the ID token with the provider.
	info, err := provider.ValidateToken(r.Context(), req.IDToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired ID token")
		return
	}

	ctx := r.Context()

	// 4. Check if an OAuth link already exists.
	link, err := a.config.OAuthStore.GetOAuthLink(ctx, providerName, info.ProviderUserID)
	if err == nil {
		// Link exists — load user and issue tokens.
		user, err := a.config.UserStore.GetUserByID(ctx, link.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to load user")
			return
		}
		a.respondWithTokens(ctx, w, http.StatusOK, user)
		return
	}
	if !errors.Is(err, ErrOAuthLinkNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to check OAuth link")
		return
	}

	// 5. No link — try email match if email is verified.
	if info.EmailVerified && info.Email != "" {
		user, err := a.config.UserStore.GetUserByEmail(ctx, info.Email)
		if err == nil {
			// Existing user with matching email — create link.
			if err := a.createOAuthLink(ctx, user.ID, providerName, info); err != nil {
				writeError(w, http.StatusInternalServerError, "internal", "Failed to create OAuth link")
				return
			}
			a.respondWithTokens(ctx, w, http.StatusOK, user)
			return
		}
		if !errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to look up user")
			return
		}
	}

	// 6. No link, no email match — create new user.
	name := info.Name
	if name == "" {
		name = strings.TrimSpace(req.Name)
	}
	if name == "" {
		name = info.Email
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to generate password placeholder")
		return
	}
	placeholderHash, err := HashPassword(string(randomBytes))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to hash password placeholder")
		return
	}

	user, err := a.config.UserStore.CreateUser(ctx, info.Email, placeholderHash, name)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			// Race condition: user was created between our check and now.
			writeError(w, http.StatusConflict, "email_taken", "A user with this email already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to create user")
		return
	}

	if err := a.createOAuthLink(ctx, user.ID, providerName, info); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to create OAuth link")
		return
	}

	a.respondWithTokens(ctx, w, http.StatusCreated, user)
}

// createOAuthLink is a convenience method for creating an OAuth link.
func (a *Auth) createOAuthLink(ctx context.Context, userID uuid.UUID, provider string, info OAuthUserInfo) error {
	return a.config.OAuthStore.CreateOAuthLink(ctx, OAuthLink{
		ID:             uuid.New(),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: info.ProviderUserID,
		Email:          info.Email,
		CreatedAt:      time.Now(),
	})
}

// respondWithTokens generates an access + refresh token pair and writes the AuthResponse.
func (a *Auth) respondWithTokens(ctx context.Context, w http.ResponseWriter, status int, user User) {
	accessToken, err := a.generateAccessToken(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to generate access token")
		return
	}

	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to generate refresh token")
		return
	}

	err = a.config.TokenStore.SaveRefreshToken(ctx, RefreshToken{
		TokenHash: refreshHash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.config.RefreshTTL),
		CreatedAt: time.Now(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to save refresh token")
		return
	}

	if a.config.CookieMode {
		a.setAuthCookies(w, accessToken, rawRefresh)
		writeJSON(w, status, AuthResponse{User: user})
		return
	}

	writeJSON(w, status, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		User:         user,
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// writeError writes a structured error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}
