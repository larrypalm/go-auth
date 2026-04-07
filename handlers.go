package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
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

	// Generate tokens
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

	// Store refresh token
	err = a.config.TokenStore.SaveRefreshToken(r.Context(), RefreshToken{
		TokenHash: refreshHash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.config.RefreshTTL),
		CreatedAt: time.Now(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to save refresh token")
		return
	}

	// Return response
	writeJSON(w, http.StatusCreated, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		User:         user,
	})
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

	// Generate tokens
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

	err = a.config.TokenStore.SaveRefreshToken(r.Context(), RefreshToken{
		TokenHash: refreshHash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.config.RefreshTTL),
		CreatedAt: time.Now(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to save refresh token")
		return
	}

	writeJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		User:         user,
	})
}

func (a *Auth) handleRefresh(w http.ResponseWriter, r *http.Request) {
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

	// Look up the stored token by hash
	tokenHash := hashToken(req.RefreshToken)
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

	err = a.config.TokenStore.SaveRefreshToken(r.Context(), RefreshToken{
		TokenHash: refreshHash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.config.RefreshTTL),
		CreatedAt: time.Now(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to save refresh token")
		return
	}

	writeJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		User:         user,
	})
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
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

	tokenHash := hashToken(req.RefreshToken)
	if err := a.config.TokenStore.RevokeRefreshToken(r.Context(), tokenHash); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid refresh token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
