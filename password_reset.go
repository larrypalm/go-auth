package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (a *Auth) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "Email is required")
		return
	}

	// Always return the same response to prevent email enumeration.
	okResponse := map[string]string{
		"message": "If an account with that email exists, a reset link has been sent.",
	}

	// Look up user — if not found, return success silently.
	user, err := a.config.UserStore.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeJSON(w, http.StatusOK, okResponse)
		return
	}

	// Rate limit: check for recent unused token.
	recent, err := a.config.ResetTokenStore.HasRecentResetToken(r.Context(), user.ID, a.config.ResetCooldown)
	if err != nil {
		writeJSON(w, http.StatusOK, okResponse)
		return
	}
	if recent {
		writeJSON(w, http.StatusOK, okResponse)
		return
	}

	// Generate token — same pattern as refresh tokens.
	raw, hash, err := generateRefreshToken()
	if err != nil {
		writeJSON(w, http.StatusOK, okResponse)
		return
	}

	// Store hashed token.
	err = a.config.ResetTokenStore.CreateResetToken(r.Context(), ResetToken{
		TokenHash: hash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.config.ResetTTL),
		CreatedAt: time.Now(),
	})
	if err != nil {
		writeJSON(w, http.StatusOK, okResponse)
		return
	}

	// Send email with raw token.
	_ = a.config.PasswordResetSender.SendPasswordReset(r.Context(), user.Email, raw)

	writeJSON(w, http.StatusOK, okResponse)
}

func (a *Auth) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.Token == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "Token and password are required")
		return
	}

	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "weak_password", "Password must be at least 8 characters")
		return
	}

	// Look up token by hash.
	tokenHash := hashToken(req.Token)
	stored, err := a.config.ResetTokenStore.GetResetToken(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, ErrResetTokenNotFound) {
			writeError(w, http.StatusGone, "invalid_token", "Reset token is invalid, expired, or already used")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to validate token")
		return
	}

	// Check if already used.
	if stored.UsedAt != nil {
		writeError(w, http.StatusGone, "token_used", "Reset token is invalid, expired, or already used")
		return
	}

	// Check if expired.
	if time.Now().After(stored.ExpiresAt) {
		writeError(w, http.StatusGone, "token_expired", "Reset token is invalid, expired, or already used")
		return
	}

	// Hash new password.
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to hash password")
		return
	}

	// Update password.
	if err := a.config.UserStore.UpdatePassword(r.Context(), stored.UserID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to update password")
		return
	}

	// Mark token as used.
	if err := a.config.ResetTokenStore.MarkResetTokenUsed(r.Context(), tokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to mark token as used")
		return
	}

	// Revoke all refresh tokens for this user (force re-login on all devices).
	if err := a.config.TokenStore.RevokeAllRefreshTokens(r.Context(), stored.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to revoke sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Password has been reset successfully.",
	})
}
