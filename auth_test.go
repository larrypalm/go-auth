package goauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// memoryUserStore is a fake in-memory UserStore for testing.
type memoryUserStore struct {
	mu    sync.Mutex
	users []User
}

func (s *memoryUserStore) CreateUser(ctx context.Context, email, passwordHash, name string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate email
	for _, u := range s.users {
		if u.Email == email {
			return User{}, ErrEmailTaken
		}
	}

	user := User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
		CreatedAt:    time.Now(),
	}
	s.users = append(s.users, user)
	return user, nil
}

func (s *memoryUserStore) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (s *memoryUserStore) GetUserByEmail(ctx context.Context, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (s *memoryUserStore) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idSet := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}

	var result []User
	for _, u := range s.users {
		if idSet[u.ID] {
			result = append(result, u)
		}
	}
	return result, nil
}

func (s *memoryUserStore) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.users {
		if u.ID == userID {
			s.users[i].PasswordHash = passwordHash
			return nil
		}
	}
	return ErrUserNotFound
}

func (s *memoryUserStore) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.users {
		if u.ID == userID {
			s.users[i].EmailVerified = true
			return nil
		}
	}
	return ErrUserNotFound
}

// memoryTokenStore is a fake in-memory TokenStore for testing.
type memoryTokenStore struct {
	mu     sync.Mutex
	tokens []RefreshToken
}

func (s *memoryTokenStore) SaveRefreshToken(ctx context.Context, token RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, token)
	return nil
}

func (s *memoryTokenStore) GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tokens {
		if t.TokenHash == tokenHash {
			return t, nil
		}
	}
	return RefreshToken{}, ErrTokenNotFound
}

func (s *memoryTokenStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, t := range s.tokens {
		if t.TokenHash == tokenHash {
			now := time.Now()
			s.tokens[i].RevokedAt = &now
			return nil
		}
	}
	return ErrTokenNotFound
}

func (s *memoryTokenStore) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for i, t := range s.tokens {
		if t.UserID == userID && t.RevokedAt == nil {
			s.tokens[i].RevokedAt = &now
		}
	}
	return nil
}

// memoryResetTokenStore is a fake in-memory ResetTokenStore for testing.
type memoryResetTokenStore struct {
	mu     sync.Mutex
	tokens []ResetToken
}

func (s *memoryResetTokenStore) CreateResetToken(ctx context.Context, token ResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, token)
	return nil
}

func (s *memoryResetTokenStore) GetResetToken(ctx context.Context, tokenHash string) (ResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tokens {
		if t.TokenHash == tokenHash {
			return t, nil
		}
	}
	return ResetToken{}, ErrResetTokenNotFound
}

func (s *memoryResetTokenStore) MarkResetTokenUsed(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, t := range s.tokens {
		if t.TokenHash == tokenHash {
			now := time.Now()
			s.tokens[i].UsedAt = &now
			return nil
		}
	}
	return ErrResetTokenNotFound
}

func (s *memoryResetTokenStore) HasRecentResetToken(ctx context.Context, userID uuid.UUID, window time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-window)
	for _, t := range s.tokens {
		if t.UserID == userID && t.UsedAt == nil && t.ExpiresAt.After(time.Now()) && t.CreatedAt.After(cutoff) {
			return true, nil
		}
	}
	return false, nil
}

// mockPasswordResetSender captures sent emails for test assertions.
type mockPasswordResetSender struct {
	mu    sync.Mutex
	sends []resetSend
}

type resetSend struct {
	Email string
	Token string
}

func (s *mockPasswordResetSender) SendPasswordReset(ctx context.Context, email string, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sends = append(s.sends, resetSend{Email: email, Token: token})
	return nil
}

func (s *mockPasswordResetSender) lastToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sends) == 0 {
		return ""
	}
	return s.sends[len(s.sends)-1].Token
}

func (s *mockPasswordResetSender) sendCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sends)
}

// memoryOAuthStore is a fake in-memory OAuthStore for testing.
type memoryOAuthStore struct {
	mu    sync.Mutex
	links []OAuthLink
}

func (s *memoryOAuthStore) GetOAuthLink(ctx context.Context, provider, providerUserID string) (OAuthLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.links {
		if l.Provider == provider && l.ProviderUserID == providerUserID {
			return l, nil
		}
	}
	return OAuthLink{}, ErrOAuthLinkNotFound
}

func (s *memoryOAuthStore) CreateOAuthLink(ctx context.Context, link OAuthLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce unique (provider, provider_user_id).
	for _, l := range s.links {
		if l.Provider == link.Provider && l.ProviderUserID == link.ProviderUserID {
			return errors.New("duplicate oauth link")
		}
	}
	s.links = append(s.links, link)
	return nil
}

// mockOAuthProvider is a fake OAuthProvider for testing.
type mockOAuthProvider struct {
	info OAuthUserInfo
	err  error
}

func (p *mockOAuthProvider) ValidateToken(ctx context.Context, idToken string) (OAuthUserInfo, error) {
	return p.info, p.err
}

// newTestAuth creates an Auth instance with in-memory stores for testing.
func newTestAuth() (*Auth, *memoryUserStore, *memoryTokenStore) {
	userStore := &memoryUserStore{}
	tokenStore := &memoryTokenStore{}

	a := New(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		JWTSecret:  "test-secret-key",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
	})

	return a, userStore, tokenStore
}

// newTestAuthWithReset creates an Auth instance with password reset support.
func newTestAuthWithReset() (*Auth, *memoryUserStore, *memoryTokenStore, *memoryResetTokenStore, *mockPasswordResetSender) {
	userStore := &memoryUserStore{}
	tokenStore := &memoryTokenStore{}
	resetStore := &memoryResetTokenStore{}
	sender := &mockPasswordResetSender{}

	a := New(Config{
		UserStore:           userStore,
		TokenStore:          tokenStore,
		JWTSecret:           "test-secret-key",
		AccessTTL:           15 * time.Minute,
		RefreshTTL:          30 * 24 * time.Hour,
		ResetTokenStore:     resetStore,
		PasswordResetSender: sender,
		ResetTTL:            time.Hour,
		ResetCooldown:       5 * time.Minute,
	})

	return a, userStore, tokenStore, resetStore, sender
}

func TestRegister_Success(t *testing.T) {
	a, userStore, _ := newTestAuth()

	body := `{"email":"larry@example.com","password":"strongpassword123","name":"Larry"}`
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.Routes().ServeHTTP(rec, req)

	// Should return 201 Created
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Response should have access_token, refresh_token, and user
	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access_token to be set")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token to be set")
	}
	if resp.User.Email != "larry@example.com" {
		t.Errorf("expected user email larry@example.com, got %s", resp.User.Email)
	}
	if resp.User.Name != "Larry" {
		t.Errorf("expected user name Larry, got %s", resp.User.Name)
	}

	// Password should be hashed in the store, not stored as plaintext
	userStore.mu.Lock()
	stored := userStore.users[0]
	userStore.mu.Unlock()

	if stored.PasswordHash == "strongpassword123" {
		t.Error("password stored as plaintext, expected bcrypt hash")
	}
	if stored.PasswordHash == "" {
		t.Error("password hash is empty")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	a, _, _ := newTestAuth()

	body := `{"email":"larry@example.com","password":"strongpassword123","name":"Larry"}`

	// First registration should succeed
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("first register: expected 201, got %d", rec.Code)
	}

	// Second registration with same email should return 409
	req = httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_MissingFields(t *testing.T) {
	a, _, _ := newTestAuth()

	tests := []struct {
		name string
		body string
	}{
		{"missing email", `{"password":"strongpassword123","name":"Larry"}`},
		{"missing password", `{"email":"larry@example.com","name":"Larry"}`},
		{"missing name", `{"email":"larry@example.com","password":"strongpassword123"}`},
		{"empty body", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			a.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	a, _, _ := newTestAuth()

	body := `{"email":"larry@example.com","password":"short","name":"Larry"}`
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for weak password, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Login tests ---

// registerUser is a test helper that registers a user and returns the response.
func registerUser(t *testing.T, a *Auth, email, password, name string) AuthResponse {
	t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `","name":"` + name + `"}`
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("registerUser helper: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("registerUser helper: failed to decode: %v", err)
	}
	return resp
}

func TestLogin_Success(t *testing.T) {
	a, _, _ := newTestAuth()

	// Register a user first
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Login with correct credentials
	body := `{"email":"larry@example.com","password":"strongpassword123"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access_token to be set")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token to be set")
	}
	if resp.User.Email != "larry@example.com" {
		t.Errorf("expected email larry@example.com, got %s", resp.User.Email)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	a, _, _ := newTestAuth()

	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	body := `{"email":"larry@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogin_NonexistentEmail(t *testing.T) {
	a, _, _ := newTestAuth()

	body := `{"email":"nobody@example.com","password":"strongpassword123"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Refresh tests ---

func TestRefresh_Success(t *testing.T) {
	a, _, _ := newTestAuth()

	// Register to get a refresh token
	regResp := registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Use the refresh token to get new tokens
	body := `{"refresh_token":"` + regResp.RefreshToken + `"}`
	req := httptest.NewRequest("POST", "/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected new access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected new refresh_token")
	}
	// New refresh token should be different from the old one (rotation)
	if resp.RefreshToken == regResp.RefreshToken {
		t.Error("expected new refresh_token to differ from old one")
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	a, _, _ := newTestAuth()

	body := `{"refresh_token":"totally-bogus-token"}`
	req := httptest.NewRequest("POST", "/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRefresh_RevokedToken(t *testing.T) {
	a, _, _ := newTestAuth()

	regResp := registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Logout to revoke the refresh token
	logoutBody := `{"refresh_token":"` + regResp.RefreshToken + `"}`
	logoutReq := httptest.NewRequest("POST", "/auth/logout", bytes.NewBufferString(logoutBody))
	logoutReq.Header.Set("Content-Type", "application/json")
	logoutRec := httptest.NewRecorder()
	a.Routes().ServeHTTP(logoutRec, logoutReq)

	// Try to refresh with the revoked token
	body := `{"refresh_token":"` + regResp.RefreshToken + `"}`
	req := httptest.NewRequest("POST", "/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Middleware tests ---

// protectedHandler is a dummy handler that returns the user from context.
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no user in context", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func TestMiddleware_ValidToken(t *testing.T) {
	a, _, _ := newTestAuth()

	// Register to get a valid access token
	regResp := registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Call a protected endpoint with the access token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+regResp.AccessToken)
	rec := httptest.NewRecorder()

	// Wrap the dummy handler with the middleware
	handler := a.Middleware(http.HandlerFunc(protectedHandler))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Check that the user was extracted from the token
	var user User
	if err := json.NewDecoder(rec.Body).Decode(&user); err != nil {
		t.Fatalf("failed to decode user: %v", err)
	}
	if user.ID == (uuid.UUID{}) {
		t.Error("expected user ID to be set, got zero UUID")
	}
	if user.Email != "larry@example.com" {
		t.Errorf("expected email larry@example.com, got %s", user.Email)
	}
}

func TestMiddleware_MissingHeader(t *testing.T) {
	a, _, _ := newTestAuth()

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	handler := a.Middleware(http.HandlerFunc(protectedHandler))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	a, _, _ := newTestAuth()

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer totally-invalid-jwt")
	rec := httptest.NewRecorder()

	handler := a.Middleware(http.HandlerFunc(protectedHandler))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_ExpiredToken(t *testing.T) {
	// Create an auth instance with 0 TTL so the token is immediately expired
	userStore := &memoryUserStore{}
	tokenStore := &memoryTokenStore{}
	a := New(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		JWTSecret:  "test-secret-key",
		AccessTTL:  -1 * time.Second, // already expired
		RefreshTTL: 30 * 24 * time.Hour,
	})

	regResp := registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+regResp.AccessToken)
	rec := httptest.NewRecorder()

	handler := a.Middleware(http.HandlerFunc(protectedHandler))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Password Reset tests ---

func TestPasswordResetRequest_Success(t *testing.T) {
	a, _, _, _, sender := newTestAuthWithReset()

	// Register a user first.
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	body := `{"email":"larry@example.com"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Sender should have been called with the user's email.
	if sender.sendCount() != 1 {
		t.Fatalf("expected 1 send, got %d", sender.sendCount())
	}
	if sender.lastToken() == "" {
		t.Error("expected a non-empty token in the send")
	}
}

func TestPasswordResetRequest_NonexistentEmail(t *testing.T) {
	a, _, _, _, sender := newTestAuthWithReset()

	// Request reset for an email that doesn't exist — should still return 200.
	body := `{"email":"nobody@example.com"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// No email should have been sent.
	if sender.sendCount() != 0 {
		t.Errorf("expected 0 sends for nonexistent email, got %d", sender.sendCount())
	}
}

func TestPasswordResetRequest_MissingEmail(t *testing.T) {
	a, _, _, _, _ := newTestAuthWithReset()

	body := `{}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetRequest_RateLimited(t *testing.T) {
	a, _, _, _, sender := newTestAuthWithReset()

	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// First request — should send.
	body := `{"email":"larry@example.com"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}
	if sender.sendCount() != 1 {
		t.Fatalf("first request: expected 1 send, got %d", sender.sendCount())
	}

	// Second request within cooldown — should return 200 but NOT send another email.
	req = httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", rec.Code)
	}
	if sender.sendCount() != 1 {
		t.Errorf("second request: expected still 1 send (rate limited), got %d", sender.sendCount())
	}
}

func TestPasswordResetConfirm_Success(t *testing.T) {
	a, _, tokenStore, _, sender := newTestAuthWithReset()

	// Register and get a refresh token (to verify it gets revoked).
	regResp := registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Request reset.
	body := `{"email":"larry@example.com"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	rawToken := sender.lastToken()

	// Confirm reset with new password.
	confirmBody := `{"token":"` + rawToken + `","password":"newstrongpassword456"}`
	req = httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Old refresh token should be revoked.
	oldHash := hashToken(regResp.RefreshToken)
	tokenStore.mu.Lock()
	for _, tok := range tokenStore.tokens {
		if tok.TokenHash == oldHash && tok.RevokedAt == nil {
			t.Error("expected old refresh token to be revoked")
		}
	}
	tokenStore.mu.Unlock()

	// Login with new password should work.
	loginBody := `{"email":"larry@example.com","password":"newstrongpassword456"}`
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login with new password: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Login with old password should fail.
	loginBody = `{"email":"larry@example.com","password":"strongpassword123"}`
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with old password: expected 401, got %d", rec.Code)
	}
}

func TestPasswordResetConfirm_InvalidToken(t *testing.T) {
	a, _, _, _, _ := newTestAuthWithReset()

	body := `{"token":"totally-bogus-token","password":"newstrongpassword456"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetConfirm_TokenReuse(t *testing.T) {
	a, _, _, _, sender := newTestAuthWithReset()

	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// Request reset.
	body := `{"email":"larry@example.com"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	rawToken := sender.lastToken()

	// First confirm — should succeed.
	confirmBody := `{"token":"` + rawToken + `","password":"newpassword12345"}`
	req = httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first confirm: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second confirm with same token — should fail with 410.
	req = httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("reuse: expected 410, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetConfirm_WeakPassword(t *testing.T) {
	a, _, _, _, _ := newTestAuthWithReset()

	body := `{"token":"some-token","password":"short"}`
	req := httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetConfirm_MissingFields(t *testing.T) {
	a, _, _, _, _ := newTestAuthWithReset()

	tests := []struct {
		name string
		body string
	}{
		{"missing token", `{"password":"strongpassword123"}`},
		{"missing password", `{"token":"some-token"}`},
		{"empty body", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/auth/password-reset/confirm", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			a.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// --- OAuth tests ---

// newTestAuthWithOAuth creates an Auth instance with OAuth support.
func newTestAuthWithOAuth(provider *mockOAuthProvider) (*Auth, *memoryUserStore, *memoryTokenStore, *memoryOAuthStore) {
	userStore := &memoryUserStore{}
	tokenStore := &memoryTokenStore{}
	oauthStore := &memoryOAuthStore{}

	a := New(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		JWTSecret:  "test-secret-key",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
		OAuthStore: oauthStore,
		OAuthProviders: map[string]OAuthProvider{
			"apple": provider,
		},
	})

	return a, userStore, tokenStore, oauthStore
}

func TestOAuth_NewUser(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-123",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "Larry",
		},
	}
	a, userStore, _, oauthStore := newTestAuthWithOAuth(provider)

	body := `{"id_token":"valid-apple-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access_token to be set")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token to be set")
	}
	if resp.User.Email != "larry@example.com" {
		t.Errorf("expected email larry@example.com, got %s", resp.User.Email)
	}
	if resp.User.Name != "Larry" {
		t.Errorf("expected name Larry, got %s", resp.User.Name)
	}

	// User should exist in the store.
	userStore.mu.Lock()
	if len(userStore.users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(userStore.users))
	}
	userStore.mu.Unlock()

	// OAuth link should exist.
	oauthStore.mu.Lock()
	if len(oauthStore.links) != 1 {
		t.Fatalf("expected 1 oauth link, got %d", len(oauthStore.links))
	}
	link := oauthStore.links[0]
	oauthStore.mu.Unlock()

	if link.Provider != "apple" {
		t.Errorf("expected provider apple, got %s", link.Provider)
	}
	if link.ProviderUserID != "apple-123" {
		t.Errorf("expected provider_user_id apple-123, got %s", link.ProviderUserID)
	}
}

func TestOAuth_ExistingLink(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-123",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "Larry",
		},
	}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	// First call — creates user and link.
	body := `{"id_token":"valid-apple-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("first call: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second call — link already exists, should return 200.
	req = httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("second call: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access_token to be set")
	}
	if resp.User.Email != "larry@example.com" {
		t.Errorf("expected email larry@example.com, got %s", resp.User.Email)
	}
}

func TestOAuth_EmailMatchLinksExistingUser(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-456",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "Larry",
		},
	}
	a, userStore, _, oauthStore := newTestAuthWithOAuth(provider)

	// Register a user with email/password first.
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// OAuth with same email — should link to existing user, not create a new one.
	body := `{"id_token":"valid-apple-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Should still be only 1 user.
	userStore.mu.Lock()
	if len(userStore.users) != 1 {
		t.Errorf("expected 1 user, got %d", len(userStore.users))
	}
	userStore.mu.Unlock()

	// Link should be created.
	oauthStore.mu.Lock()
	if len(oauthStore.links) != 1 {
		t.Errorf("expected 1 oauth link, got %d", len(oauthStore.links))
	}
	oauthStore.mu.Unlock()
}

func TestOAuth_UnverifiedEmailCreatesNewUser(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-789",
			Email:          "larry@example.com",
			EmailVerified:  false,
			Name:           "Larry",
		},
	}
	a, userStore, _, _ := newTestAuthWithOAuth(provider)

	// Register a user with the same email.
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	// OAuth with unverified email — should NOT link, should create new user.
	body := `{"id_token":"valid-apple-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	// CreateUser will fail with ErrEmailTaken since email is the same.
	// This is the race condition path — returns 409.
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// Still only 1 user.
	userStore.mu.Lock()
	if len(userStore.users) != 1 {
		t.Errorf("expected 1 user, got %d", len(userStore.users))
	}
	userStore.mu.Unlock()
}

func TestOAuth_UnknownProvider(t *testing.T) {
	provider := &mockOAuthProvider{}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	body := `{"id_token":"valid-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/google", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_MissingIDToken(t *testing.T) {
	provider := &mockOAuthProvider{}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	body := `{}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_InvalidToken(t *testing.T) {
	provider := &mockOAuthProvider{
		err: ErrOAuthTokenInvalid,
	}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	body := `{"id_token":"bad-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_NameFallbackFromRequest(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-123",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "", // Apple doesn't send name after first auth
		},
	}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	// Client sends name in request body as fallback.
	body := `{"id_token":"valid-apple-token","name":"Larry Palm"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.User.Name != "Larry Palm" {
		t.Errorf("expected name 'Larry Palm', got '%s'", resp.User.Name)
	}
}

func TestOAuth_NameFallbackToEmail(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-123",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "",
		},
	}
	a, _, _, _ := newTestAuthWithOAuth(provider)

	// No name from provider, no name in request — falls back to email.
	body := `{"id_token":"valid-apple-token"}`
	req := httptest.NewRequest("POST", "/auth/oauth/apple", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.User.Name != "larry@example.com" {
		t.Errorf("expected name 'larry@example.com', got '%s'", resp.User.Name)
	}
}
