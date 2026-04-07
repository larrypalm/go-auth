package goauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
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
		ID:           "test-uuid-1",
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
		CreatedAt:    time.Now(),
	}
	s.users = append(s.users, user)
	return user, nil
}

func (s *memoryUserStore) GetUserByID(ctx context.Context, id string) (User, error) {
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
	if user.ID != "test-uuid-1" {
		t.Errorf("expected user ID test-uuid-1, got %s", user.ID)
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
