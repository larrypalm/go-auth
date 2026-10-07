package goauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newCookieAuth creates an Auth instance in cookie mode with in-memory stores.
func newCookieAuth() (*Auth, *memoryUserStore, *memoryTokenStore) {
	userStore := &memoryUserStore{}
	tokenStore := &memoryTokenStore{}

	a := New(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		JWTSecret:  "test-secret-key",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
		CookieMode: true,
	})

	return a, userStore, tokenStore
}

// loginUser is a test helper that registers a user, logs in and returns the login response.
func loginUser(t *testing.T, a *Auth) *httptest.ResponseRecorder {
	t.Helper()
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	body := `{"email":"larry@example.com","password":"strongpassword123"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("loginUser helper: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}

// findCookie returns the cookie with the given name that the response sets.
func findCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("expected a %s cookie, got Set-Cookie: %v", name, rec.Header().Values("Set-Cookie"))
	return nil
}

// assertAuthCookie checks the attributes every auth cookie must have.
func assertAuthCookie(t *testing.T, c *http.Cookie, path string, ttl time.Duration) {
	t.Helper()
	if c.Value == "" {
		t.Errorf("%s: expected a token value", c.Name)
	}
	if c.Path != path {
		t.Errorf("%s: expected Path %q, got %q", c.Name, path, c.Path)
	}
	if c.MaxAge != int(ttl.Seconds()) {
		t.Errorf("%s: expected Max-Age %d, got %d", c.Name, int(ttl.Seconds()), c.MaxAge)
	}
	if !c.HttpOnly {
		t.Errorf("%s: expected HttpOnly", c.Name)
	}
	if !c.Secure {
		t.Errorf("%s: expected Secure", c.Name)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("%s: expected SameSite=Lax, got %v", c.Name, c.SameSite)
	}
}

func TestCookieMode_LoginSetsAuthCookies(t *testing.T) {
	a, _, tokenStore := newCookieAuth()

	rec := loginUser(t, a)

	access := findCookie(t, rec, "goauth_access")
	assertAuthCookie(t, access, "/", 15*time.Minute)

	refresh := findCookie(t, rec, "goauth_refresh")
	assertAuthCookie(t, refresh, "/auth", 30*24*time.Hour)

	if _, err := tokenStore.GetRefreshToken(context.Background(), hashToken(refresh.Value)); err != nil {
		t.Errorf("expected the refresh cookie to hold a stored refresh token: %v", err)
	}
}

func TestCookieMode_LoginLeavesTokensOutOfBody(t *testing.T) {
	a, _, _ := newCookieAuth()

	rec := loginUser(t, a)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := body["access_token"]; ok {
		t.Error("expected no access_token in the body")
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("expected no refresh_token in the body")
	}
	if _, ok := body["user"]; !ok {
		t.Error("expected the user in the body")
	}
}

func TestCookieMode_RegisterAndOAuthSetAuthCookies(t *testing.T) {
	provider := &mockOAuthProvider{
		info: OAuthUserInfo{
			ProviderUserID: "apple-123",
			Email:          "larry@example.com",
			EmailVerified:  true,
			Name:           "Larry",
		},
	}

	tests := []struct {
		name string
		path string
		body string
	}{
		{"register", "/auth/register", `{"email":"larry@example.com","password":"strongpassword123","name":"Larry"}`},
		{"oauth", "/auth/oauth/apple", `{"id_token":"valid-apple-token"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(Config{
				UserStore:      &memoryUserStore{},
				TokenStore:     &memoryTokenStore{},
				JWTSecret:      "test-secret-key",
				AccessTTL:      15 * time.Minute,
				RefreshTTL:     30 * 24 * time.Hour,
				OAuthStore:     &memoryOAuthStore{},
				OAuthProviders: map[string]OAuthProvider{"apple": provider},
				CookieMode:     true,
			})

			req := httptest.NewRequest("POST", tt.path, bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			a.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
			}
			assertAuthCookie(t, findCookie(t, rec, "goauth_access"), "/", 15*time.Minute)
			assertAuthCookie(t, findCookie(t, rec, "goauth_refresh"), "/auth", 30*24*time.Hour)

			var resp AuthResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.AccessToken != "" || resp.RefreshToken != "" {
				t.Error("expected no tokens in the body")
			}
		})
	}
}
