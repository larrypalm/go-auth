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

func TestCookieMode_RefreshReadsTokenFromCookie(t *testing.T) {
	a, _, _ := newCookieAuth()
	oldRefresh := findCookie(t, loginUser(t, a), "goauth_refresh")

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: oldRefresh.Value})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuthCookie(t, findCookie(t, rec, "goauth_access"), "/", 15*time.Minute)
	newRefresh := findCookie(t, rec, "goauth_refresh")
	assertAuthCookie(t, newRefresh, "/auth", 30*24*time.Hour)
	if newRefresh.Value == oldRefresh.Value {
		t.Error("expected the refresh token to rotate")
	}
}

func TestCookieMode_RefreshWithoutCookie(t *testing.T) {
	a, _, _ := newCookieAuth()

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCookieMode_MiddlewareReadsAccessCookie(t *testing.T) {
	a, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, a), "goauth_access")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var user User
	if err := json.NewDecoder(rec.Body).Decode(&user); err != nil {
		t.Fatalf("failed to decode user: %v", err)
	}
	if user.Email != "larry@example.com" {
		t.Errorf("expected email larry@example.com, got %s", user.Email)
	}
}

func TestCookieMode_MiddlewarePrefersAuthorizationHeader(t *testing.T) {
	a, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, a), "goauth_access")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer totally-invalid-jwt")
	req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 from the invalid header, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBearerMode_MiddlewareIgnoresAccessCookie(t *testing.T) {
	cookieAuth, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, cookieAuth), "goauth_access")

	// Same secret, so the token is valid for the bearer-mode instance too.
	a, _, _ := newTestAuth()
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// assertClearedCookie checks that the response deletes the named cookie at the given path.
func assertClearedCookie(t *testing.T, rec *httptest.ResponseRecorder, name, path string) {
	t.Helper()
	c := findCookie(t, rec, name)
	if c.MaxAge >= 0 {
		t.Errorf("%s: expected Max-Age=0 to delete it, got Max-Age %d", name, c.MaxAge)
	}
	if c.Path != path {
		t.Errorf("%s: expected Path %q, got %q", name, path, c.Path)
	}
}

func TestCookieMode_LogoutRevokesAndClearsCookies(t *testing.T) {
	a, _, tokenStore := newCookieAuth()
	refresh := findCookie(t, loginUser(t, a), "goauth_refresh")

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: refresh.Value})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	assertClearedCookie(t, rec, "goauth_access", "/")
	assertClearedCookie(t, rec, "goauth_refresh", "/auth")

	stored, err := tokenStore.GetRefreshToken(context.Background(), hashToken(refresh.Value))
	if err != nil {
		t.Fatalf("expected the refresh token in the store: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("expected the refresh token to be revoked")
	}
}

func TestCookieMode_LogoutWithoutRefreshCookieClearsCookies(t *testing.T) {
	a, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, a), "goauth_access")

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	assertClearedCookie(t, rec, "goauth_access", "/")
	assertClearedCookie(t, rec, "goauth_refresh", "/auth")
}

func TestCookieMode_ConfiguredNamesAndPath(t *testing.T) {
	a := New(Config{
		UserStore:         &memoryUserStore{},
		TokenStore:        &memoryTokenStore{},
		JWTSecret:         "test-secret-key",
		AccessTTL:         15 * time.Minute,
		RefreshTTL:        30 * 24 * time.Hour,
		CookieMode:        true,
		AccessCookieName:  "app_access",
		RefreshCookieName: "app_refresh",
		RefreshCookiePath: "/api/auth",
	})

	login := loginUser(t, a)
	access := findCookie(t, login, "app_access")
	assertAuthCookie(t, access, "/", 15*time.Minute)
	assertAuthCookie(t, findCookie(t, login, "app_refresh"), "/api/auth", 30*24*time.Hour)

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "app_refresh", Value: findCookie(t, login, "app_refresh").Value})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "app_access", Value: access.Value})
	rec = httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("middleware: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("POST", "/auth/logout", nil)
	rec = httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	assertClearedCookie(t, rec, "app_access", "/")
	assertClearedCookie(t, rec, "app_refresh", "/api/auth")
}

func TestCookieMode_InsecureCookiesLeaveSecureOff(t *testing.T) {
	a := New(Config{
		UserStore:       &memoryUserStore{},
		TokenStore:      &memoryTokenStore{},
		JWTSecret:       "test-secret-key",
		AccessTTL:       15 * time.Minute,
		RefreshTTL:      30 * 24 * time.Hour,
		CookieMode:      true,
		InsecureCookies: true,
	})

	login := loginUser(t, a)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	logout := httptest.NewRecorder()
	a.Routes().ServeHTTP(logout, req)

	for _, rec := range []*httptest.ResponseRecorder{login, logout} {
		for _, name := range []string{"goauth_access", "goauth_refresh"} {
			if findCookie(t, rec, name).Secure {
				t.Errorf("%s: expected no Secure attribute", name)
			}
		}
	}
}

func TestCookieMode_RoutesRejectCrossOriginRequests(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"cross-site", "Sec-Fetch-Site", "cross-site"},
		{"sibling subdomain", "Sec-Fetch-Site", "same-site"},
		{"foreign Origin without Sec-Fetch-Site", "Origin", "https://evil.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, _ := newCookieAuth()
			registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

			// A text/plain body is what an HTML form can send cross-site without a preflight.
			body := `{"email":"larry@example.com","password":"strongpassword123"}`
			req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set(tt.header, tt.value)
			rec := httptest.NewRecorder()
			a.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("expected no cookies on a rejected request")
			}
		})
	}
}

func TestBearerMode_RoutesAllowCrossOriginRequests(t *testing.T) {
	a, _, _ := newTestAuth()
	registerUser(t, a, "larry@example.com", "strongpassword123", "Larry")

	body := `{"email":"larry@example.com","password":"strongpassword123"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCookieMode_MiddlewareRejectsCrossOriginCookieRequests(t *testing.T) {
	a, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, a), "goauth_access")

	req := httptest.NewRequest("POST", "/protected", nil)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCookieMode_MiddlewareAllowsSafeOrBearerCrossOriginRequests(t *testing.T) {
	a, _, _ := newCookieAuth()
	access := findCookie(t, loginUser(t, a), "goauth_access")

	t.Run("GET with cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(&http.Cookie{Name: "goauth_access", Value: access.Value})
		rec := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("POST with Authorization header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/protected", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Authorization", "Bearer "+access.Value)
		rec := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(protectedHandler)).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
