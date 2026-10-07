package goauth

import "net/http"

const (
	accessCookieName  = "goauth_access"
	refreshCookieName = "goauth_refresh"
	refreshCookiePath = "/auth"
)

// setAuthCookies sets both tokens as httpOnly cookies. The refresh cookie's path
// covers only the routes that read it, /auth/refresh and /auth/logout.
func (a *Auth) setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, a.authCookie(accessCookieName, accessToken, "/", int(a.config.AccessTTL.Seconds())))
	http.SetCookie(w, a.authCookie(refreshCookieName, refreshToken, refreshCookiePath, int(a.config.RefreshTTL.Seconds())))
}

// authCookie builds a cookie with the attributes every auth cookie shares.
func (a *Auth) authCookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
