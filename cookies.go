package goauth

import "net/http"

// setAuthCookies sets both tokens as httpOnly cookies. The refresh cookie's path
// covers only the routes that read it, /auth/refresh and /auth/logout.
func (a *Auth) setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, a.authCookie(a.config.AccessCookieName, accessToken, "/", int(a.config.AccessTTL.Seconds())))
	http.SetCookie(w, a.authCookie(a.config.RefreshCookieName, refreshToken, a.config.RefreshCookiePath, int(a.config.RefreshTTL.Seconds())))
}

// clearAuthCookies tells the browser to delete both auth cookies.
func (a *Auth) clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, a.authCookie(a.config.AccessCookieName, "", "/", -1))
	http.SetCookie(w, a.authCookie(a.config.RefreshCookieName, "", a.config.RefreshCookiePath, -1))
}

// authCookie builds a cookie with the attributes every auth cookie shares.
func (a *Auth) authCookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !a.config.InsecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}
