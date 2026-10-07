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

// cookieValue returns the value of the named cookie, or "" when the request has none.
func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
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

// rejectCrossOrigin rejects unsafe requests from other origins before they reach next.
// Cookie mode needs it because SameSite=Lax still sends cookies on requests from sibling subdomains.
func (a *Auth) rejectCrossOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.sameOrigin(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin writes a 403 and returns false when r is an unsafe request from another origin.
func (a *Auth) sameOrigin(w http.ResponseWriter, r *http.Request) bool {
	if err := a.csrf.Check(r); err != nil {
		writeError(w, http.StatusForbidden, "cross_origin", "Cross-origin request rejected")
		return false
	}
	return true
}
