package google

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	goauth "github.com/larrypalm/go-auth"
)

const (
	defaultJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	issuerAccounts = "https://accounts.google.com"
	issuerPlain    = "accounts.google.com"
)

// Option configures the Google provider.
type Option func(*Provider)

// WithJWKSURL overrides the Google JWKS endpoint (useful for testing).
func WithJWKSURL(url string) Option {
	return func(p *Provider) {
		p.jwksURL = url
	}
}

// Provider validates Google ID tokens.
type Provider struct {
	clientID string
	jwksURL  string
}

// New creates a Google OAuth provider.
// clientID is your Google OAuth client ID (e.g. "123456.apps.googleusercontent.com").
func New(clientID string, opts ...Option) *Provider {
	p := &Provider{
		clientID: clientID,
		jwksURL:  defaultJWKSURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ValidateToken validates a Google ID token JWT and returns user info.
func (p *Provider) ValidateToken(ctx context.Context, idToken string) (goauth.OAuthUserInfo, error) {
	// Parse without verification to get kid from header.
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return goauth.OAuthUserInfo{}, goauth.ErrOAuthTokenInvalid
	}

	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return goauth.OAuthUserInfo{}, goauth.ErrOAuthTokenInvalid
	}

	// Fetch the matching public key from Google's JWKS.
	key, err := p.fetchPublicKey(ctx, kid)
	if err != nil {
		return goauth.OAuthUserInfo{}, err
	}

	// Parse and validate with signature, audience, and expiry checks.
	// Issuer is checked manually because Google uses two valid issuers.
	claims := &googleClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	},
		jwt.WithAudience(p.clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return goauth.OAuthUserInfo{}, goauth.ErrOAuthTokenInvalid
	}

	// Google accepts two issuer values.
	if claims.Issuer != issuerAccounts && claims.Issuer != issuerPlain {
		return goauth.OAuthUserInfo{}, goauth.ErrOAuthTokenInvalid
	}

	return goauth.OAuthUserInfo{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Name:           claims.Name,
	}, nil
}

// googleClaims extends RegisteredClaims with Google-specific fields.
type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	jwt.RegisteredClaims
}

// jwksResponse is Google's JWKS response format.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (p *Provider) fetchPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return nil, goauth.ErrOAuthTokenInvalid
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, goauth.ErrOAuthTokenInvalid
	}
	defer resp.Body.Close()

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, goauth.ErrOAuthTokenInvalid
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return jwkToRSAPublicKey(key)
		}
	}

	return nil, goauth.ErrOAuthTokenInvalid
}

func jwkToRSAPublicKey(key jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
