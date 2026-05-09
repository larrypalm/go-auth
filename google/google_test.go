package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	goauth "github.com/larrypalm/go-auth"
)

const testClientID = "123456.apps.googleusercontent.com"
const testKid = "test-key-id"

func testSetup(t *testing.T) (*Provider, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := jwksResponse{
			Keys: []jwk{
				{
					Kid: testKid,
					N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	provider := New(testClientID, WithJWKSURL(srv.URL))
	return provider, privateKey
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKid

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":            issuerAccounts,
		"aud":            testClientID,
		"sub":            "google-user-001",
		"email":          "larry@gmail.com",
		"email_verified": true,
		"name":           "Larry Palm",
		"iat":            jwt.NewNumericDate(now),
		"exp":            jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
}

func TestValidateToken_Success(t *testing.T) {
	provider, key := testSetup(t)

	idToken := signToken(t, key, validClaims())
	info, err := provider.ValidateToken(context.Background(), idToken)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if info.ProviderUserID != "google-user-001" {
		t.Errorf("expected ProviderUserID 'google-user-001', got '%s'", info.ProviderUserID)
	}
	if info.Email != "larry@gmail.com" {
		t.Errorf("expected Email 'larry@gmail.com', got '%s'", info.Email)
	}
	if !info.EmailVerified {
		t.Error("expected EmailVerified to be true")
	}
	if info.Name != "Larry Palm" {
		t.Errorf("expected Name 'Larry Palm', got '%s'", info.Name)
	}
}

func TestValidateToken_AlternateIssuer(t *testing.T) {
	provider, key := testSetup(t)

	claims := validClaims()
	claims["iss"] = issuerPlain // "accounts.google.com" without https://
	idToken := signToken(t, key, claims)

	info, err := provider.ValidateToken(context.Background(), idToken)
	if err != nil {
		t.Fatalf("expected no error for alternate issuer, got %v", err)
	}
	if info.ProviderUserID != "google-user-001" {
		t.Errorf("expected ProviderUserID 'google-user-001', got '%s'", info.ProviderUserID)
	}
}

func TestValidateToken_WrongAudience(t *testing.T) {
	provider, key := testSetup(t)

	claims := validClaims()
	claims["aud"] = "wrong-client-id"
	idToken := signToken(t, key, claims)

	_, err := provider.ValidateToken(context.Background(), idToken)
	if err != goauth.ErrOAuthTokenInvalid {
		t.Fatalf("expected ErrOAuthTokenInvalid, got %v", err)
	}
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	provider, key := testSetup(t)

	claims := validClaims()
	claims["iss"] = "https://evil.example.com"
	idToken := signToken(t, key, claims)

	_, err := provider.ValidateToken(context.Background(), idToken)
	if err != goauth.ErrOAuthTokenInvalid {
		t.Fatalf("expected ErrOAuthTokenInvalid, got %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	provider, key := testSetup(t)

	claims := validClaims()
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
	claims["iat"] = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	idToken := signToken(t, key, claims)

	_, err := provider.ValidateToken(context.Background(), idToken)
	if err != goauth.ErrOAuthTokenInvalid {
		t.Fatalf("expected ErrOAuthTokenInvalid, got %v", err)
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	provider, _ := testSetup(t)

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	idToken := signToken(t, otherKey, validClaims())

	_, err := provider.ValidateToken(context.Background(), idToken)
	if err != goauth.ErrOAuthTokenInvalid {
		t.Fatalf("expected ErrOAuthTokenInvalid, got %v", err)
	}
}

func TestValidateToken_GarbageToken(t *testing.T) {
	provider, _ := testSetup(t)

	_, err := provider.ValidateToken(context.Background(), "not-a-jwt")
	if err != goauth.ErrOAuthTokenInvalid {
		t.Fatalf("expected ErrOAuthTokenInvalid, got %v", err)
	}
}

func TestValidateToken_IncludesName(t *testing.T) {
	provider, key := testSetup(t)

	idToken := signToken(t, key, validClaims())
	info, err := provider.ValidateToken(context.Background(), idToken)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if info.Name != "Larry Palm" {
		t.Errorf("expected Name 'Larry Palm', got '%s'", info.Name)
	}
}
