package goauth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword_UsesCost12ByDefault(t *testing.T) {
	hash, err := HashPassword("strongpassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("expected a bcrypt hash, got %q: %v", hash, err)
	}
	if cost != 12 {
		t.Errorf("expected cost 12, got %d", cost)
	}
}
