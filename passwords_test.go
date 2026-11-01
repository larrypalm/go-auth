package goauth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// useMinPasswordCost calls UseMinPasswordCostForTests and turns it off again when the test ends,
// so the tests that check cost 12 still see it.
func useMinPasswordCost(t *testing.T) {
	t.Helper()
	UseMinPasswordCostForTests()
	t.Cleanup(func() { minCostForTests = false })
}

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

func TestHashPassword_UsesMinCostAfterUseMinPasswordCostForTests(t *testing.T) {
	useMinPasswordCost(t)

	hash, err := HashPassword("strongpassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("expected a bcrypt hash, got %q: %v", hash, err)
	}
	if cost != bcrypt.MinCost {
		t.Errorf("expected cost %d, got %d", bcrypt.MinCost, cost)
	}
}
