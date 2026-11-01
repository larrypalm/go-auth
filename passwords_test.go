package goauth

import (
	"sync"
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

// The first login with an unknown email after the call must not also pay to build the low-cost dummy hash.
func TestUseMinPasswordCostForTests_BuildsTheDummyHashAtMinCost(t *testing.T) {
	built := recordDummyHashBuild(t)

	useMinPasswordCost(t)

	cost, err := bcrypt.Cost([]byte(*built))
	if err != nil {
		t.Fatalf("expected UseMinPasswordCostForTests to build a bcrypt hash, got %q: %v", *built, err)
	}
	if cost != bcrypt.MinCost {
		t.Errorf("expected cost %d, got %d", bcrypt.MinCost, cost)
	}
}

// go test -race reports a data race here if the cost isn't safe to set while other goroutines read it.
// The first call makes every hash in the test cheap. The second runs while the goroutines hash.
func TestUseMinPasswordCostForTests_IsSafeWhileOtherGoroutinesHash(t *testing.T) {
	useMinPasswordCost(t)

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := HashPassword("strongpassword123"); err != nil {
				t.Errorf("HashPassword: %v", err)
			}
		})
	}
	UseMinPasswordCostForTests()
	wg.Wait()
}
