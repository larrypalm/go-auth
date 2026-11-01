package goauth

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// minCostForTests is set by UseMinPasswordCostForTests.
var minCostForTests bool

// UseMinPasswordCostForTests makes HashPassword use bcrypt.MinCost instead of cost 12,
// so tests that create users and log in run fast. Call it only from tests, for example in TestMain.
// There is no way to turn it off. A hash made at either cost still verifies,
// because bcrypt reads the cost from the hash.
func UseMinPasswordCostForTests() {
	minCostForTests = true
}

// passwordCost is the bcrypt cost HashPassword uses.
func passwordCost() int {
	if minCostForTests {
		return bcrypt.MinCost
	}
	return bcryptCost
}

// dummyPasswordHash returns a hash made by HashPassword, so it always has the current cost.
// Login compares against it when the email is unknown, which takes as long as a wrong password.
// New calls it, so the process builds the hash once, before the first login.
var dummyPasswordHash = sync.OnceValue(func() string {
	hash, err := HashPassword("go-auth dummy password")
	if err != nil {
		panic(err)
	}
	return hash
})

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost())
	return string(bytes), err
}

// CheckPassword compares a plaintext password against a bcrypt hash.
// Returns nil if they match, an error if they don't.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
