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

// dummyHashes holds one dummy hash for each cost HashPassword can use.
// Each one is built the first time it's asked for.
var dummyHashes = map[int]func() string{
	bcryptCost:     sync.OnceValue(func() string { return hashDummyPassword(bcryptCost) }),
	bcrypt.MinCost: sync.OnceValue(func() string { return hashDummyPassword(bcrypt.MinCost) }),
}

// dummyPasswordHash returns a dummy hash at the cost HashPassword uses now.
// Login compares against it when the email is unknown, which takes as long as a wrong password.
// New calls it, so the process builds the hash once, before the first login.
var dummyPasswordHash = func() string {
	return dummyHashes[passwordCost()]()
}

func hashDummyPassword(cost int) string {
	hash, err := bcrypt.GenerateFromPassword([]byte("go-auth dummy password"), cost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}

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
