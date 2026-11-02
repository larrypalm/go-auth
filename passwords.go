package goauth

import (
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// minCostForTests is set by UseMinPasswordCostForTests. It's atomic because tests may call that
// while other goroutines hash.
var minCostForTests atomic.Bool

// UseMinPasswordCostForTests makes HashPassword, and the dummy hash login compares against
// when the email is unknown, use bcrypt.MinCost instead of cost 12,
// so tests that create users and log in run fast. Call it only from tests, for example in TestMain.
// It's safe to call at any time, also after New and while other goroutines hash.
// An Auth made by New before the call switches to the low-cost dummy hash too.
// There is no way to turn it off. A hash made at either cost still verifies,
// because bcrypt reads the cost from the hash.
func UseMinPasswordCostForTests() {
	minCostForTests.Store(true)
	// Build the low-cost dummy hash now, so the next login with an unknown email doesn't also pay for it.
	dummyPasswordHash()
}

// passwordCost is the bcrypt cost HashPassword uses.
func passwordCost() int {
	if minCostForTests.Load() {
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
// New and UseMinPasswordCostForTests call it, so the process builds the hash for each cost once,
// before the first login that uses it. Tests replace it to record the hash it returns.
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

// HashPassword hashes a plaintext password with bcrypt at cost 12,
// or at bcrypt.MinCost after UseMinPasswordCostForTests.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost())
	return string(bytes), err
}

// CheckPassword compares a plaintext password against a bcrypt hash.
// Returns nil if they match, an error if they don't.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
