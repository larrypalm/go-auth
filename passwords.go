package goauth

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// dummyPasswordHash returns a hash made by HashPassword, so it always has the current cost.
// Login compares against it when the email is unknown, which takes as long as a wrong password.
var dummyPasswordHash = sync.OnceValue(func() string {
	hash, err := HashPassword("go-auth dummy password")
	if err != nil {
		panic(err)
	}
	return hash
})

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(bytes), err
}

// CheckPassword compares a plaintext password against a bcrypt hash.
// Returns nil if they match, an error if they don't.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
