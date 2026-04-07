package goauth

import "golang.org/x/crypto/bcrypt"

const bcryptCost = 12

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
