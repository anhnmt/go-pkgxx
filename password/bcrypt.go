package password

import (
	"golang.org/x/crypto/bcrypt"
)

// Ensure bcryptHasher implements Hasher at compile time.
var _ Hasher = (*bcryptHasher)(nil)

// bcryptHasher is the bcrypt implementation of Hasher.
type bcryptHasher struct {
	cost      int
	minLength int
	maxLength int
}

// NewBcryptHasher creates a new bcrypt Hasher with optional configuration.
// Defaults to bcrypt.DefaultCost (10) if no valid cost is provided.
func NewBcryptHasher(opts ...Option) Hasher {
	cfg := defaultConfig()
	cfg.Cost = bcrypt.DefaultCost

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.Cost < bcrypt.MinCost || cfg.Cost > bcrypt.MaxCost {
		cfg.Cost = bcrypt.DefaultCost
	}

	return &bcryptHasher{
		cost:      cfg.Cost,
		minLength: cfg.MinLength,
		maxLength: cfg.MaxLength,
	}
}

// Algorithm returns the hashing algorithm identifier.
func (h *bcryptHasher) Algorithm() Algorithm {
	return AlgorithmBcrypt
}

// Hash validates then generates a bcrypt hash from the given plain-text password.
func (h *bcryptHasher) Hash(password string) (string, error) {
	if err := validatePassword(password, h.minLength, h.maxLength); err != nil {
		return "", err
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// Compare checks whether the plain-text password matches the given bcrypt hash.
// Returns false (not an error) on algorithm mismatch to keep the interface consistent.
func (h *bcryptHasher) Compare(password, hash string) bool {
	if IdentifyAlgorithm(hash) != AlgorithmBcrypt {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
