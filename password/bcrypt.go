package password

import (
	"golang.org/x/crypto/bcrypt"
)

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
// Always runs bcrypt.CompareHashAndPassword to avoid timing attacks on invalid input.
func (h *bcryptHasher) Compare(password, hash string) bool {
	// Always run comparison even if password is invalid
	// to prevent timing-based detection of valid vs invalid passwords.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
