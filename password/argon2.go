package password

import (
	"github.com/matthewhartstonge/argon2"
)

// Ensure argon2Hasher implements Hasher at compile time.
var _ Hasher = (*argon2Hasher)(nil)

// argon2Hasher is the Argon2id implementation of Hasher.
type argon2Hasher struct {
	cfg       argon2.Config
	minLength int
	maxLength int
}

// NewArgon2Hasher creates a new Argon2id Hasher with optional configuration.
// Defaults follow RFC recommendations via argon2.DefaultConfig().
func NewArgon2Hasher(opts ...Option) Hasher {
	cfg := defaultConfig()
	cfg.Memory = 64 * 1024
	cfg.Time = 3
	cfg.Threads = 2

	for _, opt := range opts {
		opt(cfg)
	}

	return &argon2Hasher{
		cfg: argon2.Config{
			MemoryCost:  cfg.Memory,
			TimeCost:    cfg.Time,
			Parallelism: cfg.Threads,
			SaltLength:  16,
			HashLength:  32,
			Mode:        argon2.ModeArgon2id,
		},
		minLength: cfg.MinLength,
		maxLength: cfg.MaxLength,
	}
}

// Algorithm returns the hashing algorithm identifier.
func (h *argon2Hasher) Algorithm() Algorithm {
	return AlgorithmArgon2
}

// Hash validates then generates an Argon2id hash from the given plain-text password.
// Salt is automatically generated. Output follows the PHC string format.
func (h *argon2Hasher) Hash(password string) (string, error) {
	if err := validatePassword(password, h.minLength, h.maxLength); err != nil {
		return "", err
	}

	encoded, err := h.cfg.HashEncoded([]byte(password))
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

// Compare checks whether the plain-text password matches the given Argon2id hash.
// Returns false (not an error) on algorithm mismatch to keep the interface consistent.
func (h *argon2Hasher) Compare(password, hash string) bool {
	if IdentifyAlgorithm(hash) != AlgorithmArgon2 {
		return false
	}

	ok, err := argon2.VerifyEncoded([]byte(password), []byte(hash))
	if err != nil {
		return false
	}

	return ok
}
