package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	defaultMemory  uint32 = 64 * 1024
	defaultTime    uint32 = 3
	defaultThreads uint8  = 2
	saltLength            = 16
	keyLength             = 32
)

// argon2Hasher is the Argon2id implementation of Hasher.
type argon2Hasher struct {
	memory    uint32
	time      uint32
	threads   uint8
	minLength int
	maxLength int
}

// NewArgon2Hasher creates a new Argon2id Hasher with optional configuration.
func NewArgon2Hasher(opts ...Option) Hasher {
	cfg := defaultConfig()
	cfg.Memory = defaultMemory
	cfg.Time = defaultTime
	cfg.Threads = defaultThreads

	for _, opt := range opts {
		opt(cfg)
	}

	return &argon2Hasher{
		memory:    cfg.Memory,
		time:      cfg.Time,
		threads:   cfg.Threads,
		minLength: cfg.MinLength,
		maxLength: cfg.MaxLength,
	}
}

// Hash validates then generates an Argon2id hash from the given plain-text password.
// Output format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func (h *argon2Hasher) Hash(password string) (string, error) {
	if err := validatePassword(password, h.minLength, h.maxLength); err != nil {
		return "", err
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, h.time, h.memory, h.threads, keyLength)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.memory, h.time, h.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
}

// Compare checks whether the plain-text password matches the given Argon2id hash.
// Uses subtle.ConstantTimeCompare to prevent timing attacks.
func (h *argon2Hasher) Compare(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	var memory uint32
	var time uint32
	var threads uint8

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	key := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(decodedHash)))

	return subtle.ConstantTimeCompare(decodedHash, key) == 1
}
