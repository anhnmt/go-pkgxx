package password

import "errors"

// Hasher defines the interface for password hashing operations.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}

// Sentinel errors for password validation.
var (
	ErrPasswordTooShort = errors.New("password: too short, minimum 8 characters")
	ErrPasswordTooLong  = errors.New("password: too long, maximum 72 characters for bcrypt")
	ErrPasswordEmpty    = errors.New("password: must not be empty")
)

// Option is a functional option for configuring a Hasher.
type Option func(*Config)

// Config holds common configuration for all Hasher implementations.
type Config struct {
	Cost      int
	Memory    uint32
	Time      uint32
	Threads   uint8
	MinLength int
	MaxLength int
}

// defaultConfig returns a Config with safe defaults.
func defaultConfig() *Config {
	return &Config{
		MinLength: 8,
		MaxLength: 72, // bcrypt hard limit
	}
}

// WithCost sets the cost factor (used by bcrypt).
func WithCost(cost int) Option {
	return func(c *Config) {
		c.Cost = cost
	}
}

// WithMemory sets the memory parameter in KiB (used by argon2).
func WithMemory(memory uint32) Option {
	return func(c *Config) {
		c.Memory = memory
	}
}

// WithTime sets the time iterations (used by argon2).
func WithTime(time uint32) Option {
	return func(c *Config) {
		c.Time = time
	}
}

// WithThreads sets the parallelism threads (used by argon2).
func WithThreads(threads uint8) Option {
	return func(c *Config) {
		c.Threads = threads
	}
}

// WithMinLength sets the minimum allowed password length.
func WithMinLength(n int) Option {
	return func(c *Config) {
		c.MinLength = n
	}
}

// WithMaxLength sets the maximum allowed password length.
func WithMaxLength(n int) Option {
	return func(c *Config) {
		c.MaxLength = n
	}
}

// validatePassword checks password length constraints before hashing.
func validatePassword(password string, min, max int) error {
	l := len(password)
	if l == 0 {
		return ErrPasswordEmpty
	}
	if l < min {
		return ErrPasswordTooShort
	}
	if l > max {
		return ErrPasswordTooLong
	}
	return nil
}
