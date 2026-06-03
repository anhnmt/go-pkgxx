package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Option is a functional option for the config loader.
type Option func(*options)

type options struct {
	envReplacer *strings.Replacer
	envPrefix   string
	validator   func(any) error
}

// WithEnvKeyReplacer overrides the default key replacer ("." -> "_").
func WithEnvKeyReplacer(r *strings.Replacer) Option {
	return func(o *options) { o.envReplacer = r }
}

// WithEnvPrefix sets a prefix for all environment variables (e.g. "APP" -> APP_PORT).
func WithEnvPrefix(prefix string) Option {
	return func(o *options) { o.envPrefix = prefix }
}

// WithValidator sets a validation function called after unmarshalling.
func WithValidator(fn func(any) error) Option {
	return func(o *options) { o.validator = fn }
}

// New loads the config file into cfg, applying any provided options.
// Missing config files are silently ignored; defaults and env vars are still applied.
func New(file string, cfg any, opts ...Option) error {
	o := &options{
		envReplacer: strings.NewReplacer(".", "_"),
	}
	for _, opt := range opts {
		opt(o)
	}

	viper.SetConfigFile(file)
	viper.SetEnvKeyReplacer(o.envReplacer)
	viper.AutomaticEnv()

	if o.envPrefix != "" {
		viper.SetEnvPrefix(o.envPrefix)
	}

	if err := viper.ReadInConfig(); err != nil && !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("read config: %w", err)
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	if o.validator != nil {
		if err := o.validator(cfg); err != nil {
			return fmt.Errorf("validate config: %w", err)
		}
	}

	return nil
}
