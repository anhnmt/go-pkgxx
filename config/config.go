package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

func New(file string, cfg any) error {
	viper.SetConfigFile(file)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil && !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unable to decode into struct: %w", err)
	}

	return nil
}
