package config

import (
	"time"

	"github.com/spf13/viper"
)

// Config stores all configuration for the application.
// The values are read by viper from a config file or environment variables.
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Cache   CacheConfig   `mapstructure:"cache"`
	Logging LoggingConfig `mapstructure:"logging"`
}

// ServerConfig stores server specific configuration.
type ServerConfig struct {
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
}

// CacheConfig stores cache specific configuration.
type CacheConfig struct {
	Expiry time.Duration `mapstructure:"expiry"`
}

// LoggingConfig stores logging specific configuration.
type LoggingConfig struct {
	Path string `mapstructure:"path"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
