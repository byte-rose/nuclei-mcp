package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Cache   CacheConfig   `mapstructure:"cache"`
	Logging LoggingConfig `mapstructure:"logging"`
}

type ServerConfig struct {
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
}

type CacheConfig struct {
	Expiry time.Duration `mapstructure:"expiry"`
}

type LoggingConfig struct {
	Path string `mapstructure:"path"`
}

func LoadConfig(path string) (config Config, err error) {
	// Create a new viper instance to avoid global state issues
	v := viper.New()
	v.AddConfigPath(path)
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	v.AutomaticEnv()

	err = v.ReadInConfig()
	if err != nil {
		return
	}

	err = v.Unmarshal(&config)
	return
}
