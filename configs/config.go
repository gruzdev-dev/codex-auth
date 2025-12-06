package configs

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL string `yaml:"database_url"`
	JWTSecret   string `yaml:"jwt_secret"`
	HTTPPort    string `yaml:"http_port"`
	Server      struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
}

func NewConfig() (*Config, error) {
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(configFile, &cfg); err != nil {
		return nil, err
	}

	if envPort := os.Getenv("SERVER_PORT"); envPort != "" {
		cfg.Server.Port = envPort
		cfg.HTTPPort = envPort
	}

	if envDBURL := os.Getenv("DATABASE_URL"); envDBURL != "" {
		cfg.DatabaseURL = envDBURL
	}

	if envJWTSecret := os.Getenv("JWT_SECRET"); envJWTSecret != "" {
		cfg.JWTSecret = envJWTSecret
	}

	return &cfg, nil
}
