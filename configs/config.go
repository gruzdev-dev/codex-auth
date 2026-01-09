package configs

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL      string `yaml:"database_url"`
	JWTSecret        string `yaml:"jwt_secret"`
	InternalSecret   string `yaml:"internal_secret"`
	DocumentsService struct {
		Addr string `yaml:"addr"`
	} `yaml:"documents_service"`
	Server struct {
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
	}

	if envDBURL := os.Getenv("DATABASE_URL"); envDBURL != "" {
		cfg.DatabaseURL = envDBURL
	}

	if envJWTSecret := os.Getenv("JWT_SECRET"); envJWTSecret != "" {
		cfg.JWTSecret = envJWTSecret
	}

	if envInternalSecret := os.Getenv("INTERNAL_SERVICE_SECRET"); envInternalSecret != "" {
		cfg.InternalSecret = envInternalSecret
	}

	if envDocumentsAddr := os.Getenv("DOCUMENTS_SERVICE_ADDR"); envDocumentsAddr != "" {
		cfg.DocumentsService.Addr = envDocumentsAddr
	}

	return &cfg, nil
}
