// Package config handles loading the application configuration from config.json.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the runtime configuration loaded from config.json.
type Config struct {
	ListenHost  string `json:"LISTEN_HOST"`
	ListenPort  int    `json:"LISTEN_PORT"`
	ConnectIP   string `json:"CONNECT_IP"`
	ConnectPort int    `json:"CONNECT_PORT"`
	FakeSNI     string `json:"FAKE_SNI"`
}

// DefaultConfigPath returns the path to config.json next to the executable, or in the
// current working directory if that file does not exist (useful for `go run`).
func DefaultConfigPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", fmt.Errorf("config.json not found next to executable and failed to get cwd: %w", cwdErr)
		}
		configPath = filepath.Join(cwd, "config.json")
	}
	return configPath, nil
}

// LoadConfigFile reads and parses a JSON config from path.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config at %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// LoadConfig reads and parses config.json from the same directory as the executable,
// or from the current working directory if that file does not exist (see DefaultConfigPath).
func LoadConfig() (*Config, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return nil, err
	}
	return LoadConfigFile(path)
}
