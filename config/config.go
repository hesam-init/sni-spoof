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

// LoadConfig reads and parses config.json from the same directory as the executable.
// If running from source (go run), it uses the current working directory.
func LoadConfig() (*Config, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)

	// Try executable directory first, then current working directory
	configPath := filepath.Join(exeDir, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Fallback: current working directory (useful for `go run`)
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return nil, fmt.Errorf("config.json not found next to executable and failed to get cwd: %w", cwdErr)
		}
		configPath = filepath.Join(cwd, "config.json")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config.json at %s: %w", configPath, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config.json: %w", err)
	}

	return &cfg, nil
}
