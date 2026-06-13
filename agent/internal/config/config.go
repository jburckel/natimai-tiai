// Package config loads agent configuration from C:\ProgramData\Tiai\config.yaml,
// overridable by registry keys (see plan §2.10). The sensitive enrollment
// secret and the per-machine token are stored via DPAPI, not in clear YAML.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultHeartbeatInterval = 60    // short poll: command pickup (seconds)
	DefaultTelemetryInterval = 900   // long poll: full state report (seconds)
	DefaultRequestTimeout    = 10     // seconds
)

// Config is the agent runtime configuration.
type Config struct {
	APIBaseURL               string `json:"api_base_url"`
	MachineUUID              string `json:"machine_uuid,omitempty"`     // optional manual override; else auto-resolved (SMBIOS UUID / agent UUID)
	EnrollmentSecret         string `json:"enrollment_secret,omitempty"` // GPO-deployed; DPAPI in prod
	AuthToken                string `json:"auth_token,omitempty"`        // per-machine; DPAPI in prod
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	TelemetryIntervalSeconds int    `json:"telemetry_interval_seconds"`
	RequestTimeoutSeconds    int    `json:"request_timeout_seconds"`
	LogLevel                 string `json:"log_level"`
}

// DefaultConfig returns sane defaults.
func DefaultConfig() *Config {
	return &Config{
		HeartbeatIntervalSeconds: DefaultHeartbeatInterval,
		TelemetryIntervalSeconds: DefaultTelemetryInterval,
		RequestTimeoutSeconds:    DefaultRequestTimeout,
		LogLevel:                 "INFO",
	}
}

// DefaultConfigDir is C:\ProgramData\Tiai.
func DefaultConfigDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Tiai")
}

// DefaultConfigPath is C:\ProgramData\Tiai\config.json.
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.json")
}

// Load reads and validates the config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.APIBaseURL == "" {
		return nil, fmt.Errorf("api_base_url is required")
	}
	return cfg, nil
}

// Save persists the config atomically.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return os.Rename(tmp, path)
}
